"""Tests for the license compliance engine (requirements.md §15, OPG-133..138)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from osspolicyguard.license_compliance import (
    DEFAULT_COMPATIBILITY_POLICY,
    categorize_license,
    classify_copyleft,
    detect_commercial_restriction,
    evaluate_license,
    generate_notice,
    normalize_license,
    parse_spdx_expression,
    build_license_report,
    to_license_markdown,
)

# ---------------------------------------------------------------------------
# OPG-133: SPDX detection
# ---------------------------------------------------------------------------


class TestNormalizeLicense:
    def test_none_and_empty(self):
        assert normalize_license(None) is None
        assert normalize_license("") is None
        assert normalize_license("   ") is None

    def test_common_aliases(self):
        assert normalize_license("MIT License") == "MIT"
        assert normalize_license("Apache Software License") == "Apache-2.0"
        assert normalize_license("BSD License") == "BSD-3-Clause"
        assert normalize_license("GPLv3") == "GPL-3.0-only"
        assert normalize_license("LGPLv2.1") == "LGPL-2.1-only"

    def test_already_spdx_passthrough(self):
        assert normalize_license("Apache-2.0") == "Apache-2.0"
        assert normalize_license("GPL-3.0-or-later") == "GPL-3.0-or-later"

    def test_unrecognized_returns_none(self):
        assert normalize_license("Some Bespoke EULA") is None


class TestParseSpdxExpression:
    def test_single_license(self):
        assert parse_spdx_expression("MIT") == ["MIT"]

    def test_or_expression(self):
        assert parse_spdx_expression("MIT OR Apache-2.0") == ["MIT", "Apache-2.0"]

    def test_and_expression(self):
        assert parse_spdx_expression("GPL-2.0-only AND MIT") == ["GPL-2.0-only", "MIT"]

    def test_empty(self):
        assert parse_spdx_expression("") == []


# ---------------------------------------------------------------------------
# OPG-134: copyleft classification
# ---------------------------------------------------------------------------


class TestClassifyCopyleft:
    def test_strong_copyleft(self):
        assert classify_copyleft("GPL-3.0-only") == "strong"
        assert classify_copyleft("GPL-2.0-or-later") == "strong"
        assert classify_copyleft("AGPL-3.0-only") == "strong"

    def test_weak_copyleft(self):
        assert classify_copyleft("LGPL-2.1-only") == "weak"
        assert classify_copyleft("MPL-2.0") == "weak"
        assert classify_copyleft("EPL-2.0") == "weak"

    def test_permissive_is_none(self):
        assert classify_copyleft("MIT") == "none"
        assert classify_copyleft("Apache-2.0") == "none"

    def test_missing_is_none(self):
        assert classify_copyleft(None) == "none"


# ---------------------------------------------------------------------------
# OPG-136: commercial restriction detection
# ---------------------------------------------------------------------------


class TestDetectCommercialRestriction:
    def test_detects_commons_clause(self):
        assert detect_commercial_restriction("Apache-2.0 WITH Commons Clause") == "commons clause"

    def test_detects_sspl(self):
        assert (
            detect_commercial_restriction("Server Side Public License")
            == "server side public license"
        )

    def test_detects_noncommercial(self):
        assert detect_commercial_restriction("Free for non-commercial use only") == "non-commercial"

    def test_clean_license_returns_none(self):
        assert detect_commercial_restriction("MIT") is None

    def test_none_input(self):
        assert detect_commercial_restriction(None) is None


# ---------------------------------------------------------------------------
# OPG-135: compatibility categorization + policy evaluation
# ---------------------------------------------------------------------------


class TestCategorizeLicense:
    def test_permissive(self):
        assert categorize_license("MIT", False) == "permissive"

    def test_weak_copyleft(self):
        assert categorize_license("MPL-2.0", False) == "weak-copyleft"

    def test_strong_copyleft(self):
        assert categorize_license("GPL-3.0-only", False) == "strong-copyleft"

    def test_commercial_restricted_overrides(self):
        assert categorize_license("MIT", True) == "commercial-restricted"

    def test_unknown(self):
        assert categorize_license(None, False) == "unknown"


class TestEvaluateLicense:
    def test_permissive_passes_under_permissive_policy(self):
        finding = evaluate_license("requests", "MIT", "permissive")
        assert finding.verdict == "PASS"
        assert finding.category == "permissive"

    def test_strong_copyleft_denied_under_permissive_policy(self):
        finding = evaluate_license("some-gpl-lib", "GPL-3.0-only", "permissive")
        assert finding.verdict == "PROHIBITED"
        assert finding.category == "strong-copyleft"

    def test_weak_copyleft_reviewed_under_permissive_policy(self):
        finding = evaluate_license("some-mpl-lib", "MPL-2.0", "permissive")
        assert finding.verdict == "REVIEW"
        assert finding.category == "weak-copyleft"

    def test_strong_copyleft_allowed_under_strong_copyleft_policy(self):
        finding = evaluate_license("some-gpl-lib", "GPL-3.0-only", "strong-copyleft")
        assert finding.verdict == "PASS"

    def test_commercial_restriction_always_denied(self):
        finding = evaluate_license("weird-lib", "MIT WITH Commons Clause", "unrestricted")
        assert finding.verdict == "PROHIBITED"
        assert finding.commercial_restriction == "commons clause"

    def test_unknown_license_is_review(self):
        finding = evaluate_license("mystery-lib", "Some Bespoke EULA", "permissive")
        assert finding.verdict == "REVIEW"
        assert finding.category == "unknown"

    def test_dual_license_expression_normalizes_both_ids(self):
        finding = evaluate_license("dual-lib", "MIT OR Apache-2.0", "permissive")
        assert finding.spdx_ids == ["MIT", "Apache-2.0"]
        assert finding.verdict == "PASS"

    def test_custom_policy_override(self):
        custom_policy = {
            "permissive": {
                "allow": [],
                "review": [],
                "deny": ["permissive", "weak-copyleft", "strong-copyleft"],
            }
        }
        finding = evaluate_license("requests", "MIT", "permissive", policy=custom_policy)
        assert finding.verdict == "PROHIBITED"

    def test_default_policy_object_has_all_four_categories(self):
        assert set(DEFAULT_COMPATIBILITY_POLICY.keys()) == {
            "permissive",
            "weak-copyleft",
            "strong-copyleft",
            "unrestricted",
        }


# ---------------------------------------------------------------------------
# OPG-137: report builders
# ---------------------------------------------------------------------------


class TestBuildLicenseReport:
    def test_summary_counts(self):
        findings = [
            evaluate_license("a", "MIT"),
            evaluate_license("b", "GPL-3.0-only"),
            evaluate_license("c", "MPL-2.0"),
        ]
        report = build_license_report(findings)
        assert report["summary"] == {"PASS": 1, "REVIEW": 1, "PROHIBITED": 1}
        assert len(report["packages"]) == 3
        assert report["schema_version"] == "1.0"


class TestToLicenseMarkdown:
    def test_contains_table_and_summary(self):
        findings = [evaluate_license("requests", "MIT")]
        markdown = to_license_markdown(findings)
        assert "License Compliance Report" in markdown
        assert "requests" in markdown
        assert "PASS" in markdown


# ---------------------------------------------------------------------------
# OPG-138: NOTICE generation
# ---------------------------------------------------------------------------


class TestGenerateNotice:
    def test_basic_notice(self):
        notice = generate_notice(
            [
                {"package_name": "requests", "license": "Apache-2.0"},
                {
                    "package_name": "flask",
                    "license": "BSD-3-Clause",
                    "copyright": "Copyright (c) Pallets",
                },
            ]
        )
        assert "requests (Apache-2.0)" in notice
        assert "flask (BSD-3-Clause)" in notice
        assert "Copyright (c) Pallets" in notice

    def test_sorted_by_package_name(self):
        notice = generate_notice(
            [
                {"package_name": "zeta", "license": "MIT"},
                {"package_name": "alpha", "license": "MIT"},
            ]
        )
        assert notice.index("alpha") < notice.index("zeta")

    def test_missing_license_falls_back_to_unknown(self):
        notice = generate_notice([{"package_name": "mystery"}])
        assert "mystery (UNKNOWN)" in notice

    def test_empty_list(self):
        notice = generate_notice([])
        assert "NOTICE" in notice
