"""Tests for the typed next-gen provider implementations under
src/osspolicyguard/providers/ (OPG-007 / OPG-023).

These are independent of the legacy oss_scorer.py providers covered by
test_providers.py; they exercise the ProviderBase/ProviderResponse contract
directly with mocked HTTP calls.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from osspolicyguard.providers import ProviderStatus
from osspolicyguard.providers.github_provider import GitHubProvider
from osspolicyguard.providers.scorecard_provider import ScorecardProvider
from osspolicyguard.providers.nvd_provider import NVDProvider
from osspolicyguard.providers.osv_provider import OSVProvider
from osspolicyguard.providers.epss_provider import EPSSProvider
from osspolicyguard.providers.registry_provider import RegistryProvider


def _mock_response(status_code=200, json_data=None, url="https://example.test"):
    resp = MagicMock()
    resp.status_code = status_code
    resp.url = url
    if json_data is not None:
        resp.json.return_value = json_data
    else:
        resp.json.side_effect = ValueError("no json")
    return resp


# ---------------------------------------------------------------------------
# GitHubProvider
# ---------------------------------------------------------------------------


class TestGitHubProvider:
    def test_success(self, monkeypatch):
        payload = {
            "stargazers_count": 1200,
            "forks_count": 45,
            "pushed_at": "2025-01-01T00:00:00Z",
            "open_issues_count": 7,
            "contributors_url": "https://api.github.com/repos/x/y/contributors",
        }
        monkeypatch.setattr(
            "osspolicyguard.providers.github_provider.requests.get",
            lambda *a, **k: _mock_response(200, payload),
        )
        provider = GitHubProvider({"github": {"timeout": 5, "token": ""}})
        response = provider.fetch("https://github.com/expressjs/express")

        assert response.is_success()
        assert response.data["stars"] == 1200
        assert response.data["forks"] == 45
        assert response.data["open_issues"] == 7

    def test_malformed_url(self):
        provider = GitHubProvider({"github": {"timeout": 5}})
        response = provider.fetch("https://gitlab.com/owner/repo")
        assert response.status == ProviderStatus.MALFORMED

    def test_spoofed_netloc_rejected(self):
        """A host that merely contains 'github.com' as a substring must not
        be accepted (REQ-010: shares oss_scorer's strict netloc allow-list)."""
        provider = GitHubProvider({"github": {"timeout": 5}})
        response = provider.fetch("https://notgithub.com/owner/repo")
        assert response.status == ProviderStatus.MALFORMED

    def test_trailing_slash_and_dot_git(self):
        assert GitHubProvider._parse_owner_repo("https://github.com/owner/repo/") == (
            "owner",
            "repo",
        )
        assert GitHubProvider._parse_owner_repo("https://github.com/owner/repo.git") == (
            "owner",
            "repo",
        )

    def test_auth_error(self, monkeypatch):
        monkeypatch.setattr(
            "osspolicyguard.providers.github_provider.requests.get",
            lambda *a, **k: _mock_response(401),
        )
        provider = GitHubProvider({"github": {"timeout": 5}})
        response = provider.fetch("https://github.com/owner/repo")
        assert response.status == ProviderStatus.AUTH_ERROR

    def test_rate_limit(self, monkeypatch):
        monkeypatch.setattr(
            "osspolicyguard.providers.github_provider.requests.get",
            lambda *a, **k: _mock_response(429),
        )
        provider = GitHubProvider({"github": {"timeout": 5}})
        response = provider.fetch("https://github.com/owner/repo")
        assert response.status == ProviderStatus.RATE_LIMIT

    def test_not_found(self, monkeypatch):
        monkeypatch.setattr(
            "osspolicyguard.providers.github_provider.requests.get",
            lambda *a, **k: _mock_response(404),
        )
        provider = GitHubProvider({"github": {"timeout": 5}})
        response = provider.fetch("https://github.com/owner/repo")
        assert response.status == ProviderStatus.UNAVAILABLE

    def test_network_error(self, monkeypatch):
        def _raise(*a, **k):
            raise requests.ConnectionError("boom")

        monkeypatch.setattr("osspolicyguard.providers.github_provider.requests.get", _raise)
        provider = GitHubProvider({"github": {"timeout": 5}})
        response = provider.fetch("https://github.com/owner/repo")
        assert response.status == ProviderStatus.UNAVAILABLE

    def test_malformed_json(self, monkeypatch):
        monkeypatch.setattr(
            "osspolicyguard.providers.github_provider.requests.get",
            lambda *a, **k: _mock_response(200, None),
        )
        provider = GitHubProvider({"github": {"timeout": 5}})
        response = provider.fetch("https://github.com/owner/repo")
        assert response.status == ProviderStatus.MALFORMED


# ---------------------------------------------------------------------------
# ScorecardProvider
# ---------------------------------------------------------------------------


class TestScorecardProvider:
    def test_success(self, monkeypatch):
        payload = {
            "score": 8.2,
            "date": "2025-01-01",
            "checks": [{"name": "Code-Review", "score": 10}],
        }
        monkeypatch.setattr(
            "osspolicyguard.providers.scorecard_provider.requests.get",
            lambda *a, **k: _mock_response(200, payload),
        )
        provider = ScorecardProvider({"scorecard": {"timeout": 5}})
        response = provider.fetch("https://github.com/owner/repo")

        assert response.is_success()
        assert response.data["score"] == 8.2
        assert response.data["checks"]["Code-Review"] == 10

    def test_disabled(self):
        provider = ScorecardProvider({"scorecard": {"enabled": False}})
        response = provider.fetch("https://github.com/owner/repo")
        assert response.status == ProviderStatus.UNAVAILABLE

    def test_not_indexed(self, monkeypatch):
        monkeypatch.setattr(
            "osspolicyguard.providers.scorecard_provider.requests.get",
            lambda *a, **k: _mock_response(404),
        )
        provider = ScorecardProvider({"scorecard": {"timeout": 5}})
        response = provider.fetch("https://github.com/owner/repo")
        assert response.status == ProviderStatus.UNAVAILABLE


# ---------------------------------------------------------------------------
# NVDProvider
# ---------------------------------------------------------------------------


class TestNVDProvider:
    def test_success_v31(self, monkeypatch):
        payload = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-0001",
                        "published": "2024-01-01T00:00:00.000",
                        "metrics": {
                            "cvssMetricV31": [
                                {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
                            ]
                        },
                    }
                }
            ]
        }
        monkeypatch.setattr(
            "osspolicyguard.providers.nvd_provider.requests.get",
            lambda *a, **k: _mock_response(200, payload),
        )
        provider = NVDProvider({"nvd": {"timeout": 5, "api_key": ""}})
        response = provider.fetch("express")

        assert response.is_success()
        assert response.data["cve_count"] == 1
        assert response.data["cves"][0]["base_score"] == 9.8
        assert response.data["cves"][0]["severity"] == "CRITICAL"

    def test_auth_error(self, monkeypatch):
        monkeypatch.setattr(
            "osspolicyguard.providers.nvd_provider.requests.get",
            lambda *a, **k: _mock_response(403),
        )
        provider = NVDProvider({"nvd": {"timeout": 5}})
        response = provider.fetch("express")
        assert response.status == ProviderStatus.AUTH_ERROR


# ---------------------------------------------------------------------------
# OSVProvider
# ---------------------------------------------------------------------------


class TestOSVProvider:
    def test_detects_malicious(self, monkeypatch):
        payload = {"vulns": [{"id": "MAL-2024-0001", "aliases": [], "severity": []}]}
        monkeypatch.setattr(
            "osspolicyguard.providers.osv_provider.requests.post",
            lambda *a, **k: _mock_response(200, payload),
        )
        provider = OSVProvider({"osv": {"timeout": 5}})
        response = provider.fetch("npm", "evil-package")

        assert response.is_success()
        assert response.data["is_malicious"] is True
        assert response.data["vuln_count"] == 1

    def test_empty_response(self, monkeypatch):
        monkeypatch.setattr(
            "osspolicyguard.providers.osv_provider.requests.post",
            lambda *a, **k: _mock_response(200, {}),
        )
        provider = OSVProvider({"osv": {"timeout": 5}})
        response = provider.fetch("npm", "clean-package")

        assert response.is_success()
        assert response.data["vuln_count"] == 0
        assert response.data["is_malicious"] is False


# ---------------------------------------------------------------------------
# EPSSProvider
# ---------------------------------------------------------------------------


class TestEPSSProvider:
    def test_success(self, monkeypatch):
        payload = {
            "data": [
                {"cve": "CVE-2024-0001", "epss": "0.55", "percentile": "0.9", "date": "2025-01-01"}
            ]
        }
        monkeypatch.setattr(
            "osspolicyguard.providers.epss_provider.requests.get",
            lambda *a, **k: _mock_response(200, payload),
        )
        provider = EPSSProvider({"epss": {"timeout": 5}})
        response = provider.fetch(["CVE-2024-0001", "CVE-2024-9999"])

        assert response.is_success()
        assert response.data["scores"]["CVE-2024-0001"]["epss"] == 0.55
        assert response.data["not_found"] == ["CVE-2024-9999"]

    def test_empty_input(self):
        provider = EPSSProvider({"epss": {"timeout": 5}})
        response = provider.fetch([])
        assert response.is_success()
        assert response.data["scores"] == {}


# ---------------------------------------------------------------------------
# RegistryProvider
# ---------------------------------------------------------------------------


class TestRegistryProvider:
    def test_pypi_success(self, monkeypatch):
        payload = {
            "info": {
                "version": "1.2.3",
                "home_page": "https://example.org",
                "license": "MIT",
                "author": "me",
            }
        }
        monkeypatch.setattr(
            "osspolicyguard.providers.registry_provider.requests.get",
            lambda *a, **k: _mock_response(200, payload),
        )
        provider = RegistryProvider({"registry": {"timeout": 5}})
        response = provider.fetch("pypi", "requests")

        assert response.is_success()
        assert response.data["version"] == "1.2.3"
        assert response.data["license"] == "MIT"

    def test_npm_success(self, monkeypatch):
        payload = {
            "dist-tags": {"latest": "4.0.0"},
            "versions": {"4.0.0": {"homepage": "https://example.org", "license": "MIT"}},
            "maintainers": [{"name": "alice"}],
        }
        monkeypatch.setattr(
            "osspolicyguard.providers.registry_provider.requests.get",
            lambda *a, **k: _mock_response(200, payload),
        )
        provider = RegistryProvider({"registry": {"timeout": 5}})
        response = provider.fetch("npm", "express")

        assert response.is_success()
        assert response.data["version"] == "4.0.0"
        assert response.data["maintainers"] == ["alice"]

    def test_unsupported_ecosystem(self):
        provider = RegistryProvider({"registry": {"timeout": 5}})
        response = provider.fetch("rubygems", "rails")
        assert response.status == ProviderStatus.UNAVAILABLE

    def test_not_found(self, monkeypatch):
        monkeypatch.setattr(
            "osspolicyguard.providers.registry_provider.requests.get",
            lambda *a, **k: _mock_response(404),
        )
        provider = RegistryProvider({"registry": {"timeout": 5}})
        response = provider.fetch("pypi", "does-not-exist")
        assert response.status == ProviderStatus.UNAVAILABLE
