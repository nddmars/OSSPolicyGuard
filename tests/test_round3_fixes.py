"""
Tests for the round-3 PR review fixes:
  - Finding 1 : _determine_approval returns only APPROVED / REVIEW / PROHIBITED
  - Finding 2 : provider failures carry explicit status/error fields
  - Finding 3 : scorecard KeyError handled gracefully
  - Finding 4 : NVD query uses a single rate-limited call with params
  - Finding 5 : geo disabled → trust score == maturity (no hidden penalty)
  - Finding 6 : evidence construction errors surface as warnings (not silently dropped)
  - Finding 7 : RedactingFilter preserves non-string log args (%d / %f)
"""
from __future__ import annotations

import logging
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

MINIMAL_CONFIG = {
    "nvd": {"api_key": "", "rate_limit": 1000},
    "github": {"token": "", "timeout": 5},
    "scoring": {
        "weights": {"activity": 30, "trust": 20, "security": 35, "community": 15},
        "thresholds": {"critical": 90, "high": 80, "medium": 70, "low": 60},
        "community": {
            "weekly_high": 1_000_000,
            "weekly_med": 100_000,
            "weekly_low": 10_000,
            "download_weight": 0.7,
            "star_weight": 0.3,
        },
    },
    "osv": {"enabled": True, "timeout": 5},
    "malicious_packages": {"enabled": True},
    "risk": {"geo_compliance": {"enabled": False, "high_risk_countries": []}},
    "registries": {
        "npm": {"enabled": True, "timeout": 5, "languages": ["javascript"]},
        "pypi": {"enabled": True, "timeout": 5, "languages": ["python"]},
    },
}


def _make_scorer():
    from oss_scorer import OSSScorer
    scorer = OSSScorer.__new__(OSSScorer)
    scorer.config = MINIMAL_CONFIG
    scorer._last_request_time = 0.0
    scorer.github_provider = MagicMock()
    return scorer


def _make_workflow():
    from oss_scorer import OSSScorer, OSSWorkflow
    scorer = _make_scorer()
    workflow = OSSWorkflow.__new__(OSSWorkflow)
    workflow.scorer = scorer
    workflow.config = MINIMAL_CONFIG
    return workflow


# ---------------------------------------------------------------------------
# Finding 1 – _determine_approval: only canonical three values
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "criticality, score, expected_decision",
    [
        # Mission Critical
        ("Mission Critical", 95.0, "APPROVED"),
        ("Mission Critical", 85.0, "REVIEW"),
        ("Mission Critical", 79.0, "PROHIBITED"),
        # Business Critical
        ("Business Critical", 85.0, "APPROVED"),
        ("Business Critical", 75.0, "REVIEW"),
        ("Business Critical", 65.0, "PROHIBITED"),
        # Non-Critical — never PROHIBITED by score alone
        ("Non-Critical", 70.0, "APPROVED"),
        ("Non-Critical", 55.0, "REVIEW"),
        ("Non-Critical", 0.0, "REVIEW"),
    ],
)
def test_determine_approval_canonical(criticality, score, expected_decision):
    workflow = _make_workflow()
    result = workflow._determine_approval(score, criticality)
    assert result in {"APPROVED", "REVIEW", "PROHIBITED"}, (
        f"Unexpected non-canonical value {result!r}"
    )
    assert result == expected_decision, (
        f"criticality={criticality!r}, score={score} → expected {expected_decision!r}, got {result!r}"
    )


# ---------------------------------------------------------------------------
# Finding 1 – CLI exit codes from decision matrix
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "decision, review_fails_ci, expected_exit",
    [
        ("APPROVED", False, 0),
        ("APPROVED", True, 0),
        ("REVIEW", False, 0),
        ("REVIEW", True, 2),
        ("PROHIBITED", False, 1),
        ("PROHIBITED", True, 1),
    ],
)
def test_cli_exit_codes(decision, review_fails_ci, expected_exit, monkeypatch):
    from osspolicyguard import cli

    fake_result = {
        "schema_version": "1.0",
        "tool_version": "0.1.0",
        "generated_at": "2026-01-01T00:00:00+00:00",
        "policy": {"name": "default", "version": "0.1.0"},
        "package": {"name": "testpkg", "ecosystem": "npm", "version": None},
        "score": 75.0,
        "decision": decision,
        "dimensions": {"security": 75, "maintenance": 75, "community": 75, "supply_chain_risk": 75},
        "findings": [],
        "evidence": [],
        "warnings": [],
        "malicious_package_detected": False,
        "enforcement": "review_fails_ci" if review_fails_ci else "default",
    }

    monkeypatch.setattr(cli, "scan_package", lambda *a, **kw: fake_result)

    argv = ["scan", "testpkg", "--ecosystem", "npm"]
    if review_fails_ci:
        argv.append("--review-fails-ci")
    exit_code = cli.main(argv)
    assert exit_code == expected_exit, (
        f"decision={decision!r}, review_fails_ci={review_fails_ci} → "
        f"expected exit {expected_exit}, got {exit_code}"
    )


# ---------------------------------------------------------------------------
# Finding 2 – provider failures carry explicit status/error fields
# ---------------------------------------------------------------------------


def test_check_cves_failure_has_explicit_status(monkeypatch):
    scorer = _make_scorer()

    mock_resp = MagicMock()
    mock_resp.status_code = 503
    monkeypatch.setattr(
        "oss_scorer.OSSScorer._rate_limited_get", lambda *a, **kw: mock_resp
    )

    result = scorer.check_cves("nonexistent-pkg")
    assert result["status"] == "error"
    assert result["last_updated"] is None


def test_check_cves_success_has_explicit_status(monkeypatch):
    scorer = _make_scorer()

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"vulnerabilities": []}
    monkeypatch.setattr(
        "oss_scorer.OSSScorer._rate_limited_get", lambda *a, **kw: mock_resp
    )
    # No EPSS call needed for empty CVE list
    monkeypatch.setattr(scorer, "get_epss_scores", lambda ids: {})

    result = scorer.check_cves("safe-pkg")
    assert result["status"] == "success"
    assert result["last_updated"] is not None


def test_check_osv_failure_has_explicit_status(monkeypatch):
    scorer = _make_scorer()

    mock_resp = MagicMock()
    mock_resp.status_code = 429

    import requests as req_mod
    monkeypatch.setattr(req_mod, "post", lambda *a, **kw: mock_resp)

    result = scorer.check_osv("some-pkg", "npm")
    assert result["status"] == "error"
    assert result["last_updated"] is None


def test_get_download_count_failure_returns_dict(monkeypatch):
    scorer = _make_scorer()

    import requests as req_mod

    def _raise(*a, **kw):
        raise req_mod.RequestException("timeout")

    monkeypatch.setattr(req_mod, "get", _raise)

    result = scorer.get_download_count("some-pkg", "npm")
    assert isinstance(result, dict)
    assert result["status"] == "error"
    assert result["weekly_downloads"] is None


# ---------------------------------------------------------------------------
# Finding 3 – scorecard KeyError handled gracefully
# ---------------------------------------------------------------------------


def test_calculate_security_score_scorecard_missing_score():
    workflow = _make_workflow()
    # scorecard_data without a 'score' key (provider returned an error response)
    results = {
        "scorecard_data": {"status": "timeout", "error": "gateway timeout"},
        "cve_data": {
            "total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0,
            "epss_high": 0, "max_epss": 0.0, "cves": [],
        },
        "osv_data": {
            "total": 0, "malicious_count": 0, "is_malicious": False,
            "malicious_ids": [], "extra_advisories": 0, "advisories": [],
        },
    }
    # Must not raise KeyError
    score = workflow._calculate_security_score(results)
    assert isinstance(score, float)
    assert 0.0 <= score <= 100.0


# ---------------------------------------------------------------------------
# Finding 4 – NVD uses a single rate-limited call with params
# ---------------------------------------------------------------------------


def test_check_cves_single_request(monkeypatch):
    scorer = _make_scorer()

    calls = []

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"vulnerabilities": []}

    def fake_rate_limited(self_or_url, *args, **kwargs):
        # Called as an unbound patch so first positional arg is url or self
        calls.append(kwargs.get("params") or args)
        return mock_resp

    monkeypatch.setattr(
        "oss_scorer.OSSScorer._rate_limited_get",
        lambda *a, **kw: (calls.append(kw.get("params")), mock_resp)[1],
    )
    monkeypatch.setattr(scorer, "get_epss_scores", lambda ids: {})

    scorer.check_cves("express")
    # Only one rate-limited call should have been made
    assert len(calls) == 1
    # The params dict must be present (not None)
    assert calls[0] is not None


# ---------------------------------------------------------------------------
# Finding 5 – geo disabled → trust == maturity, no hidden 40% cap
# ---------------------------------------------------------------------------


def test_trust_score_geo_disabled_equals_maturity():
    workflow = _make_workflow()
    # High-fork package → maturity = 100
    results = {
        "github_metrics": {"forks": 10_000, "stars": 50_000},
        # contributor_locations present but geo disabled in config
        "contributor_locations": [{"country_code": "XX", "contributions": 100}],
    }
    score = workflow._calculate_trust_score(results)
    # With geo disabled, trust = maturity = 100; not 0.6*100 + 0.4*50 = 80
    assert score == 100.0, f"Expected 100.0 (maturity only), got {score}"


def test_trust_score_geo_disabled_no_locations():
    workflow = _make_workflow()
    results = {"github_metrics": {"forks": 10_000, "stars": 50_000}}
    score = workflow._calculate_trust_score(results)
    assert score == 100.0


# ---------------------------------------------------------------------------
# Finding 6 – evidence construction errors surface as warnings
# ---------------------------------------------------------------------------


def test_scan_package_evidence_error_becomes_warning(monkeypatch):
    """If EvaluationResult.from_legacy() raises, the warning must appear in output."""
    from osspolicyguard import cli

    legacy_result = {
        "approval": "APPROVED",
        "total_score": 85.0,
        "scores": {"security": 90, "activity": 80, "community": 85, "trust": 80},
        "warnings": [],
    }

    def fake_workflow_evaluate(self_or_component, *args, **kwargs):
        return legacy_result

    monkeypatch.setattr(
        "oss_scorer.OSSWorkflow.evaluate_component",
        fake_workflow_evaluate,
    )

    # Force from_legacy to raise so the except branch is exercised
    def bad_from_legacy(*a, **kw):
        raise RuntimeError("injected failure")

    import osspolicyguard.models as models_mod
    monkeypatch.setattr(models_mod.EvaluationResult, "from_legacy", staticmethod(bad_from_legacy))

    result = cli.scan_package("testpkg", "npm")
    assert any("Evidence construction error" in w for w in result["warnings"]), (
        f"Expected evidence-construction warning in {result['warnings']}"
    )


# ---------------------------------------------------------------------------
# Finding 7 – RedactingFilter preserves numeric log args
# ---------------------------------------------------------------------------


def test_redacting_filter_preserves_int_args():
    from osspolicyguard.logging_config import RedactingFilter

    rf = RedactingFilter()
    record = logging.LogRecord(
        name="test", level=logging.INFO, pathname="", lineno=0,
        msg="count=%d retries=%d", args=(3, 7), exc_info=None,
    )
    rf.filter(record)
    # Args must remain ints so %d formatting works
    assert record.args == (3, 7), f"Expected (3, 7), got {record.args}"
    # The formatted message must not raise
    msg = record.getMessage()
    assert msg == "count=3 retries=7", f"Unexpected message: {msg!r}"


def test_redacting_filter_redacts_string_args():
    from osspolicyguard.logging_config import RedactingFilter

    rf = RedactingFilter()
    record = logging.LogRecord(
        name="test", level=logging.INFO, pathname="", lineno=0,
        msg="token=%s", args=("ghp_" + "A" * 36,), exc_info=None,
    )
    rf.filter(record)
    assert record.args[0] == "[REDACTED]", f"Expected redaction, got {record.args[0]!r}"


def test_redacting_filter_preserves_float_args():
    from osspolicyguard.logging_config import RedactingFilter

    rf = RedactingFilter()
    record = logging.LogRecord(
        name="test", level=logging.INFO, pathname="", lineno=0,
        msg="latency=%.2f ms", args=(12.5,), exc_info=None,
    )
    rf.filter(record)
    assert record.args == (12.5,), f"Expected (12.5,), got {record.args}"
    msg = record.getMessage()
    assert msg == "latency=12.50 ms", f"Unexpected message: {msg!r}"


def test_redacting_filter_dict_preserves_non_str():
    from osspolicyguard.logging_config import RedactingFilter

    rf = RedactingFilter()
    record = logging.LogRecord(
        name="test", level=logging.INFO, pathname="", lineno=0,
        msg="%(count)d items, token=%(token)s",
        args={"count": 5, "token": "ghp_" + "B" * 36},
        exc_info=None,
    )
    rf.filter(record)
    assert record.args["count"] == 5, "Integer dict arg must not be coerced to str"
    assert record.args["token"] == "[REDACTED]"


# ---------------------------------------------------------------------------
# Round-4 findings
# ---------------------------------------------------------------------------

# Finding 2 (remaining P0) — Provider failures must not produce APPROVED
# ---------------------------------------------------------------------------


def test_all_security_providers_failed_cannot_be_approved():
    """E2E: when NVD and OSV both fail, evaluate_component result is not APPROVED."""
    workflow = _make_workflow()

    # Simulate both NVD and OSV returning error status (no CVE/advisory data)
    error_cve = {
        'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0,
        'epss_high': 0, 'max_epss': 0.0, 'cves': [],
        'last_updated': None, 'status': 'error', 'error': 'timeout',
    }
    error_osv = {
        'total': 0, 'malicious_count': 0, 'is_malicious': False,
        'malicious_ids': [], 'extra_advisories': 0, 'advisories': [],
        'last_updated': None, 'status': 'error', 'error': 'timeout',
    }
    error_dl = {
        'weekly_downloads': None, 'period': 'unknown', 'registry': 'npm',
        'status': 'error', 'error': 'timeout',
    }

    # Patch all three provider calls to return failures
    import unittest.mock as mock
    with mock.patch.object(workflow.scorer, 'check_cves', return_value=error_cve), \
         mock.patch.object(workflow.scorer, 'check_osv', return_value=error_osv), \
         mock.patch.object(workflow.scorer, 'get_download_count', return_value=error_dl):

        result = workflow.evaluate_component({
            'package_name': 'some-pkg',
            'ecosystem': 'npm',
            'criticality': 'Non-Critical',
        })

    assert result['approval'] != 'APPROVED', (
        f"Expected REVIEW (not APPROVED) when providers fail, got {result['approval']!r}"
    )
    assert result['insufficient_data'] is True
    # At least one warning must name a failed provider
    warnings = result.get('warnings', [])
    assert any('NVD' in w or 'OSV' in w for w in warnings), (
        f"Expected provider failure warnings, got: {warnings}"
    )


def test_provider_failure_warnings_propagated():
    """NVD failure adds a visible warning to the result."""
    workflow = _make_workflow()

    error_cve = {
        'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0,
        'epss_high': 0, 'max_epss': 0.0, 'cves': [],
        'last_updated': None, 'status': 'error', 'error': 'connection refused',
    }
    ok_osv = {
        'total': 0, 'malicious_count': 0, 'is_malicious': False,
        'malicious_ids': [], 'extra_advisories': 0, 'advisories': [],
        'last_updated': '2026-01-01T00:00:00', 'status': 'success', 'error': None,
    }

    import unittest.mock as mock
    with mock.patch.object(workflow.scorer, 'check_cves', return_value=error_cve), \
         mock.patch.object(workflow.scorer, 'check_osv', return_value=ok_osv), \
         mock.patch.object(workflow.scorer, 'get_download_count', return_value={
             'weekly_downloads': 50000, 'period': 'weekly', 'registry': 'npm',
             'status': 'success', 'error': None,
         }):

        result = workflow.evaluate_component({
            'package_name': 'some-pkg',
            'ecosystem': 'npm',
            'criticality': 'Non-Critical',
        })

    assert any('NVD' in w for w in result.get('warnings', [])), (
        f"Expected NVD warning, got: {result.get('warnings')}"
    )
    assert result['insufficient_data'] is True


def test_no_provider_failures_no_insufficient_data():
    """When all providers succeed, insufficient_data must be False."""
    workflow = _make_workflow()

    ok_cve = {
        'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0,
        'epss_high': 0, 'max_epss': 0.0, 'cves': [],
        'last_updated': '2026-01-01', 'status': 'success', 'error': None,
    }
    ok_osv = {
        'total': 0, 'malicious_count': 0, 'is_malicious': False,
        'malicious_ids': [], 'extra_advisories': 0, 'advisories': [],
        'last_updated': '2026-01-01', 'status': 'success', 'error': None,
    }

    import unittest.mock as mock
    with mock.patch.object(workflow.scorer, 'check_cves', return_value=ok_cve), \
         mock.patch.object(workflow.scorer, 'check_osv', return_value=ok_osv), \
         mock.patch.object(workflow.scorer, 'get_download_count', return_value={
             'weekly_downloads': 50000, 'period': 'weekly', 'registry': 'npm',
             'status': 'success', 'error': None,
         }):

        result = workflow.evaluate_component({
            'package_name': 'some-pkg',
            'ecosystem': 'npm',
            'criticality': 'Non-Critical',
        })

    assert result['insufficient_data'] is False
    assert result['approval'] in {'APPROVED', 'REVIEW', 'PROHIBITED'}


# Finding 5 (remaining P1) — Geography is fully separated from technical score
# ---------------------------------------------------------------------------


def test_trust_score_never_includes_geo():
    """_calculate_trust_score never blends geo — even when geo_compliance is enabled."""
    from oss_scorer import OSSWorkflow

    # Build a workflow with geo explicitly enabled
    geo_config = {
        **MINIMAL_CONFIG,
        'risk': {
            'geo_compliance': {
                'enabled': True,
                'high_risk_countries': ['XX'],
            }
        }
    }
    workflow = _make_workflow()
    workflow.config = geo_config

    results_with_geo = {
        'github_metrics': {'forks': 10_000},
        # 100% high-risk contributors — would drag trust to 0 if blended
        'contributor_locations': [
            {'country_code': 'XX', 'contributions': 1000},
        ],
    }
    score = workflow._calculate_trust_score(results_with_geo)
    # Trust must equal maturity (100) regardless of contributor locations
    assert score == 100.0, (
        f"Trust score must equal maturity (100), not blend geo; got {score}"
    )


def test_evaluate_component_geo_compliance_separate_section():
    """When geo is enabled, compliance.geo_jurisdiction appears without affecting trust."""
    workflow = _make_workflow()

    # Enable geo compliance in the workflow config
    import copy
    workflow.config = copy.deepcopy(MINIMAL_CONFIG)
    workflow.config['risk'] = {
        'geo_compliance': {
            'enabled': True,
            'high_risk_countries': ['XX'],
        }
    }
    # Also update scorer config so _calculate_geo_risk_score uses correct cfg
    workflow.scorer.config = workflow.config

    ok_cve = {
        'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0,
        'epss_high': 0, 'max_epss': 0.0, 'cves': [],
        'last_updated': '2026-01-01', 'status': 'success', 'error': None,
    }
    ok_osv = {
        'total': 0, 'malicious_count': 0, 'is_malicious': False,
        'malicious_ids': [], 'extra_advisories': 0, 'advisories': [],
        'last_updated': '2026-01-01', 'status': 'success', 'error': None,
    }

    import unittest.mock as mock
    with mock.patch.object(workflow.scorer, 'check_cves', return_value=ok_cve), \
         mock.patch.object(workflow.scorer, 'check_osv', return_value=ok_osv), \
         mock.patch.object(workflow.scorer, 'get_download_count', return_value={
             'weekly_downloads': 50000, 'period': 'weekly', 'registry': 'npm',
             'status': 'success', 'error': None,
         }):

        result = workflow.evaluate_component({
            'package_name': 'some-pkg',
            'ecosystem': 'npm',
            'criticality': 'Non-Critical',
            # contributor_locations is normally populated from GitHub; inject directly
            'contributor_locations': [
                {'country_code': 'XX', 'contributions': 500},
            ],
        })

    # Compliance section must be present
    assert 'compliance' in result, "Expected 'compliance' key in result"
    assert 'geo_jurisdiction' in result['compliance']
    geo = result['compliance']['geo_jurisdiction']
    assert geo['affects_technical_score'] is False
    assert 'score' in geo
    assert 'status' in geo

    # Trust score must still equal maturity — contributor locations should not affect it
    trust_score = result['scores']['trust']
    # Without github_metrics forks data, maturity = 50 (neutral)
    assert trust_score == 50.0, (
        f"Trust score must be maturity-only (50.0), got {trust_score}"
    )


# OSV disabled/unsupported status codes
# ---------------------------------------------------------------------------


def test_check_osv_disabled_returns_disabled_status():
    """OSV intentionally disabled should report status='disabled', not 'error'."""
    import copy
    scorer = _make_scorer()
    scorer.config = copy.deepcopy(MINIMAL_CONFIG)
    scorer.config['osv'] = {'enabled': False}

    result = scorer.check_osv('some-pkg', 'npm')
    assert result['status'] == 'disabled', (
        f"Expected 'disabled', got {result['status']!r}"
    )
    assert result['error'] is None


def test_check_osv_unsupported_ecosystem_returns_unsupported_status():
    """Unknown ecosystem should report status='unsupported', not 'error'."""
    scorer = _make_scorer()
    result = scorer.check_osv('some-pkg', 'cobol')
    assert result['status'] == 'unsupported', (
        f"Expected 'unsupported', got {result['status']!r}"
    )
