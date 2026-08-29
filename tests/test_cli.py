import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from osspolicyguard import cli


def _fake_approved(package_name, ecosystem=None, **_kwargs):
    """Reusable fake result for an APPROVED package with no warnings."""
    return {
        "schema_version": "1.0",
        "tool_version": "0.1.0",
        "generated_at": "2026-08-06T00:00:00+00:00",
        "policy": {"name": "default", "version": "0.1.0"},
        "package": {"name": package_name, "ecosystem": ecosystem or "npm", "version": None},
        "score": 84,
        "decision": "APPROVED",
        "dimensions": {"security": 88, "maintenance": 79, "community": 91, "supply_chain_risk": 76},
        "findings": [],
        "evidence": [],
        "warnings": [],
        "malicious_package_detected": False,
        "enforcement": "default",
        "insufficient_data": False,
        "compliance": {},
    }


def test_cli_json_output(monkeypatch, capsys):
    def fake_scan_package(package_name, ecosystem=None, criticality="Non-Critical", repo_url=None, review_fails_ci=False):
        return _fake_approved(package_name, ecosystem)

    monkeypatch.setattr(cli, "scan_package", fake_scan_package)

    exit_code = cli.main(["scan", "express", "--ecosystem", "npm", "--criticality", "Business Critical", "--format", "json"])

    assert exit_code == 0
    body = json.loads(capsys.readouterr().out)
    assert body["package"]["name"] == "express"
    assert body["decision"] == "APPROVED"


def test_cli_human_output(monkeypatch, capsys):
    def fake_scan_package(package_name, ecosystem=None, criticality="Non-Critical", repo_url=None, review_fails_ci=False):
        return _fake_approved(package_name, ecosystem)

    monkeypatch.setattr(cli, "scan_package", fake_scan_package)

    exit_code = cli.main(["scan", "express", "--ecosystem", "npm"])

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "express" in output
    assert "APPROVED" in output
    assert "default" in output


def test_cli_review_fails_ci_exit_code(monkeypatch, capsys):
    def fake_scan_package(package_name, ecosystem=None, criticality="Non-Critical", repo_url=None, review_fails_ci=False):
        return {
            "schema_version": "1.0",
            "tool_version": "0.1.0",
            "generated_at": "2026-08-06T00:00:00+00:00",
            "policy": {"name": "default", "version": "0.1.0"},
            "package": {"name": package_name, "ecosystem": "npm", "version": None},
            "score": 72,
            "decision": "REVIEW",
            "dimensions": {"security": 70, "maintenance": 75, "community": 65, "supply_chain_risk": 60},
            "findings": [],
            "evidence": [],
            "warnings": [],
            "malicious_package_detected": False,
            "enforcement": "review_fails_ci",
            "insufficient_data": False,
            "compliance": {},
        }

    monkeypatch.setattr(cli, "scan_package", fake_scan_package)

    exit_code = cli.main(["scan", "express", "--format", "text", "--review-fails-ci"])
    assert exit_code == 2
    output = capsys.readouterr().out
    assert "REVIEW" in output
    assert "review_fails_ci" in output


def test_cli_prohibited_returns_nonzero(monkeypatch, capsys):
    def fake_scan_package(package_name, ecosystem=None, criticality="Non-Critical", repo_url=None, review_fails_ci=False):
        return {
            "schema_version": "1.0",
            "tool_version": "0.1.0",
            "generated_at": "2026-08-06T00:00:00+00:00",
            "policy": {"name": "default", "version": "0.1.0"},
            "package": {"name": package_name, "ecosystem": "npm", "version": None},
            "score": 30,
            "decision": "PROHIBITED",
            "dimensions": {"security": 10, "maintenance": 20, "community": 30, "supply_chain_risk": 25},
            "findings": [],
            "evidence": [],
            "warnings": [],
            "malicious_package_detected": True,
            "enforcement": "default",
            "insufficient_data": False,
            "compliance": {},
        }

    monkeypatch.setattr(cli, "scan_package", fake_scan_package)

    exit_code = cli.main(["scan", "express", "--format", "text"])
    assert exit_code == 1
    output = capsys.readouterr().out
    assert "PROHIBITED" in output


def test_cli_invalid_command_returns_help(capsys):
    with pytest.raises(SystemExit):
        cli.main(["help"])


# ---------------------------------------------------------------------------
# Round-5 CLI integration tests: insufficient_data and compliance fields
# ---------------------------------------------------------------------------

def test_json_includes_insufficient_data(monkeypatch, capsys):
    """JSON output must include 'insufficient_data' field."""
    monkeypatch.setattr(cli, "scan_package", _fake_approved)
    exit_code = cli.main(["scan", "lodash", "--format", "json"])
    assert exit_code == 0
    body = json.loads(capsys.readouterr().out)
    assert "insufficient_data" in body
    assert body["insufficient_data"] is False


def test_json_includes_compliance(monkeypatch, capsys):
    """JSON output must include 'compliance' field."""
    monkeypatch.setattr(cli, "scan_package", _fake_approved)
    exit_code = cli.main(["scan", "lodash", "--format", "json"])
    assert exit_code == 0
    body = json.loads(capsys.readouterr().out)
    assert "compliance" in body
    assert isinstance(body["compliance"], dict)


def _fake_provider_failure(package_name, ecosystem=None, **_kwargs):
    """Fake result where a security provider was unavailable."""
    return {
        "schema_version": "1.0",
        "tool_version": "0.1.0",
        "generated_at": "2026-08-06T00:00:00+00:00",
        "policy": {"name": "default", "version": "0.1.0"},
        "package": {"name": package_name, "ecosystem": ecosystem or "npm", "version": None},
        "score": 65.0,
        "decision": "REVIEW",
        "dimensions": {"security": 60, "maintenance": 70, "community": 68, "supply_chain_risk": 65},
        "findings": [],
        "evidence": [],
        "warnings": ["NVD provider unavailable: Connection timed out"],
        "malicious_package_detected": False,
        "enforcement": "default",
        "insufficient_data": True,
        "compliance": {},
    }


def test_provider_failure_exit_4(monkeypatch, capsys):
    """insufficient_data=True must produce exit code 4 without --review-fails-ci."""
    monkeypatch.setattr(cli, "scan_package", _fake_provider_failure)
    exit_code = cli.main(["scan", "lodash", "--format", "text"])
    assert exit_code == 4


def test_provider_failure_ignores_review_fails_ci(monkeypatch, capsys):
    """insufficient_data=True must still produce exit code 4 even with --review-fails-ci."""
    monkeypatch.setattr(cli, "scan_package", _fake_provider_failure)
    exit_code = cli.main(["scan", "lodash", "--format", "text", "--review-fails-ci"])
    # Exit 4 takes precedence over exit 2 (--review-fails-ci)
    assert exit_code == 4


def test_text_output_shows_insufficient_data(monkeypatch, capsys):
    """Text format must print an 'Insufficient data' line when insufficient_data=True."""
    monkeypatch.setattr(cli, "scan_package", _fake_provider_failure)
    cli.main(["scan", "lodash", "--format", "text"])
    output = capsys.readouterr().out
    assert "Insufficient data" in output


def test_text_output_shows_provider_warnings(monkeypatch, capsys):
    """Text format must print each provider warning when warnings are present."""
    monkeypatch.setattr(cli, "scan_package", _fake_provider_failure)
    cli.main(["scan", "lodash", "--format", "text"])
    output = capsys.readouterr().out
    assert "NVD provider unavailable" in output
    assert "Provider warnings" in output


def test_markdown_output_shows_insufficient_data_warning(monkeypatch, capsys):
    """Markdown fallback must include the ⚠️ insufficient-data notice."""
    monkeypatch.setattr(cli, "scan_package", _fake_provider_failure)
    # Trigger the markdown fallback (no .reports module in unit-test env)
    cli.main(["scan", "lodash", "--format", "markdown"])
    output = capsys.readouterr().out
    assert "Insufficient data" in output or "insufficient" in output.lower()
