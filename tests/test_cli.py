import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from osspolicyguard import cli


def test_cli_json_output(monkeypatch, capsys):
    def fake_scan_package(package_name, ecosystem=None, criticality="Non-Critical", repo_url=None, review_fails_ci=False):
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
        }

    monkeypatch.setattr(cli, "scan_package", fake_scan_package)

    exit_code = cli.main(["scan", "express", "--ecosystem", "npm", "--criticality", "Business Critical", "--format", "json"])

    assert exit_code == 0
    body = json.loads(capsys.readouterr().out)
    assert body["package"]["name"] == "express"
    assert body["decision"] == "APPROVED"


def test_cli_human_output(monkeypatch, capsys):
    def fake_scan_package(package_name, ecosystem=None, criticality="Non-Critical", repo_url=None, review_fails_ci=False):
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
        }

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
        }

    monkeypatch.setattr(cli, "scan_package", fake_scan_package)

    exit_code = cli.main(["scan", "express", "--format", "text"])
    assert exit_code == 1
    output = capsys.readouterr().out
    assert "PROHIBITED" in output


def test_cli_invalid_command_returns_help(capsys):
    with pytest.raises(SystemExit):
        cli.main(["help"])
