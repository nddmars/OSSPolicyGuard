import json
from pathlib import Path

from jsonschema import validate

from osspolicyguard import __version__
from osspolicyguard import cli


test_root = Path(__file__).resolve().parents[0]


def test_schema_fields_present(monkeypatch, capsys):
    def fake_scan_package(package_name, ecosystem=None, criticality="Non-Critical", repo_url=None, review_fails_ci=False):
        return {
            "schema_version": "1.0",
            "tool_version": __version__,
            "generated_at": "2026-08-06T00:00:00+00:00",
            "policy": {"name": "default", "version": "0.1.0"},
            "package": {"name": package_name, "ecosystem": ecosystem or "npm", "version": None},
            "decision": "APPROVED",
            "score": 84,
            "dimensions": {"security": 88, "maintenance": 79, "community": 91, "supply_chain_risk": 76},
            "findings": [],
            "evidence": [],
            "warnings": [],
            "malicious_package_detected": False,
            "enforcement": "default",
        }

    monkeypatch.setattr(cli, "scan_package", fake_scan_package)

    exit_code = cli.main(["scan", "express", "--format", "json"])
    assert exit_code == 0
    body = json.loads(capsys.readouterr().out)
    assert body["schema_version"] == "1.0"
    assert body["tool_version"] == __version__
    assert body["decision"] == "APPROVED"
    assert body["package"]["name"] == "express"
    assert body["dimensions"]["security"] == 88
    assert body["findings"] == []


def test_schema_validates_against_schema(monkeypatch, capsys):
    def fake_scan_package(package_name, ecosystem=None, criticality="Non-Critical", repo_url=None, review_fails_ci=False):
        return {
            "schema_version": "1.0",
            "tool_version": __version__,
            "generated_at": "2026-08-06T00:00:00+00:00",
            "policy": {"name": "default", "version": "0.1.0"},
            "package": {"name": package_name, "ecosystem": ecosystem or "npm", "version": None},
            "decision": "APPROVED",
            "score": 84,
            "dimensions": {"security": 88, "maintenance": 79, "community": 91, "supply_chain_risk": 76},
            "findings": [],
            "evidence": [],
            "warnings": [],
            "malicious_package_detected": False,
            "enforcement": "default",
        }

    monkeypatch.setattr(cli, "scan_package", fake_scan_package)

    exit_code = cli.main(["scan", "express", "--format", "json"])
    assert exit_code == 0
    body = json.loads(capsys.readouterr().out)

    schema = json.loads((Path(__file__).resolve().parents[1] / "schema.json").read_text(encoding="utf-8"))
    validate(instance=body, schema=schema)


def test_golden_output_matches_snapshot(monkeypatch, capsys):
    def fake_scan_package(package_name, ecosystem=None, criticality="Non-Critical", repo_url=None, review_fails_ci=False):
        return {
            "schema_version": "1.0",
            "tool_version": __version__,
            "generated_at": "2026-08-06T00:00:00+00:00",
            "policy": {"name": "default", "version": "0.1.0"},
            "package": {"name": package_name, "ecosystem": ecosystem or "npm", "version": None},
            "decision": "APPROVED",
            "score": 84,
            "dimensions": {"security": 88, "maintenance": 79, "community": 91, "supply_chain_risk": 76},
            "findings": [],
            "evidence": [],
            "warnings": [],
            "malicious_package_detected": False,
            "enforcement": "default",
        }

    monkeypatch.setattr(cli, "scan_package", fake_scan_package)

    exit_code = cli.main(["scan", "express", "--format", "json"])
    assert exit_code == 0
    body = json.loads(capsys.readouterr().out)

    expected = json.loads((Path(__file__).resolve().parents[0] / "golden" / "small_result.json").read_text(encoding="utf-8"))
    assert body == expected
