import json
from pathlib import Path
import importlib.util

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "osspolicyguard_action.py"

spec = importlib.util.spec_from_file_location("osspolicyguard_action", MODULE_PATH)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_parse_requirements_file(tmp_path):
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("requests>=2\n# comment\npytest\n", encoding="utf-8")

    deps = module.parse_manifest_dependencies(str(manifest))

    assert deps == [
        {"name": "requests", "specifier": ">=2", "version": None},
        {"name": "pytest", "specifier": None, "version": None},
    ]


def test_parse_package_json(tmp_path):
    manifest = tmp_path / "package.json"
    manifest.write_text(
        '{"dependencies": {"react": "^18.0.0"}, "devDependencies": {"vitest": "^1.0.0"}}',
        encoding="utf-8",
    )

    deps = module.parse_manifest_dependencies(str(manifest))

    assert deps == [
        {"name": "react", "specifier": "^18.0.0", "version": None},
        {"name": "vitest", "specifier": "^1.0.0", "version": None},
    ]


def test_parse_package_json_uses_lockfile_version(tmp_path):
    manifest = tmp_path / "package.json"
    manifest.write_text('{"dependencies": {"react": "^18.0.0"}}', encoding="utf-8")
    (tmp_path / "package-lock.json").write_text(
        '{"packages": {"node_modules/react": {"version": "18.2.0"}}}', encoding="utf-8"
    )

    assert module.parse_manifest_dependencies(str(manifest)) == [
        {"name": "react", "specifier": "^18.0.0", "version": "18.2.0"}
    ]


def test_main_aggregates_scan_failures(tmp_path, monkeypatch, capsys):
    (tmp_path / "requirements.txt").write_text("requests\nflask\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    def fake_run_scan(name, ecosystem, version=None):
        if name == "flask":
            raise module.ScanError(4, "OSV unavailable")
        return {
            "package": {"name": name, "ecosystem": ecosystem, "version": version},
            "decision": "APPROVED",
            "insufficient_data": False,
        }

    monkeypatch.setattr(module, "run_scan", fake_run_scan)

    assert module.main() == 4
    report = json.loads(capsys.readouterr().out)
    assert [item["package"]["name"] for item in report["dependencies"]] == [
        "requests",
        "flask",
    ]
    failure = next(item for item in report["dependencies"] if item["package"]["name"] == "flask")
    assert failure["provider_statuses"] == {"scan": "error"}
    assert failure["warnings"] == ["OSV unavailable"]


def test_run_scan_preserves_json_for_nonzero_exit(monkeypatch):
    completed = type(
        "CompletedProcess",
        (),
        {"returncode": 4, "stdout": '{"decision": "REVIEW"}', "stderr": ""},
    )()
    monkeypatch.setattr(module.subprocess, "run", lambda *args, **kwargs: completed)

    assert module.run_scan("requests", "pypi") == ({"decision": "REVIEW"}, 4)


def test_main_preserves_configuration_exit_code(tmp_path, monkeypatch, capsys):
    (tmp_path / "requirements.txt").write_text("requests\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        module,
        "run_scan",
        lambda *args: (_ for _ in ()).throw(module.ScanError(3, "bad configuration")),
    )

    assert module.main() == 3
    report = json.loads(capsys.readouterr().out)["dependencies"][0]
    assert report["insufficient_data"] is False
    assert report["provider_statuses"] == {"scan": "configuration_error"}
