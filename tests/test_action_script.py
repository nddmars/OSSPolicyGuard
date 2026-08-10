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

    assert deps == ["requests", "pytest"]


def test_parse_package_json(tmp_path):
    manifest = tmp_path / "package.json"
    manifest.write_text('{"dependencies": {"react": "^18.0.0"}, "devDependencies": {"vitest": "^1.0.0"}}', encoding="utf-8")

    deps = module.parse_manifest_dependencies(str(manifest))

    assert deps == ["react", "vitest"]
