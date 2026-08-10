from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


def parse_manifest_dependencies(manifest_path: str) -> list[str]:
    path = Path(manifest_path)
    if path.suffix == ".json":
        data = json.loads(path.read_text(encoding="utf-8"))
        deps = []
        for section in ("dependencies", "devDependencies"):
            deps.extend(data.get(section, {}).keys())
        return sorted(set(deps))

    deps: list[str] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        match = re.match(r"^([A-Za-z0-9_.-]+)", line)
        if match:
            deps.append(match.group(1))
    return deps


def run_scan(package_name: str, ecosystem: str) -> dict[str, Any]:
    result = subprocess.run(
        [sys.executable, "-m", "osspolicyguard.cli", "scan", package_name, "--ecosystem", ecosystem, "--format", "json"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr or result.stdout)
    return json.loads(result.stdout)


def main() -> int:
    manifest_path = Path("requirements.txt")
    ecosystem = "pypi"
    if Path("package.json").exists():
        manifest_path = Path("package.json")
        ecosystem = "npm"
    elif not manifest_path.exists():
        raise SystemExit("No supported manifest found")

    deps = parse_manifest_dependencies(str(manifest_path))
    for package_name in deps:
        report = run_scan(package_name, ecosystem)
        print(json.dumps(report, indent=2))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
