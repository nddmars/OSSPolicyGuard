from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


def parse_manifest_dependencies(manifest_path: str) -> list[dict[str, str | None]]:
    path = Path(manifest_path)
    if path.suffix == ".json":
        data = json.loads(path.read_text(encoding="utf-8"))
        deps = []
        for section in ("dependencies", "devDependencies"):
            for name, specifier in data.get(section, {}).items():
                deps.append({"name": name, "specifier": str(specifier), "version": None})
        return sorted(deps, key=lambda dependency: str(dependency["name"]))

    deps: list[dict[str, str | None]] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        match = re.match(r"^([A-Za-z0-9_.-]+)", line)
        if match:
            name = match.group(1)
            specifier = line[len(name) :].strip() or None
            version = None
            if specifier and re.fullmatch(r"\s*(?:==|=)?\s*(\d+(?:\.\d+){1,3})\s*", specifier):
                version = re.fullmatch(r"\s*(?:==|=)?\s*(\d+(?:\.\d+){1,3})\s*", specifier).group(1)
            deps.append({"name": name, "specifier": specifier, "version": version})
    return deps


def run_scan(package_name: str, ecosystem: str, version: str | None = None) -> dict[str, Any]:
    command = [
        sys.executable,
        "-m",
        "osspolicyguard.cli",
        "scan",
        package_name,
        "--ecosystem",
        ecosystem,
        "--format",
        "json",
    ]
    if version:
        command.extend(["--package-version", version])
    result = subprocess.run(
        command,
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
    for dependency in deps:
        report = run_scan(dependency["name"], ecosystem, dependency["version"])
        print(json.dumps(report, indent=2))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
