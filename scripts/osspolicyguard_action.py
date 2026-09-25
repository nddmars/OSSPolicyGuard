from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from osspolicyguard.cli import parse_manifest_dependencies


class ScanError(RuntimeError):
    def __init__(self, returncode: int, message: str) -> None:
        super().__init__(message)
        self.returncode = returncode


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
        output = result.stderr or result.stdout
        message = next(
            (line for line in reversed(output.splitlines()) if line.strip()), "scan failed"
        )
        raise ScanError(result.returncode, message)
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
    reports: list[dict[str, Any]] = []
    exit_codes: list[int] = []
    for dependency in deps:
        package = {
            "name": dependency["name"],
            "ecosystem": ecosystem,
            "version": dependency["version"],
        }
        try:
            report = run_scan(dependency["name"], ecosystem, dependency["version"])
        except ScanError as exc:
            exit_codes.append(exc.returncode)
            report = {
                "package": package,
                "decision": "REVIEW",
                "insufficient_data": True,
                "provider_statuses": {"scan": "error"},
                "warnings": [str(exc)],
            }
        except Exception as exc:
            exit_codes.append(99)
            report = {
                "package": package,
                "decision": "REVIEW",
                "insufficient_data": True,
                "provider_statuses": {"scan": "error"},
                "warnings": [f"Unexpected scan error: {exc}"],
            }
        reports.append(report)

        if report.get("decision") == "PROHIBITED":
            exit_codes.append(1)
        elif report.get("insufficient_data"):
            exit_codes.append(4)

    print(json.dumps({"dependencies": reports}, indent=2))

    if 1 in exit_codes:
        return 1
    if 4 in exit_codes:
        return 4
    if 2 in exit_codes:
        return 2
    if 3 in exit_codes:
        return 3
    if 99 in exit_codes:
        return 99

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
