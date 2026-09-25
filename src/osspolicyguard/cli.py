from __future__ import annotations

import argparse
import json
import logging
import sys
import urllib.error
from typing import Any


def _normalize_criticality(criticality: str) -> str:
    normalized = (criticality or "Non-Critical").strip().lower().replace("_", "-")
    aliases = {
        "mission-critical": "Mission Critical",
        "business-critical": "Business Critical",
        "non-critical": "Non-Critical",
        "mission": "Mission Critical",
        "business": "Business Critical",
        "noncritical": "Non-Critical",
    }
    return aliases.get(normalized, criticality)


def _normalize_decision(decision: str) -> str:
    normalized = (decision or "").strip().upper()
    if normalized in {"APPROVED", "AUTO-APPROVED"}:
        return "APPROVED"
    if normalized in {"PROHIBITED"}:
        return "PROHIBITED"
    return "REVIEW"


def scan_package(
    package_name: str,
    ecosystem: str | None = None,
    criticality: str = "Non-Critical",
    repo_url: str | None = None,
    review_fails_ci: bool = False,
    version: str | None = None,
    declared_specifier: str | None = None,
) -> dict[str, Any]:
    """Create a simple machine-readable evaluation payload for a package."""
    from oss_scorer import OSSScorer, OSSWorkflow

    scorer = OSSScorer()
    workflow = OSSWorkflow(scorer)

    component = {
        "name": package_name,
        "package_name": package_name,
        "ecosystem": ecosystem or "npm",
        "criticality": _normalize_criticality(criticality),
    }
    if version:
        component["version"] = version
    if repo_url:
        component["repo_url"] = repo_url

    result = workflow.evaluate_component(component)

    enforcement = "review_fails_ci" if review_fails_ci else "default"
    decision = _normalize_decision(result.get("approval", "REVIEW"))

    findings: list[dict] = []
    try:
        from .reports import build_findings

        findings = build_findings(result)
    except ImportError:
        pass

    # Seed warnings from evaluate_component() so provider-failure notices are
    # always present even if EvaluationResult.from_legacy() later raises.
    warnings: list[str] = list(result.get("warnings", []))
    if declared_specifier and not version:
        warnings.append(
            f"Unresolved dependency range for {package_name}: {declared_specifier!r}; "
            "OSV was queried without an exact version"
        )

    # Build evidence from the legacy scorer result.  from_legacy() re-reads
    # result["warnings"] so _eval.warnings already contains the provider warnings;
    # we overwrite warnings here rather than appending to avoid duplicates.
    evidence: list[dict] = []
    try:
        from .models import EvaluationResult

        _eval = EvaluationResult.from_legacy(result, package_name, ecosystem or "npm")
        evidence = [e.to_dict() for e in _eval.evidence]
        warnings = list(_eval.warnings)
    except Exception as exc:
        # from_legacy failed; keep the provider warnings already captured above.
        warnings.append(f"Evidence construction error: {exc}")

    return {
        "schema_version": "1.0",
        "tool_version": __import__("osspolicyguard").__version__,
        "generated_at": __import__("datetime")
        .datetime.now(__import__("datetime").timezone.utc)
        .isoformat(),
        "policy": {
            "name": "default",
            "version": "0.1.0",
        },
        "package": {
            "name": package_name,
            "ecosystem": ecosystem or "npm",
            "version": version,
            "declared_specifier": declared_specifier,
        },
        "decision": decision,
        "score": round(float(result.get("total_score", 0)), 1),
        "dimensions": {
            "security": round(float(result.get("scores", {}).get("security", 0)), 1),
            "maintenance": round(float(result.get("scores", {}).get("activity", 0)), 1),
            "community": round(float(result.get("scores", {}).get("community", 0)), 1),
            "supply_chain_risk": round(float(result.get("scores", {}).get("trust", 0)), 1),
        },
        "findings": findings,
        "evidence": evidence,
        "warnings": warnings,
        "declared_specifier": declared_specifier,
        "malicious_package_detected": bool(result.get("osv_data", {}).get("is_malicious", False)),
        "enforcement": enforcement,
        # Expose safety fields added by evaluate_component() so JSON consumers
        # can distinguish an ordinary policy review from incomplete security data.
        "insufficient_data": bool(result.get("insufficient_data", False)),
        "compliance": result.get("compliance", {}),
    }


def _sarif_stub(result: dict[str, Any]) -> dict[str, Any]:
    """Minimal valid SARIF 2.1.0 stub used when .reports is not importable."""
    pkg_sub = result.get("package") or {}
    if isinstance(pkg_sub, dict):
        pkg_name: str = pkg_sub.get("name") or "unknown"
        pkg_ecosystem: str = pkg_sub.get("ecosystem") or "unknown"
        pkg_version: str | None = pkg_sub.get("version")
    else:
        pkg_name = "unknown"
        pkg_ecosystem = "unknown"
        pkg_version = None
    purl_uri = f"pkg:{pkg_ecosystem}/{pkg_name}@{pkg_version or 'unknown'}"  # noqa: F841
    tool_version: str = result.get("tool_version") or "0.1.0"
    policy_sub = result.get("policy") or {}
    policy_name: str = (
        policy_sub.get("name") if isinstance(policy_sub, dict) else str(policy_sub)
    ) or "default"
    return {
        "$schema": ("https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-schema-2.1.0.json"),
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "OSSPolicyGuard",
                        "version": tool_version,
                        "rules": [],
                    }
                },
                "results": [],
                "properties": {
                    "decision": _normalize_decision(result.get("decision", "")),
                    "score": round(float(result.get("score", 0)), 1),
                    "policyName": policy_name,
                    "generatedAt": result.get("generated_at", ""),
                },
            }
        ],
    }


def parse_manifest_dependencies(manifest_path: str) -> list[dict[str, str | None]]:
    """Extract dependency names, declared specifiers, and resolved versions.

    OPG-068: manifest / multi-package batch evaluation. Mirrors the parsing
    logic in scripts/osspolicyguard_action.py so both entry points agree on
    what counts as a dependency.
    """
    import json as _json
    import re as _re
    from pathlib import Path as _Path

    path = _Path(manifest_path)
    if path.suffix == ".json":
        data = _json.loads(path.read_text(encoding="utf-8"))
        lock_versions: dict[str, str] = {}
        for lock_name in ("package-lock.json", "npm-shrinkwrap.json"):
            lock_path = path.with_name(lock_name)
            if not lock_path.exists():
                continue
            lock_data = _json.loads(lock_path.read_text(encoding="utf-8"))
            for package_path, metadata in lock_data.get("packages", {}).items():
                if package_path.startswith("node_modules/") and isinstance(metadata, dict):
                    lock_versions[package_path.split("node_modules/", 1)[1]] = metadata.get(
                        "version", ""
                    )
            for name, metadata in lock_data.get("dependencies", {}).items():
                if isinstance(metadata, dict) and metadata.get("version"):
                    lock_versions.setdefault(name, metadata["version"])

        deps: list[dict[str, str | None]] = []
        for section in ("dependencies", "devDependencies"):
            for name, specifier in data.get(section, {}).items():
                exact = lock_versions.get(name) or _exact_version(specifier)
                deps.append(
                    {
                        "name": name,
                        "specifier": str(specifier),
                        "version": exact,
                    }
                )
        return sorted(deps, key=lambda dependency: str(dependency["name"]))

    deps = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        match = _re.match(r"^([A-Za-z0-9_.-]+)", line)
        if match:
            name = match.group(1)
            specifier = line[len(name) :].strip() or None
            deps.append(
                {
                    "name": name,
                    "specifier": specifier,
                    "version": _exact_version(specifier),
                }
            )
    return deps


def _exact_version(specifier: Any) -> str | None:
    if not isinstance(specifier, str):
        return None
    match = __import__("re").fullmatch(r"\s*(?:==|=)?\s*(\d+(?:\.\d+){1,3})\s*", specifier)
    return match.group(1) if match else None


def _detect_manifest(explicit_path: str | None) -> tuple[str, str]:
    """Return (manifest_path, ecosystem), auto-detecting when not given explicitly."""
    from pathlib import Path as _Path

    if explicit_path:
        ecosystem = "npm" if explicit_path.endswith(".json") else "pypi"
        return explicit_path, ecosystem
    if _Path("package.json").exists():
        return "package.json", "npm"
    if _Path("requirements.txt").exists():
        return "requirements.txt", "pypi"
    raise FileNotFoundError(
        "No manifest found (looked for package.json, requirements.txt); pass a path explicitly."
    )


def scan_manifest(
    manifest_path: str | None = None,
    ecosystem: str | None = None,
    criticality: str = "Business Critical",
    fmt: str = "text",
    review_fails_ci: bool = False,
) -> int:
    """Scan every dependency declared in a manifest file (OPG-068).

    Evaluates each dependency via scan_package() and aggregates the worst-case
    exit code across all packages, using the same precedence as a single scan
    (see main()'s exit-code contract): PROHIBITED > insufficient_data > REVIEW.
    """
    try:
        path, detected_ecosystem = _detect_manifest(manifest_path)
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 3

    eco = ecosystem or detected_ecosystem
    try:
        packages = parse_manifest_dependencies(path)
    except (OSError, ValueError) as exc:
        print(f"Failed to parse manifest {path!r}: {exc}", file=sys.stderr)
        return 3

    results = [
        scan_package(
            package_name=str(dependency["name"]),
            ecosystem=eco,
            criticality=criticality,
            review_fails_ci=review_fails_ci,
            version=dependency["version"],
            declared_specifier=dependency["specifier"],
        )
        for dependency in packages
    ]

    if fmt == "json":
        print(json.dumps(results, indent=2))
    else:
        print(f"Manifest: {path} ({eco}, {len(results)} package(s))")
        print()
        for result in results:
            pkg = result["package"]
            flags = []
            if result.get("insufficient_data"):
                flags.append("insufficient-data")
            if result.get("malicious_package_detected"):
                flags.append("MALICIOUS")
            suffix = f" [{', '.join(flags)}]" if flags else ""
            print(f"  {pkg['name']:<30} {result['score']:>6}/100  {result['decision']:<11}{suffix}")

    worst_exit = 0
    for result in results:
        decision = _normalize_decision(result["decision"])
        if decision == "PROHIBITED":
            return 1
        if result.get("insufficient_data"):
            worst_exit = max(worst_exit, 4)
        elif decision == "REVIEW" and review_fails_ci:
            worst_exit = max(worst_exit, 2)
    return worst_exit


def scan_license(
    package_name: str | None = None,
    license_text: str | None = None,
    batch_path: str | None = None,
    project_license: str = "permissive",
    policy_path: str | None = None,
    fmt: str = "text",
    notice: bool = False,
    review_fails_ci: bool = False,
) -> int:
    """License compliance check for one package or a batch file (requirements.md §15).

    Single-package mode takes --license directly; batch mode reads a JSON
    file of ``[{"package_name": ..., "license": ..., "copyright": ...}, ...]``
    entries (e.g. produced by a registry-metadata export). --notice switches
    the output to an aggregated NOTICE file (OPG-138) instead of a
    compliance report (OPG-137).
    """
    from .license_compliance import (
        DEFAULT_COMPATIBILITY_POLICY,
        build_license_report,
        evaluate_license,
        generate_notice,
        to_license_markdown,
    )

    policy = DEFAULT_COMPATIBILITY_POLICY
    if policy_path:
        try:
            with open(policy_path, encoding="utf-8") as fh:
                policy = json.load(fh)
        except (OSError, ValueError) as exc:
            print(f"Failed to load policy file {policy_path!r}: {exc}", file=sys.stderr)
            return 3

    entries: list[dict[str, Any]]
    if batch_path:
        try:
            with open(batch_path, encoding="utf-8") as fh:
                entries = json.load(fh)
        except (OSError, ValueError) as exc:
            print(f"Failed to load batch file {batch_path!r}: {exc}", file=sys.stderr)
            return 3
    elif package_name:
        entries = [{"package_name": package_name, "license": license_text}]
    else:
        print("Provide a package name with --license, or --batch <file.json>.", file=sys.stderr)
        return 3

    if notice:
        print(generate_notice(entries))
        return 0

    try:
        findings = [
            evaluate_license(
                entry.get("package_name", "unknown"),
                entry.get("license"),
                project_license,
                policy=policy,
            )
            for entry in entries
        ]
    except (TypeError, ValueError) as exc:
        print(f"Invalid license policy: {exc}", file=sys.stderr)
        return 3

    if fmt == "json":
        print(json.dumps(build_license_report(findings), indent=2))
    elif fmt == "markdown":
        print(to_license_markdown(findings))
    else:
        for finding in findings:
            license_display = (
                ", ".join(finding.spdx_ids)
                if finding.spdx_ids
                else (finding.raw_license or "unknown")
            )
            print(f"{finding.package_name}: {license_display} -> {finding.verdict}")
            print(f"  {finding.reason}")

    if any(f.verdict == "PROHIBITED" for f in findings):
        return 1
    if review_fails_ci and any(f.verdict == "REVIEW" for f in findings):
        return 2
    return 0


def scan_pinning(
    package_name: str | None = None,
    specifier: str | None = None,
    batch_path: str | None = None,
    lockfile_path: str | None = None,
    lockfile_type: str | None = None,
    deny_floating: bool = False,
    fmt: str = "text",
    review_fails_ci: bool = False,
) -> int:
    """Dependency pinning policy check (requirements.md §16.1, OPG-139).

    Single-package mode takes --specifier directly; --batch reads a JSON
    file of ``[{"package_name": ..., "specifier": ...}, ...]``; --lockfile
    (with --lockfile-type npm|pip) instead runs a hash-pin check over an
    npm package-lock.json or pip-compile-style requirements.txt.
    """
    from .dependency_pinning import (
        DEFAULT_PINNING_POLICY,
        build_pinning_report,
        check_npm_lockfile_hashes,
        check_requirements_hashes,
        evaluate_pinning,
        to_pinning_markdown,
    )

    if lockfile_path:
        try:
            with open(lockfile_path, encoding="utf-8") as fh:
                content = fh.read()
        except OSError as exc:
            print(f"Failed to read lockfile {lockfile_path!r}: {exc}", file=sys.stderr)
            return 3

        lf_type = lockfile_type or ("npm" if lockfile_path.endswith(".json") else "pip")
        if lf_type == "npm":
            try:
                stats = check_npm_lockfile_hashes(json.loads(content))
            except ValueError as exc:
                print(f"Failed to parse lockfile {lockfile_path!r}: {exc}", file=sys.stderr)
                return 3
        else:
            stats = check_requirements_hashes(content)

        if fmt == "json":
            print(json.dumps(stats, indent=2))
        else:
            print(f"Lockfile: {lockfile_path} ({lf_type})")
            print(f"  {stats['hashed']}/{stats['total']} dependencies are hash-pinned")
            if stats["unhashed"]:
                print(f"  Missing hash pins: {', '.join(stats['unhashed'])}")

        if stats["unhashed"] and review_fails_ci:
            return 2
        return 0

    entries: list[dict[str, Any]]
    if batch_path:
        try:
            with open(batch_path, encoding="utf-8") as fh:
                entries = json.load(fh)
        except (OSError, ValueError) as exc:
            print(f"Failed to load batch file {batch_path!r}: {exc}", file=sys.stderr)
            return 3
    elif package_name:
        entries = [{"package_name": package_name, "specifier": specifier}]
    else:
        print(
            "Provide a package name with --specifier, --batch <file.json>, "
            "or --lockfile <path>.",
            file=sys.stderr,
        )
        return 3

    policy = dict(DEFAULT_PINNING_POLICY)
    policy["deny_floating"] = deny_floating

    findings = [
        evaluate_pinning(
            entry.get("package_name", "unknown"), entry.get("specifier"), policy=policy
        )
        for entry in entries
    ]

    if fmt == "json":
        print(json.dumps(build_pinning_report(findings), indent=2))
    elif fmt == "markdown":
        print(to_pinning_markdown(findings))
    else:
        for finding in findings:
            print(
                f"{finding.package_name}: {finding.raw_specifier or '(none)'} "
                f"[{finding.range_style}] -> {finding.verdict}"
            )
            print(f"  {finding.reason}")

    if any(f.verdict == "PROHIBITED" for f in findings):
        return 1
    if review_fails_ci and any(f.verdict == "REVIEW" for f in findings):
        return 2
    return 0


def scan_eol(
    product: str | None = None,
    cycle: str | None = None,
    batch_path: str | None = None,
    as_of: str | None = None,
    prohibit_past_eol: bool = False,
    fmt: str = "text",
    review_fails_ci: bool = False,
) -> int:
    """End-of-life / deprecation check (requirements.md §16.2, OPG-140)."""
    import datetime as _datetime

    from .eol import build_eol_report, check_eol, to_eol_markdown

    as_of_date = None
    if as_of:
        try:
            as_of_date = _datetime.datetime.strptime(as_of, "%Y-%m-%d").date()
        except ValueError:
            print(f"Invalid --as-of date {as_of!r}; expected YYYY-MM-DD.", file=sys.stderr)
            return 3

    entries: list[dict[str, Any]]
    if batch_path:
        try:
            with open(batch_path, encoding="utf-8") as fh:
                entries = json.load(fh)
        except (OSError, ValueError) as exc:
            print(f"Failed to load batch file {batch_path!r}: {exc}", file=sys.stderr)
            return 3
    elif product and cycle:
        entries = [{"product": product, "cycle": cycle}]
    else:
        print("Provide a product and cycle, or --batch <file.json>.", file=sys.stderr)
        return 3

    findings = [
        check_eol(
            entry["product"],
            entry["cycle"],
            as_of=as_of_date,
            prohibit_past_eol=prohibit_past_eol,
        )
        for entry in entries
    ]

    if fmt == "json":
        print(json.dumps(build_eol_report(findings), indent=2))
    elif fmt == "markdown":
        print(to_eol_markdown(findings))
    else:
        for finding in findings:
            print(f"{finding.product} {finding.cycle}: {finding.verdict}")
            print(f"  {finding.reason}")

    if any(f.verdict == "PROHIBITED" for f in findings):
        return 1
    if review_fails_ci and any(f.verdict == "REVIEW" for f in findings):
        return 2
    return 0


def _get_version() -> str:
    try:
        import importlib.metadata

        return importlib.metadata.version("osspolicyguard")
    except Exception:
        try:
            import osspolicyguard

            return osspolicyguard.__version__
        except Exception:
            return "0.1.0"


def _build_parser() -> argparse.ArgumentParser:
    _version = _get_version()

    parser = argparse.ArgumentParser(prog="osspolicyguard")
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="WARNING",
        metavar="LEVEL",
        help="Logging verbosity: DEBUG, INFO, WARNING, ERROR (default: WARNING).",
    )

    subparsers = parser.add_subparsers(dest="command")

    # version subcommand
    subparsers.add_parser("version", help="Print the tool version and exit.")

    # scan subcommand  (OPG-067)
    scan_parser = subparsers.add_parser("scan", help="Evaluate a single package.")
    scan_parser.add_argument("package", help="Package name to evaluate.")
    scan_parser.add_argument("--ecosystem", default="npm", help="Package ecosystem (default: npm).")
    scan_parser.add_argument(
        "--criticality",
        default="Business Critical",
        help="Business criticality level.",
    )
    scan_parser.add_argument("--repo-url", help="Source repository URL.")
    scan_parser.add_argument(
        "--package-version", dest="package_version", help="Exact package version to scan."
    )
    scan_parser.add_argument(
        "--format",
        choices=["text", "json", "sarif", "markdown"],
        default="text",
        help="Output format: text, json, sarif, markdown (default: text).",
    )
    scan_parser.add_argument(
        "--review-fails-ci",
        action="store_true",
        help="Treat REVIEW decisions as CI failures (exit code 2).",
    )
    scan_parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {_version}",
        help="Print version and exit.",
    )

    # manifest subcommand  (OPG-068)
    manifest_parser = subparsers.add_parser(
        "manifest", help="Scan every dependency declared in a manifest file."
    )
    manifest_parser.add_argument(
        "path",
        nargs="?",
        help="Manifest file to scan (default: auto-detect package.json or requirements.txt).",
    )
    manifest_parser.add_argument(
        "--ecosystem", help="Override the ecosystem inferred from the manifest file type."
    )
    manifest_parser.add_argument(
        "--criticality",
        default="Business Critical",
        help="Business criticality level applied to every dependency.",
    )
    manifest_parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format: text, json (default: text).",
    )
    manifest_parser.add_argument(
        "--review-fails-ci",
        action="store_true",
        help="Treat any REVIEW decision as a CI failure (exit code 2).",
    )

    # license subcommand  (requirements.md §15, OPG-133..138)
    license_parser = subparsers.add_parser(
        "license", help="Check a package's declared license for compliance."
    )
    license_parser.add_argument(
        "package", nargs="?", help="Package name (used with --license for single-package mode)."
    )
    license_parser.add_argument(
        "--license", dest="license_text", help="The package's declared license string."
    )
    license_parser.add_argument(
        "--batch",
        dest="batch_path",
        help='JSON file of [{"package_name": ..., "license": ..., "copyright": ...}, ...].',
    )
    license_parser.add_argument(
        "--project-license",
        choices=["permissive", "weak-copyleft", "strong-copyleft", "unrestricted"],
        default="permissive",
        help="This project's own license category, used to select the compatibility policy.",
    )
    license_parser.add_argument(
        "--policy-file",
        dest="policy_path",
        help="JSON file overriding the default compatibility policy (custom allow/review/deny rules).",
    )
    license_parser.add_argument(
        "--format",
        choices=["text", "json", "markdown"],
        default="text",
        help="Output format: text, json, markdown (default: text).",
    )
    license_parser.add_argument(
        "--notice",
        action="store_true",
        help="Emit an aggregated NOTICE file instead of a compliance report (OPG-138).",
    )
    license_parser.add_argument(
        "--review-fails-ci",
        action="store_true",
        help="Treat any REVIEW verdict as a CI failure (exit code 2).",
    )

    # pinning subcommand  (requirements.md §16.1, OPG-139)
    pinning_parser = subparsers.add_parser(
        "pinning", help="Check dependency version specifiers against a pinning policy."
    )
    pinning_parser.add_argument(
        "package", nargs="?", help="Package name (used with --specifier for single-package mode)."
    )
    pinning_parser.add_argument(
        "--specifier", help="The package's declared version specifier (e.g. '^1.2.3')."
    )
    pinning_parser.add_argument(
        "--batch",
        dest="batch_path",
        help='JSON file of [{"package_name": ..., "specifier": ...}, ...].',
    )
    pinning_parser.add_argument(
        "--lockfile",
        dest="lockfile_path",
        help="Check a lockfile for hash-pinned entries instead of a range-style policy.",
    )
    pinning_parser.add_argument(
        "--lockfile-type",
        choices=["npm", "pip"],
        help="Lockfile format (default: inferred from the file extension).",
    )
    pinning_parser.add_argument(
        "--deny-floating",
        action="store_true",
        help="Escalate any floating (non-exact) specifier to PROHIBITED.",
    )
    pinning_parser.add_argument(
        "--format",
        choices=["text", "json", "markdown"],
        default="text",
        help="Output format: text, json, markdown (default: text).",
    )
    pinning_parser.add_argument(
        "--review-fails-ci",
        action="store_true",
        help="Treat any REVIEW verdict (or unhashed lockfile entry) as a CI failure (exit code 2).",
    )

    # eol subcommand  (requirements.md §16.2, OPG-140)
    eol_parser = subparsers.add_parser(
        "eol", help="Check a language runtime/platform version against its end-of-life date."
    )
    eol_parser.add_argument("product", nargs="?", help="Product name, e.g. 'python'.")
    eol_parser.add_argument("cycle", nargs="?", help="Release cycle, e.g. '3.8'.")
    eol_parser.add_argument(
        "--batch",
        dest="batch_path",
        help='JSON file of [{"product": ..., "cycle": ...}, ...].',
    )
    eol_parser.add_argument(
        "--as-of", help="Evaluate as of this date (YYYY-MM-DD) instead of today."
    )
    eol_parser.add_argument(
        "--prohibit-past-eol",
        action="store_true",
        help="Escalate a past-end-of-life product/cycle to PROHIBITED instead of REVIEW.",
    )
    eol_parser.add_argument(
        "--format",
        choices=["text", "json", "markdown"],
        default="text",
        help="Output format: text, json, markdown (default: text).",
    )
    eol_parser.add_argument(
        "--review-fails-ci",
        action="store_true",
        help="Treat any REVIEW verdict as a CI failure (exit code 2).",
    )

    return parser


def main(argv: list[str] | None = None) -> int:  # noqa: C901
    try:
        parser = _build_parser()
        args = parser.parse_args(argv)

        # Configure logging as early as possible.  Use the project's own
        # configure_logging() so that the redacting filter is attached to the
        # handler (not just the root logger) and secrets are scrubbed from all
        # propagated child-logger records.
        log_level: str = getattr(args, "log_level", "WARNING")
        try:
            from .logging_config import configure_logging

            configure_logging(level=log_level, json_output=False)
        except ImportError:
            logging.basicConfig(
                level=getattr(logging, log_level, logging.WARNING),
                format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
                stream=sys.stderr,
            )

        if args.command == "version":
            print(_get_version())
            return 0

        if args.command == "manifest":
            return scan_manifest(
                manifest_path=args.path,
                ecosystem=args.ecosystem,
                criticality=args.criticality,
                fmt=args.format,
                review_fails_ci=args.review_fails_ci,
            )

        if args.command == "license":
            return scan_license(
                package_name=args.package,
                license_text=args.license_text,
                batch_path=args.batch_path,
                project_license=args.project_license,
                policy_path=args.policy_path,
                fmt=args.format,
                notice=args.notice,
                review_fails_ci=args.review_fails_ci,
            )

        if args.command == "pinning":
            return scan_pinning(
                package_name=args.package,
                specifier=args.specifier,
                batch_path=args.batch_path,
                lockfile_path=args.lockfile_path,
                lockfile_type=args.lockfile_type,
                deny_floating=args.deny_floating,
                fmt=args.format,
                review_fails_ci=args.review_fails_ci,
            )

        if args.command == "eol":
            return scan_eol(
                product=args.product,
                cycle=args.cycle,
                batch_path=args.batch_path,
                as_of=args.as_of,
                prohibit_past_eol=args.prohibit_past_eol,
                fmt=args.format,
                review_fails_ci=args.review_fails_ci,
            )

        if args.command != "scan":
            parser.print_help()
            return 0

        scan_kwargs: dict[str, Any] = {
            "package_name": args.package,
            "ecosystem": args.ecosystem,
            "criticality": args.criticality,
            "repo_url": args.repo_url,
            "review_fails_ci": args.review_fails_ci,
        }
        if args.package_version:
            scan_kwargs["version"] = args.package_version
        result = scan_package(**scan_kwargs)

        fmt: str = args.format
        if fmt == "json":
            print(json.dumps(result, indent=2))

        elif fmt == "sarif":
            sarif_doc: dict[str, Any]
            try:
                from .reports import to_sarif

                sarif_doc = to_sarif(result)
            except ImportError:
                sarif_doc = _sarif_stub(result)
            print(json.dumps(sarif_doc, indent=2))

        elif fmt == "markdown":
            try:
                from .reports import to_markdown_pr

                print(to_markdown_pr(result))
            except ImportError:
                pkg = result.get("package") or {}
                pkg_name = pkg.get("name", "unknown") if isinstance(pkg, dict) else "unknown"
                decision_raw = result.get("decision", "")
                decision_md = _normalize_decision(decision_raw)
                score_md = result.get("score", 0)
                md_lines = [
                    "## OSSPolicyGuard Scan",
                    "",
                    f"**Package:** `{pkg_name}`",
                    "",
                    f"**Decision:** {decision_md}",
                    "",
                    f"**Score:** {score_md}/100",
                ]
                if result.get("insufficient_data"):
                    md_lines += [
                        "",
                        "> ⚠️ **Insufficient data** — one or more security providers "
                        "were unavailable; results may be incomplete.",
                    ]
                warnings_list = result.get("warnings", [])
                if warnings_list:
                    md_lines += ["", "**Provider warnings:**"]
                    md_lines += [f"- {w}" for w in warnings_list]
                print("\n".join(md_lines))

        else:
            # text format (default)
            pkg = result["package"]
            dims = result["dimensions"]
            print(f"Package:   {pkg['name']} ({pkg['ecosystem']})")
            print(f"Score:     {result['score']}/100")
            print(f"Decision:  {result['decision']}")
            print(f"Enforcement: {result['enforcement']}")
            print()
            print(f"Security:          {dims['security']}")
            print(f"Maintenance:       {dims['maintenance']}")
            print(f"Community:         {dims['community']}")
            print(f"Supply-chain risk: {dims['supply_chain_risk']}")
            print(
                f"Malicious package detected: "
                f"{'Yes' if result['malicious_package_detected'] else 'No'}"
            )
            if result.get("insufficient_data"):
                print(
                    "Insufficient data:  Yes " "(one or more security providers were unavailable)"
                )
            findings = result.get("findings", [])
            if findings:
                print()
                print(f"Findings ({len(findings)}):")
                for f in findings:
                    print(
                        f"  [{f.get('severity', '')}] " f"{f.get('code', '')}: {f.get('title', '')}"
                    )
            warnings_list = result.get("warnings", [])
            if warnings_list:
                print()
                print(f"Provider warnings ({len(warnings_list)}):")
                for w in warnings_list:
                    print(f"  - {w}")

        normalized_decision = _normalize_decision(result["decision"])
        if normalized_decision == "PROHIBITED":
            return 1
        # Exit 4 when required security providers were unavailable.  This takes
        # precedence over --review-fails-ci so automation cannot mistake an
        # incomplete scan for a successful one.
        if result.get("insufficient_data"):
            return 4
        if normalized_decision == "REVIEW" and args.review_fails_ci:
            return 2
        return 0

    except ImportError as exc:
        logging.getLogger(__name__).error("Configuration error — missing dependency: %s", exc)
        return 3
    except (ConnectionError, TimeoutError, urllib.error.URLError) as exc:
        logging.getLogger(__name__).error("Network error: %s", exc)
        return 4
    except Exception as exc:
        logging.getLogger(__name__).error("Internal error: %s", exc, exc_info=True)
        return 99


if __name__ == "__main__":
    raise SystemExit(main())
