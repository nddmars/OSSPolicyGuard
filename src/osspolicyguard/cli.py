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
        "generated_at": __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc
        ).isoformat(),
        "policy": {
            "name": "default",
            "version": "0.1.0",
        },
        "package": {
            "name": package_name,
            "ecosystem": ecosystem or "npm",
            "version": None,
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
        "malicious_package_detected": bool(
            result.get("osv_data", {}).get("is_malicious", False)
        ),
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
        "$schema": (
            "https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-schema-2.1.0.json"
        ),
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


def scan_manifest(argv: list[str] | None = None) -> int:
    """Placeholder for OPG-068: manifest scanning not yet implemented."""
    import sys
    print(
        "osspolicyguard manifest: not yet implemented (OPG-068).\n"
        "Use 'osspolicyguard scan <package>' to evaluate a single package.",
        file=sys.stderr,
    )
    return 2  # unsupported-operation — distinct from REVIEW (only set with --review-fails-ci)


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
    scan_parser.add_argument(
        "--ecosystem", default="npm", help="Package ecosystem (default: npm)."
    )
    scan_parser.add_argument(
        "--criticality",
        default="Business Critical",
        help="Business criticality level.",
    )
    scan_parser.add_argument("--repo-url", help="Source repository URL.")
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

    # manifest subcommand  (OPG-068 placeholder)
    subparsers.add_parser(
        "manifest",
        help="Scan a dependency manifest file (not yet implemented; see OPG-068).",
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
            return scan_manifest()

        if args.command != "scan":
            parser.print_help()
            return 0

        result = scan_package(
            package_name=args.package,
            ecosystem=args.ecosystem,
            criticality=args.criticality,
            repo_url=args.repo_url,
            review_fails_ci=args.review_fails_ci,
        )

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
                    "Insufficient data:  Yes "
                    "(one or more security providers were unavailable)"
                )
            findings = result.get("findings", [])
            if findings:
                print()
                print(f"Findings ({len(findings)}):")
                for f in findings:
                    print(
                        f"  [{f.get('severity', '')}] "
                        f"{f.get('code', '')}: {f.get('title', '')}"
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
        logging.getLogger(__name__).error(
            "Configuration error — missing dependency: %s", exc
        )
        return 3
    except (ConnectionError, TimeoutError, urllib.error.URLError) as exc:
        logging.getLogger(__name__).error("Network error: %s", exc)
        return 4
    except Exception as exc:
        logging.getLogger(__name__).error("Internal error: %s", exc, exc_info=True)
        return 99


if __name__ == "__main__":
    raise SystemExit(main())
