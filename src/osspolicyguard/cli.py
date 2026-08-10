from __future__ import annotations

import argparse
import json
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
    decision = result.get("approval", "REVIEW")

    return {
        "schema_version": "1.0",
        "tool_version": __import__("osspolicyguard").__version__,
        "generated_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
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
        "findings": [],
        "evidence": [],
        "warnings": [],
        "malicious_package_detected": bool(result.get("osv_data", {}).get("is_malicious", False)),
        "enforcement": enforcement,
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="osspolicyguard")
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Evaluate a package")
    scan_parser.add_argument("package")
    scan_parser.add_argument("--ecosystem", default="npm")
    scan_parser.add_argument("--criticality", default="Business Critical")
    scan_parser.add_argument("--repo-url")
    scan_parser.add_argument("--format", choices=["text", "json"], default="text")
    scan_parser.add_argument(
        "--review-fails-ci",
        action="store_true",
        help="Treat REVIEW decisions as CI failures.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

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

    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print(f"Package: {result['package']}")
        print(f"Score: {result['score']}/100")
        print(f"Decision: {result['decision']}")
        print(f"Enforcement: {result['enforcement']}")
        print()
        print(f"Security: {result['security']}")
        print(f"Maintenance: {result['maintenance']}")
        print(f"Community: {result['community']}")
        print(f"Supply-chain risk: {result['supply_chain_risk']}")
        print(f"Malicious package detected: {'Yes' if result['malicious_package_detected'] else 'No'}")

    normalized_decision = _normalize_decision(result["decision"])
    if normalized_decision == "PROHIBITED":
        return 1
    if normalized_decision == "REVIEW" and args.review_fails_ci:
        return 2
    return 0


def _normalize_decision(decision: str) -> str:
    normalized = (decision or "").strip().upper()
    if normalized in {"APPROVED", "AUTO-APPROVED"}:
        return "APPROVED"
    if normalized in {"PROHIBITED"}:
        return "PROHIBITED"
    return "REVIEW"


if __name__ == "__main__":
    raise SystemExit(main())
