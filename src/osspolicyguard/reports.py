"""OPG-061 / OPG-070 / OPG-072 — Reason-coded findings, SARIF 2.1.0, and Markdown PR reports.

This module is intentionally **standalone**: it imports nothing from .models so
that it can be used without risk of circular imports.  All inputs and outputs
are plain Python dicts / strings (fully JSON-serialisable).

Public API
----------
build_findings(evaluation)  → list[dict]   OPG-061
to_sarif(result, ...)       → dict          OPG-070
to_markdown_pr(result, ...) → str           OPG-072
"""

from __future__ import annotations

import json
import textwrap
from datetime import datetime, timezone
from typing import Any

__all__ = ["build_findings", "to_sarif", "to_markdown_pr"]

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_WIKI_BASE = "https://github.com/nddmars/OSSPolicyGuard/wiki/"
_REPO_URL = "https://github.com/nddmars/OSSPolicyGuard"

# Severity → SARIF level mapping
_SARIF_LEVEL: dict[str, str] = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}

# Decision → emoji badge
_DECISION_BADGE: dict[str, str] = {
    "APPROVED": "🟢",
    "AUTO-APPROVED": "🟢",
    "REVIEW": "🟡",
    "REVIEW BOARD": "🟡",
    "MITIGATION REQ": "🟡",
    "MITIGATION REQUIRED": "🟡",
    "PROHIBITED": "🔴",
}


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sarif_level(severity: str) -> str:
    return _SARIF_LEVEL.get(severity.upper(), "none")


def _decision_badge(decision: str) -> str:
    normalized = (decision or "").strip().upper()
    return _DECISION_BADGE.get(normalized, "🟡")


def _normalize_decision(decision: str) -> str:
    """Collapse legacy variants to the canonical three-value set."""
    normalized = (decision or "").strip().upper()
    if normalized in {"APPROVED", "AUTO-APPROVED"}:
        return "APPROVED"
    if normalized == "PROHIBITED":
        return "PROHIBITED"
    return "REVIEW"


# ---------------------------------------------------------------------------
# 1. FINDINGS BUILDER  (OPG-061)
# ---------------------------------------------------------------------------


def build_findings(evaluation: dict) -> list[dict]:
    """Produce stable reason-coded findings from a legacy evaluate_component() result dict.

    Parameters
    ----------
    evaluation:
        The raw dict returned by ``OSSWorkflow.evaluate_component()``.

    Returns
    -------
    list[dict]
        Each finding dict contains: code, title, severity, dimension,
        score_effect, evidence_refs, policy_rule, remediation, confidence.
    """
    findings: list[dict] = []

    scores: dict[str, Any] = evaluation.get("scores", {})
    osv_data: dict[str, Any] = evaluation.get("osv_data", {})
    cve_data: dict[str, Any] = evaluation.get("cve_data", {})

    cves: list[dict] = cve_data.get("cves", [])
    cve_ids: list[str] = [c.get("id", "") for c in cves if c.get("id")]
    epss_high: int = int(cve_data.get("epss_high", 0))
    extra_advisories: int = int(osv_data.get("extra_advisories", 0))

    # ------------------------------------------------------------------
    # Supply-chain / malicious
    # ------------------------------------------------------------------

    if osv_data.get("is_malicious"):
        malicious_ids: list[str] = osv_data.get("malicious_ids", [])
        findings.append(
            {
                "code": "OPG-MAL-001",
                "title": "Malicious package detected",
                "severity": "CRITICAL",
                "dimension": "SUPPLY_CHAIN",
                "score_effect": -100,
                "evidence_refs": list(malicious_ids),
                "policy_rule": "malicious_packages.auto_prohibit",
                "remediation": "Remove immediately; do not install.",
                "confidence": 1.0,
            }
        )

    # ------------------------------------------------------------------
    # Security — score thresholds
    # ------------------------------------------------------------------

    security_score: float = float(scores.get("security", 100))

    if security_score < 30:
        findings.append(
            {
                "code": "OPG-SEC-001",
                "title": "Critically low security score",
                "severity": "CRITICAL",
                "dimension": "SECURITY",
                "score_effect": round(security_score - 100, 1),
                "evidence_refs": [],
                "policy_rule": None,
                "remediation": (
                    "Audit all CVEs, enable branch protection, add a security policy, "
                    "and address OpenSSF Scorecard failures."
                ),
                "confidence": 1.0,
            }
        )
    elif security_score < 60:
        findings.append(
            {
                "code": "OPG-SEC-002",
                "title": "Low security score",
                "severity": "HIGH",
                "dimension": "SECURITY",
                "score_effect": round(security_score - 100, 1),
                "evidence_refs": [],
                "policy_rule": None,
                "remediation": (
                    "Review open CVEs, improve OpenSSF Scorecard checks, and add a "
                    "SECURITY.md policy."
                ),
                "confidence": 1.0,
            }
        )

    # ------------------------------------------------------------------
    # Security — CVEs
    # ------------------------------------------------------------------

    if len(cves) > 0:
        findings.append(
            {
                "code": "OPG-SEC-003",
                "title": f"{len(cves)} known CVE(s)",
                "severity": "HIGH",
                "dimension": "SECURITY",
                "score_effect": max(-50, -5 * len(cves)),
                "evidence_refs": cve_ids,
                "policy_rule": None,
                "remediation": (
                    "Upgrade to a patched version or apply vendor-recommended "
                    "mitigations for each listed CVE."
                ),
                "confidence": 1.0,
            }
        )

    if epss_high > 0:
        high_epss_ids: list[str] = [
            c.get("id", "")
            for c in cves
            if c.get("epss", 0.0) >= 0.5 and c.get("id")
        ]
        findings.append(
            {
                "code": "OPG-SEC-004",
                "title": (
                    f"{epss_high} CVE(s) with high exploit probability (EPSS≥0.5)"
                ),
                "severity": "CRITICAL",
                "dimension": "SECURITY",
                "score_effect": max(-50, -15 * epss_high),
                "evidence_refs": high_epss_ids,
                "policy_rule": None,
                "remediation": (
                    "Treat these CVEs as actively weaponised. Upgrade or remove the "
                    "package immediately."
                ),
                "confidence": 1.0,
            }
        )

    if extra_advisories > 0:
        advisory_ids: list[str] = [
            a.get("id", "")
            for a in osv_data.get("advisories", [])
            if a.get("id") and not a.get("id", "").startswith("CVE-")
        ]
        findings.append(
            {
                "code": "OPG-SEC-005",
                "title": (
                    f"{extra_advisories} additional security advisories (GHSA/ecosystem)"
                ),
                "severity": "MEDIUM",
                "dimension": "SECURITY",
                "score_effect": max(-20, -3 * extra_advisories),
                "evidence_refs": advisory_ids,
                "policy_rule": None,
                "remediation": (
                    "Review GHSA and ecosystem-specific advisories and apply "
                    "recommended patches."
                ),
                "confidence": 0.9,
            }
        )

    # ------------------------------------------------------------------
    # Activity / maintenance
    # ------------------------------------------------------------------

    activity_score: float = float(scores.get("activity", 100))

    if activity_score < 40:
        findings.append(
            {
                "code": "OPG-ACT-001",
                "title": "Package appears abandoned or inactive",
                "severity": "HIGH",
                "dimension": "MAINTENANCE",
                "score_effect": round(activity_score - 100, 1),
                "evidence_refs": [],
                "policy_rule": None,
                "remediation": (
                    "Consider migrating to an actively maintained alternative or "
                    "forking and owning the dependency internally."
                ),
                "confidence": 0.85,
            }
        )

    # ------------------------------------------------------------------
    # Trust / supply-chain
    # ------------------------------------------------------------------

    trust_score: float = float(scores.get("trust", 100))

    if trust_score < 40:
        findings.append(
            {
                "code": "OPG-TRU-001",
                "title": "Low maintainer trust score",
                "severity": "MEDIUM",
                "dimension": "SUPPLY_CHAIN",
                "score_effect": round(trust_score - 100, 1),
                "evidence_refs": [],
                "policy_rule": None,
                "remediation": (
                    "Verify maintainer identities, check contributor geolocation risk, "
                    "and consider requiring code-signing or provenance attestations."
                ),
                "confidence": 0.8,
            }
        )

    # ------------------------------------------------------------------
    # Community adoption
    # ------------------------------------------------------------------

    community_score: float = float(scores.get("community", 100))

    if community_score < 40:
        findings.append(
            {
                "code": "OPG-COM-001",
                "title": "Low community adoption",
                "severity": "LOW",
                "dimension": "COMMUNITY",
                "score_effect": round(community_score - 100, 1),
                "evidence_refs": [],
                "policy_rule": None,
                "remediation": (
                    "Prefer widely adopted packages with large communities; small "
                    "ecosystems carry higher long-term maintenance risk."
                ),
                "confidence": 0.75,
            }
        )

    return findings


# ---------------------------------------------------------------------------
# 2. SARIF FORMATTER  (OPG-070)
# ---------------------------------------------------------------------------


def to_sarif(result: dict, tool_version: str = "0.1.0") -> dict:
    """Return a valid SARIF 2.1.0 dict for the given evaluation result.

    Parameters
    ----------
    result:
        Either a legacy ``evaluate_component()`` dict or a new-format
        OSSPolicyGuard result dict (both are accepted).
    tool_version:
        Version string embedded in the SARIF ``tool.driver`` section.

    Returns
    -------
    dict
        A fully populated SARIF 2.1.0 document as a plain Python dict.
    """
    # ---- Resolve findings --------------------------------------------------
    raw_findings: list[dict] | None = result.get("findings")  # type: ignore[assignment]
    findings: list[dict] = raw_findings if raw_findings else build_findings(result)

    # ---- Resolve package coordinates ---------------------------------------
    # Support both new-format (package sub-dict) and legacy (flat keys).
    pkg_sub: dict = result.get("package") or {}
    if isinstance(pkg_sub, dict):
        pkg_ecosystem: str = pkg_sub.get("ecosystem") or result.get("ecosystem") or "unknown"
        pkg_name: str = pkg_sub.get("name") or result.get("name") or result.get("package_name") or "unknown"
        pkg_version: str | None = pkg_sub.get("version") or result.get("version")
    else:
        pkg_ecosystem = result.get("ecosystem") or "unknown"
        pkg_name = result.get("name") or result.get("package_name") or "unknown"
        pkg_version = result.get("version")

    purl_uri = f"pkg:{pkg_ecosystem}/{pkg_name}@{pkg_version or 'unknown'}"

    # ---- Metadata -----------------------------------------------------------
    decision: str = _normalize_decision(result.get("decision") or result.get("approval") or "")
    score: float = float(result.get("score") or result.get("total_score") or 0.0)
    policy_sub: dict = result.get("policy") or {}
    policy_name: str = (
        policy_sub.get("name") if isinstance(policy_sub, dict) else str(policy_sub)
    ) or result.get("policy_name") or "default"
    generated_at: str = result.get("generated_at") or result.get("timestamp") or _now_utc_iso()

    # ---- Build de-duplicated rules list ------------------------------------
    seen_codes: set[str] = set()
    rules: list[dict] = []
    for f in findings:
        code: str = f.get("code", "")
        if code in seen_codes:
            continue
        seen_codes.add(code)
        title: str = f.get("title", "")
        remediation: str | None = f.get("remediation")
        dimension: str = f.get("dimension", "")
        severity: str = f.get("severity", "")
        rules.append(
            {
                "id": code,
                "name": title,
                "shortDescription": {"text": title},
                "helpUri": f"{_WIKI_BASE}{code}",
                "help": {"text": remediation or title},
                "properties": {"tags": [dimension, severity]},
            }
        )

    # ---- Build results list ------------------------------------------------
    sarif_results: list[dict] = []
    for f in findings:
        code = f.get("code", "")
        title = f.get("title", "")
        severity = f.get("severity", "")
        score_effect: float = float(f.get("score_effect", 0.0))
        confidence: float = float(f.get("confidence", 1.0))

        sarif_results.append(
            {
                "ruleId": code,
                "level": _sarif_level(severity),
                "message": {"text": title},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": purl_uri}
                        }
                    }
                ],
                "properties": {
                    "scoreEffect": score_effect,
                    "confidence": confidence,
                },
            }
        )

    # ---- Assemble SARIF document -------------------------------------------
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
                        "informationUri": _REPO_URL,
                        "rules": rules,
                    }
                },
                "results": sarif_results,
                "properties": {
                    "decision": decision,
                    "score": round(score, 1),
                    "policyName": policy_name,
                    "generatedAt": generated_at,
                },
            }
        ],
    }


# ---------------------------------------------------------------------------
# 3. MARKDOWN PR FORMATTER  (OPG-072)
# ---------------------------------------------------------------------------

_MAX_FINDING_ROWS = 20


def to_markdown_pr(result: dict, changed_only: bool = False) -> str:
    """Return bounded Markdown suitable for posting as a pull-request comment.

    Parameters
    ----------
    result:
        Either a legacy ``evaluate_component()`` dict or a new-format
        OSSPolicyGuard result dict.
    changed_only:
        When ``True``, return an empty string if there are no findings so
        that only packages with policy signals generate PR noise.

    Returns
    -------
    str
        GitHub-flavoured Markdown, bounded to at most ``_MAX_FINDING_ROWS``
        finding rows.
    """
    # ---- Resolve findings --------------------------------------------------
    raw_findings: list[dict] | None = result.get("findings")  # type: ignore[assignment]
    findings: list[dict] = raw_findings if raw_findings else build_findings(result)

    if changed_only and not findings:
        return ""

    # ---- Resolve package coordinates ---------------------------------------
    pkg_sub: dict = result.get("package") or {}
    if isinstance(pkg_sub, dict):
        pkg_ecosystem: str = pkg_sub.get("ecosystem") or result.get("ecosystem") or "unknown"
        pkg_name: str = pkg_sub.get("name") or result.get("name") or result.get("package_name") or "unknown"
        pkg_version: str | None = pkg_sub.get("version") or result.get("version")
    else:
        pkg_ecosystem = result.get("ecosystem") or "unknown"
        pkg_name = result.get("name") or result.get("package_name") or "unknown"
        pkg_version = result.get("version")

    pkg_display = f"`{pkg_name}`"
    if pkg_version:
        pkg_display += f" @ {pkg_version}"
    if pkg_ecosystem and pkg_ecosystem != "unknown":
        pkg_display += f" ({pkg_ecosystem})"

    # ---- Resolve metadata --------------------------------------------------
    raw_decision: str = result.get("decision") or result.get("approval") or "REVIEW"
    decision: str = _normalize_decision(raw_decision)
    badge: str = _decision_badge(raw_decision)
    score: float = float(result.get("score") or result.get("total_score") or 0.0)

    policy_sub: dict = result.get("policy") or {}
    policy_name: str = (
        policy_sub.get("name") if isinstance(policy_sub, dict) else str(policy_sub)
    ) or result.get("policy_name") or "default"

    tool_version: str = result.get("tool_version") or "0.1.0"

    # ---- Resolve dimension scores ------------------------------------------
    dimensions: dict = result.get("dimensions") or {}
    scores_legacy: dict = result.get("scores") or {}

    def _dim(new_key: str, legacy_key: str) -> str:
        val = dimensions.get(new_key) or scores_legacy.get(legacy_key)
        if val is None:
            return "N/A"
        return str(round(float(val), 1))

    sec_score = _dim("security", "security")
    maint_score = _dim("maintenance", "activity")
    comm_score = _dim("community", "community")
    sc_score = _dim("supply_chain", "trust") or _dim("supply_chain_risk", "trust")

    # ---- Evidence ----------------------------------------------------------
    evidence: list[dict] = result.get("evidence") or []

    # ---- Build Markdown ----------------------------------------------------
    lines: list[str] = []

    # Header
    lines.append("## \U0001f6e1️ OSSPolicyGuard — Dependency Scan")
    lines.append("")
    lines.append(
        f"**Package:** {pkg_display}  "
    )
    lines.append(
        f"**Decision: {badge} {decision}** | Score: {round(score, 1)}/100 | Policy: {policy_name}"
    )
    lines.append("")

    # Score breakdown
    lines.append("### Score breakdown")
    lines.append("")
    lines.append("| Dimension | Score |")
    lines.append("|---|---|")
    lines.append(f"| Security | {sec_score} |")
    lines.append(f"| Maintenance | {maint_score} |")
    lines.append(f"| Community | {comm_score} |")
    lines.append(f"| Supply-chain | {sc_score} |")
    lines.append("")

    # Findings
    if findings:
        lines.append("### Findings")
        lines.append("")
        lines.append("| Code | Severity | Finding | Score Effect |")
        lines.append("|---|---|---|---|")

        display_findings = findings[:_MAX_FINDING_ROWS]
        for f in display_findings:
            code = f.get("code", "")
            severity = f.get("severity", "")
            title = f.get("title", "")
            effect = f.get("score_effect", 0)
            effect_str = f"{effect:+.0f}" if isinstance(effect, (int, float)) else str(effect)
            lines.append(f"| {code} | {severity} | {title} | {effect_str} |")

        if len(findings) > _MAX_FINDING_ROWS:
            overflow = len(findings) - _MAX_FINDING_ROWS
            lines.append("")
            lines.append(
                f"> **Note:** {overflow} additional finding(s) not shown. "
                "Run a full scan for the complete list."
            )

        lines.append("")
    else:
        lines.append("### Findings")
        lines.append("")
        lines.append("_No policy findings for this package._")
        lines.append("")

    # Evidence freshness
    if evidence:
        lines.append("### Evidence freshness")
        lines.append("")
        lines.append("| Source | Status | Fetched |")
        lines.append("|---|---|---|")
        for ev in evidence:
            if isinstance(ev, dict):
                provider = ev.get("provider", "unknown")
                status = ev.get("status", "unknown")
                fetched = ev.get("fetched_at") or ev.get("last_updated") or ""
                # Trim ISO timestamps to readable length
                if fetched and "T" in fetched:
                    fetched = fetched[:19].replace("T", " ") + " UTC"
                lines.append(f"| {provider} | {status} | {fetched} |")
        lines.append("")

    # Footer
    lines.append(
        f"_Powered by [OSSPolicyGuard]({_REPO_URL}) v{tool_version}_"
    )

    return "\n".join(lines)
