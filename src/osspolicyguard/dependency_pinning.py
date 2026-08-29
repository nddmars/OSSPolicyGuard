"""Dependency pinning policy enforcement (requirements.md §16.1, OPG-139).

Classifies a dependency's version specifier by "range style" (exact pin,
caret/tilde range, wildcard, unbounded range, or "latest"), and checks it
against a configurable pinning policy. Also checks common lockfile formats
(npm package-lock.json, pip-compile-style requirements.txt) for hash-pinned
entries — a manifest can declare an exact version while still resolving an
unverified artifact, so hash-pin enforcement is tracked and configured
separately from range-style enforcement.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

# ---------------------------------------------------------------------------
# Version-specifier classification
# ---------------------------------------------------------------------------

_FLOATING_STYLES = {"caret", "tilde", "wildcard", "latest", "range", "unbounded", "empty"}


def classify_specifier(specifier: str | None) -> str:
    """Return a range-style label for a dependency version specifier.

    One of: ``"exact"``, ``"caret"`` (npm ``^``), ``"tilde"`` (npm/Ruby
    ``~``/``~>``), ``"compatible"`` (PEP 440 ``~=``), ``"wildcard"``
    (``*``/``x``), ``"latest"``, ``"unbounded"`` (a bare ``>=``/``>``),
    ``"range"`` (a bounded multi-clause range), ``"empty"`` (no specifier
    at all — pinned only by a lockfile, if any), or ``"unknown"``.
    """
    if specifier is None:
        return "empty"
    spec = specifier.strip()
    if not spec:
        return "empty"
    lowered = spec.lower()
    if lowered in ("*", "x", "x.x.x"):
        return "wildcard"
    if lowered == "latest":
        return "latest"
    if spec.startswith("^"):
        return "caret"
    if spec.startswith("~>"):
        return "tilde"  # Ruby pessimistic operator
    if spec.startswith("~="):
        return "compatible"  # PEP 440 compatible release
    if spec.startswith("~"):
        return "tilde"
    if re.match(r"^(>=|>)\s*[\w.]+$", spec):
        return "unbounded"
    if re.match(r"^(==|=)?\s*[\w.]+$", spec) and not re.search(r"[<>,]", spec):
        return "exact"
    if "," in spec or re.search(r"[<>]", spec):
        return "range"
    return "unknown"


def is_floating(specifier: str | None) -> bool:
    """Return ``True`` when *specifier* can resolve to more than one version."""
    return classify_specifier(specifier) in _FLOATING_STYLES


# ---------------------------------------------------------------------------
# Pinning policy
# ---------------------------------------------------------------------------

# ``allowed_styles`` lists range styles that pass outright; anything else is
# REVIEW, escalated to PROHIBITED for floating styles when deny_floating is
# set. Override per ecosystem by passing a different policy dict.
DEFAULT_PINNING_POLICY: dict[str, Any] = {
    "allowed_styles": ["exact"],
    "deny_floating": False,
}


@dataclass
class PinningFinding:
    """One dependency's version-pinning evaluation."""

    package_name: str
    raw_specifier: str | None
    range_style: str
    is_floating: bool
    verdict: str = "PASS"  # PASS | REVIEW | PROHIBITED
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "package_name": self.package_name,
            "raw_specifier": self.raw_specifier,
            "range_style": self.range_style,
            "is_floating": self.is_floating,
            "verdict": self.verdict,
            "reason": self.reason,
        }


def evaluate_pinning(
    package_name: str,
    specifier: str | None,
    policy: dict[str, Any] | None = None,
) -> PinningFinding:
    """Evaluate one dependency's version specifier against a pinning policy."""
    policy = policy or DEFAULT_PINNING_POLICY
    style = classify_specifier(specifier)
    floating = is_floating(specifier)
    allowed = policy.get("allowed_styles", DEFAULT_PINNING_POLICY["allowed_styles"])

    if style in allowed:
        return PinningFinding(
            package_name,
            specifier,
            style,
            floating,
            "PASS",
            f"{style!r} specifier is allowed by policy",
        )

    if floating:
        verdict = "PROHIBITED" if policy.get("deny_floating") else "REVIEW"
        reason = (
            f"{style!r} specifier ({specifier!r}) is a floating range "
            f"not in the allowed set {allowed}"
        )
    else:
        verdict = "REVIEW"
        reason = f"{style!r} specifier ({specifier!r}) is not in the allowed set {allowed}"

    return PinningFinding(package_name, specifier, style, floating, verdict, reason)


def _summarize(findings: list[PinningFinding]) -> dict[str, int]:
    counts = {"PASS": 0, "REVIEW": 0, "PROHIBITED": 0}
    for finding in findings:
        counts[finding.verdict] = counts.get(finding.verdict, 0) + 1
    return counts


def build_pinning_report(findings: list[PinningFinding]) -> dict[str, Any]:
    """Machine-readable pinning-policy report (JSON-serializable)."""
    return {
        "schema_version": "1.0",
        "summary": _summarize(findings),
        "packages": [f.to_dict() for f in findings],
    }


def to_pinning_markdown(findings: list[PinningFinding]) -> str:
    """GitHub-PR-comment-friendly Markdown rendering of a pinning report."""
    counts = _summarize(findings)
    lines = [
        "## Dependency Pinning Report",
        "",
        f"**Summary:** {counts['PASS']} pass, {counts['REVIEW']} review, "
        f"{counts['PROHIBITED']} prohibited",
        "",
        "| Package | Specifier | Style | Verdict | Reason |",
        "|---|---|---|---|---|",
    ]
    for finding in findings:
        lines.append(
            f"| {finding.package_name} | {finding.raw_specifier or '(none)'} | "
            f"{finding.range_style} | {finding.verdict} | {finding.reason} |"
        )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# OPG-139: lockfile hash-pin checks
# ---------------------------------------------------------------------------


def check_npm_lockfile_hashes(package_lock: dict[str, Any]) -> dict[str, Any]:
    """Check an npm ``package-lock.json`` (v2/v3 ``"packages"`` layout) for
    missing ``integrity`` hash pins.

    Returns ``{"total": int, "hashed": int, "unhashed": [names]}``.
    """
    packages = package_lock.get("packages", {})
    total = 0
    hashed = 0
    unhashed: list[str] = []
    for path, meta in packages.items():
        if not path or not isinstance(meta, dict):
            continue  # skip the root project entry, keyed by ""
        if meta.get("link"):
            continue  # symlinked/workspace package — no remote artifact to hash
        total += 1
        if meta.get("integrity"):
            hashed += 1
        else:
            unhashed.append(path.rsplit("node_modules/", 1)[-1])
    return {"total": total, "hashed": hashed, "unhashed": unhashed}


def check_requirements_hashes(requirements_text: str) -> dict[str, Any]:
    """Check a pip-compile-style ``requirements.txt`` for ``--hash=`` pins.

    Joins backslash-continued lines before checking, so a hash on a
    continuation line is correctly attributed to its requirement. Returns
    ``{"total": int, "hashed": int, "unhashed": [names]}``.
    """
    logical_lines: list[str] = []
    buffer = ""
    for raw_line in requirements_text.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        piece = line.rstrip("\\").strip()
        buffer = f"{buffer} {piece}" if buffer else piece
        if line.endswith("\\"):
            continue
        logical_lines.append(buffer)
        buffer = ""
    if buffer:
        logical_lines.append(buffer)

    total = 0
    hashed = 0
    unhashed: list[str] = []
    for logical in logical_lines:
        match = re.match(r"^([A-Za-z0-9_.-]+)==", logical)
        if not match:
            continue
        total += 1
        name = match.group(1)
        if "--hash=" in logical:
            hashed += 1
        else:
            unhashed.append(name)
    return {"total": total, "hashed": hashed, "unhashed": unhashed}
