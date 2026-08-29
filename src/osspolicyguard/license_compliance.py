"""License compliance engine (requirements.md §15, OPG-133 through OPG-138).

Identifies a package's declared license, normalizes it to an SPDX
identifier, classifies its copyleft strength, flags dual-licensed /
commercially-restricted terms, checks it against a configurable
compatibility policy, and produces machine-readable reports and
NOTICE-file attribution text.

This module is intentionally independent of OSSConfig/config.yaml so it
can run standalone (e.g. against registry metadata a caller already has)
without requiring a full OSSPolicyGuard configuration file.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# OPG-133: SPDX license detection
# ---------------------------------------------------------------------------

# Common free-form strings seen in PyPI/npm/RubyGems/crates.io registry
# metadata, normalized to a canonical SPDX identifier.
_ALIASES: dict[str, str] = {
    "mit": "MIT",
    "mit license": "MIT",
    "expat": "MIT",
    "apache": "Apache-2.0",
    "apache 2.0": "Apache-2.0",
    "apache2": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache software license": "Apache-2.0",
    "bsd": "BSD-3-Clause",
    "bsd license": "BSD-3-Clause",
    "new bsd license": "BSD-3-Clause",
    "simplified bsd license": "BSD-2-Clause",
    "isc": "ISC",
    "isc license": "ISC",
    "gpl": "GPL-3.0-only",
    "gplv2": "GPL-2.0-only",
    "gpl v2": "GPL-2.0-only",
    "gpl2": "GPL-2.0-only",
    "gplv3": "GPL-3.0-only",
    "gpl v3": "GPL-3.0-only",
    "gpl3": "GPL-3.0-only",
    "gnu general public license v2": "GPL-2.0-only",
    "gnu general public license v3": "GPL-3.0-only",
    "gnu gpl": "GPL-3.0-only",
    "lgpl": "LGPL-3.0-only",
    "lgplv2.1": "LGPL-2.1-only",
    "lgplv3": "LGPL-3.0-only",
    "gnu lesser general public license": "LGPL-3.0-only",
    "agpl": "AGPL-3.0-only",
    "agplv3": "AGPL-3.0-only",
    "gnu affero general public license v3": "AGPL-3.0-only",
    "mpl": "MPL-2.0",
    "mozilla public license 2.0": "MPL-2.0",
    "epl": "EPL-2.0",
    "eclipse public license": "EPL-2.0",
    "eclipse public license 2.0": "EPL-2.0",
    "unlicense": "Unlicense",
    "the unlicense": "Unlicense",
    "cc0": "CC0-1.0",
    "public domain": "CC0-1.0",
    "python software foundation license": "PSF-2.0",
    "psf": "PSF-2.0",
    "psf license": "PSF-2.0",
    "wtfpl": "WTFPL",
    "zlib": "Zlib",
    "zlib license": "Zlib",
    "boost software license 1.0": "BSL-1.0",
}

# Prefixes that identify a string as already being (or closely resembling)
# a valid SPDX identifier, so it is trusted verbatim rather than requiring
# an exact alias match.
_SPDX_LIKE_PREFIXES = (
    "MIT",
    "BSD",
    "APACHE",
    "GPL",
    "LGPL",
    "AGPL",
    "MPL",
    "EPL",
    "ISC",
    "CC0",
    "CC-BY",
    "UNLICENSE",
    "PSF",
    "WTFPL",
    "ZLIB",
    "BSL",
    "0BSD",
)

_SPDX_EXPRESSION_OPERATORS = re.compile(r"\s+(AND|OR|WITH)\s+", re.IGNORECASE)


def normalize_license(raw: str | None) -> str | None:
    """Best-effort normalize a free-form license string to an SPDX identifier.

    Returns ``None`` when *raw* is empty or unrecognized — callers should
    treat that as "unknown", not as a specific (e.g. permissive) category.
    """
    if not raw or not raw.strip():
        return None
    cleaned = raw.strip()
    key = cleaned.lower()
    if key in _ALIASES:
        return _ALIASES[key]
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+-]*", cleaned) and any(
        cleaned.upper().startswith(prefix) for prefix in _SPDX_LIKE_PREFIXES
    ):
        return cleaned
    return None


def parse_spdx_expression(expression: str) -> list[str]:
    """Split a compound SPDX expression (e.g. ``"MIT OR Apache-2.0"``) into
    its individual license identifiers (OPG-133: dual-licensed packages that
    declare more than one SPDX id)."""
    if not expression:
        return []
    parts = _SPDX_EXPRESSION_OPERATORS.split(expression.strip())
    return [
        p.strip().strip("()")
        for p in parts
        if p.strip() and p.strip().upper() not in ("AND", "OR", "WITH")
    ]


# ---------------------------------------------------------------------------
# OPG-134: copyleft propagation classification
# ---------------------------------------------------------------------------

_STRONG_COPYLEFT_PREFIXES = ("GPL-2.0", "GPL-3.0", "AGPL-3.0")
_WEAK_COPYLEFT_PREFIXES = ("LGPL-2.1", "LGPL-3.0", "MPL-2.0", "EPL-1.0", "EPL-2.0")


def classify_copyleft(spdx_id: str | None) -> str:
    """Return ``"strong"``, ``"weak"``, or ``"none"`` copyleft strength."""
    if not spdx_id:
        return "none"
    upper = spdx_id.upper()
    if any(upper.startswith(p.upper()) for p in _STRONG_COPYLEFT_PREFIXES):
        return "strong"
    if any(upper.startswith(p.upper()) for p in _WEAK_COPYLEFT_PREFIXES):
        return "weak"
    return "none"


# ---------------------------------------------------------------------------
# OPG-136: dual-license / commercial restriction detection
# ---------------------------------------------------------------------------

_COMMERCIAL_RESTRICTION_MARKERS = (
    "commons clause",
    "business source license",
    "busl",
    "server side public license",
    "sspl",
    "elastic license",
    "non-commercial",
    "noncommercial",
    "for evaluation only",
    "commercial use is prohibited",
    "commercial license required",
    "commercial license is required",
)


def detect_commercial_restriction(raw_license_text: str | None) -> str | None:
    """Return the matched marker phrase if *raw_license_text* looks like a
    dual-licensed or commercially-restricted license, else ``None``."""
    if not raw_license_text:
        return None
    lowered = raw_license_text.lower()
    for marker in _COMMERCIAL_RESTRICTION_MARKERS:
        if marker in lowered:
            return marker
    return None


# ---------------------------------------------------------------------------
# OPG-135: license compatibility matrix
# ---------------------------------------------------------------------------

# Each project-license category maps to which dependency-license categories
# are allowed outright, which require manual review, and which are denied.
# Callers may override this wholesale (e.g. loaded from a JSON policy file)
# to express organization-specific allow/deny rules.
DEFAULT_COMPATIBILITY_POLICY: dict[str, dict[str, list[str]]] = {
    "permissive": {
        "allow": ["permissive"],
        "review": ["weak-copyleft"],
        "deny": ["strong-copyleft", "commercial-restricted"],
    },
    "weak-copyleft": {
        "allow": ["permissive", "weak-copyleft"],
        "review": [],
        "deny": ["strong-copyleft", "commercial-restricted"],
    },
    "strong-copyleft": {
        "allow": ["permissive", "weak-copyleft", "strong-copyleft"],
        "review": [],
        "deny": ["commercial-restricted"],
    },
    "unrestricted": {
        "allow": ["permissive", "weak-copyleft", "strong-copyleft"],
        "review": [],
        "deny": ["commercial-restricted"],
    },
}


def categorize_license(spdx_id: str | None, is_commercial_restricted: bool) -> str:
    """Bucket a normalized license into a compatibility-policy category."""
    if is_commercial_restricted:
        return "commercial-restricted"
    copyleft = classify_copyleft(spdx_id)
    if copyleft == "strong":
        return "strong-copyleft"
    if copyleft == "weak":
        return "weak-copyleft"
    if spdx_id is None:
        return "unknown"
    return "permissive"


@dataclass
class LicenseFinding:
    """One dependency's license-compliance evaluation (OPG-137 report row)."""

    package_name: str
    raw_license: str | None
    spdx_ids: list[str] = field(default_factory=list)
    category: str = "unknown"
    copyleft: str = "none"
    commercial_restriction: str | None = None
    verdict: str = "REVIEW"  # PASS | REVIEW | PROHIBITED
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "package_name": self.package_name,
            "raw_license": self.raw_license,
            "spdx_ids": self.spdx_ids,
            "category": self.category,
            "copyleft": self.copyleft,
            "commercial_restriction": self.commercial_restriction,
            "verdict": self.verdict,
            "reason": self.reason,
        }


def evaluate_license(
    package_name: str,
    raw_license: str | None,
    project_license_category: str = "permissive",
    policy: dict[str, dict[str, list[str]]] | None = None,
) -> LicenseFinding:
    """Evaluate one dependency's declared license against a project policy.

    Combines OPG-133 (SPDX normalization), OPG-134 (copyleft strength),
    OPG-136 (commercial-restriction detection), and OPG-135 (the
    compatibility-policy verdict) into a single typed finding.
    """
    policy = policy or DEFAULT_COMPATIBILITY_POLICY
    commercial_marker = detect_commercial_restriction(raw_license)

    spdx_ids = [
        normalized
        for part in parse_spdx_expression(raw_license or "")
        if (normalized := normalize_license(part))
    ]
    if not spdx_ids:
        single = normalize_license(raw_license)
        if single:
            spdx_ids = [single]

    # A compound "MIT OR Apache-2.0" expression lets a consumer choose either
    # branch; a conservative default still evaluates the first (typically
    # most-restrictive-declared) branch for the verdict.
    primary = spdx_ids[0] if spdx_ids else None
    category = categorize_license(primary, commercial_marker is not None)

    project_rules = policy.get(project_license_category, DEFAULT_COMPATIBILITY_POLICY["permissive"])

    if category == "unknown":
        verdict = "REVIEW"
        reason = f"Could not determine an SPDX license from {raw_license!r}"
    elif category in project_rules.get("deny", []):
        verdict = "PROHIBITED"
        reason = (
            f"{category} license is denied under the {project_license_category!r} project policy"
        )
    elif category in project_rules.get("review", []):
        verdict = "REVIEW"
        reason = f"{category} license requires manual review under the {project_license_category!r} project policy"
    else:
        verdict = "PASS"
        reason = (
            f"{category} license is allowed under the {project_license_category!r} project policy"
        )

    if commercial_marker:
        reason = f"Detected commercial/dual-license restriction ({commercial_marker!r}); {reason}"

    return LicenseFinding(
        package_name=package_name,
        raw_license=raw_license,
        spdx_ids=spdx_ids,
        category=category,
        copyleft=classify_copyleft(primary),
        commercial_restriction=commercial_marker,
        verdict=verdict,
        reason=reason,
    )


# ---------------------------------------------------------------------------
# OPG-137: license compliance report
# ---------------------------------------------------------------------------


def _summarize(findings: list[LicenseFinding]) -> dict[str, int]:
    counts = {"PASS": 0, "REVIEW": 0, "PROHIBITED": 0}
    for finding in findings:
        counts[finding.verdict] = counts.get(finding.verdict, 0) + 1
    return counts


def build_license_report(findings: list[LicenseFinding]) -> dict[str, Any]:
    """Machine-readable license compliance report (JSON-serializable)."""
    return {
        "schema_version": "1.0",
        "summary": _summarize(findings),
        "packages": [f.to_dict() for f in findings],
    }


def to_license_markdown(findings: list[LicenseFinding]) -> str:
    """GitHub-PR-comment-friendly Markdown rendering of a license report."""
    counts = _summarize(findings)
    lines = [
        "## License Compliance Report",
        "",
        f"**Summary:** {counts['PASS']} pass, {counts['REVIEW']} review, "
        f"{counts['PROHIBITED']} prohibited",
        "",
        "| Package | License | Category | Verdict | Reason |",
        "|---|---|---|---|---|",
    ]
    for finding in findings:
        license_display = (
            ", ".join(finding.spdx_ids) if finding.spdx_ids else (finding.raw_license or "unknown")
        )
        lines.append(
            f"| {finding.package_name} | {license_display} | {finding.category} | "
            f"{finding.verdict} | {finding.reason} |"
        )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# OPG-138: attribution / NOTICE file generation
# ---------------------------------------------------------------------------


def generate_notice(entries: list[dict[str, Any]]) -> str:
    """Aggregate copyright notices and license identifiers into NOTICE text.

    Each entry is a dict with at least ``package_name`` and ``license``; an
    optional ``copyright`` line is included verbatim when present. Suitable
    as the basis for a distribution bundle's NOTICE file.
    """
    lines = [
        "NOTICE",
        "",
        "This distribution includes the following third-party components:",
        "",
    ]
    for entry in sorted(entries, key=lambda e: str(e.get("package_name", ""))):
        name = entry.get("package_name", "unknown")
        license_id = entry.get("license") or "UNKNOWN"
        lines.append(f"- {name} ({license_id})")
        copyright_line = entry.get("copyright")
        if copyright_line:
            lines.append(f"  {copyright_line}")
    lines.append("")
    return "\n".join(lines)
