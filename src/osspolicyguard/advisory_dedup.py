"""OPG-040 — Advisory deduplication: merge CVE/GHSA/OSV/vendor aliases.

Merges raw advisories from heterogeneous sources (OSV, NVD, GHSA, vendor
feeds) into a single, deduplicated list of Advisory objects using union-find
on shared IDs and alias sets.
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

# ---------------------------------------------------------------------------
# ID pattern matchers
# ---------------------------------------------------------------------------

CVE_RE = re.compile(r'CVE-\d{4}-\d{4,}', re.I)
GHSA_RE = re.compile(r'GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}', re.I)
MAL_RE = re.compile(r'MAL-\d{4}-\d+', re.I)

# ---------------------------------------------------------------------------
# Severity ranking (higher number = more severe)
# ---------------------------------------------------------------------------

_SEVERITY_RANK: dict[str, int] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "NONE": 0,
    "UNKNOWN": -1,
}

# ---------------------------------------------------------------------------
# Advisory dataclass
# ---------------------------------------------------------------------------


@dataclass
class Advisory:
    canonical_id: str
    aliases: set[str]
    severity: str | None
    cvss_score: float | None
    affected_versions: list[str]
    fixed_versions: list[str]
    references: list[str]
    sources: list[str]
    modified: str | None
    is_malicious: bool

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable dict; sets become sorted lists, None -> null."""
        return {
            "canonical_id": self.canonical_id,
            "aliases": sorted(self.aliases),
            "severity": self.severity,          # None serialises to null in JSON
            "cvss_score": self.cvss_score,      # None serialises to null in JSON
            "affected_versions": self.affected_versions,
            "fixed_versions": self.fixed_versions,
            "references": self.references,
            "sources": self.sources,
            "modified": self.modified,          # None serialises to null in JSON
            "is_malicious": self.is_malicious,
        }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _canonical_id(aliases: set[str]) -> str:
    """Choose the canonical ID from a set of aliases.

    Priority: CVE > GHSA > MAL > alphabetical first element.
    Within each class, the lexicographically smallest match wins so that
    output is deterministic.
    """
    cves = sorted(a for a in aliases if CVE_RE.fullmatch(a))
    if cves:
        return cves[0]
    ghsas = sorted(a for a in aliases if GHSA_RE.fullmatch(a))
    if ghsas:
        return ghsas[0]
    mals = sorted(a for a in aliases if MAL_RE.fullmatch(a))
    if mals:
        return mals[0]
    return sorted(aliases)[0]


def _higher_severity(a: str | None, b: str | None) -> str | None:
    """Return the severity string with the higher rank.

    If one argument is None the other is returned unchanged.
    Unknown severity strings are treated as rank -1 (below UNKNOWN).
    """
    if a is None:
        return b
    if b is None:
        return a
    rank_a = _SEVERITY_RANK.get(a.upper(), -1)
    rank_b = _SEVERITY_RANK.get(b.upper(), -1)
    return a if rank_a >= rank_b else b


# ---------------------------------------------------------------------------
# Core deduplication — union-find
# ---------------------------------------------------------------------------


def deduplicate_advisories(raw_advisories: list[dict]) -> list[Advisory]:
    """Merge a list of raw advisory dicts into deduplicated Advisory objects.

    Algorithm
    ---------
    1. For every raw advisory collect its full ID set (``id`` field + every
       element of the ``aliases`` list).
    2. Register all IDs in a union-find structure (``parent`` dict) and
       union together all IDs that appear in the same advisory — they
       describe the same vulnerability.
    3. Group raw advisories by their union-find root.
    4. For each group build a merged Advisory:
       - canonical_id via _canonical_id()
       - aliases = union of all IDs minus the canonical
       - severity  = highest severity across the group
       - cvss_score = maximum score across the group
       - affected_versions, fixed_versions, references = ordered union
       - sources = ordered union of source strings
       - modified = lexicographic maximum (ISO-8601 strings sort correctly)
       - is_malicious = True if any ID in the group matches MAL_RE

    Parameters
    ----------
    raw_advisories:
        Each element is a dict with keys:
        ``id`` (str), ``aliases`` (list[str]), ``severity`` (str|None),
        ``cvss_score`` (float|None), ``affected_versions`` (list[str]),
        ``fixed_versions`` (list[str]), ``references`` (list[str]),
        ``source`` (str), ``modified`` (str|None).

    Returns
    -------
    list[Advisory]
        One Advisory per deduplicated vulnerability, in an unspecified order.
    """
    # ------------------------------------------------------------------ #
    # Step 1 — collect ID sets for every raw advisory                     #
    # ------------------------------------------------------------------ #
    id_sets: list[set[str]] = []
    for raw in raw_advisories:
        ids: set[str] = set()
        primary = raw.get("id", "")
        if primary:
            ids.add(primary)
        for alias in raw.get("aliases", []):
            if alias:
                ids.add(alias)
        id_sets.append(ids)

    # ------------------------------------------------------------------ #
    # Step 2 — union-find                                                 #
    # ------------------------------------------------------------------ #
    parent: dict[str, str] = {}

    def _find(x: str) -> str:
        if parent.setdefault(x, x) != x:
            parent[x] = _find(parent[x])   # path compression
        return parent[x]

    def _union(x: str, y: str) -> None:
        rx, ry = _find(x), _find(y)
        if rx != ry:
            parent[ry] = rx

    for ids in id_sets:
        for id_ in ids:
            _find(id_)                      # initialise entry
        id_list = list(ids)
        for i in range(1, len(id_list)):
            _union(id_list[0], id_list[i])

    # ------------------------------------------------------------------ #
    # Step 3 — group by root                                              #
    # ------------------------------------------------------------------ #
    groups: dict[str, list[int]] = defaultdict(list)
    for idx, ids in enumerate(id_sets):
        if ids:
            root = _find(next(iter(ids)))
        else:
            # Advisory with no IDs — treat as its own singleton group.
            root = f"__no_id_{idx}__"
        groups[root].append(idx)

    # ------------------------------------------------------------------ #
    # Step 4 — merge each group into one Advisory                        #
    # ------------------------------------------------------------------ #
    result: list[Advisory] = []

    for root, indices in groups.items():
        all_ids: set[str] = set()
        severity: str | None = None
        cvss_score: float | None = None
        affected_versions: list[str] = []
        fixed_versions: list[str] = []
        references: list[str] = []
        sources: list[str] = []
        modified: str | None = None
        is_malicious: bool = False

        for idx in indices:
            raw = raw_advisories[idx]
            ids = id_sets[idx]
            all_ids |= ids

            severity = _higher_severity(severity, raw.get("severity"))

            raw_cvss = raw.get("cvss_score")
            if raw_cvss is not None:
                try:
                    raw_cvss_f = float(raw_cvss)
                    if cvss_score is None or raw_cvss_f > cvss_score:
                        cvss_score = raw_cvss_f
                except (TypeError, ValueError):
                    pass

            for v in raw.get("affected_versions", []):
                if v and v not in affected_versions:
                    affected_versions.append(v)

            for v in raw.get("fixed_versions", []):
                if v and v not in fixed_versions:
                    fixed_versions.append(v)

            for ref in raw.get("references", []):
                if ref and ref not in references:
                    references.append(ref)

            src = raw.get("source")
            if src and src not in sources:
                sources.append(src)

            raw_modified = raw.get("modified")
            if raw_modified is not None:
                if modified is None or raw_modified > modified:
                    modified = raw_modified

            # Mark malicious when any ID in this raw advisory matches MAL_RE
            if not is_malicious and any(MAL_RE.fullmatch(id_) for id_ in ids):
                is_malicious = True

        canonical = _canonical_id(all_ids) if all_ids else root
        aliases = all_ids - {canonical}

        result.append(Advisory(
            canonical_id=canonical,
            aliases=aliases,
            severity=severity,
            cvss_score=cvss_score,
            affected_versions=affected_versions,
            fixed_versions=fixed_versions,
            references=references,
            sources=sources,
            modified=modified,
            is_malicious=is_malicious,
        ))

    return result


# ---------------------------------------------------------------------------
# OSV + NVD integration helper
# ---------------------------------------------------------------------------


def merge_osv_nvd(osv_data: dict, nvd_cves: list[dict]) -> list[Advisory]:
    """Convert OSV vulns and NVD CVEs to raw advisory format, then deduplicate.

    Parameters
    ----------
    osv_data:
        OSV batch response dict with a ``"vulns"`` list.  Each vuln must have
        at minimum an ``"id"`` key; ``"aliases"`` and ``"modified"`` are used
        when present.
    nvd_cves:
        List of NVD CVE dicts.  Each must have at minimum an ``"id"`` key;
        ``"severity"`` and ``"cvss_score"`` are used when present.

    Returns
    -------
    list[Advisory]
        Deduplicated advisories merged across both sources.
    """
    raw_advisories: list[dict] = []

    for v in osv_data.get("vulns", []):
        raw_advisories.append({
            "id": v.get("id", ""),
            "aliases": v.get("aliases", []),
            "severity": None,
            "cvss_score": None,
            "affected_versions": [],
            "fixed_versions": [],
            "references": [],
            "source": "osv",
            "modified": v.get("modified"),
        })

    for c in nvd_cves:
        raw_advisories.append({
            "id": c.get("id", ""),
            "aliases": [],
            "severity": c.get("severity"),
            "cvss_score": c.get("cvss_score"),
            "affected_versions": [],
            "fixed_versions": [],
            "references": [],
            "source": "nvd",
            "modified": None,
        })

    return deduplicate_advisories(raw_advisories)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = ["Advisory", "deduplicate_advisories", "merge_osv_nvd"]
