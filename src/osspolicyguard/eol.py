"""End-of-life / deprecation tracking (requirements.md §16.2, OPG-140).

Checks whether a language runtime or platform's declared version has
passed its official end-of-life date, using a small bundled dataset for
offline/test use. For broader or always-current coverage, merge in a live
response from ``EndOfLifeDateProvider``
(``src/osspolicyguard/providers/endoflife_provider.py``), which queries the
public endoflife.date API and returns cycles in the same shape as
``BUNDLED_EOL_DATA``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from typing import Any

# A small, deliberately non-exhaustive bundled dataset of well-known EOL
# dates for common language runtimes, keyed by product -> list of
# {"cycle": ..., "eol": "YYYY-MM-DD"} entries — the same shape the public
# endoflife.date API returns, so a live lookup can extend this dataset
# without changing check_eol()'s contract.
BUNDLED_EOL_DATA: dict[str, list[dict[str, Any]]] = {
    "python": [
        {"cycle": "3.8", "eol": "2024-10-07"},
        {"cycle": "3.9", "eol": "2025-10-05"},
        {"cycle": "3.10", "eol": "2026-10-04"},
        {"cycle": "3.11", "eol": "2027-10-24"},
        {"cycle": "3.12", "eol": "2028-10-02"},
    ],
    "nodejs": [
        {"cycle": "16", "eol": "2023-09-11"},
        {"cycle": "18", "eol": "2025-04-30"},
        {"cycle": "20", "eol": "2026-04-30"},
        {"cycle": "22", "eol": "2027-04-30"},
    ],
    "ruby": [
        {"cycle": "3.0", "eol": "2024-04-23"},
        {"cycle": "3.1", "eol": "2025-03-31"},
        {"cycle": "3.2", "eol": "2026-03-31"},
        {"cycle": "3.3", "eol": "2027-03-31"},
    ],
    "php": [
        {"cycle": "8.0", "eol": "2023-11-26"},
        {"cycle": "8.1", "eol": "2025-12-31"},
        {"cycle": "8.2", "eol": "2026-12-31"},
        {"cycle": "8.3", "eol": "2027-12-31"},
    ],
}


@dataclass
class EolFinding:
    """One product/cycle's end-of-life evaluation."""

    product: str
    cycle: str
    eol_date: str | None
    is_past_eol: bool
    verdict: str  # PASS | REVIEW | PROHIBITED
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "product": self.product,
            "cycle": self.cycle,
            "eol_date": self.eol_date,
            "is_past_eol": self.is_past_eol,
            "verdict": self.verdict,
            "reason": self.reason,
        }


def _find_cycle_entry(
    product: str, cycle: str, dataset: dict[str, list[dict[str, Any]]]
) -> dict[str, Any] | None:
    for entry in dataset.get(product.lower(), []):
        if str(entry.get("cycle")) == str(cycle):
            return entry
    return None


def check_eol(
    product: str,
    cycle: str,
    as_of: date | None = None,
    dataset: dict[str, list[dict[str, Any]]] | None = None,
    prohibit_past_eol: bool = False,
) -> EolFinding:
    """Check whether *product* *cycle* (e.g. ``("python", "3.8")``) has
    reached its documented end-of-life date.

    *as_of* defaults to today; pass an explicit date for reproducible
    checks/tests. *dataset* defaults to ``BUNDLED_EOL_DATA``.
    """
    as_of = as_of or datetime.now().date()
    dataset = dataset if dataset is not None else BUNDLED_EOL_DATA
    entry = _find_cycle_entry(product, cycle, dataset)

    if entry is None:
        return EolFinding(
            product=product,
            cycle=cycle,
            eol_date=None,
            is_past_eol=False,
            verdict="REVIEW",
            reason=f"No EOL data available for {product} {cycle}; verify manually",
        )

    eol_raw = entry.get("eol")
    if not eol_raw:
        # endoflife.date represents "not yet scheduled" as eol: false.
        return EolFinding(
            product=product,
            cycle=cycle,
            eol_date=None,
            is_past_eol=False,
            verdict="PASS",
            reason=f"{product} {cycle} has no scheduled end-of-life date",
        )

    try:
        eol_date = datetime.strptime(str(eol_raw), "%Y-%m-%d").date()
    except ValueError:
        return EolFinding(
            product=product,
            cycle=cycle,
            eol_date=str(eol_raw),
            is_past_eol=False,
            verdict="REVIEW",
            reason=f"Could not parse EOL date {eol_raw!r} for {product} {cycle}",
        )

    is_past = as_of >= eol_date
    if is_past:
        verdict = "PROHIBITED" if prohibit_past_eol else "REVIEW"
        reason = f"{product} {cycle} reached end-of-life on {eol_date.isoformat()}"
    else:
        verdict = "PASS"
        reason = f"{product} {cycle} is supported until {eol_date.isoformat()}"

    return EolFinding(
        product=product,
        cycle=cycle,
        eol_date=eol_date.isoformat(),
        is_past_eol=is_past,
        verdict=verdict,
        reason=reason,
    )


def _summarize(findings: list[EolFinding]) -> dict[str, int]:
    counts = {"PASS": 0, "REVIEW": 0, "PROHIBITED": 0}
    for finding in findings:
        counts[finding.verdict] = counts.get(finding.verdict, 0) + 1
    return counts


def build_eol_report(findings: list[EolFinding]) -> dict[str, Any]:
    """Machine-readable EOL report (JSON-serializable)."""
    return {
        "schema_version": "1.0",
        "summary": _summarize(findings),
        "products": [f.to_dict() for f in findings],
    }


def to_eol_markdown(findings: list[EolFinding]) -> str:
    """GitHub-PR-comment-friendly Markdown rendering of an EOL report."""
    counts = _summarize(findings)
    lines = [
        "## End-of-Life Report",
        "",
        f"**Summary:** {counts['PASS']} pass, {counts['REVIEW']} review, "
        f"{counts['PROHIBITED']} prohibited",
        "",
        "| Product | Cycle | EOL Date | Verdict | Reason |",
        "|---|---|---|---|---|",
    ]
    for finding in findings:
        lines.append(
            f"| {finding.product} | {finding.cycle} | {finding.eol_date or 'unknown'} | "
            f"{finding.verdict} | {finding.reason} |"
        )
    return "\n".join(lines)
