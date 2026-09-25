"""Tests for the end-of-life tracking engine (requirements.md §16.2, OPG-140)."""

from __future__ import annotations

import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from osspolicyguard.eol import BUNDLED_EOL_DATA, build_eol_report, check_eol, to_eol_markdown


class TestCheckEol:
    def test_past_eol_is_review_by_default(self):
        finding = check_eol("python", "3.8", as_of=date(2026, 1, 1))
        assert finding.is_past_eol is True
        assert finding.verdict == "REVIEW"
        assert finding.eol_date == "2024-10-07"

    def test_past_eol_prohibited_when_configured(self):
        finding = check_eol("python", "3.8", as_of=date(2026, 1, 1), prohibit_past_eol=True)
        assert finding.verdict == "PROHIBITED"

    def test_not_yet_past_eol_passes(self):
        finding = check_eol("python", "3.12", as_of=date(2026, 1, 1))
        assert finding.is_past_eol is False
        assert finding.verdict == "PASS"

    def test_exactly_on_eol_date_counts_as_past(self):
        finding = check_eol("python", "3.9", as_of=date(2025, 10, 5))
        assert finding.is_past_eol is True

    def test_unknown_product_cycle_is_review(self):
        finding = check_eol("cobol", "1985", as_of=date(2026, 1, 1))
        assert finding.verdict == "REVIEW"
        assert finding.eol_date is None

    def test_custom_dataset_override(self):
        dataset = {"widget": [{"cycle": "1.0", "eol": "2020-01-01"}]}
        finding = check_eol("widget", "1.0", as_of=date(2026, 1, 1), dataset=dataset)
        assert finding.is_past_eol is True

    def test_eol_false_means_not_scheduled(self):
        dataset = {"widget": [{"cycle": "2.0", "eol": False}]}
        finding = check_eol("widget", "2.0", as_of=date(2026, 1, 1), dataset=dataset)
        assert finding.verdict == "PASS"
        assert finding.is_past_eol is False

    def test_case_insensitive_product_lookup(self):
        finding = check_eol("Python", "3.12", as_of=date(2026, 1, 1))
        assert finding.verdict == "PASS"

    def test_bundled_dataset_has_expected_products(self):
        assert set(BUNDLED_EOL_DATA.keys()) >= {"python", "nodejs", "ruby", "php"}


class TestReportBuilders:
    def test_build_eol_report_summary(self):
        findings = [
            check_eol("python", "3.8", as_of=date(2026, 1, 1)),
            check_eol("python", "3.12", as_of=date(2026, 1, 1)),
        ]
        report = build_eol_report(findings)
        assert report["summary"] == {"PASS": 1, "REVIEW": 1, "PROHIBITED": 0}

    def test_markdown_contains_table(self):
        findings = [check_eol("python", "3.8", as_of=date(2026, 1, 1))]
        markdown = to_eol_markdown(findings)
        assert "End-of-Life Report" in markdown
        assert "python" in markdown
