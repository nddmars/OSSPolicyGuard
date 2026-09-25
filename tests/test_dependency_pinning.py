"""Tests for the dependency pinning engine (requirements.md §16.1, OPG-139)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from osspolicyguard.dependency_pinning import (
    DEFAULT_PINNING_POLICY,
    build_pinning_report,
    check_npm_lockfile_hashes,
    check_requirements_hashes,
    classify_specifier,
    evaluate_pinning,
    is_floating,
    to_pinning_markdown,
)


class TestClassifySpecifier:
    def test_exact(self):
        assert classify_specifier("1.2.3") == "exact"
        assert classify_specifier("==1.2.3") == "exact"

    def test_caret(self):
        assert classify_specifier("^1.2.3") == "caret"

    def test_tilde(self):
        assert classify_specifier("~1.2.3") == "tilde"
        assert classify_specifier("~> 1.2.3") == "tilde"

    def test_compatible_release(self):
        assert classify_specifier("~=1.2.3") == "compatible"

    def test_wildcard(self):
        assert classify_specifier("*") == "wildcard"
        assert classify_specifier("x") == "wildcard"

    def test_latest(self):
        assert classify_specifier("latest") == "latest"

    def test_unbounded(self):
        assert classify_specifier(">=1.2.3") == "unbounded"
        assert classify_specifier(">1.2.3") == "unbounded"

    def test_range(self):
        assert classify_specifier(">=1.2.3,<2.0.0") == "range"

    def test_empty(self):
        assert classify_specifier(None) == "empty"
        assert classify_specifier("") == "empty"
        assert classify_specifier("   ") == "empty"


class TestIsFloating:
    def test_exact_is_not_floating(self):
        assert is_floating("1.2.3") is False

    def test_caret_tilde_wildcard_latest_range_are_floating(self):
        for spec in (
            "^1.2.3",
            "~1.2.3",
            "~=1.2.3",
            "*",
            "latest",
            ">=1.2.3,<2.0.0",
            None,
        ):
            assert is_floating(spec) is True


class TestEvaluatePinning:
    def test_exact_passes_default_policy(self):
        finding = evaluate_pinning("requests", "2.31.0")
        assert finding.verdict == "PASS"

    def test_caret_is_review_by_default(self):
        finding = evaluate_pinning("express", "^4.18.0")
        assert finding.verdict == "REVIEW"
        assert finding.is_floating is True

    def test_caret_prohibited_when_deny_floating(self):
        policy = {"allowed_styles": ["exact"], "deny_floating": True}
        finding = evaluate_pinning("express", "^4.18.0", policy=policy)
        assert finding.verdict == "PROHIBITED"

    def test_compatible_prohibited_when_deny_floating(self):
        policy = {"allowed_styles": ["exact"], "deny_floating": True}
        finding = evaluate_pinning("requests", "~=1.2.3", policy=policy)
        assert finding.verdict == "PROHIBITED"

    def test_custom_allowed_styles(self):
        policy = {"allowed_styles": ["exact", "tilde"], "deny_floating": False}
        finding = evaluate_pinning("lib", "~1.2.3", policy=policy)
        assert finding.verdict == "PASS"

    def test_default_policy_object(self):
        assert DEFAULT_PINNING_POLICY["allowed_styles"] == ["exact"]


class TestReportBuilders:
    def test_build_pinning_report_summary(self):
        findings = [evaluate_pinning("a", "1.0.0"), evaluate_pinning("b", "^1.0.0")]
        report = build_pinning_report(findings)
        assert report["summary"] == {"PASS": 1, "REVIEW": 1, "PROHIBITED": 0}

    def test_markdown_contains_table(self):
        findings = [evaluate_pinning("a", "1.0.0")]
        markdown = to_pinning_markdown(findings)
        assert "Dependency Pinning Report" in markdown
        assert "a" in markdown


class TestCheckNpmLockfileHashes:
    def test_all_hashed(self):
        lockfile = {
            "packages": {
                "": {"name": "root"},
                "node_modules/express": {"version": "4.18.0", "integrity": "sha512-abc"},
                "node_modules/lodash": {"version": "4.17.0", "integrity": "sha512-def"},
            }
        }
        result = check_npm_lockfile_hashes(lockfile)
        assert result == {"total": 2, "hashed": 2, "unhashed": []}

    def test_missing_hash_detected(self):
        lockfile = {
            "packages": {
                "": {"name": "root"},
                "node_modules/express": {"version": "4.18.0"},
            }
        }
        result = check_npm_lockfile_hashes(lockfile)
        assert result["unhashed"] == ["express"]
        assert result["hashed"] == 0

    def test_workspace_link_skipped(self):
        lockfile = {
            "packages": {
                "": {"name": "root"},
                "packages/my-workspace": {"link": True},
            }
        }
        result = check_npm_lockfile_hashes(lockfile)
        assert result["total"] == 0


class TestCheckRequirementsHashes:
    def test_single_line_no_hash(self):
        result = check_requirements_hashes("flask==2.3.0\n")
        assert result == {"total": 1, "hashed": 0, "unhashed": ["flask"]}

    def test_continuation_with_hashes(self):
        text = (
            "requests==2.31.0 \\\n    --hash=sha256:abc \\\n    --hash=sha256:def\nflask==2.3.0\n"
        )
        result = check_requirements_hashes(text)
        assert result["total"] == 2
        assert result["hashed"] == 1
        assert result["unhashed"] == ["flask"]

    def test_ignores_comments_and_blank_lines(self):
        text = "# a comment\n\nflask==2.3.0\n"
        result = check_requirements_hashes(text)
        assert result["total"] == 1

    def test_non_pinned_lines_ignored(self):
        text = "requests>=2.31.0\nflask==2.3.0\n"
        result = check_requirements_hashes(text)
        assert result["total"] == 1
        assert result["unhashed"] == ["flask"]
