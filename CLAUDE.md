# OSSPolicyGuard — CLAUDE.md

Developer reference for Claude Code sessions. Read this before modifying any file.

---

## Project overview

OSSPolicyGuard is a **policy-as-code engine** that evaluates open-source packages using
measurable technical signals (vulnerabilities, exploitability, maintenance, community, supply
chain) and returns an auditable APPROVED / REVIEW / PROHIBITED decision.

- Python ≥ 3.9, MIT licence, version 0.1.0
- Install: `pip install -e '.[dev]'`
- Entry point: `osspolicyguard` CLI → `src/osspolicyguard/cli.py:main()`

---

## Repository layout

```
oss_scorer.py                  # Core engine — OSSConfig, OSSScorer, OSSWorkflow, OSSVisualizer
config.yaml                    # Runtime configuration (API keys, weights, thresholds, registries)
config.schema.json             # JSON Schema for config.yaml editor validation
pyproject.toml                 # Package metadata; entry point osspolicyguard = osspolicyguard.cli:main

src/osspolicyguard/
  __init__.py                  # Public API: scan_package, Decision, EvaluationResult, Finding
  cli.py                       # CLI (main, scan_package, _normalize_decision, _sarif_stub)
  models.py                    # Typed dataclasses: EvaluationResult, Finding, ProviderResult
  reports.py                   # Output formatters: build_findings, to_sarif, to_markdown_pr
  logging_config.py            # configure_logging(); RedactingFilter scrubs secrets from logs
  exceptions.py                # OSSPolicyGuardError hierarchy
  policy.py                    # PolicyBundle (next-gen; not yet wired into OSSScorer)
  license_compliance.py        # SPDX normalization, copyleft, compatibility policy, NOTICE (§15)
  dependency_pinning.py        # Version-specifier classification, pinning policy, lockfile hash checks (§16.1)
  eol.py                       # Bundled end-of-life dataset + check_eol() (§16.2)
  providers/                   # Next-gen typed providers (implemented; not yet wired into OSSScorer)
    __init__.py                # ProviderBase ABC, ProviderResponse, ProviderStatus, NullProvider
    github_provider.py         # GitHubProvider
    nvd_provider.py            # NVDProvider
    osv_provider.py            # OSVProvider
    epss_provider.py           # EPSSProvider
    scorecard_provider.py      # ScorecardProvider
    registry_provider.py       # RegistryProvider (pypi/npm/maven)
    endoflife_provider.py      # EndOfLifeDateProvider (endoflife.date API)
  advisory_dedup.py            # Advisory deduplication helpers
  artifact_inventory.py        # (stub) Artifact inventory
  dep_confusion.py             # (stub) Dependency-confusion detection
  identity.py                  # (stub) Maintainer identity model
  kev.py                       # (stub) KEV integration
  typosquatting.py             # (stub) Typosquatting detection

tests/
  test_oss_scorer.py           # 163+ unit tests for OSSScorer / OSSWorkflow internals
  test_round3_fixes.py         # 35 regression tests for rounds 3-5 PR fixes
  test_cli.py                  # CLI integration tests (scan_package, manifest, main, exit codes)
  test_reports.py              # Report formatter tests
  test_providers.py            # Legacy oss_scorer.py GitHubProvider/ScorecardProvider tests
  test_next_gen_providers.py   # src/osspolicyguard/providers/ typed provider tests
  test_new_modules.py          # Stub module tests
  test_action_script.py        # GitHub Action script tests
  test_license_compliance.py   # license_compliance.py unit tests
  test_dependency_pinning.py   # dependency_pinning.py unit tests
  test_eol.py                  # eol.py unit tests
  golden/small_result.json     # Golden fixture for report tests

scripts/
  osspolicyguard_action.py     # Called by .github/workflows/osspolicyguard-action.yml
```

---

## Core classes (`oss_scorer.py`)

### `OSSConfig` (line ~385)
Singleton config loader. Reads `config.yaml`, applies `GITHUB_TOKEN` / `NVD_API_KEY` env
overrides, warns on placeholder values. Raises `RuntimeError` if `config.yaml` is missing.

### `OSSScorer` (line ~494)
Main scoring engine. All public entry points go through `OSSWorkflow`.

Key methods:
| Method | Purpose |
|---|---|
| `evaluate_component(component_data)` | Full evaluation pipeline; returns result dict |
| `_calculate_security_score(results)` | CVE/EPSS deductions + Scorecard blend (40%) |
| `_calculate_activity_score(results)` | Days-since-last-commit staleness buckets |
| `_calculate_trust_score(results)` | Maturity via fork count **only** — no geo blending |
| `_calculate_community_score(results)` | Downloads (70%) + stars (30%) blend |
| `_determine_approval(score, criticality)` | Returns APPROVED / REVIEW / PROHIBITED |
| `_calculate_geo_risk_score(locations)` | Commit-weighted geo penalty (for compliance only) |
| `check_cves(package, ecosystem)` | NVD v2 query + EPSS enrichment |
| `check_osv(package, ecosystem)` | OSV.dev query; detects MAL- advisories |
| `get_download_count(package, ecosystem)` | Registry download count (error dict on failure) |
| `get_scorecard(repo_url)` | OpenSSF Scorecard (0–10 scale) |
| `_rate_limited_get(url, headers, timeout, params)` | Rate-limited HTTP GET |

### `OSSWorkflow` (line ~1240)
Thin orchestrator. `evaluate_component()` here is the safe public entry point — it calls
`OSSScorer.evaluate_component()` and sets:
- `insufficient_data = True` when NVD or OSV provider failed → APPROVED downgraded to REVIEW
- `compliance.geo_jurisdiction` when `geo_compliance.enabled = true` (separate from score)

### `OSSVisualizer` (line ~1168)
Matplotlib + Jupyter charts. `create_dashboard()`, `interactive_selector()`.

---

## CLI (`src/osspolicyguard/cli.py`)

### `scan_package()` — programmatic API
Calls `OSSWorkflow.evaluate_component()` and returns a schema-v1.0 dict:

```python
{
    "schema_version": "1.0",
    "tool_version": str,
    "generated_at": str,          # ISO-8601 UTC
    "policy": {"name": str, "version": str},
    "package": {"name": str, "ecosystem": str, "version": None},
    "decision": "APPROVED" | "REVIEW" | "PROHIBITED",
    "score": float,               # 0–100, one decimal place
    "dimensions": {
        "security": float, "maintenance": float,
        "community": float, "supply_chain_risk": float
    },
    "findings": list[dict],       # from reports.build_findings()
    "evidence": list[dict],       # from EvaluationResult.from_legacy()
    "warnings": list[str],        # provider-failure notices
    "malicious_package_detected": bool,
    "enforcement": "default" | "review_fails_ci",
    "insufficient_data": bool,    # True when NVD/OSV unavailable
    "compliance": dict,           # geo_jurisdiction sub-section when enabled
}
```

### `main()` — CLI entry point
Exit-code contract (in precedence order):

| Code | Condition |
|---|---|
| 1 | PROHIBITED |
| 4 | `insufficient_data=True` OR network exception — takes precedence over `--review-fails-ci` |
| 2 | REVIEW + `--review-fails-ci` |
| 3 | Configuration / import error |
| 99 | Unexpected internal error |
| 0 | APPROVED |

---

## Decision thresholds (`config.yaml → scoring.thresholds`)

| Criticality | APPROVED | REVIEW | PROHIBITED |
|---|---|---|---|
| Mission Critical | score ≥ 90 | 80–89 | score < 80 |
| Business Critical | score ≥ 80 | 70–79 | score < 70 |
| Non-Critical | score ≥ 60 | score < 60 | **never** |

`_determine_approval()` returns only the three canonical strings above.
`_normalize_decision()` in `cli.py` maps any raw value → APPROVED / REVIEW / PROHIBITED.

---

## Scoring weights (`config.yaml → scoring.weights`)

| Dimension | Weight | Signal |
|---|---|---|
| Security | 35% | CVE/EPSS deductions + Scorecard (40% blend) |
| Activity | 30% | Days since last commit |
| Trust | 20% | Fork count (maturity only — geo is separate) |
| Community | 15% | Downloads (70%) + GitHub stars (30%) |

Weights must sum to 100; `_load_config` emits `UserWarning` if they don't.

---

## Provider status conventions

Every provider result dict must have a `status` field:

| Value | Meaning |
|---|---|
| `"success"` | Data fetched successfully |
| `"error"` | Network / API failure → `insufficient_data=True` in evaluate_component |
| `"disabled"` | Feature disabled in config (OSV, Scorecard, registry) — not an error |
| `"unsupported"` | Ecosystem not supported by this provider — not an error |

`check_cves()` and `check_osv()` set `status='error'` and `last_updated=None` on failure.
`get_download_count()` returns `{'weekly_downloads': None, 'status': 'error', ...}` — never `None`.
`_calculate_community_score()` guards against `weekly_downloads=None`.

---

## Models (`src/osspolicyguard/models.py`)

`EvaluationResult.from_legacy(result, package_name, ecosystem)` — converts an
`evaluate_component()` dict to a typed `EvaluationResult`. Reads provider `status` fields
first; falls back to timestamp heuristics for backward compatibility.

`Finding`, `ProviderResult`, `Decision`, `Severity`, `Dimension` are the public typed API.

---

## Reports (`src/osspolicyguard/reports.py`)

| Function | Output |
|---|---|
| `build_findings(result)` | List of finding dicts from score signals |
| `to_sarif(result)` | Valid SARIF 2.1.0 document |
| `to_markdown_pr(result)` | GitHub PR comment Markdown including insufficient-data banner and warnings |

`to_markdown_pr()` appends:
- ⚠️ insufficient-data banner when `result["insufficient_data"]` is True
- Provider warnings list when `result["warnings"]` is non-empty

---

## Logging (`src/osspolicyguard/logging_config.py`)

`configure_logging(level, json_output)` — attaches a `RedactingFilter` that scrubs secrets
(tokens, API keys) from log records. **Non-string args (int, float) are never coerced to
string** — `logger.info("count=%d", 3)` is safe. Always call this via CLI's `--log-level`
flag; do not call `logging.basicConfig()` in library code.

---

## Geography / compliance

Geo is **opt-in only** and **never affects the technical score**:

```yaml
# config.yaml
risk:
  geo_compliance:
    enabled: true   # default: false
```

When enabled, `evaluate_component()` calls `_calculate_geo_risk_score()` and stores the
result under `result["compliance"]["geo_jurisdiction"]` with `affects_technical_score: false`.
`_calculate_trust_score()` always returns maturity only regardless of geo settings.

---

## Running tests

```bash
python -m pytest tests/ -q          # 382 tests, all must pass
python -m pytest tests/test_cli.py  # CLI tests only
python -m pytest tests/test_round3_fixes.py  # Provider-safety regression suite

ruff check .                        # lint (rules pinned in pyproject.toml: E4,E7,E9,F)
black --check .                     # format check
mypy src/osspolicyguard oss_scorer.py  # type check
```

CI (`.github/workflows/tests.yml`) runs all four gates on every push/PR to `main`.
No network calls are made in tests — all providers are mocked via `unittest.mock` or
`monkeypatch`.

---

## Adding a new feature

1. **Provider change** → edit `oss_scorer.py` (`OSSScorer` or a provider method). Return a
   dict with `status='success'/'error'/'disabled'`. Update `evaluate_component()` to audit
   the new status and set `insufficient_data` if appropriate.
2. **Scoring change** → edit the relevant `_calculate_*_score()` method. Add a threshold to
   `config.yaml` rather than hardcoding it.
3. **CLI output change** → edit `src/osspolicyguard/cli.py`. Update all three output blocks
   (text, json, markdown/sarif). Add new keys to `scan_package()` return dict.
4. **New output format** → add a formatter to `src/osspolicyguard/reports.py` and wire it
   into `main()` and `scan_package()`.
5. **Tests** → mock at the boundary (`OSSScorer` method or `scan_package`). Do not import
   `oss_scorer` directly from test files — use `from osspolicyguard import ...` or import the
   specific class.

---

## Git conventions

- Branch: `feature/requirements-doc` (remote); local alias `round3-fixes`
- Commits: GPG-signed (`git commit -S --gpg-sign=30CEBB02F0950648`)
- Author: `Surya Nalluri <nddmars@gmail.com>`
- Push: `git push -u origin round3-fixes:feature/requirements-doc`
- **Never** include AI tool names in commit messages, code comments, or PR bodies

---

## Files that must stay consistent

When changing decision logic, keep these in sync:

| File | What to update |
|---|---|
| `oss_scorer.py:_determine_approval()` | Threshold logic |
| `REQUIREMENTS.md` §11 | Threshold table |
| `README.md` — Decision semantics table | Threshold table |
| `tests/test_oss_scorer.py:TestDetermineApproval` | Boundary tests |

When changing provider status semantics:

| File | What to update |
|---|---|
| `oss_scorer.py` (provider method) | `status` field in returned dict |
| `src/osspolicyguard/models.py:from_legacy()` | Status-first evidence construction |
| `oss_scorer.py:evaluate_component()` | `insufficient_data` audit logic |
| `tests/test_round3_fixes.py` | Provider safety regression tests |
