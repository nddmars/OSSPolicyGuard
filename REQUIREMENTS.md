# OSSPolicyGuard — Requirements & Implementation Status

> **Legend**
> | Badge | Meaning |
> |---|---|
> | ✅ | Implemented & tested |
> | ❌ | Not yet implemented (future roadmap) |

---

## 1. System Architecture

| # | Requirement | Status | Notes |
|---|---|---|---|
| 1.1 | Single-module Python application (`oss_scorer.py`) | ✅ | 1,514 lines; four main classes + provider layer |
| 1.2 | Singleton configuration manager | ✅ | `OSSConfig` — one instance per process |
| 1.3 | Provider abstraction layer with base class | ✅ | `ProviderBase` — shared HTTP, caching, rate-limiting, retry logic |
| 1.4 | Structured provider responses (`ProviderResponse`) | ✅ | Dataclass with `provider`, `status`, `fetched_at`, `data`, `error` |
| 1.5 | Structured error model (`ProviderError`) | ✅ | Captures provider name, `ProviderStatus` enum, message, details |
| 1.6 | Provider status enumeration | ✅ | `ProviderStatus`: SUCCESS, TIMEOUT, RATE_LIMIT, MALFORMED, NETWORK_ERROR, UNKNOWN |
| 1.7 | TTL-based in-memory response cache (`SimpleCache`) | ✅ | Per-provider; expires entries on read |
| 1.8 | Exponential backoff retry on transient HTTP errors | ✅ | `ProviderBase._get()` — configurable retries + backoff factor |
| 1.9 | Jupyter Notebook integration helper (`init_oss_analysis`) | ✅ | Bootstraps all four main objects and displays Markdown header |

---

## 2. Configuration Management

| # | Requirement | Status | Notes |
|---|---|---|---|
| 2.1 | Load configuration from `config.yaml` | ✅ | `OSSConfig._load_config()` via PyYAML |
| 2.2 | Apply sensible defaults when config sections are absent | ✅ | All sections default-filled in `_load_config` |
| 2.3 | Override `github.token` from `GITHUB_TOKEN` environment variable | ✅ | Applied after YAML load; higher priority |
| 2.4 | Override `nvd.api_key` from `NVD_API_KEY` environment variable | ✅ | Applied after YAML load; higher priority |
| 2.5 | Warn when credentials are placeholder values | ✅ | `logger.warning` when token/key starts with `<<` |
| 2.6 | Raise `RuntimeError` if `config.yaml` is missing | ✅ | Prevents silent misconfiguration |
| 2.7 | Per-feature `enabled` flag (OSV, malicious packages, geocoding, EPSS, scorecard) | ✅ | All features can be independently disabled via config |
| 2.8 | Per-registry `enabled` flag for download count lookups | ✅ | Maven disabled by default (no public download API) |
| 2.9 | Configurable scoring weights (activity, trust, security, community) | ✅ | `scoring.weights` in config.yaml |
| 2.10 | Configurable approval thresholds (critical, high, medium, low) | ✅ | `scoring.thresholds` defaults (90/80/70/60) set in `_load_config`; no `KeyError` if section omitted |
| 2.11 | Configurable EPSS thresholds via config.yaml | ✅ | `_calculate_security_score` reads `epss.high_threshold`/`med_threshold` from config; falls back to constants |
| 2.12 | `scorecard.enabled` flag respected before API call | ✅ | Guard added at top of `get_scorecard()` — returns `None` immediately when flag is `false` |

---

## 3. Provider Infrastructure

| # | Requirement | Status | Notes |
|---|---|---|---|
| 3.1 | `GitHubProvider` — fetches GitHub repository metadata | ✅ | Extends `ProviderBase`; parses owner/repo from URL; uses token auth |
| 3.2 | `ScorecardProvider` — fetches OpenSSF Scorecard data | ✅ | Extends `ProviderBase`; sets `Accept: application/json` header |
| 3.3 | Rate-limiting enforced at provider level | ✅ | `_sleep_rate_limit()` in `ProviderBase` using monotonic clock |
| 3.4 | Response caching with configurable TTL | ✅ | `SimpleCache` in `ProviderBase`; cache key = URL + sorted params |
| 3.5 | Retry with exponential backoff | ✅ | Up to `retries` attempts; sleep = `backoff_factor × 2^attempt` |
| 3.6 | Malformed JSON response captured as `MALFORMED` error | ✅ | `ValueError` on `.json()` is caught and wrapped |
| 3.7 | HTTP 429 (rate limit) distinguished from other HTTP errors | ✅ | Mapped to `ProviderStatus.RATE_LIMIT` |

---

## 4. GitHub Integration

| # | Requirement | Status | Notes |
|---|---|---|---|
| 4.1 | Fetch repository star count | ✅ | `get_github_metrics()` → `stargazers_count` |
| 4.2 | Fetch repository fork count | ✅ | `get_github_metrics()` → `forks_count` |
| 4.3 | Fetch last commit timestamp (`pushed_at`) | ✅ | Used for activity score calculation |
| 4.4 | Fetch open issue count | ✅ | `get_github_metrics()` → `open_issues_count` |
| 4.5 | Fetch contributors URL for geolocation pipeline | ✅ | `get_github_metrics()` → `contributors_url` |
| 4.6 | Validate GitHub URL before API call | ✅ | `_parse_github_owner_repo()` raises `ValueError` on non-GitHub or malformed URLs |
| 4.7 | Return `None` gracefully on network failure | ✅ | `requests.RequestException` caught; logs error |
| 4.8 | Fetch top-N contributors with profile data | ✅ | `get_contributor_locations()` — queries `/users/{login}` for location + company |
| 4.9 | Configurable contributor fetch limit (`max_contributors`) | ✅ | `geocoding.max_contributors` in config.yaml (default 10) |
| 4.10 | Authenticated requests using GitHub personal access token | ✅ | `Authorization: token {token}` header when configured |
| 4.11 | GitLab / Bitbucket support | ❌ | GitHub only; future roadmap |

---

## 5. CVE Intelligence — NVD v2 + EPSS

| # | Requirement | Status | Notes |
|---|---|---|---|
| 5.1 | Query NVD API v2 (`/rest/json/cves/2.0`) | ✅ | Replaces deprecated NVD v1 |
| 5.2 | Apply 3-year look-back window via `pubStartDate` | ✅ | `_CVE_LOOKBACK_DAYS = 3 × 365` |
| 5.3 | Return up to 50 CVEs per query (`resultsPerPage`) | ✅ | Configurable constant |
| 5.4 | Parse CVSSv3.1 severity and base score (preferred) | ✅ | `cvssMetricV31` checked first |
| 5.5 | Fall back to CVSSv3.0 if v3.1 unavailable | ✅ | Priority chain: v3.1 → v3.0 → v2 |
| 5.6 | Fall back to CVSSv2 if v3.x unavailable | ✅ | Captures `baseSeverity` from v2 bucket |
| 5.7 | Count CVEs by severity band (CRITICAL / HIGH / MEDIUM / LOW) | ✅ | Returned in `check_cves()` result dict |
| 5.8 | Return safe empty structure on API failure | ✅ | All zero counts; `last_updated` timestamp preserved |
| 5.9 | Authenticated NVD requests using API key | ✅ | `apiKey` header when configured |
| 5.10 | Fetch EPSS exploit-probability from FIRST.org (`api.first.org`) | ✅ | `get_epss_scores()`; no API key required |
| 5.11 | Batch EPSS requests in groups of 30 CVE IDs | ✅ | Handles pagination within a single CVE result set |
| 5.12 | Attach `epss` and `epss_percentile` to each CVE object | ✅ | Per-CVE enrichment in `check_cves()` |
| 5.13 | Count CVEs with EPSS ≥ 0.5 (`epss_high`) | ✅ | Actively-weaponised indicator |
| 5.14 | Track maximum EPSS value across all CVEs (`max_epss`) | ✅ | Useful for dashboard display |
| 5.15 | Graceful batch-level EPSS failure (continue other batches) | ✅ | Per-batch try/except; partial results returned |
| 5.16 | NVD rate-limit enforcement | ✅ | `_rate_limited_get()` using `nvd.rate_limit` config |

---

## 6. OSV / Malicious Package Detection

| # | Requirement | Status | Notes |
|---|---|---|---|
| 6.1 | Query OSV.dev API (`api.osv.dev/v1/query`) by package + ecosystem | ✅ | `check_osv()` using HTTP POST |
| 6.2 | Detect malicious packages via `MAL-` advisory IDs (ossf/malicious-packages) | ✅ | `is_malicious` flag set when any MAL- advisory found |
| 6.3 | Count GHSA / ecosystem advisories without CVE aliases as `extra_advisories` | ✅ | Supplements NVD pipeline without double-counting |
| 6.4 | Skip CVE-aliased advisories in `extra_advisories` count | ✅ | Avoids double-penalising CVEs already in NVD pipeline |
| 6.5 | Map registry/language names to OSV ecosystem identifiers | ✅ | `_resolve_osv_ecosystem()` — `_OSV_ECOSYSTEM_MAP` covers 7 registries |
| 6.6 | OSV check works for Maven even when download counting is disabled | ✅ | `_resolve_osv_ecosystem` intentionally ignores `enabled` flag |
| 6.7 | `osv.enabled` config flag gates all OSV queries | ✅ | Returns empty result without making any HTTP call |
| 6.8 | `malicious_packages.enabled` flag gates MAL- detection independently | ✅ | OSV vulns still checked; only MAL- flagging suppressed |
| 6.9 | Return safe empty structure on API failure | ✅ | `requests.RequestException` caught; `is_malicious=False` returned |

---

## 7. Package Registry Download Counts

| # | Requirement | Status | Notes |
|---|---|---|---|
| 7.1 | Config-driven registry selection (`registries` section in config.yaml) | ✅ | Each registry has `enabled`, `timeout`, `languages` |
| 7.2 | Language-alias resolution (e.g. `python` → `pypi`, `javascript` → `npm`) | ✅ | `_resolve_registry()` scans `languages` list |
| 7.3 | Case-insensitive ecosystem/language matching | ✅ | `.lower().strip()` normalisation |
| 7.4 | Respect `enabled: false` registry flag | ✅ | Returns `None` without fetching |
| 7.5 | npm — true weekly download count | ✅ | `api.npmjs.org/downloads/point/last-week/{package}` |
| 7.6 | PyPI — true weekly download count | ✅ | `pypistats.org/api/packages/{package}/recent` → `last_week` |
| 7.7 | RubyGems — estimated weekly (`version_downloads ÷ 52`) | ✅ | No public weekly API; noted in config comments |
| 7.8 | crates.io — estimated weekly (`recent_downloads ÷ 13`, 90-day window) | ✅ | `crates.io/api/v1/crates/{package}` → `recent_downloads` |
| 7.9 | NuGet — estimated weekly (`totalDownloads ÷ 104`, 2-year lifetime) | ✅ | `azuresearch-usnc.nuget.org/query` |
| 7.10 | Packagist — estimated weekly (`monthly ÷ 4`) | ✅ | Requires `vendor/package` format |
| 7.11 | Packagist: warn and return zero for missing vendor prefix | ✅ | `logger.warning`; does not raise |
| 7.12 | Maven — download count | ❌ | Maven Central has no public download API; registry disabled |
| 7.13 | All fetchers return `{weekly_downloads, period, registry}` | ✅ | Normalised structure regardless of underlying API period |
| 7.14 | Return `None` gracefully on network failure | ✅ | `requests.RequestException` caught at dispatcher level |

---

## 8. OpenSSF Scorecard

| # | Requirement | Status | Notes |
|---|---|---|---|
| 8.1 | Fetch security score (0–10) from `api.securityscorecards.dev` | ✅ | `get_scorecard()` |
| 8.2 | Fetch per-check scores (Code-Review, Branch-Protection, etc.) | ✅ | Returns `checks` dict of name → score |
| 8.3 | Return `None` gracefully when repo is not indexed (HTTP 404) | ✅ | Logged at INFO level |
| 8.4 | Return `None` gracefully on network failure | ✅ | `requests.RequestException` caught |
| 8.5 | Blend Scorecard into security score at 40% weight | ✅ | `0.6 × CVE_score + 0.4 × (scorecard × 10)` |
| 8.6 | `scorecard.enabled` flag checked before making API call | ✅ | Guard in `get_scorecard()` skips HTTP call and returns `None` when disabled |

---

## 9. Contributor Geolocation

| # | Requirement | Status | Notes |
|---|---|---|---|
| 9.1 | Fast-path location lookup via local dictionary (~150 entries) | ✅ | `_LOCATION_COUNTRY_MAP`; covers high-risk nations + major developer cities |
| 9.2 | Fallback geocoding via Nominatim (OpenStreetMap) | ✅ | `_geocode_location()` — no API key required |
| 9.3 | Configurable Nominatim URL and User-Agent | ✅ | `geocoding.nominatim_url` / `geocoding.user_agent` |
| 9.4 | `geocoding.enabled` flag gates all geolocation (skip Nominatim + contributor fetch) | ✅ | Returns empty list without any HTTP call |
| 9.5 | Case-insensitive location string matching | ✅ | `.lower().strip()` before lookup |
| 9.6 | Geocoding failures are best-effort (silently swallowed) | ✅ | Returns `''` on Nominatim network error |
| 9.7 | ISO-3166-1 alpha-2 country codes returned | ✅ | Used for geo-risk country comparison |
| 9.8 | Contributor commit count used to weight geo-risk | ✅ | `_calculate_geo_risk_score()` weights by `contributions` |
| 9.9 | High-risk countries configurable via `risk.high_risk_countries` | ✅ | Default: CN, RU, IR, KP, SY |
| 9.10 | Unknown location applies partial penalty (20%) | ✅ | Accounts for unresolvable locations without full penalisation |

---

## 10. Scoring Algorithms

| # | Requirement | Status | Notes |
|---|---|---|---|
| 10.1 | **Activity score** — based on days since last commit | ✅ | <7d→100, <30d→80, <90d→60, <365d→30, ≥365d→10, no data→40 |
| 10.2 | **Security score** — EPSS-weighted CVE deductions | ✅ | EPSS ≥0.5→−15, 0.1–0.5→−8, >0→−2; fallback: CRITICAL→−10, HIGH→−5, MEDIUM→−2 |
| 10.3 | **Security score** — OSV extra-advisory deduction | ✅ | −3 pts per GHSA/ecosystem advisory; capped at −20 pts (configurable) |
| 10.4 | **Security score** — malicious package forces score to 0 | ✅ | Triggered by `is_malicious=True` + `auto_prohibit=True` |
| 10.5 | **Security score** — OpenSSF Scorecard blended at 40% | ✅ | `0.6 × CVE_score + 0.4 × (scorecard × 10)` |
| 10.6 | **Trust score** — project maturity via fork count (60% weight) | ✅ | >5K forks→100, >1K→80, >100→60, low→40, no data→50 neutral |
| 10.7 | **Trust score** — geopolitical risk via contributor locations (40% weight) | ✅ | `_calculate_geo_risk_score()` — commit-weighted penalty |
| 10.8 | **Community score** — weekly download count (70% weight) | ✅ | >1M→100, >100K→80, >10K→60, else→40 |
| 10.9 | **Community score** — GitHub star count (30% weight) | ✅ | >10K→100, >1K→80, >100→60, else→40 |
| 10.10 | Community score falls back to single signal when only one is available | ✅ | Downloads-only or stars-only handled separately |
| 10.11 | Weighted total score using configurable weights from config.yaml | ✅ | `scoring.weights`: activity=30%, trust=20%, security=35%, community=15% |
| 10.12 | Score weights must sum to 100 | ✅ | `_load_config` emits `UserWarning` with actual sum when weights don't add to 100 |
| 10.13 | Issue / PR response time metric | ❌ | Future roadmap |
| 10.14 | Release cadence analysis | ❌ | Future roadmap |
| 10.15 | Commit frequency metric (separate from staleness) | ❌ | Future roadmap |
| 10.16 | Dependency vulnerability depth (transitive deps) | ❌ | Future roadmap |

---

## 11. Approval & Risk Decision Logic

| # | Requirement | Status | Notes |
|---|---|---|---|
| 11.1 | Criticality-tiered approval for **Mission Critical** components | ✅ | ≥90→APPROVED, ≥80→REVIEW BOARD, else→PROHIBITED |
| 11.2 | Criticality-tiered approval for **Business Critical** components | ✅ | ≥80→APPROVED, ≥70→MITIGATION REQUIRED, else→PROHIBITED |
| 11.3 | Criticality-tiered approval for **Non-Critical** components | ✅ | ≥70→AUTO-APPROVED, ≥60→APPROVED, else→MITIGATION REQUIRED |
| 11.4 | Validate `criticality` field on input; reject unknown values | ✅ | `ValueError` raised for any value outside `_VALID_CRITICALITY` |
| 11.5 | Validate `component_data` is a dict; reject other types | ✅ | `TypeError` raised with descriptive message |
| 11.6 | Malicious package overrides approval to PROHIBITED regardless of score | ✅ | Post-scoring override in `evaluate_component()` |
| 11.7 | Risk level mapping: Low / Medium-Low / Medium / Medium-High / High | ✅ | `_get_risk_level()` using `scoring.thresholds` |
| 11.8 | Result includes `timestamp`, `analysis_version`, `config_used` | ✅ | Full audit context in each `evaluate_component()` result |
| 11.9 | Audit trail persistence (database / file) | ❌ | Future roadmap |
| 11.10 | JIRA / Slack / Teams notification on PROHIBITED result | ❌ | Future roadmap |

---

## 12. Visualization & Jupyter Integration

| # | Requirement | Status | Notes |
|---|---|---|---|
| 12.1 | Score breakdown bar chart (matplotlib) | ✅ | `OSSVisualizer.create_dashboard()` — colour-coded four-component bar |
| 12.2 | Risk gauge pie chart | ✅ | Score vs risk gap; colour-keyed to risk level |
| 12.3 | Scoring framework reference table (pandas DataFrame) | ✅ | Rendered as styled Markdown via `IPython.display` |
| 12.4 | Risk heat mapping reference table | ✅ | `OSSScorer.create_proprietary_additions()` → `Risk_Heat_Mapping` DataFrame |
| 12.5 | Geopolitical risk matrix reference table | ✅ | `Geopolitical_Risk_Matrix` DataFrame |
| 12.6 | Interactive criticality dropdown (Jupyter / ipywidgets) | ✅ | `OSSVisualizer.interactive_selector()` |
| 12.7 | `show=False` mode for test-safe dashboard rendering | ✅ | Suppresses `plt.show()` in non-interactive environments |
| 12.8 | Standalone CLI or REST API interface | ❌ | Jupyter/notebook only; future roadmap |
| 12.9 | HTML / PDF report export | ❌ | Future roadmap |

---

## 13. Test Coverage

| # | Requirement | Status | Notes |
|---|---|---|---|
| 13.1 | Unit tests using `pytest` + `unittest.mock` | ✅ | 163 tests across 30 test classes |
| 13.2 | Config loading tests (defaults, env overrides, missing file) | ✅ | `TestOSSConfig` — 4 tests |
| 13.3 | GitHub URL parsing tests (valid, malformed, edge cases) | ✅ | `TestParseGitHubOwnerRepo` — 6 tests |
| 13.4 | Header building tests | ✅ | `TestBuildHeaders` — 4 tests |
| 13.5 | GitHub metrics fetch tests (success, network error, bad URL) | ✅ | `TestGetGitHubMetrics` — 4 tests |
| 13.6 | NVD v2 CVE parsing tests (severity bands, EPSS, errors) | ✅ | `TestCheckCves` — 4 tests |
| 13.7 | EPSS score fetch and batch-split tests | ✅ | `TestGetEpssScores` — 4 tests |
| 13.8 | Security score calculation tests (all deduction tiers, floor, scorecard blend) | ✅ | `TestCalculateSecurityScore` — 10 tests |
| 13.9 | Activity score staleness bucket tests | ✅ | `TestCalculateActivityScore` — 7 tests |
| 13.10 | Trust score blending tests | ✅ | `TestCalculateTrustScore`, `TestTrustScoreBlending` — 9 tests |
| 13.11 | Community score tests (stars, downloads, blend) | ✅ | `TestCalculateCommunityScore`, `TestCalculateCommunityScoreWithDownloads` — 12 tests |
| 13.12 | Approval threshold boundary tests | ✅ | `TestDetermineApproval` — 10 tests |
| 13.13 | Risk level mapping tests | ✅ | `TestGetRiskLevel` — 5 tests |
| 13.14 | Input validation tests | ✅ | `TestEvaluateComponentValidation` — 3 tests |
| 13.15 | OpenSSF Scorecard fetch tests | ✅ | `TestGetScorecard` — 4 tests |
| 13.16 | Scorecard security score blending tests | ✅ | `TestSecurityScoreBlending` — 4 tests |
| 13.17 | Geocoding fast-path and Nominatim fallback tests | ✅ | `TestGeocodeLocation` — 9 tests |
| 13.18 | Geo-risk weighted scoring tests | ✅ | `TestCalculateGeoRiskScore` — 6 tests |
| 13.19 | Contributor location fetch tests | ✅ | `TestGetContributorLocations` — 3 tests |
| 13.20 | Registry resolution tests (direct, alias, disabled, unknown) | ✅ | `TestResolveRegistry` — 11 tests |
| 13.21 | Per-registry download fetcher tests (all 6 registries + edge cases) | ✅ | `TestGetDownloadCount` — 10 tests |
| 13.22 | OSV ecosystem resolution tests | ✅ | `TestResolveOsvEcosystem` — 9 tests |
| 13.23 | OSV advisory parsing tests (MAL-, GHSA, CVE alias deduplication) | ✅ | `TestCheckOsv` — 11 tests |
| 13.24 | OSV security score effect tests | ✅ | `TestOsvSecurityScoreEffect` — 6 tests |
| 13.25 | End-to-end malicious package PROHIBITED override test | ✅ | `TestEvaluateMaliciousComponent` — 2 tests |
| 13.26 | Config thresholds default values test | ✅ | `TestConfigThresholdsDefault` — 2 tests |
| 13.27 | EPSS config threshold override test | ✅ | `TestEpssConfigThresholds` — 3 tests |
| 13.28 | Scorecard enabled flag test | ✅ | `TestScorecardEnabledFlag` — 2 tests |
| 13.29 | Score weights sum validation warning test | ✅ | `TestWeightsSumWarning` — 2 tests |
| 13.30 | Integration / end-to-end tests with real API calls | ❌ | Future roadmap (requires API keys and network) |
| 13.31 | Performance / load tests | ❌ | Future roadmap |

---

## 14. Roadmap Items (no formal OPG requirement yet)

Items without an OPG-* number are unscheduled backlog entries. Items that now have a formal
requirement are listed with their OPG ID.

| # | Requirement | Priority | OPG Ref | Notes |
|---|---|---|---|---|
| 14.1 | License compliance detection | High | OPG-133–138 | Formalised in section 15 |
| 14.2 | Transitive dependency analysis | High | OPG-020 | Full graph via dependency graph construction |
| 14.3 | Audit trail persistence | Medium | OPG-081 | Immutable audit log |
| 14.4 | REST API / CLI interface | Medium | OPG-075 | Optional REST service |
| 14.5 | CI/CD pipeline integration | Medium | OPG-073–074 | GitHub Action + CI templates |
| 14.6 | JIRA / Slack / Teams notifications | Medium | — | No formal requirement yet |
| 14.7 | GitLab / Bitbucket support | Medium | OPG-074 | Covered by reusable CI templates |
| 14.8 | Release cadence scoring | Low | — | No formal requirement yet |
| 14.9 | Issue/PR response time metric | Low | — | No formal requirement yet |
| 14.10 | Commit frequency metric | Low | — | No formal requirement yet |
| 14.11 | Multi-package batch evaluation | Low | OPG-068 | CLI manifest scan |
| 14.12 | Historical trend dashboard | Low | — | No formal requirement yet |
| 14.13 | HTML / PDF report export | Low | OPG-137 | Via license compliance report; general export roadmap |
| 14.14 | Maven download count | Low | — | Pending public Maven Central API |
| 14.15 | Package proxy / registry firewall | Medium | OPG-152 | Formalised in section 20 |
| 14.16 | Automated fix PR creation | Medium | OPG-150 | Formalised in section 20 |
| 14.17 | Container image scanning | Medium | OPG-151 | Formalised in section 20 |

---

## 15. License Compliance

| # | Requirement | Status | Notes |
|---|---|---|---|
| 15.1 | SPDX license detection (OPG-133) | ❌ | Identify declared license from registry metadata and package files; parse SPDX expressions; store canonical SPDX identifier per package |
| 15.2 | Copyleft propagation analysis (OPG-134) | ❌ | Flag GPL-2/3, LGPL, AGPL, MPL, EPL; determine strong/weak copyleft applicability based on link type |
| 15.3 | License compatibility matrix (OPG-135) | ❌ | Configurable compatibility matrix; flag incompatible combinations in the dependency graph; custom allow/deny rules |
| 15.4 | Dual-license and commercial restriction detection (OPG-136) | ❌ | Detect dual-licensed packages with commercial fees or non-commercial-use clauses; surface as REVIEW finding |
| 15.5 | License compliance report (OPG-137) | ❌ | Machine-readable report per component: license, compatibility verdict, applicable policy rule; JSON and Markdown outputs |
| 15.6 | Attribution / NOTICE file generation (OPG-138) | ❌ | Aggregate copyright notices and license texts for all direct and transitive dependencies; suitable for distribution bundles |

---

## 16. Dependency Management — Extended

| # | Requirement | Status | Notes |
|---|---|---|---|
| 16.1 | Dependency pinning policy enforcement (OPG-139) | ❌ | Flag manifests with floating ranges (^, ~, *, latest, >x); configurable allowed range styles per ecosystem; lockfile hash-pin requirement separately configurable |
| 16.2 | End-of-life and formal deprecation tracking (OPG-140) | ❌ | Ingest official EOL dates from registry deprecation flags, endoflife.date API, and language-runtime schedules; surface as distinct REVIEW/PROHIBITED finding with exact EOL date |

---

## 17. Evidence Providers — Extended

| # | Requirement | Status | Notes |
|---|---|---|---|
| 17.1 | Private registry provider (OPG-141) | ❌ | Support JFrog Artifactory, Sonatype Nexus, GitHub Packages, AWS CodeArtifact, Azure Artifacts, Google Artifact Registry; credentials never hard-coded |
| 17.2 | Real-time new-version alerting (OPG-142) | ❌ | Subscribe to registry publication feeds (npm hooks, PyPI RSS, crates.io); emit typed event when watched package publishes a new version whose risk score exceeds the approved version by a configurable delta |
| 17.3 | Maintainer account credibility scoring (OPG-143) | ❌ | Score account age, MFA status, prior release history, and organisational affiliation; separate from ownership-transfer detection (OPG-052) |

---

## 18. Supply Chain Defense — Extended

| # | Requirement | Status | Notes |
|---|---|---|---|
| 18.1 | Static behavioral analysis of package source (OPG-144) | ❌ | AST-level analysis for outbound network calls, child-process spawning, filesystem writes, env-var exfiltration, dynamic evaluation; typed signal per behavior; never execute the code |
| 18.2 | Phantom dependency detection (OPG-145) | ❌ | Cross-reference static import analysis of user project source against declared manifest; identify imports satisfied only by transitive or phantom packages |
| 18.3 | Source-artifact binding via reproducible-build equivalence (OPG-146) | ❌ | Rebuild from declared source revision and compare digest to published artifact; report match, mismatch, or unverifiable with evidence |
| 18.4 | Adversarial namespace squatting detection (OPG-147) | ❌ | Detect recently-registered packages (<30 days) closely matching a popular package name with no prior publisher history; configurable confidence thresholds |

---

## 19. Policy Engine — Extended

| # | Requirement | Status | Notes |
|---|---|---|---|
| 19.1 | Cross-ecosystem vulnerability cascade modeling (OPG-148) [Research] | ❌ | Model CVE propagation from foundational C/C++ libraries (OpenSSL, zlib, libcurl) to wrapper packages across npm, PyPI, Ruby, Maven; aggregate cross-ecosystem blast-radius score; ground-truth labeled benchmark |

---

## 20. Outputs, APIs & Developer Integrations — Extended

| # | Requirement | Status | Notes |
|---|---|---|---|
| 20.1 | SBOM generation for the analyzed project (OPG-149) | ❌ | Produce CycloneDX 1.5 or SPDX 2.3 SBOM of user's project enriched with policy decisions, CVSS, EPSS, and license data; validate against official schema; attach to CI artifacts |
| 20.2 | Automated fix pull-request creation (OPG-150) | ❌ | When safe upgrade identified (OPG-038) and token configured, open dependency-update PR modifying manifest and lock file; PR body includes risk reduction summary and scan report link |
| 20.3 | Container image and OS-package scanning (OPG-151) | ❌ | Accept container image reference or OCI tarball; extract OS package database (dpkg/rpm/apk); scan through same evidence providers and policy engine; report unified findings |
| 20.4 | Package proxy / registry firewall mode (OPG-152) | ❌ | Operate as HTTPS proxy in front of public registry; evaluate policy before package enters build environment; block PROHIBITED packages with typed error response; log all interceptions |

---

## 21. Quality & Compliance — Extended

| # | Requirement | Status | Notes |
|---|---|---|---|
| 21.1 | Compliance evidence packaging (OPG-153) | ❌ | Exportable evidence bundles for SOC 2 Type II (CC7.2/CC8.1), FedRAMP third-party component tracking, PCI-DSS SCA; machine-readable JSON + Markdown; includes scan date, policy digest, findings, remediation status |

---

## 22. Research — Extended

| # | Requirement | Status | Notes |
|---|---|---|---|
| 22.1 | LLM-assisted novel malicious pattern recognition (OPG-154) [Research] | ❌ | Language model generates natural-language explanations for suspicious behaviors not covered by rule-based signals; calibrate against confirmed-malicious ground-truth corpus; publish precision/recall; no auto-enforcement without human review |
| 22.2 | Runtime dependency inventory via instrumentation (OPG-155) [Research] | ❌ | Discover packages loaded in running Python or Node.js process via import hooks or eBPF tracing; compare runtime inventory to manifest; surface undeclared runtime dependencies as phantom-dependency findings |
| 22.3 | Infrastructure-as-Code deployment context enrichment (OPG-156) [Research] | ❌ | Parse Terraform, Helm, Kubernetes manifests to determine deployment exposure (internet-facing, internal, batch-only); pass context to blast-radius model for environment-adjusted risk scores |
| 22.4 | Hierarchical team-scoped catalog with delegated administration (OPG-157) | ❌ | BU security teams approve packages within enterprise policy envelope; application teams create scoped exceptions with rollup reporting; revocation cascades downward; all delegation actions in immutable audit log (OPG-081) |

---

*Last updated: 2026-08-15 — 25 new requirements added (OPG-133–157); 213 tests passing.*
