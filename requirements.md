# OSSPolicyGuard Requirements Roadmap

**Purpose:** turn OSSPolicyGuard into a trustworthy, installable, explainable policy-as-code product that developers can run locally and enforce in CI.

**Primary success test:** a stranger can install the project, scan one dependency, understand the decision, and reproduce the result in under five minutes.

This document is structured so a developer can implement one requirement group at a time. Each group includes behavior, acceptance criteria, focused Pytest expectations, and a verification gate.

## 1. Developer execution protocol

For every requirement group:

1. Read the group and acceptance criteria before editing.
2. Inspect the existing implementation and tests.
3. Write or update tests first where practical.
4. Make the smallest implementation change that satisfies the criteria.
5. Run the exact verification commands listed for the group.
6. Do not start the next group until every acceptance criterion passes.
7. If a test fails, fix the current group or record a blocker; do not weaken the test.
8. Preserve existing behavior unless the requirement explicitly changes it.
9. Update documentation and release notes for user-visible behavior.
10. Report changed files, tests added, commands run, results, and remaining risks.

Required baseline from the repository root:

    python -m pytest -q

The normal test suite must not depend on live NVD, OSV, GitHub, registry, or geocoding services. Use mocks or recorded fixtures. A group is complete only when its focused tests and the full Pytest suite pass, required lint/type/security checks pass, and its documentation is updated.

## 2. Priority and delivery gates

- P0: required for a credible public beta.
- P1: required for adoption, trust, integrations, and community growth.
- P2: scale and differentiation after real usage exists.

| Phase | Outcome | Gate before next phase |
|---|---|---|
| 0. Foundation | Maintainable package, tests, and CLI contract | Clean install and full Pytest pass |
| 1. Explainable engine | Stable JSON, evidence, and policy decisions | Fixture results are reproducible |
| 2. CI integration | GitHub Action, SARIF, and PR feedback | Sample workflow passes and blocks correctly |
| 3. Adoption | Pilots, docs, benchmark, and community workflow | Independent users succeed without author help |
| 4. Impact | External usage, integrations, references, and upstream work | Evidence ledger shows durable independent impact |

## 3. Product contract and safety

### REQ-001 — Public product contract (P0)

OSSPolicyGuard evaluates open-source dependencies using vulnerability, exploitability, maintenance, community, license/compliance, and supply-chain evidence, then returns APPROVED, REVIEW, or PROHIBITED.

Acceptance criteria:

- README states the target user, primary workflow, decision states, and non-goals.
- README states that a score is not proof that a package is safe.
- Scores use one documented direction: higher means safer.
- Supported Python versions and initial ecosystems are documented.
- Implemented features are separated from planned features.

Required tests and checks:

- Add a documentation checklist test or review checklist for the above claims.
- Run: 'python -m pytest -q'.

### REQ-002 — Safe signal policy (P0)

Use measurable technical evidence. Do not use maintainer nationality, ethnicity, religion, or inferred personal identity as a security score. Geography may exist only as an explicitly labeled organization compliance rule, never as a default maliciousness proxy.

Acceptance criteria:

- Default scoring contains no identity or geography penalty.
- Technical alternatives are documented: signed releases, provenance, branch protection, ownership changes, release recency, package age, typosquatting similarity, OpenSSF/SLSA evidence, and security policy presence.
- Jurisdiction rules, if supported, are opt-in and separate from the core security score.
- Every deduction identifies its source and meaning.

Required tests:

- Same technical score when maintainer-location metadata changes.
- Explicit compliance rule is labeled separately.
- Run: 'python -m pytest -q tests/test_oss_scorer.py'.

## 4. Repository and packaging foundation

### REQ-010 — Maintainable package layout (P0)

Split the concentrated implementation into modules without changing the public CLI behavior.

Target structure:

    src/osspolicyguard/
        __init__.py
        cli.py
        models.py
        config.py
        errors.py
        providers/base.py
        providers/github.py
        providers/nvd.py
        providers/osv.py
        providers/epss.py
        providers/registries.py
        providers/malicious_packages.py
        providers/openssf.py
        policy/scoring.py
        policy/decisions.py
        policy/explain.py
        reports/human.py
        reports/json.py
        reports/sarif.py
        manifests/detect.py
        manifests/python.py
        manifests/node.py

Acceptance criteria:

- Provider retrieval, normalization, scoring, policy decisions, and rendering have separate responsibilities.
- Public imports remain stable or have a migration note.
- A contributor can add one provider without editing unrelated providers.
- No module performs live network calls during import.
- Existing tests still pass.

Required tests:

- Import tests for public modules.
- Regression test for required top-level scan fields.
- Run: 'python -m pytest -q tests/test_cli.py tests/test_oss_scorer.py'.

### REQ-011 — Installable package and CLI entry point (P0)

Acceptance criteria:

- pyproject.toml contains package metadata, supported Python versions, dependencies, and the osspolicyguard console entry point.
- 'python -m pip install -e .[dev]' succeeds.
- 'osspolicyguard --help' succeeds.
- README has one canonical install instruction.
- Notebook-only dependencies are optional or removed from runtime dependencies.

Required tests:

- Subprocess test for help output.
- Clean-install check in CI.
- Run: 'python -m pytest -q tests/test_cli.py'.

### REQ-012 — Quality automation (P0)

Acceptance criteria:

- GitHub Actions runs on pull requests and pushes to the default branch.
- Pytest, Ruff, Black check, and MyPy commands are documented.
- Dependency updates and CodeQL or equivalent static analysis are enabled.
- CI does not require live provider credentials.
- Failure output identifies the failing check.

Required checks:

- 'python -m pytest -q'
- 'python -m ruff check .'
- 'python -m black --check .'
- 'python -m mypy src'

## 5. CLI contract and machine output

### REQ-020 — Package scan command (P0)

Support:

    osspolicyguard scan express --ecosystem npm --criticality business-critical
    osspolicyguard scan express --ecosystem npm --format json

Acceptance criteria:

- scan accepts package, ecosystem, optional version, criticality, policy path, repository URL, output format, output path, and offline/cache controls as applicable.
- Human output shows identity, score or insufficient-data state, decision, dimensions, findings, and remediation.
- JSON output is valid JSON on stdout with no logging noise.
- Invalid input produces a helpful message and nonzero exit code.
- Command is non-interactive and CI-safe.

Required tests:

- Human output with a mocked scan.
- JSON output parsed with json.loads.
- Invalid ecosystem and missing package tests.
- stdout/stderr separation.
- Run: 'python -m pytest -q tests/test_cli.py'.

### REQ-021 — Exit-code contract (P0)

Acceptance criteria:

- APPROVED returns 0.
- REVIEW follows a documented configurable rule.
- PROHIBITED returns a nonzero policy-failure code.
- Invalid input and provider/system failure have distinct documented behavior.
- Formatter failure cannot turn PROHIBITED into success.
- Result includes effective enforcement mode.

Required tests:

- Parameterized decision/exit-code matrix.
- review_fails_ci true and false.
- Provider failure and malformed policy.
- Run: 'python -m pytest -q tests/test_cli.py'.

### REQ-022 — Versioned JSON schema (P0)

Minimum result fields:

    schema_version
    tool_version
    package: name, ecosystem, version
    policy: name, version
    decision
    score or insufficient_data
    dimensions
    findings
    evidence
    warnings
    generated_at

Acceptance criteria:

- Schema is committed and versioned independently of package version.
- Findings contain stable ID, severity, dimension, contribution, confidence, evidence, and remediation.
- Evidence contains provider, source identifier or URL, retrieval time, freshness, and status.
- Provider unavailable differs from no finding.
- Golden tests detect accidental output changes.

Required tests:

- Valid and invalid schema tests.
- Golden files for APPROVED, REVIEW, PROHIBITED, and partial-data results.
- Run: 'python -m pytest -q tests/test_cli.py tests/test_reports.py'.

## 6. Evidence providers and scoring

### REQ-030 — Provider interface and resilience (P0)

Create a common provider contract for GitHub, NVD, OSV, EPSS, registries, malicious-package intelligence, and future OpenSSF signals.

Acceptance criteria:

- Providers return normalized evidence or a typed provider error.
- Each provider has timeout, retry/backoff, rate-limit, and cache behavior.
- Tests use mocked or recorded responses.
- API keys are optional unless upstream requires them.
- Provider status and freshness appear in the final report.
- Failed providers never become an unannounced zero-risk result.
- Network calls are bounded.

Required tests:

- Success, timeout, rate-limit, malformed response, network-error, cache-hit, and cache-expiry tests for each provider.
- Run: 'python -m pytest -q tests/test_oss_scorer.py tests/test_providers.py'.

### REQ-031 — Package identity normalization (P0)

Acceptance criteria:

- Package name, ecosystem, version, registry coordinates, repository URL, direct/transitive status, and aliases normalize consistently.
- Ambiguous identity fails safely.
- Evaluated version appears in every report.
- Lockfile resolution is used for ranges.
- Unsupported ecosystems are reported as unsupported.

Required tests:

- npm, PyPI, Rust, Ruby, NuGet, PHP, and Maven mapping tests.
- Aliases, scoped names, versions, and invalid identity tests.
- Run: 'python -m pytest -q tests/test_oss_scorer.py'.

### REQ-032 — Explainable scoring (P0)

Acceptance criteria:

- Publish dimensions, weights, thresholds, normalization, confidence, and missing-data behavior.
- Reports show positive and negative evidence.
- Each material finding explains score and decision impact.
- Hard rules are separate from weighted score math.
- Tool can abstain when coverage is too low.
- Methodology changes have decision record and release-note entries.

Required tests:

- Each dimension independently.
- Weight normalization and threshold boundaries.
- Missing-data and low-confidence outcomes.
- Malicious-package hard prohibition.
- Run: 'python -m pytest -q tests/test_scoring.py tests/test_oss_scorer.py'.

### REQ-033 — Policy-as-code configuration (P0)

Support a documented YAML policy with thresholds, hard rules, exceptions, and enforcement behavior.

Example fields:

    version
    name
    thresholds.approved
    thresholds.review
    enforcement.review_fails_ci
    signals
    exceptions

Acceptance criteria:

- Invalid policy gives line-level validation errors.
- Default policy is useful and unsurprising.
- Policy name/version appear in every result.
- Exceptions require package, owner, reason, expiration, and review status.
- Expired exceptions are not silently accepted.
- Rule precedence is documented and tested.
- Policy runs offline with fixtures.

Required tests:

- Valid/invalid YAML.
- Threshold boundaries.
- Hard-rule-versus-score precedence.
- Exception owner/reason/expiration.
- Run: 'python -m pytest -q tests/test_policy.py'.

### REQ-034 — Security signal coverage (P0/P1)

Acceptance criteria:

- NVD/CVSS data includes identifiers and affected versions.
- OSV advisories are represented and deduplicated against CVE aliases.
- EPSS is attached to applicable CVEs with retrieval time.
- Malicious-package indicators are distinct from ordinary vulnerabilities.
- GitHub activity/community signals have definitions and freshness.
- Registry downloads are context, not proof of safety.
- OpenSSF Scorecard/SLSA/Sigstore inputs have a modular optional boundary.
- License/compliance policy is separate from security scoring.

Required tests:

- Existing NVD, EPSS, OSV, malicious-package, registry, and GitHub fixtures continue passing.
- Deduplication and provider-failure tests.
- Run: 'python -m pytest -q tests/test_oss_scorer.py'.

## 7. Manifest and dependency workflows

### REQ-040 — Manifest and lockfile scanning (P1)

Acceptance criteria:

- First supported ecosystems are documented and tested.
- Direct and transitive dependencies are labeled.
- Newly introduced dependencies can be identified from a PR diff.
- Unresolved versions and unsupported syntax produce warnings.
- Unchanged dependencies are not rescanned by default in PR mode.

Required tests:

- Fixture manifests and lockfiles.
- Direct, transitive, changed, unchanged, unresolved, and malformed cases.
- Run: 'python -m pytest -q tests/test_manifests.py'.

## 8. GitHub Action and CI/CD integration

### REQ-050 — GitHub Action (P0/P1)

A consuming repository should need checkout, the versioned Action, manifest, and policy.

Acceptance criteria:

- Inputs include manifest, lockfile, package, policy, format, and enforcement.
- PR mode evaluates changed dependencies by default; full scan is opt-in.
- Action produces JSON artifact, Markdown job summary, and SARIF where permitted.
- Action updates one stable PR comment rather than spamming.
- Action fails only when policy requires it.
- Forks and missing secrets produce actionable behavior.
- Required permissions are minimized and documented.
- Major action tag and breaking-change policy are published.

Required tests and checks:

- Action metadata validation.
- Fixture workflow tests for approved, review, prohibited, provider failure, fork, and missing-permission cases.
- Run: 'python -m pytest -q tests/test_action.py'.
- Validate a sample repository workflow before marking complete.

### REQ-051 — CI-neutral outputs (P1)

Acceptance criteria:

- JSON is available for automation.
- SARIF is valid and maps findings to packages/locations where possible.
- Markdown is readable in PR comments and job summaries.
- One non-GitHub CI example is documented.
- Reports do not leak secrets or private URLs unexpectedly.

Required tests:

- SARIF schema validation.
- Markdown escaping and deterministic rendering.
- Run: 'python -m pytest -q tests/test_reports.py tests/test_sarif.py'.

## 9. Security, releases, and operations

### REQ-060 — Project security (P0)

Acceptance criteria:

- SECURITY.md explains supported versions and private reporting.
- Dependabot or equivalent is enabled.
- CodeQL or equivalent is enabled.
- Action permissions are least-privilege.
- Secrets never appear in logs, fixtures, reports, or examples.
- Threat model covers malicious packages, provider compromise, stale data, action tampering, and report manipulation.

Required checks:

- Security workflow passes.
- Redaction and secret-safe logging regression tests.
- Run: 'python -m pytest -q'.

### REQ-061 — Versioned releases (P0)

Acceptance criteria:

- Publish an initial v0.1.0 or clearly labeled beta.
- Use semantic versioning or document the alternative.
- Publish changelog and release notes.
- Define compatibility for CLI, JSON schema, policy format, and Action major tags.
- Build and publish from CI with trusted publishing or documented equivalent.
- Generate provenance, SBOM, and signatures where feasible.

Required checks:

- Build and install in a clean environment.
- Verify osspolicyguard --help after install.
- Run: 'python -m pytest -q'.

## 10. Documentation and onboarding

### REQ-070 — README and five-minute quick start (P0)

Acceptance criteria:

- README answers problem, user, differentiation, install, first scan, CI behavior, limitations, and contribution path.
- Quick start is terminal-first and copy-pasteable.
- Includes human, JSON, and Action examples.
- Includes architecture diagram and ecosystem support matrix.
- Does not claim OpenSSF endorsement or adoption without evidence.
- Links to policy, troubleshooting, security, roadmap, and contributing docs.

Required checks:

- Documentation checklist review.
- Run: 'python -m pytest -q'.

### REQ-071 — Demonstration assets (P1)

Create reproducible examples for a package that passes, one that requires review, and a safe fixture that demonstrates malicious/typosquat blocking without encouraging use of live malicious packages.

Acceptance criteria:

- Examples run without undisclosed credentials.
- Expected decision and reasons are documented.
- A 60–90 second demo shows installation, scan, and CI/PR result.
- Examples are tested in CI or periodically verified.

Required tests:

- Example smoke tests with mocked providers.
- Run: 'python -m pytest -q tests/test_examples.py'.

### REQ-072 — Trust documentation (P1)

Acceptance criteria:

- Publish scoring methodology, data sources, attribution, freshness, caching, missing-data, privacy, telemetry, false-positive, false-negative, and correction procedures.
- Document exception governance.
- Explain what the tool can and cannot conclude.
- Link every signal to source and semantics.

Required checks:

- Documentation review against the acceptance list.
- Run: 'python -m pytest -q'.

## 11. OpenSSF alignment

### REQ-080 — OpenSSF-compatible positioning (P1)

Acceptance criteria:

- Describe OSSPolicyGuard as an organization-level policy and decision layer that consumes ecosystem evidence.
- Keep Scorecard, SLSA, Sigstore, OSV, malicious-package intelligence, and dependency-graph integrations modular and accurately labeled.
- Do not claim certification, endorsement, or partnership without a public source.
- Pursue at least one narrowly scoped upstream contribution or public technical discussion when mature.
- Record external discussions and contributions with durable links.

Required checks:

- Review README and integration documentation.
- Run provider and report tests.
- Run: 'python -m pytest -q'.

## 12. Community growth and adoption

### REQ-090 — Contributor experience (P1)

Acceptance criteria:

- Add CONTRIBUTING.md, CODE_OF_CONDUCT.md, issue templates, PR template, and roadmap.
- Explain setup, tests, linting, fixtures, provider adapters, policies, and report formats.
- Provide real good-first-issue tasks.
- Contributors can run tests without live API keys.
- Maintainer response and triage expectations are documented.

Required checks:

- Clean checkout follows CONTRIBUTING.md through a passing test run.
- Run: 'python -m pytest -q'.

### REQ-091 — Pilot program (P1)

Acceptance criteria:

- Recruit five independent pilot users from security, DevSecOps, platform engineering, or open-source communities.
- Each pilot runs a real or representative repository.
- Collect setup time, decision usefulness, false positives, missing signals, and CI willingness.
- Convert recurring feedback into public issues or documented decisions where privacy permits.
- Publish anonymized findings with method and limitations.

Required evidence:

- Pilot repository or workflow link where permission exists.
- Issue, pull request, or written feedback artifact.
- Date, participant role, scenario, result, and follow-up action.

### REQ-092 — Discoverability with substance (P1)

Acceptance criteria:

- Publish package and Action metadata with accurate keywords.
- Add a release announcement based on a real feature, benchmark, or user problem.
- Publish technical articles or talks explaining implementation and limitations.
- Contact communities with a concrete technical question or demo, not a generic star request.
- Measure successful scans and repeat usage, not only impressions or stars.

## 13. Validation and benchmarking

### REQ-100 — Public benchmark (P1)

Acceptance criteria:

- Benchmark contains safe, vulnerable, abandoned, malicious/typosquat, popular, and ambiguous fixtures.
- Inputs, expected findings, retrieval dates, tool version, policy version, and limitations are recorded.
- Benchmark runs offline.
- Metrics include false positives, false negatives where measurable, coverage, latency, and provider failure behavior.
- Major methodology changes rerun the benchmark and publish differences.

Required tests:

- Benchmark fixtures and expected-result tests.
- Run: 'python -m pytest -q tests/test_benchmark.py'.

### REQ-101 — Reproducible reports (P1)

Acceptance criteria:

- Store sanitized fixtures and report snapshots.
- Record retrieval times and provider status.
- Provide a command to regenerate public results offline.
- Reports disclose which upstream data may change.

Required tests:

- Regeneration command runs in CI.
- Output matches golden files.
- Run: 'python -m pytest -q tests/test_reproducibility.py'.

## 14. Independent-impact evidence

This section helps preserve evidence of real external impact; it is not legal advice and does not guarantee immigration eligibility.

### REQ-110 — Evidence ledger (P1)

Maintain a private or repository-local ledger:

| Date | Evidence type | Independent party | What happened | Durable URL/artifact | Verification |
|---|---|---|---|---|---|
| YYYY-MM-DD | External issue | User or organization | Reported and reproduced a finding | Issue/PR/release URL | Screenshot/export |

Acceptance criteria:

- Record external users, organizations, Action references, package downloads, forks, issues, pull requests, citations, talks, reviews, and upstream work.
- Record dates, roles, links, and artifacts while fresh.
- Preserve screenshots/exports for mutable metrics.
- Distinguish independent evidence from self-authored promotion.
- Do not call the project adopted based only on stars, impressions, or one unaudited installation.
- Get permission before publishing testimonials or identifying organizations.

### REQ-111 — Impact targets (P1)

Prioritize:

1. Independent repositories running the Action.
2. External issues and meaningful pull requests.
3. Recurring package or Action usage.
4. Independent articles, talks, courses, or citations.
5. Upstream security-ecosystem contributions.
6. Reused benchmark results.
7. Expert references based on direct observation.

## 15. Metrics and guardrails

Track monthly:

- time from clean install to first successful scan;
- successful scans and repeat usage;
- Action references and package downloads;
- independent pilots and external contributors;
- findings with source, timestamp, and confidence;
- false-positive reports and resolution time;
- CI and release success rate;
- external references, talks, citations, and upstream contributions.

Do not increase false positives to make the tool appear stricter, change weights silently to improve benchmarks, collect telemetry without consent, claim adoption from vanity metrics, hide provider failures, or allow exceptions without owner, reason, and expiry.

## 16. Recommended implementation order

1. Rewrite README and confirm product contract.
2. Add packaging and verify clean install.
3. Add typed result/evidence models.
4. Extract provider interfaces.
5. Stabilize CLI human and JSON output.
6. Add JSON schema and golden tests.
7. Add policy loader, validation, exit codes, and exception tests.
8. Add provider resilience and fixture tests.
9. Add CI quality/security checks.
10. Add security, contribution, conduct, issue-template, and roadmap files.
11. Publish beta package/release.
12. Add SARIF and Markdown reports.
13. Build and test GitHub Action.
14. Create demo repositories/fixtures.
15. Recruit five pilots and publish anonymized findings.
16. Publish benchmark and methodology.
17. Start and update the evidence ledger monthly.
18. Expand OpenSSF and ecosystem integrations only after the core workflow is reliable.

## 17. Definition of done for every requirement

A requirement is complete only when:

- implementation exists behind a stable interface;
- acceptance criteria are checked one by one;
- focused Pytest tests exist and pass;
- full Pytest suite passes;
- required lint/type/security checks pass;
- documentation and examples are updated;
- errors and partial-data behavior are tested;
- no live network dependency exists in the normal test suite;
- compatibility and release impact are documented;
- Developer reports exact commands and results before moving on.

## 18. First-release gate

Do not call the project a credible public beta until:

- a stranger can install it from the README;
- a stranger can scan one package from a terminal;
- the result includes decision, score or abstention, reasons, evidence, and remediation;
- JSON output is stable enough for automation;
- scoring and policy methodology is public;
- provider failures and stale data are visible;
- tests cover important decisions and failure modes;
- CI verifies pull requests;
- security and contribution workflows exist;
- a versioned package/release is published;
- a complete GitHub Action example exists;
- at least one independent pilot has completed the workflow.

The north-star outcome is: **make a stranger successful in five minutes, then make that success repeatable in a pull request.**

