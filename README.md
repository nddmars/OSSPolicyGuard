# OSSPolicyGuard 🛡️

OSSPolicyGuard is a policy-as-code engine that evaluates open-source dependencies using measurable technical signals such as vulnerability, exploitability, maintenance, community, and supply-chain evidence, then returns an auditable approve, review, or prohibit decision.

## Safety policy

OSSPolicyGuard does not infer maliciousness from maintainer nationality, ethnicity, religion, or other personal identity markers. Geography is not used as a default security signal. If a jurisdiction or compliance rule is required, it must be explicit, opt-in, and kept separate from the baseline technical score.

The project follows a simple rule: higher scores are safer, and any penalty must be traceable to a concrete technical or policy signal.

## Supported ecosystems

| Ecosystem | Registry | Download counts | Notes |
|-----------|----------|-----------------|-------|
| npm / Node.js | npmjs.com | ✅ weekly | — |
| Python | PyPI | ✅ weekly | — |
| Ruby | RubyGems | ✅ estimated | Cumulative ÷ 52 |
| Rust | crates.io | ✅ estimated | 90-day ÷ 13 |
| .NET | NuGet | ✅ estimated | Total ÷ 104 |
| PHP | Packagist | ✅ estimated | Monthly ÷ 4 |
| Java / JVM | Maven Central | ❌ N/A | No public download API |

## Decision semantics

The decision depends on the package's **criticality level** (passed via `--criticality`) and its composite score. Default thresholds are defined in `config.yaml` under `scoring.thresholds` (critical: 90, high: 80, medium: 70, low: 60):

| Decision | Mission Critical | Business Critical | Non-Critical |
|----------|-----------------|-------------------|--------------|
| APPROVED | score ≥ 90 | score ≥ 80 | score ≥ 60 |
| REVIEW | 80 ≤ score < 90 | 70 ≤ score < 80 | score < 60 |
| PROHIBITED | score < 80 | score < 70 | — (never by score alone) |

A confirmed malicious-package flag (`is_malicious=True` from the OSV/ossf malicious-packages feed) forces **PROHIBITED** regardless of the numeric score or criticality level.

> **Roadmap:** The `PolicyBundle` in `src/osspolicyguard/policy.py` defines additional hard-block rules (KEV/EPSS threshold, security-score floor). These are not yet wired into the production `OSSScorer`; see the implementation note in the Scoring methodology section below.

## Limitations

- **Not a guarantee of safety.** Scores are probability signals, not certainty. A high score does not mean a package is safe; a low score does not mean it is dangerous.
- **No transitive dependency analysis yet.** Only direct dependencies are evaluated. Transitive scanning is on the roadmap.
- **No license compliance detection yet.** License identification is on the roadmap.
- **Scorecard requires a public GitHub repository.** Packages without a detectable public repository receive a partial score on the supply-chain dimension.
- **Download counts are weekly estimates.** Methodology varies by registry and is documented in the Supported ecosystems table above.
- **Geolocation is opt-in only.** Geographic jurisdiction checks are excluded from default scores and must be explicitly configured in `config.yaml`.
- **KEV / EPSS correlation requires network access.** Offline mode uses cached data only; cached data may be stale.

## Quick start

### Install

```bash
pip install -e '.[dev]'
```

### Scan a package

```bash
osspolicyguard scan requests --ecosystem pypi --format text
```

### JSON output

```bash
osspolicyguard scan express --ecosystem npm --format json
```

### SARIF output

```bash
osspolicyguard scan lodash --ecosystem npm --format sarif
```

### GitHub Actions

A workflow that runs on pull requests is provided at `.github/workflows/osspolicyguard-action.yml` **for use within this repository**. It triggers when `requirements.txt` or `package.json` changes and calls `scripts/osspolicyguard_action.py`.

> **Using OSSPolicyGuard in another repository:** The project is not yet published as a reusable GitHub Action or installable package. To integrate it today, check out the repository at a pinned commit and install it:
> ```yaml
> - uses: actions/checkout@v4
>   with:
>     repository: nddmars/OSSPolicyGuard
>     ref: main          # pin to a specific commit SHA in production
>     path: osspolicyguard
> - run: pip install -e osspolicyguard/
> - run: osspolicyguard scan <package> --ecosystem <eco>
> ```
> A proper composite action or published package is on the roadmap (OPG-073).

### Configuration

The scanner reads `config.yaml` at startup. A JSON Schema for editor validation is provided at `config.schema.json`. To enable a jurisdiction compliance check, set `geo_compliance.enabled` in the `risk` section (it is disabled by default):

```yaml
risk:
  geo_compliance:
    enabled: true
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Package APPROVED |
| 1 | Package PROHIBITED |
| 2 | REVIEW decision (when `--review-fails-ci` is set) **or** unsupported command (e.g. `manifest`) |
| 3 | Configuration error |
| 4 | Provider or network error |
| 99 | Unexpected internal error |

## Scoring methodology

Each package receives a composite score from 0 to 100 across four weighted dimensions:

- **Security (35%)** — CVE severity bands (NVD v2), EPSS exploit-probability weighting, OSV advisories, malicious-package flag (ossf/malicious-packages), and OpenSSF Scorecard blended at 40%.
- **Maintenance (30%)** — Days since last commit, bucketed into staleness tiers.
- **Supply-chain (20%)** — Geopolitical risk from contributor locations, weighted by commit count.
- **Community (15%)** — Weekly download count (npm/PyPI true weekly; other registries estimated) and GitHub star count.

> **Implementation note:** The `PolicyBundle`, `KevProvider`, `IdentityModel`, and modular provider classes (`github_provider.py`, `nvd_provider.py`) are part of the next-generation architecture and are not yet wired into the main scoring pipeline. The CLI currently calls the production `OSSScorer` / `OSSWorkflow` classes in `oss_scorer.py`. Provider stub files contain TODO comments indicating the integration work remaining. See [DEVELOPMENT_GUIDE.md](DEVELOPMENT_GUIDE.md) for the full roadmap and implementation status.

Hard block: a confirmed malicious-package flag (`is_malicious=True`) forces a PROHIBITED decision regardless of the numeric score.

## Architecture

```text
Package input
     ↓
GitHub + OSV + NVD + EPSS + registry metadata
     ↓
Configurable policy engine
     ↓
Score + evidence + approval decision
     ↓
CLI / JSON / SARIF / GitHub Action
```

## Contributing

Contributions are welcome. Issues and pull requests are open. A `CONTRIBUTING.md` is coming soon with setup instructions, coding conventions, and the pull-request checklist.

## License

MIT
