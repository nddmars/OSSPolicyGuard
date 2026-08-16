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

| Decision | Score range | Conditions | Action |
|----------|-------------|------------|--------|
| APPROVED | ≥ 80 | No hard blocks | Safe to use |
| REVIEW REQUIRED | 60–79 | Advisory flags or low sub-scores | Manual review needed |
| PROHIBITED | Any | Malicious package, critical exploit with active EPSS, or hard policy rule | Block immediately |

A package with a high numeric score can still receive PROHIBITED if a hard-block condition is triggered (for example, a confirmed malicious-package flag or a KEV-listed vulnerability above the EPSS threshold).

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

A ready-to-use workflow lives at `.github/workflows/osspolicyguard-action.yml` and triggers on pull requests that touch `requirements.txt` or `package.json`. To add it to another repository:

```yaml
- uses: actions/checkout@v4
- uses: actions/setup-python@v7
  with:
    python-version: '3.11'
- run: pip install -e .
- run: python scripts/osspolicyguard_action.py
```

### Configuration

The scanner reads `config.yaml` at startup. A JSON Schema for editor validation is provided at `config.schema.json`. To enable a jurisdiction compliance check, set `geo_compliance: true` in the `risk` section; it is disabled by default.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | All packages APPROVED |
| 1 | At least one package PROHIBITED |
| 2 | At least one package REVIEW REQUIRED (when `--review-fails-ci` is set) |
| 3 | Configuration error |
| 4 | Provider or network error |
| 99 | Unexpected internal error |

## Scoring methodology

Each package receives a composite score from 0 to 100 across four weighted dimensions:

- **Security (35%)** — CVE severity, EPSS exploitability probability, KEV presence, OSV advisories, and malicious-package signals.
- **Maintenance (30%)** — Commit recency, release cadence, open issue ratio, and bus-factor estimate.
- **Supply-chain (20%)** — OpenSSF Scorecard sub-scores, provenance signals, and repository visibility.
- **Community (15%)** — Download volume, dependent-package count, and contributor breadth.

Hard blocks (malicious flag, critical CVE with active EPSS above threshold, explicit policy rule) override the numeric score and force a PROHIBITED decision regardless of total. See [REQUIREMENTS.md](REQUIREMENTS.md) for the full factor definitions, weight rationale, and threshold tables.

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
