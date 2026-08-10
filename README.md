# OSSPolicyGuard 🛡️

OSSPolicyGuard is a policy-as-code engine that evaluates open-source dependencies using measurable technical signals such as vulnerability, exploitability, maintenance, community, and supply-chain evidence, then returns an auditable approve, review, or prohibit decision.

## Safety policy

OSSPolicyGuard does not infer maliciousness from maintainer nationality, ethnicity, religion, or other personal identity markers. Geography is not used as a default security signal. If a jurisdiction or compliance rule is required, it must be explicit, opt-in, and kept separate from the baseline technical score.

The project follows a simple rule: higher scores are safer, and any penalty must be traceable to a concrete technical or policy signal.

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
CLI / JSON / GitHub Action
```

## Quick start

### Install

```bash
python -m pip install -e .
```

### Scan one package

```bash
osspolicyguard scan express --ecosystem npm --criticality "Business Critical"
```

Example output:

```text
Package: express
Score: 84/100
Decision: APPROVED

Security: 88
Maintenance: 79
Community: 91
Supply-chain risk: 76
Malicious package detected: No
```

### JSON output

```bash
osspolicyguard scan express --ecosystem npm --format json
```

### Configuration

The scorer reads configuration from a local config.yaml file. A minimal example is included in the repository.

To enable a separate compliance check, opt into the geo_compliance rule in the risk section; it is not active by default.

## What it evaluates

- GitHub repository metrics
- NVD and EPSS-based vulnerability scoring
- OSV advisory checks
- Registry download and ecosystem signals
- Malicious-package detection
- Configurable policy thresholds and approval outcomes
- Optional compliance-only geographic policies when explicitly configured

## Current implementation status

The project currently includes the core CLI, scoring flow, JSON output, and a security-first policy engine. The remaining work is tracked in the requirements status file and the roadmap document.

## Development

```bash
python -m pip install -e .[dev]
python -m pytest -q
```

## Roadmap

The next milestones are:

1. Finalize the remaining pending requirement in the requirements tracker
2. Complete provider refactoring and stronger evidence reporting
3. GitHub Action integration for PR review and policy enforcement


