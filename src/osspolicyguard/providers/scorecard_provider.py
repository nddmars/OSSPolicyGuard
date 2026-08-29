"""OpenSSF Scorecard provider: fetches automated supply-chain security scores."""

from __future__ import annotations

# TODO: Implement ScorecardProvider.fetch()
#   - Accept a GitHub repository URL as the first argument.
#   - Query the public Scorecard REST API
#     (https://api.securityscorecards.dev/projects/github.com/{owner}/{repo}).
#   - Extract the top-level score (0–10) and per-check scores into
#     ProviderResponse.data as {"score": float, "checks": {name: score, ...},
#     "date": str}.
#   - Derive freshness_seconds from the "date" field in the API response.
#   - Handle 404 (repo not indexed) → ProviderStatus.UNAVAILABLE, 429 →
#     ProviderStatus.RATE_LIMIT, timeout → ProviderStatus.TIMEOUT.
#   - No authentication required; respect self._timeout.
