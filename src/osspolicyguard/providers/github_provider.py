"""GitHub REST API provider: fetches repository metadata and activity signals."""

from __future__ import annotations

# TODO: Implement GitHubProvider.fetch()
#   - Accept a GitHub repository URL (or owner/repo pair) as the first argument.
#   - Query the GitHub REST API (/repos/{owner}/{repo}) using the token from
#     self.config["github"].get("token") for authenticated requests.
#   - Map stargazers_count, forks_count, pushed_at, open_issues_count, and
#     contributor count into the ProviderResponse.data payload.
#   - Handle 401/403 → ProviderStatus.AUTH_ERROR, 429 → ProviderStatus.RATE_LIMIT,
#     timeout → ProviderStatus.TIMEOUT, and generic HTTP errors appropriately.
#   - Populate source_url and freshness_seconds where possible.
