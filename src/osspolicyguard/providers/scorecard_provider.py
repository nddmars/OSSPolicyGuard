"""OpenSSF Scorecard provider: fetches automated supply-chain security scores."""

from __future__ import annotations

from typing import Any

import requests

from . import ProviderBase, ProviderResponse, ProviderStatus
from .github_provider import GitHubProvider

_SCORECARD_API = "https://api.securityscorecards.dev/projects/github.com"


class ScorecardProvider(ProviderBase):
    """Fetches OpenSSF Scorecard results (0-10 scale) for a GitHub repository."""

    name = "scorecard"

    def fetch(self, repo_url: str, **kwargs: Any) -> ProviderResponse:
        if not self.config.get(self.name, {}).get("enabled", True):
            return ProviderResponse(
                provider=self.name,
                status=ProviderStatus.UNAVAILABLE,
                fetched_at=self._now_iso(),
                error="Scorecard provider disabled in config",
            )

        try:
            owner, repo = GitHubProvider._parse_owner_repo(repo_url)
        except ValueError as exc:
            return ProviderResponse(
                provider=self.name,
                status=ProviderStatus.MALFORMED,
                fetched_at=self._now_iso(),
                error=str(exc),
                source_url=repo_url,
            )

        url = f"{_SCORECARD_API}/{owner}/{repo}"
        try:
            resp = requests.get(url, headers={"Accept": "application/json"}, timeout=self._timeout)
        except requests.Timeout:
            return ProviderResponse(
                provider=self.name,
                status=ProviderStatus.TIMEOUT,
                fetched_at=self._now_iso(),
                error="Scorecard request timed out",
                source_url=url,
            )
        except requests.RequestException as exc:
            return ProviderResponse(
                provider=self.name,
                status=ProviderStatus.UNAVAILABLE,
                fetched_at=self._now_iso(),
                error=f"Network error: {exc}",
                source_url=url,
            )

        if resp.status_code == 404:
            return ProviderResponse(
                provider=self.name,
                status=ProviderStatus.UNAVAILABLE,
                fetched_at=self._now_iso(),
                error="Repository not indexed by OpenSSF Scorecard",
                source_url=url,
            )
        if resp.status_code == 429:
            return ProviderResponse(
                provider=self.name,
                status=ProviderStatus.RATE_LIMIT,
                fetched_at=self._now_iso(),
                error="Scorecard API rate limit exceeded",
                source_url=url,
            )
        if resp.status_code != 200:
            return ProviderResponse(
                provider=self.name,
                status=ProviderStatus.UNKNOWN,
                fetched_at=self._now_iso(),
                error=f"Unexpected HTTP status {resp.status_code}",
                source_url=url,
            )

        try:
            payload = resp.json()
        except ValueError as exc:
            return ProviderResponse(
                provider=self.name,
                status=ProviderStatus.MALFORMED,
                fetched_at=self._now_iso(),
                error=f"Malformed JSON response: {exc}",
                source_url=url,
            )

        checks = {
            c.get("name"): c.get("score")
            for c in payload.get("checks", [])
            if c.get("name") is not None
        }
        data = {
            "score": payload.get("score"),
            "checks": checks,
            "date": payload.get("date"),
        }
        return ProviderResponse(
            provider=self.name,
            status=ProviderStatus.SUCCESS,
            fetched_at=self._now_iso(),
            data=data,
            source_url=url,
        )
