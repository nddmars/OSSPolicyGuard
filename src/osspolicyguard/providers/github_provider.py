"""GitHub REST API provider: fetches repository metadata and activity signals."""

from __future__ import annotations

from typing import Any

import requests

from . import ProviderBase, ProviderResponse, ProviderStatus

_GITHUB_API = "https://api.github.com"


class GitHubProvider(ProviderBase):
    """Fetches repository metadata (stars, forks, activity) from GitHub."""

    name = "github"

    def fetch(self, repo_url: str, **kwargs: Any) -> ProviderResponse:
        try:
            owner, repo = self._parse_owner_repo(repo_url)
        except ValueError as exc:
            return ProviderResponse(
                provider=self.name,
                status=ProviderStatus.MALFORMED,
                fetched_at=self._now_iso(),
                error=str(exc),
                source_url=repo_url,
            )

        url = f"{_GITHUB_API}/repos/{owner}/{repo}"
        headers = {"Accept": "application/vnd.github+json"}
        token = self.config.get("github", {}).get("token", "")
        if token and not token.startswith("<<"):
            headers["Authorization"] = f"token {token}"

        try:
            resp = requests.get(url, headers=headers, timeout=self._timeout)
        except requests.Timeout:
            return ProviderResponse(
                provider=self.name,
                status=ProviderStatus.TIMEOUT,
                fetched_at=self._now_iso(),
                error="GitHub request timed out",
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

        if resp.status_code in (401, 403):
            return ProviderResponse(
                provider=self.name,
                status=ProviderStatus.AUTH_ERROR,
                fetched_at=self._now_iso(),
                error=f"GitHub authentication/authorization error (HTTP {resp.status_code})",
                source_url=url,
            )
        if resp.status_code == 429:
            return ProviderResponse(
                provider=self.name,
                status=ProviderStatus.RATE_LIMIT,
                fetched_at=self._now_iso(),
                error="GitHub rate limit exceeded",
                source_url=url,
            )
        if resp.status_code == 404:
            return ProviderResponse(
                provider=self.name,
                status=ProviderStatus.UNAVAILABLE,
                fetched_at=self._now_iso(),
                error="Repository not found",
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

        data = {
            "stars": payload.get("stargazers_count", 0),
            "forks": payload.get("forks_count", 0),
            "open_issues": payload.get("open_issues_count", 0),
            "pushed_at": payload.get("pushed_at"),
            "contributors_url": payload.get("contributors_url"),
        }
        return ProviderResponse(
            provider=self.name,
            status=ProviderStatus.SUCCESS,
            fetched_at=self._now_iso(),
            data=data,
            source_url=url,
        )

    @staticmethod
    def _parse_owner_repo(repo_url: str) -> tuple[str, str]:
        """Extract (owner, repo) from a GitHub URL.

        Delegates to oss_scorer's canonical parser (REQ-010) so this typed
        provider and the legacy engine agree on what counts as a valid
        GitHub URL — in particular, a strict netloc allow-list rather than a
        substring check, which would otherwise accept a spoofed host such as
        ``notgithub.com``.
        """
        from oss_scorer import _parse_github_owner_repo

        return _parse_github_owner_repo(repo_url)
