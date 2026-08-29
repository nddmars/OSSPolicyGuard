"""OSV (Open Source Vulnerabilities) provider: queries vulnerability advisories by package."""

from __future__ import annotations

from typing import Any

import requests

from . import ProviderBase, ProviderResponse, ProviderStatus

_OSV_API = "https://api.osv.dev/v1/query"


class OSVProvider(ProviderBase):
    """Queries OSV.dev for vulnerabilities (and MAL- malicious-package advisories)."""

    name = "osv"

    def fetch(
        self, ecosystem: str, package: str, version: str | None = None, **kwargs: Any
    ) -> ProviderResponse:
        body: dict[str, Any] = {"package": {"ecosystem": ecosystem, "name": package}}
        if version:
            body["version"] = version

        try:
            resp = requests.post(_OSV_API, json=body, timeout=self._timeout)
        except requests.Timeout:
            return ProviderResponse(
                provider=self.name,
                status=ProviderStatus.TIMEOUT,
                fetched_at=self._now_iso(),
                error="OSV request timed out",
                source_url=_OSV_API,
            )
        except requests.RequestException as exc:
            return ProviderResponse(
                provider=self.name,
                status=ProviderStatus.UNAVAILABLE,
                fetched_at=self._now_iso(),
                error=f"Network error: {exc}",
                source_url=_OSV_API,
            )

        if resp.status_code == 429:
            return ProviderResponse(
                provider=self.name,
                status=ProviderStatus.RATE_LIMIT,
                fetched_at=self._now_iso(),
                error="OSV API rate limit exceeded",
                source_url=_OSV_API,
            )
        if resp.status_code != 200:
            return ProviderResponse(
                provider=self.name,
                status=ProviderStatus.UNKNOWN,
                fetched_at=self._now_iso(),
                error=f"Unexpected HTTP status {resp.status_code}",
                source_url=_OSV_API,
            )

        try:
            payload = resp.json()
        except ValueError as exc:
            return ProviderResponse(
                provider=self.name,
                status=ProviderStatus.MALFORMED,
                fetched_at=self._now_iso(),
                error=f"Malformed JSON response: {exc}",
                source_url=_OSV_API,
            )

        vulns = []
        is_malicious = False
        for vuln in payload.get("vulns", []):
            vuln_id = vuln.get("id", "")
            aliases = vuln.get("aliases", [])
            if vuln_id.startswith("MAL-") or any(a.startswith("MAL-") for a in aliases):
                is_malicious = True
            severity_list = vuln.get("severity", [])
            severity = severity_list[0].get("score") if severity_list else None
            vulns.append({"id": vuln_id, "aliases": aliases, "severity": severity})

        return ProviderResponse(
            provider=self.name,
            status=ProviderStatus.SUCCESS,
            fetched_at=self._now_iso(),
            data={
                "vuln_count": len(vulns),
                "is_malicious": is_malicious,
                "vulns": vulns,
            },
            source_url=_OSV_API,
        )
