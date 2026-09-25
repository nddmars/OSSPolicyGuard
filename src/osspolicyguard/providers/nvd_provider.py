"""NVD (National Vulnerability Database) provider: fetches CVE records and CVSS scores."""

from __future__ import annotations

from typing import Any

import requests

from . import ProviderBase, ProviderResponse, ProviderStatus

_NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _extract_cvss(metrics: dict[str, Any]) -> tuple[float | None, str | None]:
    """Return (base_score, base_severity), preferring CVSS v3.1 > v3.0 > v2."""
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key) or []
        if entries:
            cvss_data = entries[0].get("cvssData", {})
            return cvss_data.get("baseScore"), cvss_data.get("baseSeverity")
    entries = metrics.get("cvssMetricV2") or []
    if entries:
        cvss_data = entries[0].get("cvssData", {})
        return cvss_data.get("baseScore"), entries[0].get("baseSeverity")
    return None, None


class NVDProvider(ProviderBase):
    """Fetches CVE records for a keyword or CPE search term from NVD API v2."""

    name = "nvd"

    def fetch(self, keyword: str, **kwargs: Any) -> ProviderResponse:
        params: dict[str, Any] = {"keywordSearch": keyword, "resultsPerPage": 50}
        headers: dict[str, str] = {}
        api_key = self.config.get("nvd", {}).get("api_key", "")
        if api_key and not api_key.startswith("<<"):
            headers["apiKey"] = api_key

        try:
            resp = requests.get(_NVD_API, params=params, headers=headers, timeout=self._timeout)
        except requests.Timeout:
            return ProviderResponse(
                provider=self.name,
                status=ProviderStatus.TIMEOUT,
                fetched_at=self._now_iso(),
                error="NVD request timed out",
                source_url=_NVD_API,
            )
        except requests.RequestException as exc:
            return ProviderResponse(
                provider=self.name,
                status=ProviderStatus.UNAVAILABLE,
                fetched_at=self._now_iso(),
                error=f"Network error: {exc}",
                source_url=_NVD_API,
            )

        if resp.status_code == 403:
            return ProviderResponse(
                provider=self.name,
                status=ProviderStatus.AUTH_ERROR,
                fetched_at=self._now_iso(),
                error="NVD authentication error (invalid or missing API key)",
                source_url=resp.url,
            )
        if resp.status_code == 429:
            return ProviderResponse(
                provider=self.name,
                status=ProviderStatus.RATE_LIMIT,
                fetched_at=self._now_iso(),
                error="NVD rate limit exceeded",
                source_url=resp.url,
            )
        if resp.status_code != 200:
            return ProviderResponse(
                provider=self.name,
                status=ProviderStatus.UNKNOWN,
                fetched_at=self._now_iso(),
                error=f"Unexpected HTTP status {resp.status_code}",
                source_url=resp.url,
            )

        try:
            payload = resp.json()
        except ValueError as exc:
            return ProviderResponse(
                provider=self.name,
                status=ProviderStatus.MALFORMED,
                fetched_at=self._now_iso(),
                error=f"Malformed JSON response: {exc}",
                source_url=resp.url,
            )

        cves = []
        for item in payload.get("vulnerabilities", []):
            cve = item.get("cve", {})
            base_score, severity = _extract_cvss(cve.get("metrics", {}))
            cves.append(
                {
                    "id": cve.get("id"),
                    "published": cve.get("published"),
                    "base_score": base_score,
                    "severity": severity,
                }
            )

        return ProviderResponse(
            provider=self.name,
            status=ProviderStatus.SUCCESS,
            fetched_at=self._now_iso(),
            data={"cve_count": len(cves), "cves": cves},
            source_url=resp.url,
        )
