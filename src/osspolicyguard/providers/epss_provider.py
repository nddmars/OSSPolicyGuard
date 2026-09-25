"""EPSS (Exploit Prediction Scoring System) provider: fetches exploit-likelihood scores for CVEs."""

from __future__ import annotations

from typing import Any

import requests

from . import ProviderBase, ProviderResponse, ProviderStatus

_EPSS_API = "https://api.first.org/data/v1/epss"
_BATCH_SIZE = 30


class EPSSProvider(ProviderBase):
    """Fetches EPSS exploit-probability scores for one or more CVE IDs."""

    name = "epss"

    def fetch(self, cve_ids: str | list[str], **kwargs: Any) -> ProviderResponse:
        ids = [cve_ids] if isinstance(cve_ids, str) else list(cve_ids)
        if not ids:
            return ProviderResponse(
                provider=self.name,
                status=ProviderStatus.SUCCESS,
                fetched_at=self._now_iso(),
                data={"scores": {}, "not_found": []},
            )

        scores: dict[str, dict[str, Any]] = {}
        last_url: str | None = None
        for batch_start in range(0, len(ids), _BATCH_SIZE):
            batch = ids[batch_start : batch_start + _BATCH_SIZE]
            params = {"cve": ",".join(batch)}
            try:
                resp = requests.get(_EPSS_API, params=params, timeout=self._timeout)
                last_url = resp.url
            except requests.Timeout:
                return ProviderResponse(
                    provider=self.name,
                    status=ProviderStatus.TIMEOUT,
                    fetched_at=self._now_iso(),
                    error="EPSS request timed out",
                    source_url=last_url,
                    data={"scores": scores},
                )
            except requests.RequestException as exc:
                return ProviderResponse(
                    provider=self.name,
                    status=ProviderStatus.UNAVAILABLE,
                    fetched_at=self._now_iso(),
                    error=f"Network error: {exc}",
                    source_url=last_url,
                    data={"scores": scores},
                )

            if resp.status_code == 429:
                return ProviderResponse(
                    provider=self.name,
                    status=ProviderStatus.RATE_LIMIT,
                    fetched_at=self._now_iso(),
                    error="EPSS API rate limit exceeded",
                    source_url=last_url,
                    data={"scores": scores},
                )
            if resp.status_code != 200:
                return ProviderResponse(
                    provider=self.name,
                    status=ProviderStatus.UNKNOWN,
                    fetched_at=self._now_iso(),
                    error=f"Unexpected HTTP status {resp.status_code}",
                    source_url=last_url,
                    data={"scores": scores},
                )

            try:
                payload = resp.json()
            except ValueError as exc:
                return ProviderResponse(
                    provider=self.name,
                    status=ProviderStatus.MALFORMED,
                    fetched_at=self._now_iso(),
                    error=f"Malformed JSON response: {exc}",
                    source_url=last_url,
                    data={"scores": scores},
                )

            for entry in payload.get("data", []):
                cve_id = entry.get("cve")
                if not cve_id:
                    continue
                try:
                    scores[cve_id] = {
                        "epss": float(entry.get("epss", 0.0)),
                        "percentile": float(entry.get("percentile", 0.0)),
                        "date": entry.get("date"),
                    }
                except (TypeError, ValueError):
                    continue

        not_found = [cve_id for cve_id in ids if cve_id not in scores]
        return ProviderResponse(
            provider=self.name,
            status=ProviderStatus.SUCCESS,
            fetched_at=self._now_iso(),
            data={"scores": scores, "not_found": not_found},
            source_url=last_url,
        )
