"""endoflife.date provider: live end-of-life / support-cycle data for
language runtimes and platforms (requirements.md §16.2, OPG-140)."""

from __future__ import annotations

from typing import Any

import requests

from . import ProviderBase, ProviderResponse, ProviderStatus

_EOL_API = "https://endoflife.date/api/{product}.json"


class EndOfLifeDateProvider(ProviderBase):
    """Fetches release-cycle end-of-life data from the public endoflife.date API."""

    name = "endoflife"

    def fetch(self, product: str, **kwargs: Any) -> ProviderResponse:
        url = _EOL_API.format(product=product.lower())
        try:
            resp = requests.get(url, timeout=self._timeout)
        except requests.Timeout:
            return ProviderResponse(
                provider=self.name,
                status=ProviderStatus.TIMEOUT,
                fetched_at=self._now_iso(),
                error="endoflife.date request timed out",
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
                error=f"Unknown product: {product!r}",
                source_url=url,
            )
        if resp.status_code == 429:
            return ProviderResponse(
                provider=self.name,
                status=ProviderStatus.RATE_LIMIT,
                fetched_at=self._now_iso(),
                error="endoflife.date rate limit exceeded",
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

        cycles = [
            {
                "cycle": str(entry.get("cycle")),
                "eol": entry.get("eol"),
                "latest": entry.get("latest"),
            }
            for entry in payload
            if isinstance(entry, dict)
        ]
        return ProviderResponse(
            provider=self.name,
            status=ProviderStatus.SUCCESS,
            fetched_at=self._now_iso(),
            data={"product": product, "cycles": cycles},
            source_url=url,
        )
