"""OPG-032: CISA Known Exploited Vulnerabilities (KEV) exploitation provider."""

from __future__ import annotations

import json
import logging
import time
import urllib.request
from typing import TypedDict

KEV_CATALOG_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

logger = logging.getLogger(__name__)


class KevEntry(TypedDict):
    cveID: str
    vendorProject: str
    product: str
    vulnerabilityName: str
    dateAdded: str
    shortDescription: str
    requiredAction: str
    dueDate: str
    notes: str
    knownRansomwareCampaignUse: str


class KevProvider:
    """Provider that fetches and caches the CISA KEV catalog."""

    def __init__(self, timeout: int = 10, cache_ttl_seconds: int = 3600) -> None:
        self._timeout = timeout
        self._cache_ttl_seconds = cache_ttl_seconds
        self._catalog: dict[str, KevEntry] | None = None
        self._loaded_at: float | None = None

    def _is_cache_valid(self) -> bool:
        """Return True if the cached catalog is present and not yet expired."""
        return (
            self._catalog is not None
            and self._loaded_at is not None
            and (time.time() - self._loaded_at) < self._cache_ttl_seconds
        )

    def fetch_catalog(self) -> dict[str, KevEntry]:
        """Return the KEV catalog keyed by CVE ID (uppercase).

        Uses the in-memory cache when valid.  On any network or parse error
        the previous cache (if available) is returned; otherwise an empty
        dict is returned so callers always get a mapping.
        """
        if self._is_cache_valid():
            return self._catalog  # type: ignore[return-value]

        try:
            with urllib.request.urlopen(KEV_CATALOG_URL, timeout=self._timeout) as response:
                raw = response.read()
            data = json.loads(raw)
            vulnerabilities: list[KevEntry] = data.get("vulnerabilities", [])
            catalog: dict[str, KevEntry] = {
                entry["cveID"].upper(): entry for entry in vulnerabilities
            }
            self._catalog = catalog
            self._loaded_at = time.time()
            logger.debug("KEV catalog loaded: %d entries", len(self._catalog))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to fetch KEV catalog: %s", exc)
            if self._catalog is not None:
                return self._catalog
            return {}

        return self._catalog

    def is_known_exploited(self, cve_id: str) -> bool:
        """Return True if *cve_id* appears in the CISA KEV catalog."""
        return cve_id.upper() in self.fetch_catalog()

    def get_entry(self, cve_id: str) -> KevEntry | None:
        """Return the KEV entry for *cve_id*, or None if not found."""
        return self.fetch_catalog().get(cve_id.upper())

    def correlate_cves(self, cve_ids: list[str]) -> list[dict]:
        """Correlate a list of CVE IDs against the KEV catalog.

        Returns a list of dicts with keys:
            cve_id, in_kev, due_date, ransomware, date_added
        """
        catalog = self.fetch_catalog()
        result = []
        for cid in cve_ids:
            upper = cid.upper()
            in_kev = upper in catalog
            entry = catalog.get(upper)
            result.append(
                {
                    "cve_id": cid,
                    "in_kev": in_kev,
                    "due_date": entry.get("dueDate") if entry is not None else None,
                    "ransomware": (
                        entry.get("knownRansomwareCampaignUse", "Unknown") == "Known"
                        if entry is not None
                        else False
                    ),
                    "date_added": entry.get("dateAdded") if entry is not None else None,
                }
            )
        return result

    def catalog_size(self) -> int:
        """Return the number of entries currently in the catalog."""
        return len(self.fetch_catalog())


# Module-level default provider instance
_default_provider: KevProvider = KevProvider()


def correlate_cves(cve_ids: list[str]) -> list[dict]:
    """Correlate *cve_ids* against the KEV catalog using the default provider."""
    return _default_provider.correlate_cves(cve_ids)


def is_known_exploited(cve_id: str) -> bool:
    """Return True if *cve_id* is in the KEV catalog using the default provider."""
    return _default_provider.is_known_exploited(cve_id)


__all__ = ["KevProvider", "KevEntry", "correlate_cves", "is_known_exploited"]
