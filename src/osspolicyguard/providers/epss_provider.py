"""EPSS (Exploit Prediction Scoring System) provider: fetches exploit-likelihood scores for CVEs."""

from __future__ import annotations

# TODO: Implement EPSSProvider.fetch()
#   - Accept one or more CVE IDs as positional arguments (str or list[str]).
#   - Query the FIRST EPSS API
#     (https://api.first.org/data/v1/epss?cve=CVE-XXXX-YYYY[,CVE-...]).
#   - Parse the "data" array from the response into ProviderResponse.data as
#     {"scores": {cve_id: {"epss": float, "percentile": float, "date": str}}}.
#   - CVEs absent from the response should be noted in a "not_found" list.
#   - Handle timeout → ProviderStatus.TIMEOUT, malformed JSON →
#     ProviderStatus.MALFORMED, HTTP errors appropriately.
#   - No authentication is required; respect self._timeout.
