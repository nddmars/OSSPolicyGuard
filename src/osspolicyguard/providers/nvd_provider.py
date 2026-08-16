"""NVD (National Vulnerability Database) provider: fetches CVE records and CVSS scores."""

from __future__ import annotations

# TODO: Implement NVDProvider.fetch()
#   - Accept a CPE name or keyword search term as the first argument.
#   - Query the NVD REST API v2.0
#     (https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=...).
#   - Extract CVE IDs, CVSS v3.1 base scores, and publication dates into
#     ProviderResponse.data as {"cve_count": int, "cves": [{...}, ...]}.
#   - Use the NVD API key from self.config["nvd"].get("api_key") as the
#     apiKey query parameter to raise rate-limit thresholds.
#   - Handle 403 → ProviderStatus.AUTH_ERROR, 429 → ProviderStatus.RATE_LIMIT,
#     timeout → ProviderStatus.TIMEOUT, malformed response →
#     ProviderStatus.MALFORMED.
#   - Respect the NVD rolling-window rate-limit even with an API key.
