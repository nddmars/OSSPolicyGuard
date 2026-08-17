"""OSV (Open Source Vulnerabilities) provider: queries vulnerability advisories by package."""

from __future__ import annotations

# TODO: Implement OSVProvider.fetch()
#   - Accept ecosystem (str) and package name (str) as positional arguments;
#     optionally accept version (str) as a keyword argument.
#   - POST to https://api.osv.dev/v1/query with the appropriate JSON body
#     ({"package": {"ecosystem": ..., "name": ...}, "version": ...}).
#   - Parse the "vulns" array from the response; detect MAL-* IDs to set
#     ProviderResponse.data["is_malicious"] = True.
#   - Summarise findings into data: {"vuln_count": int, "is_malicious": bool,
#     "vulns": [{"id": str, "aliases": [...], "severity": str}, ...]}.
#   - Handle empty responses (no "vulns" key) as SUCCESS with vuln_count=0.
#   - Handle timeout → ProviderStatus.TIMEOUT, malformed JSON →
#     ProviderStatus.MALFORMED, HTTP errors appropriately.
