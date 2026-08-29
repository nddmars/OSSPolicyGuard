"""Package-registry provider: fetches download counts and metadata from PyPI, npm, or Maven."""

from __future__ import annotations

# TODO: Implement RegistryProvider.fetch()
#   - Accept ecosystem (str) and package name (str) as positional arguments.
#   - Dispatch to the appropriate registry API based on ecosystem:
#       * "pypi"  → https://pypi.org/pypi/{name}/json
#       * "npm"   → https://registry.npmjs.org/{name}
#       * "maven" → https://search.maven.org/solrsearch/select?q=...
#   - Extract into ProviderResponse.data: {"version": str, "downloads_30d": int,
#     "homepage": str, "license": str, "maintainers": [str, ...]}.
#   - Handle unknown ecosystems → ProviderStatus.UNAVAILABLE with a clear error.
#   - Handle 404 (package not found) → ProviderStatus.UNAVAILABLE, timeout →
#     ProviderStatus.TIMEOUT, malformed JSON → ProviderStatus.MALFORMED.
#   - Populate source_url with the registry URL that was queried.
