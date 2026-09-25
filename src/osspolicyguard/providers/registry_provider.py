"""Package-registry provider: fetches download counts and metadata from PyPI, npm, or Maven."""

from __future__ import annotations

from typing import Any

import requests

from . import ProviderBase, ProviderResponse, ProviderStatus

_PYPI_API = "https://pypi.org/pypi/{name}/json"
_NPM_API = "https://registry.npmjs.org/{name}"
_MAVEN_API = "https://search.maven.org/solrsearch/select"

_SUPPORTED_ECOSYSTEMS = {"pypi", "npm", "maven"}


class RegistryProvider(ProviderBase):
    """Fetches package metadata (version, homepage, license) from a registry."""

    name = "registry"

    def fetch(self, ecosystem: str, package: str, **kwargs: Any) -> ProviderResponse:
        eco = (ecosystem or "").strip().lower()
        if eco not in _SUPPORTED_ECOSYSTEMS:
            return ProviderResponse(
                provider=self.name,
                status=ProviderStatus.UNAVAILABLE,
                fetched_at=self._now_iso(),
                error=f"Unsupported ecosystem: {ecosystem!r}",
            )

        if eco == "pypi":
            return self._fetch_pypi(package)
        if eco == "npm":
            return self._fetch_npm(package)
        return self._fetch_maven(package)

    def _request(self, url: str, **kwargs: Any) -> requests.Response | ProviderResponse:
        try:
            return requests.get(url, timeout=self._timeout, **kwargs)
        except requests.Timeout:
            return ProviderResponse(
                provider=self.name,
                status=ProviderStatus.TIMEOUT,
                fetched_at=self._now_iso(),
                error="Registry request timed out",
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

    def _fetch_pypi(self, package: str) -> ProviderResponse:
        url = _PYPI_API.format(name=package)
        result = self._request(url)
        if isinstance(result, ProviderResponse):
            return result
        resp = result

        if resp.status_code == 404:
            return ProviderResponse(
                provider=self.name,
                status=ProviderStatus.UNAVAILABLE,
                fetched_at=self._now_iso(),
                error="Package not found on PyPI",
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

        info = payload.get("info", {})
        data = {
            "version": info.get("version"),
            "downloads_30d": None,
            "homepage": info.get("home_page") or info.get("project_url"),
            "license": info.get("license"),
            "maintainers": [info.get("author")] if info.get("author") else [],
        }
        return ProviderResponse(
            provider=self.name,
            status=ProviderStatus.SUCCESS,
            fetched_at=self._now_iso(),
            data=data,
            source_url=url,
        )

    def _fetch_npm(self, package: str) -> ProviderResponse:
        url = _NPM_API.format(name=package)
        result = self._request(url)
        if isinstance(result, ProviderResponse):
            return result
        resp = result

        if resp.status_code == 404:
            return ProviderResponse(
                provider=self.name,
                status=ProviderStatus.UNAVAILABLE,
                fetched_at=self._now_iso(),
                error="Package not found on npm",
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

        dist_tags = payload.get("dist-tags", {})
        latest = dist_tags.get("latest")
        versions = payload.get("versions", {})
        latest_info = versions.get(latest, {}) if latest else {}
        maintainers = [m.get("name") for m in payload.get("maintainers", []) if m.get("name")]
        data = {
            "version": latest,
            "downloads_30d": None,
            "homepage": latest_info.get("homepage") or payload.get("homepage"),
            "license": latest_info.get("license") or payload.get("license"),
            "maintainers": maintainers,
        }
        return ProviderResponse(
            provider=self.name,
            status=ProviderStatus.SUCCESS,
            fetched_at=self._now_iso(),
            data=data,
            source_url=url,
        )

    def _fetch_maven(self, package: str) -> ProviderResponse:
        params: dict[str, Any] = {"q": package, "rows": 1, "wt": "json"}
        try:
            resp = requests.get(_MAVEN_API, params=params, timeout=self._timeout)
        except requests.Timeout:
            return ProviderResponse(
                provider=self.name,
                status=ProviderStatus.TIMEOUT,
                fetched_at=self._now_iso(),
                error="Registry request timed out",
                source_url=_MAVEN_API,
            )
        except requests.RequestException as exc:
            return ProviderResponse(
                provider=self.name,
                status=ProviderStatus.UNAVAILABLE,
                fetched_at=self._now_iso(),
                error=f"Network error: {exc}",
                source_url=_MAVEN_API,
            )

        if resp.status_code != 200:
            return ProviderResponse(
                provider=self.name,
                status=ProviderStatus.UNKNOWN,
                fetched_at=self._now_iso(),
                error=f"Unexpected HTTP status {resp.status_code}",
                source_url=_MAVEN_API,
            )
        try:
            payload = resp.json()
        except ValueError as exc:
            return ProviderResponse(
                provider=self.name,
                status=ProviderStatus.MALFORMED,
                fetched_at=self._now_iso(),
                error=f"Malformed JSON response: {exc}",
                source_url=_MAVEN_API,
            )

        docs = payload.get("response", {}).get("docs", [])
        if not docs:
            return ProviderResponse(
                provider=self.name,
                status=ProviderStatus.UNAVAILABLE,
                fetched_at=self._now_iso(),
                error="Package not found on Maven Central",
                source_url=_MAVEN_API,
            )
        doc = docs[0]
        data = {
            "version": doc.get("latestVersion") or doc.get("v"),
            "downloads_30d": None,  # Maven Central has no public download-count API
            "homepage": None,
            "license": None,
            "maintainers": [],
        }
        return ProviderResponse(
            provider=self.name,
            status=ProviderStatus.SUCCESS,
            fetched_at=self._now_iso(),
            data=data,
            source_url=_MAVEN_API,
        )
