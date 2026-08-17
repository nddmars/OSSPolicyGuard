from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional

try:
    from .exceptions import InvalidPackageUrlError
except ImportError:
    InvalidPackageUrlError = ValueError  # type: ignore[assignment,misc]

__all__ = [
    "PackageUrl",
    "normalize_package_name",
    "ecosystem_to_purl_type",
    "build_purl",
]

_PURL_RE = re.compile(
    r"""
    ^
    pkg:                                    # scheme
    (?P<type>[a-zA-Z][a-zA-Z0-9.+\-]*)    # type
    /                                       # separator
    (?P<remainder>[^@?#]*)                  # namespace/name portion
    (?:@(?P<version>[^?#]*))?              # optional @version
    (?:\?(?P<qualifiers>[^#]*))?           # optional ?qualifiers
    (?:\#(?P<subpath>.*))?                 # optional #subpath
    $
    """,
    re.VERBOSE,
)

_PYPI_NORM_RE = re.compile(r"[_\-\.]+")
_TRAILING_DASH_RE = re.compile(r"-+$")


@dataclass
class PackageUrl:
    type: str
    name: str
    namespace: Optional[str] = None
    version: Optional[str] = None
    qualifiers: dict[str, str] = field(default_factory=dict)
    subpath: Optional[str] = None

    @classmethod
    def from_string(cls, purl: str) -> "PackageUrl":
        """Parse a Package URL string into a PackageUrl instance.

        Expected format: pkg:type[/namespace]/name[@version][?qualifiers][#subpath]

        Raises InvalidPackageUrlError if the string is malformed.
        """
        if not isinstance(purl, str) or not purl:
            raise InvalidPackageUrlError(
                f"Package URL must be a non-empty string, got {purl!r}"
            )

        match = _PURL_RE.match(purl)
        if match is None:
            raise InvalidPackageUrlError(
                f"Malformed Package URL (does not match purl scheme): {purl!r}"
            )

        purl_type = match.group("type").lower()
        remainder = match.group("remainder") or ""
        raw_version = match.group("version")
        raw_qualifiers = match.group("qualifiers")
        raw_subpath = match.group("subpath")

        # Split remainder into namespace + name
        # The last path segment is always the name; everything before is namespace
        parts = remainder.split("/")
        if not parts or parts[-1] == "":
            raise InvalidPackageUrlError(
                f"Package URL is missing a package name: {purl!r}"
            )

        raw_name = urllib.parse.unquote(parts[-1])
        if not raw_name:
            raise InvalidPackageUrlError(
                f"Package URL has an empty package name: {purl!r}"
            )

        namespace_parts = parts[:-1]
        namespace: Optional[str]
        if namespace_parts:
            decoded_ns = "/".join(
                urllib.parse.unquote(p) for p in namespace_parts
            )
            namespace = decoded_ns if decoded_ns else None
        else:
            namespace = None

        version: Optional[str]
        if raw_version is not None:
            version = urllib.parse.unquote(raw_version) if raw_version else None
        else:
            version = None

        qualifiers: dict[str, str] = {}
        if raw_qualifiers:
            for pair in raw_qualifiers.split("&"):
                if "=" not in pair:
                    raise InvalidPackageUrlError(
                        f"Malformed qualifier (no '='): {pair!r} in {purl!r}"
                    )
                key, _, val = pair.partition("=")
                key = key.strip().lower()
                if not key:
                    raise InvalidPackageUrlError(
                        f"Qualifier has empty key in {purl!r}"
                    )
                qualifiers[key] = urllib.parse.unquote(val)

        subpath: Optional[str]
        if raw_subpath is not None:
            # Strip leading/trailing slashes and decode
            cleaned = raw_subpath.strip("/")
            subpath = cleaned if cleaned else None
        else:
            subpath = None

        return cls(
            type=purl_type,
            name=raw_name,
            namespace=namespace,
            version=version,
            qualifiers=qualifiers,
            subpath=subpath,
        )

    def to_canonical(self) -> str:
        """Reconstruct the canonical Package URL string.

        Format: pkg:type[/namespace]/name[@version][?qualifiers][#subpath]
        """
        parts: list[str] = [f"pkg:{self.type.lower()}/"]

        if self.namespace is not None:
            ns_encoded = "/".join(
                urllib.parse.quote(seg, safe="")
                for seg in self.namespace.split("/")
            )
            parts.append(f"{ns_encoded}/")

        parts.append(urllib.parse.quote(self.name, safe=""))

        if self.version is not None:
            parts.append(f"@{urllib.parse.quote(self.version, safe='')}")

        if self.qualifiers:
            # Sort qualifiers for deterministic output
            qs = "&".join(
                f"{k}={urllib.parse.quote(v, safe='')}"
                for k, v in sorted(self.qualifiers.items())
            )
            parts.append(f"?{qs}")

        if self.subpath is not None:
            parts.append(f"#{self.subpath}")

        return "".join(parts)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PackageUrl):
            return NotImplemented
        return self.to_canonical().lower() == other.to_canonical().lower()

    def __hash__(self) -> int:
        return hash(self.to_canonical().lower())

    def __repr__(self) -> str:
        return (
            f"PackageUrl(type={self.type!r}, name={self.name!r}, "
            f"namespace={self.namespace!r}, version={self.version!r}, "
            f"qualifiers={self.qualifiers!r}, subpath={self.subpath!r})"
        )

    def __str__(self) -> str:
        return self.to_canonical()


def normalize_package_name(name: str, ecosystem: str) -> str:
    """Normalize a package name according to ecosystem-specific rules.

    Parameters
    ----------
    name:
        The raw package name as it appears in a manifest or dependency file.
    ecosystem:
        The ecosystem / package manager name (case-insensitive).

    Returns
    -------
    str
        The normalized package name suitable for deduplication and comparison.
    """
    eco = ecosystem.lower().strip()

    if eco in ("npm", "javascript"):
        # For npm, strip leading @scope for bare name comparison, keep lowercase.
        # e.g. "@babel/core" -> "core", "lodash" -> "lodash"
        bare = name.split("/")[-1] if "/" in name else name
        return bare.lower()

    if eco in ("pypi", "python"):
        # PEP 503: lowercase and collapse runs of [-_.] to a single "-"
        normalized = _PYPI_NORM_RE.sub("-", name.lower())
        normalized = _TRAILING_DASH_RE.sub("", normalized)
        return normalized

    if eco in ("rubygems", "ruby"):
        return name.lower()

    if eco in ("cargo", "crates", "rust"):
        return name.lower()

    if eco in ("nuget", "csharp", "dotnet"):
        return name.lower()

    if eco in ("packagist", "php"):
        # Keep vendor/package format, just lowercase
        return name.lower()

    if eco in ("maven", "java"):
        # Keep group:artifact format, just lowercase
        return name.lower()

    return name.lower()


def ecosystem_to_purl_type(ecosystem: str) -> str:
    """Map an ecosystem name to its canonical Package URL type string.

    Parameters
    ----------
    ecosystem:
        The ecosystem / package manager name (case-insensitive).

    Returns
    -------
    str
        The canonical purl type (e.g. "npm", "pypi", "gem", "cargo", ...).
    """
    mapping: dict[str, str] = {
        "npm": "npm",
        "javascript": "npm",
        "pypi": "pypi",
        "python": "pypi",
        "rubygems": "gem",
        "ruby": "gem",
        "cargo": "cargo",
        "crates": "cargo",
        "rust": "cargo",
        "nuget": "nuget",
        "csharp": "nuget",
        "dotnet": "nuget",
        "packagist": "composer",
        "php": "composer",
        "maven": "maven",
        "java": "maven",
    }
    return mapping.get(ecosystem.lower().strip(), ecosystem.lower().strip())


def build_purl(
    name: str,
    ecosystem: str,
    version: Optional[str] = None,
    namespace: Optional[str] = None,
) -> PackageUrl:
    """Normalize *name* and build a canonical PackageUrl for the given ecosystem.

    Parameters
    ----------
    name:
        The raw package name.
    ecosystem:
        The ecosystem / package manager name (case-insensitive).
    version:
        Optional version string.
    namespace:
        Optional namespace (e.g. Maven group id, npm scope).
        When *None* and the ecosystem is npm and *name* contains a leading
        ``@scope/``, the scope is extracted automatically as the namespace.

    Returns
    -------
    PackageUrl
        A fully populated PackageUrl instance ready to be serialised via
        ``to_canonical()``.
    """
    purl_type = ecosystem_to_purl_type(ecosystem)
    eco = ecosystem.lower().strip()

    # For npm, handle scoped packages: "@scope/package" -> namespace="scope", name="package"
    resolved_namespace = namespace
    resolved_name = name

    if eco in ("npm", "javascript") and namespace is None:
        if name.startswith("@") and "/" in name:
            scope, _, pkg = name[1:].partition("/")
            resolved_namespace = scope.lower() if scope else None
            resolved_name = pkg
        # else: unscoped package — namespace stays None

    normalized = normalize_package_name(resolved_name, ecosystem)

    return PackageUrl(
        type=purl_type,
        name=normalized,
        namespace=resolved_namespace.lower() if resolved_namespace is not None else None,
        version=version,
    )
