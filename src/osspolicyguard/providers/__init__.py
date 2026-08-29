"""OPG-007 / OPG-023: Provider sub-package for OSSPolicyGuard.

OPG-007 — Dependency injection: every concrete provider is registered by
name and can be swapped at runtime by supplying a different implementation
that satisfies the :class:`ProviderBase` abstract interface.

OPG-023 — Provider interface contract: all providers must implement
:meth:`ProviderBase.fetch` and return a :class:`ProviderResponse`.  The
response carries a typed :class:`ProviderStatus`, a fetched-at ISO-8601
timestamp, an arbitrary ``data`` payload, and optional error / source-URL /
freshness metadata.

Only stdlib modules are used; no third-party dependencies are imported here.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

__all__ = [
    "ProviderBase",
    "ProviderResponse",
    "ProviderStatus",
    "NullProvider",
]


# ---------------------------------------------------------------------------
# ProviderStatus
# ---------------------------------------------------------------------------


class ProviderStatus(str, Enum):
    """Typed status codes returned by every provider fetch call.

    Extends ``str`` so that status values serialise to plain strings without
    a custom JSON encoder (``status.value`` and ``str(status)`` are
    equivalent).
    """

    SUCCESS = "SUCCESS"
    TIMEOUT = "TIMEOUT"
    RATE_LIMIT = "RATE_LIMIT"
    AUTH_ERROR = "AUTH_ERROR"
    MALFORMED = "MALFORMED"
    UNAVAILABLE = "UNAVAILABLE"
    UNKNOWN = "UNKNOWN"
    STALE = "STALE"


# ---------------------------------------------------------------------------
# ProviderResponse
# ---------------------------------------------------------------------------


@dataclass
class ProviderResponse:
    """Typed envelope returned by every :class:`ProviderBase` implementation.

    Attributes
    ----------
    provider:
        Short identifier of the provider that produced this response, e.g.
        ``"github"``, ``"osv"``, ``"scorecard"``.
    status:
        Machine-readable outcome of the fetch operation.
    fetched_at:
        ISO-8601 UTC timestamp recording when the fetch was performed.
    data:
        Arbitrary, provider-specific payload.  Must be JSON-serialisable.
    error:
        Human-readable error description when *status* is not
        :attr:`ProviderStatus.SUCCESS`.  ``None`` on success.
    source_url:
        The URL that was queried, when applicable.
    freshness_seconds:
        Age of the underlying data in seconds relative to *fetched_at*, when
        the provider can determine this from a published ``date`` or
        ``last_modified`` field.  ``None`` when unknown.
    confidence:
        A value in [0, 1] expressing overall confidence in the returned
        ``data``.  Defaults to ``1.0`` (full confidence).
    """

    provider: str
    status: ProviderStatus
    fetched_at: str  # ISO8601
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    source_url: str | None = None
    freshness_seconds: int | None = None
    confidence: float = 1.0

    # ------------------------------------------------------------------
    # Convenience predicates
    # ------------------------------------------------------------------

    def is_success(self) -> bool:
        """Return ``True`` when the fetch completed without errors."""
        return self.status == ProviderStatus.SUCCESS

    def is_stale(self) -> bool:
        """Return ``True`` when the provider flagged the data as stale."""
        return self.status == ProviderStatus.STALE

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Return a fully JSON-serialisable dict representation.

        :class:`ProviderStatus` values are serialised to their string
        equivalents so no custom encoder is needed.
        """
        return {
            "provider": self.provider,
            "status": self.status.value,
            "fetched_at": self.fetched_at,
            "data": self.data,
            "error": self.error,
            "source_url": self.source_url,
            "freshness_seconds": self.freshness_seconds,
            "confidence": self.confidence,
        }


# ---------------------------------------------------------------------------
# ProviderBase  (OPG-023: interface contract)
# ---------------------------------------------------------------------------


class ProviderBase(ABC):
    """Abstract base class that defines the provider interface contract.

    All concrete providers **must** subclass this class and implement the
    :meth:`fetch` method.  The constructor accepts a unified ``config`` dict
    (keyed by provider name) so that the dependency-injection layer (OPG-007)
    can pass the same configuration object to every provider without knowing
    each provider's individual settings.

    Attributes
    ----------
    name:
        Short, stable identifier for this provider.  Concrete subclasses
        **must** override this class attribute.
    config:
        Full application configuration dict as passed to ``__init__``.
    _timeout:
        Per-provider HTTP timeout in seconds, extracted from
        ``config[self.name]["timeout"]`` (default: 10).
    """

    name: str = "base"

    def __init__(self, config: dict[str, Any]) -> None:
        self.config: dict[str, Any] = config
        self._timeout: int = int(
            config.get(self.name, {}).get("timeout", 10)
        )

    # ------------------------------------------------------------------
    # Abstract interface
    # ------------------------------------------------------------------

    @abstractmethod
    def fetch(self, *args: Any, **kwargs: Any) -> ProviderResponse:
        """Fetch data from the upstream source and return a typed response.

        Parameters
        ----------
        *args:
            Provider-specific positional arguments (e.g. a package URL or
            ecosystem + name pair).
        **kwargs:
            Provider-specific keyword arguments.

        Returns
        -------
        ProviderResponse
            A fully populated response.  The ``status`` field indicates
            whether the fetch succeeded; inspect ``error`` on failure.
        """

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    def _now_iso(self) -> str:
        """Return the current UTC time as an ISO-8601 string."""
        return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# NullProvider  (offline / test mode)
# ---------------------------------------------------------------------------


class NullProvider(ProviderBase):
    """No-op provider for testing and offline mode.

    Always returns a :attr:`ProviderStatus.UNAVAILABLE` response with no
    data.  Useful as a safe default when a real provider is not configured,
    or as a test double that satisfies the :class:`ProviderBase` contract
    without making any network calls.
    """

    name: str = "null"

    def fetch(self, *args: Any, **kwargs: Any) -> ProviderResponse:
        """Return an UNAVAILABLE response immediately without any I/O."""
        return ProviderResponse(
            provider=self.name,
            status=ProviderStatus.UNAVAILABLE,
            fetched_at=self._now_iso(),
            error="NullProvider: no data available (offline/test mode)",
        )
