"""Domain exception hierarchy for OSSPolicyGuard.

All exceptions raised by OSSPolicyGuard inherit from :class:`OSSPolicyGuardError`,
which carries an ``exit_code`` (used by the CLI when the process terminates) and a
``message_prefix`` (used to build a human-readable message via :meth:`user_message`).

Hierarchy overview::

    OSSPolicyGuardError                   (exit_code=1)
    ├── ConfigurationError                (exit_code=2)
    │   ├── ConfigSchemaError
    │   └── ConfigMigrationError
    ├── ProviderError                     (exit_code=3)
    │   ├── ProviderTimeoutError
    │   ├── ProviderRateLimitError
    │   ├── ProviderAuthenticationError
    │   ├── ProviderMalformedResponseError
    │   └── ProviderUnavailableError
    ├── IdentityError                     (exit_code=4)
    │   ├── InvalidPackageUrlError
    │   ├── AmbiguousRepositoryError
    │   └── VersionResolutionError
    ├── PolicyError                       (exit_code=5)
    │   ├── PolicySchemaError
    │   └── PolicyConflictError
    ├── ReportError                       (exit_code=6)
    │   ├── UnsupportedFormatError
    │   └── SchemaViolationError
    └── InternalError                     (exit_code=99)
"""

from __future__ import annotations

__all__ = [
    # Base
    "OSSPolicyGuardError",
    # Configuration
    "ConfigurationError",
    "ConfigSchemaError",
    "ConfigMigrationError",
    # Provider
    "ProviderError",
    "ProviderTimeoutError",
    "ProviderRateLimitError",
    "ProviderAuthenticationError",
    "ProviderMalformedResponseError",
    "ProviderUnavailableError",
    # Identity
    "IdentityError",
    "InvalidPackageUrlError",
    "AmbiguousRepositoryError",
    "VersionResolutionError",
    # Policy
    "PolicyError",
    "PolicySchemaError",
    "PolicyConflictError",
    # Report
    "ReportError",
    "UnsupportedFormatError",
    "SchemaViolationError",
    # Internal
    "InternalError",
]


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------


class OSSPolicyGuardError(Exception):
    """Base class for all OSSPolicyGuard exceptions.

    Attributes:
        exit_code: Process exit code the CLI should use when this exception
            propagates to the top level.
        message_prefix: Short label prepended to the exception message in
            :meth:`user_message`.
    """

    exit_code: int = 1
    message_prefix: str = "Error"

    def user_message(self) -> str:
        """Return a human-readable representation of this exception."""
        return f"{self.message_prefix}: {self}"


# ---------------------------------------------------------------------------
# Configuration errors  (exit_code=2)
# ---------------------------------------------------------------------------


class ConfigurationError(OSSPolicyGuardError):
    """Raised when the OSSPolicyGuard configuration is invalid or cannot be loaded."""

    exit_code: int = 2
    message_prefix: str = "Configuration error"


class ConfigSchemaError(ConfigurationError):
    """Raised when a configuration file does not conform to its expected schema."""


class ConfigMigrationError(ConfigurationError):
    """Raised when a configuration file cannot be migrated to the current format."""


# ---------------------------------------------------------------------------
# Provider errors  (exit_code=3)
# ---------------------------------------------------------------------------


class ProviderError(OSSPolicyGuardError):
    """Raised when communication with an upstream data provider fails."""

    exit_code: int = 3
    message_prefix: str = "Provider error"


class ProviderTimeoutError(ProviderError):
    """Raised when a provider request exceeds the configured timeout."""


class ProviderRateLimitError(ProviderError):
    """Raised when a provider signals that the request rate limit has been exceeded."""


class ProviderAuthenticationError(ProviderError):
    """Raised when a provider rejects the supplied credentials."""


class ProviderMalformedResponseError(ProviderError):
    """Raised when a provider returns a response that cannot be parsed or understood."""


class ProviderUnavailableError(ProviderError):
    """Raised when a provider is temporarily or permanently unavailable."""


# ---------------------------------------------------------------------------
# Identity errors  (exit_code=4)
# ---------------------------------------------------------------------------


class IdentityError(OSSPolicyGuardError):
    """Raised when a package or repository identity cannot be resolved."""

    exit_code: int = 4
    message_prefix: str = "Identity error"


class InvalidPackageUrlError(IdentityError):
    """Raised when a Package URL (purl) is syntactically or semantically invalid."""


class AmbiguousRepositoryError(IdentityError):
    """Raised when a package identifier maps to more than one candidate repository."""


class VersionResolutionError(IdentityError):
    """Raised when a requested package version cannot be resolved."""


# ---------------------------------------------------------------------------
# Policy errors  (exit_code=5)
# ---------------------------------------------------------------------------


class PolicyError(OSSPolicyGuardError):
    """Raised when a policy definition is invalid or produces a conflict."""

    exit_code: int = 5
    message_prefix: str = "Policy error"


class PolicySchemaError(PolicyError):
    """Raised when a policy document does not conform to its expected schema."""


class PolicyConflictError(PolicyError):
    """Raised when two or more policy rules produce an irreconcilable conflict."""


# ---------------------------------------------------------------------------
# Report errors  (exit_code=6)
# ---------------------------------------------------------------------------


class ReportError(OSSPolicyGuardError):
    """Raised when a report cannot be generated or serialised."""

    exit_code: int = 6
    message_prefix: str = "Report error"


class UnsupportedFormatError(ReportError):
    """Raised when the requested output format is not supported."""


class SchemaViolationError(ReportError):
    """Raised when generated report output violates its target schema."""


# ---------------------------------------------------------------------------
# Internal errors  (exit_code=99)
# ---------------------------------------------------------------------------


class InternalError(OSSPolicyGuardError):
    """Raised for unexpected internal errors that indicate a bug in OSSPolicyGuard.

    Users should never encounter this exception during normal operation.  When
    they do, the :meth:`user_message` output directs them to the issue tracker.
    """

    exit_code: int = 99
    message_prefix: str = "Internal error"

    def user_message(self) -> str:
        """Return a human-readable message that includes a link to the issue tracker."""
        base = super().user_message()
        return (
            f"{base}  "
            "Please report this at https://github.com/nddmars/OSSPolicyGuard/issues"
        )
