import re
import logging
from typing import TypedDict

logger = logging.getLogger(__name__)

_PRIVATE_NS_PATTERNS: list[re.Pattern] = [
    re.compile(r"^@internal/"),
    re.compile(r"^@corp/"),
    re.compile(r"^@company/"),
    re.compile(r"^@private/"),
    re.compile(r"^@myorg/"),
    re.compile(r"^@local/"),
    re.compile(r"^internal-"),
    re.compile(r"^corp-"),
    re.compile(r"^private-"),
    re.compile(r"^company-"),
    re.compile(r"^myapp-"),
    re.compile(r"^mylib-"),
]


class DepConfusionResult(TypedDict):
    package_name: str
    suspicious: bool
    reason: str | None
    matched_pattern: str | None
    confidence: float


def detect_dependency_confusion(
    package_name: str,
    internal_namespaces: list[str] | None = None,
    known_internal_packages: set[str] | None = None,
) -> DepConfusionResult:
    """Detect potential dependency confusion attacks for a given package name.

    Checks are applied in priority order:
    1. Exact match against known internal packages (confidence=0.95).
    2. Regex match against caller-supplied internal namespace patterns (confidence=0.90).
    3. Regex match against built-in private namespace patterns (confidence=0.70).
    4. No match — package is considered safe (confidence=1.0).

    Args:
        package_name: The name of the package to evaluate.
        internal_namespaces: Optional list of regex strings representing
            organisation-specific internal namespace patterns.
        known_internal_packages: Optional set of exact package names that are
            known to be internal/private packages.

    Returns:
        A :class:`DepConfusionResult` mapping with detection details.
    """
    # 1. Exact match against known internal packages.
    if known_internal_packages and package_name in known_internal_packages:
        logger.warning(
            "OPG-047: Package %r found in known_internal_packages — "
            "possible dependency confusion attack.",
            package_name,
        )
        return DepConfusionResult(
            package_name=package_name,
            suspicious=True,
            reason=(
                f"Package '{package_name}' is listed as a known internal package. "
                "A public registry version of this name may be an adversarial upload."
            ),
            matched_pattern=package_name,
            confidence=0.95,
        )

    # 2. Caller-supplied internal namespace patterns.
    if internal_namespaces:
        for ns in internal_namespaces:
            if re.search(ns, package_name):
                logger.warning(
                    "OPG-047: Package %r matched caller-supplied internal namespace "
                    "pattern %r — possible dependency confusion attack.",
                    package_name,
                    ns,
                )
                return DepConfusionResult(
                    package_name=package_name,
                    suspicious=True,
                    reason=(
                        f"Package '{package_name}' matches the internal namespace "
                        f"pattern '{ns}' provided by the caller."
                    ),
                    matched_pattern=ns,
                    confidence=0.90,
                )

    # 3. Built-in private namespace patterns.
    for pattern in _PRIVATE_NS_PATTERNS:
        if pattern.search(package_name):
            logger.warning(
                "OPG-047: Package %r matched built-in private namespace pattern %r "
                "— possible dependency confusion attack.",
                package_name,
                pattern.pattern,
            )
            return DepConfusionResult(
                package_name=package_name,
                suspicious=True,
                reason=(
                    f"Package '{package_name}' matches the built-in private namespace "
                    f"pattern '{pattern.pattern}', suggesting it may be an internal "
                    "package that should not appear on a public registry."
                ),
                matched_pattern=pattern.pattern,
                confidence=0.70,
            )

    # 4. No match — package appears safe.
    logger.debug(
        "OPG-047: Package %r did not match any dependency confusion indicators.",
        package_name,
    )
    return DepConfusionResult(
        package_name=package_name,
        suspicious=False,
        reason=None,
        matched_pattern=None,
        confidence=1.0,
    )


def check_registry_collision(
    package_name: str,
    ecosystem: str,
    internal_registry_url: str | None = None,
) -> bool:
    """Check whether an internal package name collides with a public registry entry.

    .. note::
        This is a **placeholder** implementation (OPG-047).  Live registry
        collision checking requires outbound network access and is provided by
        the full OPG-023 provider implementation.  This function always returns
        ``False`` and logs a warning to make the limitation visible.

    Args:
        package_name: The package name to check.
        ecosystem: The package ecosystem (e.g. ``"npm"``, ``"pypi"``,
            ``"maven"``).
        internal_registry_url: Optional URL of an internal/private registry to
            compare against the public registry.

    Returns:
        ``False`` — always, because live network checks are not performed here.
    """
    logger.warning(
        "OPG-047: check_registry_collision called for package %r (ecosystem=%r, "
        "internal_registry_url=%r). Live registry collision checking requires "
        "network access and is not performed by this placeholder. Replace with "
        "the full OPG-023 provider implementation for production use.",
        package_name,
        ecosystem,
        internal_registry_url,
    )
    return False


__all__ = [
    "detect_dependency_confusion",
    "check_registry_collision",
    "DepConfusionResult",
]
