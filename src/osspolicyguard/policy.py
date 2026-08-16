"""OPG-056 / OPG-060: Versioned policy-as-code and missing-data semantics.

OPG-056 – PolicyBundle is the single source of truth for all policy rules and
thresholds.  Every bundle carries a schema_version, a semver version, an
effective_date, an owner, and a human-readable changelog so that policy
changes are fully auditable.  The digest property produces a short
content-addressed fingerprint that can be stored alongside evaluation results.

OPG-060 – evaluate_missing_data() and apply_missing_data_rule() give callers
a uniform way to handle missing, stale, or unavailable provider data without
silently skipping rules or producing misleading scores.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

__all__ = [
    "PolicyBundle",
    "PolicyRule",
    "DataPresence",
    "DEFAULT_POLICY",
    "evaluate_missing_data",
    "apply_missing_data_rule",
]


# ---------------------------------------------------------------------------
# OPG-060 – Missing-data semantics
# ---------------------------------------------------------------------------


class DataPresence(str, Enum):
    """Describes how reliably a data value is available from a provider.

    PRESENT     – value was returned and is current.
    ABSENT      – provider was reachable but explicitly returned no data
                  (e.g. package not in database).
    STALE       – value was returned but is older than the freshness window.
    UNAVAILABLE – provider could not be reached (network error, rate-limit…).
    UNKNOWN     – presence has not been assessed yet.
    """

    PRESENT = "PRESENT"
    ABSENT = "ABSENT"
    STALE = "STALE"
    UNAVAILABLE = "UNAVAILABLE"
    UNKNOWN = "UNKNOWN"


def evaluate_missing_data(value: Any, provider_status: str) -> DataPresence:
    """Classify a provider value into a DataPresence enum member.

    Args:
        value:           The raw value returned by the provider (may be None).
        provider_status: A string token produced by the provider layer.
                         Recognised values (case-insensitive):
                           "ok" / "success" / "present"  → PRESENT (if value
                           is not None) or ABSENT
                           "absent" / "not_found"         → ABSENT
                           "stale" / "cached"             → STALE
                           "error" / "unavailable" /
                           "timeout" / "rate_limited" /
                           "rate_limit"                   → UNAVAILABLE
                           anything else                  → UNKNOWN

    Returns:
        A DataPresence member that callers can pass to apply_missing_data_rule.
    """
    normalised = (provider_status or "").strip().lower()

    absent_tokens = {"absent", "not_found"}
    stale_tokens = {"stale", "cached"}
    unavailable_tokens = {"error", "unavailable", "timeout", "rate_limited", "rate_limit"}
    ok_tokens = {"ok", "success", "present"}

    if normalised in absent_tokens:
        return DataPresence.ABSENT

    if normalised in stale_tokens:
        # Value may still be present even if stale
        return DataPresence.STALE

    if normalised in unavailable_tokens:
        return DataPresence.UNAVAILABLE

    if normalised in ok_tokens:
        # Treat a "success" status with a None value as absent
        if value is None:
            return DataPresence.ABSENT
        return DataPresence.PRESENT

    return DataPresence.UNKNOWN


def apply_missing_data_rule(presence: DataPresence, rule: "PolicyRule") -> str | None:
    """Decide how a rule should handle missing provider data.

    Policy:
      * If evidence_required lists at least one source AND the data presence is
        ABSENT or UNKNOWN → the rule cannot be evaluated confidently; return
        "abstain" so the caller records an abstention rather than a pass/fail.
      * If presence is UNAVAILABLE AND no evidence is required → the provider
        is optional; return "skip" so the caller ignores this rule for the
        current run without penalising the package.
      * In all other cases (PRESENT, STALE, or no hard evidence requirement)
        → return None, meaning the caller should proceed with normal evaluation.

    Args:
        presence: DataPresence enum member for the relevant provider value.
        rule:     The PolicyRule being considered.

    Returns:
        "abstain" | "skip" | None
    """
    has_required_evidence = bool(rule.evidence_required)

    # A required data source that is absent, unknown, or unavailable (provider
    # outage / rate-limit) cannot satisfy the rule → abstain rather than allow.
    if has_required_evidence and presence in (
        DataPresence.ABSENT,
        DataPresence.UNKNOWN,
        DataPresence.UNAVAILABLE,
    ):
        return "abstain"

    # Optional provider is down → skip this rule silently for the current run.
    if presence is DataPresence.UNAVAILABLE and not has_required_evidence:
        return "skip"

    return None


# ---------------------------------------------------------------------------
# OPG-056 – Versioned policy-as-code
# ---------------------------------------------------------------------------


@dataclass
class PolicyRule:
    """A single evaluable rule within a PolicyBundle.

    Attributes:
        id:                Stable identifier (e.g. "POL-SEC-001").
        description:       Human-readable description of what the rule checks.
        dimension:         Which scoring dimension this rule belongs to
                           (e.g. "SECURITY", "MAINTENANCE").
        threshold:         Numeric threshold that triggers the rule, or None
                           when the rule is binary (block on any match).
        action:            What to do when the rule triggers:
                             "block"          – prohibit the package outright.
                             "penalize"       – reduce its score.
                             "warn"           – emit a warning but allow.
                             "require_review" – escalate for human review.
                             "abstain"        – take no action (data missing).
        enabled:           Whether the rule is active in this bundle.
        evidence_required: Provider sources that must supply data for this rule
                           to produce a verdict (used by apply_missing_data_rule).
    """

    id: str
    description: str
    dimension: str
    threshold: float | None = None
    action: str = "require_review"  # block | penalize | warn | require_review | abstain
    enabled: bool = True
    evidence_required: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "description": self.description,
            "dimension": self.dimension,
            "threshold": self.threshold,
            "action": self.action,
            "enabled": self.enabled,
            "evidence_required": list(self.evidence_required),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "PolicyRule":
        return cls(
            id=d["id"],
            description=d["description"],
            dimension=d["dimension"],
            threshold=d.get("threshold"),
            action=d.get("action", "require_review"),
            enabled=d.get("enabled", True),
            evidence_required=list(d.get("evidence_required", [])),
        )


@dataclass
class PolicyBundle:
    """A versioned, content-addressed collection of PolicyRules.

    A PolicyBundle is the single source of truth for all thresholds, weights,
    and rules used during package evaluation.  Bundles are serialisable to/from
    plain dicts (and therefore JSON) so they can be loaded from files, network
    endpoints, or environment variables without any third-party dependencies.

    Attributes:
        schema_version: Version of the PolicyBundle schema itself.  Increment
                        when the serialisation format changes.
        name:           Short identifier for this bundle (e.g. "default",
                        "strict", "permissive").
        version:        Semver of this particular bundle's content.
        effective_date: ISO-8601 date from which this bundle applies.
        owner:          Team or individual responsible for this policy.
        changelog:      Ordered list of human-readable change notes.
        rules:          Ordered list of PolicyRule objects.
        thresholds:     Named numeric thresholds (e.g. {"approved": 80.0}).
        weights:        Dimension weights that must sum to 1.0
                        (e.g. {"security": 0.35, "maintenance": 0.30, …}).
    """

    schema_version: str = "1.0"
    name: str = "default"
    version: str = "0.1.0"
    effective_date: str = "2024-01-01"
    owner: str = "OSSPolicyGuard project"
    changelog: list[str] = field(default_factory=list)
    rules: list[PolicyRule] = field(default_factory=list)
    thresholds: dict[str, float] = field(default_factory=dict)
    weights: dict[str, float] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Content-addressed fingerprint (OPG-056)
    # ------------------------------------------------------------------

    @property
    def digest(self) -> str:
        """Return a 16-character SHA-256 hex digest of the canonical bundle.

        The digest is computed over the JSON-serialised form of to_dict() with
        keys sorted and compact separators so it is deterministic across
        platforms and Python versions.
        """
        canonical = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()[:16]

    # ------------------------------------------------------------------
    # Serialisation helpers
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Serialise the bundle to a plain dict suitable for JSON encoding."""
        return {
            "schema_version": self.schema_version,
            "name": self.name,
            "version": self.version,
            "effective_date": self.effective_date,
            "owner": self.owner,
            "changelog": list(self.changelog),
            "rules": [r.to_dict() for r in self.rules],
            "thresholds": dict(self.thresholds),
            "weights": dict(self.weights),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "PolicyBundle":
        """Deserialise a PolicyBundle from a plain dict.

        Unknown top-level keys are silently ignored so that newer bundle files
        remain loadable by older versions of the library.
        """
        rules = [PolicyRule.from_dict(r) for r in d.get("rules", [])]
        return cls(
            schema_version=d.get("schema_version", "1.0"),
            name=d.get("name", "default"),
            version=d.get("version", "0.1.0"),
            effective_date=d.get("effective_date", "2024-01-01"),
            owner=d.get("owner", "OSSPolicyGuard project"),
            changelog=list(d.get("changelog", [])),
            rules=rules,
            thresholds=dict(d.get("thresholds", {})),
            weights=dict(d.get("weights", {})),
        )

    # ------------------------------------------------------------------
    # Rule look-up
    # ------------------------------------------------------------------

    def get_rule(self, rule_id: str) -> "PolicyRule | None":
        """Return the first enabled rule whose id matches rule_id, or None."""
        for rule in self.rules:
            if rule.id == rule_id:
                return rule
        return None


# ---------------------------------------------------------------------------
# DEFAULT_POLICY – shipped with the library (OPG-056)
# ---------------------------------------------------------------------------

DEFAULT_POLICY = PolicyBundle(
    name="default",
    version="0.1.0",
    effective_date="2024-01-01",
    owner="OSSPolicyGuard project",
    changelog=["Initial policy bundle"],
    rules=[
        PolicyRule(
            "POL-MAL-001",
            "Malicious package detected",
            "SUPPLY_CHAIN",
            None,
            "block",
            True,
            ["osv"],
        ),
        PolicyRule(
            "POL-SEC-001",
            "Critical CVE with active exploit (EPSS≥0.5)",
            "SECURITY",
            None,
            "block",
            True,
            ["nvd", "epss"],
        ),
        PolicyRule(
            "POL-SEC-002",
            "Security score below review threshold",
            "SECURITY",
            60.0,
            "require_review",
            True,
            [],
        ),
        PolicyRule(
            "POL-SEC-003",
            "Security score below critical threshold",
            "SECURITY",
            30.0,
            "block",
            True,
            [],
        ),
        PolicyRule(
            "POL-ACT-001",
            "Package abandoned (activity score<40)",
            "MAINTENANCE",
            40.0,
            "require_review",
            True,
            ["github"],
        ),
        PolicyRule(
            "POL-COM-001",
            "Low community adoption",
            "COMMUNITY",
            40.0,
            "warn",
            True,
            [],
        ),
        PolicyRule(
            "POL-TRU-001",
            "Low trust score",
            "SUPPLY_CHAIN",
            40.0,
            "warn",
            True,
            [],
        ),
    ],
    thresholds={"approved": 80.0, "review": 60.0},
    weights={
        "security": 0.35,
        "maintenance": 0.30,
        "community": 0.15,
        "supply_chain": 0.20,
    },
)
