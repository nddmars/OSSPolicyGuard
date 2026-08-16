from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

__all__ = [
    "Decision",
    "Severity",
    "Dimension",
    "DataPresence",
    "PackageCoordinates",
    "Finding",
    "ProviderResult",
    "EvaluationResult",
]


class Decision(str, Enum):
    APPROVED = "APPROVED"
    REVIEW = "REVIEW"
    PROHIBITED = "PROHIBITED"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"
    UNKNOWN = "UNKNOWN"


class Dimension(str, Enum):
    SECURITY = "SECURITY"
    MAINTENANCE = "MAINTENANCE"
    COMMUNITY = "COMMUNITY"
    SUPPLY_CHAIN = "SUPPLY_CHAIN"


class DataPresence(str, Enum):
    PRESENT = "PRESENT"
    ABSENT = "ABSENT"
    STALE = "STALE"
    UNAVAILABLE = "UNAVAILABLE"
    UNKNOWN = "UNKNOWN"


@dataclass
class PackageCoordinates:
    ecosystem: str
    name: str
    version: str | None = None
    digest: str | None = None
    purl: str | None = None

    def canonical_name(self) -> str:
        return f"{self.ecosystem}:{self.name}"


@dataclass
class Finding:
    code: str
    title: str
    severity: Severity
    dimension: Dimension
    score_effect: float = 0.0
    evidence_refs: list[str] = field(default_factory=list)
    policy_rule: str | None = None
    remediation: str | None = None
    confidence: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "title": self.title,
            "severity": self.severity.value,
            "dimension": self.dimension.value,
            "score_effect": self.score_effect,
            "evidence_refs": list(self.evidence_refs),
            "policy_rule": self.policy_rule,
            "remediation": self.remediation,
            "confidence": self.confidence,
        }


@dataclass
class ProviderResult:
    provider: str
    status: str
    fetched_at: str
    source_url: str | None = None
    freshness_seconds: int | None = None
    confidence: float = 1.0
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "status": self.status,
            "fetched_at": self.fetched_at,
            "source_url": self.source_url,
            "freshness_seconds": self.freshness_seconds,
            "confidence": self.confidence,
            "data": self.data,
            "error": self.error,
        }


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class EvaluationResult:
    package: PackageCoordinates
    decision: Decision
    score: float
    dimensions: dict[str, float] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    evidence: list[ProviderResult] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    malicious_package_detected: bool = False
    policy_digest: str | None = None
    policy_name: str = "default"
    generated_at: str = field(default_factory=_now_utc_iso)
    tool_version: str = "0.1.0"
    schema_version: str = "1.0"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "tool_version": self.tool_version,
            "generated_at": self.generated_at,
            "policy": {
                "name": self.policy_name,
                "digest": self.policy_digest,
            },
            "package": {
                "ecosystem": self.package.ecosystem,
                "name": self.package.name,
                "version": self.package.version,
                "digest": self.package.digest,
                "purl": self.package.purl,
            },
            "decision": self.decision.value,
            "score": self.score,
            "dimensions": dict(self.dimensions),
            "findings": [f.to_dict() for f in self.findings],
            "evidence": [e.to_dict() for e in self.evidence],
            "warnings": list(self.warnings),
            "malicious_package_detected": self.malicious_package_detected,
        }

    @classmethod
    def from_legacy(
        cls,
        result: dict[str, Any],
        package_name: str,
        ecosystem: str,
    ) -> "EvaluationResult":
        package = PackageCoordinates(
            ecosystem=ecosystem,
            name=package_name,
            version=result.get("version"),
        )

        raw_approval = (result.get("approval") or "").strip().upper()
        if raw_approval in {"APPROVED", "AUTO-APPROVED"}:
            decision = Decision.APPROVED
        elif raw_approval == "PROHIBITED":
            decision = Decision.PROHIBITED
        else:
            decision = Decision.REVIEW

        score = round(float(result.get("total_score", 0.0)), 1)

        legacy_scores: dict[str, Any] = result.get("scores", {})
        dimensions: dict[str, float] = {
            Dimension.SECURITY.value.lower(): round(float(legacy_scores.get("security", 0.0)), 1),
            Dimension.MAINTENANCE.value.lower(): round(float(legacy_scores.get("activity", 0.0)), 1),
            Dimension.COMMUNITY.value.lower(): round(float(legacy_scores.get("community", 0.0)), 1),
            Dimension.SUPPLY_CHAIN.value.lower(): round(float(legacy_scores.get("trust", 0.0)), 1),
        }

        malicious = bool(
            result.get("is_malicious")
            or result.get("osv_data", {}).get("is_malicious", False)
        )

        evidence: list[ProviderResult] = []

        if "github_metrics" in result:
            gh = result["github_metrics"]
            evidence.append(ProviderResult(
                provider="github",
                status=gh.get("status", "success"),
                fetched_at=gh.get("fetched_at", ""),
                data={k: v for k, v in gh.items() if k not in {"status", "fetched_at"}},
                error=str(gh["error"]) if gh.get("error") else None,
            ))

        if "scorecard_data" in result:
            sc = result["scorecard_data"]
            evidence.append(ProviderResult(
                provider="scorecard",
                status=sc.get("status", "success"),
                fetched_at=sc.get("fetched_at", ""),
                data={k: v for k, v in sc.items() if k not in {"status", "fetched_at"}},
                error=str(sc["error"]) if sc.get("error") else None,
            ))

        if "osv_data" in result:
            osv = result["osv_data"]
            evidence.append(ProviderResult(
                provider="osv",
                status="success",
                fetched_at=osv.get("last_updated", ""),
                data={k: v for k, v in osv.items() if k != "last_updated"},
            ))

        if "cve_data" in result:
            cve = result["cve_data"]
            evidence.append(ProviderResult(
                provider="nvd",
                status="success",
                fetched_at=cve.get("last_updated", ""),
                data={k: v for k, v in cve.items() if k != "last_updated"},
            ))

        if "download_data" in result:
            dl = result["download_data"]
            evidence.append(ProviderResult(
                provider=dl.get("registry", "registry"),
                status="success",
                fetched_at="",
                data=dict(dl),
            ))

        warnings: list[str] = list(result.get("warnings", []))
        generated_at = result.get("timestamp") or _now_utc_iso()

        return cls(
            package=package,
            decision=decision,
            score=score,
            dimensions=dimensions,
            findings=[],
            evidence=evidence,
            warnings=warnings,
            malicious_package_detected=malicious,
            policy_name="default",
            generated_at=generated_at,
        )
