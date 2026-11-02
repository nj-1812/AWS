"""Core domain models shared by the scanner, the agents, and the evaluation harness."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Pillar(str, Enum):
    """The six pillars of the AWS Well-Architected Framework."""

    OPERATIONAL_EXCELLENCE = "operational_excellence"
    SECURITY = "security"
    RELIABILITY = "reliability"
    PERFORMANCE = "performance_efficiency"
    COST = "cost_optimization"
    SUSTAINABILITY = "sustainability"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def weight(self) -> int:
        return {"critical": 10, "high": 6, "medium": 3, "low": 1}[self.value]


@dataclass(frozen=True)
class Resource:
    """A normalized infrastructure resource, independent of the IaC source format."""

    logical_id: str
    type: str  # CloudFormation type, e.g. "AWS::S3::Bucket"
    properties: dict[str, Any]
    source_file: str = ""


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    pillar: Pillar
    severity: Severity
    resource_id: str
    resource_type: str
    message: str
    remediation: str
    wa_best_practice: str  # Well-Architected best practice ID, e.g. "SEC03-BP02"
    fix_hint: dict[str, Any] = field(default_factory=dict)  # machine-readable property patch

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["pillar"] = self.pillar.value
        d["severity"] = self.severity.value
        return d

    @property
    def key(self) -> tuple[str, str]:
        """Identity used for de-duplication and benchmark matching."""
        return (self.rule_id, self.resource_id)
