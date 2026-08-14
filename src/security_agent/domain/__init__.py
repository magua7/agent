"""Stable public API for the framework's dependency-free domain layer."""

from security_agent.domain.action import ActionRecord
from security_agent.domain.evidence import Evidence, EvidencePreview, EvidenceType, content_digest
from security_agent.domain.finding import (
    Finding,
    FindingDraft,
    FindingStatus,
    Severity,
    finding_fingerprint,
)
from security_agent.domain.plan import NodeStatus, Plan, PlanNode, PlanStatus
from security_agent.domain.run import RunState, RunStatus
from security_agent.domain.task import ScopeSpec, TaskSpec, TaskType
from security_agent.domain.utils import new_id, utc_now
from security_agent.domain.verification import (
    CriterionAssessment,
    Observation,
    VerificationResult,
)

__all__ = [
    "ActionRecord",
    "CriterionAssessment",
    "Evidence",
    "EvidencePreview",
    "EvidenceType",
    "Finding",
    "FindingDraft",
    "FindingStatus",
    "NodeStatus",
    "Observation",
    "Plan",
    "PlanNode",
    "PlanStatus",
    "RunState",
    "RunStatus",
    "ScopeSpec",
    "Severity",
    "TaskSpec",
    "TaskType",
    "VerificationResult",
    "content_digest",
    "finding_fingerprint",
    "new_id",
    "utc_now",
]
