"""Agent proposals and verifier decisions."""

from __future__ import annotations

from dataclasses import dataclass

from security_agent.domain._validation import require_non_blank, string_tuple
from security_agent.domain.finding import FindingDraft


@dataclass(frozen=True, slots=True)
class CriterionAssessment:
    criterion: str
    satisfied: bool
    evidence_ids: tuple[str, ...] = ()
    reason: str = ""

    def __post_init__(self) -> None:
        require_non_blank(self.criterion, "criterion")
        if not isinstance(self.satisfied, bool):
            raise ValueError("satisfied must be a bool")
        object.__setattr__(
            self,
            "evidence_ids",
            string_tuple(self.evidence_ids, "assessment evidence_ids"),
        )
        require_non_blank(self.reason, "assessment reason")


@dataclass(frozen=True, slots=True)
class Observation:
    """An agent's evidence interpretation; it has no mutation authority."""

    summary: str
    criterion_assessments: tuple[CriterionAssessment, ...]
    finding_drafts: tuple[FindingDraft, ...] = ()
    suggested_replan: bool = False

    def __post_init__(self) -> None:
        require_non_blank(self.summary, "observation summary")
        assessments = tuple(self.criterion_assessments)
        if not all(isinstance(item, CriterionAssessment) for item in assessments):
            raise ValueError("criterion_assessments must contain CriterionAssessment values")
        criteria = tuple(item.criterion for item in assessments)
        if len(criteria) != len(set(criteria)):
            raise ValueError("criterion_assessments must contain unique criteria")
        drafts = tuple(self.finding_drafts)
        if not all(isinstance(item, FindingDraft) for item in drafts):
            raise ValueError("finding_drafts must contain FindingDraft values")
        if not isinstance(self.suggested_replan, bool):
            raise ValueError("suggested_replan must be a bool")
        object.__setattr__(self, "criterion_assessments", assessments)
        object.__setattr__(self, "finding_drafts", drafts)


@dataclass(frozen=True, slots=True)
class VerificationResult:
    """Independent verifier decision.  The object itself performs no mutation."""

    success: bool
    reason: str
    evidence_ids: tuple[str, ...] = ()
    missing_requirements: tuple[str, ...] = ()
    conflicts: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.success, bool):
            raise ValueError("verification success must be a bool")
        require_non_blank(self.reason, "verification reason")
        object.__setattr__(
            self,
            "evidence_ids",
            string_tuple(self.evidence_ids, "verification evidence_ids"),
        )
        object.__setattr__(
            self,
            "missing_requirements",
            string_tuple(self.missing_requirements, "missing_requirements"),
        )
        object.__setattr__(
            self,
            "conflicts",
            string_tuple(self.conflicts, "conflicts"),
        )
        if self.success and (self.missing_requirements or self.conflicts):
            raise ValueError(
                "successful verification cannot have missing requirements or conflicts"
            )

    @classmethod
    def accepted(
        cls,
        reason: str,
        evidence_ids: tuple[str, ...] = (),
    ) -> VerificationResult:
        return cls(success=True, reason=reason, evidence_ids=evidence_ids)

    @classmethod
    def rejected(
        cls,
        reason: str,
        *,
        evidence_ids: tuple[str, ...] = (),
        missing_requirements: tuple[str, ...] = (),
        conflicts: tuple[str, ...] = (),
    ) -> VerificationResult:
        return cls(
            success=False,
            reason=reason,
            evidence_ids=evidence_ids,
            missing_requirements=missing_requirements,
            conflicts=conflicts,
        )
