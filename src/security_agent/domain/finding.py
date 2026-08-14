"""Evidence-backed security findings and agent finding proposals."""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass, field, replace
from datetime import datetime
from enum import StrEnum

from security_agent.domain._validation import (
    merge_unique,
    require_non_blank,
    require_utc,
    string_tuple,
)
from security_agent.domain.utils import new_id, utc_now


class Severity(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(StrEnum):
    DRAFT = "draft"
    UNVERIFIED = "unverified"
    VERIFIED = "verified"
    REJECTED = "rejected"
    RESOLVED = "resolved"


def _validate_confidence(confidence: float) -> None:
    if isinstance(confidence, bool) or not isinstance(confidence, int | float):
        raise ValueError("finding confidence must be numeric")
    if not math.isfinite(float(confidence)) or not 0.0 <= confidence <= 1.0:
        raise ValueError("finding confidence must be between 0 and 1")


def finding_fingerprint(subject: str, title: str) -> str:
    """Build a stable deduplication key from normalized finding identity."""
    normalized_subject = " ".join(subject.split()).casefold()
    normalized_title = " ".join(title.split()).casefold()
    return hashlib.sha256(f"{normalized_subject}\0{normalized_title}".encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class FindingDraft:
    """An agent proposal that has not been granted verified status."""

    title: str
    description: str
    severity: Severity
    confidence: float
    evidence_ids: tuple[str, ...] = ()
    subject: str = ""
    fingerprint: str = ""

    def __post_init__(self) -> None:
        require_non_blank(self.title, "finding draft title")
        require_non_blank(self.description, "finding draft description")
        if not isinstance(self.severity, Severity):
            raise ValueError("finding draft severity must be a Severity")
        _validate_confidence(self.confidence)
        object.__setattr__(
            self,
            "evidence_ids",
            string_tuple(self.evidence_ids, "finding draft evidence_ids"),
        )
        if self.subject:
            require_non_blank(self.subject, "finding draft subject")
        if self.fingerprint:
            require_non_blank(self.fingerprint, "finding draft fingerprint")
        else:
            object.__setattr__(self, "fingerprint", finding_fingerprint(self.subject, self.title))

    def to_finding(
        self,
        run_id: str,
        *,
        status: FindingStatus = FindingStatus.DRAFT,
        id: str | None = None,
        created_at: datetime | None = None,
    ) -> Finding:
        return Finding(
            run_id=run_id,
            title=self.title,
            description=self.description,
            severity=self.severity,
            confidence=self.confidence,
            evidence_ids=self.evidence_ids,
            status=status,
            subject=self.subject,
            fingerprint=self.fingerprint,
            id=new_id() if id is None else id,
            created_at=utc_now() if created_at is None else created_at,
        )


@dataclass(frozen=True, slots=True)
class Finding:
    run_id: str
    title: str
    description: str
    severity: Severity
    confidence: float
    evidence_ids: tuple[str, ...] = ()
    status: FindingStatus = FindingStatus.DRAFT
    subject: str = ""
    fingerprint: str = ""
    id: str = field(default_factory=new_id)
    created_at: datetime = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        require_non_blank(self.id, "finding id")
        require_non_blank(self.run_id, "finding run_id")
        require_non_blank(self.title, "finding title")
        require_non_blank(self.description, "finding description")
        if not isinstance(self.severity, Severity):
            raise ValueError("finding severity must be a Severity")
        _validate_confidence(self.confidence)
        evidence_ids = string_tuple(self.evidence_ids, "finding evidence_ids")
        if not isinstance(self.status, FindingStatus):
            raise ValueError("finding status must be a FindingStatus")
        if self.status is FindingStatus.VERIFIED and not evidence_ids:
            raise ValueError("a verified finding must reference evidence")
        if self.subject:
            require_non_blank(self.subject, "finding subject")
        fingerprint = self.fingerprint or finding_fingerprint(self.subject, self.title)
        require_non_blank(fingerprint, "finding fingerprint")
        require_utc(self.created_at, "created_at")
        object.__setattr__(self, "evidence_ids", evidence_ids)
        object.__setattr__(self, "fingerprint", fingerprint)

    @classmethod
    def create(
        cls,
        *,
        run_id: str,
        title: str,
        description: str,
        severity: Severity,
        confidence: float,
        evidence_ids: tuple[str, ...] = (),
        status: FindingStatus = FindingStatus.DRAFT,
        subject: str = "",
        fingerprint: str = "",
        id: str | None = None,
        created_at: datetime | None = None,
    ) -> Finding:
        return cls(
            run_id=run_id,
            title=title,
            description=description,
            severity=severity,
            confidence=confidence,
            evidence_ids=evidence_ids,
            status=status,
            subject=subject,
            fingerprint=fingerprint,
            id=new_id() if id is None else id,
            created_at=utc_now() if created_at is None else created_at,
        )

    def add_evidence(self, *evidence_ids: str) -> Finding:
        return replace(
            self,
            evidence_ids=merge_unique(self.evidence_ids, evidence_ids, "finding evidence_ids"),
        )

    def verify(self, *evidence_ids: str) -> Finding:
        linked = merge_unique(self.evidence_ids, evidence_ids, "finding evidence_ids")
        if not linked:
            raise ValueError("a finding cannot be verified without evidence")
        return replace(self, evidence_ids=linked, status=FindingStatus.VERIFIED)
