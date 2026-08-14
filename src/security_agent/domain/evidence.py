"""Raw evidence and bounded evidence previews."""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import ClassVar

from security_agent.domain._validation import (
    JSONObject,
    copy_json_object,
    require_non_blank,
    require_utc,
)
from security_agent.domain.utils import new_id, utc_now


class EvidenceType(StrEnum):
    TOOL_OUTPUT = "tool_output"
    TOOL_ERROR = "tool_error"
    NETWORK_SCAN = "network_scan"
    FILE_CONTENT = "file_content"
    HTTP_RESPONSE = "http_response"
    ARTIFACT = "artifact"
    OBSERVATION = "observation"
    OTHER = "other"


def content_digest(raw_content: str) -> str:
    return hashlib.sha256(raw_content.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class Evidence:
    """Full, integrity-protected output retained outside model context."""

    MAX_SUMMARY_CHARS: ClassVar[int] = 1_000

    run_id: str
    action_id: str | None
    type: EvidenceType
    source: str
    summary: str
    raw_content: str
    metadata: JSONObject = field(default_factory=dict)
    id: str = field(default_factory=new_id)
    content_hash: str = ""
    created_at: datetime = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        require_non_blank(self.id, "evidence id")
        require_non_blank(self.run_id, "evidence run_id")
        if self.action_id is not None:
            require_non_blank(self.action_id, "evidence action_id")
        if not isinstance(self.type, EvidenceType):
            raise ValueError("evidence type must be an EvidenceType")
        require_non_blank(self.source, "evidence source")
        if self.action_id is not None and not self.source.startswith("tool:"):
            raise ValueError("action-linked evidence source must start with 'tool:'")
        require_non_blank(self.summary, "evidence summary")
        if len(self.summary) > self.MAX_SUMMARY_CHARS:
            raise ValueError(f"evidence summary cannot exceed {self.MAX_SUMMARY_CHARS} characters")
        if not isinstance(self.raw_content, str):
            raise ValueError("raw_content must be a string")
        metadata: Mapping[str, object] = self.metadata
        object.__setattr__(self, "metadata", copy_json_object(metadata, "evidence metadata"))
        require_utc(self.created_at, "created_at")

        expected_hash = content_digest(self.raw_content)
        if self.content_hash and not hmac.compare_digest(self.content_hash, expected_hash):
            raise ValueError("content_hash does not match raw_content")
        object.__setattr__(self, "content_hash", expected_hash)

    @classmethod
    def create(
        cls,
        *,
        run_id: str,
        action_id: str | None,
        type: EvidenceType,
        source: str,
        summary: str,
        raw_content: str,
        metadata: Mapping[str, object] | None = None,
        id: str | None = None,
        created_at: datetime | None = None,
    ) -> Evidence:
        copied_metadata = copy_json_object(
            {} if metadata is None else metadata,
            "evidence metadata",
        )
        return cls(
            run_id=run_id,
            action_id=action_id,
            type=type,
            source=source,
            summary=summary,
            raw_content=raw_content,
            metadata=copied_metadata,
            id=new_id() if id is None else id,
            created_at=utc_now() if created_at is None else created_at,
        )

    @classmethod
    def from_content(
        cls,
        *,
        run_id: str,
        action_id: str | None,
        type: EvidenceType,
        source: str,
        summary: str,
        raw_content: str,
        metadata: Mapping[str, object] | None = None,
        id: str | None = None,
        created_at: datetime | None = None,
    ) -> Evidence:
        return cls.create(
            run_id=run_id,
            action_id=action_id,
            type=type,
            source=source,
            summary=summary,
            raw_content=raw_content,
            metadata=metadata,
            id=id,
            created_at=created_at,
        )

    def verify_hash(self) -> bool:
        return hmac.compare_digest(self.content_hash, content_digest(self.raw_content))

    def assert_integrity(self) -> None:
        if not self.verify_hash():
            raise ValueError(f"evidence {self.id!r} failed its SHA-256 integrity check")

    def preview(self, max_chars: int = 2_000) -> EvidencePreview:
        if isinstance(max_chars, bool) or not isinstance(max_chars, int) or max_chars <= 0:
            raise ValueError("max_chars must be a positive integer")
        return EvidencePreview(
            id=self.id,
            summary=self.summary,
            content_preview=self.raw_content[:max_chars],
            content_hash=self.content_hash,
            metadata=self.metadata,
        )


@dataclass(frozen=True, slots=True)
class EvidencePreview:
    """A bounded context DTO that is never a substitute for raw evidence."""

    id: str
    summary: str
    content_preview: str
    content_hash: str
    metadata: JSONObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        require_non_blank(self.id, "evidence preview id")
        require_non_blank(self.summary, "evidence preview summary")
        require_non_blank(self.content_hash, "evidence preview content_hash")
        if not isinstance(self.content_preview, str):
            raise ValueError("content_preview must be a string")
        metadata: Mapping[str, object] = self.metadata
        object.__setattr__(self, "metadata", copy_json_object(metadata, "preview metadata"))
