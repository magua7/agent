"""Product-facing values kept outside the Security Agent kernel domain."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from itertools import pairwise

from security_agent.contracts import RunEvent
from security_agent.domain import RunStatus, TaskSpec, new_id, utc_now


class TaskStatus(StrEnum):
    """Lifecycle of a user-owned product task.

    This is deliberately separate from :class:`RunStatus`: a draft or queued
    product task may not have a kernel run yet.
    """

    DRAFT = "draft"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass(frozen=True, slots=True)
class ProductUser:
    id: str
    username: str
    password_hash: str
    created_at: datetime = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        _require_text(self.id, "user id", maximum=128)
        _require_text(self.username, "username", maximum=128)
        _require_text(self.password_hash, "password_hash", maximum=4_096)
        _require_utc(self.created_at, "user created_at")


@dataclass(frozen=True, slots=True)
class ProductTask:
    """A user-owned task record and its optional executable kernel intent."""

    id: str
    user_id: str
    title: str
    description: str
    status: TaskStatus = TaskStatus.DRAFT
    task_spec: TaskSpec | None = None
    run_id: str | None = None
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        _require_text(self.id, "task id", maximum=128)
        _require_text(self.user_id, "task user_id", maximum=128)
        _require_text(self.title, "task title", maximum=200)
        _require_text(self.description, "task description", maximum=20_000)
        if not isinstance(self.status, TaskStatus):
            raise ValueError("task status must be a TaskStatus")
        if self.task_spec is not None:
            if not isinstance(self.task_spec, TaskSpec):
                raise ValueError("task_spec must be a TaskSpec or None")
            if self.task_spec.id != self.id:
                raise ValueError("task_spec id must match the product task id")
        if self.run_id is not None:
            _require_text(self.run_id, "task run_id", maximum=128)
            if self.task_spec is None:
                raise ValueError("a task with a run_id requires task_spec")
        _require_utc(self.created_at, "task created_at")
        _require_utc(self.updated_at, "task updated_at")
        if self.updated_at < self.created_at:
            raise ValueError("task updated_at cannot be earlier than created_at")

    @classmethod
    def create(
        cls,
        *,
        user_id: str,
        title: str,
        description: str,
        task_spec: TaskSpec | None = None,
        id: str | None = None,
        created_at: datetime | None = None,
    ) -> ProductTask:
        identifier = task_spec.id if id is None and task_spec is not None else id or new_id()
        timestamp = created_at or utc_now()
        return cls(
            id=identifier,
            user_id=user_id,
            title=title,
            description=description,
            task_spec=task_spec,
            created_at=timestamp,
            updated_at=timestamp,
        )


@dataclass(frozen=True, slots=True)
class TaskProjection:
    """Bounded task/run read model; it never contains raw Evidence."""

    task: ProductTask
    run_status: RunStatus | None = None
    run_updated_at: datetime | None = None
    plan_node_count: int = 0
    action_count: int = 0
    evidence_count: int = 0
    finding_count: int = 0
    last_event_sequence: int = 0
    last_error: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.task, ProductTask):
            raise ValueError("projection task must be a ProductTask")
        if self.run_status is not None and not isinstance(self.run_status, RunStatus):
            raise ValueError("projection run_status must be a RunStatus or None")
        if self.run_updated_at is not None:
            _require_utc(self.run_updated_at, "run_updated_at")
        for label, value in (
            ("plan_node_count", self.plan_node_count),
            ("action_count", self.action_count),
            ("evidence_count", self.evidence_count),
            ("finding_count", self.finding_count),
            ("last_event_sequence", self.last_event_sequence),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{label} must be a non-negative integer")
        if self.last_error is not None:
            _require_text(self.last_error, "last_error", maximum=20_000)

    @property
    def effective_status(self) -> TaskStatus:
        if self.run_status is None:
            return self.task.status
        return {
            RunStatus.CREATED: TaskStatus.QUEUED,
            RunStatus.PLANNING: TaskStatus.RUNNING,
            RunStatus.RUNNING: TaskStatus.RUNNING,
            RunStatus.VERIFYING: TaskStatus.RUNNING,
            RunStatus.COMPLETED: TaskStatus.COMPLETED,
            RunStatus.FAILED: TaskStatus.FAILED,
            RunStatus.CANCELLED: TaskStatus.CANCELLED,
        }[self.run_status]


@dataclass(frozen=True, slots=True)
class ProductRunEvent:
    """A persisted kernel event with its stable SQLite row cursor."""

    sequence: int
    event: RunEvent

    def __post_init__(self) -> None:
        if isinstance(self.sequence, bool) or not isinstance(self.sequence, int):
            raise ValueError("event sequence must be an integer")
        if self.sequence <= 0:
            raise ValueError("event sequence must be positive")
        if not isinstance(self.event, RunEvent):
            raise ValueError("event must be a RunEvent")


@dataclass(frozen=True, slots=True)
class EventPage:
    events: tuple[ProductRunEvent, ...]
    next_cursor: int
    has_more: bool

    def __post_init__(self) -> None:
        events = tuple(self.events)
        if not all(isinstance(item, ProductRunEvent) for item in events):
            raise ValueError("events must contain ProductRunEvent values")
        if any(left.sequence >= right.sequence for left, right in pairwise(events)):
            raise ValueError("events must be ordered by increasing sequence")
        if isinstance(self.next_cursor, bool) or not isinstance(self.next_cursor, int):
            raise ValueError("next_cursor must be an integer")
        if self.next_cursor < 0:
            raise ValueError("next_cursor cannot be negative")
        if events and self.next_cursor != events[-1].sequence:
            raise ValueError("next_cursor must identify the final returned event")
        if not isinstance(self.has_more, bool):
            raise ValueError("has_more must be boolean")
        object.__setattr__(self, "events", events)

    @property
    def items(self) -> tuple[ProductRunEvent, ...]:
        return self.events


def _require_text(value: str, label: str, *, maximum: int) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be non-empty text")
    if len(value) > maximum:
        raise ValueError(f"{label} cannot exceed {maximum} characters")


def _require_utc(value: datetime, label: str) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError(f"{label} must be timezone-aware")
    offset = value.utcoffset()
    if offset is None:
        raise ValueError(f"{label} must be timezone-aware")
    if offset.total_seconds() != 0:
        raise ValueError(f"{label} must be UTC")
