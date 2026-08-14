"""Auditable records for attempted tool invocations."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from datetime import datetime

from security_agent.domain._validation import (
    JSONObject,
    copy_json_object,
    merge_unique,
    require_non_blank,
    require_non_negative_int,
    require_utc,
    string_tuple,
)
from security_agent.domain.utils import new_id, utc_now


@dataclass(frozen=True, slots=True)
class ActionRecord:
    """One tool attempt, including rejected and failed attempts."""

    run_id: str
    plan_node_id: str
    agent_id: str
    tool_name: str
    arguments: JSONObject = field(default_factory=dict)
    id: str = field(default_factory=new_id)
    started_at: datetime = field(default_factory=utc_now)
    finished_at: datetime | None = None
    duration_ms: int | None = None
    success: bool | None = None
    exit_code: int | None = None
    error: str | None = None
    evidence_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        require_non_blank(self.id, "action id")
        require_non_blank(self.run_id, "action run_id")
        require_non_blank(self.plan_node_id, "action plan_node_id")
        require_non_blank(self.agent_id, "action agent_id")
        require_non_blank(self.tool_name, "action tool_name")
        arguments: Mapping[str, object] = self.arguments
        object.__setattr__(self, "arguments", copy_json_object(arguments, "action arguments"))
        object.__setattr__(
            self,
            "evidence_ids",
            string_tuple(self.evidence_ids, "action evidence_ids"),
        )
        require_utc(self.started_at, "started_at")

        finished_values = (self.finished_at, self.duration_ms, self.success)
        has_any_finished_value = any(value is not None for value in finished_values)
        has_all_finished_values = all(value is not None for value in finished_values)
        if has_any_finished_value and not has_all_finished_values:
            raise ValueError("finished_at, duration_ms, and success must be set together")
        if self.finished_at is None:
            if self.exit_code is not None or self.error is not None or self.evidence_ids:
                raise ValueError("unfinished actions cannot have a result or evidence references")
            return

        require_utc(self.finished_at, "finished_at")
        if self.finished_at < self.started_at:
            raise ValueError("finished_at cannot be earlier than started_at")
        if self.duration_ms is None:  # narrowed by has_all_finished_values
            raise ValueError("finished actions require duration_ms")
        require_non_negative_int(self.duration_ms, "duration_ms")
        if not isinstance(self.success, bool):
            raise ValueError("finished actions require a boolean success value")
        if self.exit_code is not None and (
            isinstance(self.exit_code, bool) or not isinstance(self.exit_code, int)
        ):
            raise ValueError("exit_code must be an integer or None")
        if self.error is not None:
            require_non_blank(self.error, "action error")
        if self.success and self.error is not None:
            raise ValueError("successful actions cannot contain an error")
        if not self.success and self.error is None:
            raise ValueError("failed actions must contain an error")

    @classmethod
    def start(
        cls,
        *,
        run_id: str,
        plan_node_id: str,
        agent_id: str,
        tool_name: str,
        arguments: Mapping[str, object] | None = None,
        id: str | None = None,
        started_at: datetime | None = None,
    ) -> ActionRecord:
        """Create an unfinished action at the execution boundary."""
        copied_arguments = copy_json_object(
            {} if arguments is None else arguments,
            "action arguments",
        )
        return cls(
            run_id=run_id,
            plan_node_id=plan_node_id,
            agent_id=agent_id,
            tool_name=tool_name,
            arguments=copied_arguments,
            id=new_id() if id is None else id,
            started_at=utc_now() if started_at is None else started_at,
        )

    @property
    def is_finished(self) -> bool:
        return self.finished_at is not None

    def finish(
        self,
        *,
        success: bool,
        duration_ms: int,
        error: str | None = None,
        exit_code: int | None = None,
        evidence_ids: tuple[str, ...] = (),
        finished_at: datetime | None = None,
    ) -> ActionRecord:
        """Return the immutable finished form of this action."""
        if self.is_finished:
            raise ValueError("an action can only be finished once")
        return replace(
            self,
            finished_at=utc_now() if finished_at is None else finished_at,
            duration_ms=duration_ms,
            success=success,
            exit_code=exit_code,
            error=error,
            evidence_ids=string_tuple(evidence_ids, "action evidence_ids"),
        )

    def add_evidence(self, *evidence_ids: str) -> ActionRecord:
        """Append evidence references to a finished record without duplicates."""
        if not self.is_finished:
            raise ValueError("evidence can only be linked after an action finishes")
        return replace(
            self,
            evidence_ids=merge_unique(self.evidence_ids, evidence_ids, "action evidence_ids"),
        )
