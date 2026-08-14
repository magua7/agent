"""Run event contract."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Protocol

from security_agent.contracts.common import JSONObject, is_json_value
from security_agent.domain import new_id, utc_now


class EventType(StrEnum):
    RUN_STARTED = "run_started"
    SKILLS_SELECTED = "skills_selected"
    PLAN_CREATED = "plan_created"
    PLAN_UPDATED = "plan_updated"
    NODE_STARTED = "node_started"
    NODE_COMPLETED = "node_completed"
    NODE_FAILED = "node_failed"
    AGENT_THINKING = "agent_thinking"
    TOOL_STARTED = "tool_started"
    TOOL_COMPLETED = "tool_completed"
    TOOL_FAILED = "tool_failed"
    EVIDENCE_CREATED = "evidence_created"
    FINDING_CREATED = "finding_created"
    VERIFICATION_STARTED = "verification_started"
    VERIFICATION_FAILED = "verification_failed"
    VERIFICATION_PASSED = "verification_passed"
    RUN_COMPLETED = "run_completed"
    RUN_FAILED = "run_failed"


@dataclass(frozen=True, slots=True)
class RunEvent:
    event_type: EventType
    run_id: str
    payload: JSONObject = field(default_factory=dict)
    id: str = field(default_factory=new_id)
    created_at: datetime = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        if not self.run_id:
            raise ValueError("event run_id must be non-empty")
        if not is_json_value(self.payload):
            raise ValueError("event payload must be a finite JSON object")


class EventSink(Protocol):
    async def publish(self, event: RunEvent) -> None: ...
