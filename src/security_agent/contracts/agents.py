"""Agent decision boundary."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol

from security_agent.contracts.common import JSONValue, is_json_value
from security_agent.domain import (
    ActionRecord,
    EvidencePreview,
    Finding,
    Observation,
    Plan,
    PlanNode,
    TaskSpec,
)


@dataclass(frozen=True, slots=True)
class AgentContext:
    task: TaskSpec
    plan: Plan
    node: PlanNode
    evidence: tuple[EvidencePreview, ...] = ()
    findings: tuple[Finding, ...] = ()
    recent_actions: tuple[ActionRecord, ...] = ()
    skills: tuple[str, ...] = ()
    knowledge: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ActionDecision:
    capability: str
    arguments: Mapping[str, JSONValue]
    rationale: str
    preferred_tool: str | None = None

    def __post_init__(self) -> None:
        if not self.capability.strip():
            raise ValueError("decision capability must be non-empty")
        if not self.rationale.strip():
            raise ValueError("decision rationale must be non-empty")
        if not is_json_value(dict(self.arguments)):
            raise ValueError("decision arguments must be finite JSON values")


class Agent(Protocol):
    @property
    def id(self) -> str: ...

    @property
    def capabilities(self) -> frozenset[str]: ...

    async def decide(self, context: AgentContext) -> ActionDecision: ...

    async def observe(
        self,
        context: AgentContext,
        action: ActionRecord,
        evidence: EvidencePreview,
    ) -> Observation: ...


class AgentDispatcher(Protocol):
    def dispatch(self, node: PlanNode) -> Agent: ...
