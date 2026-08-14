"""Planning and verification strategy ports."""

from __future__ import annotations

from enum import StrEnum
from typing import Protocol

from security_agent.contracts.skills import KnowledgeDocument, SkillDocument
from security_agent.domain import (
    ActionRecord,
    Evidence,
    FindingDraft,
    Observation,
    Plan,
    PlanNode,
    RunState,
    TaskSpec,
    VerificationResult,
)


class ReplanReason(StrEnum):
    TOOL_FAILURE = "tool_failure"
    TOOL_UNAVAILABLE = "tool_unavailable"
    NO_EVIDENCE = "no_evidence"
    DUPLICATE_ACTION = "duplicate_action"
    MAX_ATTEMPTS = "max_attempts"
    VERIFICATION_REJECTED = "verification_rejected"


class Planner(Protocol):
    async def generate_plan(
        self,
        task: TaskSpec,
        skills: tuple[SkillDocument, ...] = (),
        knowledge: tuple[KnowledgeDocument, ...] = (),
    ) -> Plan: ...


class Replanner(Protocol):
    async def replan(
        self,
        task: TaskSpec,
        plan: Plan,
        failed_node: PlanNode | None,
        reason: ReplanReason,
    ) -> Plan | None: ...


class Verifier(Protocol):
    async def verify_node(
        self,
        run_id: str,
        node: PlanNode,
        action: ActionRecord,
        evidence: Evidence,
        observation: Observation,
    ) -> VerificationResult: ...

    async def verify_finding(
        self,
        run_id: str,
        node: PlanNode,
        action: ActionRecord,
        evidence: Evidence,
        draft: FindingDraft,
    ) -> VerificationResult: ...

    async def verify_run(self, state: RunState) -> VerificationResult: ...
