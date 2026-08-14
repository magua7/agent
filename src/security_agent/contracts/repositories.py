"""Persistence ports."""

from __future__ import annotations

from typing import Protocol

from security_agent.domain import ActionRecord, Evidence, Finding, Plan, RunState


class EvidenceRepository(Protocol):
    async def save_evidence(self, evidence: Evidence) -> None: ...

    async def get_evidence(self, evidence_id: str) -> Evidence | None: ...

    async def list_evidence(self, run_id: str) -> tuple[Evidence, ...]: ...

    async def search_evidence(
        self,
        run_id: str,
        query: str,
        limit: int = 20,
    ) -> tuple[Evidence, ...]: ...


class RunRepository(Protocol):
    async def save_run(self, run: RunState) -> None: ...

    async def get_run(self, run_id: str) -> RunState | None: ...

    async def save_plan(self, run_id: str, plan: Plan) -> None: ...

    async def get_plan(self, plan_id: str, version: int | None = None) -> Plan | None: ...

    async def list_plan_versions(self, plan_id: str) -> tuple[Plan, ...]: ...

    async def save_action(self, action: ActionRecord) -> None: ...

    async def get_action(self, action_id: str) -> ActionRecord | None: ...

    async def list_actions(
        self,
        run_id: str,
        plan_node_id: str | None = None,
    ) -> tuple[ActionRecord, ...]: ...

    async def save_finding(self, finding: Finding) -> None: ...

    async def list_findings(self, run_id: str) -> tuple[Finding, ...]: ...
