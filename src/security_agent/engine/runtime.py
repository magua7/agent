"""Verifier-gated, UI-independent agent loop."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

from security_agent.contracts import (
    AgentDispatcher,
    EventSink,
    EventType,
    KnowledgeProvider,
    Planner,
    Replanner,
    ReplanReason,
    RunEvent,
    RunRepository,
    SkillDocument,
    SkillProvider,
    Verifier,
)
from security_agent.contracts.common import JSONObject, JSONValue
from security_agent.domain import (
    FindingStatus,
    NodeStatus,
    Plan,
    PlanNode,
    PlanStatus,
    RunState,
    RunStatus,
    TaskSpec,
)
from security_agent.engine.context import ContextBuilder
from security_agent.engine.errors import (
    AgentDecisionError,
    PlanningError,
    RunBudgetExceeded,
    ToolSelectionError,
)
from security_agent.engine.executor import ToolExecutor


@dataclass(frozen=True, slots=True)
class RunLimits:
    max_steps: int = 20
    max_replans: int = 3
    max_seconds: float = 300.0

    def __post_init__(self) -> None:
        if self.max_steps <= 0 or self.max_replans < 0 or self.max_seconds <= 0:
            raise ValueError("run limits must be positive (max_replans may be zero)")


class AgentRuntime:
    def __init__(
        self,
        *,
        planner: Planner,
        dispatcher: AgentDispatcher,
        executor: ToolExecutor,
        context_builder: ContextBuilder,
        verifier: Verifier,
        replanner: Replanner,
        run_repository: RunRepository,
        event_sink: EventSink,
        skill_provider: SkillProvider,
        knowledge_provider: KnowledgeProvider,
        limits: RunLimits | None = None,
    ) -> None:
        self._planner = planner
        self._dispatcher = dispatcher
        self._executor = executor
        self._context = context_builder
        self._verifier = verifier
        self._replanner = replanner
        self._runs = run_repository
        self._events = event_sink
        self._skills = skill_provider
        self._knowledge = knowledge_provider
        self._limits = limits or RunLimits()

    async def run(self, task: TaskSpec, *, run_id: str | None = None) -> RunState:
        timed_out = asyncio.Event()
        execution = asyncio.create_task(self._run_task(task, timed_out, run_id))
        try:
            return await asyncio.wait_for(
                asyncio.shield(execution),
                timeout=self._limits.max_seconds,
            )
        except TimeoutError:
            timed_out.set()
            execution.cancel()
            return await execution
        except asyncio.CancelledError:
            execution.cancel()
            try:
                await asyncio.shield(execution)
            except asyncio.CancelledError:
                pass
            raise

    async def _run_task(
        self,
        task: TaskSpec,
        timed_out: asyncio.Event,
        run_id: str | None,
    ) -> RunState:
        state = RunState.create(task, run_id=run_id)
        started = time.monotonic()
        try:
            await self._runs.save_run(state)
            await self._emit(EventType.RUN_STARTED, state, {"task_id": task.id})
            state = state.transition(RunStatus.PLANNING)
            await self._runs.save_run(state)
            skills = await self._skills.select(task)
            await self._emit(
                EventType.SKILLS_SELECTED,
                state,
                _skill_snapshot_payload(skills),
            )
            knowledge = await self._knowledge.search(task.objective, 4)
            plan = await self._planner.generate_plan(task, skills, knowledge)
            plan = plan.activate(task)
            state = state.with_plan(plan).transition(RunStatus.RUNNING)
            await self._runs.save_plan(state.run_id, plan)
            await self._runs.save_run(state)
            await self._emit(
                EventType.PLAN_CREATED,
                state,
                {"plan_id": plan.id, "version": plan.version, "nodes": len(plan.nodes)},
            )

            while not state.is_terminal:
                self._check_time_budget(started)
                plan = _require_plan(state)
                refreshed = plan.refresh_readiness()
                if refreshed != plan:
                    state = state.with_plan(refreshed)
                    plan = refreshed
                    await self._runs.save_plan(state.run_id, plan)
                    await self._runs.save_run(state)

                if plan.ready_nodes:
                    self._check_step_budget(state)
                    state = await self._execute_node(state, plan.ready_nodes[0], skills)
                    continue

                state = state.with_current_nodes().transition(RunStatus.VERIFYING)
                await self._runs.save_run(state)
                await self._emit(EventType.VERIFICATION_STARTED, state, {"level": "run"})
                result = await self._verifier.verify_run(state)
                if result.success:
                    state = state.transition(RunStatus.COMPLETED, verification=result)
                    await self._runs.save_plan(state.run_id, _require_plan(state))
                    await self._runs.save_run(state)
                    await self._emit(
                        EventType.VERIFICATION_PASSED,
                        state,
                        {"level": "run", "evidence_ids": list(result.evidence_ids)},
                    )
                    await self._emit(
                        EventType.RUN_COMPLETED,
                        state,
                        {
                            "evidence_count": len(state.evidence),
                            "finding_count": len(state.findings),
                            "steps": state.step_count,
                        },
                    )
                    return state

                await self._emit(
                    EventType.VERIFICATION_FAILED,
                    state,
                    {
                        "level": "run",
                        "missing": list(result.missing_requirements),
                        "conflicts": list(result.conflicts),
                    },
                )
                failed = _last_failed_node(_require_plan(state))
                replanned = await self._try_replan(
                    state,
                    failed,
                    ReplanReason.VERIFICATION_REJECTED,
                )
                if replanned is None:
                    return await self._fail(state, result.reason)
                state = replanned

            return state
        except asyncio.CancelledError:
            latest = await self._runs.get_run(state.run_id)
            if timed_out.is_set():
                return await self._fail(
                    latest or state,
                    "run exhausted its wall-clock budget",
                )
            state = await self._cancel(latest or state)
            raise
        except (PlanningError, AgentDecisionError, ToolSelectionError, RunBudgetExceeded) as exc:
            latest = await self._runs.get_run(state.run_id)
            return await self._fail(latest or state, str(exc))
        except Exception as exc:
            # Adapters and model providers are replaceable trust boundaries.
            # Persist a coherent terminal state without leaking exception text.
            latest = await self._runs.get_run(state.run_id)
            return await self._fail(
                latest or state,
                f"unexpected runtime error: {type(exc).__name__}",
            )

    async def _execute_node(
        self,
        state: RunState,
        node: PlanNode,
        skills: tuple[SkillDocument, ...],
    ) -> RunState:
        running_node = node.transition(NodeStatus.RUNNING)
        plan = _require_plan(state).replace_node(running_node)
        state = state.with_plan(plan).with_current_nodes(running_node.id).increment_step()
        await self._runs.save_plan(state.run_id, plan)
        await self._runs.save_run(state)
        await self._emit(
            EventType.NODE_STARTED,
            state,
            {"node_id": running_node.id, "attempt": running_node.attempt_count},
        )
        agent = self._dispatcher.dispatch(running_node)
        context = await self._context.build(
            run_id=state.run_id,
            task=state.task,
            plan=plan,
            node=running_node,
            skills=skills,
        )
        await self._emit(
            EventType.AGENT_THINKING,
            state,
            {"node_id": running_node.id, "agent_id": agent.id},
        )
        decision = await agent.decide(context)
        outcome = await self._executor.execute(
            run_id=state.run_id,
            task_id=state.task.id,
            plan_node_id=running_node.id,
            agent_id=agent.id,
            scope=state.task.scope,
            decision=decision,
        )
        state = state.add_evidence(outcome.evidence)
        running_node = running_node.add_evidence(outcome.evidence.id)
        plan = plan.replace_node(running_node)
        state = state.with_plan(plan)
        await self._runs.save_plan(state.run_id, plan)
        await self._runs.save_run(state)

        post_context = await self._context.build(
            run_id=state.run_id,
            task=state.task,
            plan=plan,
            node=running_node,
            skills=skills,
        )
        observation = await agent.observe(
            post_context,
            outcome.action,
            self._context.preview(outcome.evidence),
        )
        await self._emit(
            EventType.VERIFICATION_STARTED,
            state,
            {"level": "node", "node_id": running_node.id},
        )
        verification = await self._verifier.verify_node(
            state.run_id,
            running_node,
            outcome.action,
            outcome.evidence,
            observation,
        )
        if verification.success:
            for draft in observation.finding_drafts:
                finding_verification = await self._verifier.verify_finding(
                    state.run_id,
                    running_node,
                    outcome.action,
                    outcome.evidence,
                    draft,
                )
                finding = draft.to_finding(
                    state.run_id,
                    status=FindingStatus.UNVERIFIED,
                )
                if finding_verification.success:
                    finding = finding.verify()
                if any(
                    existing.fingerprint == finding.fingerprint
                    and existing.description == finding.description
                    for existing in state.findings
                ):
                    continue
                state = state.add_finding(finding)
                running_node = running_node.add_findings(finding.id)
                await self._runs.save_finding(finding)
                await self._emit(
                    EventType.FINDING_CREATED,
                    state,
                    {
                        "finding_id": finding.id,
                        "node_id": running_node.id,
                        "severity": finding.severity.value,
                        "status": finding.status.value,
                        "evidence_ids": list(finding.evidence_ids),
                    },
                )
            running_node = running_node.transition(
                NodeStatus.SUCCEEDED,
                verification=verification,
            )
            plan = plan.replace_node(running_node)
            state = state.with_plan(plan).with_current_nodes()
            await self._runs.save_plan(state.run_id, plan)
            await self._runs.save_run(state)
            await self._emit(
                EventType.VERIFICATION_PASSED,
                state,
                {"level": "node", "node_id": running_node.id},
            )
            await self._emit(
                EventType.NODE_COMPLETED,
                state,
                {
                    "node_id": running_node.id,
                    "evidence_ids": list(running_node.evidence_ids),
                },
            )
            return state

        failed_node = running_node.transition(NodeStatus.FAILED)
        plan = plan.replace_node(failed_node)
        state = state.with_plan(plan).with_current_nodes()
        await self._runs.save_plan(state.run_id, plan)
        await self._runs.save_run(state)
        await self._emit(
            EventType.VERIFICATION_FAILED,
            state,
            {
                "level": "node",
                "node_id": failed_node.id,
                "missing": list(verification.missing_requirements),
            },
        )
        await self._emit(
            EventType.NODE_FAILED,
            state,
            {"node_id": failed_node.id, "error": outcome.action.error},
        )
        reason = (
            ReplanReason.TOOL_UNAVAILABLE
            if outcome.action.error
            and any(
                marker in outcome.action.error.casefold()
                for marker in ("unavailable", "toolselectionerror")
            )
            else ReplanReason.TOOL_FAILURE
            if outcome.action.success is False
            else ReplanReason.VERIFICATION_REJECTED
        )
        replanned = await self._try_replan(state, failed_node, reason)
        if replanned is None:
            return await self._fail(state, verification.reason)
        return replanned

    async def _try_replan(
        self,
        state: RunState,
        failed_node: PlanNode | None,
        reason: ReplanReason,
    ) -> RunState | None:
        if state.replan_count >= self._limits.max_replans:
            return None
        current = _require_plan(state)
        revised = await self._replanner.replan(state.task, current, failed_node, reason)
        if revised is None:
            return None
        if revised.id != current.id or revised.version != current.version + 1:
            raise PlanningError("replanner must preserve plan id and increment one version")
        revised.validate_for_task(state.task)
        if revised.status is not PlanStatus.ACTIVE:
            raise PlanningError("replanner must return an active plan")
        superseded = current.transition(PlanStatus.SUPERSEDED)
        await self._runs.save_plan(state.run_id, superseded)
        state = state.transition(RunStatus.PLANNING).with_plan(revised)
        state = state.transition(RunStatus.RUNNING)
        await self._runs.save_plan(state.run_id, revised)
        await self._runs.save_run(state)
        await self._emit(
            EventType.PLAN_UPDATED,
            state,
            {
                "plan_id": revised.id,
                "version": revised.version,
                "reason": reason.value,
            },
        )
        return state

    def _check_step_budget(self, state: RunState) -> None:
        if state.step_count >= self._limits.max_steps:
            raise RunBudgetExceeded("run exhausted its step budget")

    def _check_time_budget(self, started: float) -> None:
        if time.monotonic() - started >= self._limits.max_seconds:
            raise RunBudgetExceeded("run exhausted its wall-clock budget")

    async def _fail(self, state: RunState, error: str) -> RunState:
        if state.is_terminal:
            return state
        state = state.with_current_nodes()
        if state.plan is not None and state.plan.status in {
            PlanStatus.DRAFT,
            PlanStatus.ACTIVE,
        }:
            failed_plan = _terminalize_plan(state.plan, cancelled=False)
            state = state.with_plan(failed_plan)
            await self._runs.save_plan(state.run_id, failed_plan)
        state = state.transition(RunStatus.FAILED, error=error or "run failed")
        await self._runs.save_run(state)
        await self._emit(EventType.RUN_FAILED, state, {"error": state.last_error})
        return state

    async def _cancel(self, state: RunState) -> RunState:
        if state.is_terminal:
            return state
        state = state.with_current_nodes()
        if state.plan is not None and state.plan.status in {
            PlanStatus.DRAFT,
            PlanStatus.ACTIVE,
        }:
            cancelled_plan = _terminalize_plan(state.plan, cancelled=True)
            state = state.with_plan(cancelled_plan)
            await self._runs.save_plan(state.run_id, cancelled_plan)
        state = state.transition(RunStatus.CANCELLED)
        await self._runs.save_run(state)
        return state

    async def _emit(
        self,
        event_type: EventType,
        state: RunState,
        payload: JSONObject,
    ) -> None:
        await self._events.publish(RunEvent(event_type, state.run_id, payload))


def _skill_snapshot_payload(skills: tuple[SkillDocument, ...]) -> JSONObject:
    records: list[JSONValue] = []
    for skill in skills:
        policy = skill.policy
        policy_payload: JSONObject | None = None
        if policy is not None:
            capabilities: list[JSONValue] = []
            capabilities.extend(policy.required_capabilities)
            policy_payload = {
                "group": policy.group_id,
                "role": policy.role.value,
                "risk_class": policy.risk_class.value,
                "human_approval_required": policy.human_approval_required,
                "required_capabilities": capabilities,
            }
        records.append(
            {
                "name": skill.name,
                "content_hash": skill.content_hash,
                "policy": policy_payload,
            }
        )
    return {"skills": records}


def _require_plan(state: RunState) -> Plan:
    if state.plan is None:
        raise PlanningError("run has no plan")
    return state.plan


def _last_failed_node(plan: Plan) -> PlanNode | None:
    failed = [node for node in plan.nodes if node.status in {NodeStatus.FAILED, NodeStatus.BLOCKED}]
    return failed[-1] if failed else None


def _terminalize_plan(plan: Plan, *, cancelled: bool) -> Plan:
    updated = plan
    for node in plan.nodes:
        target: NodeStatus | None = None
        if cancelled and node.status not in {NodeStatus.SUCCEEDED, NodeStatus.CANCELLED}:
            target = NodeStatus.CANCELLED
        elif not cancelled:
            if node.status is NodeStatus.RUNNING:
                target = NodeStatus.FAILED
            elif node.status in {NodeStatus.PENDING, NodeStatus.READY, NodeStatus.BLOCKED}:
                target = NodeStatus.CANCELLED
        if target is not None and target is not node.status:
            updated = updated.replace_node(node.transition(target))
    return updated.transition(PlanStatus.CANCELLED if cancelled else PlanStatus.FAILED)
