from __future__ import annotations

import asyncio
import json
import unittest
from collections import deque
from collections.abc import Mapping

from security_agent.contracts import (
    ActionDecision,
    Agent,
    EventType,
    LLMRequest,
    LLMResponse,
    Planner,
    RiskLevel,
    SkillDocument,
    SkillPolicy,
    SkillProvider,
    SkillResourceLoading,
    SkillRiskClass,
    SkillRole,
    ToolExecutionContext,
    ToolResult,
)
from security_agent.contracts.common import JSONValue
from security_agent.domain import (
    ActionRecord,
    CriterionAssessment,
    Evidence,
    EvidenceType,
    FindingDraft,
    FindingStatus,
    NodeStatus,
    Observation,
    Plan,
    PlanNode,
    RunStatus,
    ScopeSpec,
    Severity,
    TaskSpec,
    TaskType,
)
from security_agent.engine import (
    AgentRegistry,
    AgentRuntime,
    ContextBuilder,
    DeterministicPlanner,
    EvidenceVerifier,
    LocalSecurityAgent,
    RunLimits,
    StructuredLLMPlanner,
    StructuredLLMSecurityAgent,
    ToolExecutor,
    VersionedReplanner,
)
from security_agent.engine.context import _skill_context
from security_agent.engine.redaction import redact_json_object
from security_agent.infrastructure.events import EventBus, MemoryEventSink
from security_agent.infrastructure.llm import FakeLLMProvider
from security_agent.infrastructure.skills import NullKnowledgeProvider, NullSkillProvider
from security_agent.infrastructure.storage import SQLiteStore
from security_agent.infrastructure.tools import NetworkScanTool, ToolRegistry


class SequencedScanTool:
    name = "fixture_scan"
    description = "Return deterministic scan outcomes for runtime tests."
    capabilities = frozenset({"network.scan"})
    risk_level = RiskLevel.MEDIUM
    input_schema: Mapping[str, JSONValue] = {
        "type": "object",
        "properties": {
            "target": {"type": "string", "minLength": 1},
            "ports": {
                "type": "array",
                "items": {"type": "integer", "minimum": 1, "maximum": 65_535},
                "minItems": 1,
            },
        },
        "required": ["target", "ports"],
        "additionalProperties": False,
    }

    def __init__(self, outcomes: list[ToolResult] | None = None) -> None:
        self._outcomes = deque(outcomes or [])
        self.calls: list[dict[str, JSONValue]] = []

    async def execute(
        self,
        context: ToolExecutionContext,
        arguments: Mapping[str, JSONValue],
    ) -> ToolResult:
        del context
        self.calls.append(dict(arguments))
        await asyncio.sleep(0)
        if self._outcomes:
            return self._outcomes.popleft()
        target = arguments["target"]
        ports = arguments["ports"]
        assert isinstance(target, str)
        assert isinstance(ports, list)
        open_ports = [port for port in ports if isinstance(port, int)]
        open_ports_json: list[JSONValue] = list(open_ports)
        return ToolResult(
            success=True,
            output=json.dumps({"target": target, "open_ports": open_ports}),
            exit_code=0,
            metadata={
                "engine": "fixture",
                "target": target,
                "open_ports": open_ports_json,
            },
        )


class MissingPreferredToolAgent(LocalSecurityAgent):
    async def decide(self, context: object) -> ActionDecision:
        del context
        return ActionDecision(
            capability="network.scan",
            arguments={"target": "127.0.0.1", "ports": [41009]},
            rationale="Exercise the unavailable preferred-tool path.",
            preferred_tool="missing-tool",
        )


class HangingPlanner:
    async def generate_plan(
        self,
        task: TaskSpec,
        skills: tuple[object, ...] = (),
        knowledge: tuple[object, ...] = (),
    ) -> Plan:
        del task, skills, knowledge
        await asyncio.Event().wait()
        raise AssertionError("unreachable")


class CountingSkillProvider:
    def __init__(self, document: SkillDocument) -> None:
        self.document = document
        self.calls = 0

    async def select(self, task: TaskSpec) -> tuple[SkillDocument, ...]:
        del task
        self.calls += 1
        return (self.document,)


class EngineTests(unittest.IsolatedAsyncioTestCase):
    def test_nested_secrets_and_url_tokens_are_redacted(self) -> None:
        redacted = redact_json_object(
            {
                "headers": {
                    "Authorization": "Bearer secret",
                    "X-Api-Key": "key-value",
                    "Accept": "application/json",
                },
                "url": "https://example.invalid/path?access_token=secret&view=summary",
                "nested": {"password": "guess-me"},
            }
        )
        headers = redacted["headers"]
        assert isinstance(headers, dict)
        self.assertEqual("[REDACTED]", headers["Authorization"])
        self.assertEqual("[REDACTED]", headers["X-Api-Key"])
        self.assertEqual("application/json", headers["Accept"])
        safe_url = redacted["url"]
        assert isinstance(safe_url, str)
        self.assertNotIn("secret", safe_url)
        nested = redacted["nested"]
        assert isinstance(nested, dict)
        self.assertEqual("[REDACTED]", nested["password"])

    async def test_structured_planner_redacts_model_bound_task_inputs(self) -> None:
        provider = FakeLLMProvider(
            [
                json.dumps(
                    {
                        "nodes": [
                            {
                                "key": "scan",
                                "goal": "Inspect",
                                "description": "Inspect the scoped target.",
                                "required_capabilities": ["network.scan"],
                                "dependencies": [],
                                "success_criteria": ["Record evidence"],
                            }
                        ]
                    }
                )
            ]
        )
        task = TaskSpec.create(
            objective="Inspect",
            task_type=TaskType.PENTEST,
            scope=ScopeSpec(network_targets=("127.0.0.1",)),
            inputs={
                "target": "127.0.0.1",
                "Authorization": "Bearer do-not-send",
                "url": "https://user:password@example.invalid/?sig=do-not-send#token",
            },
            success_criteria=("Record evidence",),
        )
        skill_policy = SkillPolicy(
            group_id="test-router",
            enabled=True,
            task_types=(TaskType.PENTEST,),
            role=SkillRole.ROUTER,
            risk_class=SkillRiskClass.PASSIVE,
            required_capabilities=(),
            human_approval_required=False,
            resource_loading=SkillResourceLoading.LINKED_MARKDOWN,
        )
        skill = SkillDocument(
            name="test-router",
            description="Route the authorized test.",
            applicable_tasks=skill_policy.task_types,
            required_capabilities=skill_policy.required_capabilities,
            workflow_guidance="Use tool-produced evidence.",
            verification_guidance="Cite the exact evidence.",
            references=("https://example.invalid/reference",),
            policy=skill_policy,
            resources=("SCENARIOS.md",),
            content_hash="a" * 64,
        )
        await StructuredLLMPlanner(provider).generate_plan(task, (skill,))
        request_task = provider.requests[0].payload["task"]
        assert isinstance(request_task, dict)
        serialized = json.dumps(request_task)
        self.assertNotIn("do-not-send", serialized)
        self.assertNotIn("password", serialized)
        request_skills = provider.requests[0].payload["skills"]
        assert isinstance(request_skills, list)
        request_skill = request_skills[0]
        assert isinstance(request_skill, dict)
        trusted_policy = request_skill["trusted_policy"]
        assert isinstance(trusted_policy, dict)
        self.assertEqual("router", trusted_policy["role"])
        self.assertEqual("passive", trusted_policy["risk_class"])
        self.assertEqual("a" * 64, request_skill["content_hash"])
        self.assertEqual(["SCENARIOS.md"], request_skill["resources"])
        self.assertIn("frozen for this Run", provider.requests[0].system_prompt)
        self.assertIn("Never invent shell", provider.requests[0].system_prompt)

        rendered_skill = _skill_context(skill)
        self.assertIn("[Trusted runtime constraints]", rendered_skill)
        self.assertIn("Sibling Skill names are routing hints only", rendered_skill)
        self.assertIn("report the capability gap", rendered_skill)
        self.assertIn("[Untrusted Skill guidance", rendered_skill)

    async def test_tool_failure_creates_evidence_and_a_new_plan_version(self) -> None:
        tool = SequencedScanTool(
            [
                ToolResult(
                    success=False,
                    error="ToolUnavailable: temporary fixture failure",
                    metadata={"error_type": "ToolUnavailable"},
                ),
                ToolResult(
                    success=True,
                    output='{"open_ports":[41001]}',
                    exit_code=0,
                    metadata={
                        "engine": "fixture",
                        "target": "127.0.0.1",
                        "open_ports": [41001],
                    },
                ),
            ]
        )
        store, runtime, _ = await _build_runtime(tool=tool)
        try:
            state = await runtime.run(_scan_task("retry", 41001))
            self.assertEqual(RunStatus.COMPLETED, state.status)
            self.assertEqual(1, state.replan_count)
            self.assertEqual(2, len(state.evidence))
            self.assertEqual(2, len(await store.list_actions(state.run_id)))
            assert state.plan is not None
            self.assertEqual(2, state.plan.version)
            versions = await store.list_plan_versions(state.plan.id)
            self.assertEqual((1, 2), tuple(plan.version for plan in versions))
            self.assertEqual("superseded", versions[0].status.value)
            self.assertEqual("completed", versions[1].status.value)
        finally:
            await store.close()

    async def test_run_accepts_a_preallocated_run_identity(self) -> None:
        store, runtime, _events = await _build_runtime(tool=SequencedScanTool())
        try:
            state = await runtime.run(
                _scan_task("preallocated", 41013),
                run_id="run-preallocated",
            )

            self.assertEqual("run-preallocated", state.run_id)
            self.assertEqual(state, await store.get_run("run-preallocated"))
        finally:
            await store.close()

    async def test_run_freezes_one_skill_snapshot_and_emits_its_hash(self) -> None:
        skill = SkillDocument(
            name="fixture-guidance",
            description="Fixture guidance for an authorized local scan.",
            applicable_tasks=(TaskType.PENTEST,),
            required_capabilities=(),
            workflow_guidance="Preserve the complete tool result.",
            verification_guidance="Require tool-produced evidence.",
            content_hash="b" * 64,
        )
        skills = CountingSkillProvider(skill)
        store, runtime, events = await _build_runtime(
            tool=SequencedScanTool(),
            skill_provider=skills,
        )
        try:
            state = await runtime.run(_scan_task("skill-snapshot", 41011))
            self.assertEqual(RunStatus.COMPLETED, state.status)
            self.assertEqual(1, skills.calls)
            snapshots = [
                event for event in events.events if event.event_type is EventType.SKILLS_SELECTED
            ]
            self.assertEqual(1, len(snapshots))
            records = snapshots[0].payload["skills"]
            assert isinstance(records, list)
            record = records[0]
            assert isinstance(record, dict)
            self.assertEqual("fixture-guidance", record["name"])
            self.assertEqual("b" * 64, record["content_hash"])
        finally:
            await store.close()

    async def test_node_verifier_rejects_evidence_free_finding(self) -> None:
        store = SQLiteStore(":memory:")
        verifier = EvidenceVerifier(store)
        task = _scan_task("verify", 41002)
        node = PlanNode.create(
            id="node-verify",
            goal="Inspect",
            description="Inspect fixture",
            assigned_agent="local-security-agent",
            required_capabilities=("network.scan",),
            success_criteria=task.success_criteria,
        )
        plan = Plan.create(task_id=task.id, nodes=(node,)).activate(task)
        running = plan.get_node(node.id).transition(NodeStatus.RUNNING)
        action = ActionRecord.start(
            id="action-verify",
            run_id="run-verify",
            plan_node_id=node.id,
            agent_id="local-security-agent",
            tool_name="fixture_scan",
        ).finish(success=True, duration_ms=1, evidence_ids=("evidence-verify",))
        evidence = Evidence.create(
            id="evidence-verify",
            run_id="run-verify",
            action_id=action.id,
            type=EvidenceType.NETWORK_SCAN,
            source="tool:fixture_scan",
            summary="fixture output",
            raw_content="observed",
            metadata={"provenance": "tool_execution", "tool_success": True},
        )
        running = running.add_evidence(evidence.id)
        observation = Observation(
            summary="proposed",
            criterion_assessments=(
                CriterionAssessment(
                    criterion=task.success_criteria[0],
                    satisfied=True,
                    evidence_ids=(evidence.id,),
                    reason="fixture evidence",
                ),
            ),
            finding_drafts=(
                FindingDraft(
                    title="Unsupported claim",
                    description="No evidence reference",
                    severity=Severity.LOW,
                    confidence=0.2,
                ),
            ),
        )

        result = await verifier.verify_node("run-verify", running, action, evidence, observation)

        self.assertFalse(result.success)
        self.assertTrue(
            any("finding draft lacks evidence" in item for item in result.missing_requirements)
        )
        await store.close()

    async def test_fake_llm_drives_plan_action_and_evidence_assessment(self) -> None:
        criterion = "Record the observed service state"

        def observation_response(request: LLMRequest) -> LLMResponse:
            current = request.payload["current_evidence"]
            assert isinstance(current, dict)
            evidence_id = current["id"]
            return LLMResponse(
                content=json.dumps(
                    {
                        "summary": "The fixture output satisfies the exact criterion.",
                        "criterion_assessments": [
                            {
                                "criterion": criterion,
                                "satisfied": True,
                                "evidence_ids": [evidence_id],
                                "reason": "The cited tool evidence contains the observed port.",
                            }
                        ],
                        "finding_drafts": [
                            {
                                "title": "Fixture TCP service observed",
                                "description": "A deterministic local fixture reported an open port.",
                                "severity": "informational",
                                "confidence": 1.0,
                                "evidence_ids": [evidence_id],
                                "subject": "127.0.0.1:41003",
                            }
                        ],
                        "suggested_replan": False,
                    }
                )
            )

        provider = FakeLLMProvider(
            [
                json.dumps(
                    {
                        "nodes": [
                            {
                                "key": "discover",
                                "goal": "Discover the fixture",
                                "description": "Use a bounded scoped scan.",
                                "assigned_agent": "structured-llm-agent",
                                "required_capabilities": ["network.scan"],
                                "dependencies": [],
                                "success_criteria": [criterion],
                                "max_attempts": 2,
                            }
                        ]
                    }
                ),
                json.dumps(
                    {
                        "capability": "network.scan",
                        "arguments": {"target": "127.0.0.1", "ports": [41003]},
                        "rationale": "Probe the explicitly scoped fixture.",
                    }
                ),
                observation_response,
            ]
        )
        tool = SequencedScanTool()
        agent = StructuredLLMSecurityAgent(provider)
        store, runtime, _ = await _build_runtime(
            tool=tool,
            planner=StructuredLLMPlanner(provider),
            agent=agent,
        )
        task = TaskSpec.create(
            objective="Inspect the model-selected local fixture",
            task_type=TaskType.PENTEST,
            scope=ScopeSpec(network_targets=("127.0.0.1",)),
            inputs={"target": "127.0.0.1", "ports": [41003]},
            success_criteria=(criterion,),
        )
        try:
            state = await runtime.run(task)
            self.assertEqual(RunStatus.COMPLETED, state.status)
            self.assertEqual(1, len(state.findings))
            self.assertEqual(FindingStatus.UNVERIFIED, state.findings[0].status)
            self.assertEqual(
                ("generate_plan", "decide_action", "observe_evidence"),
                tuple(request.operation for request in provider.requests),
            )
            provider.assert_exhausted()
        finally:
            await store.close()

    async def test_concurrent_runs_keep_state_and_evidence_isolated(self) -> None:
        tool = SequencedScanTool()
        store, runtime, _ = await _build_runtime(tool=tool)
        try:
            first, second = await asyncio.gather(
                runtime.run(_scan_task("first", 41004)),
                runtime.run(_scan_task("second", 41005)),
            )
            self.assertEqual({RunStatus.COMPLETED}, {first.status, second.status})
            self.assertNotEqual(first.run_id, second.run_id)
            first_evidence = await store.list_evidence(first.run_id)
            second_evidence = await store.list_evidence(second.run_id)
            self.assertEqual({first.run_id}, {item.run_id for item in first_evidence})
            self.assertEqual({second.run_id}, {item.run_id for item in second_evidence})
            self.assertFalse(
                {item.id for item in first_evidence} & {item.id for item in second_evidence}
            )
        finally:
            await store.close()

    async def test_real_localhost_tcp_service_completes_end_to_end(self) -> None:
        server = await asyncio.start_server(lambda reader, writer: writer.close(), "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        tool = NetworkScanTool(nmap_locator=lambda _: None)
        store, runtime, events = await _build_runtime(tool=tool)
        try:
            state = await runtime.run(_scan_task("real", port))
            self.assertEqual(RunStatus.COMPLETED, state.status)
            self.assertEqual(1, len(state.findings))
            self.assertEqual(FindingStatus.VERIFIED, state.findings[0].status)
            tool_metadata = state.evidence[-1].metadata["tool_metadata"]
            assert isinstance(tool_metadata, dict)
            open_ports = tool_metadata["open_ports"]
            assert isinstance(open_ports, list)
            self.assertIn(port, open_ports)
            event_types = {event.event_type for event in events.events}
            self.assertIn(EventType.RUN_COMPLETED, event_types)
            self.assertIn(EventType.VERIFICATION_PASSED, event_types)
        finally:
            server.close()
            await server.wait_closed()
            await store.close()

    async def test_missing_preferred_tool_is_audited_before_run_failure(self) -> None:
        store, runtime, _events = await _build_runtime(
            tool=SequencedScanTool(),
            agent=MissingPreferredToolAgent(),
            limits=RunLimits(max_steps=2, max_replans=0, max_seconds=2.0),
        )
        try:
            state = await runtime.run(_scan_task("missing-tool", 41009))
            self.assertEqual(RunStatus.FAILED, state.status)
            actions = await store.list_actions(state.run_id)
            evidence = await store.list_evidence(state.run_id)
            self.assertEqual(1, len(actions))
            self.assertEqual(1, len(evidence))
            self.assertFalse(actions[0].success)
            self.assertIn("ToolSelectionError", actions[0].error or "")
        finally:
            await store.close()

    async def test_wall_clock_budget_cancels_a_hanging_planner(self) -> None:
        store, runtime, _events = await _build_runtime(
            tool=SequencedScanTool(),
            planner=HangingPlanner(),
            limits=RunLimits(max_steps=2, max_replans=0, max_seconds=0.05),
        )
        try:
            state = await runtime.run(_scan_task("timeout", 41010))
            self.assertEqual(RunStatus.FAILED, state.status)
            self.assertIn("wall-clock budget", state.last_error or "")
        finally:
            await store.close()


async def _build_runtime(
    *,
    tool: SequencedScanTool | NetworkScanTool,
    planner: Planner | None = None,
    agent: Agent | None = None,
    skill_provider: SkillProvider | None = None,
    limits: RunLimits | None = None,
) -> tuple[SQLiteStore, AgentRuntime, MemoryEventSink]:
    store = SQLiteStore(":memory:")
    await store.initialize()
    events = MemoryEventSink()
    event_bus = EventBus((store, events), strict=True)
    registry = ToolRegistry()
    registry.register(tool)
    agents = AgentRegistry()
    agents.register(agent or LocalSecurityAgent())
    skills = skill_provider or NullSkillProvider()
    knowledge = NullKnowledgeProvider()
    context = ContextBuilder(store, store, skills, knowledge)
    runtime = AgentRuntime(
        planner=planner or DeterministicPlanner(),
        dispatcher=agents,
        executor=ToolExecutor(registry, store, store, event_bus),
        context_builder=context,
        verifier=EvidenceVerifier(store),
        replanner=VersionedReplanner(),
        run_repository=store,
        event_sink=event_bus,
        skill_provider=skills,
        knowledge_provider=knowledge,
        limits=limits,
    )
    return store, runtime, events


def _scan_task(name: str, port: int) -> TaskSpec:
    return TaskSpec.create(
        objective=f"Inspect authorized local fixture {name}",
        task_type=TaskType.PENTEST,
        scope=ScopeSpec(network_targets=("127.0.0.1",)),
        inputs={"target": "127.0.0.1", "ports": [port]},
        success_criteria=("Record the observed service state",),
    )


if __name__ == "__main__":
    unittest.main()
