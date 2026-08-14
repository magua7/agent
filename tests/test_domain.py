from __future__ import annotations

import hashlib
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from itertools import pairwise
from pathlib import Path

from security_agent.domain import (
    ActionRecord,
    CriterionAssessment,
    Evidence,
    EvidenceType,
    Finding,
    FindingDraft,
    FindingStatus,
    NodeStatus,
    Observation,
    Plan,
    PlanNode,
    PlanStatus,
    RunState,
    RunStatus,
    ScopeSpec,
    Severity,
    TaskSpec,
    TaskType,
    VerificationResult,
    utc_now,
)


def make_task(*, task_id: str = "task-1", criterion: str = "services recorded") -> TaskSpec:
    return TaskSpec.create(
        id=task_id,
        objective="Inspect explicitly authorized localhost services",
        task_type=TaskType.PENTEST,
        scope=ScopeSpec(network_targets=("127.0.0.1",)),
        success_criteria=(criterion,),
    )


def make_node(
    *,
    node_id: str = "node-1",
    criterion: str = "services recorded",
    dependencies: tuple[str, ...] = (),
    max_attempts: int = 2,
) -> PlanNode:
    return PlanNode.create(
        id=node_id,
        goal="Discover services",
        description="Perform a bounded scan and preserve its result",
        assigned_agent="security-agent",
        required_capabilities=("network.scan",),
        dependencies=dependencies,
        success_criteria=(criterion,),
        max_attempts=max_attempts,
    )


class TaskDomainTests(unittest.TestCase):
    def test_task_copies_inputs_and_uses_utc(self) -> None:
        inputs: dict[str, object] = {"ports": [80, 443]}
        task = TaskSpec.create(
            objective="Scan localhost",
            task_type=TaskType.PENTEST,
            scope=ScopeSpec(network_targets=("127.0.0.1",)),
            success_criteria=("output captured",),
            inputs=inputs,
        )
        ports = inputs["ports"]
        assert isinstance(ports, list)
        ports.append(8080)

        self.assertEqual(task.inputs, {"ports": [80, 443]})
        self.assertEqual(task.created_at.utcoffset(), timedelta(0))

    def test_task_rejects_blank_or_duplicate_criteria(self) -> None:
        with self.assertRaises(ValueError):
            TaskSpec.create(
                objective=" ",
                task_type=TaskType.GENERIC,
                scope=ScopeSpec(),
                success_criteria=("done",),
            )
        with self.assertRaises(ValueError):
            TaskSpec.create(
                objective="Do work",
                task_type=TaskType.GENERIC,
                scope=ScopeSpec(),
                success_criteria=("done", "done"),
            )

    def test_task_rejects_naive_timestamp_and_non_json_inputs(self) -> None:
        with self.assertRaises(ValueError):
            TaskSpec(
                objective="Do work",
                task_type=TaskType.GENERIC,
                scope=ScopeSpec(),
                success_criteria=("done",),
                created_at=datetime.now(),
            )
        with self.assertRaises(ValueError):
            TaskSpec.create(
                objective="Do work",
                task_type=TaskType.GENERIC,
                scope=ScopeSpec(),
                success_criteria=("done",),
                inputs={"bad": object()},
            )

    def test_task_rejects_unbounded_structured_inputs(self) -> None:
        with self.assertRaisesRegex(ValueError, "encoded bytes"):
            TaskSpec.create(
                objective="Do work",
                task_type=TaskType.GENERIC,
                scope=ScopeSpec(),
                success_criteria=("done",),
                inputs={"oversize": "x" * TaskSpec.MAX_INPUT_BYTES},
            )

    def test_scope_requires_absolute_file_roots(self) -> None:
        with self.assertRaises(ValueError):
            ScopeSpec(file_roots=("relative/path",))
        with tempfile.TemporaryDirectory() as directory:
            scope = ScopeSpec(file_roots=(str(Path(directory).resolve()),))
        self.assertFalse(scope.is_empty)


class PlanDomainTests(unittest.TestCase):
    def test_plan_rejects_missing_dependency_and_cycles(self) -> None:
        with self.assertRaisesRegex(ValueError, "missing dependencies"):
            Plan.create(
                task_id="task-1",
                nodes=(make_node(dependencies=("unknown",)),),
            )

        first = make_node(node_id="first", dependencies=("second",))
        second = make_node(node_id="second", dependencies=("first",))
        with self.assertRaisesRegex(ValueError, "acyclic"):
            Plan.create(task_id="task-1", nodes=(first, second))

    def test_activation_checks_criterion_coverage_and_marks_roots_ready(self) -> None:
        task = make_task()
        plan = Plan.create(task_id=task.id, nodes=(make_node(),))

        active = plan.activate(task)

        self.assertEqual(plan.status, PlanStatus.DRAFT)
        self.assertEqual(active.status, PlanStatus.ACTIVE)
        self.assertEqual(active.nodes[0].status, NodeStatus.READY)
        with self.assertRaisesRegex(ValueError, "does not cover"):
            plan.activate(("a different criterion",))

    def test_readiness_requires_all_dependencies_to_succeed(self) -> None:
        task = make_task()
        parent = make_node(node_id="parent")
        child = make_node(node_id="child", dependencies=(parent.id,))
        plan = Plan.create(task_id=task.id, nodes=(parent, child)).activate(task)
        self.assertEqual(tuple(node.id for node in plan.ready_nodes), (parent.id,))

        parent = plan.get_node(parent.id).transition(NodeStatus.RUNNING)
        parent = parent.add_evidence("evidence-1")
        verification = VerificationResult.accepted("real output accepted", ("evidence-1",))
        parent = parent.transition(NodeStatus.SUCCEEDED, verification=verification)
        plan = plan.replace_node(parent).refresh_readiness()

        self.assertEqual(plan.get_node(child.id).status, NodeStatus.READY)

    def test_plan_rejects_manually_readied_node_with_unfinished_dependency(self) -> None:
        parent = make_node(node_id="parent")
        child = make_node(node_id="child", dependencies=(parent.id,)).transition(NodeStatus.READY)
        with self.assertRaisesRegex(ValueError, "before its dependencies succeed"):
            Plan.create(task_id="task-1", nodes=(parent, child))

    def test_node_transition_is_verifier_gated_and_counts_attempts_once(self) -> None:
        node = make_node().transition(NodeStatus.READY)
        running = node.transition(NodeStatus.RUNNING)
        self.assertEqual(running.attempt_count, 1)
        with self.assertRaisesRegex(ValueError, "VerificationResult"):
            running.transition(NodeStatus.SUCCEEDED)
        running = running.add_evidence("evidence-1", "evidence-1")
        with self.assertRaisesRegex(ValueError, "successful"):
            running.transition(
                NodeStatus.SUCCEEDED,
                verification=VerificationResult.rejected("not enough evidence"),
            )

        succeeded = running.transition(
            NodeStatus.SUCCEEDED,
            verification=VerificationResult.accepted("accepted", ("evidence-1",)),
        )
        self.assertEqual(succeeded.evidence_ids, ("evidence-1",))
        with self.assertRaises(ValueError):
            succeeded.transition(NodeStatus.READY)

    def test_exhausted_failed_node_cannot_retry(self) -> None:
        node = make_node(max_attempts=1).transition(NodeStatus.READY)
        node = node.transition(NodeStatus.RUNNING).transition(NodeStatus.FAILED)
        with self.assertRaisesRegex(ValueError, "exhausted"):
            node.transition(NodeStatus.READY)

    def test_revision_retains_id_and_history(self) -> None:
        plan = Plan.create(task_id="task-1", nodes=(make_node(),))
        revision = plan.revise((make_node(node_id="replacement"),))
        self.assertEqual(revision.id, plan.id)
        self.assertEqual(revision.version, plan.version + 1)
        self.assertEqual(plan.version, 1)


class EvidenceActionFindingTests(unittest.TestCase):
    def test_action_lifecycle_and_argument_copy(self) -> None:
        arguments: dict[str, object] = {"target": "127.0.0.1", "ports": [80]}
        started = datetime(2026, 1, 1, tzinfo=UTC)
        action = ActionRecord.start(
            run_id="run-1",
            plan_node_id="node-1",
            agent_id="agent-1",
            tool_name="network_scan",
            arguments=arguments,
            started_at=started,
        )
        ports = arguments["ports"]
        assert isinstance(ports, list)
        ports.append(443)
        self.assertEqual(action.arguments["ports"], [80])

        finished = action.finish(
            success=True,
            duration_ms=12,
            exit_code=0,
            evidence_ids=("evidence-1",),
            finished_at=started + timedelta(milliseconds=12),
        )
        self.assertTrue(finished.success)
        self.assertTrue(finished.is_finished)
        self.assertFalse(action.is_finished)
        with self.assertRaises(ValueError):
            finished.finish(success=True, duration_ms=1)

    def test_failed_action_requires_error(self) -> None:
        action = ActionRecord.start(
            run_id="run-1",
            plan_node_id="node-1",
            agent_id="agent-1",
            tool_name="network_scan",
        )
        with self.assertRaisesRegex(ValueError, "failed actions"):
            action.finish(success=False, duration_ms=0)

    def test_evidence_hash_is_computed_and_corruption_fails_closed(self) -> None:
        raw = "127.0.0.1:8080 open\n"
        evidence = Evidence.create(
            run_id="run-1",
            action_id="action-1",
            type=EvidenceType.NETWORK_SCAN,
            source="tool:network_scan",
            summary="One open service",
            raw_content=raw,
            metadata={"engine": "tcp-connect"},
        )
        self.assertEqual(evidence.content_hash, hashlib.sha256(raw.encode()).hexdigest())
        self.assertTrue(evidence.verify_hash())
        preview = evidence.preview(max_chars=4)
        self.assertEqual(preview.content_preview, raw[:4])

        object.__setattr__(evidence, "raw_content", "tampered")
        self.assertFalse(evidence.verify_hash())
        with self.assertRaisesRegex(ValueError, "integrity"):
            evidence.assert_integrity()

    def test_evidence_rejects_wrong_hash_and_non_tool_provenance(self) -> None:
        with self.assertRaisesRegex(ValueError, "content_hash"):
            Evidence(
                run_id="run-1",
                action_id="action-1",
                type=EvidenceType.TOOL_OUTPUT,
                source="tool:test",
                summary="output",
                raw_content="raw",
                content_hash="0" * 64,
            )
        with self.assertRaisesRegex(ValueError, "tool:"):
            Evidence.create(
                run_id="run-1",
                action_id="action-1",
                type=EvidenceType.TOOL_OUTPUT,
                source="agent:test",
                summary="output",
                raw_content="raw",
            )

    def test_verified_finding_requires_evidence(self) -> None:
        with self.assertRaisesRegex(ValueError, "must reference evidence"):
            Finding.create(
                run_id="run-1",
                title="Open service",
                description="A service is listening",
                severity=Severity.INFORMATIONAL,
                confidence=1.0,
                status=FindingStatus.VERIFIED,
            )

        draft = FindingDraft(
            title="Open service",
            description="A service is listening",
            severity=Severity.INFORMATIONAL,
            confidence=0.9,
        )
        verified = draft.to_finding("run-1").verify("evidence-1")
        self.assertEqual(verified.status, FindingStatus.VERIFIED)
        self.assertEqual(verified.evidence_ids, ("evidence-1",))


class ObservationTests(unittest.TestCase):
    def test_observation_rejects_duplicate_criterion_assessments(self) -> None:
        assessment = CriterionAssessment(
            criterion="output captured",
            satisfied=True,
            evidence_ids=("evidence-1",),
            reason="scanner output is present",
        )
        with self.assertRaisesRegex(ValueError, "unique criteria"):
            Observation(
                summary="done",
                criterion_assessments=(assessment, assessment),
            )


class RunStateTests(unittest.TestCase):
    def make_completed_inputs(self) -> tuple[RunState, Evidence, VerificationResult]:
        task = make_task()
        node = make_node()
        plan = Plan.create(task_id=task.id, nodes=(node,)).activate(task)
        run = RunState.create(task, plan, run_id="run-1")
        run = run.transition(RunStatus.PLANNING).transition(RunStatus.RUNNING)

        evidence = Evidence.create(
            id="evidence-1",
            run_id=run.run_id,
            action_id="action-1",
            type=EvidenceType.NETWORK_SCAN,
            source="tool:network_scan",
            summary="One open service",
            raw_content="127.0.0.1:8080 open",
        )
        node = plan.nodes[0].transition(NodeStatus.RUNNING)
        node = node.add_evidence(evidence.id)
        result = VerificationResult.accepted("criteria covered", (evidence.id,))
        node = node.transition(NodeStatus.SUCCEEDED, verification=result)
        plan = plan.replace_node(node)
        run = run.add_evidence(evidence).with_plan(plan)
        return run, evidence, result

    def test_run_completion_is_reachable_only_via_verifying(self) -> None:
        run, _, result = self.make_completed_inputs()
        with self.assertRaisesRegex(ValueError, "invalid run transition"):
            run.transition(RunStatus.COMPLETED, verification=result)

        verifying = run.transition(RunStatus.VERIFYING)
        with self.assertRaisesRegex(ValueError, "successful"):
            verifying.transition(
                RunStatus.COMPLETED,
                verification=VerificationResult.rejected("rejected"),
            )
        completed = verifying.transition(RunStatus.COMPLETED, verification=result)
        self.assertEqual(completed.status, RunStatus.COMPLETED)
        completed_plan = completed.plan
        self.assertIsNotNone(completed_plan)
        assert completed_plan is not None
        self.assertEqual(completed_plan.status, PlanStatus.COMPLETED)
        self.assertIsNotNone(completed.finished_at)

    def test_verified_finding_requires_same_run_action_evidence(self) -> None:
        run, evidence, _ = self.make_completed_inputs()
        finding = Finding.create(
            run_id=run.run_id,
            title="Open service",
            description="Port 8080 is accepting TCP connections",
            severity=Severity.INFORMATIONAL,
            confidence=1.0,
            evidence_ids=(evidence.id,),
            status=FindingStatus.VERIFIED,
            subject="127.0.0.1:8080",
        )
        run = run.add_finding(finding)
        self.assertEqual(run.findings, (finding,))

        dangling = Finding.create(
            run_id=run.run_id,
            title="Other",
            description="No backing record",
            severity=Severity.LOW,
            confidence=0.5,
            evidence_ids=("missing",),
            status=FindingStatus.VERIFIED,
        )
        with self.assertRaisesRegex(ValueError, "dangling"):
            run.add_finding(dangling)

    def test_run_rejects_cross_run_evidence(self) -> None:
        run = RunState.create(make_task(), run_id="run-1")
        evidence = Evidence.create(
            run_id="run-2",
            action_id="action-1",
            type=EvidenceType.TOOL_OUTPUT,
            source="tool:test",
            summary="output",
            raw_content="raw",
        )
        with self.assertRaisesRegex(ValueError, "different run"):
            run.add_evidence(evidence)

    def test_failed_run_records_error_and_terminal_timestamp(self) -> None:
        run = RunState.create(make_task()).transition(RunStatus.PLANNING)
        failed = run.transition(RunStatus.FAILED, error="planner unavailable")
        self.assertEqual(failed.last_error, "planner unavailable")
        self.assertTrue(failed.is_terminal)
        self.assertIsNotNone(failed.finished_at)


class FactoryTests(unittest.TestCase):
    def test_domain_clock_is_strictly_increasing_inside_one_process(self) -> None:
        timestamps = [utc_now() for _ in range(1_000)]

        self.assertTrue(all(left < right for left, right in pairwise(timestamps)))

    def test_utc_now_is_aware_utc(self) -> None:
        self.assertEqual(utc_now().utcoffset(), timedelta(0))


if __name__ == "__main__":
    unittest.main()
