from __future__ import annotations

import sqlite3
import tempfile
import unittest
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path

from security_agent.contracts import EventType, RunEvent
from security_agent.domain import (
    ActionRecord,
    Evidence,
    EvidenceType,
    Finding,
    FindingStatus,
    Plan,
    PlanNode,
    PlanStatus,
    RunState,
    RunStatus,
    ScopeSpec,
    Severity,
    TaskSpec,
    TaskType,
)
from security_agent.infrastructure.storage import (
    CorruptEvidenceError,
    SQLiteStore,
    StalePlanWriteError,
    StaleRunWriteError,
    StorageReferenceError,
)


class SQLiteStoreTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.database = Path(self.temporary.name) / "agent.sqlite3"
        self.store = SQLiteStore(self.database)
        await self.store.initialize()

    async def asyncTearDown(self) -> None:
        await self.store.close()
        self.temporary.cleanup()

    async def test_run_round_trip_preserves_nested_task_json_and_utc(self) -> None:
        task = _task("task-round-trip")
        run = RunState.create(task, run_id="run-round-trip", started_at=_time())

        await self.store.save_run(run)

        loaded = await self.store.get_run(run.run_id)
        self.assertEqual(run, loaded)
        self.assertIsNone(await self.store.get_run("missing-run"))

    async def test_ctf_task_type_round_trips_through_sqlite(self) -> None:
        task = _task("task-ctf", task_type=TaskType.CTF)
        run = RunState.create(task, run_id="run-ctf", started_at=_time())

        await self.store.save_run(run)

        loaded = await self.store.get_run(run.run_id)
        assert loaded is not None
        self.assertEqual(TaskType.CTF, loaded.task.task_type)

    async def test_raw_evidence_is_not_truncated_and_hash_is_checked_on_read(self) -> None:
        run = RunState.create(_task("task-raw"), run_id="run-raw", started_at=_time())
        await self.store.save_run(run)
        raw_content = "扫描输出🙂\n" + ("service-banner\n" * 25_000) + "END"
        evidence = Evidence.create(
            id="evidence-raw",
            run_id=run.run_id,
            action_id=None,
            type=EvidenceType.ARTIFACT,
            source="fixture:large-output",
            summary="full scanner output",
            raw_content=raw_content,
            metadata={"encoding": "utf-8", "nested": {"complete": True}},
            created_at=_time(1),
        )

        await self.store.save_evidence(evidence)
        loaded = await self.store.get_evidence(evidence.id)

        self.assertEqual(evidence, loaded)
        assert loaded is not None
        self.assertEqual(raw_content, loaded.raw_content)
        self.assertTrue(loaded.raw_content.endswith("END"))

        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute(
                "UPDATE evidence SET raw_content = ? WHERE id = ?",
                ("tampered", evidence.id),
            )
        with self.assertRaisesRegex(CorruptEvidenceError, "stored SHA-256"):
            await self.store.get_evidence(evidence.id)

    async def test_action_evidence_finding_and_event_round_trip(self) -> None:
        run = RunState.create(_task("task-audit"), run_id="run-audit", started_at=_time())
        await self.store.save_run(run)
        action = ActionRecord.start(
            id="action-audit",
            run_id=run.run_id,
            plan_node_id="node-audit",
            agent_id="agent-local",
            tool_name="network_scan",
            arguments={"target": "127.0.0.1", "ports": [80, 443]},
            started_at=_time(1),
        ).finish(
            success=True,
            duration_ms=17,
            exit_code=0,
            finished_at=_time(2),
        )
        await self.store.save_action(action)
        evidence = Evidence.create(
            id="evidence-audit",
            run_id=run.run_id,
            action_id=action.id,
            type=EvidenceType.NETWORK_SCAN,
            source="tool:network_scan",
            summary="localhost scan",
            raw_content='{"ports":[80]}',
            metadata={"engine": "fixture"},
            created_at=_time(3),
        )
        await self.store.save_evidence(evidence)
        action = action.add_evidence(evidence.id)
        await self.store.save_action(action)
        finding = Finding.create(
            id="finding-audit",
            run_id=run.run_id,
            title="HTTP service detected",
            description="A local HTTP listener responded.",
            severity=Severity.INFORMATIONAL,
            confidence=1.0,
            evidence_ids=(evidence.id,),
            status=FindingStatus.VERIFIED,
            subject="127.0.0.1:80",
            created_at=_time(4),
        )
        await self.store.save_finding(finding)
        event = RunEvent(
            id="event-audit",
            event_type=EventType.EVIDENCE_CREATED,
            run_id=run.run_id,
            payload={"evidence_id": evidence.id},
            created_at=_time(5),
        )
        await self.store.publish(event)

        self.assertEqual(action, await self.store.get_action(action.id))
        self.assertEqual((action,), await self.store.list_actions(run.run_id))
        self.assertEqual((evidence,), await self.store.list_evidence(run.run_id))
        self.assertEqual((finding,), await self.store.list_findings(run.run_id))
        loaded_run = await self.store.get_run(run.run_id)
        assert loaded_run is not None
        self.assertEqual((evidence,), loaded_run.evidence)
        self.assertEqual((finding,), loaded_run.findings)
        with closing(sqlite3.connect(self.database)) as connection, connection:
            event_count = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        self.assertEqual(1, event_count)

    async def test_every_list_and_search_is_isolated_by_run(self) -> None:
        first = RunState.create(_task("task-one"), run_id="run-one", started_at=_time())
        second = RunState.create(_task("task-two"), run_id="run-two", started_at=_time())
        await self.store.save_run(first)
        await self.store.save_run(second)

        first_action = _finished_action(first.run_id, "action-one", "node-one")
        second_action = _finished_action(second.run_id, "action-two", "node-two")
        await self.store.save_action(first_action)
        await self.store.save_action(second_action)
        first_evidence = _evidence(
            first.run_id, first_action.id, "evidence-one", "shared needle one"
        )
        second_evidence = _evidence(
            second.run_id, second_action.id, "evidence-two", "shared needle two"
        )
        await self.store.save_evidence(first_evidence)
        await self.store.save_evidence(second_evidence)
        first_finding = _finding(first.run_id, first_evidence.id, "finding-one")
        second_finding = _finding(second.run_id, second_evidence.id, "finding-two")
        await self.store.save_finding(first_finding)
        await self.store.save_finding(second_finding)

        self.assertEqual((first_action,), await self.store.list_actions(first.run_id))
        self.assertEqual((second_action,), await self.store.list_actions(second.run_id))
        self.assertEqual((first_evidence,), await self.store.list_evidence(first.run_id))
        self.assertEqual((second_evidence,), await self.store.list_evidence(second.run_id))
        self.assertEqual(
            (first_evidence,), await self.store.search_evidence(first.run_id, "shared needle")
        )
        self.assertEqual(
            (second_evidence,), await self.store.search_evidence(second.run_id, "shared needle")
        )
        self.assertEqual((first_finding,), await self.store.list_findings(first.run_id))
        self.assertEqual((second_finding,), await self.store.list_findings(second.run_id))
        self.assertEqual((), await self.store.search_evidence(first.run_id, "two"))

        with self.assertRaises(StorageReferenceError):
            await self.store.save_evidence(
                Evidence.create(
                    id="cross-run-evidence",
                    run_id=first.run_id,
                    action_id=second_action.id,
                    type=EvidenceType.TOOL_OUTPUT,
                    source="tool:fixture",
                    summary="invalid cross-run provenance",
                    raw_content="must fail",
                    created_at=_time(6),
                )
            )

    async def test_plan_versions_keep_history_and_reject_stale_rewrites(self) -> None:
        task = _task("task-plan")
        run = RunState.create(task, run_id="run-plan", started_at=_time())
        await self.store.save_run(run)
        node = PlanNode.create(
            id="node-plan",
            goal="Discover services",
            description="Scan the authorized local fixture.",
            assigned_agent="local-security",
            required_capabilities=("network.scan",),
            success_criteria=task.success_criteria,
            created_at=_time(1),
        )
        version_one = Plan.create(
            id="plan-stable",
            task_id=task.id,
            nodes=(node,),
            created_at=_time(1),
        )
        await self.store.save_plan(run.run_id, version_one)

        version_one = version_one.activate(task, at=_time(2))
        await self.store.save_plan(run.run_id, version_one)
        self.assertEqual(version_one, await self.store.get_plan(version_one.id, 1))

        version_two = version_one.revise(version_one.nodes, at=_time(3))
        await self.store.save_plan(run.run_id, version_two)
        stale_version_one = version_one.transition(PlanStatus.FAILED, at=_time(4))
        with self.assertRaises(StalePlanWriteError):
            await self.store.save_plan(run.run_id, stale_version_one)

        self.assertEqual(version_two, await self.store.get_plan(version_one.id))
        self.assertEqual(
            (version_one, version_two),
            await self.store.list_plan_versions(version_one.id),
        )

    async def test_terminal_run_cannot_be_resurrected_by_a_later_stale_branch(self) -> None:
        task = _task("task-terminal")
        base = RunState.create(task, run_id="run-terminal", started_at=_time())
        await self.store.save_run(base)
        failed = base.transition(RunStatus.FAILED, error="fixture failure", at=_time(1))
        await self.store.save_run(failed)

        stale_planning = base.transition(RunStatus.PLANNING, at=_time(2))
        with self.assertRaises(StaleRunWriteError):
            await self.store.save_run(stale_planning)
        self.assertEqual(failed, await self.store.get_run(base.run_id))

    async def test_file_database_uses_wal_and_declares_all_audit_tables(self) -> None:
        with closing(sqlite3.connect(self.database)) as connection:
            journal_mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
            tables = {
                row[0]
                for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
            }
        self.assertEqual("wal", journal_mode.casefold())
        self.assertTrue(
            {"runs", "plans", "plan_nodes", "actions", "evidence", "findings", "events"} <= tables
        )

    async def test_shared_in_memory_database_survives_short_lived_connections(self) -> None:
        store = SQLiteStore(":memory:")
        try:
            run = RunState.create(_task("task-memory"), run_id="run-memory", started_at=_time())
            await store.save_run(run)
            self.assertEqual(run, await store.get_run(run.run_id))
        finally:
            await store.close()


def _task(identifier: str, *, task_type: TaskType = TaskType.GENERIC) -> TaskSpec:
    return TaskSpec(
        id=identifier,
        objective="Inspect an authorized local fixture",
        task_type=task_type,
        scope=ScopeSpec(network_targets=("127.0.0.1",)),
        success_criteria=("Record the observed service",),
        constraints=("localhost only",),
        inputs={"labels": ["本地", "fixture"], "options": {"safe": True}},
        created_at=_time(),
    )


def _finished_action(run_id: str, action_id: str, node_id: str) -> ActionRecord:
    return ActionRecord.start(
        id=action_id,
        run_id=run_id,
        plan_node_id=node_id,
        agent_id="fixture-agent",
        tool_name="fixture-tool",
        arguments={"target": "127.0.0.1"},
        started_at=_time(1),
    ).finish(success=True, duration_ms=2, exit_code=0, finished_at=_time(2))


def _evidence(run_id: str, action_id: str, evidence_id: str, raw: str) -> Evidence:
    return Evidence.create(
        id=evidence_id,
        run_id=run_id,
        action_id=action_id,
        type=EvidenceType.TOOL_OUTPUT,
        source="tool:fixture-tool",
        summary=raw,
        raw_content=raw,
        created_at=_time(3),
    )


def _finding(run_id: str, evidence_id: str, finding_id: str) -> Finding:
    return Finding.create(
        id=finding_id,
        run_id=run_id,
        title="Fixture observation",
        description="The isolated fixture produced evidence.",
        severity=Severity.INFORMATIONAL,
        confidence=0.9,
        evidence_ids=(evidence_id,),
        status=FindingStatus.UNVERIFIED,
        created_at=_time(4),
    )


def _time(seconds: int = 0) -> datetime:
    return datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=seconds)


if __name__ == "__main__":
    unittest.main()
