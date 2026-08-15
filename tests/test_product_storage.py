from __future__ import annotations

import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from security_agent.application.models import TaskStatus
from security_agent.contracts import EventType, RunEvent
from security_agent.domain import (
    ActionRecord,
    Evidence,
    EvidenceType,
    Finding,
    RunState,
    RunStatus,
    ScopeSpec,
    Severity,
    TaskSpec,
    TaskType,
)
from security_agent.infrastructure.storage.product import (
    ProductConflictError,
    ProductReferenceError,
    SQLiteProductStore,
)


class SQLiteProductStoreTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.database = Path(self.temporary.name) / "sec-go.db"
        self.store = SQLiteProductStore(self.database)
        await self.store.initialize()

    async def asyncTearDown(self) -> None:
        await self.store.close()
        self.temporary.cleanup()

    async def test_initialization_places_product_and_kernel_tables_in_one_database(self) -> None:
        with closing(sqlite3.connect(self.database)) as connection:
            tables = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                ).fetchall()
            }
            journal_mode = str(connection.execute("PRAGMA journal_mode").fetchone()[0])

        self.assertTrue({"users", "tasks", "runs", "plans", "events"} <= tables)
        self.assertEqual("wal", journal_mode.casefold())

    async def test_user_auth_lookups_are_case_insensitive_and_conflicts_are_explicit(self) -> None:
        user = await self.store.create_user("Admin", "$2b$fixture", user_id="user-admin")

        self.assertEqual(user, await self.store.get_user("user-admin"))
        self.assertEqual(user, await self.store.get_user_by_username("admin"))
        with self.assertRaises(ProductConflictError):
            await self.store.create_user("ADMIN", "$2b$other")

    async def test_task_crud_is_owner_scoped_and_bound_tasks_are_immutable(self) -> None:
        owner = await self.store.create_user("owner", "hash")
        stranger = await self.store.create_user("stranger", "hash")
        spec = _task("task-owned")
        task = await self.store.create_task(
            owner.id,
            "Authorized scan",
            "Inspect the local fixture",
            task_spec=spec,
        )

        self.assertEqual("task-owned", task.id)
        self.assertIsNone(await self.store.get_task(stranger.id, task.id))
        self.assertEqual((), await self.store.list_tasks(stranger.id))
        updated = await self.store.update_task(owner.id, task.id, title="Renamed scan")
        assert updated is not None
        self.assertEqual("Renamed scan", updated.title)

        bound = await self.store.bind_run(owner.id, task.id, "run-owned")
        assert bound is not None
        self.assertEqual(TaskStatus.QUEUED, bound.status)
        self.assertEqual("run-owned", bound.run_id)
        self.assertEqual(bound, await self.store.bind_run(owner.id, task.id, "run-owned"))
        with self.assertRaises(ProductConflictError):
            await self.store.update_task(owner.id, task.id, description="too late")
        with self.assertRaises(ProductConflictError):
            await self.store.delete_task(owner.id, task.id)

        self.assertFalse(await self.store.delete_task(stranger.id, task.id))
        self.assertIsNone(await self.store.get_task_projection(stranger.id, task.id))
        self.assertIsNone(await self.store.list_task_events(stranger.id, task.id))

    async def test_draft_delete_and_missing_owner_behave_predictably(self) -> None:
        with self.assertRaises(ProductReferenceError):
            await self.store.create_task("missing", "Title", "Description")

        user = await self.store.create_user("draft-owner", "hash")
        task = await self.store.create_task(user.id, "Draft", "Disposable")
        self.assertTrue(await self.store.delete_task(user.id, task.id))
        self.assertFalse(await self.store.delete_task(user.id, task.id))

    async def test_projection_reuses_kernel_audit_rows_without_returning_raw_evidence(self) -> None:
        user = await self.store.create_user("analyst", "hash")
        task_spec = _task("task-projection")
        task = await self.store.create_task(
            user.id,
            "Projection",
            "Read bounded run state",
            task_spec=task_spec,
        )

        # The product can reserve an identity before the kernel creates the run row.
        await self.store.bind_run(user.id, task.id, "run-projection")
        run = RunState.create(task_spec, run_id="run-projection")
        await self.store.kernel_store.save_run(run)
        action = ActionRecord.start(
            run_id=run.run_id,
            plan_node_id="node-fixture",
            agent_id="agent-fixture",
            tool_name="fixture.tool",
        )
        evidence = Evidence.create(
            run_id=run.run_id,
            action_id=None,
            type=EvidenceType.OBSERVATION,
            source="fixture",
            summary="bounded summary",
            raw_content="sensitive raw content",
        )
        finding = Finding.create(
            run_id=run.run_id,
            title="Fixture finding",
            description="Projection count fixture",
            severity=Severity.LOW,
            confidence=0.5,
        )
        await self.store.kernel_store.save_action(action)
        await self.store.kernel_store.save_evidence(evidence)
        await self.store.kernel_store.save_finding(finding)
        first_event = RunEvent(EventType.RUN_STARTED, run.run_id, {"ordinal": 1})
        second_event = RunEvent(EventType.SKILLS_SELECTED, run.run_id, {"ordinal": 2})
        await self.store.kernel_store.publish(first_event)
        await self.store.kernel_store.publish(second_event)

        projection = await self.store.get_task_projection(user.id, task.id)
        assert projection is not None
        self.assertEqual(RunStatus.CREATED, projection.run_status)
        self.assertEqual(TaskStatus.QUEUED, projection.effective_status)
        self.assertEqual(1, projection.action_count)
        self.assertEqual(1, projection.evidence_count)
        self.assertEqual(1, projection.finding_count)
        self.assertNotIn("sensitive raw content", repr(projection))

        first_page = await self.store.list_task_events(user.id, task.id, limit=1)
        assert first_page is not None
        self.assertTrue(first_page.has_more)
        self.assertEqual((first_event,), tuple(item.event for item in first_page.events))
        second_page = await self.store.list_task_events(
            user.id,
            task.id,
            after_sequence=first_page.next_cursor,
            limit=1,
        )
        assert second_page is not None
        self.assertFalse(second_page.has_more)
        self.assertEqual((second_event,), tuple(item.event for item in second_page.events))
        self.assertGreater(second_page.next_cursor, first_page.next_cursor)
        self.assertEqual(second_page.next_cursor, projection.last_event_sequence)

    async def test_shared_memory_database_keeps_kernel_and_product_rows_visible(self) -> None:
        store = SQLiteProductStore(":memory:")
        await store.initialize()
        try:
            user = await store.create_user("memory", "hash")
            spec = _task("task-memory")
            task = await store.create_task(
                user.id,
                "Memory task",
                "Shared SQLite URI",
                task_spec=spec,
            )
            await store.bind_run(user.id, task.id, "run-memory")
            await store.kernel_store.save_run(RunState.create(spec, run_id="run-memory"))

            projection = await store.get_task_projection(user.id, task.id)
            assert projection is not None
            self.assertEqual(RunStatus.CREATED, projection.run_status)
        finally:
            await store.close()


def _task(identifier: str) -> TaskSpec:
    return TaskSpec.create(
        id=identifier,
        objective="Inspect an explicitly authorized local fixture",
        task_type=TaskType.PENTEST,
        scope=ScopeSpec(network_targets=("127.0.0.1",)),
        inputs={"target": "127.0.0.1", "ports": [41012]},
        success_criteria=("Record the observed state",),
    )


if __name__ == "__main__":
    unittest.main()
