"""Short-lived-connection SQLite repositories for durable agent state."""

from __future__ import annotations

import asyncio
import hmac
import sqlite3
from contextlib import closing
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from security_agent.contracts.events import RunEvent
from security_agent.domain import (
    ActionRecord,
    Evidence,
    Finding,
    FindingStatus,
    NodeStatus,
    Plan,
    PlanNode,
    PlanStatus,
    RunState,
    RunStatus,
    content_digest,
)
from security_agent.infrastructure.storage.codec import (
    CorruptStorageError,
    action_from_row,
    decode_datetime,
    dump_json,
    encode_datetime,
    evidence_from_row_values,
    finding_from_row,
    load_string_tuple,
    plan_from_rows,
    task_from_json,
    task_to_json,
)
from security_agent.infrastructure.storage.schema import SCHEMA


class StorageError(RuntimeError):
    """Base class for errors at the persistence boundary."""


class StorageConflictError(StorageError):
    """An existing durable identity conflicts with the proposed value."""


class StorageReferenceError(StorageError):
    """A durable relationship points to a missing or differently owned row."""


class StalePlanWriteError(StorageConflictError):
    """A caller attempted to rewrite a plan after a newer revision was stored."""


class StaleRunWriteError(StorageConflictError):
    """A caller attempted to replace newer run state with older state."""


class CorruptEvidenceError(CorruptStorageError, StorageError):
    """Persisted evidence bytes no longer match their recorded SHA-256 digest."""


_RUN_TRANSITIONS: dict[RunStatus, frozenset[RunStatus]] = {
    RunStatus.CREATED: frozenset({RunStatus.PLANNING, RunStatus.FAILED, RunStatus.CANCELLED}),
    RunStatus.PLANNING: frozenset({RunStatus.RUNNING, RunStatus.FAILED, RunStatus.CANCELLED}),
    RunStatus.RUNNING: frozenset(
        {RunStatus.PLANNING, RunStatus.VERIFYING, RunStatus.FAILED, RunStatus.CANCELLED}
    ),
    RunStatus.VERIFYING: frozenset(
        {
            RunStatus.PLANNING,
            RunStatus.RUNNING,
            RunStatus.COMPLETED,
            RunStatus.FAILED,
            RunStatus.CANCELLED,
        }
    ),
    RunStatus.COMPLETED: frozenset(),
    RunStatus.FAILED: frozenset(),
    RunStatus.CANCELLED: frozenset(),
}

_PLAN_TRANSITIONS: dict[PlanStatus, frozenset[PlanStatus]] = {
    PlanStatus.DRAFT: frozenset({PlanStatus.ACTIVE, PlanStatus.FAILED, PlanStatus.CANCELLED}),
    PlanStatus.ACTIVE: frozenset(
        {
            PlanStatus.COMPLETED,
            PlanStatus.FAILED,
            PlanStatus.SUPERSEDED,
            PlanStatus.CANCELLED,
        }
    ),
    PlanStatus.COMPLETED: frozenset(),
    PlanStatus.FAILED: frozenset(),
    PlanStatus.SUPERSEDED: frozenset(),
    PlanStatus.CANCELLED: frozenset(),
}

_NODE_TRANSITIONS: dict[NodeStatus, frozenset[NodeStatus]] = {
    NodeStatus.PENDING: frozenset({NodeStatus.READY, NodeStatus.BLOCKED, NodeStatus.CANCELLED}),
    NodeStatus.READY: frozenset({NodeStatus.RUNNING, NodeStatus.BLOCKED, NodeStatus.CANCELLED}),
    NodeStatus.RUNNING: frozenset(
        {
            NodeStatus.SUCCEEDED,
            NodeStatus.FAILED,
            NodeStatus.BLOCKED,
            NodeStatus.CANCELLED,
        }
    ),
    NodeStatus.FAILED: frozenset({NodeStatus.READY, NodeStatus.BLOCKED, NodeStatus.CANCELLED}),
    NodeStatus.BLOCKED: frozenset({NodeStatus.READY, NodeStatus.CANCELLED}),
    NodeStatus.SUCCEEDED: frozenset(),
    NodeStatus.CANCELLED: frozenset(),
}

_FINDING_TRANSITIONS: dict[FindingStatus, frozenset[FindingStatus]] = {
    FindingStatus.DRAFT: frozenset(
        {FindingStatus.UNVERIFIED, FindingStatus.VERIFIED, FindingStatus.REJECTED}
    ),
    FindingStatus.UNVERIFIED: frozenset({FindingStatus.VERIFIED, FindingStatus.REJECTED}),
    FindingStatus.VERIFIED: frozenset({FindingStatus.REJECTED, FindingStatus.RESOLVED}),
    FindingStatus.REJECTED: frozenset(),
    FindingStatus.RESOLVED: frozenset(),
}


class SQLiteStore:
    """Implement run, evidence, and event ports with stdlib ``sqlite3``.

    Each operation opens and closes its own connection. Blocking SQLite work is
    delegated to a worker thread; writes are serialized per store instance to
    avoid avoidable lock contention while still allowing independent runs and
    independent store instances to proceed concurrently.
    """

    def __init__(self, database: str | Path) -> None:
        database_text = str(database)
        if not database_text:
            raise ValueError("database path must not be empty")
        self._memory_database = database_text == ":memory:"
        self._database = (
            f"file:security-agent-{uuid4().hex}?mode=memory&cache=shared"
            if self._memory_database
            else database_text
        )
        self._uri = self._memory_database or database_text.startswith("file:")
        self._keeper: sqlite3.Connection | None = None
        self._initialized: bool = False
        self._initialize_lock = asyncio.Lock()
        self._write_lock = asyncio.Lock()

    @property
    def database(self) -> str:
        return self._database

    async def initialize(self) -> None:
        if self._initialized:
            return
        async with self._initialize_lock:
            # Re-check through a method because another coroutine may have
            # initialized the store while this one awaited the lock.
            if self._is_initialized():
                return
            await asyncio.to_thread(self._initialize_sync)
            self._initialized = True

    def _is_initialized(self) -> bool:
        return self._initialized

    async def close(self) -> None:
        """Release the keeper used only for shared in-memory databases."""
        async with self._write_lock:
            keeper, self._keeper = self._keeper, None
            self._initialized = False
            if keeper is not None:
                await asyncio.to_thread(keeper.close)

    async def save_run(self, run: RunState) -> None:
        await self.initialize()
        async with self._write_lock:
            await asyncio.to_thread(self._save_run_sync, run)

    async def get_run(self, run_id: str) -> RunState | None:
        _require_non_blank(run_id, "run_id")
        await self.initialize()
        return await asyncio.to_thread(self._get_run_sync, run_id)

    async def save_plan(self, run_id: str, plan: Plan) -> None:
        _require_non_blank(run_id, "run_id")
        await self.initialize()
        async with self._write_lock:
            await asyncio.to_thread(self._save_plan_sync, run_id, plan)

    async def get_plan(self, plan_id: str, version: int | None = None) -> Plan | None:
        _require_non_blank(plan_id, "plan_id")
        if version is not None and (isinstance(version, bool) or version <= 0):
            raise ValueError("version must be a positive integer or None")
        await self.initialize()
        return await asyncio.to_thread(self._get_plan_sync, plan_id, version)

    async def list_plan_versions(self, plan_id: str) -> tuple[Plan, ...]:
        _require_non_blank(plan_id, "plan_id")
        await self.initialize()
        return await asyncio.to_thread(self._list_plan_versions_sync, plan_id)

    async def save_action(self, action: ActionRecord) -> None:
        await self.initialize()
        async with self._write_lock:
            await asyncio.to_thread(self._save_action_sync, action)

    async def get_action(self, action_id: str) -> ActionRecord | None:
        _require_non_blank(action_id, "action_id")
        await self.initialize()
        return await asyncio.to_thread(self._get_action_sync, action_id)

    async def list_actions(
        self,
        run_id: str,
        plan_node_id: str | None = None,
    ) -> tuple[ActionRecord, ...]:
        _require_non_blank(run_id, "run_id")
        if plan_node_id is not None:
            _require_non_blank(plan_node_id, "plan_node_id")
        await self.initialize()
        return await asyncio.to_thread(self._list_actions_sync, run_id, plan_node_id)

    async def save_evidence(self, evidence: Evidence) -> None:
        await self.initialize()
        async with self._write_lock:
            await asyncio.to_thread(self._save_evidence_sync, evidence)

    async def get_evidence(self, evidence_id: str) -> Evidence | None:
        _require_non_blank(evidence_id, "evidence_id")
        await self.initialize()
        return await asyncio.to_thread(self._get_evidence_sync, evidence_id)

    async def list_evidence(self, run_id: str) -> tuple[Evidence, ...]:
        _require_non_blank(run_id, "run_id")
        await self.initialize()
        return await asyncio.to_thread(self._list_evidence_sync, run_id)

    async def search_evidence(
        self,
        run_id: str,
        query: str,
        limit: int = 20,
    ) -> tuple[Evidence, ...]:
        _require_non_blank(run_id, "run_id")
        _require_non_blank(query, "query")
        if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
            raise ValueError("limit must be a positive integer")
        await self.initialize()
        return await asyncio.to_thread(self._search_evidence_sync, run_id, query, limit)

    async def save_finding(self, finding: Finding) -> None:
        await self.initialize()
        async with self._write_lock:
            await asyncio.to_thread(self._save_finding_sync, finding)

    async def list_findings(self, run_id: str) -> tuple[Finding, ...]:
        _require_non_blank(run_id, "run_id")
        await self.initialize()
        return await asyncio.to_thread(self._list_findings_sync, run_id)

    async def publish(self, event: RunEvent) -> None:
        """Persist a bounded event payload, satisfying ``EventSink`` as well."""
        await self.initialize()
        async with self._write_lock:
            await asyncio.to_thread(self._publish_sync, event)

    def _initialize_sync(self) -> None:
        if not self._uri:
            Path(self._database).expanduser().parent.mkdir(parents=True, exist_ok=True)
        if self._memory_database:
            keeper = self._new_connection()
            self._keeper = keeper
            keeper.executescript(SCHEMA)
            keeper.commit()
            return
        with closing(self._new_connection()) as connection:
            mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]
            if str(mode).casefold() != "wal":
                raise StorageError(f"SQLite refused WAL journal mode: {mode!r}")
            connection.executescript(SCHEMA)
            connection.commit()

    def _new_connection(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self._database,
            timeout=30.0,
            uri=self._uri,
            check_same_thread=False,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 30000")
        return connection

    def _save_run_sync(self, run: RunState) -> None:
        task_json = task_to_json(run.task)
        plan_id = None if run.plan is None else run.plan.id
        plan_version = None if run.plan is None else run.plan.version
        with closing(self._new_connection()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                """
                SELECT *
                FROM runs WHERE run_id = ?
                """,
                (run.run_id,),
            ).fetchone()
            if existing is not None:
                if existing["task_id"] != run.task.id or existing["task_json"] != task_json:
                    raise StorageConflictError(
                        f"run {run.run_id!r} is already bound to a different task"
                    )
                if existing["started_at"] != encode_datetime(run.started_at):
                    raise StorageConflictError(
                        f"run {run.run_id!r} has a conflicting start timestamp"
                    )
                stored_updated = decode_datetime(existing["updated_at"], "runs.updated_at")
                if run.updated_at < stored_updated:
                    raise StaleRunWriteError(f"run {run.run_id!r} has newer stored state")
                stored_status = RunStatus(str(existing["status"]))
                if (
                    run.status is not stored_status
                    and run.status not in _RUN_TRANSITIONS[stored_status]
                ):
                    raise StaleRunWriteError(
                        f"run status cannot move from {stored_status.value} to {run.status.value}"
                    )
                if run.step_count < int(existing["step_count"]):
                    raise StaleRunWriteError("run step_count is monotonic")
                if run.replan_count < int(existing["replan_count"]):
                    raise StaleRunWriteError("run replan_count is monotonic")
                if existing["last_error"] is not None and run.last_error is None:
                    raise StaleRunWriteError("run last_error cannot be cleared")
                stored_plan_id = existing["plan_id"]
                stored_version = existing["plan_version"]
                if stored_plan_id is not None and plan_id != stored_plan_id:
                    raise StaleRunWriteError(
                        f"run {run.run_id!r} cannot discard or replace its plan identity"
                    )
                if stored_version is not None and (
                    plan_version is None or plan_version < stored_version
                ):
                    raise StaleRunWriteError(
                        f"run {run.run_id!r} cannot return to plan version {plan_version}"
                    )
                stored_snapshot = _stored_run_snapshot(existing)
                proposed_snapshot = _run_snapshot(run)
                if (
                    stored_status
                    in {
                        RunStatus.COMPLETED,
                        RunStatus.FAILED,
                        RunStatus.CANCELLED,
                    }
                    and proposed_snapshot != stored_snapshot
                ):
                    raise StaleRunWriteError("a terminal run is immutable")
                if run.updated_at == stored_updated and proposed_snapshot != stored_snapshot:
                    raise StaleRunWriteError(
                        "a run write with the stored timestamp must be idempotent"
                    )
            connection.execute(
                """
                INSERT INTO runs (
                    run_id, task_id, task_json, plan_id, plan_version, status,
                    current_nodes_json, started_at, updated_at, finished_at,
                    step_count, replan_count, last_error
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(run_id) DO UPDATE SET
                    plan_id = excluded.plan_id,
                    plan_version = excluded.plan_version,
                    status = excluded.status,
                    current_nodes_json = excluded.current_nodes_json,
                    updated_at = excluded.updated_at,
                    finished_at = excluded.finished_at,
                    step_count = excluded.step_count,
                    replan_count = excluded.replan_count,
                    last_error = excluded.last_error
                """,
                (
                    run.run_id,
                    run.task.id,
                    task_json,
                    plan_id,
                    plan_version,
                    run.status.value,
                    dump_json(list(run.current_nodes)),
                    encode_datetime(run.started_at),
                    encode_datetime(run.updated_at),
                    None if run.finished_at is None else encode_datetime(run.finished_at),
                    run.step_count,
                    run.replan_count,
                    run.last_error,
                ),
            )

    def _get_run_sync(self, run_id: str) -> RunState | None:
        with closing(self._new_connection()) as connection:
            connection.execute("BEGIN")
            row = connection.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
            if row is None:
                return None
            task = task_from_json(_row_str(row, "task_json"))
            if task.id != _row_str(row, "task_id"):
                raise CorruptStorageError(f"run {run_id!r} task identity is inconsistent")
            plan_id = row["plan_id"]
            plan_version = row["plan_version"]
            plan: Plan | None = None
            if plan_id is not None and plan_version is not None:
                plan = self._fetch_plan(connection, str(plan_id), int(plan_version))
                if plan is None:
                    raise CorruptStorageError(f"run {run_id!r} points to a missing plan revision")
            evidence = self._fetch_evidence_many(
                connection,
                "SELECT * FROM evidence WHERE run_id = ? ORDER BY rowid",
                (run_id,),
            )
            findings = self._fetch_findings_many(
                connection,
                "SELECT * FROM findings WHERE run_id = ? ORDER BY rowid",
                (run_id,),
            )
            try:
                return RunState(
                    run_id=run_id,
                    task=task,
                    plan=plan,
                    status=RunStatus(_row_str(row, "status")),
                    current_nodes=load_string_tuple(
                        _row_str(row, "current_nodes_json"), "runs.current_nodes_json"
                    ),
                    findings=findings,
                    evidence=evidence,
                    started_at=decode_datetime(_row_str(row, "started_at"), "runs.started_at"),
                    updated_at=decode_datetime(_row_str(row, "updated_at"), "runs.updated_at"),
                    finished_at=(
                        None
                        if row["finished_at"] is None
                        else decode_datetime(str(row["finished_at"]), "runs.finished_at")
                    ),
                    step_count=_row_int(row, "step_count"),
                    replan_count=_row_int(row, "replan_count"),
                    last_error=None if row["last_error"] is None else str(row["last_error"]),
                )
            except (TypeError, ValueError) as error:
                raise CorruptStorageError(f"invalid RunState for {run_id!r}") from error

    def _save_plan_sync(self, run_id: str, plan: Plan) -> None:
        with closing(self._new_connection()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            self._save_plan(connection, run_id, plan)

    def _save_plan(self, connection: sqlite3.Connection, run_id: str, plan: Plan) -> None:
        run_row = connection.execute(
            "SELECT task_id FROM runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        if run_row is None:
            raise StorageReferenceError(f"cannot save a plan for missing run {run_id!r}")
        if run_row["task_id"] != plan.task_id:
            raise StorageReferenceError("plan task_id does not match the owning run")

        identity_row = connection.execute(
            "SELECT run_id, task_id FROM plans WHERE plan_id = ? LIMIT 1", (plan.id,)
        ).fetchone()
        if identity_row is not None and (
            identity_row["run_id"] != run_id or identity_row["task_id"] != plan.task_id
        ):
            raise StorageConflictError(
                f"plan {plan.id!r} is already bound to a different run or task"
            )

        latest_row = connection.execute(
            "SELECT MAX(version) AS version FROM plans WHERE plan_id = ?", (plan.id,)
        ).fetchone()
        latest = None if latest_row is None else latest_row["version"]
        if latest is not None and plan.version < int(latest):
            raise StalePlanWriteError(
                f"plan {plan.id!r} version {plan.version} is historic; latest is {latest}"
            )

        existing = self._fetch_plan(connection, plan.id, plan.version)
        if existing is None:
            self._insert_plan(connection, run_id, plan)
            return
        owner = connection.execute(
            "SELECT run_id FROM plans WHERE plan_id = ? AND version = ?",
            (plan.id, plan.version),
        ).fetchone()
        if owner is None or owner["run_id"] != run_id:
            raise StorageConflictError(f"plan {plan.id!r} belongs to a different run")
        if _plan_structure(existing) != _plan_structure(plan):
            raise StorageConflictError("structural plan changes require a new plan version")
        if (
            plan.status is not existing.status
            and plan.status not in _PLAN_TRANSITIONS[existing.status]
        ):
            raise StalePlanWriteError(
                f"plan status cannot move from {existing.status.value} to {plan.status.value}"
            )
        if (
            existing.status
            in {
                PlanStatus.COMPLETED,
                PlanStatus.FAILED,
                PlanStatus.SUPERSEDED,
                PlanStatus.CANCELLED,
            }
            and existing != plan
        ):
            raise StalePlanWriteError("a terminal plan revision is immutable")
        if plan.updated_at < existing.updated_at or any(
            proposed.updated_at < stored.updated_at
            for proposed, stored in zip(plan.nodes, existing.nodes, strict=True)
        ):
            raise StalePlanWriteError(
                f"plan {plan.id!r} version {plan.version} has newer stored progress"
            )
        if plan.updated_at == existing.updated_at and existing != plan:
            raise StalePlanWriteError("a plan write with the stored timestamp must be idempotent")
        for proposed, stored in zip(plan.nodes, existing.nodes, strict=True):
            if (
                proposed.status is not stored.status
                and proposed.status not in _NODE_TRANSITIONS[stored.status]
            ):
                raise StalePlanWriteError(
                    f"node {proposed.id!r} status cannot move from "
                    f"{stored.status.value} to {proposed.status.value}"
                )
            if proposed.attempt_count < stored.attempt_count:
                raise StalePlanWriteError(f"node {proposed.id!r} attempt_count is monotonic")
            if not set(stored.evidence_ids).issubset(proposed.evidence_ids):
                raise StalePlanWriteError(f"node {proposed.id!r} evidence links are append-only")
            if not set(stored.finding_ids).issubset(proposed.finding_ids):
                raise StalePlanWriteError(f"node {proposed.id!r} finding links are append-only")
        connection.execute(
            "UPDATE plans SET status = ?, updated_at = ? WHERE plan_id = ? AND version = ?",
            (plan.status.value, encode_datetime(plan.updated_at), plan.id, plan.version),
        )
        for node in plan.nodes:
            connection.execute(
                """
                UPDATE plan_nodes SET
                    status = ?, attempt_count = ?, evidence_ids_json = ?,
                    finding_ids_json = ?, updated_at = ?
                WHERE plan_id = ? AND plan_version = ? AND node_id = ?
                """,
                (
                    node.status.value,
                    node.attempt_count,
                    dump_json(list(node.evidence_ids)),
                    dump_json(list(node.finding_ids)),
                    encode_datetime(node.updated_at),
                    plan.id,
                    plan.version,
                    node.id,
                ),
            )

    def _insert_plan(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        plan: Plan,
    ) -> None:
        try:
            connection.execute(
                """
                INSERT INTO plans (
                    plan_id, version, run_id, task_id, status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    plan.id,
                    plan.version,
                    run_id,
                    plan.task_id,
                    plan.status.value,
                    encode_datetime(plan.created_at),
                    encode_datetime(plan.updated_at),
                ),
            )
            connection.executemany(
                """
                INSERT INTO plan_nodes (
                    plan_id, plan_version, position, node_id, goal, description,
                    status, assigned_agent, required_capabilities_json,
                    dependencies_json, success_criteria_json, attempt_count,
                    max_attempts, evidence_ids_json, finding_ids_json,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        plan.id,
                        plan.version,
                        position,
                        node.id,
                        node.goal,
                        node.description,
                        node.status.value,
                        node.assigned_agent,
                        dump_json(list(node.required_capabilities)),
                        dump_json(list(node.dependencies)),
                        dump_json(list(node.success_criteria)),
                        node.attempt_count,
                        node.max_attempts,
                        dump_json(list(node.evidence_ids)),
                        dump_json(list(node.finding_ids)),
                        encode_datetime(node.created_at),
                        encode_datetime(node.updated_at),
                    )
                    for position, node in enumerate(plan.nodes)
                ],
            )
        except sqlite3.IntegrityError as error:
            raise StorageReferenceError("failed to persist plan relationships") from error

    def _get_plan_sync(self, plan_id: str, version: int | None) -> Plan | None:
        with closing(self._new_connection()) as connection:
            connection.execute("BEGIN")
            if version is None:
                row = connection.execute(
                    "SELECT MAX(version) AS version FROM plans WHERE plan_id = ?", (plan_id,)
                ).fetchone()
                if row is None or row["version"] is None:
                    return None
                version = int(row["version"])
            return self._fetch_plan(connection, plan_id, version)

    def _list_plan_versions_sync(self, plan_id: str) -> tuple[Plan, ...]:
        with closing(self._new_connection()) as connection:
            connection.execute("BEGIN")
            rows = connection.execute(
                "SELECT version FROM plans WHERE plan_id = ? ORDER BY version", (plan_id,)
            ).fetchall()
            result: list[Plan] = []
            for row in rows:
                plan = self._fetch_plan(connection, plan_id, int(row["version"]))
                if plan is None:  # pragma: no cover - same connection and source rows
                    raise CorruptStorageError("plan version disappeared during a read")
                result.append(plan)
            return tuple(result)

    def _fetch_plan(
        self,
        connection: sqlite3.Connection,
        plan_id: str,
        version: int,
    ) -> Plan | None:
        header = connection.execute(
            "SELECT * FROM plans WHERE plan_id = ? AND version = ?",
            (plan_id, version),
        ).fetchone()
        if header is None:
            return None
        nodes = connection.execute(
            """
            SELECT * FROM plan_nodes
            WHERE plan_id = ? AND plan_version = ? ORDER BY position
            """,
            (plan_id, version),
        ).fetchall()
        return plan_from_rows(_row_dict(header), [_row_dict(row) for row in nodes])

    def _save_action_sync(self, action: ActionRecord) -> None:
        with closing(self._new_connection()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            self._validate_action_evidence(connection, action)
            existing_row = connection.execute(
                "SELECT * FROM actions WHERE id = ?", (action.id,)
            ).fetchone()
            if existing_row is not None:
                existing = action_from_row(_row_dict(existing_row))
                self._validate_action_update(existing, action)
                if existing == action:
                    return
            try:
                connection.execute(
                    """
                    INSERT INTO actions (
                        id, run_id, plan_node_id, agent_id, tool_name, arguments_json,
                        started_at, finished_at, duration_ms, success, exit_code,
                        error, evidence_ids_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        finished_at = excluded.finished_at,
                        duration_ms = excluded.duration_ms,
                        success = excluded.success,
                        exit_code = excluded.exit_code,
                        error = excluded.error,
                        evidence_ids_json = excluded.evidence_ids_json
                    """,
                    _action_values(action),
                )
            except sqlite3.IntegrityError as error:
                raise StorageReferenceError("action refers to a missing run") from error

    @staticmethod
    def _validate_action_evidence(
        connection: sqlite3.Connection,
        action: ActionRecord,
    ) -> None:
        for evidence_id in action.evidence_ids:
            row = connection.execute(
                "SELECT run_id, action_id FROM evidence WHERE id = ?", (evidence_id,)
            ).fetchone()
            if row is None or row["run_id"] != action.run_id or row["action_id"] != action.id:
                raise StorageReferenceError(
                    f"action evidence {evidence_id!r} has invalid run/action provenance"
                )

    @staticmethod
    def _validate_action_update(existing: ActionRecord, proposed: ActionRecord) -> None:
        static_existing = (
            existing.run_id,
            existing.plan_node_id,
            existing.agent_id,
            existing.tool_name,
            existing.arguments,
            existing.started_at,
        )
        static_proposed = (
            proposed.run_id,
            proposed.plan_node_id,
            proposed.agent_id,
            proposed.tool_name,
            proposed.arguments,
            proposed.started_at,
        )
        if static_existing != static_proposed:
            raise StorageConflictError(f"action {proposed.id!r} has conflicting identity data")
        if existing.is_finished and not proposed.is_finished:
            raise StorageConflictError("a finished action cannot become unfinished")
        if existing.is_finished and proposed.is_finished:
            stored_result = (
                existing.finished_at,
                existing.duration_ms,
                existing.success,
                existing.exit_code,
                existing.error,
            )
            proposed_result = (
                proposed.finished_at,
                proposed.duration_ms,
                proposed.success,
                proposed.exit_code,
                proposed.error,
            )
            if stored_result != proposed_result:
                raise StorageConflictError("a finished action result is immutable")
            if not set(existing.evidence_ids).issubset(proposed.evidence_ids):
                raise StorageConflictError("action evidence references are append-only")

    def _get_action_sync(self, action_id: str) -> ActionRecord | None:
        with closing(self._new_connection()) as connection:
            row = connection.execute("SELECT * FROM actions WHERE id = ?", (action_id,)).fetchone()
            return None if row is None else action_from_row(_row_dict(row))

    def _list_actions_sync(
        self,
        run_id: str,
        plan_node_id: str | None,
    ) -> tuple[ActionRecord, ...]:
        with closing(self._new_connection()) as connection:
            if plan_node_id is None:
                rows = connection.execute(
                    "SELECT * FROM actions WHERE run_id = ? ORDER BY rowid", (run_id,)
                ).fetchall()
            else:
                rows = connection.execute(
                    """
                    SELECT * FROM actions
                    WHERE run_id = ? AND plan_node_id = ? ORDER BY rowid
                    """,
                    (run_id, plan_node_id),
                ).fetchall()
            return tuple(action_from_row(_row_dict(row)) for row in rows)

    def _save_evidence_sync(self, evidence: Evidence) -> None:
        if not evidence.verify_hash():
            raise CorruptEvidenceError(
                f"evidence {evidence.id!r} failed integrity validation before storage"
            )
        with closing(self._new_connection()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            existing_row = connection.execute(
                "SELECT * FROM evidence WHERE id = ?", (evidence.id,)
            ).fetchone()
            if existing_row is not None:
                existing = self._decode_evidence(existing_row)
                if existing == evidence:
                    return
                raise StorageConflictError(
                    f"evidence {evidence.id!r} is immutable and already exists"
                )
            try:
                connection.execute(
                    """
                    INSERT INTO evidence (
                        id, run_id, action_id, type, source, summary, raw_content,
                        content_hash, created_at, metadata_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        evidence.id,
                        evidence.run_id,
                        evidence.action_id,
                        evidence.type.value,
                        evidence.source,
                        evidence.summary,
                        evidence.raw_content,
                        evidence.content_hash,
                        encode_datetime(evidence.created_at),
                        dump_json(evidence.metadata),
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise StorageReferenceError(
                    "evidence run/action provenance is missing or belongs to another run"
                ) from error

    def _get_evidence_sync(self, evidence_id: str) -> Evidence | None:
        with closing(self._new_connection()) as connection:
            row = connection.execute(
                "SELECT * FROM evidence WHERE id = ?", (evidence_id,)
            ).fetchone()
            return None if row is None else self._decode_evidence(row)

    def _list_evidence_sync(self, run_id: str) -> tuple[Evidence, ...]:
        with closing(self._new_connection()) as connection:
            return self._fetch_evidence_many(
                connection,
                "SELECT * FROM evidence WHERE run_id = ? ORDER BY rowid",
                (run_id,),
            )

    def _search_evidence_sync(
        self,
        run_id: str,
        query: str,
        limit: int,
    ) -> tuple[Evidence, ...]:
        escaped = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        pattern = f"%{escaped}%"
        with closing(self._new_connection()) as connection:
            return self._fetch_evidence_many(
                connection,
                """
                SELECT * FROM evidence
                WHERE run_id = ? AND (
                    summary LIKE ? ESCAPE '\\' OR
                    raw_content LIKE ? ESCAPE '\\' OR
                    source LIKE ? ESCAPE '\\'
                )
                ORDER BY rowid
                LIMIT ?
                """,
                (run_id, pattern, pattern, pattern, limit),
            )

    def _fetch_evidence_many(
        self,
        connection: sqlite3.Connection,
        statement: str,
        parameters: tuple[object, ...],
    ) -> tuple[Evidence, ...]:
        rows = connection.execute(statement, parameters).fetchall()
        return tuple(self._decode_evidence(row) for row in rows)

    @staticmethod
    def _decode_evidence(row: sqlite3.Row) -> Evidence:
        values = _row_dict(row)
        evidence_id = _row_str(row, "id")
        raw_content = _row_str(row, "raw_content", allow_empty=True)
        stored_hash = _row_str(row, "content_hash")
        computed_hash = content_digest(raw_content)
        if not hmac.compare_digest(stored_hash, computed_hash):
            raise CorruptEvidenceError(
                f"evidence {evidence_id!r} is corrupt: stored SHA-256 does not match raw content"
            )
        return evidence_from_row_values(values, verified_hash=stored_hash)

    def _save_finding_sync(self, finding: Finding) -> None:
        with closing(self._new_connection()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            self._validate_finding_evidence(connection, finding)
            existing_row = connection.execute(
                "SELECT * FROM findings WHERE id = ?", (finding.id,)
            ).fetchone()
            if existing_row is not None:
                existing = finding_from_row(_row_dict(existing_row))
                self._validate_finding_update(existing, finding)
                if existing == finding:
                    return
            try:
                connection.execute(
                    """
                    INSERT INTO findings (
                        id, run_id, title, description, severity, confidence,
                        evidence_ids_json, status, created_at, subject, fingerprint
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        evidence_ids_json = excluded.evidence_ids_json,
                        status = excluded.status
                    """,
                    (
                        finding.id,
                        finding.run_id,
                        finding.title,
                        finding.description,
                        finding.severity.value,
                        finding.confidence,
                        dump_json(list(finding.evidence_ids)),
                        finding.status.value,
                        encode_datetime(finding.created_at),
                        finding.subject,
                        finding.fingerprint,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise StorageReferenceError("finding refers to a missing run") from error

    @staticmethod
    def _validate_finding_evidence(
        connection: sqlite3.Connection,
        finding: Finding,
    ) -> None:
        for evidence_id in finding.evidence_ids:
            row = connection.execute(
                "SELECT run_id, action_id FROM evidence WHERE id = ?", (evidence_id,)
            ).fetchone()
            if row is None or row["run_id"] != finding.run_id:
                raise StorageReferenceError(
                    f"finding evidence {evidence_id!r} is missing or belongs to another run"
                )
            if finding.status is FindingStatus.VERIFIED and row["action_id"] is None:
                raise StorageReferenceError(
                    f"verified finding evidence {evidence_id!r} has no tool action provenance"
                )

    @staticmethod
    def _validate_finding_update(existing: Finding, proposed: Finding) -> None:
        static_existing = (
            existing.run_id,
            existing.title,
            existing.description,
            existing.severity,
            existing.confidence,
            existing.subject,
            existing.fingerprint,
            existing.created_at,
        )
        static_proposed = (
            proposed.run_id,
            proposed.title,
            proposed.description,
            proposed.severity,
            proposed.confidence,
            proposed.subject,
            proposed.fingerprint,
            proposed.created_at,
        )
        if static_existing != static_proposed:
            raise StorageConflictError(f"finding {proposed.id!r} has conflicting identity data")
        if not set(existing.evidence_ids).issubset(proposed.evidence_ids):
            raise StorageConflictError("finding evidence references are append-only")
        if (
            proposed.status is not existing.status
            and proposed.status not in _FINDING_TRANSITIONS[existing.status]
        ):
            raise StorageConflictError("finding status transition is not allowed")

    def _list_findings_sync(self, run_id: str) -> tuple[Finding, ...]:
        with closing(self._new_connection()) as connection:
            return self._fetch_findings_many(
                connection,
                "SELECT * FROM findings WHERE run_id = ? ORDER BY rowid",
                (run_id,),
            )

    @staticmethod
    def _fetch_findings_many(
        connection: sqlite3.Connection,
        statement: str,
        parameters: tuple[object, ...],
    ) -> tuple[Finding, ...]:
        rows = connection.execute(statement, parameters).fetchall()
        return tuple(finding_from_row(_row_dict(row)) for row in rows)

    def _publish_sync(self, event: RunEvent) -> None:
        if not isinstance(event.created_at, datetime):
            raise ValueError("event.created_at must be a datetime")
        with closing(self._new_connection()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT * FROM events WHERE id = ?", (event.id,)
            ).fetchone()
            values = (
                event.id,
                event.run_id,
                event.event_type.value,
                dump_json(event.payload),
                encode_datetime(event.created_at),
            )
            if existing is not None:
                stored = tuple(
                    existing[key]
                    for key in ("id", "run_id", "event_type", "payload_json", "created_at")
                )
                if stored == values:
                    return
                raise StorageConflictError(f"event {event.id!r} already exists")
            try:
                connection.execute(
                    """
                    INSERT INTO events (id, run_id, event_type, payload_json, created_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    values,
                )
            except sqlite3.IntegrityError as error:
                raise StorageReferenceError("event refers to a missing run") from error


def _action_values(action: ActionRecord) -> tuple[object, ...]:
    return (
        action.id,
        action.run_id,
        action.plan_node_id,
        action.agent_id,
        action.tool_name,
        dump_json(action.arguments),
        encode_datetime(action.started_at),
        None if action.finished_at is None else encode_datetime(action.finished_at),
        action.duration_ms,
        None if action.success is None else int(action.success),
        action.exit_code,
        action.error,
        dump_json(list(action.evidence_ids)),
    )


def _run_snapshot(run: RunState) -> tuple[object, ...]:
    return (
        None if run.plan is None else run.plan.id,
        None if run.plan is None else run.plan.version,
        run.status.value,
        dump_json(list(run.current_nodes)),
        encode_datetime(run.updated_at),
        None if run.finished_at is None else encode_datetime(run.finished_at),
        run.step_count,
        run.replan_count,
        run.last_error,
    )


def _stored_run_snapshot(row: sqlite3.Row) -> tuple[object, ...]:
    return tuple(
        row[key]
        for key in (
            "plan_id",
            "plan_version",
            "status",
            "current_nodes_json",
            "updated_at",
            "finished_at",
            "step_count",
            "replan_count",
            "last_error",
        )
    )


def _plan_structure(plan: Plan) -> tuple[object, ...]:
    return (
        plan.id,
        plan.task_id,
        plan.version,
        plan.created_at,
        tuple(_node_structure(node) for node in plan.nodes),
    )


def _node_structure(node: PlanNode) -> tuple[object, ...]:
    return (
        node.id,
        node.goal,
        node.description,
        node.assigned_agent,
        node.required_capabilities,
        node.dependencies,
        node.success_criteria,
        node.max_attempts,
        node.created_at,
    )


def _row_dict(row: sqlite3.Row) -> dict[str, object]:
    return {key: row[key] for key in row.keys()}


def _row_str(row: sqlite3.Row, key: str, *, allow_empty: bool = False) -> str:
    value = row[key]
    if not isinstance(value, str) or (not allow_empty and not value):
        raise CorruptStorageError(f"SQLite column {key!r} is not a valid string")
    return value


def _row_int(row: sqlite3.Row, key: str) -> int:
    value = row[key]
    if isinstance(value, bool) or not isinstance(value, int):
        raise CorruptStorageError(f"SQLite column {key!r} is not an integer")
    return int(value)


def _require_non_blank(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-blank string")
