"""SQLite-backed product projection layered over the durable kernel store.

The product tables deliberately live in the same database as the kernel audit
tables.  They add ownership and UI-friendly task lifecycle state without
duplicating (or weakening) the authoritative run, plan, action, evidence,
finding, and event records.
"""

from __future__ import annotations

import asyncio
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import cast

from security_agent.application.models import (
    EventPage,
    ProductRunEvent,
    ProductTask,
    ProductUser,
    TaskProjection,
    TaskStatus,
)
from security_agent.contracts import EventType, RunEvent
from security_agent.domain import RunStatus, TaskSpec, new_id, utc_now
from security_agent.infrastructure.storage.codec import (
    CorruptStorageError,
    decode_datetime,
    encode_datetime,
    load_object,
    task_from_json,
    task_to_json,
)
from security_agent.infrastructure.storage.sqlite import SQLiteStore

PRODUCT_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL COLLATE NOCASE UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    task_spec_json TEXT,
    status TEXT NOT NULL CHECK (
        status IN ('draft', 'queued', 'running', 'completed', 'failed', 'cancelled')
    ),
    run_id TEXT UNIQUE,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_tasks_user_updated
    ON tasks(user_id, updated_at DESC, id);
CREATE INDEX IF NOT EXISTS idx_tasks_user_created
    ON tasks(user_id, created_at DESC, id);
"""


class ProductStorageError(RuntimeError):
    """Base class for failures at the product persistence boundary."""


class ProductConflictError(ProductStorageError):
    """A product identity or lifecycle transition conflicts with stored state."""


class ProductReferenceError(ProductStorageError):
    """A product record refers to a missing owner or kernel object."""


_TASK_TRANSITIONS: dict[TaskStatus, frozenset[TaskStatus]] = {
    TaskStatus.DRAFT: frozenset({TaskStatus.QUEUED, TaskStatus.CANCELLED}),
    TaskStatus.QUEUED: frozenset({TaskStatus.RUNNING, TaskStatus.FAILED, TaskStatus.CANCELLED}),
    TaskStatus.RUNNING: frozenset({TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED}),
    TaskStatus.COMPLETED: frozenset(),
    TaskStatus.FAILED: frozenset(),
    TaskStatus.CANCELLED: frozenset(),
}


class SQLiteProductStore:
    """User-scoped task repository and bounded read model for SEC-GO.

    ``kernel_store`` is intentionally exposed so composition roots can use one
    initialized object for both product operations and kernel persistence.
    """

    def __init__(self, database: str | Path) -> None:
        self._kernel_store = SQLiteStore(database)
        self._database = self._kernel_store.database
        self._uri = self._database.startswith("file:")
        self._initialized = False
        self._initialize_lock = asyncio.Lock()
        self._write_lock = asyncio.Lock()

    @property
    def database(self) -> str:
        return self._database

    @property
    def kernel_store(self) -> SQLiteStore:
        return self._kernel_store

    async def initialize(self) -> None:
        if self._initialized:
            return
        async with self._initialize_lock:
            if self._is_initialized():
                return
            await self._kernel_store.initialize()
            try:
                await asyncio.to_thread(self._initialize_sync)
            except Exception:
                await self._kernel_store.close()
                raise
            self._initialized = True

    def _is_initialized(self) -> bool:
        return self._initialized

    async def close(self) -> None:
        async with self._write_lock:
            self._initialized = False
            await self._kernel_store.close()

    async def create_user(
        self,
        username: str,
        password_hash: str,
        *,
        user_id: str | None = None,
    ) -> ProductUser:
        await self.initialize()
        normalized_username = _normalized_username(username)
        user = ProductUser(
            id=user_id or new_id(),
            username=normalized_username,
            password_hash=password_hash,
        )
        async with self._write_lock:
            await asyncio.to_thread(self._create_user_sync, user)
        return user

    async def get_user_by_username(self, username: str) -> ProductUser | None:
        await self.initialize()
        normalized_username = _normalized_username(username)
        return await asyncio.to_thread(self._get_user_by_username_sync, normalized_username)

    async def get_user(self, user_id: str) -> ProductUser | None:
        await self.initialize()
        _require_identifier(user_id, "user_id")
        return await asyncio.to_thread(self._get_user_sync, user_id)

    async def create_task(
        self,
        user_id: str,
        title: str,
        description: str,
        *,
        task_spec: TaskSpec | None = None,
        task_id: str | None = None,
    ) -> ProductTask:
        await self.initialize()
        _require_identifier(user_id, "user_id")
        task = ProductTask.create(
            user_id=user_id,
            title=title,
            description=description,
            task_spec=task_spec,
            id=task_id,
        )
        async with self._write_lock:
            await asyncio.to_thread(self._create_task_sync, task)
        return task

    async def get_task(self, user_id: str, task_id: str) -> ProductTask | None:
        await self.initialize()
        _require_identifier(user_id, "user_id")
        _require_identifier(task_id, "task_id")
        return await asyncio.to_thread(self._get_task_sync, user_id, task_id)

    async def list_tasks(
        self,
        user_id: str,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[ProductTask, ...]:
        await self.initialize()
        _require_identifier(user_id, "user_id")
        _validate_page(limit, offset)
        return await asyncio.to_thread(self._list_tasks_sync, user_id, limit, offset)

    async def update_task(
        self,
        user_id: str,
        task_id: str,
        *,
        title: str | None = None,
        description: str | None = None,
        task_spec: TaskSpec | None = None,
    ) -> ProductTask | None:
        await self.initialize()
        _require_identifier(user_id, "user_id")
        _require_identifier(task_id, "task_id")
        async with self._write_lock:
            return await asyncio.to_thread(
                self._update_task_sync,
                user_id,
                task_id,
                title,
                description,
                task_spec,
            )

    async def delete_task(self, user_id: str, task_id: str) -> bool:
        await self.initialize()
        _require_identifier(user_id, "user_id")
        _require_identifier(task_id, "task_id")
        async with self._write_lock:
            return await asyncio.to_thread(self._delete_task_sync, user_id, task_id)

    async def bind_run(
        self,
        user_id: str,
        task_id: str,
        run_id: str,
    ) -> ProductTask | None:
        """Pre-bind a run identity before the kernel creates its run row."""
        await self.initialize()
        _require_identifier(user_id, "user_id")
        _require_identifier(task_id, "task_id")
        _require_identifier(run_id, "run_id")
        async with self._write_lock:
            return await asyncio.to_thread(self._bind_run_sync, user_id, task_id, run_id)

    async def update_task_status(
        self,
        user_id: str,
        task_id: str,
        status: TaskStatus,
    ) -> ProductTask | None:
        await self.initialize()
        _require_identifier(user_id, "user_id")
        _require_identifier(task_id, "task_id")
        if not isinstance(status, TaskStatus):
            raise ValueError("status must be a TaskStatus")
        async with self._write_lock:
            return await asyncio.to_thread(self._update_task_status_sync, user_id, task_id, status)

    async def get_task_projection(
        self,
        user_id: str,
        task_id: str,
    ) -> TaskProjection | None:
        await self.initialize()
        _require_identifier(user_id, "user_id")
        _require_identifier(task_id, "task_id")
        return await asyncio.to_thread(self._get_task_projection_sync, user_id, task_id)

    async def list_task_events(
        self,
        user_id: str,
        task_id: str,
        *,
        after_sequence: int = 0,
        limit: int = 100,
    ) -> EventPage | None:
        await self.initialize()
        _require_identifier(user_id, "user_id")
        _require_identifier(task_id, "task_id")
        _validate_event_page(after_sequence, limit)
        return await asyncio.to_thread(
            self._list_task_events_sync,
            user_id,
            task_id,
            after_sequence,
            limit,
        )

    def _initialize_sync(self) -> None:
        with closing(self._new_connection()) as connection, connection:
            connection.executescript(PRODUCT_SCHEMA)

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

    def _create_user_sync(self, user: ProductUser) -> None:
        with closing(self._new_connection()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                connection.execute(
                    """
                    INSERT INTO users (id, username, password_hash, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        user.id,
                        user.username,
                        user.password_hash,
                        encode_datetime(user.created_at),
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise ProductConflictError("user id or username already exists") from error

    def _get_user_by_username_sync(self, username: str) -> ProductUser | None:
        with closing(self._new_connection()) as connection:
            row = connection.execute(
                "SELECT * FROM users WHERE username = ? COLLATE NOCASE",
                (username,),
            ).fetchone()
            return None if row is None else _user_from_row(row)

    def _get_user_sync(self, user_id: str) -> ProductUser | None:
        with closing(self._new_connection()) as connection:
            row = connection.execute(
                "SELECT * FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()
            return None if row is None else _user_from_row(row)

    def _create_task_sync(self, task: ProductTask) -> None:
        with closing(self._new_connection()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            owner = connection.execute(
                "SELECT 1 FROM users WHERE id = ?",
                (task.user_id,),
            ).fetchone()
            if owner is None:
                raise ProductReferenceError("task owner does not exist")
            try:
                connection.execute(
                    """
                    INSERT INTO tasks (
                        id, user_id, title, description, task_spec_json, status,
                        run_id, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    _task_values(task),
                )
            except sqlite3.IntegrityError as error:
                raise ProductConflictError("task id already exists") from error

    def _get_task_sync(self, user_id: str, task_id: str) -> ProductTask | None:
        with closing(self._new_connection()) as connection:
            row = connection.execute(
                "SELECT * FROM tasks WHERE id = ? AND user_id = ?",
                (task_id, user_id),
            ).fetchone()
            return None if row is None else _task_from_row(row)

    def _list_tasks_sync(
        self,
        user_id: str,
        limit: int,
        offset: int,
    ) -> tuple[ProductTask, ...]:
        with closing(self._new_connection()) as connection:
            rows = connection.execute(
                """
                SELECT * FROM tasks
                WHERE user_id = ?
                ORDER BY updated_at DESC, id
                LIMIT ? OFFSET ?
                """,
                (user_id, limit, offset),
            ).fetchall()
            return tuple(_task_from_row(row) for row in rows)

    def _update_task_sync(
        self,
        user_id: str,
        task_id: str,
        title: str | None,
        description: str | None,
        task_spec: TaskSpec | None,
    ) -> ProductTask | None:
        with closing(self._new_connection()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM tasks WHERE id = ? AND user_id = ?",
                (task_id, user_id),
            ).fetchone()
            if row is None:
                return None
            stored = _task_from_row(row)
            if title is None and description is None and task_spec is None:
                return stored
            if stored.status is not TaskStatus.DRAFT or stored.run_id is not None:
                raise ProductConflictError("only an unbound draft task can be edited")
            updated = ProductTask(
                id=stored.id,
                user_id=stored.user_id,
                title=stored.title if title is None else title,
                description=stored.description if description is None else description,
                task_spec=stored.task_spec if task_spec is None else task_spec,
                status=stored.status,
                created_at=stored.created_at,
                updated_at=utc_now(),
            )
            connection.execute(
                """
                UPDATE tasks
                SET title = ?, description = ?, task_spec_json = ?, updated_at = ?
                WHERE id = ? AND user_id = ?
                """,
                (
                    updated.title,
                    updated.description,
                    None if updated.task_spec is None else task_to_json(updated.task_spec),
                    encode_datetime(updated.updated_at),
                    task_id,
                    user_id,
                ),
            )
            return updated

    def _delete_task_sync(self, user_id: str, task_id: str) -> bool:
        with closing(self._new_connection()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT status, run_id FROM tasks WHERE id = ? AND user_id = ?",
                (task_id, user_id),
            ).fetchone()
            if row is None:
                return False
            if _row_str(row, "status") != TaskStatus.DRAFT.value or row["run_id"] is not None:
                raise ProductConflictError("only an unbound draft task can be deleted")
            connection.execute(
                "DELETE FROM tasks WHERE id = ? AND user_id = ?",
                (task_id, user_id),
            )
            return True

    def _bind_run_sync(
        self,
        user_id: str,
        task_id: str,
        run_id: str,
    ) -> ProductTask | None:
        with closing(self._new_connection()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM tasks WHERE id = ? AND user_id = ?",
                (task_id, user_id),
            ).fetchone()
            if row is None:
                return None
            stored = _task_from_row(row)
            if stored.run_id == run_id:
                return stored
            if stored.status is not TaskStatus.DRAFT or stored.run_id is not None:
                raise ProductConflictError("task is already bound or no longer a draft")
            if stored.task_spec is None:
                raise ProductConflictError("task requires an executable TaskSpec before binding")
            updated = ProductTask(
                id=stored.id,
                user_id=stored.user_id,
                title=stored.title,
                description=stored.description,
                task_spec=stored.task_spec,
                status=TaskStatus.QUEUED,
                run_id=run_id,
                created_at=stored.created_at,
                updated_at=utc_now(),
            )
            try:
                connection.execute(
                    """
                    UPDATE tasks
                    SET status = ?, run_id = ?, updated_at = ?
                    WHERE id = ? AND user_id = ?
                    """,
                    (
                        updated.status.value,
                        updated.run_id,
                        encode_datetime(updated.updated_at),
                        task_id,
                        user_id,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise ProductConflictError("run id is already bound to another task") from error
            return updated

    def _update_task_status_sync(
        self,
        user_id: str,
        task_id: str,
        status: TaskStatus,
    ) -> ProductTask | None:
        with closing(self._new_connection()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM tasks WHERE id = ? AND user_id = ?",
                (task_id, user_id),
            ).fetchone()
            if row is None:
                return None
            stored = _task_from_row(row)
            if stored.status is status:
                return stored
            if status not in _TASK_TRANSITIONS[stored.status]:
                raise ProductConflictError(
                    f"task status cannot move from {stored.status.value} to {status.value}"
                )
            if status in {TaskStatus.QUEUED, TaskStatus.RUNNING, TaskStatus.COMPLETED}:
                if stored.run_id is None:
                    raise ProductConflictError(f"{status.value} task requires a bound run")
            updated = ProductTask(
                id=stored.id,
                user_id=stored.user_id,
                title=stored.title,
                description=stored.description,
                task_spec=stored.task_spec,
                status=status,
                run_id=stored.run_id,
                created_at=stored.created_at,
                updated_at=utc_now(),
            )
            connection.execute(
                "UPDATE tasks SET status = ?, updated_at = ? WHERE id = ? AND user_id = ?",
                (status.value, encode_datetime(updated.updated_at), task_id, user_id),
            )
            return updated

    def _get_task_projection_sync(
        self,
        user_id: str,
        task_id: str,
    ) -> TaskProjection | None:
        with closing(self._new_connection()) as connection:
            task_row = connection.execute(
                "SELECT * FROM tasks WHERE id = ? AND user_id = ?",
                (task_id, user_id),
            ).fetchone()
            if task_row is None:
                return None
            task = _task_from_row(task_row)
            if task.run_id is None:
                return TaskProjection(task=task)
            run_row = connection.execute(
                """
                SELECT
                    runs.status,
                    runs.updated_at,
                    runs.last_error,
                    (
                        SELECT COUNT(*) FROM plan_nodes
                        WHERE plan_id = runs.plan_id
                          AND plan_version = runs.plan_version
                    ) AS plan_node_count,
                    (SELECT COUNT(*) FROM actions WHERE run_id = runs.run_id) AS action_count,
                    (SELECT COUNT(*) FROM evidence WHERE run_id = runs.run_id) AS evidence_count,
                    (SELECT COUNT(*) FROM findings WHERE run_id = runs.run_id) AS finding_count,
                    COALESCE(
                        (SELECT MAX(events.rowid) FROM events WHERE run_id = runs.run_id),
                        0
                    ) AS last_event_sequence
                FROM runs
                WHERE runs.run_id = ?
                """,
                (task.run_id,),
            ).fetchone()
            if run_row is None:
                return TaskProjection(task=task)
            try:
                run_status = RunStatus(_row_str(run_row, "status"))
            except ValueError as error:
                raise CorruptStorageError("invalid run status in runs.status") from error
            last_error = run_row["last_error"]
            if last_error is not None and not isinstance(last_error, str):
                raise CorruptStorageError("runs.last_error must be text or null")
            return TaskProjection(
                task=task,
                run_status=run_status,
                run_updated_at=decode_datetime(_row_str(run_row, "updated_at"), "runs.updated_at"),
                plan_node_count=_row_int(run_row, "plan_node_count"),
                action_count=_row_int(run_row, "action_count"),
                evidence_count=_row_int(run_row, "evidence_count"),
                finding_count=_row_int(run_row, "finding_count"),
                last_event_sequence=_row_int(run_row, "last_event_sequence"),
                last_error=last_error,
            )

    def _list_task_events_sync(
        self,
        user_id: str,
        task_id: str,
        after_sequence: int,
        limit: int,
    ) -> EventPage | None:
        with closing(self._new_connection()) as connection:
            task_row = connection.execute(
                "SELECT run_id FROM tasks WHERE id = ? AND user_id = ?",
                (task_id, user_id),
            ).fetchone()
            if task_row is None:
                return None
            run_id_raw = task_row["run_id"]
            if run_id_raw is None:
                return EventPage((), after_sequence, False)
            if not isinstance(run_id_raw, str) or not run_id_raw:
                raise CorruptStorageError("tasks.run_id must be non-empty text or null")
            rows = connection.execute(
                """
                SELECT rowid AS event_sequence, *
                FROM events
                WHERE run_id = ? AND rowid > ?
                ORDER BY rowid
                LIMIT ?
                """,
                (run_id_raw, after_sequence, limit + 1),
            ).fetchall()
            has_more = len(rows) > limit
            page_rows = rows[:limit]
            events = tuple(_event_from_row(row) for row in page_rows)
            next_cursor = events[-1].sequence if events else after_sequence
            return EventPage(events, next_cursor, has_more)


def _normalized_username(username: str) -> str:
    if not isinstance(username, str):
        raise ValueError("username must be text")
    normalized = username.strip()
    if (
        not normalized
        or len(normalized) > 128
        or any(character.isspace() for character in normalized)
    ):
        raise ValueError(
            "username must be non-empty, contain no whitespace, and fit 128 characters"
        )
    return normalized


def _require_identifier(value: str, label: str) -> None:
    if not isinstance(value, str) or not value.strip() or len(value) > 128:
        raise ValueError(f"{label} must be non-empty text of at most 128 characters")


def _validate_page(limit: int, offset: int) -> None:
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
        raise ValueError("limit must be an integer between 1 and 500")
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise ValueError("offset must be a non-negative integer")


def _validate_event_page(after_sequence: int, limit: int) -> None:
    if (
        isinstance(after_sequence, bool)
        or not isinstance(after_sequence, int)
        or after_sequence < 0
    ):
        raise ValueError("after_sequence must be a non-negative integer")
    _validate_page(limit, 0)


def _user_from_row(row: sqlite3.Row) -> ProductUser:
    return ProductUser(
        id=_row_str(row, "id"),
        username=_row_str(row, "username"),
        password_hash=_row_str(row, "password_hash"),
        created_at=decode_datetime(_row_str(row, "created_at"), "users.created_at"),
    )


def _task_from_row(row: sqlite3.Row) -> ProductTask:
    raw_task_spec = row["task_spec_json"]
    if raw_task_spec is not None and not isinstance(raw_task_spec, str):
        raise CorruptStorageError("tasks.task_spec_json must be text or null")
    run_id = row["run_id"]
    if run_id is not None and (not isinstance(run_id, str) or not run_id):
        raise CorruptStorageError("tasks.run_id must be non-empty text or null")
    try:
        status = TaskStatus(_row_str(row, "status"))
        return ProductTask(
            id=_row_str(row, "id"),
            user_id=_row_str(row, "user_id"),
            title=_row_str(row, "title"),
            description=_row_str(row, "description"),
            task_spec=None if raw_task_spec is None else task_from_json(raw_task_spec),
            status=status,
            run_id=run_id,
            created_at=decode_datetime(_row_str(row, "created_at"), "tasks.created_at"),
            updated_at=decode_datetime(_row_str(row, "updated_at"), "tasks.updated_at"),
        )
    except ValueError as error:
        raise CorruptStorageError("invalid ProductTask in SQLite") from error


def _task_values(task: ProductTask) -> tuple[object, ...]:
    return (
        task.id,
        task.user_id,
        task.title,
        task.description,
        None if task.task_spec is None else task_to_json(task.task_spec),
        task.status.value,
        task.run_id,
        encode_datetime(task.created_at),
        encode_datetime(task.updated_at),
    )


def _event_from_row(row: sqlite3.Row) -> ProductRunEvent:
    try:
        event = RunEvent(
            event_type=EventType(_row_str(row, "event_type")),
            run_id=_row_str(row, "run_id"),
            payload=load_object(_row_str(row, "payload_json"), "events.payload_json"),
            id=_row_str(row, "id"),
            created_at=decode_datetime(_row_str(row, "created_at"), "events.created_at"),
        )
        return ProductRunEvent(sequence=_row_int(row, "event_sequence"), event=event)
    except ValueError as error:
        raise CorruptStorageError("invalid RunEvent in SQLite") from error


def _row_str(row: sqlite3.Row, name: str) -> str:
    value = row[name]
    if not isinstance(value, str):
        raise CorruptStorageError(f"{name} must be text")
    return value


def _row_int(row: sqlite3.Row, name: str) -> int:
    value = row[name]
    if isinstance(value, bool) or not isinstance(value, int):
        raise CorruptStorageError(f"{name} must be an integer")
    return cast(int, value)
