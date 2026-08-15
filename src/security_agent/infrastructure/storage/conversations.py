"""Lightweight SQLite persistence for assistant conversations.

Conversations keep only bounded message rows (role, content, kind, task_id,
created_at).  Raw Evidence, plans, and reports stay in the kernel tables; the
assistant references them by task_id only.
"""

from __future__ import annotations

import asyncio
import sqlite3
from contextlib import closing
from pathlib import Path

from security_agent.application.models import ConversationMessage
from security_agent.domain import utc_now
from security_agent.infrastructure.storage.codec import decode_datetime, encode_datetime
from security_agent.infrastructure.storage.product import ProductReferenceError

CONVERSATION_SCHEMA = """
CREATE TABLE IF NOT EXISTS conversations (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS conversation_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('user', 'assistant', 'system')),
    content TEXT NOT NULL,
    kind TEXT NOT NULL,
    task_id TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_conversation_messages_conversation
    ON conversation_messages(conversation_id, id);
"""


class SQLiteConversationStore:
    """Conversation rows stored in the same database as the product tasks."""

    def __init__(self, database: str | Path) -> None:
        self._database = str(database)
        self._uri = self._database.startswith("file:")
        self._initialized = False
        self._initialize_lock = asyncio.Lock()
        self._write_lock = asyncio.Lock()

    async def initialize(self) -> None:
        if self._is_initialized():
            return
        async with self._initialize_lock:
            if self._is_initialized():
                return
            await asyncio.to_thread(self._initialize_sync)
            self._initialized = True

    def _is_initialized(self) -> bool:
        return self._initialized

    async def close(self) -> None:
        self._initialized = False

    async def ensure_conversation(self, user_id: str, conversation_id: str) -> None:
        await self.initialize()
        _require_identifier(user_id, "user_id")
        _require_identifier(conversation_id, "conversation_id")
        async with self._write_lock:
            await asyncio.to_thread(
                self._ensure_conversation_sync,
                user_id,
                conversation_id,
            )

    async def record_message(
        self,
        conversation_id: str,
        *,
        role: str,
        content: str,
        kind: str,
        task_id: str | None = None,
    ) -> ConversationMessage:
        await self.initialize()
        _require_identifier(conversation_id, "conversation_id")
        if role not in {"user", "assistant", "system"}:
            raise ValueError("role must be user, assistant, or system")
        if not isinstance(content, str) or not content.strip():
            raise ValueError("content must be non-empty text")
        if not isinstance(kind, str) or not kind.strip():
            raise ValueError("kind must be non-empty text")
        if task_id is not None:
            _require_identifier(task_id, "task_id")
        async with self._write_lock:
            return await asyncio.to_thread(
                self._record_message_sync,
                conversation_id,
                role,
                content,
                kind,
                task_id,
            )

    async def recent_messages(
        self,
        conversation_id: str,
        *,
        limit: int,
    ) -> tuple[ConversationMessage, ...]:
        await self.initialize()
        _require_identifier(conversation_id, "conversation_id")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ValueError("limit must be an integer between 1 and 100")
        return await asyncio.to_thread(self._recent_messages_sync, conversation_id, limit)

    async def last_task_id(self, conversation_id: str) -> str | None:
        await self.initialize()
        _require_identifier(conversation_id, "conversation_id")
        return await asyncio.to_thread(self._last_task_id_sync, conversation_id)

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

    def _initialize_sync(self) -> None:
        with closing(self._new_connection()) as connection, connection:
            connection.executescript(CONVERSATION_SCHEMA)

    def _ensure_conversation_sync(self, user_id: str, conversation_id: str) -> None:
        with closing(self._new_connection()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT 1 FROM conversations WHERE id = ?",
                (conversation_id,),
            ).fetchone()
            if existing is not None:
                return
            owner = connection.execute(
                "SELECT 1 FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()
            if owner is None:
                raise ProductReferenceError("conversation owner does not exist")
            timestamp = encode_datetime(utc_now())
            connection.execute(
                """
                INSERT INTO conversations (id, user_id, created_at, updated_at)
                VALUES (?, ?, ?, ?)
                """,
                (conversation_id, user_id, timestamp, timestamp),
            )

    def _record_message_sync(
        self,
        conversation_id: str,
        role: str,
        content: str,
        kind: str,
        task_id: str | None,
    ) -> ConversationMessage:
        with closing(self._new_connection()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT 1 FROM conversations WHERE id = ?",
                (conversation_id,),
            ).fetchone()
            if row is None:
                raise ProductReferenceError("conversation does not exist")
            timestamp = encode_datetime(utc_now())
            cursor = connection.execute(
                """
                INSERT INTO conversation_messages (
                    conversation_id, role, content, kind, task_id, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (conversation_id, role, content, kind, task_id, timestamp),
            )
            connection.execute(
                "UPDATE conversations SET updated_at = ? WHERE id = ?",
                (timestamp, conversation_id),
            )
            raw_message_id = cursor.lastrowid
            if raw_message_id is None:
                raise RuntimeError("sqlite did not return a message row id")
            message_id = int(raw_message_id)
        return ConversationMessage(
            id=message_id,
            conversation_id=conversation_id,
            role=role,
            content=content,
            kind=kind,
            task_id=task_id,
            created_at=decode_datetime(timestamp, "conversation_messages.created_at"),
        )

    def _recent_messages_sync(
        self,
        conversation_id: str,
        limit: int,
    ) -> tuple[ConversationMessage, ...]:
        with closing(self._new_connection()) as connection:
            rows = connection.execute(
                """
                SELECT * FROM conversation_messages
                WHERE conversation_id = ?
                ORDER BY id DESC LIMIT ?
                """,
                (conversation_id, limit),
            ).fetchall()
        return tuple(_message_from_row(row) for row in reversed(rows))

    def _last_task_id_sync(self, conversation_id: str) -> str | None:
        with closing(self._new_connection()) as connection:
            row = connection.execute(
                """
                SELECT task_id FROM conversation_messages
                WHERE conversation_id = ? AND task_id IS NOT NULL
                ORDER BY id DESC LIMIT 1
                """,
                (conversation_id,),
            ).fetchone()
        if row is None or row["task_id"] is None:
            return None
        value = row["task_id"]
        if not isinstance(value, str):
            raise ValueError("stored conversation task_id is not text")
        return value


def _message_from_row(row: sqlite3.Row) -> ConversationMessage:
    task_id = row["task_id"]
    if task_id is not None and not isinstance(task_id, str):
        raise ValueError("conversation_messages.task_id must be text or null")
    return ConversationMessage(
        id=int(row["id"]),
        conversation_id=str(row["conversation_id"]),
        role=str(row["role"]),
        content=str(row["content"]),
        kind=str(row["kind"]),
        task_id=task_id,
        created_at=decode_datetime(str(row["created_at"]), "conversation_messages.created_at"),
    )


def _require_identifier(value: str, label: str) -> None:
    if not isinstance(value, str) or not value.strip() or len(value) > 128:
        raise ValueError(f"{label} must be non-empty text of at most 128 characters")
