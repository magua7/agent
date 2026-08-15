"""Ports owned by the product application layer."""

from __future__ import annotations

from typing import Protocol

from security_agent.application.models import (
    EventPage,
    ProductTask,
    ProductUser,
    TaskProjection,
    TaskStatus,
)
from security_agent.domain import TaskSpec


class ProductRepository(Protocol):
    async def initialize(self) -> None: ...

    async def close(self) -> None: ...

    async def create_user(
        self,
        username: str,
        password_hash: str,
        *,
        user_id: str | None = None,
    ) -> ProductUser: ...

    async def get_user_by_username(self, username: str) -> ProductUser | None: ...

    async def get_user(self, user_id: str) -> ProductUser | None: ...

    async def create_task(
        self,
        user_id: str,
        title: str,
        description: str,
        *,
        task_spec: TaskSpec | None = None,
        task_id: str | None = None,
    ) -> ProductTask: ...

    async def get_task(self, user_id: str, task_id: str) -> ProductTask | None: ...

    async def list_tasks(
        self,
        user_id: str,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[ProductTask, ...]: ...

    async def update_task(
        self,
        user_id: str,
        task_id: str,
        *,
        title: str | None = None,
        description: str | None = None,
        task_spec: TaskSpec | None = None,
    ) -> ProductTask | None: ...

    async def delete_task(self, user_id: str, task_id: str) -> bool: ...

    async def bind_run(
        self,
        user_id: str,
        task_id: str,
        run_id: str,
    ) -> ProductTask | None: ...

    async def update_task_status(
        self,
        user_id: str,
        task_id: str,
        status: TaskStatus,
    ) -> ProductTask | None: ...

    async def get_task_projection(
        self,
        user_id: str,
        task_id: str,
    ) -> TaskProjection | None: ...

    async def list_task_events(
        self,
        user_id: str,
        task_id: str,
        *,
        after_sequence: int = 0,
        limit: int = 100,
    ) -> EventPage | None: ...
