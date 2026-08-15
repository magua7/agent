"""Single-process background orchestration for product-owned Agent runs."""

from __future__ import annotations

import asyncio
from functools import partial

from security_agent.application.models import ProductTask, TaskStatus
from security_agent.application.ports import ProductRepository
from security_agent.domain import RunState, RunStatus, new_id
from security_agent.engine import AgentRuntime
from security_agent.infrastructure.storage import SQLiteStore


class RunAlreadyStartedError(RuntimeError):
    pass


class RunServiceClosedError(RuntimeError):
    pass


class RunService:
    """Connect product task lifecycle to the existing verifier-gated Runtime.

    SQLite remains the durable source of run/evidence state.  The in-process task
    registry only provides bounded local concurrency and cancellation for the MVP.
    """

    def __init__(
        self,
        runtime: AgentRuntime,
        product_repository: ProductRepository,
        kernel_store: SQLiteStore,
        *,
        max_concurrent_runs: int = 2,
    ) -> None:
        if isinstance(max_concurrent_runs, bool) or max_concurrent_runs <= 0:
            raise ValueError("max_concurrent_runs must be a positive integer")
        self._runtime = runtime
        self._products = product_repository
        self._kernel = kernel_store
        self._semaphore = asyncio.Semaphore(max_concurrent_runs)
        self._active: dict[str, asyncio.Task[RunState | None]] = {}
        self._lock = asyncio.Lock()
        self._closed = False

    @property
    def active_task_ids(self) -> tuple[str, ...]:
        return tuple(self._active)

    async def start(self, task: ProductTask) -> str:
        if self._closed:
            raise RunServiceClosedError("run service is closed")
        if task.task_spec is None:
            raise ValueError("an executable task requires an explicit TaskSpec")
        async with self._lock:
            active = self._active.get(task.id)
            if active is not None and not active.done():
                if task.run_id is None:
                    raise RunAlreadyStartedError("active task has no bound run id")
                return task.run_id
            current = await self._products.get_task(task.user_id, task.id)
            if current is None:
                raise ValueError("product task no longer exists")
            if current.run_id is not None or current.status is not TaskStatus.DRAFT:
                raise RunAlreadyStartedError("product task was already started")

            run_id = new_id()
            bound = await self._products.bind_run(task.user_id, task.id, run_id)
            if bound is None:
                raise ValueError("product task could not be bound to a run")
            queued = await self._products.update_task_status(
                task.user_id,
                task.id,
                TaskStatus.QUEUED,
            )
            if queued is None:
                raise ValueError("product task disappeared while being queued")
            execution = asyncio.create_task(
                self._execute(queued, run_id),
                name=f"sec-go-run-{run_id}",
            )
            self._active[task.id] = execution
            execution.add_done_callback(partial(self._forget, task.id))
            return run_id

    async def wait(self, user_id: str, task_id: str) -> RunState | None:
        task = await self._products.get_task(user_id, task_id)
        if task is None:
            return None
        execution = self._active.get(task_id)
        if execution is not None:
            try:
                return await asyncio.shield(execution)
            except asyncio.CancelledError:
                pass
        refreshed = await self._products.get_task(user_id, task_id)
        if refreshed is None or refreshed.run_id is None:
            return None
        return await self._kernel.get_run(refreshed.run_id)

    async def cancel(self, user_id: str, task_id: str) -> bool:
        task = await self._products.get_task(user_id, task_id)
        if task is None:
            return False
        execution = self._active.get(task_id)
        if execution is None or execution.done():
            return False
        execution.cancel()
        try:
            await execution
        except asyncio.CancelledError:
            pass
        return True

    async def close(self) -> None:
        self._closed = True
        executions = tuple(self._active.values())
        for execution in executions:
            if not execution.done():
                execution.cancel()
        if executions:
            await asyncio.gather(*executions, return_exceptions=True)
        self._active.clear()

    async def _execute(self, task: ProductTask, run_id: str) -> RunState | None:
        try:
            async with self._semaphore:
                await self._products.update_task_status(
                    task.user_id,
                    task.id,
                    TaskStatus.RUNNING,
                )
                if task.task_spec is None:  # defensive narrowing
                    raise ValueError("queued task lost its TaskSpec")
                state = await self._runtime.run(task.task_spec, run_id=run_id)
                await self._products.update_task_status(
                    task.user_id,
                    task.id,
                    _product_status(state.status),
                )
                return state
        except asyncio.CancelledError:
            await self._products.update_task_status(
                task.user_id,
                task.id,
                TaskStatus.CANCELLED,
            )
            raise
        except Exception:
            # Runtime itself persists a sanitized failure state for adapter errors.
            # This guard covers orchestration/storage failures without exposing details.
            await self._products.update_task_status(
                task.user_id,
                task.id,
                TaskStatus.FAILED,
            )
            return None

    def _forget(self, task_id: str, completed: asyncio.Task[RunState | None]) -> None:
        if self._active.get(task_id) is completed:
            self._active.pop(task_id, None)
        # Retrieve a swallowed result so a background failure never produces the
        # "Task exception was never retrieved" warning.
        if not completed.cancelled():
            completed.exception()


def _product_status(status: RunStatus) -> TaskStatus:
    return {
        RunStatus.CREATED: TaskStatus.QUEUED,
        RunStatus.PLANNING: TaskStatus.RUNNING,
        RunStatus.RUNNING: TaskStatus.RUNNING,
        RunStatus.VERIFYING: TaskStatus.RUNNING,
        RunStatus.COMPLETED: TaskStatus.COMPLETED,
        RunStatus.FAILED: TaskStatus.FAILED,
        RunStatus.CANCELLED: TaskStatus.CANCELLED,
    }[status]
