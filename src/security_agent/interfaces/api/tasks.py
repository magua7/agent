"""Authenticated task, evidence, and replayable SSE routes."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import StreamingResponse

from security_agent.application.bootstrap import ProductServices
from security_agent.application.models import ProductTask, ProductUser, TaskStatus
from security_agent.application.run_service import RunAlreadyStartedError
from security_agent.application.task_service import (
    TaskInputError,
    TaskNotFoundError,
)
from security_agent.infrastructure.storage.product import ProductConflictError
from security_agent.interfaces.api.dependencies import get_current_user, get_services
from security_agent.interfaces.api.schemas import CreateTaskRequest

router = APIRouter(prefix="/api/tasks", tags=["tasks"])
_TERMINAL_EVENTS = {"task_completed", "task_failed", "task_cancelled", "task_timed_out"}
_TERMINAL_STATUSES = {TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED}


@router.get("")
async def list_tasks(
    user: Annotated[ProductUser, Depends(get_current_user)],
    services: Annotated[ProductServices, Depends(get_services)],
) -> dict[str, object]:
    return {"items": list(await services.tasks.list_tasks(user.id))}


@router.post("", status_code=status.HTTP_202_ACCEPTED)
async def create_task(
    body: CreateTaskRequest,
    user: Annotated[ProductUser, Depends(get_current_user)],
    services: Annotated[ProductServices, Depends(get_services)],
) -> dict[str, object]:
    try:
        task = await services.tasks.create_task(
            user.id,
            title=body.title,
            description=body.description,
            target=body.target,
            ports=body.ports,
        )
    except TaskInputError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except (ProductConflictError, RunAlreadyStartedError) as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return _created_payload(task)


@router.get("/{task_id}")
async def get_task(
    task_id: str,
    user: Annotated[ProductUser, Depends(get_current_user)],
    services: Annotated[ProductServices, Depends(get_services)],
) -> dict[str, Any]:
    try:
        return await services.tasks.get_task_detail(user.id, task_id)
    except TaskNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.post("/{task_id}/cancel")
async def cancel_task(
    task_id: str,
    user: Annotated[ProductUser, Depends(get_current_user)],
    services: Annotated[ProductServices, Depends(get_services)],
) -> dict[str, object]:
    try:
        return await services.tasks.cancel_task(user.id, task_id)
    except TaskNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.get("/{task_id}/evidence/{evidence_id}")
async def get_evidence(
    task_id: str,
    evidence_id: str,
    user: Annotated[ProductUser, Depends(get_current_user)],
    services: Annotated[ProductServices, Depends(get_services)],
) -> dict[str, Any]:
    try:
        return await services.tasks.get_evidence(user.id, task_id, evidence_id)
    except TaskNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.get("/{task_id}/events")
async def task_events(
    task_id: str,
    request: Request,
    user: Annotated[ProductUser, Depends(get_current_user)],
    services: Annotated[ProductServices, Depends(get_services)],
) -> StreamingResponse:
    try:
        task = await services.tasks.get_task(user.id, task_id)
    except TaskNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    cursor = _parse_cursor(request.headers.get("Last-Event-ID"))
    return StreamingResponse(
        _event_stream(request, services, user, task, cursor),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


async def _event_stream(
    request: Request,
    services: ProductServices,
    user: ProductUser,
    task: ProductTask,
    cursor: int,
) -> AsyncIterator[str]:
    heartbeat_at = asyncio.get_running_loop().time() + 15.0
    while True:
        if await request.is_disconnected():
            return
        page = await services.tasks.list_events(
            user.id,
            task.id,
            after_sequence=cursor,
            limit=100,
        )
        for record in page.events:
            event = await services.tasks.project_event(user.id, task.id, record)
            cursor = record.sequence
            yield _sse_frame(event)
            if event["type"] in _TERMINAL_EVENTS:
                return
        if page.has_more:
            continue

        refreshed = await services.tasks.get_task(user.id, task.id)
        if refreshed.status in _TERMINAL_STATUSES:
            # Kernel cancellation predates a dedicated cancel event.  This stable
            # synthetic terminal record closes that narrow compatibility gap.
            terminal = {
                "event_id": f"terminal:{refreshed.id}:{refreshed.status.value}",
                "sequence": cursor + 1,
                "task_id": refreshed.id,
                "run_id": refreshed.run_id,
                "type": f"task_{refreshed.status.value}",
                "timestamp": refreshed.updated_at.isoformat(),
                "payload": {"status": refreshed.status.value},
            }
            yield _sse_frame(terminal)
            return

        now = asyncio.get_running_loop().time()
        if now >= heartbeat_at:
            yield ": keep-alive\n\n"
            heartbeat_at = now + 15.0
        await asyncio.sleep(0.25)


def _created_payload(task: ProductTask) -> dict[str, object]:
    return {
        "task_id": task.id,
        "run_id": task.run_id,
        "status": task.status.value,
        "created_at": task.created_at.isoformat(),
    }


def _parse_cursor(value: str | None) -> int:
    if value is None or not value.strip():
        return 0
    try:
        cursor = int(value)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Last-Event-ID must be a non-negative event sequence",
        ) from exc
    if cursor < 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Last-Event-ID must be a non-negative event sequence",
        )
    return cursor


def _sse_frame(event: dict[str, Any]) -> str:
    data = json.dumps(event, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
    return f"id: {event['sequence']}\nevent: {event['type']}\ndata: {data}\n\n"
