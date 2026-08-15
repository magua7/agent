"""Product task orchestration and bounded UI projections."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Sequence
from typing import Any

from security_agent.application.models import EventPage, ProductRunEvent, ProductTask, TaskStatus
from security_agent.application.ports import ProductRepository
from security_agent.application.run_service import RunService
from security_agent.domain import RunState, RunStatus, TaskType
from security_agent.engine import TaskInterpreter
from security_agent.infrastructure.storage import SQLiteStore

_DEFAULT_PORTS = (22, 80, 443, 8000, 8080)
_LOOPBACK_HINT = re.compile(r"(?<![\w.])(?:localhost|127(?:\.\d{1,3}){3}|::1)(?![\w.])", re.I)


class TaskNotFoundError(LookupError):
    pass


class TaskInputError(ValueError):
    pass


class TaskService:
    """The only product service allowed to create and start a Security Agent task."""

    def __init__(
        self,
        products: ProductRepository,
        runs: RunService,
        kernel_store: SQLiteStore,
        *,
        interpreter: TaskInterpreter | None = None,
    ) -> None:
        self._products = products
        self._runs = runs
        self._kernel = kernel_store
        self._interpreter = interpreter or TaskInterpreter()

    async def create_task(
        self,
        user_id: str,
        *,
        title: str,
        description: str,
        target: str | None = None,
        ports: Sequence[int] | None = None,
    ) -> ProductTask:
        normalized_title = _required_text(title, "title", maximum=200)
        normalized_description = _required_text(description, "description", maximum=20_000)
        normalized_target = _explicit_loopback_target(
            target,
            f"{normalized_title}\n{normalized_description}",
        )
        normalized_ports = _normalize_ports(ports)
        criterion = "Record the observed localhost service state as tool-produced evidence"
        spec = self._interpreter.interpret(
            normalized_description,
            task_type=TaskType.PENTEST,
            network_targets=(normalized_target,),
            inputs={"target": normalized_target, "ports": list(normalized_ports)},
            success_criteria=(criterion,),
            constraints=(
                "explicitly authorized loopback target only",
                "no exploit activity",
            ),
        )
        product_task = await self._products.create_task(
            user_id,
            normalized_title,
            normalized_description,
            task_spec=spec,
        )
        await self._runs.start(product_task)
        refreshed = await self._products.get_task(user_id, product_task.id)
        if refreshed is None:
            raise RuntimeError("created task disappeared from product storage")
        return refreshed

    async def list_tasks(self, user_id: str, *, limit: int = 100) -> tuple[dict[str, Any], ...]:
        tasks = await self._products.list_tasks(user_id, limit=limit)
        return tuple(_task_summary(task) for task in tasks)

    async def get_task(self, user_id: str, task_id: str) -> ProductTask:
        task = await self._products.get_task(user_id, task_id)
        if task is None:
            raise TaskNotFoundError("task was not found")
        return task

    async def get_task_detail(self, user_id: str, task_id: str) -> dict[str, Any]:
        task = await self.get_task(user_id, task_id)
        state = None if task.run_id is None else await self._kernel.get_run(task.run_id)
        return _task_detail(task, state)

    async def cancel_task(self, user_id: str, task_id: str) -> dict[str, Any]:
        task = await self.get_task(user_id, task_id)
        cancelled = await self._runs.cancel(user_id, task.id)
        refreshed = await self.get_task(user_id, task.id)
        return {
            "task_id": refreshed.id,
            "run_id": refreshed.run_id,
            "status": refreshed.status.value,
            "cancelled": cancelled,
        }

    async def wait(self, user_id: str, task_id: str) -> RunState | None:
        await self.get_task(user_id, task_id)
        return await self._runs.wait(user_id, task_id)

    async def get_evidence(
        self,
        user_id: str,
        task_id: str,
        evidence_id: str,
    ) -> dict[str, Any]:
        task = await self.get_task(user_id, task_id)
        if task.run_id is None:
            raise TaskNotFoundError("evidence was not found")
        evidence = await self._kernel.get_evidence(evidence_id)
        if evidence is None or evidence.run_id != task.run_id:
            raise TaskNotFoundError("evidence was not found")
        payload = _evidence_payload(evidence)
        payload["raw_content"] = evidence.raw_content
        payload["integrity_valid"] = evidence.verify_hash()
        return payload

    async def list_events(
        self,
        user_id: str,
        task_id: str,
        *,
        after_sequence: int = 0,
        limit: int = 100,
    ) -> EventPage:
        page = await self._products.list_task_events(
            user_id,
            task_id,
            after_sequence=after_sequence,
            limit=limit,
        )
        if page is None:
            raise TaskNotFoundError("task was not found")
        return page

    async def project_event(
        self,
        user_id: str,
        task_id: str,
        record: ProductRunEvent,
    ) -> dict[str, Any]:
        task = await self.get_task(user_id, task_id)
        event = record.event
        if task.run_id is None or event.run_id != task.run_id:
            raise TaskNotFoundError("event does not belong to this task")
        payload: dict[str, Any] = dict(event.payload)
        event_name = _product_event_name(event.event_type.value, payload)

        if event.event_type.value in {"plan_created", "plan_updated"}:
            state = await self._kernel.get_run(event.run_id)
            payload["plan"] = None if state is None else _plan_payload(state)
        elif event.event_type.value == "evidence_created":
            evidence_id = payload.get("evidence_id")
            if isinstance(evidence_id, str):
                evidence = await self._kernel.get_evidence(evidence_id)
                if evidence is not None and evidence.run_id == event.run_id:
                    payload.update(_evidence_payload(evidence))
        elif event.event_type.value == "finding_created":
            finding_id = payload.get("finding_id")
            findings = await self._kernel.list_findings(event.run_id)
            finding = next((item for item in findings if item.id == finding_id), None)
            if finding is not None:
                payload.update(_finding_payload(finding))
        elif event.event_type.value in {"tool_completed", "tool_failed"}:
            action_id = payload.get("action_id")
            if isinstance(action_id, str):
                action = await self._kernel.get_action(action_id)
                if action is not None and action.run_id == event.run_id:
                    payload["evidence_ids"] = list(action.evidence_ids)
                    payload["arguments"] = action.arguments
        elif event.event_type.value in {"run_completed", "run_failed", "run_cancelled"}:
            detail = await self.get_task_detail(user_id, task_id)
            payload["stats"] = detail["stats"]
            payload["status"] = detail["status"]

        if event.event_type.value in {"verification_passed", "verification_failed"}:
            payload["success"] = event.event_type.value == "verification_passed"

        return {
            "event_id": event.id,
            "sequence": record.sequence,
            "task_id": task_id,
            "run_id": event.run_id,
            "type": event_name,
            "timestamp": event.created_at.isoformat(),
            "payload": payload,
        }


def _task_summary(task: ProductTask) -> dict[str, Any]:
    return {
        "id": task.id,
        "task_id": task.id,
        "run_id": task.run_id,
        "title": task.title,
        "description": task.description,
        "status": task.status.value,
        "created_at": task.created_at.isoformat(),
        "updated_at": task.updated_at.isoformat(),
    }


def _task_detail(task: ProductTask, state: RunState | None) -> dict[str, Any]:
    summary = _task_summary(task)
    effective_status = task.status if state is None else _task_status_from_run(state.status)
    summary["status"] = effective_status.value
    summary["task_spec"] = (
        None
        if task.task_spec is None
        else {
            "objective": task.task_spec.objective,
            "task_type": task.task_spec.task_type.value,
            "scope": {
                "network_targets": list(task.task_spec.scope.network_targets),
                "file_roots": list(task.task_spec.scope.file_roots),
            },
            "constraints": list(task.task_spec.constraints),
            "inputs": task.task_spec.inputs,
            "success_criteria": list(task.task_spec.success_criteria),
        }
    )
    summary["plan"] = None if state is None else _plan_payload(state)
    summary["evidence"] = (
        [] if state is None else [_evidence_payload(item) for item in state.evidence]
    )
    summary["findings"] = (
        [] if state is None else [_finding_payload(item) for item in state.findings]
    )
    summary["verification"] = _verification_payload(state)
    summary["stats"] = _stats_payload(state)
    summary["report"] = _render_report(task, state)
    if state is not None:
        summary["last_error"] = state.last_error
    else:
        summary["last_error"] = None
    return summary


def _plan_payload(state: RunState) -> dict[str, Any] | None:
    plan = state.plan
    if plan is None:
        return None
    return {
        "id": plan.id,
        "version": plan.version,
        "status": plan.status.value,
        "nodes": [
            {
                "id": node.id,
                "goal": node.goal,
                "description": node.description,
                "status": node.status.value,
                "assigned_agent": node.assigned_agent,
                "dependencies": list(node.dependencies),
                "required_capabilities": list(node.required_capabilities),
                "success_criteria": list(node.success_criteria),
                "attempt_count": node.attempt_count,
                "max_attempts": node.max_attempts,
                "evidence_ids": list(node.evidence_ids),
                "finding_ids": list(node.finding_ids),
            }
            for node in plan.nodes
        ],
    }


def _evidence_payload(evidence: Any) -> dict[str, Any]:
    return {
        "id": evidence.id,
        "type": evidence.type.value,
        "source": evidence.source,
        "summary": evidence.summary,
        "content_hash": evidence.content_hash,
        "created_at": evidence.created_at.isoformat(),
        "metadata": evidence.metadata,
    }


def _finding_payload(finding: Any) -> dict[str, Any]:
    return {
        "id": finding.id,
        "title": finding.title,
        "severity": finding.severity.value,
        "description": finding.description,
        "confidence": finding.confidence,
        "status": finding.status.value,
        "evidence_ids": list(finding.evidence_ids),
        "created_at": finding.created_at.isoformat(),
    }


def _verification_payload(state: RunState | None) -> dict[str, Any] | None:
    if state is None or state.status not in {RunStatus.COMPLETED, RunStatus.FAILED}:
        return None
    evidence_ids = [item.id for item in state.evidence]
    return {
        "success": state.status is RunStatus.COMPLETED,
        "reason": "Independent verification passed"
        if state.status is RunStatus.COMPLETED
        else state.last_error or "Independent verification failed",
        "evidence_ids": evidence_ids if state.status is RunStatus.COMPLETED else [],
        "missing_requirements": [],
        "conflicts": [],
    }


def _stats_payload(state: RunState | None) -> dict[str, Any]:
    if state is None:
        return {
            "step_count": 0,
            "evidence_count": 0,
            "finding_count": 0,
            "replan_count": 0,
            "elapsed_sec": 0.0,
        }
    finished = state.finished_at or state.updated_at
    return {
        "step_count": state.step_count,
        "evidence_count": len(state.evidence),
        "finding_count": len(state.findings),
        "replan_count": state.replan_count,
        "elapsed_sec": max(0.0, round((finished - state.started_at).total_seconds(), 3)),
    }


def _render_report(task: ProductTask, state: RunState | None) -> str | None:
    if state is None or not state.is_terminal:
        return None
    status = _task_status_from_run(state.status).value
    lines = [
        "# SEC-GO Security Report",
        "",
        f"- Task: {_markdown_text(task.title)}",
        f"- Status: `{status}`",
        f"- Run ID: `{state.run_id}`",
        f"- Started: `{state.started_at.isoformat()}`",
        f"- Finished: `{state.finished_at.isoformat() if state.finished_at else '-'}`",
        "",
        "## Objective",
        "",
        _markdown_text(task.description),
        "",
        "## Execution plan",
        "",
    ]
    if state.plan is None:
        lines.append("No plan was produced.")
    else:
        for index, node in enumerate(state.plan.nodes, start=1):
            lines.append(f"{index}. **{_markdown_text(node.goal)}** - `{node.status.value}`")
    lines.extend(["", "## Findings", ""])
    if not state.findings:
        lines.append("No evidence-backed security finding was produced.")
    else:
        for finding in state.findings:
            lines.extend(
                [
                    f"### {_markdown_text(finding.title)}",
                    "",
                    f"- Severity: `{finding.severity.value}`",
                    f"- Verification: `{finding.status.value}`",
                    f"- Evidence: {', '.join(f'`{item}`' for item in finding.evidence_ids)}",
                    "",
                    _markdown_text(finding.description),
                    "",
                ]
            )
    lines.extend(["", "## Evidence index", ""])
    for evidence in state.evidence:
        lines.append(
            f"- `{evidence.id}` - {_markdown_text(evidence.summary)} - SHA-256 `{evidence.content_hash}`"
        )
    if not state.evidence:
        lines.append("No tool-produced evidence was retained.")
    lines.extend(["", "## Verification", ""])
    if state.status is RunStatus.COMPLETED:
        lines.append("Independent run verification passed with tool-produced evidence.")
    else:
        lines.append(f"Run did not complete: {_markdown_text(state.last_error or status)}")
    return "\n".join(lines)


def _product_event_name(kernel_name: str, payload: dict[str, Any]) -> str:
    if kernel_name == "run_started":
        return "task_started"
    if kernel_name == "run_completed":
        return "task_completed"
    if kernel_name == "run_failed":
        return "task_failed"
    if kernel_name == "run_cancelled":
        return "task_cancelled"
    if kernel_name in {"verification_passed", "verification_failed"}:
        return "verification_finished"
    return kernel_name


def _task_status_from_run(status: RunStatus) -> TaskStatus:
    return {
        RunStatus.CREATED: TaskStatus.QUEUED,
        RunStatus.PLANNING: TaskStatus.RUNNING,
        RunStatus.RUNNING: TaskStatus.RUNNING,
        RunStatus.VERIFYING: TaskStatus.RUNNING,
        RunStatus.COMPLETED: TaskStatus.COMPLETED,
        RunStatus.FAILED: TaskStatus.FAILED,
        RunStatus.CANCELLED: TaskStatus.CANCELLED,
    }[status]


def _explicit_loopback_target(target: str | None, description: str) -> str:
    candidate = target.strip() if isinstance(target, str) and target.strip() else None
    if candidate is None:
        match = _LOOPBACK_HINT.search(description)
        if match is None:
            raise TaskInputError(
                "an explicit localhost or loopback target is required by the MVP scope policy"
            )
        candidate = match.group(0)
    if candidate.casefold().rstrip(".") == "localhost":
        return "127.0.0.1"
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError as exc:
        raise TaskInputError("SEC-GO MVP accepts only localhost or a loopback IP") from exc
    if not address.is_loopback:
        raise TaskInputError("SEC-GO MVP accepts only loopback targets")
    return str(address)


def _normalize_ports(ports: Sequence[int] | None) -> tuple[int, ...]:
    if ports is None:
        return _DEFAULT_PORTS
    values = tuple(ports)
    if not values or len(values) > 128:
        raise TaskInputError("ports must contain between 1 and 128 entries")
    if any(isinstance(value, bool) or not isinstance(value, int) for value in values):
        raise TaskInputError("ports must contain integers")
    result = tuple(sorted(set(values)))
    if any(value < 1 or value > 65_535 for value in result):
        raise TaskInputError("ports must be between 1 and 65535")
    return result


def _required_text(value: str, label: str, *, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise TaskInputError(f"{label} must be non-empty text")
    normalized = value.strip()
    if len(normalized) > maximum:
        raise TaskInputError(f"{label} cannot exceed {maximum} characters")
    return normalized


def _markdown_text(value: str) -> str:
    # ReactMarkdown does not enable raw HTML, but escaping the structural tokens
    # also keeps user/tool text from changing the report's section hierarchy.
    return value.replace("\\", "\\\\").replace("`", "\\`").replace("<", "&lt;")
