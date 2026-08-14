"""Audited tool selection, policy, execution, and evidence capture."""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass

from security_agent.contracts import (
    ActionDecision,
    EventSink,
    EventType,
    EvidenceRepository,
    RunEvent,
    RunRepository,
    Tool,
    ToolExecutionContext,
    ToolRegistryPort,
    ToolResult,
)
from security_agent.domain import ActionRecord, Evidence, EvidenceType, ScopeSpec
from security_agent.engine.errors import PolicyDeniedError, ToolSelectionError
from security_agent.engine.policy import ExecutionPolicy
from security_agent.engine.redaction import redact_json_object
from security_agent.engine.schema import SchemaValidationError, validate_object


@dataclass(frozen=True, slots=True)
class ExecutionOutcome:
    action: ActionRecord
    evidence: Evidence
    result: ToolResult


class ToolExecutor:
    def __init__(
        self,
        registry: ToolRegistryPort,
        run_repository: RunRepository,
        evidence_repository: EvidenceRepository,
        event_sink: EventSink,
        *,
        policy: ExecutionPolicy | None = None,
        timeout_seconds: float = 30.0,
        max_output_bytes: int = 1_000_000,
    ) -> None:
        if timeout_seconds <= 0 or max_output_bytes <= 0:
            raise ValueError("tool timeout and output limit must be positive")
        self._registry = registry
        self._runs = run_repository
        self._evidence = evidence_repository
        self._events = event_sink
        self._policy = policy or ExecutionPolicy()
        self._timeout_seconds = timeout_seconds
        self._max_output_bytes = max_output_bytes

    async def execute(
        self,
        *,
        run_id: str,
        task_id: str,
        plan_node_id: str,
        agent_id: str,
        scope: ScopeSpec,
        decision: ActionDecision,
    ) -> ExecutionOutcome:
        tool: Tool | None = None
        selection_error: ToolSelectionError | None = None
        try:
            tool = self._select(decision)
        except ToolSelectionError as exc:
            selection_error = exc
        audit_tool_name = (
            tool.name
            if tool is not None
            else decision.preferred_tool or f"unavailable:{decision.capability}"
        )
        action = ActionRecord.start(
            run_id=run_id,
            plan_node_id=plan_node_id,
            agent_id=agent_id,
            tool_name=audit_tool_name,
            arguments=redact_json_object(decision.arguments),
        )
        await self._runs.save_action(action)
        await self._events.publish(
            RunEvent(
                EventType.TOOL_STARTED,
                run_id,
                {
                    "action_id": action.id,
                    "node_id": plan_node_id,
                    "tool": audit_tool_name,
                    "capability": decision.capability,
                    "arguments": action.arguments,
                },
            )
        )
        started = time.perf_counter()
        cancelled = False
        try:
            if selection_error is not None:
                raise selection_error
            if tool is None:  # defensive narrowing; selection establishes it
                raise ToolSelectionError("tool selection produced no result")
            validate_object(decision.arguments, tool.input_schema)
            self._policy.authorize(tool, decision.arguments, scope)
            context = ToolExecutionContext(
                run_id=run_id,
                task_id=task_id,
                plan_node_id=plan_node_id,
                scope=scope,
                timeout_seconds=self._timeout_seconds,
                max_output_bytes=self._max_output_bytes,
            )
            result = await asyncio.wait_for(
                tool.execute(context, decision.arguments),
                timeout=self._timeout_seconds,
            )
        except asyncio.CancelledError:
            cancelled = True
            result = ToolResult(success=False, error="tool execution was cancelled")
        except TimeoutError:
            result = ToolResult(success=False, error="tool execution timed out")
        except (SchemaValidationError, PolicyDeniedError, ToolSelectionError) as exc:
            result = ToolResult(success=False, error=f"{type(exc).__name__}: {exc}")
        except Exception as exc:  # adapters are isolated at this boundary
            result = ToolResult(
                success=False,
                error=f"tool adapter raised {type(exc).__name__}",
                metadata={"exception_type": type(exc).__name__},
            )

        result = _enforce_output_limit(result, self._max_output_bytes)
        duration_ms = max(0, round((time.perf_counter() - started) * 1_000))
        evidence = _evidence_from_result(
            run_id=run_id,
            action_id=action.id,
            tool_name=audit_tool_name,
            capability=decision.capability,
            result=result,
        )
        action = action.finish(
            success=result.success,
            duration_ms=duration_ms,
            error=result.error,
            exit_code=result.exit_code,
            evidence_ids=(evidence.id,),
        )
        await self._evidence.save_evidence(evidence)
        await self._runs.save_action(action)
        await self._events.publish(
            RunEvent(
                EventType.EVIDENCE_CREATED,
                run_id,
                {
                    "evidence_id": evidence.id,
                    "action_id": action.id,
                    "type": evidence.type.value,
                    "content_hash": evidence.content_hash,
                },
            )
        )
        await self._events.publish(
            RunEvent(
                EventType.TOOL_COMPLETED if result.success else EventType.TOOL_FAILED,
                run_id,
                {
                    "action_id": action.id,
                    "tool": audit_tool_name,
                    "success": result.success,
                    "exit_code": result.exit_code,
                    "error": result.error,
                    "duration_ms": duration_ms,
                },
            )
        )
        if cancelled:
            raise asyncio.CancelledError
        return ExecutionOutcome(action=action, evidence=evidence, result=result)

    def _select(self, decision: ActionDecision) -> Tool:
        if decision.preferred_tool is not None:
            try:
                tool = self._registry.get(decision.preferred_tool)
            except KeyError as exc:
                raise ToolSelectionError(
                    f"preferred tool {decision.preferred_tool!r} is not registered"
                ) from exc
            if decision.capability not in tool.capabilities:
                raise ToolSelectionError(
                    f"tool {tool.name!r} does not provide {decision.capability!r}"
                )
            return tool
        candidates = self._registry.find_by_capability(decision.capability)
        if not candidates:
            raise ToolSelectionError(f"no tool provides capability {decision.capability!r}")
        return candidates[0]


def _enforce_output_limit(result: ToolResult, maximum: int) -> ToolResult:
    size = len(result.output.encode("utf-8"))
    if size > maximum:
        return ToolResult(
            success=False,
            error=f"tool output exceeded the {maximum}-byte evidence limit",
            exit_code=result.exit_code,
            metadata={"output_bytes": size, "output_discarded": True},
        )

    metadata = redact_json_object(result.metadata)
    metadata_bytes = len(json.dumps(metadata, ensure_ascii=False, sort_keys=True).encode("utf-8"))
    metadata_limit = min(maximum, 64_000)
    if metadata_bytes > metadata_limit:
        metadata = (
            {"metadata_discarded": True, "metadata_bytes": metadata_bytes}
            if metadata_limit >= 64
            else {}
        )

    output = result.output
    error = result.error
    if error is not None:
        framing_bytes = len(b"\nERROR: ")
        error_budget = max(1, maximum - framing_bytes)
        safe_error = _truncate_utf8(error, min(error_budget, 4_096)) or "E"
        remaining = max(
            0,
            maximum - framing_bytes - len(safe_error.encode("utf-8")),
        )
        safe_output = _truncate_utf8(output, remaining)
        if safe_error != error or safe_output != output:
            metadata["result_text_truncated"] = True
        error = safe_error
        output = safe_output
    return ToolResult(
        success=result.success,
        output=output,
        error=error,
        exit_code=result.exit_code,
        metadata=metadata,
    )


def _truncate_utf8(value: str, byte_limit: int) -> str:
    encoded = value.encode("utf-8")
    if len(encoded) <= byte_limit:
        return value
    return encoded[:byte_limit].decode("utf-8", errors="ignore")


def _evidence_from_result(
    *,
    run_id: str,
    action_id: str,
    tool_name: str,
    capability: str,
    result: ToolResult,
) -> Evidence:
    evidence_type = {
        "network.scan": EvidenceType.NETWORK_SCAN,
        "http.request": EvidenceType.HTTP_RESPONSE,
        "file.read": EvidenceType.FILE_CONTENT,
    }.get(capability, EvidenceType.TOOL_OUTPUT)
    if not result.success:
        evidence_type = EvidenceType.TOOL_ERROR
    raw_content = result.output
    if result.error:
        raw_content = f"{raw_content}\nERROR: {result.error}".lstrip()
    summary = (
        f"{tool_name} completed successfully"
        if result.success
        else f"{tool_name} failed: {result.error}"
    )
    return Evidence.create(
        run_id=run_id,
        action_id=action_id,
        type=evidence_type,
        source=f"tool:{tool_name}",
        summary=summary[: Evidence.MAX_SUMMARY_CHARS],
        raw_content=raw_content,
        metadata={
            "capability": capability,
            "tool_success": result.success,
            "exit_code": result.exit_code,
            "tool_metadata": result.metadata,
            "provenance": "tool_execution",
        },
    )
