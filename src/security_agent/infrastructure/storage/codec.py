"""Strict JSON and UTC codecs at the SQLite/domain boundary."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import cast

from security_agent.domain import (
    ActionRecord,
    Evidence,
    EvidenceType,
    Finding,
    FindingStatus,
    NodeStatus,
    Plan,
    PlanNode,
    PlanStatus,
    ScopeSpec,
    Severity,
    TaskSpec,
    TaskType,
)
from security_agent.domain._validation import JSONObject, JSONValue


class CorruptStorageError(RuntimeError):
    """Stored data cannot be decoded into the promised domain representation."""


def dump_json(value: object) -> str:
    """Produce deterministic, lossless JSON for values accepted by the domain."""
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def load_json(raw: str, field_name: str) -> JSONValue:
    try:
        value = json.loads(raw)
    except (TypeError, json.JSONDecodeError) as error:
        raise CorruptStorageError(f"invalid JSON in {field_name}") from error
    return cast(JSONValue, value)


def load_object(raw: str, field_name: str) -> JSONObject:
    value = load_json(raw, field_name)
    if not isinstance(value, dict):
        raise CorruptStorageError(f"{field_name} must contain a JSON object")
    return value


def load_string_tuple(raw: str, field_name: str) -> tuple[str, ...]:
    value = load_json(raw, field_name)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise CorruptStorageError(f"{field_name} must contain a JSON string array")
    return tuple(cast(list[str], value))


def encode_datetime(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamps must be timezone-aware")
    return value.astimezone(UTC).isoformat()


def decode_datetime(raw: str, field_name: str) -> datetime:
    try:
        value = datetime.fromisoformat(raw)
    except (TypeError, ValueError) as error:
        raise CorruptStorageError(f"invalid ISO timestamp in {field_name}") from error
    if value.tzinfo is None or value.utcoffset() is None:
        raise CorruptStorageError(f"{field_name} timestamp is not timezone-aware")
    return value.astimezone(UTC)


def task_to_json(task: TaskSpec) -> str:
    return dump_json(
        {
            "id": task.id,
            "objective": task.objective,
            "task_type": task.task_type.value,
            "scope": {
                "network_targets": list(task.scope.network_targets),
                "file_roots": list(task.scope.file_roots),
            },
            "success_criteria": list(task.success_criteria),
            "constraints": list(task.constraints),
            "inputs": task.inputs,
            "created_at": encode_datetime(task.created_at),
        }
    )


def task_from_json(raw: str) -> TaskSpec:
    value = load_object(raw, "runs.task_json")
    try:
        scope_value = value["scope"]
        if not isinstance(scope_value, dict):
            raise TypeError("scope is not an object")
        network_targets = _string_tuple_value(scope_value["network_targets"], "network_targets")
        file_roots = _string_tuple_value(scope_value["file_roots"], "file_roots")
        return TaskSpec(
            id=_string_value(value["id"], "task.id"),
            objective=_string_value(value["objective"], "task.objective"),
            task_type=TaskType(_string_value(value["task_type"], "task.task_type")),
            scope=ScopeSpec(network_targets=network_targets, file_roots=file_roots),
            success_criteria=_string_tuple_value(
                value["success_criteria"], "task.success_criteria"
            ),
            constraints=_string_tuple_value(value["constraints"], "task.constraints"),
            inputs=_object_value(value["inputs"], "task.inputs"),
            created_at=decode_datetime(
                _string_value(value["created_at"], "task.created_at"),
                "task.created_at",
            ),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise CorruptStorageError("invalid TaskSpec in runs.task_json") from error


def plan_from_rows(
    header_row: dict[str, object],
    rows: list[dict[str, object]],
) -> Plan:
    try:
        nodes = tuple(node_from_row(row) for row in rows)
        return Plan(
            id=_row_str(header_row, "plan_id"),
            task_id=_row_str(header_row, "task_id"),
            version=_row_int(header_row, "version"),
            status=PlanStatus(_row_str(header_row, "status")),
            nodes=nodes,
            created_at=decode_datetime(_row_str(header_row, "created_at"), "plans.created_at"),
            updated_at=decode_datetime(_row_str(header_row, "updated_at"), "plans.updated_at"),
        )
    except (TypeError, ValueError) as error:
        raise CorruptStorageError("invalid Plan in SQLite") from error


def node_from_row(row: dict[str, object]) -> PlanNode:
    return PlanNode(
        id=_row_str(row, "node_id"),
        goal=_row_str(row, "goal"),
        description=_row_str(row, "description"),
        status=NodeStatus(_row_str(row, "status")),
        assigned_agent=_row_str(row, "assigned_agent"),
        required_capabilities=load_string_tuple(
            _row_str(row, "required_capabilities_json"),
            "plan_nodes.required_capabilities_json",
        ),
        dependencies=load_string_tuple(
            _row_str(row, "dependencies_json"), "plan_nodes.dependencies_json"
        ),
        success_criteria=load_string_tuple(
            _row_str(row, "success_criteria_json"), "plan_nodes.success_criteria_json"
        ),
        attempt_count=_row_int(row, "attempt_count"),
        max_attempts=_row_int(row, "max_attempts"),
        evidence_ids=load_string_tuple(
            _row_str(row, "evidence_ids_json"), "plan_nodes.evidence_ids_json"
        ),
        finding_ids=load_string_tuple(
            _row_str(row, "finding_ids_json"), "plan_nodes.finding_ids_json"
        ),
        created_at=decode_datetime(_row_str(row, "created_at"), "plan_nodes.created_at"),
        updated_at=decode_datetime(_row_str(row, "updated_at"), "plan_nodes.updated_at"),
    )


def action_from_row(row: dict[str, object]) -> ActionRecord:
    finished_raw = row["finished_at"]
    duration_raw = row["duration_ms"]
    success_raw = row["success"]
    try:
        return ActionRecord(
            id=_row_str(row, "id"),
            run_id=_row_str(row, "run_id"),
            plan_node_id=_row_str(row, "plan_node_id"),
            agent_id=_row_str(row, "agent_id"),
            tool_name=_row_str(row, "tool_name"),
            arguments=load_object(_row_str(row, "arguments_json"), "actions.arguments_json"),
            started_at=decode_datetime(_row_str(row, "started_at"), "actions.started_at"),
            finished_at=(
                None
                if finished_raw is None
                else decode_datetime(
                    _string_value(finished_raw, "finished_at"), "actions.finished_at"
                )
            ),
            duration_ms=None if duration_raw is None else _int_value(duration_raw, "duration_ms"),
            success=None if success_raw is None else _bool_db_value(success_raw, "success"),
            exit_code=(
                None if row["exit_code"] is None else _int_value(row["exit_code"], "exit_code")
            ),
            error=None if row["error"] is None else _string_value(row["error"], "error"),
            evidence_ids=load_string_tuple(
                _row_str(row, "evidence_ids_json"), "actions.evidence_ids_json"
            ),
        )
    except (TypeError, ValueError) as error:
        raise CorruptStorageError("invalid ActionRecord in SQLite") from error


def evidence_from_row_values(row: dict[str, object], *, verified_hash: str) -> Evidence:
    try:
        return Evidence(
            id=_row_str(row, "id"),
            run_id=_row_str(row, "run_id"),
            action_id=(
                None if row["action_id"] is None else _string_value(row["action_id"], "action_id")
            ),
            type=EvidenceType(_row_str(row, "type")),
            source=_row_str(row, "source"),
            summary=_row_str(row, "summary"),
            raw_content=_row_str(row, "raw_content", allow_empty=True),
            content_hash=verified_hash,
            created_at=decode_datetime(_row_str(row, "created_at"), "evidence.created_at"),
            metadata=load_object(_row_str(row, "metadata_json"), "evidence.metadata_json"),
        )
    except (TypeError, ValueError) as error:
        raise CorruptStorageError("invalid Evidence in SQLite") from error


def finding_from_row(row: dict[str, object]) -> Finding:
    try:
        confidence = row["confidence"]
        if isinstance(confidence, bool) or not isinstance(confidence, int | float):
            raise TypeError("confidence is not numeric")
        return Finding(
            id=_row_str(row, "id"),
            run_id=_row_str(row, "run_id"),
            title=_row_str(row, "title"),
            description=_row_str(row, "description"),
            severity=Severity(_row_str(row, "severity")),
            confidence=float(confidence),
            evidence_ids=load_string_tuple(
                _row_str(row, "evidence_ids_json"), "findings.evidence_ids_json"
            ),
            status=FindingStatus(_row_str(row, "status")),
            subject=_row_str(row, "subject", allow_empty=True),
            fingerprint=_row_str(row, "fingerprint"),
            created_at=decode_datetime(_row_str(row, "created_at"), "findings.created_at"),
        )
    except (TypeError, ValueError) as error:
        raise CorruptStorageError("invalid Finding in SQLite") from error


def _string_value(value: object, field_name: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} is not a string")
    return value


def _int_value(value: object, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{field_name} is not an integer")
    return value


def _bool_db_value(value: object, field_name: str) -> bool:
    integer = _int_value(value, field_name)
    if integer not in (0, 1):
        raise TypeError(f"{field_name} is not a SQLite boolean")
    return bool(integer)


def _string_tuple_value(value: object, field_name: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise TypeError(f"{field_name} is not a string array")
    return tuple(cast(list[str], value))


def _object_value(value: object, field_name: str) -> JSONObject:
    if not isinstance(value, dict):
        raise TypeError(f"{field_name} is not an object")
    return cast(JSONObject, value)


def _row_str(row: dict[str, object], key: str, *, allow_empty: bool = False) -> str:
    value = _string_value(row[key], key)
    if not allow_empty and not value:
        raise TypeError(f"{key} is empty")
    return value


def _row_int(row: dict[str, object], key: str) -> int:
    return _int_value(row[key], key)
