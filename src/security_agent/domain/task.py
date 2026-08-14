"""Durable task intent and explicit authorization scope."""

from __future__ import annotations

import json
import os
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import ClassVar

from security_agent.domain._validation import (
    JSONObject,
    copy_json_object,
    require_non_blank,
    require_utc,
    string_tuple,
)
from security_agent.domain.utils import new_id, utc_now


class TaskType(StrEnum):
    GENERIC = "generic"
    PENTEST = "pentest"
    INCIDENT_RESPONSE = "incident_response"
    CODE_AUDIT = "code_audit"
    REVERSE_ANALYSIS = "reverse_analysis"
    CTF = "ctf"


@dataclass(frozen=True, slots=True)
class ScopeSpec:
    """Caller-granted network and filesystem authorization boundaries."""

    network_targets: tuple[str, ...] = ()
    file_roots: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        network_targets = string_tuple(self.network_targets, "network_targets")
        file_roots = string_tuple(self.file_roots, "file_roots")
        for target in network_targets:
            if any(character.isspace() for character in target):
                raise ValueError("network targets cannot contain whitespace")
            if "://" in target:
                raise ValueError("network targets must be hosts, IPs, or CIDRs, not URLs")
        for root in file_roots:
            if not Path(root).is_absolute():
                raise ValueError("file_roots must contain absolute paths")
        normalized_roots = {os.path.normcase(os.path.normpath(root)) for root in file_roots}
        if len(normalized_roots) != len(file_roots):
            raise ValueError("file_roots must be unique after path normalization")
        object.__setattr__(self, "network_targets", network_targets)
        object.__setattr__(self, "file_roots", file_roots)

    @property
    def is_empty(self) -> bool:
        return not self.network_targets and not self.file_roots


@dataclass(frozen=True, slots=True)
class TaskSpec:
    """Validated, durable interpretation of a caller's task."""

    MAX_INPUT_BYTES: ClassVar[int] = 65_536

    objective: str
    task_type: TaskType
    scope: ScopeSpec
    success_criteria: tuple[str, ...]
    constraints: tuple[str, ...] = ()
    inputs: JSONObject = field(default_factory=dict)
    id: str = field(default_factory=new_id)
    created_at: datetime = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        require_non_blank(self.id, "task id")
        require_non_blank(self.objective, "objective")
        if not isinstance(self.task_type, TaskType):
            raise ValueError("task_type must be a TaskType")
        if not isinstance(self.scope, ScopeSpec):
            raise ValueError("scope must be a ScopeSpec")
        criteria = string_tuple(
            self.success_criteria,
            "success_criteria",
            required=True,
        )
        constraints = string_tuple(self.constraints, "constraints", unique=False)
        inputs: Mapping[str, object] = self.inputs
        copied_inputs = copy_json_object(inputs, "inputs")
        input_size = len(
            json.dumps(
                copied_inputs,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            ).encode("utf-8")
        )
        if input_size > self.MAX_INPUT_BYTES:
            raise ValueError(f"inputs cannot exceed {self.MAX_INPUT_BYTES} encoded bytes")
        object.__setattr__(self, "success_criteria", criteria)
        object.__setattr__(self, "constraints", constraints)
        object.__setattr__(self, "inputs", copied_inputs)
        require_utc(self.created_at, "created_at")

    @classmethod
    def create(
        cls,
        *,
        objective: str,
        task_type: TaskType,
        scope: ScopeSpec,
        success_criteria: Iterable[str],
        constraints: Iterable[str] = (),
        inputs: Mapping[str, object] | None = None,
        id: str | None = None,
        created_at: datetime | None = None,
    ) -> TaskSpec:
        copied_inputs = copy_json_object(
            {} if inputs is None else inputs,
            "inputs",
        )
        return cls(
            objective=objective,
            task_type=task_type,
            scope=scope,
            success_criteria=tuple(success_criteria),
            constraints=tuple(constraints),
            inputs=copied_inputs,
            id=new_id() if id is None else id,
            created_at=utc_now() if created_at is None else created_at,
        )
