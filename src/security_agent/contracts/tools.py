"""Tool and registry ports."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol, runtime_checkable

from security_agent.contracts.common import JSONObject, JSONValue, is_json_value
from security_agent.domain import ScopeSpec


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class ToolExecutionContext:
    run_id: str
    task_id: str
    plan_node_id: str
    scope: ScopeSpec
    timeout_seconds: float = 30.0
    max_output_bytes: int = 1_000_000

    def __post_init__(self) -> None:
        if not self.run_id or not self.task_id or not self.plan_node_id:
            raise ValueError("tool context IDs must be non-empty")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if self.max_output_bytes <= 0:
            raise ValueError("max_output_bytes must be positive")


@dataclass(frozen=True, slots=True)
class ToolResult:
    success: bool
    output: str = ""
    error: str | None = None
    exit_code: int | None = None
    metadata: JSONObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not is_json_value(self.metadata):
            raise ValueError("tool metadata must be JSON-compatible")
        if self.success and self.error:
            raise ValueError("successful tool result cannot contain an error")
        if not self.success and not self.error:
            raise ValueError("failed tool result must contain an error")


@runtime_checkable
class Tool(Protocol):
    @property
    def name(self) -> str: ...

    @property
    def description(self) -> str: ...

    @property
    def capabilities(self) -> frozenset[str]: ...

    @property
    def input_schema(self) -> Mapping[str, JSONValue]: ...

    @property
    def risk_level(self) -> RiskLevel: ...

    async def execute(
        self,
        context: ToolExecutionContext,
        arguments: Mapping[str, JSONValue],
    ) -> ToolResult: ...


class ToolRegistryPort(Protocol):
    def register(self, tool: Tool) -> None: ...

    def unregister(self, name: str) -> Tool: ...

    def get(self, name: str) -> Tool: ...

    def list(self) -> tuple[Tool, ...]: ...

    def find_by_capability(self, capability: str) -> tuple[Tool, ...]: ...
