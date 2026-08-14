"""In-memory implementation of the tool registry port."""

from __future__ import annotations

import re
from collections.abc import Mapping

from security_agent.contracts import RiskLevel, Tool
from security_agent.infrastructure.tools.errors import DuplicateToolError

_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]*$")


class ToolRegistry:
    """A strict registry with deterministic lookup order."""

    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        """Register *tool*, rejecting malformed or duplicate entries."""

        self._validate_tool(tool)
        if tool.name in self._tools:
            raise DuplicateToolError(f"tool already registered: {tool.name}")
        self._tools[tool.name] = tool

    def unregister(self, name: str) -> Tool:
        """Remove and return a tool.

        ``KeyError`` is intentional: silently ignoring a missing adapter makes
        runtime configuration mistakes difficult to audit.
        """

        return self._tools.pop(name)

    def get(self, name: str) -> Tool:
        """Return the named tool or raise ``KeyError``."""

        return self._tools[name]

    def list(self) -> tuple[Tool, ...]:
        """Return all tools in stable name order."""

        return tuple(self._tools[name] for name in sorted(self._tools))

    def find_by_capability(self, capability: str) -> tuple[Tool, ...]:
        """Return exact capability matches in stable name order."""

        if not isinstance(capability, str) or not capability:
            raise ValueError("capability must be a non-empty string")
        return tuple(tool for tool in self.list() if capability in tool.capabilities)

    @staticmethod
    def _validate_tool(tool: Tool) -> None:
        try:
            name = tool.name
            description = tool.description
            capabilities = tool.capabilities
            input_schema = tool.input_schema
            risk_level = tool.risk_level
            execute = tool.execute
        except AttributeError as exc:
            raise TypeError("tool does not implement the Tool protocol") from exc
        if not isinstance(name, str) or _NAME_PATTERN.fullmatch(name) is None:
            raise ValueError("tool name must be a lowercase dotted identifier")
        if not isinstance(description, str) or not description.strip():
            raise ValueError("tool description must be non-empty")
        if not isinstance(capabilities, frozenset) or not capabilities:
            raise TypeError("tool capabilities must be a non-empty frozenset")
        if any(not isinstance(item, str) or not item for item in capabilities):
            raise ValueError("tool capabilities must contain non-empty strings")
        if not isinstance(input_schema, Mapping):
            raise TypeError("tool input_schema must be a mapping")
        if not isinstance(risk_level, RiskLevel):
            raise TypeError("tool risk_level must be a RiskLevel")
        if not callable(execute):
            raise TypeError("tool execute member must be callable")


LocalToolRegistry = ToolRegistry
