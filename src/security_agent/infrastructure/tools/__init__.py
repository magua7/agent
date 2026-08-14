"""Built-in, scope-aware tool adapters."""

from security_agent.infrastructure.tools.errors import (
    DuplicateToolError,
    InputValidationError,
    ScopeViolation,
    ToolUnavailable,
)
from security_agent.infrastructure.tools.filesystem import FileReadTool, FileSearchTool
from security_agent.infrastructure.tools.http import HttpRequestTool
from security_agent.infrastructure.tools.network import NetworkScanTool
from security_agent.infrastructure.tools.registry import LocalToolRegistry, ToolRegistry
from security_agent.infrastructure.tools.validation import validate_arguments, validate_input


def build_default_tool_registry(*, nmap_only: bool = False) -> ToolRegistry:
    """Create a registry containing the four lightweight built-in tools."""

    registry = ToolRegistry()
    registry.register(FileReadTool())
    registry.register(FileSearchTool())
    registry.register(HttpRequestTool())
    registry.register(NetworkScanTool(nmap_only=nmap_only))
    return registry


__all__ = [
    "DuplicateToolError",
    "FileReadTool",
    "FileSearchTool",
    "HttpRequestTool",
    "InputValidationError",
    "LocalToolRegistry",
    "NetworkScanTool",
    "ScopeViolation",
    "ToolRegistry",
    "ToolUnavailable",
    "build_default_tool_registry",
    "validate_arguments",
    "validate_input",
]
