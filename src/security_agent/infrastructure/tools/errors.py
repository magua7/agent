"""Errors raised by local tool adapters.

Adapters normally turn these errors into :class:`ToolResult` failures at their
public boundary.  Keeping distinct exception types still makes the internal
policy checks easy to test and gives callers a stable ``error_type`` value.
"""

from __future__ import annotations


class InputValidationError(ValueError):
    """The supplied tool arguments do not satisfy the advertised schema."""


class ScopeViolation(PermissionError):
    """A requested resource is outside the task's explicit authorization."""


class ToolUnavailable(RuntimeError):
    """A requested execution engine is not installed or cannot be used."""


class DuplicateToolError(ValueError):
    """A registry already contains a tool with the requested name."""
