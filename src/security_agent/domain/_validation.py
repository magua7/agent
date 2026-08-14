"""Small validation helpers shared by the domain model.

The domain deliberately owns its JSON checks instead of importing the
contracts layer.  This keeps the dependency direction pointing inward.
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
from typing import TypeAlias

JSONScalar: TypeAlias = str | int | float | bool | None
JSONValue: TypeAlias = JSONScalar | list["JSONValue"] | dict[str, "JSONValue"]
JSONObject: TypeAlias = dict[str, JSONValue]


def require_non_blank(value: str, field_name: str) -> None:
    """Reject a missing or whitespace-only string."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-blank string")


def string_tuple(
    values: Iterable[str],
    field_name: str,
    *,
    required: bool = False,
    unique: bool = True,
) -> tuple[str, ...]:
    """Copy and validate a collection of non-blank strings."""
    if isinstance(values, str):
        raise ValueError(f"{field_name} must be a collection of strings")
    copied = tuple(values)
    for value in copied:
        require_non_blank(value, f"{field_name} item")
    if required and not copied:
        raise ValueError(f"{field_name} must not be empty")
    if unique and len(set(copied)) != len(copied):
        raise ValueError(f"{field_name} must contain unique values")
    return copied


def require_utc(value: datetime, field_name: str) -> None:
    """Require an aware datetime whose effective offset is UTC."""
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError(f"{field_name} must be a timezone-aware UTC datetime")
    try:
        offset = value.utcoffset()
    except (OverflowError, ValueError) as error:
        raise ValueError(f"{field_name} must be a valid UTC datetime") from error
    if offset != timedelta(0):
        raise ValueError(f"{field_name} must use UTC")


def require_non_negative_int(value: int, field_name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{field_name} must be a non-negative integer")


def require_positive_int(value: int, field_name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{field_name} must be a positive integer")


def copy_json_value(value: object, field_name: str = "value") -> JSONValue:
    """Validate and recursively copy a JSON value.

    NaN and infinities are rejected because they are not portable JSON even
    though Python's ``json`` module accepts them by default.
    """
    if value is None or isinstance(value, str | bool | int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{field_name} must contain only finite JSON numbers")
        return value
    if isinstance(value, list):
        return [copy_json_value(item, field_name) for item in value]
    if isinstance(value, Mapping):
        copied: JSONObject = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{field_name} JSON object keys must be strings")
            copied[key] = copy_json_value(item, field_name)
        return copied
    raise ValueError(f"{field_name} must be JSON-compatible")


def copy_json_object(value: Mapping[str, object], field_name: str) -> JSONObject:
    copied = copy_json_value(value, field_name)
    if not isinstance(copied, dict):  # pragma: no cover - guarded by the type and helper
        raise ValueError(f"{field_name} must be a JSON object")
    return copied


def merge_unique(
    existing: tuple[str, ...], additions: Iterable[str], field_name: str
) -> tuple[str, ...]:
    """Append validated references while retaining first-seen order."""
    new_values = string_tuple(additions, field_name, unique=False)
    result = list(existing)
    seen = set(existing)
    for value in new_values:
        if value not in seen:
            result.append(value)
            seen.add(value)
    return tuple(result)
