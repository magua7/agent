"""A deliberately small, dependency-free JSON Schema validator.

The validator implements only the keywords used by core tools.  It is strict
about JSON types (notably, booleans are not integers) and reports the first
failure with a stable JSON-path-like location.
"""

from __future__ import annotations

import math
import re
from collections.abc import Callable, Mapping, Sequence
from typing import cast

from security_agent.contracts.common import JSONValue
from security_agent.infrastructure.tools.errors import InputValidationError


def validate_input(schema: Mapping[str, JSONValue], value: object) -> None:
    """Validate *value* against the supported schema subset.

    Supported keywords are ``type``, ``enum``, ``const``, object properties,
    required/additional properties, array item and size constraints, string
    size/pattern constraints, and numeric bounds.
    """

    _validate(schema, value, path="$")


def validate_arguments(
    schema: Mapping[str, JSONValue],
    arguments: Mapping[str, JSONValue],
) -> None:
    """Validate a tool argument mapping."""

    validate_input(schema, arguments)


def _validate(schema: Mapping[str, JSONValue], value: object, *, path: str) -> None:
    declared_type = schema.get("type")
    if declared_type is not None and not _matches_declared_type(declared_type, value):
        expected = _describe_declared_type(declared_type)
        raise InputValidationError(f"{path}: expected {expected}, got {_json_type(value)}")

    enum_values = schema.get("enum")
    if enum_values is not None:
        if not isinstance(enum_values, list):
            raise ValueError("schema enum must be an array")
        if not any(_json_equal(value, candidate) for candidate in enum_values):
            raise InputValidationError(f"{path}: value is not one of the permitted values")

    if "const" in schema and not _json_equal(value, schema["const"]):
        raise InputValidationError(f"{path}: value does not equal the required constant")

    if isinstance(value, str):
        _validate_string(schema, value, path=path)
    elif _is_number(value):
        _validate_number(schema, cast(int | float, value), path=path)
    elif isinstance(value, list):
        _validate_array(schema, value, path=path)
    elif isinstance(value, Mapping):
        _validate_object(schema, value, path=path)


def _matches_declared_type(declared: JSONValue, value: object) -> bool:
    if isinstance(declared, str):
        return _matches_type(declared, value)
    if isinstance(declared, list) and declared and all(isinstance(item, str) for item in declared):
        declared_names = cast(list[str], declared)
        return any(_matches_type(item, value) for item in declared_names)
    raise ValueError("schema type must be a string or non-empty array of strings")


def _describe_declared_type(declared: JSONValue) -> str:
    if isinstance(declared, str):
        return declared
    if isinstance(declared, list):
        return " or ".join(str(item) for item in declared)
    return "valid JSON type"


def _matches_type(name: str, value: object) -> bool:
    if name == "null":
        return value is None
    if name == "boolean":
        return isinstance(value, bool)
    if name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if name == "number":
        return _is_number(value)
    if name == "string":
        return isinstance(value, str)
    if name == "array":
        return isinstance(value, list)
    if name == "object":
        return isinstance(value, Mapping) and all(isinstance(key, str) for key in value)
    raise ValueError(f"unsupported schema type: {name}")


def _validate_string(schema: Mapping[str, JSONValue], value: str, *, path: str) -> None:
    minimum = _optional_int_keyword(schema, "minLength")
    maximum = _optional_int_keyword(schema, "maxLength")
    if minimum is not None and len(value) < minimum:
        raise InputValidationError(f"{path}: string is shorter than {minimum} characters")
    if maximum is not None and len(value) > maximum:
        raise InputValidationError(f"{path}: string is longer than {maximum} characters")
    pattern = schema.get("pattern")
    if pattern is not None:
        if not isinstance(pattern, str):
            raise ValueError("schema pattern must be a string")
        try:
            matched = re.search(pattern, value) is not None
        except re.error as exc:
            raise ValueError(f"invalid schema pattern: {exc}") from exc
        if not matched:
            raise InputValidationError(f"{path}: string does not match the required pattern")


def _validate_number(
    schema: Mapping[str, JSONValue],
    value: int | float,
    *,
    path: str,
) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise InputValidationError(f"{path}: number must be finite")
    bounds: tuple[
        tuple[str, Callable[[int | float, int | float], bool], str],
        ...,
    ] = (
        ("minimum", lambda current, bound: current >= bound, ">="),
        ("maximum", lambda current, bound: current <= bound, "<="),
        ("exclusiveMinimum", lambda current, bound: current > bound, ">"),
        ("exclusiveMaximum", lambda current, bound: current < bound, "<"),
    )
    for keyword, predicate, operator in bounds:
        bound = schema.get(keyword)
        if bound is None:
            continue
        if not _is_number(bound):
            raise ValueError(f"schema {keyword} must be a number")
        numeric_bound = cast(int | float, bound)
        if not predicate(value, numeric_bound):
            raise InputValidationError(f"{path}: number must be {operator} {numeric_bound}")


def _validate_array(
    schema: Mapping[str, JSONValue],
    value: list[object],
    *,
    path: str,
) -> None:
    minimum = _optional_int_keyword(schema, "minItems")
    maximum = _optional_int_keyword(schema, "maxItems")
    if minimum is not None and len(value) < minimum:
        raise InputValidationError(f"{path}: array has fewer than {minimum} items")
    if maximum is not None and len(value) > maximum:
        raise InputValidationError(f"{path}: array has more than {maximum} items")
    if schema.get("uniqueItems") is True:
        for index, item in enumerate(value):
            if any(_json_equal(item, previous) for previous in value[:index]):
                raise InputValidationError(f"{path}[{index}]: duplicate array item")
    items = schema.get("items")
    if items is None:
        return
    item_schema = _as_schema(items, keyword="items")
    for index, item in enumerate(value):
        _validate(item_schema, item, path=f"{path}[{index}]")


def _validate_object(
    schema: Mapping[str, JSONValue],
    value: Mapping[object, object],
    *,
    path: str,
) -> None:
    if not all(isinstance(key, str) for key in value):
        raise InputValidationError(f"{path}: object keys must be strings")
    string_value = cast(Mapping[str, object], value)
    required = schema.get("required", [])
    if not isinstance(required, list) or not all(isinstance(item, str) for item in required):
        raise ValueError("schema required must be an array of strings")
    for name in cast(list[str], required):
        if name not in string_value:
            raise InputValidationError(f"{path}.{name}: required property is missing")

    properties_value = schema.get("properties", {})
    if not isinstance(properties_value, dict):
        raise ValueError("schema properties must be an object")
    properties = properties_value
    additional = schema.get("additionalProperties", True)
    for name, item in string_value.items():
        property_schema_value = properties.get(name)
        child_path = f"{path}.{name}"
        if property_schema_value is not None:
            _validate(
                _as_schema(property_schema_value, keyword=f"properties.{name}"),
                item,
                path=child_path,
            )
        elif additional is False:
            raise InputValidationError(f"{child_path}: additional property is not permitted")
        elif isinstance(additional, dict):
            _validate(_as_schema(additional, keyword="additionalProperties"), item, path=child_path)
        elif additional is not True:
            raise ValueError("schema additionalProperties must be a boolean or object")


def _as_schema(value: JSONValue, *, keyword: str) -> Mapping[str, JSONValue]:
    if not isinstance(value, dict):
        raise ValueError(f"schema {keyword} must be an object")
    return value


def _optional_int_keyword(schema: Mapping[str, JSONValue], keyword: str) -> int | None:
    value = schema.get(keyword)
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"schema {keyword} must be a non-negative integer")
    return value


def _is_number(value: object) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool)


def _json_type(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, Mapping):
        return "object"
    return type(value).__name__


def _json_equal(left: object, right: object) -> bool:
    if _json_type(left) != _json_type(right):
        return False
    if isinstance(left, Mapping) and isinstance(right, Mapping):
        return dict(left) == dict(right)
    if isinstance(left, Sequence) and not isinstance(left, str | bytes):
        return left == right
    return left == right
