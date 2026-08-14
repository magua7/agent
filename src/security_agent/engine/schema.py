"""A deliberately small JSON-schema subset for tool arguments."""

from __future__ import annotations

from collections.abc import Mapping

from security_agent.contracts.common import JSONValue


class SchemaValidationError(ValueError):
    pass


def validate_object(arguments: Mapping[str, JSONValue], schema: Mapping[str, JSONValue]) -> None:
    if schema.get("type", "object") != "object":
        raise SchemaValidationError("tool root schema must have type 'object'")
    properties_value = schema.get("properties", {})
    if not isinstance(properties_value, dict):
        raise SchemaValidationError("schema properties must be an object")
    required_value = schema.get("required", [])
    if not isinstance(required_value, list) or not all(
        isinstance(item, str) for item in required_value
    ):
        raise SchemaValidationError("schema required must be a string list")
    required_keys = [item for item in required_value if isinstance(item, str)]
    missing = [key for key in required_keys if key not in arguments]
    if missing:
        raise SchemaValidationError(f"missing required argument(s): {', '.join(missing)}")
    additional = schema.get("additionalProperties", False)
    if additional is not True:
        unknown = sorted(set(arguments) - set(properties_value))
        if unknown:
            raise SchemaValidationError(f"unknown argument(s): {', '.join(unknown)}")
    for name, value in arguments.items():
        property_schema = properties_value.get(name)
        if property_schema is None:
            continue
        if not isinstance(property_schema, dict):
            raise SchemaValidationError(f"schema for {name!r} must be an object")
        _validate_value(value, property_schema, path=name)


def _validate_value(value: JSONValue, schema: Mapping[str, JSONValue], *, path: str) -> None:
    expected = schema.get("type")
    if expected is not None:
        if not isinstance(expected, str):
            raise SchemaValidationError(f"schema type at {path} must be text")
        matches = {
            "string": isinstance(value, str),
            "integer": isinstance(value, int) and not isinstance(value, bool),
            "number": isinstance(value, int | float) and not isinstance(value, bool),
            "boolean": isinstance(value, bool),
            "array": isinstance(value, list),
            "object": isinstance(value, dict),
            "null": value is None,
        }.get(expected)
        if matches is None:
            raise SchemaValidationError(f"unsupported schema type {expected!r} at {path}")
        if not matches:
            raise SchemaValidationError(f"argument {path!r} must have type {expected}")
    enum = schema.get("enum")
    if enum is not None:
        if not isinstance(enum, list):
            raise SchemaValidationError(f"enum at {path} must be a list")
        if value not in enum:
            raise SchemaValidationError(f"argument {path!r} is not an allowed value")
    if isinstance(value, str):
        _check_integer_keyword(len(value), schema, "minLength", path, minimum=True)
        _check_integer_keyword(len(value), schema, "maxLength", path, minimum=False)
    if isinstance(value, list):
        _check_integer_keyword(len(value), schema, "minItems", path, minimum=True)
        _check_integer_keyword(len(value), schema, "maxItems", path, minimum=False)
        item_schema = schema.get("items")
        if item_schema is not None:
            if not isinstance(item_schema, dict):
                raise SchemaValidationError(f"items at {path} must be an object")
            for index, item in enumerate(value):
                _validate_value(item, item_schema, path=f"{path}[{index}]")
    if isinstance(value, int | float) and not isinstance(value, bool):
        minimum = schema.get("minimum")
        maximum = schema.get("maximum")
        if isinstance(minimum, int | float) and value < minimum:
            raise SchemaValidationError(f"argument {path!r} is below minimum")
        if isinstance(maximum, int | float) and value > maximum:
            raise SchemaValidationError(f"argument {path!r} is above maximum")


def _check_integer_keyword(
    actual: int,
    schema: Mapping[str, JSONValue],
    keyword: str,
    path: str,
    *,
    minimum: bool,
) -> None:
    boundary = schema.get(keyword)
    if boundary is None:
        return
    if not isinstance(boundary, int) or isinstance(boundary, bool) or boundary < 0:
        raise SchemaValidationError(f"{keyword} at {path} must be a non-negative integer")
    if (minimum and actual < boundary) or (not minimum and actual > boundary):
        raise SchemaValidationError(f"argument {path!r} violates {keyword}={boundary}")
