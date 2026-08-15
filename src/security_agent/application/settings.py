"""Strict local product settings loaded from a small JSON file."""

from __future__ import annotations

import json
import math
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TypeVar, cast

_MAX_SETTINGS_BYTES = 64 * 1024
_TOP_LEVEL_KEYS = frozenset({"llm"})
_LLM_KEYS = frozenset(
    {
        "enabled",
        "provider",
        "base_url",
        "api_key",
        "model",
        "timeout_seconds",
        "max_response_bytes",
    }
)
_T = TypeVar("_T")


class SettingsError(ValueError):
    """The local product settings file is unsafe or invalid."""


@dataclass(frozen=True, slots=True)
class LLMSettings:
    """Configuration needed to construct the optional model provider."""

    enabled: bool = False
    provider: str = "openai-compatible"
    base_url: str = ""
    api_key: str = field(default="", repr=False)
    model: str = ""
    timeout_seconds: float = 60.0
    max_response_bytes: int = 2_000_000

    def __post_init__(self) -> None:
        if type(self.enabled) is not bool:
            raise SettingsError("llm.enabled must be a boolean")
        for name, value in (
            ("provider", self.provider),
            ("base_url", self.base_url),
            ("api_key", self.api_key),
            ("model", self.model),
        ):
            if not isinstance(value, str):
                raise SettingsError(f"llm.{name} must be a string")
        if (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, (int, float))
            or not math.isfinite(self.timeout_seconds)
            or self.timeout_seconds <= 0
        ):
            raise SettingsError("llm.timeout_seconds must be a finite positive number")
        if type(self.max_response_bytes) is not int or self.max_response_bytes <= 0:
            raise SettingsError("llm.max_response_bytes must be a positive integer")
        if self.enabled:
            if self.provider != "openai-compatible":
                raise SettingsError("llm.provider must be 'openai-compatible' when llm is enabled")
            for name, value in (
                ("base_url", self.base_url),
                ("api_key", self.api_key),
                ("model", self.model),
            ):
                if not value.strip():
                    raise SettingsError(f"llm.{name} must be non-empty when llm is enabled")


@dataclass(frozen=True, slots=True)
class ProductSettings:
    """All local settings used by the SEC-GO product bootstrap."""

    llm: LLMSettings = field(default_factory=LLMSettings)


def load_product_settings(path: Path) -> ProductSettings:
    """Load a bounded, strict JSON settings file; a missing file disables the LLM."""

    try:
        with path.open("rb") as handle:
            encoded = handle.read(_MAX_SETTINGS_BYTES + 1)
    except FileNotFoundError:
        return ProductSettings()
    except OSError as exc:
        raise SettingsError("unable to read the product settings file") from exc

    if len(encoded) > _MAX_SETTINGS_BYTES:
        raise SettingsError("product settings file exceeds the size limit")

    try:
        source = encoded.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise SettingsError("product settings file must be UTF-8 JSON") from exc

    try:
        document = json.loads(
            source,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_non_json_number,
        )
    except SettingsError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise SettingsError("product settings file contains invalid JSON") from exc

    root = _require_object(document, "top level")
    _reject_unknown_keys(root, _TOP_LEVEL_KEYS, "top level")
    raw_llm = root.get("llm")
    if raw_llm is None and "llm" not in root:
        return ProductSettings()
    llm = _require_object(raw_llm, "llm")
    _reject_unknown_keys(llm, _LLM_KEYS, "llm")

    defaults = LLMSettings()
    return ProductSettings(
        llm=LLMSettings(
            enabled=_value(llm, "enabled", defaults.enabled, _is_bool),
            provider=_value(llm, "provider", defaults.provider, _is_string),
            base_url=_value(llm, "base_url", defaults.base_url, _is_string),
            api_key=_value(llm, "api_key", defaults.api_key, _is_string),
            model=_value(llm, "model", defaults.model, _is_string),
            timeout_seconds=float(
                _value(llm, "timeout_seconds", defaults.timeout_seconds, _is_number)
            ),
            max_response_bytes=_value(
                llm,
                "max_response_bytes",
                defaults.max_response_bytes,
                _is_integer,
            ),
        )
    )


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SettingsError("product settings file contains a duplicate key")
        result[key] = value
    return result


def _reject_non_json_number(_value: str) -> Any:
    raise SettingsError("product settings file contains a non-standard number")


def _require_object(value: Any, location: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SettingsError(f"product settings {location} must be an object")
    return value


def _reject_unknown_keys(
    value: dict[str, Any],
    allowed: frozenset[str],
    location: str,
) -> None:
    if value.keys() - allowed:
        raise SettingsError(f"product settings {location} contains unknown keys")


def _value(
    values: dict[str, Any],
    name: str,
    default: _T,
    predicate: Callable[[Any], bool],
) -> _T:
    value = values.get(name, default)
    if not predicate(value):
        raise SettingsError(f"llm.{name} has the wrong type")
    return cast(_T, value)


def _is_bool(value: Any) -> bool:
    return type(value) is bool


def _is_string(value: Any) -> bool:
    return isinstance(value, str)


def _is_number(value: Any) -> bool:
    return not isinstance(value, bool) and isinstance(value, (int, float))


def _is_integer(value: Any) -> bool:
    return type(value) is int
