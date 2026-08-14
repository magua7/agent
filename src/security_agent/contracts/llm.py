"""Model-provider port with no vendor SDK dependency."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Protocol

from security_agent.contracts.common import JSONObject, is_json_value


@dataclass(frozen=True, slots=True)
class LLMRequest:
    operation: str
    system_prompt: str
    payload: JSONObject
    response_schema: JSONObject = field(default_factory=dict)
    temperature: float = 0.0

    def __post_init__(self) -> None:
        if not self.operation.strip():
            raise ValueError("LLM operation must be non-empty")
        if not 0.0 <= self.temperature <= 2.0:
            raise ValueError("temperature must be between 0 and 2")
        if not is_json_value(self.payload) or not is_json_value(self.response_schema):
            raise ValueError("LLM payload and response schema must be finite JSON values")


@dataclass(frozen=True, slots=True)
class LLMResponse:
    content: str
    model: str | None = None
    finish_reason: str | None = None
    usage: JSONObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.content, str):
            raise ValueError("LLM response content must be text")
        if not is_json_value(self.usage):
            raise ValueError("LLM usage must be a finite JSON object")

    def json_object(self) -> JSONObject:
        value = json.loads(self.content)
        if (
            not isinstance(value, dict)
            or not all(isinstance(key, str) for key in value)
            or not is_json_value(value)
        ):
            raise ValueError("LLM response must be a JSON object")
        return value


class LLMProvider(Protocol):
    async def complete(self, request: LLMRequest) -> LLMResponse: ...
