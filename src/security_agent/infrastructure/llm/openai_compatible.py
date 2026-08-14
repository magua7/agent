"""Small OpenAI-compatible HTTP adapter, intentionally without an SDK."""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx

from security_agent.contracts import LLMRequest, LLMResponse


class LLMProviderError(RuntimeError):
    """A model transport or response contract failed."""


@dataclass(frozen=True, slots=True)
class OpenAICompatibleConfig:
    base_url: str
    api_key: str
    model: str
    timeout_seconds: float = 60.0
    max_response_bytes: int = 2_000_000

    def __post_init__(self) -> None:
        parsed = urlsplit(self.base_url)
        if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
            raise ValueError("base_url must use http or https")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("base_url cannot contain credentials")
        if parsed.scheme == "http" and not _is_loopback_host(parsed.hostname):
            raise ValueError("non-loopback model endpoints must use https")
        if not self.api_key:
            raise ValueError("api_key must be non-empty")
        if not self.model:
            raise ValueError("model must be non-empty")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if self.max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be positive")


class OpenAICompatibleProvider:
    def __init__(
        self,
        config: OpenAICompatibleConfig,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._config = config
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(
            timeout=config.timeout_seconds,
            follow_redirects=False,
            trust_env=False,
        )

    async def complete(self, request: LLMRequest) -> LLMResponse:
        schema_note = ""
        if request.response_schema:
            schema_note = "\nReturn one JSON object matching this schema:\n" + json.dumps(
                request.response_schema,
                ensure_ascii=False,
                sort_keys=True,
            )
        body: dict[str, Any] = {
            "model": self._config.model,
            "temperature": request.temperature,
            "messages": [
                {"role": "system", "content": request.system_prompt + schema_note},
                {
                    "role": "user",
                    "content": json.dumps(request.payload, ensure_ascii=False, sort_keys=True),
                },
            ],
        }
        if request.response_schema:
            body["response_format"] = {"type": "json_object"}

        endpoint = self._config.base_url.rstrip("/") + "/chat/completions"
        try:
            async with self._client.stream(
                "POST",
                endpoint,
                headers={
                    "Authorization": f"Bearer {self._config.api_key}",
                    "Content-Type": "application/json",
                },
                json=body,
            ) as response:
                response.raise_for_status()
                encoded = bytearray()
                async for chunk in response.aiter_bytes():
                    if len(encoded) + len(chunk) > self._config.max_response_bytes:
                        raise LLMProviderError("model response exceeded the byte limit")
                    encoded.extend(chunk)
                payload = json.loads(encoded)
        except LLMProviderError:
            raise
        except (httpx.HTTPError, ValueError) as exc:
            raise LLMProviderError(f"model request failed: {type(exc).__name__}") from exc

        try:
            choice = payload["choices"][0]
            content = choice["message"]["content"]
            if not isinstance(content, str):
                raise TypeError("message content is not text")
            usage = payload.get("usage", {})
            if not isinstance(usage, dict):
                usage = {}
            return LLMResponse(
                content=content,
                model=payload.get("model"),
                finish_reason=choice.get("finish_reason"),
                usage=usage,
            )
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMProviderError("model response has an invalid shape") from exc

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()


def _is_loopback_host(host: str) -> bool:
    if host.casefold().rstrip(".") == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False
