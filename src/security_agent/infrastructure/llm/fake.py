"""Deterministic model provider for offline tests."""

from __future__ import annotations

import asyncio
from collections import deque
from collections.abc import Callable, Iterable

from security_agent.contracts import LLMRequest, LLMResponse

FakeResponseFactory = Callable[[LLMRequest], LLMResponse | str]
FakeResponse = LLMResponse | str | Exception | FakeResponseFactory


class FakeLLMProvider:
    """Return predefined responses in order and retain received requests."""

    def __init__(self, responses: Iterable[FakeResponse]) -> None:
        self._responses = deque(responses)
        self._requests: list[LLMRequest] = []
        self._lock = asyncio.Lock()

    @property
    def requests(self) -> tuple[LLMRequest, ...]:
        return tuple(self._requests)

    @property
    def remaining(self) -> int:
        return len(self._responses)

    async def complete(self, request: LLMRequest) -> LLMResponse:
        async with self._lock:
            self._requests.append(request)
            if not self._responses:
                raise RuntimeError("FakeLLMProvider has no response remaining")
            item = self._responses.popleft()
        if callable(item):
            item = item(request)
        if isinstance(item, Exception):
            raise item
        if isinstance(item, str):
            return LLMResponse(content=item, model="fake")
        return item

    def assert_exhausted(self) -> None:
        if self._responses:
            raise AssertionError(f"{len(self._responses)} fake LLM response(s) were not consumed")
