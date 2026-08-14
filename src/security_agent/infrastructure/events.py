"""Lightweight in-process event fan-out."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from security_agent.contracts import EventSink, RunEvent


class EventPublishError(RuntimeError):
    pass


class NullEventSink:
    async def publish(self, event: RunEvent) -> None:
        del event


@dataclass(slots=True)
class MemoryEventSink:
    _events: list[RunEvent] = field(default_factory=list)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    @property
    def events(self) -> tuple[RunEvent, ...]:
        return tuple(self._events)

    async def publish(self, event: RunEvent) -> None:
        async with self._lock:
            self._events.append(event)


class EventBus:
    def __init__(self, sinks: tuple[EventSink, ...] = (), *, strict: bool = False) -> None:
        self._sinks = sinks
        self._strict = strict
        self._errors: list[str] = []

    @property
    def errors(self) -> tuple[str, ...]:
        return tuple(self._errors)

    async def publish(self, event: RunEvent) -> None:
        if not self._sinks:
            return
        results = await asyncio.gather(
            *(sink.publish(event) for sink in self._sinks),
            return_exceptions=True,
        )
        failures = [result for result in results if isinstance(result, BaseException)]
        if not failures:
            return
        self._errors.extend(type(failure).__name__ for failure in failures)
        if self._strict:
            raise EventPublishError(
                f"{len(failures)} event sink(s) failed while publishing {event.event_type}"
            ) from failures[0]
