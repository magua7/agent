"""Construction-boundary factories used throughout the domain."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from threading import Lock
from uuid import uuid4

_CLOCK_LOCK = Lock()
_LAST_TIMESTAMP: datetime | None = None


def new_id() -> str:
    """Return a new opaque UUID string."""
    return str(uuid4())


def utc_now() -> datetime:
    """Return a process-monotonic, timezone-aware UTC timestamp.

    Some Windows clocks expose less than microsecond resolution. Domain state
    revisions still need distinct timestamps when several transitions happen
    inside one clock tick, so equal or backwards wall-clock readings advance by
    one microsecond.
    """

    global _LAST_TIMESTAMP
    observed = datetime.now(UTC)
    with _CLOCK_LOCK:
        if _LAST_TIMESTAMP is not None and observed <= _LAST_TIMESTAMP:
            observed = _LAST_TIMESTAMP + timedelta(microseconds=1)
        _LAST_TIMESTAMP = observed
        return observed
