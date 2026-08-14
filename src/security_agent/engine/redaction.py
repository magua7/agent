"""Deterministic redaction for audit records and model-bound task inputs."""

from __future__ import annotations

from collections.abc import Mapping
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from security_agent.contracts.common import JSONObject, JSONValue

_SECRET_MARKERS = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "api-key",
    "apikey",
    "authorization",
    "cookie",
    "credential",
    "signature",
    "sig",
)


def redact_json_object(value: Mapping[str, JSONValue]) -> JSONObject:
    """Recursively redact secret-like keys and sensitive URL query values."""
    return {key: _redact_value(item, key=key) for key, item in value.items()}


def _redact_value(value: JSONValue, *, key: str) -> JSONValue:
    normalized = key.casefold()
    if any(marker in normalized for marker in _SECRET_MARKERS):
        return "[REDACTED]"
    if isinstance(value, dict):
        return redact_json_object(value)
    if isinstance(value, list):
        return [_redact_value(item, key=key) for item in value]
    if isinstance(value, str) and normalized in {"url", "uri", "endpoint"}:
        return redact_url_query(value)
    return value


def redact_url_query(url: str) -> str:
    """Return a safe audit/model form of a URL.

    Userinfo and fragments are removed, and every query value is redacted. A
    query parameter name is useful for planning; its value generally is not.
    """
    try:
        parsed = urlsplit(url)
        query = parse_qsl(parsed.query, keep_blank_values=True)
        safe_query = [(name, "[REDACTED]") for name, _value in query]
        netloc = parsed.netloc
        if parsed.hostname is not None:
            host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
            port = parsed.port
            netloc = host if port is None else f"{host}:{port}"
        elif parsed.netloc:
            netloc = "[REDACTED]"
        return urlunsplit((parsed.scheme, netloc, parsed.path, urlencode(safe_query), ""))
    except ValueError:
        return "[REDACTED INVALID URL]"
