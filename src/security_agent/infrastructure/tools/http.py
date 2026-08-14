"""A bounded, scope-aware HTTP client tool."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import cast
from urllib.parse import urlsplit, urlunsplit

import httpx

from security_agent.contracts import RiskLevel, ToolExecutionContext, ToolResult
from security_agent.contracts.common import JSONValue
from security_agent.infrastructure.tools._scope import (
    IPAddress,
    authorize_network_target,
    resolve_network_host,
)
from security_agent.infrastructure.tools.errors import InputValidationError
from security_agent.infrastructure.tools.validation import validate_arguments

_SENSITIVE_RESPONSE_HEADERS = frozenset(
    {
        "authorization",
        "authentication-info",
        "cookie",
        "location",
        "proxy-authenticate",
        "proxy-authentication-info",
        "proxy-authorization",
        "set-cookie",
        "set-cookie2",
        "www-authenticate",
    }
)
_SENSITIVE_HEADER_FRAGMENTS = ("api-key", "apikey", "secret", "token")
_HEADER_NAME = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


class HttpRequestTool:
    """Perform non-redirecting HTTP requests to explicitly scoped targets."""

    name = "http_request"
    description = "Issue a bounded GET or HEAD request to an authorized network target."
    capabilities = frozenset({"http.request"})
    risk_level = RiskLevel.MEDIUM

    def __init__(
        self,
        *,
        max_response_bytes: int = 1_000_000,
        max_timeout_seconds: float = 30.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be positive")
        if max_timeout_seconds <= 0:
            raise ValueError("max_timeout_seconds must be positive")
        self._max_response_bytes = max_response_bytes
        self._max_timeout_seconds = max_timeout_seconds
        self._transport = transport

    @property
    def input_schema(self) -> Mapping[str, JSONValue]:
        return {
            "type": "object",
            "properties": {
                "url": {"type": "string", "minLength": 1, "maxLength": 8192},
                "method": {"type": "string", "enum": ["GET", "HEAD", "get", "head"]},
                "headers": {
                    "type": "object",
                    "additionalProperties": {"type": "string", "maxLength": 8192},
                },
                "timeout_seconds": {
                    "type": "number",
                    "exclusiveMinimum": 0,
                    "maximum": self._max_timeout_seconds,
                },
                "max_response_bytes": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": self._max_response_bytes,
                },
            },
            "required": ["url"],
            "additionalProperties": False,
        }

    async def execute(
        self,
        context: ToolExecutionContext,
        arguments: Mapping[str, JSONValue],
    ) -> ToolResult:
        try:
            validate_arguments(self.input_schema, arguments)
            url = cast(str, arguments["url"])
            method = cast(str, arguments.get("method", "GET")).upper()
            parsed = urlsplit(url)
            if parsed.scheme.lower() not in {"http", "https"}:
                raise InputValidationError("$.url: only http and https schemes are permitted")
            if parsed.hostname is None:
                raise InputValidationError("$.url: URL must include a hostname")
            if parsed.username is not None or parsed.password is not None:
                raise InputValidationError("$.url: embedded credentials are not permitted")
            try:
                port = parsed.port
            except ValueError as exc:
                raise InputValidationError(f"$.url: invalid port: {exc}") from exc
            if port is None:
                port = 443 if parsed.scheme.lower() == "https" else 80
            if not 1 <= port <= 65_535:
                raise InputValidationError("$.url: port must be between 1 and 65535")

            raw_timeout = arguments.get("timeout_seconds", context.timeout_seconds)
            requested_timeout = float(cast(int | float, raw_timeout))
            timeout = min(context.timeout_seconds, self._max_timeout_seconds)
            if requested_timeout > timeout:
                raise InputValidationError(
                    f"$.timeout_seconds: must not exceed the execution limit of {timeout}"
                )
            requested_bytes = cast(
                int,
                arguments.get("max_response_bytes", self._max_response_bytes),
            )
            byte_limit = min(self._max_response_bytes, context.max_output_bytes)
            if requested_bytes > byte_limit:
                raise InputValidationError(
                    f"$.max_response_bytes: must not exceed the execution limit of {byte_limit}"
                )

            addresses = await resolve_network_host(
                parsed.hostname,
                port,
                resolution_timeout=requested_timeout,
            )
            authorize_network_target(context.scope, parsed.hostname, port, addresses)
            raw_headers = arguments.get("headers", {})
            if not isinstance(raw_headers, Mapping):
                raise InputValidationError("$.headers: expected object")
            headers = {str(key): cast(str, value) for key, value in raw_headers.items()}
            for name, value in headers.items():
                if not _HEADER_NAME.fullmatch(name):
                    raise InputValidationError("$.headers: invalid HTTP header name")
                if any(character in value for character in ("\r", "\n", "\x00")):
                    raise InputValidationError(
                        "$.headers: header values cannot contain control line breaks"
                    )
            if any(name.casefold() == "host" for name in headers):
                raise InputValidationError(
                    "$.headers.Host: overriding the Host header is not permitted"
                )
            connected_address = _select_http_address(addresses)
            pinned_url, host_header = _pin_url_to_address(
                url,
                address=connected_address,
                port=port,
            )
            headers["Host"] = host_header
            return await self._request(
                method=method,
                url=pinned_url,
                headers=headers,
                request_timeout=requested_timeout,
                byte_limit=requested_bytes,
                addresses=tuple(str(address) for address in addresses),
                connected_address=str(connected_address),
                sni_hostname=parsed.hostname,
            )
        except (OSError, RuntimeError, ValueError, httpx.HTTPError) as exc:
            return _http_failure(exc)

    async def _request(
        self,
        *,
        method: str,
        url: str,
        headers: dict[str, str],
        request_timeout: float,
        byte_limit: int,
        addresses: tuple[str, ...],
        connected_address: str,
        sni_hostname: str,
    ) -> ToolResult:
        client_timeout = httpx.Timeout(request_timeout)
        try:
            async with httpx.AsyncClient(
                follow_redirects=False,
                timeout=client_timeout,
                trust_env=False,
                transport=self._transport,
            ) as client:
                async with client.stream(
                    method,
                    url,
                    headers=headers,
                    extensions={"sni_hostname": sni_hostname},
                ) as response:
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        if len(body) + len(chunk) > byte_limit:
                            metadata = _response_metadata(
                                response,
                                addresses,
                                connected_address,
                            )
                            metadata["response_bytes_exceeded"] = byte_limit
                            return ToolResult(
                                success=False,
                                error=(
                                    "ResponseTooLarge: response body exceeds "
                                    f"the {byte_limit}-byte limit"
                                ),
                                metadata=metadata,
                            )
                        body.extend(chunk)
                    encoding = response.encoding or "utf-8"
                    output = bytes(body).decode(encoding, errors="replace")
                    output_bytes = len(output.encode("utf-8"))
                    if output_bytes > byte_limit:
                        metadata = _response_metadata(response, addresses, connected_address)
                        metadata["output_bytes"] = output_bytes
                        return ToolResult(
                            success=False,
                            error=(
                                "ResponseTooLarge: decoded response exceeds "
                                f"the {byte_limit}-byte output limit"
                            ),
                            metadata=metadata,
                        )
                    metadata = _response_metadata(response, addresses, connected_address)
                    metadata["body_bytes"] = len(body)
                    metadata["output_bytes"] = output_bytes
                    metadata["encoding"] = encoding
                    return ToolResult(success=True, output=output, metadata=metadata)
        except TimeoutError as exc:
            raise OSError(f"HTTP request timed out after {request_timeout} seconds") from exc


def _response_metadata(
    response: httpx.Response,
    addresses: tuple[str, ...],
    connected_address: str,
) -> dict[str, JSONValue]:
    location = response.headers.get("location")
    metadata: dict[str, JSONValue] = {
        "status_code": response.status_code,
        "http_version": response.http_version,
        "resolved_addresses": cast(JSONValue, list(addresses)),
        "connected_address": connected_address,
        "redirect_followed": False,
        "response_headers": cast(JSONValue, _redact_response_headers(response.headers)),
    }
    if location is not None:
        parsed_location = urlsplit(location)
        metadata["location"] = urlunsplit(
            (
                parsed_location.scheme,
                parsed_location.netloc,
                parsed_location.path,
                "[REDACTED]" if parsed_location.query else "",
                "",
            )
        )
    return metadata


def _select_http_address(addresses: tuple[IPAddress, ...]) -> IPAddress:
    if not addresses:
        raise OSError("network target has no resolved address")
    return next((address for address in addresses if address.version == 4), addresses[0])


def _pin_url_to_address(url: str, *, address: IPAddress, port: int) -> tuple[str, str]:
    parsed = urlsplit(url)
    original_host = parsed.hostname
    if original_host is None:
        raise InputValidationError("$.url: URL must include a hostname")
    address_text = f"[{address}]" if address.version == 6 else str(address)
    pinned_netloc = f"{address_text}:{port}"
    original_host_text = f"[{original_host}]" if ":" in original_host else original_host
    try:
        explicit_port = parsed.port is not None
    except ValueError as exc:
        raise InputValidationError(f"$.url: invalid port: {exc}") from exc
    host_header = f"{original_host_text}:{port}" if explicit_port else original_host_text
    pinned_url = urlunsplit(
        (parsed.scheme, pinned_netloc, parsed.path, parsed.query, parsed.fragment)
    )
    return pinned_url, host_header


def _redact_response_headers(headers: httpx.Headers) -> dict[str, str]:
    redacted: dict[str, str] = {}
    for name, value in headers.items():
        normalized = name.casefold()
        is_sensitive = normalized in _SENSITIVE_RESPONSE_HEADERS or any(
            fragment in normalized for fragment in _SENSITIVE_HEADER_FRAGMENTS
        )
        redacted[name] = "[REDACTED]" if is_sensitive else value
    return redacted


def _http_failure(exc: Exception) -> ToolResult:
    detail = str(exc) if isinstance(exc, InputValidationError) else "request failed"
    return ToolResult(
        success=False,
        error=f"{type(exc).__name__}: {detail}",
        metadata={"error_type": type(exc).__name__, "redirect_followed": False},
    )
