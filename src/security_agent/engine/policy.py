"""Central defense-in-depth authorization gate."""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from pathlib import Path
from urllib.parse import urlsplit

from security_agent.contracts import RiskLevel, Tool
from security_agent.contracts.common import JSONValue
from security_agent.domain import ScopeSpec
from security_agent.engine.errors import PolicyDeniedError


class ExecutionPolicy:
    def __init__(self, *, allow_high_risk: bool = False) -> None:
        self._allow_high_risk = allow_high_risk

    def authorize(
        self,
        tool: Tool,
        arguments: Mapping[str, JSONValue],
        scope: ScopeSpec,
    ) -> None:
        if tool.risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL} and not self._allow_high_risk:
            raise PolicyDeniedError(f"tool {tool.name!r} requires explicit high-risk approval")
        capabilities = tool.capabilities
        if any(capability.startswith(("network.", "http.")) for capability in capabilities):
            host = _network_host(arguments)
            if host is None or not _host_is_declared(host, scope.network_targets):
                raise PolicyDeniedError(f"network host {host!r} is outside the declared scope")
        if any(capability.startswith(("file.", "code.")) for capability in capabilities):
            path = _file_path(arguments)
            if path is None or not _path_is_declared(path, scope.file_roots):
                raise PolicyDeniedError(f"file path {path!r} is outside the declared scope")


def _network_host(arguments: Mapping[str, JSONValue]) -> str | None:
    target = arguments.get("target")
    if isinstance(target, str) and target:
        return target.rstrip(".").casefold()
    url = arguments.get("url")
    if isinstance(url, str):
        return urlsplit(url).hostname
    return None


def _file_path(arguments: Mapping[str, JSONValue]) -> str | None:
    for key in ("path", "root"):
        value = arguments.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _host_is_declared(host: str, declared: tuple[str, ...]) -> bool:
    normalized = host.rstrip(".").casefold()
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        return any(normalized == item.rstrip(".").casefold() for item in declared)
    for item in declared:
        try:
            if address in ipaddress.ip_network(item, strict=False):
                return True
        except ValueError:
            if normalized == item.rstrip(".").casefold():
                return True
    return False


def _path_is_declared(path: str, roots: tuple[str, ...]) -> bool:
    candidate = Path(path).resolve(strict=False)
    for root_text in roots:
        root = Path(root_text).resolve(strict=False)
        if candidate == root or root in candidate.parents:
            return True
    return False
