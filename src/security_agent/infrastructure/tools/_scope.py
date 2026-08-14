"""Shared scope enforcement for local tools."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import TypeAlias
from urllib.parse import urlsplit

from security_agent.infrastructure.tools.errors import ScopeViolation

IPAddress: TypeAlias = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork: TypeAlias = ipaddress.IPv4Network | ipaddress.IPv6Network


def authorized_file_roots(scope: object) -> tuple[Path, ...]:
    """Return canonical, existing directory roots declared by *scope*."""

    raw_roots = getattr(scope, "file_roots", ())
    if isinstance(raw_roots, str | Path):
        values: Iterable[object] = (raw_roots,)
    elif isinstance(raw_roots, Iterable):
        values = raw_roots
    else:
        values = ()
    roots: set[Path] = set()
    for value in values:
        if not isinstance(value, str | Path):
            continue
        try:
            root = Path(value).expanduser().resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if root.is_dir():
            roots.add(root)
    return tuple(sorted(roots, key=lambda item: str(item).casefold()))


def resolve_authorized_path(
    scope: object,
    requested: str | Path,
    *,
    require_directory: bool | None = None,
) -> Path:
    """Resolve a path and prove that it is contained by an authorized root.

    Relative paths are interpreted relative to each authorized root.  An
    absolute path is never rewritten.  Symlinks are resolved before the
    containment check.
    """

    roots = authorized_file_roots(scope)
    if not roots:
        raise ScopeViolation("file access denied: scope has no authorized file roots")
    supplied = Path(requested).expanduser()
    candidates = (supplied,) if supplied.is_absolute() else tuple(root / supplied for root in roots)
    missing_candidate = False
    for candidate in candidates:
        try:
            unresolved = candidate.resolve(strict=False)
        except (OSError, RuntimeError):
            continue
        if not any(_is_within(unresolved, root) for root in roots):
            continue
        try:
            resolved = candidate.resolve(strict=True)
        except FileNotFoundError:
            missing_candidate = True
            continue
        except (OSError, RuntimeError):
            continue
        if not any(_is_within(resolved, root) for root in roots):
            continue
        if require_directory is True and not resolved.is_dir():
            raise NotADirectoryError(str(resolved))
        if require_directory is False and not resolved.is_file():
            raise IsADirectoryError(str(resolved))
        return resolved
    if missing_candidate:
        raise FileNotFoundError(str(requested))
    raise ScopeViolation("file access denied: resolved path is outside authorized roots")


def path_is_authorized(path: Path, roots: tuple[Path, ...]) -> bool:
    """Return whether a resolved path is within any resolved root."""

    return any(_is_within(path, root) for root in roots)


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


@dataclass(frozen=True, slots=True)
class NetworkRule:
    """A normalized network target from a task scope."""

    hostname: str | None = None
    network: IPNetwork | None = None
    port: int | None = None

    def permits_port(self, port: int) -> bool:
        return self.port is None or self.port == port


def network_rules(scope: object) -> tuple[NetworkRule, ...]:
    """Normalize explicit network targets from *scope*.

    Accepted scope entries are a hostname, IP address, CIDR, ``host:port``, or
    an HTTP(S) URL.  Wildcards and malformed entries grant no authority.
    """

    raw_targets = getattr(scope, "network_targets", ())
    if isinstance(raw_targets, str):
        values: Iterable[object] = (raw_targets,)
    elif isinstance(raw_targets, Iterable):
        values = raw_targets
    else:
        values = ()
    rules: set[NetworkRule] = set()
    for value in values:
        if not isinstance(value, str):
            continue
        rule = _parse_network_rule(value)
        if rule is not None:
            rules.add(rule)
    return tuple(sorted(rules, key=_network_rule_sort_key))


async def resolve_network_host(
    host: str,
    port: int,
    *,
    resolution_timeout: float,
) -> tuple[IPAddress, ...]:
    """Resolve *host* once, returning stable, de-duplicated addresses."""

    try:
        literal = _parse_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        return (literal,)
    normalized = normalize_hostname(host)
    if not normalized:
        raise ScopeViolation("network target has an invalid hostname")
    loop = asyncio.get_running_loop()
    try:
        records = await asyncio.wait_for(
            loop.getaddrinfo(
                normalized,
                port,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
            ),
            timeout=resolution_timeout,
        )
    except TimeoutError as exc:
        raise OSError(f"DNS resolution timed out for {normalized}") from exc
    addresses: set[IPAddress] = set()
    for family, _type, _protocol, _canonname, sockaddr in records:
        if family not in {socket.AF_INET, socket.AF_INET6}:
            continue
        try:
            addresses.add(ipaddress.ip_address(sockaddr[0].split("%", maxsplit=1)[0]))
        except ValueError:
            continue
    if not addresses:
        raise OSError(f"DNS resolution returned no usable addresses for {normalized}")
    if len(addresses) > 16:
        raise ScopeViolation("network target resolves to more than 16 addresses")
    return tuple(sorted(addresses, key=lambda item: (item.version, int(item))))


def authorize_network_target(
    scope: object,
    host: str,
    port: int,
    resolved_addresses: tuple[IPAddress, ...],
) -> None:
    """Require a host/port and every resolved address to be explicitly scoped."""

    rules = network_rules(scope)
    if not rules:
        raise ScopeViolation("network access denied: scope has no explicit network targets")
    normalized_host = normalize_hostname(host)
    hostname_rules = tuple(
        rule for rule in rules if rule.hostname == normalized_host and rule.permits_port(port)
    )
    if hostname_rules:
        # A hostname authorizes its ordinary public destinations. Special-use
        # addresses require a second, explicit IP/CIDR rule; this blocks a
        # controlled DNS name from silently becoming loopback/link-local/private.
        for address in resolved_addresses:
            if _is_special_use(address) and not _address_permitted_by_network_rule(
                rules,
                address,
                port,
            ):
                raise ScopeViolation(
                    "network access denied: hostname resolved to a special-use address "
                    "that is not explicitly scoped"
                )
        return
    if not resolved_addresses:
        raise ScopeViolation("network access denied: target has no resolved addresses")
    for address in resolved_addresses:
        permitted = _address_permitted_by_network_rule(rules, address, port)
        if not permitted:
            raise ScopeViolation(
                f"network access denied: {address} is outside the authorized target scope"
            )


def _address_permitted_by_network_rule(
    rules: tuple[NetworkRule, ...],
    address: IPAddress,
    port: int,
) -> bool:
    return any(
        rule.network is not None
        and rule.permits_port(port)
        and address.version == rule.network.version
        and address in rule.network
        for rule in rules
    )


def _is_special_use(address: IPAddress) -> bool:
    return bool(
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def normalize_hostname(host: str) -> str:
    """Return a lower-case ASCII hostname without a trailing dot."""

    candidate = host.strip().rstrip(".")
    if not candidate or candidate == "*" or "\x00" in candidate:
        return ""
    try:
        return candidate.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return ""


def _parse_network_rule(raw: str) -> NetworkRule | None:
    value = raw.strip()
    if not value or value == "*":
        return None
    host: str
    port: int | None = None
    if "://" in value:
        parsed = urlsplit(value)
        if parsed.scheme.lower() not in {"http", "https"} or parsed.hostname is None:
            return None
        host = parsed.hostname
        try:
            port = parsed.port
        except ValueError:
            return None
        if port is None:
            port = 443 if parsed.scheme.lower() == "https" else 80
    else:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            network = None
        if network is not None:
            return NetworkRule(network=network)
        host, port = _split_host_port(value)
    if port is not None and not 1 <= port <= 65_535:
        return None
    try:
        address = _parse_address(host)
    except ValueError:
        address = None
    if address is not None:
        bits = 32 if address.version == 4 else 128
        return NetworkRule(network=ipaddress.ip_network(f"{address}/{bits}"), port=port)
    hostname = normalize_hostname(host)
    if not hostname or any(character.isspace() for character in hostname):
        return None
    return NetworkRule(hostname=hostname, port=port)


def _split_host_port(value: str) -> tuple[str, int | None]:
    if value.startswith("["):
        closing = value.find("]")
        if closing == -1:
            return value, None
        host = value[1:closing]
        suffix = value[closing + 1 :]
        if not suffix:
            return host, None
        if suffix.startswith(":") and suffix[1:].isdigit():
            return host, int(suffix[1:])
        return value, None
    if value.count(":") == 1:
        host, possible_port = value.rsplit(":", maxsplit=1)
        if host and possible_port.isdigit():
            return host, int(possible_port)
    return value, None


def _parse_address(host: str) -> IPAddress:
    return ipaddress.ip_address(host.strip().strip("[]").split("%", maxsplit=1)[0])


def _network_rule_sort_key(rule: NetworkRule) -> tuple[str, str, int]:
    return (
        rule.hostname or "",
        str(rule.network) if rule.network is not None else "",
        rule.port or 0,
    )
