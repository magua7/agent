"""A tightly bounded network scan adapter."""

from __future__ import annotations

import asyncio
import json
import xml.etree.ElementTree as ET
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import cast

from security_agent.contracts import RiskLevel, ToolExecutionContext, ToolResult
from security_agent.contracts.common import JSONObject, JSONValue
from security_agent.infrastructure.tools._scope import (
    IPAddress,
    authorize_network_target,
    resolve_network_host,
)
from security_agent.infrastructure.tools.errors import InputValidationError, ToolUnavailable
from security_agent.infrastructure.tools.validation import validate_arguments

NmapLocator = Callable[[str], str | None]


class NetworkScanTool:
    """Scan explicit ports using nmap or a real asyncio TCP-connect fallback."""

    name = "network_scan"
    description = "Probe an authorized host and explicit bounded list of TCP ports."
    capabilities = frozenset({"network.scan"})
    # This adapter only performs bounded TCP connect probes (directly or via
    # nmap -sT). Exploitation, raw packets, scripts, and arbitrary nmap flags
    # are deliberately unavailable.
    risk_level = RiskLevel.MEDIUM

    def __init__(
        self,
        *,
        max_ports: int = 1024,
        max_timeout_seconds: float = 10.0,
        max_concurrency: int = 128,
        nmap_only: bool = False,
        nmap_locator: NmapLocator | None = None,
    ) -> None:
        if max_ports <= 0:
            raise ValueError("max_ports must be positive")
        if max_timeout_seconds <= 0:
            raise ValueError("max_timeout_seconds must be positive")
        if max_concurrency <= 0:
            raise ValueError("max_concurrency must be positive")
        self._max_ports = max_ports
        self._max_timeout_seconds = max_timeout_seconds
        self._max_concurrency = max_concurrency
        self._nmap_only = nmap_only
        # Automatic PATH discovery is unsafe on Windows because the current
        # working directory participates in executable lookup. Applications
        # that want nmap must inject a trusted locator returning an absolute
        # path; the safe default uses the built-in TCP-connect engine.
        self._nmap_locator = nmap_locator or (lambda _name: None)

    @property
    def input_schema(self) -> Mapping[str, JSONValue]:
        return {
            "type": "object",
            "properties": {
                "target": {"type": "string", "minLength": 1, "maxLength": 253},
                "ports": {
                    "type": "array",
                    "items": {"type": "integer", "minimum": 1, "maximum": 65_535},
                    "minItems": 1,
                    "maxItems": self._max_ports,
                    "uniqueItems": True,
                },
                "timeout_seconds": {
                    "type": "number",
                    "minimum": 0.05,
                    "maximum": self._max_timeout_seconds,
                },
                "engine": {"type": "string", "enum": ["auto", "nmap", "tcp"]},
            },
            "required": ["target", "ports"],
            "additionalProperties": False,
        }

    async def execute(
        self,
        context: ToolExecutionContext,
        arguments: Mapping[str, JSONValue],
    ) -> ToolResult:
        try:
            validate_arguments(self.input_schema, arguments)
            target = cast(str, arguments["target"]).strip()
            if "/" in target or "://" in target:
                raise InputValidationError(
                    "$.target: expected one hostname or IP address, not a range"
                )
            raw_ports = cast(list[JSONValue], arguments["ports"])
            ports = tuple(sorted(cast(int, port) for port in raw_ports))
            raw_timeout = arguments.get("timeout_seconds", 1.0)
            requested_timeout = float(cast(int | float, raw_timeout))
            timeout_limit = min(self._max_timeout_seconds, context.timeout_seconds)
            if requested_timeout > timeout_limit:
                raise InputValidationError(
                    f"$.timeout_seconds: must not exceed the execution limit of {timeout_limit}"
                )
            engine = cast(str, arguments.get("engine", "auto"))
            if self._nmap_only and engine == "tcp":
                raise ToolUnavailable("TCP fallback is disabled in nmap-only mode")
            addresses = await resolve_network_host(
                target,
                ports[0],
                resolution_timeout=min(requested_timeout, context.timeout_seconds),
            )
            for port in ports:
                authorize_network_target(context.scope, target, port, addresses)
            nmap_path = self._nmap_locator("nmap") if engine in {"auto", "nmap"} else None
            if nmap_path is not None:
                nmap_path = _validated_nmap_path(nmap_path)
                address = _select_scan_address(addresses)
                return await self._scan_with_nmap(
                    nmap_path=nmap_path,
                    target=target,
                    address=address,
                    all_addresses=addresses,
                    ports=ports,
                    per_target_timeout=requested_timeout,
                    execution_timeout=context.timeout_seconds,
                    output_limit=context.max_output_bytes,
                )
            if engine == "nmap" or self._nmap_only:
                raise ToolUnavailable("nmap executable was not found")
            return await self._scan_with_tcp(
                target=target,
                addresses=addresses,
                ports=ports,
                connect_timeout=requested_timeout,
                execution_timeout=context.timeout_seconds,
                output_limit=context.max_output_bytes,
            )
        except ToolUnavailable as exc:
            return ToolResult(
                success=False,
                error=f"ToolUnavailable: {exc}",
                metadata={
                    "error_type": "ToolUnavailable",
                    "engine": "nmap",
                    "open_ports": [],
                },
            )
        except (OSError, RuntimeError, ValueError) as exc:
            return _scan_failure(exc)

    async def _scan_with_nmap(
        self,
        *,
        nmap_path: str,
        target: str,
        address: IPAddress,
        all_addresses: tuple[IPAddress, ...],
        ports: tuple[int, ...],
        per_target_timeout: float,
        execution_timeout: float,
        output_limit: int,
    ) -> ToolResult:
        command = [
            nmap_path,
            "-n",
            "-Pn",
            "-sT",
            "--max-retries",
            "1",
            "--host-timeout",
            f"{max(50, int(per_target_timeout * 1000))}ms",
            "-p",
            ",".join(str(port) for port in ports),
            "-oX",
            "-",
        ]
        if address.version == 6:
            command.append("-6")
        command.append(str(address))
        try:
            process = await asyncio.create_subprocess_exec(
                command[0],
                *command[1:],
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except OSError as exc:
            return ToolResult(
                success=False,
                error=f"NmapStartError: {exc}",
                metadata={
                    "engine": "nmap",
                    "open_ports": [],
                    "target": target,
                    "scanned_addresses": [str(address)],
                    "error_type": "NmapStartError",
                },
            )
        try:
            stdout_result, stderr_result = await _collect_process_output(
                process,
                byte_limit=output_limit,
                execution_timeout=execution_timeout,
            )
        except TimeoutError:
            return ToolResult(
                success=False,
                error=f"ScanTimeout: nmap exceeded {execution_timeout} seconds",
                exit_code=process.returncode,
                metadata={
                    "engine": "nmap",
                    "open_ports": [],
                    "target": target,
                    "scanned_addresses": [str(address)],
                    "error_type": "ScanTimeout",
                },
            )
        stdout, stdout_bytes = stdout_result
        stderr, stderr_bytes = stderr_result
        if stdout_bytes > output_limit or stderr_bytes > output_limit:
            return ToolResult(
                success=False,
                error=f"OutputTooLarge: nmap output exceeds the {output_limit}-byte limit",
                exit_code=process.returncode,
                metadata={
                    "engine": "nmap",
                    "open_ports": [],
                    "target": target,
                    "scanned_addresses": [str(address)],
                    "stdout_bytes": stdout_bytes,
                    "stderr_bytes": stderr_bytes,
                    "output_discarded": True,
                    "error_type": "OutputTooLarge",
                },
            )
        if process.returncode != 0:
            error_text = _decode_bounded(stderr or stdout, output_limit)
            return ToolResult(
                success=False,
                error=f"NmapError: {error_text or 'nmap exited unsuccessfully'}",
                exit_code=process.returncode,
                metadata={
                    "engine": "nmap",
                    "open_ports": [],
                    "target": target,
                    "scanned_addresses": [str(address)],
                    "error_type": "NmapError",
                },
            )
        try:
            open_ports = _parse_nmap_open_ports(stdout)
        except (ET.ParseError, ValueError) as exc:
            return ToolResult(
                success=False,
                error=f"NmapOutputError: {exc}",
                exit_code=process.returncode,
                metadata={
                    "engine": "nmap",
                    "open_ports": [],
                    "target": target,
                    "scanned_addresses": [str(address)],
                    "error_type": "NmapOutputError",
                },
            )
        open_ports_json: list[JSONValue] = [port for port in open_ports]
        output = stdout.decode("utf-8", errors="replace")
        output_bytes = len(output.encode("utf-8"))
        if output_bytes > output_limit:
            return ToolResult(
                success=False,
                error=f"OutputTooLarge: decoded nmap output exceeds the {output_limit}-byte limit",
                exit_code=process.returncode,
                metadata={
                    "engine": "nmap",
                    "open_ports": open_ports_json,
                    "target": target,
                    "scanned_addresses": [str(address)],
                    "output_bytes": output_bytes,
                    "output_discarded": True,
                    "error_type": "OutputTooLarge",
                },
            )
        resolved_addresses_json: list[JSONValue] = [str(item) for item in all_addresses]
        return ToolResult(
            success=True,
            output=output,
            exit_code=process.returncode,
            metadata={
                "engine": "nmap",
                "target": target,
                "resolved_addresses": resolved_addresses_json,
                "scanned_addresses": [str(address)],
                "ports_scanned": len(ports),
                "open_ports": open_ports_json,
                "output_truncated": False,
            },
        )

    async def _scan_with_tcp(
        self,
        *,
        target: str,
        addresses: tuple[IPAddress, ...],
        ports: tuple[int, ...],
        connect_timeout: float,
        execution_timeout: float,
        output_limit: int,
    ) -> ToolResult:
        semaphore = asyncio.Semaphore(self._max_concurrency)

        async def probe(address: IPAddress, port: int) -> tuple[str, int, bool]:
            async with semaphore:
                is_open = await _tcp_connect(
                    address,
                    port,
                    connect_timeout=connect_timeout,
                )
                return str(address), port, is_open

        tasks = [probe(address, port) for address in addresses for port in ports]
        try:
            observations = await asyncio.wait_for(
                asyncio.gather(*tasks),
                timeout=execution_timeout,
            )
        except TimeoutError:
            return ToolResult(
                success=False,
                error=f"ScanTimeout: TCP scan exceeded {execution_timeout} seconds",
                metadata={
                    "engine": "asyncio_tcp",
                    "target": target,
                    "open_ports": [],
                    "error_type": "ScanTimeout",
                },
            )
        address_results: dict[str, list[int]] = {str(address): [] for address in addresses}
        for address, port, is_open in observations:
            if is_open:
                address_results[address].append(port)
        for values in address_results.values():
            values.sort()
        open_ports = sorted({port for values in address_results.values() for port in values})
        address_results_json: dict[str, JSONValue] = {
            address: [port for port in values] for address, values in address_results.items()
        }
        open_ports_json: list[JSONValue] = [port for port in open_ports]
        report: JSONObject = {
            "target": target,
            "engine": "asyncio_tcp",
            "addresses": address_results_json,
            "open_ports": open_ports_json,
        }
        output = json.dumps(report, ensure_ascii=False, sort_keys=True)
        if len(output.encode("utf-8")) > output_limit:
            return ToolResult(
                success=False,
                error=f"OutputTooLarge: scan report exceeds the {output_limit}-byte limit",
                metadata={
                    "engine": "asyncio_tcp",
                    "target": target,
                    "open_ports": open_ports_json,
                    "error_type": "OutputTooLarge",
                },
            )
        return ToolResult(
            success=True,
            output=output,
            exit_code=0,
            metadata={
                "engine": "asyncio_tcp",
                "target": target,
                "resolved_addresses": [str(address) for address in addresses],
                "scanned_addresses": [str(address) for address in addresses],
                "ports_scanned": len(ports) * len(addresses),
                "open_ports": open_ports_json,
                "address_results": address_results_json,
                "connect_timeout_seconds": connect_timeout,
            },
        )


async def _tcp_connect(
    address: IPAddress,
    port: int,
    *,
    connect_timeout: float,
) -> bool:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(str(address), port),
            timeout=connect_timeout,
        )
    except (OSError, TimeoutError):
        return False
    del reader
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
    return True


def _select_scan_address(addresses: tuple[IPAddress, ...]) -> IPAddress:
    if not addresses:
        raise ValueError("network target has no resolved address")
    return next((address for address in addresses if address.version == 4), addresses[0])


def _validated_nmap_path(candidate: str) -> str:
    path = Path(candidate).expanduser()
    if not path.is_absolute():
        raise ToolUnavailable("configured nmap path must be absolute")
    return str(path.resolve(strict=False))


async def _collect_process_output(
    process: asyncio.subprocess.Process,
    *,
    byte_limit: int,
    execution_timeout: float,
) -> tuple[tuple[bytes, int], tuple[bytes, int]]:
    stdout = process.stdout
    stderr = process.stderr
    if stdout is None or stderr is None:
        raise RuntimeError("nmap subprocess pipes were not created")

    async def collect() -> tuple[tuple[bytes, int], tuple[bytes, int]]:
        stdout_result, stderr_result, _returncode = await asyncio.gather(
            _read_process_stream(stdout, byte_limit),
            _read_process_stream(stderr, byte_limit),
            process.wait(),
        )
        return stdout_result, stderr_result

    try:
        return await asyncio.wait_for(collect(), timeout=execution_timeout)
    except BaseException:
        # Cancellation and the outer ToolExecutor timeout must end the real
        # process as well as the Python coroutine; otherwise a scan can outlive
        # its authorization/run lifecycle.
        if process.returncode is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass
        try:
            await asyncio.shield(process.wait())
        except (ProcessLookupError, OSError):
            pass
        raise


async def _read_process_stream(
    stream: asyncio.StreamReader,
    byte_limit: int,
) -> tuple[bytes, int]:
    kept = bytearray()
    total = 0
    while True:
        chunk = await stream.read(65_536)
        if not chunk:
            break
        total += len(chunk)
        if len(kept) < byte_limit:
            kept.extend(chunk[: byte_limit - len(kept)])
    return bytes(kept), total


def _parse_nmap_open_ports(raw_xml: bytes) -> tuple[int, ...]:
    root = ET.fromstring(raw_xml)
    ports: set[int] = set()
    for port_element in root.findall(".//port"):
        state = port_element.find("state")
        if state is None or state.attrib.get("state") != "open":
            continue
        port_id = port_element.attrib.get("portid")
        if port_id is None:
            continue
        try:
            port = int(port_id)
        except ValueError as exc:
            raise ValueError(f"nmap returned an invalid port: {port_id}") from exc
        if not 1 <= port <= 65_535:
            raise ValueError(f"nmap returned an out-of-range port: {port}")
        ports.add(port)
    return tuple(sorted(ports))


def _decode_bounded(value: bytes, byte_limit: int) -> str:
    clipped = value[:byte_limit]
    return clipped.decode("utf-8", errors="replace")


def _scan_failure(exc: Exception) -> ToolResult:
    error_type = type(exc).__name__
    if isinstance(exc, ToolUnavailable):
        error_type = "ToolUnavailable"
    return ToolResult(
        success=False,
        error=f"{error_type}: {exc}",
        metadata={"error_type": error_type, "open_ports": []},
    )
