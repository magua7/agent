from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from collections.abc import Mapping
from pathlib import Path
from typing import cast
from unittest.mock import AsyncMock, patch

from security_agent.contracts import RiskLevel, ToolExecutionContext, ToolResult
from security_agent.contracts.common import JSONValue
from security_agent.domain import ScopeSpec
from security_agent.infrastructure.tools import (
    DuplicateToolError,
    FileReadTool,
    FileSearchTool,
    HttpRequestTool,
    InputValidationError,
    NetworkScanTool,
    ToolRegistry,
    validate_input,
)


def make_context(
    scope: ScopeSpec,
    *,
    timeout_seconds: float = 3.0,
    max_output_bytes: int = 100_000,
) -> ToolExecutionContext:
    return ToolExecutionContext(
        run_id="run-test",
        task_id="task-test",
        plan_node_id="node-test",
        scope=scope,
        timeout_seconds=timeout_seconds,
        max_output_bytes=max_output_bytes,
    )


class _DummyTool:
    description = "A registry test tool."
    input_schema: Mapping[str, JSONValue] = {
        "type": "object",
        "additionalProperties": False,
    }
    risk_level = RiskLevel.LOW

    def __init__(self, name: str, *capabilities: str) -> None:
        self.name = name
        self.capabilities = frozenset(capabilities)

    async def execute(
        self,
        context: ToolExecutionContext,
        arguments: Mapping[str, JSONValue],
    ) -> ToolResult:
        del context, arguments
        return ToolResult(success=True)


class _FakeNmapProcess:
    def __init__(self, stdout: bytes, stderr: bytes = b"", returncode: int = 0) -> None:
        self.returncode: int | None = returncode
        self._stdout = stdout
        self._stderr = stderr
        self.killed = False
        self.stdout = asyncio.StreamReader()
        self.stdout.feed_data(stdout)
        self.stdout.feed_eof()
        self.stderr = asyncio.StreamReader()
        self.stderr.feed_data(stderr)
        self.stderr.feed_eof()

    async def wait(self) -> int:
        assert self.returncode is not None
        return self.returncode

    def kill(self) -> None:
        self.killed = True


class _HangingNmapProcess:
    def __init__(self) -> None:
        self.returncode: int | None = None
        self.killed = False
        self.stdout = asyncio.StreamReader()
        self.stderr = asyncio.StreamReader()
        self._finished = asyncio.Event()

    async def wait(self) -> int:
        await self._finished.wait()
        assert self.returncode is not None
        return self.returncode

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9
        self.stdout.feed_eof()
        self.stderr.feed_eof()
        self._finished.set()


class ToolRegistryTests(unittest.TestCase):
    def test_registry_is_strict_and_stably_sorted(self) -> None:
        registry = ToolRegistry()
        bravo = _DummyTool("bravo", "network.scan")
        alpha = _DummyTool("alpha", "network.scan", "http.request")
        registry.register(bravo)
        registry.register(alpha)

        self.assertEqual((alpha, bravo), registry.list())
        self.assertIs(alpha, registry.get("alpha"))
        self.assertEqual((alpha, bravo), registry.find_by_capability("network.scan"))
        self.assertEqual((alpha,), registry.find_by_capability("http.request"))
        self.assertIs(alpha, registry.unregister("alpha"))
        self.assertEqual((bravo,), registry.list())

    def test_duplicate_and_missing_names_are_not_silent(self) -> None:
        registry = ToolRegistry()
        registry.register(_DummyTool("only", "file.read"))
        with self.assertRaises(DuplicateToolError):
            registry.register(_DummyTool("only", "file.search"))
        with self.assertRaises(KeyError):
            registry.get("missing")
        with self.assertRaises(KeyError):
            registry.unregister("missing")


class InputValidationTests(unittest.TestCase):
    def test_object_validation_rejects_unknown_and_missing_values(self) -> None:
        schema: Mapping[str, JSONValue] = {
            "type": "object",
            "properties": {"count": {"type": "integer", "minimum": 1}},
            "required": ["count"],
            "additionalProperties": False,
        }
        validate_input(schema, {"count": 1})
        with self.assertRaisesRegex(InputValidationError, "required property"):
            validate_input(schema, {})
        with self.assertRaisesRegex(InputValidationError, "additional property"):
            validate_input(schema, {"count": 1, "surprise": True})
        with self.assertRaisesRegex(InputValidationError, "expected integer"):
            validate_input(schema, {"count": True})

    def test_array_limits_and_uniqueness_are_enforced(self) -> None:
        schema: Mapping[str, JSONValue] = {
            "type": "array",
            "items": {"type": "integer", "minimum": 1, "maximum": 65535},
            "maxItems": 2,
            "uniqueItems": True,
        }
        validate_input(schema, [80, 443])
        with self.assertRaisesRegex(InputValidationError, "duplicate"):
            validate_input(schema, [80, 80])
        with self.assertRaisesRegex(InputValidationError, "more than"):
            validate_input(schema, [1, 2, 3])


class FileToolTests(unittest.IsolatedAsyncioTestCase):
    async def test_file_read_is_bounded_and_scope_constrained(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            allowed = root / "allowed"
            outside = root / "outside"
            allowed.mkdir()
            outside.mkdir()
            readable = allowed / "hello.txt"
            readable.write_text("hello security agent", encoding="utf-8")
            secret = outside / "secret.txt"
            secret.write_text("not authorized", encoding="utf-8")
            context = make_context(ScopeSpec(file_roots=(str(allowed),)))
            tool = FileReadTool(max_file_bytes=64)

            result = await tool.execute(context, {"path": str(readable)})
            self.assertTrue(result.success, result.error)
            self.assertEqual("hello security agent", result.output)
            self.assertEqual(len(result.output), result.metadata["bytes_read"])

            denied = await tool.execute(context, {"path": str(secret)})
            self.assertFalse(denied.success)
            self.assertIn("ScopeViolation", denied.error or "")

            readable.write_bytes(b"x" * 65)
            oversized = await tool.execute(context, {"path": "hello.txt"})
            self.assertFalse(oversized.success)
            self.assertIn("exceeds", oversized.error or "")

    async def test_file_search_has_stable_result_and_file_bounds(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "b.txt").write_text("needle second\n", encoding="utf-8")
            (root / "a.txt").write_text("first NEEDLE\nnone\n", encoding="utf-8")
            (root / "large.txt").write_bytes(b"needle" * 20)
            context = make_context(ScopeSpec(file_roots=(str(root),)))
            tool = FileSearchTool(max_results=10, max_file_bytes=32, max_files=10)

            result = await tool.execute(
                context,
                {"root": str(root), "query": "needle", "glob": "*.txt"},
            )
            self.assertTrue(result.success, result.error)
            matches = json.loads(result.output)
            self.assertEqual(["a.txt", "b.txt"], [Path(item["path"]).name for item in matches])
            self.assertEqual(1, result.metadata["files_skipped_large"])

            bounded = await tool.execute(
                context,
                {
                    "root": str(root),
                    "query": "needle",
                    "glob": "*.txt",
                    "max_results": 1,
                },
            )
            self.assertTrue(bounded.success, bounded.error)
            self.assertEqual(1, len(json.loads(bounded.output)))
            self.assertTrue(bounded.metadata["truncated"])


class LocalHTTPToolTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.server = await asyncio.start_server(self._handle_request, "127.0.0.1", 0)
        socket = self.server.sockets[0]
        self.port = int(socket.getsockname()[1])

    async def asyncTearDown(self) -> None:
        self.server.close()
        await self.server.wait_closed()

    async def _handle_request(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            request = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=1)
            request_line = request.split(b"\r\n", maxsplit=1)[0]
            path = request_line.split(b" ")[1]
            if path == b"/redirect":
                response = (
                    b"HTTP/1.1 302 Found\r\n"
                    + (
                        f"Location: http://127.0.0.1:{self.port}/final?"
                        "access_token=do-not-expose\r\n"
                    ).encode()
                    + b"Content-Length: 0\r\nConnection: close\r\n\r\n"
                )
            elif path == b"/large":
                body = b"x" * 128
                response = (
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                    + f"Content-Length: {len(body)}\r\n".encode()
                    + b"Connection: close\r\n\r\n"
                    + body
                )
            else:
                body = b"local fixture"
                response = (
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n"
                    + f"Content-Length: {len(body)}\r\n".encode()
                    + b"Set-Cookie: session=do-not-expose\r\n"
                    + b"X-Api-Key: do-not-expose\r\n"
                    + b"Connection: close\r\n\r\n"
                    + body
                )
            writer.write(response)
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    async def test_http_request_uses_scope_and_does_not_follow_redirects(self) -> None:
        context = make_context(ScopeSpec(network_targets=(f"127.0.0.1:{self.port}",)))
        tool = HttpRequestTool(max_response_bytes=64)

        result = await tool.execute(context, {"url": f"http://127.0.0.1:{self.port}/"})
        self.assertTrue(result.success, result.error)
        self.assertEqual("local fixture", result.output)
        self.assertEqual(200, result.metadata["status_code"])
        response_headers = result.metadata["response_headers"]
        self.assertIsInstance(response_headers, dict)
        response_headers = cast(dict[str, JSONValue], response_headers)
        self.assertEqual("[REDACTED]", response_headers["set-cookie"])
        self.assertEqual("[REDACTED]", response_headers["x-api-key"])

        redirect = await tool.execute(
            context,
            {"url": f"http://127.0.0.1:{self.port}/redirect"},
        )
        self.assertTrue(redirect.success, redirect.error)
        self.assertEqual(302, redirect.metadata["status_code"])
        self.assertFalse(redirect.metadata["redirect_followed"])
        safe_location = redirect.metadata["location"]
        assert isinstance(safe_location, str)
        self.assertNotIn("do-not-expose", safe_location)
        redirect_headers = redirect.metadata["response_headers"]
        assert isinstance(redirect_headers, dict)
        self.assertEqual("[REDACTED]", redirect_headers["location"])

    async def test_http_request_rejects_scope_escape_and_large_body(self) -> None:
        tool = HttpRequestTool(max_response_bytes=64)
        denied_context = make_context(ScopeSpec(network_targets=("192.0.2.1",)))
        denied = await tool.execute(
            denied_context,
            {"url": f"http://127.0.0.1:{self.port}/"},
        )
        self.assertFalse(denied.success)
        self.assertIn("ScopeViolation", denied.error or "")

        secret = "do-not-expose"
        invalid_header = await tool.execute(
            make_context(ScopeSpec(network_targets=("127.0.0.1",))),
            {
                "url": f"http://127.0.0.1:{self.port}/",
                "headers": {"Authorization": f"Bearer {secret}\nInjected: yes"},
            },
        )
        self.assertFalse(invalid_header.success)
        self.assertEqual("InputValidationError", invalid_header.metadata["error_type"])
        self.assertNotIn(secret, invalid_header.error or "")

        context = make_context(ScopeSpec(network_targets=("127.0.0.1",)))
        oversized = await tool.execute(
            context,
            {
                "url": f"http://127.0.0.1:{self.port}/large",
                "max_response_bytes": 32,
            },
        )
        self.assertFalse(oversized.success)
        self.assertIn("ResponseTooLarge", oversized.error or "")


class LocalNetworkScanTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.server = await asyncio.start_server(self._accept_connection, "127.0.0.1", 0)
        socket = self.server.sockets[0]
        self.port = int(socket.getsockname()[1])

    async def asyncTearDown(self) -> None:
        self.server.close()
        await self.server.wait_closed()

    async def _accept_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        del reader
        writer.close()
        await writer.wait_closed()

    async def test_tcp_fallback_reports_real_open_port_and_engine(self) -> None:
        context = make_context(ScopeSpec(network_targets=("127.0.0.1",)))
        tool = NetworkScanTool(nmap_locator=lambda _name: None)
        self.assertEqual(RiskLevel.MEDIUM, tool.risk_level)
        result = await tool.execute(
            context,
            {"target": "127.0.0.1", "ports": [self.port], "engine": "auto"},
        )
        self.assertTrue(result.success, result.error)
        self.assertEqual("asyncio_tcp", result.metadata["engine"])
        self.assertEqual([self.port], result.metadata["open_ports"])
        self.assertEqual([self.port], json.loads(result.output)["open_ports"])

    async def test_scan_scope_ports_and_nmap_only_are_strict(self) -> None:
        tool = NetworkScanTool(nmap_locator=lambda _name: None)
        empty_scope = make_context(ScopeSpec())
        denied = await tool.execute(
            empty_scope,
            {"target": "127.0.0.1", "ports": [self.port]},
        )
        self.assertFalse(denied.success)
        self.assertIn("ScopeViolation", denied.error or "")

        context = make_context(ScopeSpec(network_targets=("127.0.0.1",)))
        invalid_port = await tool.execute(context, {"target": "127.0.0.1", "ports": [0]})
        self.assertFalse(invalid_port.success)
        self.assertEqual("InputValidationError", invalid_port.metadata["error_type"])

        strict_tool = NetworkScanTool(nmap_only=True, nmap_locator=lambda _name: None)
        unavailable = await strict_tool.execute(
            context,
            {"target": "127.0.0.1", "ports": [self.port]},
        )
        self.assertFalse(unavailable.success)
        self.assertEqual("ToolUnavailable", unavailable.metadata["error_type"])

        relative_nmap = NetworkScanTool(nmap_locator=lambda _name: "nmap.exe")
        unsafe_lookup = await relative_nmap.execute(
            context,
            {"target": "127.0.0.1", "ports": [self.port], "engine": "nmap"},
        )
        self.assertFalse(unsafe_lookup.success)
        self.assertEqual("ToolUnavailable", unsafe_lookup.metadata["error_type"])

        hostname_only = await tool.execute(
            make_context(ScopeSpec(network_targets=("localhost",))),
            {"target": "localhost", "ports": [self.port], "engine": "tcp"},
        )
        self.assertFalse(hostname_only.success)
        self.assertIn("ScopeViolation", hostname_only.error or "")

    async def test_nmap_output_over_limit_fails_without_silent_truncation(self) -> None:
        raw_xml = (
            b'<?xml version="1.0"?><nmaprun>'
            + b" " * 256
            + f'<host><ports><port portid="{self.port}"><state state="open"/>'
            f"</port></ports></host></nmaprun>".encode()
        )
        process = _FakeNmapProcess(raw_xml)
        context = make_context(
            ScopeSpec(network_targets=("127.0.0.1",)),
            max_output_bytes=64,
        )
        tool = NetworkScanTool(nmap_locator=lambda _name: str(Path.cwd() / "nmap"))
        create_process = AsyncMock(return_value=process)
        with patch(
            "security_agent.infrastructure.tools.network.asyncio.create_subprocess_exec",
            new=create_process,
        ):
            result = await tool.execute(
                context,
                {"target": "127.0.0.1", "ports": [self.port]},
            )

        self.assertFalse(result.success)
        self.assertEqual("OutputTooLarge", result.metadata["error_type"])
        self.assertEqual("nmap", result.metadata["engine"])
        self.assertEqual([], result.metadata["open_ports"])
        self.assertTrue(result.metadata["output_discarded"])
        self.assertEqual("", result.output)

    async def test_cancelling_nmap_adapter_kills_the_child_process(self) -> None:
        process = _HangingNmapProcess()
        tool = NetworkScanTool(nmap_locator=lambda _name: str(Path.cwd() / "nmap"))
        with patch(
            "security_agent.infrastructure.tools.network.asyncio.create_subprocess_exec",
            new=AsyncMock(return_value=process),
        ):
            execution = asyncio.create_task(
                tool.execute(
                    make_context(ScopeSpec(network_targets=("127.0.0.1",))),
                    {"target": "127.0.0.1", "ports": [self.port], "engine": "nmap"},
                )
            )
            await asyncio.sleep(0)
            execution.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await execution
        self.assertTrue(process.killed)


if __name__ == "__main__":
    unittest.main()
