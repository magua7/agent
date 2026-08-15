from __future__ import annotations

import asyncio
import tempfile
import unittest
from collections.abc import Awaitable, Callable
from pathlib import Path
from unittest.mock import Mock, patch

from security_agent.application.assistant_service import AssistantService
from security_agent.application.bootstrap import ProductServices, build_product_services
from security_agent.application.models import ProductUser
from security_agent.engine import RunLimits
from security_agent.infrastructure.llm import FakeLLMProvider, LLMProviderError
from security_agent.interfaces.product_cli import _parse_ports, build_parser, run_repl

InputFunction = Callable[[str], Awaitable[str]]


def _scripted_input(lines: list[str]) -> InputFunction:
    async def read(_prompt: str) -> str:
        if not lines:
            raise EOFError
        return lines.pop(0)

    return read


def _interrupting_input() -> InputFunction:
    async def read(_prompt: str) -> str:
        raise KeyboardInterrupt

    return read


class ReplTestSetup(unittest.IsolatedAsyncioTestCase):
    services: ProductServices
    admin: ProductUser
    temporary: tempfile.TemporaryDirectory[str]

    async def asyncSetUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.services = await build_product_services(
            Path(self.temporary.name) / "sec-go.db",
            jwt_secret="repl-test-secret-that-is-more-than-32-bytes",
            run_limits=RunLimits(max_steps=5, max_replans=1, max_seconds=20),
        )
        admin = await self.services.products.get_user_by_username("admin")
        if admin is None:
            raise AssertionError("default admin was not created")
        self.admin = admin

    async def asyncTearDown(self) -> None:
        for task_id in self.services.runs.active_task_ids:
            await self.services.tasks.wait(self.admin.id, task_id)
        await self.services.close()
        # Cancelling a mid-write run can leave an orphaned to_thread SQLite
        # write holding the database file; drain the default executor before
        # removing the temporary directory on Windows.
        await asyncio.get_running_loop().shutdown_default_executor()
        self.temporary.cleanup()

    async def run_session(
        self,
        lines: list[str],
        *,
        assistant: AssistantService | None = None,
        input_func: InputFunction | None = None,
        poll_interval: float = 0.05,
    ) -> tuple[int, list[str]]:
        captured: list[str] = []
        exit_code = await run_repl(
            self.services,
            self.admin.id,
            input_func=input_func or _scripted_input(lines),
            print_func=captured.append,
            assistant=assistant,
            poll_interval=poll_interval,
        )
        return exit_code, captured

    async def task_count(self) -> int:
        return len(await self.services.tasks.list_tasks(self.admin.id))


class ReplTests(ReplTestSetup):
    async def test_identity_question_never_enters_port_parsing_or_creates_tasks(self) -> None:
        guard = Mock(side_effect=AssertionError("_parse_ports must not be reached"))
        with patch("security_agent.interfaces.product_cli._parse_ports", guard):
            exit_code, output = await self.run_session(["你是谁", "/exit"])

        self.assertEqual(0, exit_code)
        guard.assert_not_called()
        self.assertTrue(any("SEC-GO" in line for line in output))
        self.assertEqual(0, await self.task_count())

    async def test_multi_turn_clarification_then_target_creates_a_task(self) -> None:
        exit_code, output = await self.run_session(
            ["帮我扫描一下", "127.0.0.1 的 443", "/exit"]
        )

        self.assertEqual(0, exit_code)
        self.assertTrue(any("请补充" in line for line in output))
        self.assertEqual(1, await self.task_count())
        tasks = await self.services.tasks.list_tasks(self.admin.id)
        detail = await self.services.tasks.get_task_detail(
            self.admin.id,
            str(tasks[0]["task_id"]),
        )
        spec = detail["task_spec"]
        self.assertEqual(["127.0.0.1"], spec["scope"]["network_targets"])
        self.assertEqual([443], spec["inputs"]["ports"])
        self.assertEqual("completed", detail["status"])

    async def test_runtime_events_are_really_displayed(self) -> None:
        _, output = await self.run_session(["扫描 127.0.0.1 的 443", "/exit"])
        joined = "\n".join(output)

        for marker in (
            "[task]",
            "[plan]",
            "[tool]",
            "[evidence]",
            "[verification]",
            "passed",
            "任务结束",
        ):
            self.assertIn(marker, joined)

    async def test_task_still_runs_the_full_kernel_chain(self) -> None:
        _, output = await self.run_session(["扫描 127.0.0.1 的 443", "/exit"])

        self.assertEqual(1, await self.task_count())
        tasks = await self.services.tasks.list_tasks(self.admin.id)
        detail = await self.services.tasks.get_task_detail(
            self.admin.id,
            str(tasks[0]["task_id"]),
        )
        self.assertEqual("completed", detail["status"])
        self.assertEqual("network.scan", detail["plan"]["nodes"][0]["required_capabilities"][0])
        self.assertEqual(1, len(detail["evidence"]))
        self.assertTrue(detail["evidence"][0]["content_hash"])
        self.assertIs(True, detail["verification"]["success"])
        self.assertTrue(any("任务结束" in line for line in output))

    async def test_model_failure_does_not_exit_the_repl(self) -> None:
        failing = AssistantService(
            self.services.tasks,
            llm_provider=FakeLLMProvider([LLMProviderError("model endpoint refused")]),
        )
        exit_code, output = await self.run_session(
            ["扫描 127.0.0.1", "/exit"],
            assistant=failing,
        )

        self.assertEqual(0, exit_code)
        self.assertTrue(any("模型暂时不可用" in line for line in output))
        self.assertEqual(0, await self.task_count())

    async def test_slash_commands(self) -> None:
        exit_code, output = await self.run_session(
            [
                "扫描 127.0.0.1 的 443",
                "/tasks",
                "/status",
                "/evidence",
                "/findings",
                "/report",
                "/model",
                "/help",
                "/unknown",
                "/clear",
                "/exit",
            ]
        )
        joined = "\n".join(output)

        self.assertEqual(0, exit_code)
        self.assertIn("SEC-GO Security Report", joined)
        self.assertIn("状态: completed", joined)
        self.assertIn("端口扫描 127.0.0.1", joined)
        self.assertIn("Model:", joined)
        self.assertIn("/help", joined)
        self.assertIn("未知命令", joined)
        self.assertIn("已开始新会话。", joined)

    async def test_empty_and_unknown_inputs_keep_the_repl_alive(self) -> None:
        exit_code, output = await self.run_session(["", "   ", "/nope", "/exit"])

        self.assertEqual(0, exit_code)
        self.assertTrue(any("未知命令" in line for line in output))
        self.assertEqual(0, await self.task_count())

    async def test_bad_turn_error_is_printed_and_repl_continues(self) -> None:
        oversized = "x" * 30_000
        exit_code, output = await self.run_session([oversized, "/exit"])

        self.assertEqual(0, exit_code)
        self.assertTrue(any("错误" in line for line in output))
        self.assertEqual(0, await self.task_count())

    async def test_ctrl_c_at_idle_exits(self) -> None:
        exit_code, output = await self.run_session([], input_func=_interrupting_input())

        self.assertEqual(130, exit_code)
        self.assertTrue(any("再见" in line for line in output))

    async def test_ctrl_c_during_a_task_cancels_and_keeps_the_repl(self) -> None:
        async def interrupted_stream(*_args: object, **_kwargs: object) -> None:
            raise KeyboardInterrupt

        with patch("security_agent.interfaces.product_cli._stream_task", interrupted_stream):
            exit_code, output = await self.run_session(["扫描 127.0.0.1 的 443", "/exit"])

        self.assertEqual(0, exit_code)
        self.assertTrue(any("任务已取消" in line for line in output))
        tasks = await self.services.tasks.list_tasks(self.admin.id)
        self.assertEqual("cancelled", tasks[0]["status"])

    async def test_repl_streams_without_a_model_configured(self) -> None:
        _, output = await self.run_session(["扫描 127.0.0.1 的 443", "/exit"])

        self.assertTrue(any("Model: local-deterministic" in line for line in output))
        self.assertTrue(any("受信任操作者模式" in line for line in output))


class StructuredCLITests(unittest.TestCase):
    def test_run_parser_still_accepts_structured_arguments(self) -> None:
        args = build_parser().parse_args(
            [
                "run",
                "Analyze localhost",
                "--target",
                "127.0.0.1",
                "--ports",
                "80,443",
            ]
        )

        self.assertEqual("run", args.command)
        self.assertEqual("127.0.0.1", args.target)
        self.assertEqual("80,443", args.ports)

    def test_no_arguments_enters_the_repl_path(self) -> None:
        args = build_parser().parse_args([])
        self.assertIsNone(args.command)

    def test_parse_ports_is_used_only_by_the_structured_command(self) -> None:
        self.assertEqual((80, 443), _parse_ports("443,80"))


if __name__ == "__main__":
    unittest.main()
