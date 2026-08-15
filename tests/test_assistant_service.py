from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from typing import cast

from security_agent.application.assistant_service import AssistantService, MessageKind
from security_agent.application.bootstrap import ProductServices, build_product_services
from security_agent.application.models import ProductUser
from security_agent.application.task_service import TaskInputError
from security_agent.domain import RunStatus, TaskSpec
from security_agent.engine import RunLimits
from security_agent.infrastructure.llm import FakeLLMProvider, LLMProviderError
from security_agent.infrastructure.llm.fake import FakeResponse


def _task_payload(**overrides: object) -> str:
    payload: dict[str, object] = {
        "kind": "task",
        "reply": "准备检查目标。",
        "title": "127.0.0.1 服务检查",
        "task_type": "pentest",
        "capability": "network.scan",
        "network_targets": ["127.0.0.1"],
        "file_roots": [],
        "inputs": {"target": "127.0.0.1", "ports": [80, 443]},
        "success_criteria": ["保存真实服务探测证据"],
        "missing_fields": [],
    }
    payload.update(overrides)
    return json.dumps(payload, ensure_ascii=False)


class AssistantServiceSetup:
    services: ProductServices
    assistant: AssistantService
    admin: ProductUser
    temporary: tempfile.TemporaryDirectory[str]

    async def asyncSetUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.services = await build_product_services(
            Path(self.temporary.name) / "sec-go.db",
            jwt_secret="assistant-test-secret-that-is-more-than-32-bytes",
            run_limits=RunLimits(max_steps=5, max_replans=1, max_seconds=20),
        )
        admin = await self.services.products.get_user_by_username("admin")
        if admin is None:
            raise AssertionError("default admin was not created")
        self.admin = admin
        assistant = self.services.assistant
        if assistant is None:
            raise AssertionError("bootstrap did not wire the AssistantService")
        self.assistant = assistant

    async def asyncTearDown(self) -> None:
        for task_id in self.services.runs.active_task_ids:
            await self.services.tasks.wait(self.admin.id, task_id)
        await self.services.close()
        # Cancelling a mid-write run can leave an orphaned to_thread SQLite
        # write holding the database file; drain the default executor before
        # removing the temporary directory on Windows.
        await asyncio.get_running_loop().shutdown_default_executor()
        self.temporary.cleanup()

    async def task_count(self) -> int:
        return len(await self.services.tasks.list_tasks(self.admin.id))


class AssistantServiceWithoutLLMTests(AssistantServiceSetup, unittest.IsolatedAsyncioTestCase):
    async def test_identity_question_is_chat_and_creates_no_task(self) -> None:
        result = await self.assistant.handle_message(self.admin.id, "你是谁")

        self.assertIs(result.kind, MessageKind.CHAT)
        self.assertIsNone(result.task)
        self.assertIn("SEC-GO", result.reply)
        self.assertEqual(0, await self.task_count())

    async def test_definition_question_is_chat(self) -> None:
        result = await self.assistant.handle_message(self.admin.id, "什么是端口扫描?")

        self.assertIs(result.kind, MessageKind.CHAT)
        self.assertIsNone(result.task)
        self.assertEqual(0, await self.task_count())

    async def test_structured_scan_message_creates_a_correct_task_spec(self) -> None:
        result = await self.assistant.handle_message(self.admin.id, "扫描 127.0.0.1 的 80,443")

        self.assertIs(result.kind, MessageKind.TASK)
        self.assertIsNotNone(result.task)
        task = result.task
        if task is None:
            raise AssertionError("task result lost its ProductTask")
        spec = task.task_spec
        if spec is None:
            raise AssertionError("task was created without a TaskSpec")
        self.assertEqual(("127.0.0.1",), spec.scope.network_targets)
        self.assertEqual(("127.0.0.1",), (spec.inputs["target"],))
        self.assertEqual([80, 443], spec.inputs["ports"])
        self.assertEqual(1, await self.task_count())

        state = await self.services.tasks.wait(self.admin.id, task.id)
        if state is None:
            raise AssertionError("runtime returned no state")
        self.assertEqual(RunStatus.COMPLETED, state.status)
        detail = await self.services.tasks.get_task_detail(self.admin.id, task.id)
        self.assertEqual("network.scan", detail["plan"]["nodes"][0]["required_capabilities"][0])
        self.assertEqual(1, len(detail["evidence"]))

    async def test_vague_scan_request_is_clarification(self) -> None:
        result = await self.assistant.handle_message(self.admin.id, "帮我扫描一下")

        self.assertIs(result.kind, MessageKind.CLARIFICATION)
        self.assertIsNone(result.task)
        self.assertEqual(0, await self.task_count())

    async def test_open_chat_mentions_the_disabled_model(self) -> None:
        result = await self.assistant.handle_message(self.admin.id, "今天天气不错")

        self.assertIs(result.kind, MessageKind.CHAT)
        self.assertIn("LLM 未启用", result.reply)

    async def test_open_question_points_to_llm_settings(self) -> None:
        result = await self.assistant.handle_message(self.admin.id, "今天天气怎么样?")

        self.assertIs(result.kind, MessageKind.CHAT)
        self.assertIn("llm.enabled", result.reply)

    async def test_unsupported_request_is_unsupported(self) -> None:
        result = await self.assistant.handle_message(self.admin.id, "帮我反弹一个 shell")

        self.assertIs(result.kind, MessageKind.UNSUPPORTED)
        self.assertIsNone(result.task)

    async def test_empty_message_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            await self.assistant.handle_message(self.admin.id, "   ")

    async def test_create_task_from_spec_requires_a_task_spec(self) -> None:
        with self.assertRaises(TaskInputError):
            await self.services.tasks.create_task_from_spec(
                self.admin.id,
                title="broken",
                description="broken",
                spec=cast(TaskSpec, None),
            )


class AssistantServiceWithLLMTests(AssistantServiceSetup, unittest.IsolatedAsyncioTestCase):
    def assistant_with(self, *responses: FakeResponse) -> AssistantService:
        return AssistantService(self.services.tasks, llm_provider=FakeLLMProvider(responses))

    async def test_llm_chat_answer_creates_no_task(self) -> None:
        assistant = self.assistant_with(
            json.dumps({"kind": "chat", "reply": "我是 SEC-GO。本地安全助手。"}, ensure_ascii=False)
        )

        result = await assistant.handle_message(self.admin.id, "你是谁")

        self.assertIs(result.kind, MessageKind.CHAT)
        self.assertIsNone(result.task)
        self.assertEqual(0, await self.task_count())

    async def test_llm_task_payload_creates_the_requested_task(self) -> None:
        assistant = self.assistant_with(_task_payload())

        result = await assistant.handle_message(self.admin.id, "扫描 127.0.0.1 的 80,443")

        self.assertIs(result.kind, MessageKind.TASK)
        self.assertIsNotNone(result.task)
        task = result.task
        if task is None:
            raise AssertionError("task result lost its ProductTask")
        spec = task.task_spec
        if spec is None:
            raise AssertionError("task was created without a TaskSpec")
        self.assertEqual(("127.0.0.1",), spec.scope.network_targets)
        self.assertEqual([80, 443], spec.inputs["ports"])
        self.assertEqual("127.0.0.1 服务检查", task.title)
        self.assertEqual(1, await self.task_count())

        state = await self.services.tasks.wait(self.admin.id, task.id)
        if state is None:
            raise AssertionError("runtime returned no state")
        self.assertEqual(RunStatus.COMPLETED, state.status)
        detail = await self.services.tasks.get_task_detail(self.admin.id, task.id)
        self.assertEqual(1, len(detail["evidence"]))

    async def test_llm_may_not_swap_the_operator_target(self) -> None:
        assistant = self.assistant_with(_task_payload(network_targets=["8.8.8.8"]))

        result = await assistant.handle_message(self.admin.id, "扫描 127.0.0.1 的 80,443")

        self.assertIsNot(result.kind, MessageKind.TASK)
        self.assertIsNone(result.task)
        self.assertEqual(0, await self.task_count())

    async def test_llm_may_not_invent_ports(self) -> None:
        assistant = self.assistant_with(
            _task_payload(inputs={"target": "127.0.0.1", "ports": [1, 2, 3]})
        )

        result = await assistant.handle_message(self.admin.id, "扫描 127.0.0.1 的 80,443")

        self.assertIsNot(result.kind, MessageKind.TASK)
        self.assertEqual(0, await self.task_count())

    async def test_llm_task_with_missing_fields_is_downgraded(self) -> None:
        assistant = self.assistant_with(_task_payload(missing_fields=["ports"]))

        result = await assistant.handle_message(self.admin.id, "扫描 127.0.0.1")

        self.assertIs(result.kind, MessageKind.CLARIFICATION)
        self.assertEqual(0, await self.task_count())

    async def test_llm_clarification_passes_through(self) -> None:
        assistant = self.assistant_with(
            json.dumps(
                {"kind": "clarification", "reply": "请补充目标。", "missing_fields": ["target"]},
                ensure_ascii=False,
            )
        )

        result = await assistant.handle_message(self.admin.id, "帮我扫描一下")

        self.assertIs(result.kind, MessageKind.CLARIFICATION)
        self.assertEqual("请补充目标。", result.reply)
        self.assertEqual(0, await self.task_count())

    async def test_llm_invalid_json_degrades_to_clarification(self) -> None:
        assistant = self.assistant_with("definitely not json")

        result = await assistant.handle_message(self.admin.id, "扫描 127.0.0.1")

        self.assertIs(result.kind, MessageKind.CLARIFICATION)
        self.assertEqual(0, await self.task_count())

    async def test_llm_provider_failure_degrades_to_clarification(self) -> None:
        assistant = self.assistant_with(LLMProviderError("model endpoint refused"))

        result = await assistant.handle_message(self.admin.id, "扫描 127.0.0.1")

        self.assertIs(result.kind, MessageKind.CLARIFICATION)
        self.assertEqual(0, await self.task_count())

    async def test_llm_receives_the_assistant_routing_operation(self) -> None:
        provider = FakeLLMProvider(
            [json.dumps({"kind": "chat", "reply": "你好。"}, ensure_ascii=False)]
        )
        assistant = AssistantService(self.services.tasks, llm_provider=provider)

        await assistant.handle_message(self.admin.id, "你好")

        self.assertEqual(1, len(provider.requests))
        self.assertEqual("assistant_message", provider.requests[0].operation)
        payload = provider.requests[0].payload
        self.assertEqual("你好", payload["message"])
        self.assertIn("conversation", payload)
        self.assertIn("recent_task", payload)

    async def test_llm_may_not_invent_ports_when_operator_named_none(self) -> None:
        assistant = self.assistant_with(
            _task_payload(inputs={"target": "127.0.0.1", "ports": [1, 2, 3]})
        )

        result = await assistant.handle_message(self.admin.id, "扫描 127.0.0.1")

        self.assertIs(result.kind, MessageKind.TASK)
        self.assertIsNotNone(result.task)
        task = result.task
        if task is None:
            raise AssertionError("task result lost its ProductTask")
        spec = task.task_spec
        if spec is None:
            raise AssertionError("task was created without a TaskSpec")
        self.assertEqual([22, 80, 443, 8000, 8080], spec.inputs["ports"])

    async def test_llm_file_read_task_does_not_require_network_targets(self) -> None:
        root = Path(self.temporary.name)
        target_file = root / "notes.txt"
        target_file.write_text("fixture content", encoding="utf-8")
        assistant = self.assistant_with(
            json.dumps(
                {
                    "kind": "task",
                    "reply": "读取文件。",
                    "title": "读取本地文件",
                    "task_type": "code_audit",
                    "capability": "file.read",
                    "network_targets": [],
                    "file_roots": [str(root)],
                    "inputs": {"path": str(target_file)},
                    "success_criteria": ["读取文件并保留证据"],
                    "missing_fields": [],
                },
                ensure_ascii=False,
            )
        )

        result = await assistant.handle_message(self.admin.id, f"读取 {target_file}")

        self.assertIs(result.kind, MessageKind.TASK)
        self.assertIsNotNone(result.task)
        task = result.task
        if task is None:
            raise AssertionError("task result lost its ProductTask")
        spec = task.task_spec
        if spec is None:
            raise AssertionError("task was created without a TaskSpec")
        self.assertEqual((), spec.scope.network_targets)
        self.assertEqual((str(root),), spec.scope.file_roots)
        self.assertEqual(str(target_file), spec.inputs["path"])

        state = await self.services.tasks.wait(self.admin.id, task.id)
        if state is None:
            raise AssertionError("runtime returned no state")
        self.assertEqual(RunStatus.COMPLETED, state.status)

    async def test_llm_file_task_may_not_invent_file_roots(self) -> None:
        assistant = self.assistant_with(
            json.dumps(
                {
                    "kind": "task",
                    "reply": "读取文件。",
                    "title": "读取本地文件",
                    "task_type": "code_audit",
                    "capability": "file.read",
                    "network_targets": [],
                    "file_roots": ["C:\\invented\\root"],
                    "inputs": {"path": "C:\\invented\\root\\secret.txt"},
                    "success_criteria": ["读取文件并保留证据"],
                    "missing_fields": [],
                },
                ensure_ascii=False,
            )
        )

        result = await assistant.handle_message(self.admin.id, "读取 C:\\Users\\HP\\notes.txt")

        self.assertIsNot(result.kind, MessageKind.TASK)
        self.assertEqual(0, await self.task_count())

    async def test_llm_multi_turn_completes_a_clarified_task(self) -> None:
        assistant = self.assistant_with(
            json.dumps(
                {"kind": "clarification", "reply": "请补充目标。", "missing_fields": ["target"]},
                ensure_ascii=False,
            ),
            _task_payload(inputs={"target": "127.0.0.1", "ports": [443]}),
        )

        first = await assistant.handle_message(
            self.admin.id,
            "帮我扫描一下",
            conversation_id="conv-multi",
        )
        second = await assistant.handle_message(
            self.admin.id,
            "127.0.0.1 的 443",
            conversation_id="conv-multi",
        )

        self.assertIs(first.kind, MessageKind.CLARIFICATION)
        self.assertIs(second.kind, MessageKind.TASK)
        self.assertIsNotNone(second.task)
        task = second.task
        if task is None:
            raise AssertionError("task result lost its ProductTask")
        spec = task.task_spec
        if spec is None:
            raise AssertionError("task was created without a TaskSpec")
        self.assertEqual(("127.0.0.1",), spec.scope.network_targets)
        self.assertEqual([443], spec.inputs["ports"])
        self.assertEqual(1, await self.task_count())

    async def test_conversation_histories_do_not_leak_between_conversations(self) -> None:
        clarified = await self.assistant.handle_message(
            self.admin.id,
            "帮我扫描一下",
            conversation_id="conv-a",
        )
        self.assertIs(clarified.kind, MessageKind.CLARIFICATION)

        isolated = await self.assistant.handle_message(
            self.admin.id,
            "127.0.0.1",
            conversation_id="conv-b",
        )
        self.assertIsNot(isolated.kind, MessageKind.TASK)
        self.assertEqual(0, await self.task_count())

        completed = await self.assistant.handle_message(
            self.admin.id,
            "127.0.0.1 的 443",
            conversation_id="conv-a",
        )
        self.assertIs(completed.kind, MessageKind.TASK)
        self.assertEqual(1, await self.task_count())

    async def test_follow_up_question_answers_from_recent_task(self) -> None:
        created = await self.assistant.handle_message(
            self.admin.id,
            "扫描 127.0.0.1 的 443",
            conversation_id="conv-follow",
        )
        self.assertIs(created.kind, MessageKind.TASK)
        self.assertIsNotNone(created.task)
        task = created.task
        if task is None:
            raise AssertionError("task result lost its ProductTask")
        await self.services.tasks.wait(self.admin.id, task.id)

        follow_up = await self.assistant.handle_message(
            self.admin.id,
            "刚才发现了什么?",
            conversation_id="conv-follow",
        )

        self.assertIs(follow_up.kind, MessageKind.CHAT)
        self.assertIn("任务", follow_up.reply)
        self.assertIsNone(follow_up.task)
        self.assertEqual(1, await self.task_count())

    async def test_conversation_id_flows_through_the_result(self) -> None:
        result = await self.assistant.handle_message(self.admin.id, "你是谁")

        self.assertTrue(result.conversation_id)
        reused = await self.assistant.handle_message(
            self.admin.id,
            "你好",
            conversation_id=result.conversation_id,
        )
        self.assertEqual(result.conversation_id, reused.conversation_id)


class BootstrapWiringTests(AssistantServiceSetup, unittest.IsolatedAsyncioTestCase):
    async def test_assistant_is_wired_and_reflects_llm_settings(self) -> None:
        self.assertFalse(self.assistant.llm_enabled)


if __name__ == "__main__":
    unittest.main()
