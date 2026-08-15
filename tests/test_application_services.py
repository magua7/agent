from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path

from security_agent.application.bootstrap import build_product_services
from security_agent.application.models import ProductUser
from security_agent.application.task_service import TaskInputError, TaskNotFoundError
from security_agent.domain import RunStatus
from security_agent.engine import RunLimits


class ApplicationServiceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.services = await build_product_services(
            Path(self.temporary.name) / "sec-go.db",
            jwt_secret="application-test-secret-that-is-more-than-32-bytes",
            run_limits=RunLimits(max_steps=5, max_replans=1, max_seconds=20),
        )
        admin = await self.services.products.get_user_by_username("admin")
        if admin is None:
            raise AssertionError("default admin was not created")
        self.admin: ProductUser = admin

    async def asyncTearDown(self) -> None:
        await self.services.close()
        self.temporary.cleanup()

    async def test_real_runtime_is_reached_through_task_and_run_services(self) -> None:
        server = await asyncio.start_server(lambda _reader, writer: writer.close(), "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            task = await self.services.tasks.create_task(
                self.admin.id,
                title="Authorized fixture",
                description="Analyze the explicitly authorized localhost fixture",
                target="127.0.0.1",
                ports=(port,),
            )
            self.assertIsNotNone(task.run_id)
            state = await self.services.tasks.wait(self.admin.id, task.id)
            detail = await self.services.tasks.get_task_detail(self.admin.id, task.id)
        finally:
            server.close()
            await server.wait_closed()

        self.assertIsNotNone(state)
        if state is None:
            raise AssertionError("runtime returned no state")
        self.assertEqual(RunStatus.COMPLETED, state.status)
        self.assertEqual("completed", detail["status"])
        self.assertEqual("network.scan", detail["plan"]["nodes"][0]["required_capabilities"][0])
        self.assertEqual(1, len(detail["evidence"]))
        self.assertTrue(detail["evidence"][0]["content_hash"])
        self.assertIn("SEC-GO Security Report", detail["report"])

        page = await self.services.tasks.list_events(self.admin.id, task.id, limit=100)
        event_types = [
            (await self.services.tasks.project_event(self.admin.id, task.id, item))["type"]
            for item in page.events
        ]
        self.assertIn("task_started", event_types)
        self.assertIn("plan_created", event_types)
        self.assertIn("evidence_created", event_types)
        self.assertIn("verification_finished", event_types)
        self.assertIn("task_completed", event_types)

    async def test_scope_is_explicit_and_owner_isolation_is_enforced(self) -> None:
        with self.assertRaises(TaskInputError):
            await self.services.tasks.create_task(
                self.admin.id,
                title="Missing scope",
                description="Analyze an unspecified service",
            )
        with self.assertRaises(TaskInputError):
            await self.services.tasks.create_task(
                self.admin.id,
                title="Remote scope",
                description="Analyze a remote service",
                target="192.0.2.10",
                ports=(80,),
            )

        other = await self.services.products.create_user(
            "other",
            self.admin.password_hash,
        )
        task = await self.services.tasks.create_task(
            self.admin.id,
            title="Owner task",
            description="Analyze localhost",
            ports=(9,),
        )
        with self.assertRaises(TaskNotFoundError):
            await self.services.tasks.get_task_detail(other.id, task.id)
        await self.services.tasks.wait(self.admin.id, task.id)


if __name__ == "__main__":
    unittest.main()
