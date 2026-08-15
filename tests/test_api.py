from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path

import httpx

from security_agent.application.bootstrap import build_product_services
from security_agent.engine import RunLimits
from security_agent.interfaces.api.app import create_app


class FastAPIIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.services = await build_product_services(
            Path(self.temporary.name) / "sec-go.db",
            jwt_secret="api-integration-secret-that-is-more-than-32-bytes",
            run_limits=RunLimits(max_steps=5, max_replans=1, max_seconds=20),
        )
        app = create_app(
            services=self.services,
            frontend_dist=Path(self.temporary.name) / "no-frontend",
        )
        self.lifespan = app.router.lifespan_context(app)
        await self.lifespan.__aenter__()
        self.client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        )

    async def asyncTearDown(self) -> None:
        await self.client.aclose()
        await self.lifespan.__aexit__(None, None, None)
        await self.services.close()
        self.temporary.cleanup()

    async def _admin_headers(self) -> dict[str, str]:
        response = await self.client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "secgo"},
        )
        self.assertEqual(200, response.status_code)
        return {"Authorization": f"Bearer {response.json()['access_token']}"}

    async def test_login_validation_and_authentication_boundary(self) -> None:
        wrong = await self.client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "wrong"},
        )
        self.assertEqual(401, wrong.status_code)
        self.assertNotIn("password_hash", wrong.text)

        unauthenticated = await self.client.get("/api/tasks")
        self.assertEqual(401, unauthenticated.status_code)
        self.assertEqual("Bearer", unauthenticated.headers["www-authenticate"])

        extra = await self.client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "secgo", "extra": True},
        )
        self.assertEqual(422, extra.status_code)
        self.assertEqual("ok", (await self.client.get("/api/health")).json()["status"])

    async def test_real_task_sse_replay_evidence_and_owner_isolation(self) -> None:
        fixture = await asyncio.start_server(
            lambda _reader, writer: writer.close(),
            "127.0.0.1",
            0,
        )
        port = fixture.sockets[0].getsockname()[1]
        headers = await self._admin_headers()
        try:
            created = await self.client.post(
                "/api/tasks",
                headers=headers,
                json={
                    "title": "API localhost fixture",
                    "description": "Analyze an explicitly authorized localhost fixture",
                    "target": "127.0.0.1",
                    "ports": [port],
                },
            )
            self.assertEqual(202, created.status_code, created.text)
            task_id = created.json()["task_id"]

            stream = await self.client.get(f"/api/tasks/{task_id}/events", headers=headers)
        finally:
            fixture.close()
            await fixture.wait_closed()

        self.assertEqual(200, stream.status_code)
        self.assertTrue(stream.headers["content-type"].startswith("text/event-stream"))
        events = _sse_events(stream.text)
        event_types = [item["type"] for item in events]
        for required in (
            "task_started",
            "plan_created",
            "node_started",
            "tool_started",
            "evidence_created",
            "verification_finished",
            "task_completed",
        ):
            self.assertIn(required, event_types)
        sequences = [_sequence(item) for item in events]
        self.assertEqual(sorted(sequences), sequences)

        detail_response = await self.client.get(f"/api/tasks/{task_id}", headers=headers)
        self.assertEqual(200, detail_response.status_code)
        detail = detail_response.json()
        self.assertEqual("completed", detail["status"])
        self.assertEqual(1, len(detail["evidence"]))
        self.assertNotIn("raw_content", detail["evidence"][0])
        self.assertTrue(detail["report"].startswith("# SEC-GO"))

        evidence_id = detail["evidence"][0]["id"]
        evidence = await self.client.get(
            f"/api/tasks/{task_id}/evidence/{evidence_id}",
            headers=headers,
        )
        self.assertEqual(200, evidence.status_code)
        self.assertTrue(evidence.json()["integrity_valid"])
        self.assertIn("raw_content", evidence.json())

        replay_cursor = _sequence(events[2])
        replay = await self.client.get(
            f"/api/tasks/{task_id}/events",
            headers={**headers, "Last-Event-ID": str(replay_cursor)},
        )
        replayed = _sse_events(replay.text)
        self.assertTrue(replayed)
        self.assertTrue(all(_sequence(item) > replay_cursor for item in replayed))

        admin = await self.services.products.get_user_by_username("admin")
        if admin is None:
            self.fail("admin disappeared")
        other = await self.services.products.create_user("api-other", admin.password_hash)
        other_token = self.services.auth.issue_token(other).access_token
        hidden = await self.client.get(
            f"/api/tasks/{task_id}",
            headers={"Authorization": f"Bearer {other_token}"},
        )
        self.assertEqual(404, hidden.status_code)

    async def test_non_loopback_scope_is_rejected(self) -> None:
        headers = await self._admin_headers()
        response = await self.client.post(
            "/api/tasks",
            headers=headers,
            json={
                "title": "Remote",
                "description": "Analyze remote host",
                "target": "198.51.100.2",
                "ports": [443],
            },
        )
        self.assertEqual(422, response.status_code)


def _sse_events(body: str) -> list[dict[str, object]]:
    events: list[dict[str, object]] = []
    for frame in body.replace("\r\n", "\n").split("\n\n"):
        data = [line[6:] for line in frame.splitlines() if line.startswith("data: ")]
        if data:
            value = json.loads("\n".join(data))
            if isinstance(value, dict):
                events.append(value)
    return events


def _sequence(event: dict[str, object]) -> int:
    value = event.get("sequence")
    if isinstance(value, bool) or not isinstance(value, int):
        raise AssertionError("SSE event sequence must be an integer")
    return value


if __name__ == "__main__":
    unittest.main()
