from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any, cast

from security_agent.application.bootstrap import ProductServices, build_product_services
from security_agent.application.settings import ProductSettings
from security_agent.infrastructure.llm import (
    OpenAICompatibleConfig,
    OpenAICompatibleProvider,
)
from security_agent.interfaces.product_cli import build_parser


class ModelConfigurationTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_openai_compatible_http_path_drives_the_runtime(self) -> None:
        authorizations: list[str] = []

        async def model_handler(
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
        ) -> None:
            try:
                await reader.readline()
                headers: dict[str, str] = {}
                while True:
                    line = await reader.readline()
                    if line in {b"\r\n", b"\n", b""}:
                        break
                    name, value = line.decode("ascii").split(":", 1)
                    headers[name.casefold()] = value.strip()
                body = await reader.readexactly(int(headers.get("content-length", "0")))
                request = json.loads(body)
                model_payload = json.loads(request["messages"][1]["content"])
                authorizations.append(headers.get("authorization", ""))
                task = model_payload["task"]
                criterion = task["success_criteria"][0]
                if "current_evidence" in model_payload:
                    evidence_id = model_payload["current_evidence"]["id"]
                    answer: dict[str, object] = {
                        "summary": "The scoped tool evidence satisfies the criterion.",
                        "criterion_assessments": [
                            {
                                "criterion": criterion,
                                "satisfied": True,
                                "evidence_ids": [evidence_id],
                                "reason": "The cited network scan recorded the service state.",
                            }
                        ],
                        "finding_drafts": [],
                        "suggested_replan": False,
                    }
                elif "plan" in model_payload:
                    answer = {
                        "capability": "network.scan",
                        "arguments": {
                            "target": task["inputs"]["target"],
                            "ports": task["inputs"]["ports"],
                        },
                        "rationale": "Run the explicitly scoped localhost scan.",
                    }
                else:
                    answer = {
                        "nodes": [
                            {
                                "key": "discover",
                                "goal": "Inspect the authorized localhost service",
                                "description": "Use the bounded network capability.",
                                "assigned_agent": "structured-llm-agent",
                                "required_capabilities": ["network.scan"],
                                "dependencies": [],
                                "success_criteria": [criterion],
                                "max_attempts": 1,
                            }
                        ]
                    }
                response = json.dumps(
                    {
                        "choices": [
                            {
                                "message": {"content": json.dumps(answer)},
                                "finish_reason": "stop",
                            }
                        ],
                        "model": "local-openai-stub",
                        "usage": {},
                    }
                ).encode()
                writer.write(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: application/json\r\n"
                    + f"Content-Length: {len(response)}\r\n".encode()
                    + b"Connection: close\r\n\r\n"
                    + response
                )
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        model_server = await asyncio.start_server(model_handler, "127.0.0.1", 0)
        fixture = await asyncio.start_server(
            lambda _reader, writer: writer.close(),
            "127.0.0.1",
            0,
        )
        model_port = model_server.sockets[0].getsockname()[1]
        fixture_port = fixture.sockets[0].getsockname()[1]
        state = None
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                settings_path = root / "settings.json"
                settings_path.write_text(
                    json.dumps(
                        {
                            "llm": {
                                "enabled": True,
                                "provider": "openai-compatible",
                                "base_url": f"http://127.0.0.1:{model_port}/v1",
                                "api_key": "local-stub-key",
                                "model": "local-openai-stub",
                            }
                        }
                    ),
                    encoding="utf-8",
                )
                services = await build_product_services(
                    root / "sec-go.db",
                    jwt_secret="real-model-path-test-secret-over-32-bytes",
                    settings_path=settings_path,
                )
                admin = await services.products.get_user_by_username("admin")
                if admin is None:
                    self.fail("default admin was not created")
                try:
                    task = await services.tasks.create_task(
                        admin.id,
                        title="Configured model path",
                        description="Analyze the explicitly authorized localhost fixture",
                        target="127.0.0.1",
                        ports=(fixture_port,),
                    )
                    state = await services.tasks.wait(admin.id, task.id)
                finally:
                    await services.close()
        finally:
            model_server.close()
            fixture.close()
            await model_server.wait_closed()
            await fixture.wait_closed()

        self.assertIsNotNone(state)
        if state is None:
            self.fail("configured model run returned no state")
        self.assertEqual("completed", state.status.value)
        self.assertEqual(3, len(authorizations))
        self.assertEqual({"Bearer local-stub-key"}, set(authorizations))

    async def test_enabled_private_settings_construct_the_shared_model_provider(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings_path = root / "settings.json"
            settings_path.write_text(
                json.dumps(
                    {
                        "llm": {
                            "enabled": True,
                            "provider": "openai-compatible",
                            "base_url": "https://models.example/v1",
                            "api_key": "integration-secret",
                            "model": "example-model",
                        }
                    }
                ),
                encoding="utf-8",
            )
            services = await build_product_services(
                root / "sec-go.db",
                jwt_secret="model-configuration-test-secret-over-32-bytes",
                settings_path=settings_path,
            )
            try:
                self.assertIsInstance(services.llm_provider, OpenAICompatibleProvider)
                self.assertTrue(services.settings.llm.enabled)
                self.assertEqual("example-model", services.settings.llm.model)
                self.assertNotIn("integration-secret", repr(services.settings))
            finally:
                await services.close()

    async def test_product_close_always_reaches_runtime_and_provider(self) -> None:
        calls: list[str] = []

        class Closer:
            def __init__(self, name: str, *, fail: bool = False) -> None:
                self.name = name
                self.fail = fail

            async def close(self) -> None:
                calls.append(self.name)
                if self.fail:
                    raise RuntimeError(f"{self.name} close failed")

        class Provider:
            async def aclose(self) -> None:
                calls.append("provider")

        services = ProductServices(
            auth=cast(Any, object()),
            tasks=cast(Any, object()),
            runs=cast(Any, Closer("runs")),
            products=cast(Any, Closer("products", fail=True)),
            runtime=cast(Any, Closer("runtime")),
            database=Path("unused.db"),
            settings=ProductSettings(),
            llm_provider=cast(Any, Provider()),
        )

        with self.assertRaisesRegex(RuntimeError, "products close failed"):
            await services.close()

        self.assertEqual(["runs", "products", "runtime", "provider"], calls)

    def test_cli_accepts_an_explicit_settings_path(self) -> None:
        path = Path("private-model.json")
        args = build_parser().parse_args(
            [
                "run",
                "Analyze localhost",
                "--target",
                "127.0.0.1",
                "--settings",
                str(path),
            ]
        )

        self.assertEqual(path, args.settings)

    def test_openai_adapter_repr_does_not_expose_the_key(self) -> None:
        config = OpenAICompatibleConfig(
            base_url="https://models.example/v1",
            api_key="adapter-secret",
            model="example-model",
        )

        self.assertNotIn("adapter-secret", repr(config))


if __name__ == "__main__":
    unittest.main()
