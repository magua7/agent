from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from security_agent.domain import RunStatus, ScopeSpec, TaskSpec, TaskType
from security_agent.infrastructure.llm import FakeLLMProvider
from security_agent.infrastructure.skills import NullSkillProvider
from security_agent.interfaces.bootstrap import build_local_runtime


class BootstrapTests(unittest.IsolatedAsyncioTestCase):
    async def test_composition_passes_the_real_tool_capability_inventory_to_skills(self) -> None:
        captured: dict[str, object] = {}

        def provider_factory(root: Path, **options: object) -> NullSkillProvider:
            captured["root"] = root
            captured.update(options)
            return NullSkillProvider()

        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "runtime.sqlite3"
            skill_root = Path(directory) / "skills"
            skill_root.mkdir()
            with patch(
                "security_agent.interfaces.bootstrap.FilesystemSkillProvider",
                side_effect=provider_factory,
            ):
                bundle = await build_local_runtime(database, skills_root=skill_root)
            await bundle.close()

        self.assertEqual(skill_root.resolve(), captured["root"])
        self.assertEqual(
            frozenset({"network.scan", "http.request", "file.read", "file.search", "code.search"}),
            captured["available_capabilities"],
        )

    async def test_llm_composition_receives_the_packaged_skill_snapshot(self) -> None:
        provider = FakeLLMProvider(["{}"])
        task = TaskSpec.create(
            objective="Inspect explicitly authorized localhost service ports",
            task_type=TaskType.PENTEST,
            scope=ScopeSpec(network_targets=("127.0.0.1",)),
            inputs={"target": "127.0.0.1", "ports": [41012]},
            success_criteria=("Record the observed service state",),
        )
        with tempfile.TemporaryDirectory() as directory:
            bundle = await build_local_runtime(
                Path(directory) / "runtime.sqlite3",
                llm_provider=provider,
            )
            try:
                state = await bundle.runtime.run(task)
            finally:
                await bundle.close()

        self.assertEqual(RunStatus.FAILED, state.status)
        self.assertEqual("generate_plan", provider.requests[0].operation)
        skills = provider.requests[0].payload["skills"]
        assert isinstance(skills, list)
        self.assertTrue(skills)
        local = next(
            item
            for item in skills
            if isinstance(item, dict) and item.get("name") == "local-service-discovery"
        )
        self.assertIsInstance(local.get("content_hash"), str)


if __name__ == "__main__":
    unittest.main()
