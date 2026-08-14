from __future__ import annotations

import hashlib
import json
import math
import tempfile
import unittest
from pathlib import Path
from typing import Any

import httpx

from security_agent.contracts import LLMRequest, LLMResponse
from security_agent.domain import ScopeSpec, TaskSpec, TaskType
from security_agent.infrastructure.events import EventBus, MemoryEventSink
from security_agent.infrastructure.llm import (
    FakeLLMProvider,
    LLMProviderError,
    OpenAICompatibleConfig,
    OpenAICompatibleProvider,
)
from security_agent.infrastructure.skills import (
    FilesystemSkillProvider,
    SkillDiagnosticCode,
    SkillFormatError,
    SkillResourceLoading,
    SkillRiskClass,
    SkillSourceFormat,
)


def _task(objective: str = "Inspect", task_type: TaskType = TaskType.PENTEST) -> TaskSpec:
    return TaskSpec.create(
        objective=objective,
        task_type=task_type,
        scope=ScopeSpec(network_targets=("127.0.0.1",))
        if task_type is TaskType.PENTEST
        else ScopeSpec(),
        success_criteria=("Record evidence",),
    )


def _write_frontmatter_skill(
    root: Path,
    name: str,
    *,
    description: str = "A test skill.",
    body: str = "# Workflow\n\nUse bounded evidence.",
    folded: str | None = None,
) -> Path:
    skill = root / name
    skill.mkdir()
    if folded is None:
        frontmatter = f"---\nname: {name}\ndescription: {description}\n---\n\n"
    else:
        frontmatter = f"---\nname: {name}\ndescription: {folded}\n---\n\n"
    (skill / "SKILL.md").write_text(frontmatter + body, encoding="utf-8")
    return skill


def _write_legacy_skill(root: Path, name: str = "legacy") -> Path:
    skill = root / name
    skill.mkdir()
    manifest = {
        "name": name,
        "description": "Legacy bounded inspection.",
        "applicable_tasks": ["pentest"],
        "required_capabilities": ["network.scan"],
        "verification_guidance": "Require scanner evidence.",
        "references": [],
    }
    (skill / "skill.yaml").write_text(json.dumps(manifest), encoding="utf-8")
    (skill / "SKILL.md").write_text("# Legacy workflow", encoding="utf-8")
    return skill


def _policy_group(
    group_id: str,
    skills: list[str],
    *,
    enabled: bool = True,
    task_types: list[str] | None = None,
    risk_class: str = "passive",
    capabilities: list[str] | None = None,
    approval: bool = False,
    role: str = "leaf",
    resource_loading: str = "metadata_only",
) -> dict[str, Any]:
    return {
        "id": group_id,
        "skills": skills,
        "enabled": enabled,
        "task_types": ["pentest"] if task_types is None else task_types,
        "role": role,
        "risk_class": risk_class,
        "required_capabilities": [] if capabilities is None else capabilities,
        "human_approval_required": approval,
        "resource_loading": resource_loading,
    }


def _write_policy(
    root: Path,
    groups: list[dict[str, Any]],
    *,
    excluded: list[dict[str, str]] | None = None,
    extra: dict[str, Any] | None = None,
) -> None:
    policy: dict[str, Any] = {
        "schema_version": 1,
        "excluded": [] if excluded is None else excluded,
        "groups": groups,
    }
    if extra is not None:
        policy.update(extra)
    (root / "policy.json").write_text(json.dumps(policy), encoding="utf-8")


class FakeLLMTests(unittest.IsolatedAsyncioTestCase):
    async def test_responses_are_ordered_and_requests_are_recorded(self) -> None:
        provider = FakeLLMProvider(['{"value": 1}', '{"value": 2}'])
        request = LLMRequest(operation="test", system_prompt="test", payload={})

        first = await provider.complete(request)
        second = await provider.complete(request)

        self.assertEqual({"value": 1}, first.json_object())
        self.assertEqual({"value": 2}, second.json_object())
        self.assertEqual(2, len(provider.requests))
        provider.assert_exhausted()

    async def test_non_finite_model_json_is_rejected(self) -> None:
        response = LLMResponse(content=json.dumps({"value": math.nan}))
        with self.assertRaises(ValueError):
            response.json_object()


class OpenAIAdapterTests(unittest.IsolatedAsyncioTestCase):
    def test_remote_plaintext_endpoint_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            OpenAICompatibleConfig(
                base_url="http://model.invalid/v1",
                api_key="secret",
                model="example-model",
            )

    async def test_normalizes_chat_completion(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            self.assertNotIn("secret", request.url.query.decode())
            body = json.loads(request.content)
            self.assertEqual("example-model", body["model"])
            return httpx.Response(
                200,
                json={
                    "model": "example-model",
                    "choices": [
                        {
                            "message": {"content": '{"ok": true}'},
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {"total_tokens": 3},
                },
            )

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        provider = OpenAICompatibleProvider(
            OpenAICompatibleConfig(
                base_url="https://model.invalid/v1",
                api_key="secret",
                model="example-model",
            ),
            client=client,
        )
        response = await provider.complete(
            LLMRequest(
                operation="test",
                system_prompt="Return JSON.",
                payload={"hello": "world"},
                response_schema={"type": "object"},
            )
        )

        self.assertEqual({"ok": True}, response.json_object())
        await client.aclose()

    async def test_model_response_is_bounded_before_json_loading(self) -> None:
        client = httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda _request: httpx.Response(200, content=b"{" + b" " * 128 + b"}")
            )
        )
        provider = OpenAICompatibleProvider(
            OpenAICompatibleConfig(
                base_url="https://model.invalid/v1",
                api_key="secret",
                model="example-model",
                max_response_bytes=32,
            ),
            client=client,
        )
        with self.assertRaises(LLMProviderError):
            await provider.complete(LLMRequest(operation="test", system_prompt="test", payload={}))
        await client.aclose()


class SkillProviderTests(unittest.IsolatedAsyncioTestCase):
    async def test_repository_policy_loads_and_ranks_matching_skills(self) -> None:
        root = Path(__file__).resolve().parents[1] / "skills"
        provider = FilesystemSkillProvider(root, available_capabilities={"network.scan"})

        skills = await provider.select(_task("Inspect a local service"))
        descriptors = await provider.list_descriptors()

        self.assertEqual("local-service-discovery", skills[0].name)
        self.assertIn("pentest-quality-gate", {item.name for item in skills})
        self.assertLessEqual(len(skills), 4)
        self.assertIn("network.scan", skills[0].required_capabilities)
        self.assertEqual(106, len(descriptors))
        self.assertEqual(20, sum(item.policy.enabled for item in descriptors))
        self.assertEqual(64, len(descriptors[0].content_hash))
        self.assertTrue(
            all(item.code is SkillDiagnosticCode.SKILL_EXCLUDED for item in provider.diagnostics)
        )

    async def test_frontmatter_supports_plain_and_folded_descriptions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_frontmatter_skill(root, "plain", description="One line.")
            _write_frontmatter_skill(
                root,
                "folded-strip",
                folded=">-\n  First folded line\n  and its continuation.",
            )
            _write_frontmatter_skill(
                root,
                "folded-keep",
                folded=">\n  Another folded line\n  and continuation.",
            )
            _write_policy(
                root,
                [_policy_group("frontmatter", ["plain", "folded-strip", "folded-keep"])],
            )
            provider = FilesystemSkillProvider(root)

            descriptors = {item.name: item for item in await provider.list_descriptors()}

            self.assertEqual("One line.", descriptors["plain"].description)
            self.assertEqual(
                "First folded line and its continuation.",
                descriptors["folded-strip"].description,
            )
            self.assertEqual(
                "Another folded line and continuation.",
                descriptors["folded-keep"].description,
            )
            self.assertTrue(
                all(
                    item.source_format is SkillSourceFormat.FRONTMATTER
                    for item in descriptors.values()
                )
            )

    async def test_frontmatter_rejects_unknown_fields_and_empty_body(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_frontmatter_skill(root, "good")
            unknown = _write_frontmatter_skill(root, "unknown")
            (unknown / "SKILL.md").write_text(
                "---\nname: unknown\ndescription: test\nversion: 1\n---\nbody",
                encoding="utf-8",
            )
            empty = _write_frontmatter_skill(root, "empty")
            (empty / "SKILL.md").write_text(
                "---\nname: empty\ndescription: test\n---\n\n  \n",
                encoding="utf-8",
            )
            _write_policy(root, [_policy_group("strict", ["good", "unknown", "empty"])])

            provider = FilesystemSkillProvider(root)
            descriptors = await provider.list_descriptors()

            self.assertEqual(("good",), tuple(item.name for item in descriptors))
            failures = [
                item
                for item in provider.diagnostics
                if item.code is SkillDiagnosticCode.SKILL_INVALID
            ]
            self.assertEqual(2, len(failures))
            with self.assertRaises(SkillFormatError) as caught:
                await FilesystemSkillProvider(root, strict=True).list_descriptors()
            self.assertEqual(2, len(caught.exception.diagnostics))

    async def test_catalog_and_description_limits_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_frontmatter_skill(root, "one")
            _write_frontmatter_skill(root, "two")
            _write_policy(root, [_policy_group("all", ["one", "two"])])
            provider = FilesystemSkillProvider(root, max_skills=1)

            self.assertEqual((), await provider.list_descriptors())
            self.assertEqual(1, len(provider.diagnostics))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_frontmatter_skill(root, "verbose", description="too long")
            _write_policy(root, [_policy_group("verbose", ["verbose"])])
            provider = FilesystemSkillProvider(root, max_description_chars=4)

            self.assertEqual((), await provider.list_descriptors())
            self.assertIn(
                SkillDiagnosticCode.SKILL_INVALID,
                {item.code for item in provider.diagnostics},
            )

    async def test_duplicate_json_keys_are_rejected_at_every_object_depth(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_frontmatter_skill(root, "frontmatter")
            (root / "policy.json").write_text(
                """{
                  "schema_version": 1,
                  "excluded": [],
                  "groups": [{
                    "id": "first",
                    "id": "duplicate",
                    "skills": ["frontmatter"],
                    "enabled": true,
                    "task_types": ["pentest"],
                    "role": "leaf",
                    "risk_class": "passive",
                    "required_capabilities": [],
                    "human_approval_required": false,
                    "resource_loading": "metadata_only"
                  }]
                }""",
                encoding="utf-8",
            )
            provider = FilesystemSkillProvider(root)

            await provider.list_descriptors()

            codes = [item.code for item in provider.diagnostics]
            self.assertEqual(1, codes.count(SkillDiagnosticCode.POLICY_INVALID))
            self.assertNotIn(SkillDiagnosticCode.SKILL_UNCLASSIFIED, codes)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            skill = _write_legacy_skill(root)
            (skill / "skill.yaml").write_text(
                """{
                  "name": "legacy",
                  "description": "Legacy",
                  "applicable_tasks": ["pentest"],
                  "required_capabilities": [],
                  "verification_guidance": "Verify",
                  "references": [],
                  "extension": {"nested": 1, "nested": 2}
                }""",
                encoding="utf-8",
            )
            provider = FilesystemSkillProvider(root, trust_legacy_manifests=True)

            self.assertEqual((), await provider.list_descriptors())
            self.assertIn(
                SkillDiagnosticCode.SKILL_INVALID,
                {item.code for item in provider.diagnostics},
            )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_frontmatter_skill(root, "constant")
            (root / "policy.json").write_text(
                '{"schema_version": NaN, "excluded": [], "groups": []}',
                encoding="utf-8",
            )
            provider = FilesystemSkillProvider(root)

            await provider.list_descriptors()

            self.assertIn(
                SkillDiagnosticCode.POLICY_INVALID,
                {item.code for item in provider.diagnostics},
            )

    async def test_mixed_invalid_skills_are_isolated_and_strict_aggregates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_frontmatter_skill(root, "good", description="Good inspection skill.")
            mismatch = _write_frontmatter_skill(root, "mismatch")
            (mismatch / "SKILL.md").write_text(
                "---\nname: another-name\ndescription: mismatch\n---\nbody",
                encoding="utf-8",
            )
            missing = root / "missing-description"
            missing.mkdir()
            (missing / "SKILL.md").write_text(
                "---\nname: missing-description\n---\nbody",
                encoding="utf-8",
            )
            _write_policy(
                root,
                [_policy_group("mixed", ["good", "mismatch", "missing-description"])],
            )

            provider = FilesystemSkillProvider(root)
            selected = await provider.select(_task("good inspection"))

            self.assertEqual(("good",), tuple(item.name for item in selected))
            failures = [
                item
                for item in provider.diagnostics
                if item.code is SkillDiagnosticCode.SKILL_INVALID
            ]
            self.assertEqual(2, len(failures))

            strict_provider = FilesystemSkillProvider(root, strict=True)
            with self.assertRaises(SkillFormatError) as caught:
                await strict_provider.select(_task())
            self.assertEqual(2, len(caught.exception.diagnostics))

    async def test_unclassified_frontmatter_is_disabled_without_policy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_frontmatter_skill(root, "unclassified")
            provider = FilesystemSkillProvider(root)

            self.assertEqual((), await provider.select(_task()))
            descriptors = await provider.list_descriptors()
            self.assertEqual(1, len(descriptors))
            self.assertFalse(descriptors[0].policy.enabled)
            self.assertEqual("unclassified", descriptors[0].policy.group_id)
            self.assertIn(
                SkillDiagnosticCode.SKILL_UNCLASSIFIED,
                {item.code for item in provider.diagnostics},
            )

    async def test_legacy_manifest_remains_compatible_without_policy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_legacy_skill(root)
            untrusted = FilesystemSkillProvider(
                root,
                available_capabilities={"network.scan"},
            )
            self.assertEqual((), await untrusted.select(_task("legacy inspection")))
            self.assertIn(
                SkillDiagnosticCode.SKILL_UNCLASSIFIED,
                {item.code for item in untrusted.diagnostics},
            )

            provider = FilesystemSkillProvider(
                root,
                available_capabilities={"network.scan"},
                trust_legacy_manifests=True,
            )

            selected = await provider.select(_task("legacy inspection"))

            self.assertEqual(("legacy",), tuple(item.name for item in selected))
            self.assertEqual(("network.scan",), selected[0].required_capabilities)
            self.assertIsNotNone(selected[0].policy)
            assert selected[0].policy is not None
            self.assertEqual("legacy-manifest", selected[0].policy.group_id)
            descriptors = await provider.list_descriptors()
            self.assertIs(descriptors[0].source_format, SkillSourceFormat.LEGACY_MANIFEST)

    async def test_policy_filters_task_enabled_capabilities_and_lab_risk(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            names = ("passive", "wrong-task", "disabled", "lab", "missing-capability")
            for name in names:
                _write_frontmatter_skill(root, name, description=f"{name} workflow")
            _write_policy(
                root,
                [
                    _policy_group("passive", ["passive"], capabilities=["file.read"]),
                    _policy_group(
                        "wrong-task",
                        ["wrong-task"],
                        task_types=["incident_response"],
                    ),
                    _policy_group("disabled", ["disabled"], enabled=False),
                    _policy_group(
                        "lab",
                        ["lab"],
                        enabled=False,
                        risk_class="lab_only",
                        approval=True,
                    ),
                    _policy_group(
                        "missing-capability",
                        ["missing-capability"],
                        capabilities=["browser.inspect"],
                    ),
                ],
            )

            provider = FilesystemSkillProvider(root, available_capabilities={"file.read"})
            self.assertEqual(
                ("passive",),
                tuple(item.name for item in await provider.select(_task("passive"))),
            )

            lab_provider = FilesystemSkillProvider(
                root,
                available_capabilities={"file.read"},
                allow_lab_only=True,
            )
            self.assertEqual(
                {"passive"},
                {item.name for item in await lab_provider.select(_task("passive lab"))},
            )
            disabled = await provider.get_document("disabled")
            self.assertIsNone(disabled)
            disabled = await provider.get_document("disabled", allow_disabled=True)
            self.assertIsNotNone(disabled)
            assert disabled is not None
            self.assertIn("human_approval_required=false", disabled.workflow_guidance)
            self.assertIn("do not grant approval", disabled.workflow_guidance)
            lab = await provider.get_document(
                "lab",
                allow_disabled=True,
                allow_lab_only=True,
            )
            self.assertIsNotNone(lab)
            self.assertIs(lab.policy.risk_class, SkillRiskClass.LAB_ONLY)  # type: ignore[union-attr]

    async def test_missing_capability_inventory_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_frontmatter_skill(root, "scanner", description="Scanner workflow.")
            _write_policy(
                root,
                [_policy_group("scanner", ["scanner"], capabilities=["network.scan"])],
            )

            unavailable = FilesystemSkillProvider(root)
            available = FilesystemSkillProvider(
                root,
                available_capabilities={"network.scan"},
            )

            self.assertEqual((), await unavailable.select(_task("scanner")))
            self.assertEqual(
                ("scanner",),
                tuple(item.name for item in await available.select(_task("scanner"))),
            )

    async def test_policy_enforces_risk_approval_cross_field_constraints(self) -> None:
        invalid_groups = (
            _policy_group(
                "enabled-lab",
                ["risky"],
                risk_class="lab_only",
                approval=True,
            ),
            _policy_group(
                "unapproved-active",
                ["risky"],
                risk_class="active",
                approval=False,
            ),
        )
        for group in invalid_groups:
            with self.subTest(group=group["id"]), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                _write_frontmatter_skill(root, "risky")
                _write_policy(root, [group])
                provider = FilesystemSkillProvider(root)

                descriptors = await provider.list_descriptors()

                self.assertEqual(1, len(descriptors))
                self.assertFalse(descriptors[0].policy.enabled)
                codes = [item.code for item in provider.diagnostics]
                self.assertEqual(1, codes.count(SkillDiagnosticCode.POLICY_INVALID))
                self.assertNotIn(SkillDiagnosticCode.SKILL_UNCLASSIFIED, codes)

    async def test_selection_is_relevant_stable_and_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_frontmatter_skill(root, "zeta", description="General review.")
            _write_frontmatter_skill(root, "sql-injection", description="SQL injection testing.")
            _write_frontmatter_skill(root, "alpha", description="General review.")
            _write_frontmatter_skill(root, "quality", description="Verify evidence quality.")
            _write_policy(
                root,
                [
                    _policy_group("ranked", ["zeta", "sql-injection", "alpha"]),
                    _policy_group("quality", ["quality"], role="quality_gate"),
                ],
            )
            provider = FilesystemSkillProvider(root, max_selected=2)

            selected = await provider.select(_task("Investigate SQL injection vulnerability"))

            self.assertEqual(("sql-injection", "quality"), tuple(item.name for item in selected))
            gate_only = await provider.select(_task("completely unrelated objective"))
            self.assertEqual(("quality",), tuple(item.name for item in gate_only))

    async def test_selection_does_not_fill_results_from_generic_security_terms(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_frontmatter_skill(
                root,
                "rsa-attack-techniques",
                description="RSA shared-prime cryptanalysis playbook.",
            )
            _write_frontmatter_skill(
                root,
                "symbolic-execution-tools",
                description="Symbolic execution playbook for CTF challenges.",
            )
            _write_frontmatter_skill(
                root,
                "vm-bytecode-reverse",
                description="VM reverse analysis playbook for CTF challenges.",
            )
            _write_frontmatter_skill(
                root,
                "lattice-crypto-attacks",
                description="Advanced RSA techniques for CTF challenges.",
            )
            _write_policy(
                root,
                [
                    _policy_group(
                        "ctf",
                        [
                            "rsa-attack-techniques",
                            "symbolic-execution-tools",
                            "vm-bytecode-reverse",
                            "lattice-crypto-attacks",
                        ],
                        task_types=["ctf"],
                    )
                ],
            )
            provider = FilesystemSkillProvider(root)

            selected = await provider.select(
                _task("Solve an authorized RSA shared-prime CTF challenge", task_type=TaskType.CTF)
            )

            self.assertEqual(("rsa-attack-techniques",), tuple(item.name for item in selected))

    async def test_index_is_cached_until_refresh_and_hash_tracks_raw_document(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            skill = _write_frontmatter_skill(root, "cached", description="Old description.")
            _write_policy(root, [_policy_group("cache", ["cached"])])
            provider = FilesystemSkillProvider(root)
            first = (await provider.list_descriptors())[0]
            old_document = await provider.get_document("cached")
            self.assertIsNotNone(old_document)
            assert old_document is not None
            self.assertEqual(first.content_hash, old_document.content_hash)

            updated_text = (
                "---\nname: cached\ndescription: New description.\n---\n\n# Updated workflow"
            )
            (skill / "SKILL.md").write_text(updated_text, encoding="utf-8")
            cached = (await provider.list_descriptors())[0]
            self.assertEqual("Old description.", cached.description)
            self.assertEqual(first.content_hash, cached.content_hash)
            with self.assertRaisesRegex(SkillFormatError, "call refresh"):
                await provider.get_document("cached")

            refreshed = (await provider.refresh())[0]
            self.assertEqual("New description.", refreshed.description)
            self.assertEqual(
                hashlib.sha256((skill / "SKILL.md").read_bytes()).hexdigest(),
                refreshed.content_hash,
            )
            refreshed_document = await provider.get_document("cached")
            self.assertIsNotNone(refreshed_document)
            assert refreshed_document is not None
            self.assertEqual(refreshed.content_hash, refreshed_document.content_hash)
            self.assertIn("Updated workflow", refreshed_document.workflow_guidance)

    async def test_body_changed_before_first_document_load_requires_refresh(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            skill = _write_frontmatter_skill(root, "lazy", body="# Original body")
            _write_policy(root, [_policy_group("lazy", ["lazy"])])
            provider = FilesystemSkillProvider(root)
            await provider.list_descriptors()

            (skill / "SKILL.md").write_text(
                "---\nname: lazy\ndescription: A test skill.\n---\n\n# Changed body",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(SkillFormatError, "call refresh"):
                await provider.get_document("lazy")

    async def test_only_directly_linked_same_skill_markdown_resources_can_be_read(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outside = root / "outside.md"
            outside.write_text("outside", encoding="utf-8")
            skill = _write_frontmatter_skill(
                root,
                "resources",
                body=(
                    "[Guide](guide.md)\n"
                    "[Nested]: <notes/extra.md>\n"
                    "[Outside](../outside.md)\n"
                    "[Not Markdown](secret.txt)"
                ),
            )
            (skill / "guide.md").write_text("trusted guide", encoding="utf-8")
            notes = skill / "notes"
            notes.mkdir()
            (notes / "extra.md").write_text("nested guide", encoding="utf-8")
            (skill / "unreferenced.md").write_text("secret", encoding="utf-8")
            (skill / "secret.txt").write_text("text", encoding="utf-8")
            _write_policy(
                root,
                [
                    _policy_group(
                        "resources",
                        ["resources"],
                        resource_loading="linked_markdown",
                    )
                ],
            )
            provider = FilesystemSkillProvider(root)

            self.assertEqual(
                ("guide.md", "notes/extra.md"),
                await provider.list_resources("resources"),
            )
            self.assertEqual("trusted guide", await provider.read_resource("resources", "guide.md"))
            self.assertEqual(
                "nested guide",
                await provider.read_resource("resources", "notes/extra.md"),
            )
            for denied in ("../outside.md", str(outside.resolve()), "unreferenced.md", "SKILL.md"):
                with self.subTest(denied=denied), self.assertRaises(SkillFormatError):
                    await provider.read_resource("resources", denied)

            bounded = FilesystemSkillProvider(root, max_resource_bytes=4)
            with self.assertRaises(SkillFormatError):
                await bounded.read_resource("resources", "guide.md")

    async def test_resource_access_requires_disabled_and_lab_overrides(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("active", "lab"):
                skill = _write_frontmatter_skill(root, name, body="[Guide](guide.md)")
                (skill / "guide.md").write_text(f"{name} guide", encoding="utf-8")
            _write_policy(
                root,
                [
                    _policy_group(
                        "active",
                        ["active"],
                        enabled=False,
                        risk_class="active",
                        approval=True,
                        resource_loading="linked_markdown",
                    ),
                    _policy_group(
                        "lab",
                        ["lab"],
                        enabled=False,
                        risk_class="lab_only",
                        approval=True,
                        resource_loading="linked_markdown",
                    ),
                ],
            )
            provider = FilesystemSkillProvider(root)

            with self.assertRaises(SkillFormatError):
                await provider.list_resources("active")
            self.assertEqual(
                ("guide.md",),
                await provider.list_resources("active", allow_disabled=True),
            )
            self.assertEqual(
                "active guide",
                await provider.read_resource("active", "guide.md", allow_disabled=True),
            )
            with self.assertRaises(SkillFormatError):
                await provider.list_resources("lab", allow_disabled=True)
            self.assertEqual(
                ("guide.md",),
                await provider.list_resources(
                    "lab",
                    allow_disabled=True,
                    allow_lab_only=True,
                ),
            )
            self.assertEqual(
                "lab guide",
                await provider.read_resource(
                    "lab",
                    "guide.md",
                    allow_disabled=True,
                    allow_lab_only=True,
                ),
            )

    async def test_replacing_indexed_skill_directory_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            skill = _write_frontmatter_skill(root, "replaceable", body="[Guide](guide.md)")
            (skill / "guide.md").write_text("original", encoding="utf-8")
            _write_policy(
                root,
                [
                    _policy_group(
                        "replaceable",
                        ["replaceable"],
                        resource_loading="linked_markdown",
                    )
                ],
            )
            provider = FilesystemSkillProvider(root)
            await provider.list_descriptors()

            skill.rename(root / "original-replaceable")
            replacement = _write_frontmatter_skill(
                root,
                "replaceable",
                body="[Guide](guide.md)",
            )
            (replacement / "guide.md").write_text("replacement", encoding="utf-8")

            with self.assertRaisesRegex(SkillFormatError, "call refresh"):
                await provider.get_document("replaceable")
            with self.assertRaisesRegex(SkillFormatError, "call refresh"):
                await provider.list_resources("replaceable")
            with self.assertRaisesRegex(SkillFormatError, "call refresh"):
                await provider.read_resource("replaceable", "guide.md")

    async def test_metadata_only_and_excluded_skills_do_not_expose_resources(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            metadata = _write_frontmatter_skill(root, "metadata", body="[Guide](guide.md)")
            (metadata / "guide.md").write_text("guide", encoding="utf-8")
            excluded = root / "excluded"
            excluded.mkdir()
            (excluded / "SKILL.md").write_text("not parsed", encoding="utf-8")
            _write_policy(
                root,
                [_policy_group("metadata", ["metadata"])],
                excluded=[{"skill": "excluded", "reason": "not trusted"}],
            )
            provider = FilesystemSkillProvider(root, strict=True)

            descriptors = await provider.list_descriptors()

            self.assertEqual(("metadata",), tuple(item.name for item in descriptors))
            self.assertIs(
                descriptors[0].policy.resource_loading, SkillResourceLoading.METADATA_ONLY
            )
            self.assertEqual((), await provider.list_resources("metadata"))
            self.assertIn(
                SkillDiagnosticCode.SKILL_EXCLUDED,
                {item.code for item in provider.diagnostics},
            )

    async def test_policy_schema_is_strict_and_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_frontmatter_skill(root, "frontmatter")
            _write_policy(
                root,
                [_policy_group("group", ["frontmatter"])],
                extra={"unknown": True},
            )
            provider = FilesystemSkillProvider(root)

            descriptors = await provider.list_descriptors()

            self.assertEqual(1, len(descriptors))
            self.assertFalse(descriptors[0].policy.enabled)
            self.assertIn(
                SkillDiagnosticCode.POLICY_INVALID,
                {item.code for item in provider.diagnostics},
            )
            with self.assertRaises(SkillFormatError):
                await FilesystemSkillProvider(root, strict=True).list_descriptors()

    async def test_non_json_legacy_manifest_is_isolated_or_strictly_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            skill = root / "bad"
            skill.mkdir()
            (skill / "skill.yaml").write_text("name: unsupported", encoding="utf-8")
            (skill / "SKILL.md").write_text("guidance", encoding="utf-8")
            provider = FilesystemSkillProvider(root)

            self.assertEqual((), await provider.select(_task()))
            self.assertIn(
                SkillDiagnosticCode.SKILL_INVALID,
                {item.code for item in provider.diagnostics},
            )
            with self.assertRaises(SkillFormatError):
                await FilesystemSkillProvider(root, strict=True).select(_task())

    async def test_rejects_linked_skill_guidance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outside = root / "outside.md"
            outside.write_text("do not load", encoding="utf-8")
            skill = root / "linked"
            skill.mkdir()
            (skill / "skill.yaml").write_text("{}", encoding="utf-8")
            try:
                (skill / "SKILL.md").symlink_to(outside)
            except OSError as exc:
                self.skipTest(f"symlinks unavailable: {exc}")
            provider = FilesystemSkillProvider(root, strict=True)
            with self.assertRaises(SkillFormatError):
                await provider.select(_task(task_type=TaskType.GENERIC))


class EventBusTests(unittest.IsolatedAsyncioTestCase):
    async def test_memory_sink_keeps_run_events(self) -> None:
        from security_agent.contracts import EventType, RunEvent

        sink = MemoryEventSink()
        bus = EventBus((sink,))
        event = RunEvent(EventType.RUN_STARTED, "run-1", {"safe": True})
        await bus.publish(event)
        self.assertEqual((event,), sink.events)


if __name__ == "__main__":
    unittest.main()
