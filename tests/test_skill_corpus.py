from __future__ import annotations

import json
import re
import subprocess
import sys
import unittest
from collections import Counter
from pathlib import Path
from typing import cast

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SKILLS_ROOT = REPOSITORY_ROOT / "skills"
POLICY_PATH = SKILLS_ROOT / "policy.json"

EXPECTED_SKILL_DIRECTORY_COUNT = 106
PROJECT_OWNED_SKILLS = frozenset({"local-service-discovery"})
DEFERRED_SKILLS = frozenset({"php-audit-skills"})

ALLOWED_RISK_CLASSES = frozenset({"passive", "active", "lab_only"})
ALLOWED_ROLES = frozenset({"router", "leaf", "quality_gate", "orchestrator"})
ALLOWED_RESOURCE_LOADING = frozenset({"metadata_only", "linked_markdown"})
ALLOWED_TASK_TYPES = frozenset(
    {"generic", "pentest", "incident_response", "code_audit", "reverse_analysis", "ctf"}
)
ALLOWED_CAPABILITIES = frozenset(
    {"network.scan", "http.request", "file.read", "file.search", "code.search"}
)

REPRESENTATIVE_LAB_ONLY_SKILLS = frozenset(
    {
        "reverse-shell-techniques",
        "windows-av-evasion",
        "windows-lateral-movement",
        "linux-lateral-movement",
        "tunneling-and-pivoting",
        "container-escape-techniques",
        "sandbox-escape-techniques",
    }
)

_FRONTMATTER_KEY = re.compile(r"^([a-z][a-z0-9_-]*):(?:[ ]*(.*))?$")
_SKILL_NAME = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")
_CROSS_DIRECTORY_MARKDOWN_LINK = re.compile(
    r"\]\(\.\./[^)\r\n]+\.md(?:#[^)\r\n]*)?\)",
    re.IGNORECASE,
)
_DETAIL_REFERENCE_LINK = re.compile(
    r"\]\((?:\./)?TECHNIQUE_REFERENCE\.md(?:#[^)]*)?\)",
    re.IGNORECASE,
)
_LEGACY_MODEL_OR_LOAD_INSTRUCTION = re.compile(
    r"\bclaude(?: code)?\b|\bbase models\b|WHEN TO LOAD THIS SKILL|"
    r"^\s*(?:Also load|Load when|Before [^\n:]+can first load):\s*$",
    re.IGNORECASE | re.MULTILINE,
)
_UNAVAILABLE_ACTION_ASSUMPTION = re.compile(
    r"Routing note:\s*load this skill|\*\*LOAD FIRST\*\*|Send to Group|"
    r"Race Condition Test with Burp|Check Burp Collaborator|Burp [\"']Discover Content|"
    r"Run these immediately after landing a shell|Use `redis-rogue-server`|"
    r"^## 3\. TESTING WITH TOOLS\s*$|Log in as UserA|Hook `fopen|"
    r"Unset suspicious env vars|Capture the \*\*state-changing\*\* request|"
    r"Send the \*\*same\*\* authenticated request|Start two parallel pipelines",
    re.IGNORECASE | re.MULTILINE,
)

CONTRACT_START = "<!-- zhiyugo:contract:start -->"
CONTRACT_END = "<!-- zhiyugo:contract:end -->"
RESOURCE_START = "<!-- zhiyugo:resource:start -->"
RESOURCE_END = "<!-- zhiyugo:resource:end -->"
TOC_START = "<!-- zhiyugo:toc:start -->"
TOC_END = "<!-- zhiyugo:toc:end -->"
MAX_LINKED_LEAF_BODY_CHARS = 6_500


def _load_policy() -> dict[str, object]:
    value = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssertionError("skills/policy.json must contain a JSON object")
    return value


def _skill_directories() -> set[str]:
    return {
        path.name
        for path in SKILLS_ROOT.iterdir()
        if path.is_dir() and path.name not in DEFERRED_SKILLS
    }


def _parse_frontmatter(path: Path) -> dict[str, str]:
    """Parse the intentionally small frontmatter subset used by the corpus.

    This parser is data-only: it recognizes plain scalars and indented YAML
    block scalars without importing or executing anything from a Skill.
    """

    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines or lines[0] != "---":
        raise ValueError("frontmatter must start on the first line")
    try:
        closing_index = lines.index("---", 1)
    except ValueError as exc:
        raise ValueError("frontmatter closing delimiter is missing") from exc
    if not any(line.strip() for line in lines[closing_index + 1 :]):
        raise ValueError("SKILL.md body must not be empty")

    metadata: dict[str, str] = {}
    index = 1
    while index < closing_index:
        line = lines[index]
        if not line.strip():
            index += 1
            continue
        if line[0].isspace():
            raise ValueError(f"unexpected frontmatter continuation on line {index + 1}")
        match = _FRONTMATTER_KEY.fullmatch(line)
        if match is None:
            raise ValueError(f"unsupported frontmatter syntax on line {index + 1}")
        key, raw_value = match.groups()
        if key in metadata:
            raise ValueError(f"duplicate frontmatter key {key!r}")
        raw_value = (raw_value or "").strip()

        if raw_value in {">", ">-", "|", "|-"}:
            index += 1
            block: list[str] = []
            while index < closing_index:
                continuation = lines[index]
                if continuation and not continuation.startswith("  "):
                    break
                block.append(continuation[2:] if continuation else "")
                index += 1
            separator = "\n" if raw_value.startswith("|") else " "
            value = separator.join(part.strip() for part in block).strip()
        else:
            if not raw_value:
                raise ValueError(f"frontmatter value {key!r} must not be empty")
            value = raw_value
            index += 1

        if not value:
            raise ValueError(f"frontmatter value {key!r} must not be empty")
        metadata[key] = value

    if set(metadata) != {"name", "description"}:
        raise ValueError("frontmatter must contain only name and description")
    if _SKILL_NAME.fullmatch(metadata["name"]) is None:
        raise ValueError("frontmatter name is not a canonical Skill name")
    return metadata


def _skill_body(path: Path) -> str:
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    try:
        closing_index = next(
            index for index, line in enumerate(lines[1:], start=1) if line.strip() == "---"
        )
    except StopIteration as exc:
        raise ValueError("frontmatter closing delimiter is missing") from exc
    return "".join(lines[closing_index + 1 :]).lstrip("\r\n")


def _groups(policy: dict[str, object]) -> list[dict[str, object]]:
    groups = policy.get("groups")
    if not isinstance(groups, list) or not all(isinstance(group, dict) for group in groups):
        raise AssertionError("policy groups must be a list of objects")
    return cast(list[dict[str, object]], groups)


def _string_field(group: dict[str, object], key: str) -> str:
    value = group.get(key)
    if not isinstance(value, str) or not value:
        raise AssertionError(f"policy group field {key!r} must be non-empty text")
    return value


def _string_list_field(group: dict[str, object], key: str) -> list[str]:
    value = group.get(key)
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise AssertionError(f"policy group field {key!r} must be a string list")
    return cast(list[str], value)


def _bool_field(group: dict[str, object], key: str) -> bool:
    value = group.get(key)
    if type(value) is not bool:
        raise AssertionError(f"policy group field {key!r} must be boolean")
    return value


def _group_by_skill(policy: dict[str, object]) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    for group in _groups(policy):
        for skill in _string_list_field(group, "skills"):
            if skill in result:
                raise AssertionError(f"skill {skill!r} is assigned to more than one group")
            result[skill] = group
    return result


class SkillCorpusPolicyTests(unittest.TestCase):
    def test_current_directories_are_covered_by_exactly_one_group(self) -> None:
        policy = _load_policy()
        directories = _skill_directories()
        self.assertEqual(EXPECTED_SKILL_DIRECTORY_COUNT, len(directories))

        assigned = [
            skill for group in _groups(policy) for skill in _string_list_field(group, "skills")
        ]
        counts = Counter(assigned)
        self.assertEqual(directories, set(counts))
        self.assertEqual([], sorted(skill for skill, count in counts.items() if count != 1))

        excluded = policy.get("excluded")
        self.assertIsInstance(excluded, list)
        assert isinstance(excluded, list)
        excluded_names: list[str] = []
        for entry in excluded:
            self.assertIsInstance(entry, dict)
            assert isinstance(entry, dict)
            self.assertIsInstance(entry.get("skill"), str)
            self.assertIsInstance(entry.get("reason"), str)
            self.assertTrue(str(entry.get("reason", "")).strip())
            excluded_names.append(str(entry["skill"]))
        self.assertEqual(len(excluded_names), len(set(excluded_names)))
        self.assertTrue(DEFERRED_SKILLS.issubset(excluded_names))
        self.assertTrue(DEFERRED_SKILLS.isdisjoint(counts))

    def test_policy_values_and_capabilities_use_closed_enums(self) -> None:
        policy = _load_policy()
        self.assertEqual(1, policy.get("schema_version"))

        group_ids: list[str] = []
        required_fields = {
            "id",
            "skills",
            "enabled",
            "task_types",
            "role",
            "risk_class",
            "required_capabilities",
            "human_approval_required",
            "resource_loading",
        }
        for group in _groups(policy):
            with self.subTest(group=group.get("id")):
                self.assertTrue(required_fields.issubset(group))
                group_ids.append(_string_field(group, "id"))
                _bool_field(group, "enabled")
                _bool_field(group, "human_approval_required")
                self.assertIn(_string_field(group, "role"), ALLOWED_ROLES)
                self.assertIn(_string_field(group, "risk_class"), ALLOWED_RISK_CLASSES)
                self.assertIn(
                    _string_field(group, "resource_loading"),
                    ALLOWED_RESOURCE_LOADING,
                )
                risk_class = _string_field(group, "risk_class")
                if risk_class in {"active", "lab_only"}:
                    self.assertTrue(_bool_field(group, "human_approval_required"))
                if risk_class == "lab_only":
                    self.assertFalse(_bool_field(group, "enabled"))
                if risk_class == "active" and _bool_field(group, "enabled"):
                    self.assertEqual("native-local-discovery", _string_field(group, "id"))

                skills = _string_list_field(group, "skills")
                self.assertTrue(skills)
                self.assertEqual(len(skills), len(set(skills)))

                task_types = _string_list_field(group, "task_types")
                self.assertTrue(task_types)
                self.assertEqual(len(task_types), len(set(task_types)))
                self.assertTrue(set(task_types).issubset(ALLOWED_TASK_TYPES))

                capabilities = _string_list_field(group, "required_capabilities")
                self.assertEqual(len(capabilities), len(set(capabilities)))
                self.assertTrue(set(capabilities).issubset(ALLOWED_CAPABILITIES))

        self.assertEqual(len(group_ids), len(set(group_ids)))

    def test_external_skills_cannot_request_runtime_capabilities(self) -> None:
        policy = _load_policy()
        directories = _skill_directories()
        self.assertEqual(105, len(directories - PROJECT_OWNED_SKILLS))
        by_skill = _group_by_skill(policy)

        for skill in sorted(directories - PROJECT_OWNED_SKILLS):
            with self.subTest(skill=skill):
                self.assertEqual([], _string_list_field(by_skill[skill], "required_capabilities"))
        self.assertEqual(
            ["network.scan"],
            _string_list_field(by_skill["local-service-discovery"], "required_capabilities"),
        )

    def test_representative_high_risk_skills_remain_quarantined(self) -> None:
        by_skill = _group_by_skill(_load_policy())
        self.assertTrue(REPRESENTATIVE_LAB_ONLY_SKILLS.issubset(by_skill))

        for skill in sorted(REPRESENTATIVE_LAB_ONLY_SKILLS):
            group = by_skill[skill]
            with self.subTest(skill=skill, group=group.get("id")):
                self.assertEqual("lab_only", _string_field(group, "risk_class"))
                self.assertIs(_bool_field(group, "enabled"), False)
                self.assertIs(_bool_field(group, "human_approval_required"), True)


class SkillCorpusFrontmatterTests(unittest.TestCase):
    def test_external_skill_frontmatter_is_standard_and_name_matches_directory(self) -> None:
        external_skills = _skill_directories() - PROJECT_OWNED_SKILLS
        self.assertEqual(105, len(external_skills))

        for skill in sorted(external_skills):
            with self.subTest(skill=skill):
                skill_file = SKILLS_ROOT / skill / "SKILL.md"
                self.assertTrue(skill_file.is_file())
                metadata = _parse_frontmatter(skill_file)
                self.assertEqual(skill, metadata["name"])
                self.assertTrue(metadata["description"].strip())


class SkillCorpusAdaptationTests(unittest.TestCase):
    def test_every_cataloged_skill_has_one_policy_mirrored_contract(self) -> None:
        by_skill = _group_by_skill(_load_policy())

        for skill, group in sorted(by_skill.items()):
            with self.subTest(skill=skill):
                path = SKILLS_ROOT / skill / "SKILL.md"
                body = _skill_body(path)
                self.assertEqual(1, body.count(CONTRACT_START))
                self.assertEqual(1, body.count(CONTRACT_END))
                self.assertLess(body.index(CONTRACT_START), 400)

                default = "enabled" if _bool_field(group, "enabled") else "disabled"
                self.assertIn(f"`role={_string_field(group, 'role')}`", body)
                self.assertIn(f"`risk={_string_field(group, 'risk_class')}`", body)
                self.assertIn(f"`default={default}`", body)
                self.assertNotIn("AI LOAD INSTRUCTION", body)
                self.assertIsNone(_CROSS_DIRECTORY_MARKDOWN_LINK.search(body))
                self.assertIsNone(_LEGACY_MODEL_OR_LOAD_INSTRUCTION.search(body))
                self.assertIsNone(_UNAVAILABLE_ACTION_ASSUMPTION.search(body))

    def test_linked_leaf_main_documents_fit_the_runtime_budget(self) -> None:
        by_skill = _group_by_skill(_load_policy())

        for skill, group in sorted(by_skill.items()):
            if (
                _string_field(group, "role") != "leaf"
                or _string_field(group, "resource_loading") != "linked_markdown"
            ):
                continue
            with self.subTest(skill=skill):
                directory = SKILLS_ROOT / skill
                body = _skill_body(directory / "SKILL.md")
                self.assertLessEqual(len(body), MAX_LINKED_LEAF_BODY_CHARS)
                detail = directory / "TECHNIQUE_REFERENCE.md"
                if detail.is_file():
                    self.assertIsNotNone(_DETAIL_REFERENCE_LINK.search(body))

    def test_every_companion_markdown_is_explicitly_linked_and_managed(self) -> None:
        for skill in sorted(_skill_directories()):
            directory = SKILLS_ROOT / skill
            body = _skill_body(directory / "SKILL.md")
            for resource in sorted(directory.glob("*.md")):
                if resource.name == "SKILL.md":
                    continue
                with self.subTest(skill=skill, resource=resource.name):
                    link = re.compile(
                        rf"\]\((?:\./)?{re.escape(resource.name)}(?:#[^)]*)?\)",
                        re.IGNORECASE,
                    )
                    self.assertIsNotNone(link.search(body))
                    text = resource.read_text(encoding="utf-8")
                    self.assertEqual(1, text.count(RESOURCE_START))
                    self.assertEqual(1, text.count(RESOURCE_END))
                    self.assertEqual(1, text.count("ZhiyuGo reference material only"))
                    self.assertIsNone(_CROSS_DIRECTORY_MARKDOWN_LINK.search(text))
                    has_unmanaged_h2 = re.search(r"(?m)^## (?!Contents\s*$).+", text) is not None
                    expected_toc_count = 1 if has_unmanaged_h2 else 0
                    self.assertEqual(expected_toc_count, text.count(TOC_START))
                    self.assertEqual(expected_toc_count, text.count(TOC_END))

    def test_corpus_adaptation_is_idempotent(self) -> None:
        command = [
            sys.executable,
            "-X",
            "utf8",
            "-B",
            str(REPOSITORY_ROOT / "scripts" / "adapt_skill_corpus.py"),
            "--root",
            str(SKILLS_ROOT),
            "--check",
        ]
        result = subprocess.run(
            command,
            cwd=REPOSITORY_ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
        )
        self.assertEqual(0, result.returncode, msg=result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
