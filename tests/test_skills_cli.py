from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any

from security_agent.interfaces.cli import main

ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "skills"


class SkillsCLITests(unittest.TestCase):
    def test_catalog_root_must_be_explicit(self) -> None:
        stderr = io.StringIO()
        with redirect_stderr(stderr), self.assertRaises(SystemExit) as raised:
            main(("skills", "list"))

        self.assertEqual(2, raised.exception.code)
        self.assertIn("--root", stderr.getvalue())

    def test_list_reports_the_complete_non_white_box_catalog(self) -> None:
        code, payload, _error = _run_cli("skills", "list", "--root", str(SKILLS))

        self.assertEqual(0, code)
        self.assertEqual(106, payload["count"])
        names = {item["name"] for item in payload["skills"]}
        self.assertIn("traffic-analysis-pcap", names)
        self.assertNotIn("php-audit-skills", names)

    def test_enabled_only_lists_the_runtime_safe_subset(self) -> None:
        code, payload, _error = _run_cli(
            "skills",
            "list",
            "--root",
            str(SKILLS),
            "--enabled-only",
        )

        self.assertEqual(0, code)
        self.assertEqual(20, payload["count"])
        self.assertTrue(all(item["policy"]["enabled"] for item in payload["skills"]))

    def test_doctor_accepts_the_project_catalog(self) -> None:
        code, payload, _error = _run_cli("skills", "doctor", "--root", str(SKILLS), "--strict")

        self.assertEqual(0, code)
        self.assertEqual(106, payload["valid_skills"])
        self.assertEqual(0, payload["errors"])
        self.assertEqual(0, payload["warnings"])

    def test_recommend_ranks_an_enabled_forensics_skill(self) -> None:
        code, payload, _error = _run_cli(
            "skills",
            "recommend",
            "--root",
            str(SKILLS),
            "--task-type",
            "ctf",
            "--max-results",
            "2",
            "Analyze the authorized PCAP network capture",
        )

        self.assertEqual(0, code)
        names = [item["name"] for item in payload["skills"]]
        self.assertEqual("traffic-analysis-pcap", names[0])
        self.assertNotIn("stack-overflow-and-rop", names)

    def test_recommend_handles_simple_plural_forms(self) -> None:
        code, payload, _error = _run_cli(
            "skills",
            "recommend",
            "--root",
            str(SKILLS),
            "--task-type",
            "pentest",
            "Inspect authorized localhost services",
        )

        self.assertEqual(0, code)
        names = [item["name"] for item in payload["skills"]]
        self.assertEqual("local-service-discovery", names[0])

    def test_lab_body_requires_two_explicit_inspection_flags(self) -> None:
        arguments = (
            "skills",
            "show",
            "--root",
            str(SKILLS),
            "stack-overflow-and-rop",
            "--body",
        )

        denied, _payload, error = _run_cli(*arguments)
        allowed, payload, _error = _run_cli(
            *arguments,
            "--allow-disabled",
            "--allow-lab-only",
        )

        self.assertEqual(2, denied)
        self.assertIn("--allow-disabled", error["error"])
        self.assertIn("--allow-lab-only", error["error"])
        self.assertEqual(0, allowed)
        self.assertTrue(payload["body"]["untrusted_guidance"])

    def test_doctor_isolates_a_broken_skill_and_returns_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "policy.json").write_text(
                json.dumps({"schema_version": 1, "groups": [], "excluded": []}),
                encoding="utf-8",
            )
            broken = root / "broken"
            broken.mkdir()
            (broken / "SKILL.md").write_text("no frontmatter", encoding="utf-8")

            code, payload, _error = _run_cli("skills", "doctor", "--root", str(root))

        self.assertEqual(2, code)
        self.assertEqual(1, payload["errors"])
        self.assertEqual(0, payload["valid_skills"])

    def test_lab_resource_requires_two_explicit_inspection_flags(self) -> None:
        arguments = (
            "skills",
            "resource",
            "--root",
            str(SKILLS),
            "stack-overflow-and-rop",
            "ROP_ADVANCED_TECHNIQUES.md",
        )

        denied, _payload, error = _run_cli(*arguments)
        allowed, payload, _error = _run_cli(
            *arguments,
            "--allow-disabled",
            "--allow-lab-only",
        )

        self.assertEqual(2, denied)
        self.assertIn("disabled", error["error"])
        self.assertEqual(0, allowed)
        self.assertEqual("stack-overflow-and-rop", payload["skill"])
        self.assertTrue(payload["content"])


def _run_cli(*arguments: str) -> tuple[int, Any, Any]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = main(arguments)
    output = json.loads(stdout.getvalue()) if stdout.getvalue() else {}
    error = json.loads(stderr.getvalue()) if stderr.getvalue() else {}
    assert isinstance(output, dict)
    assert isinstance(error, dict)
    return code, output, error


if __name__ == "__main__":
    unittest.main()
