from __future__ import annotations

import ast
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "src" / "security_agent"


class ArchitectureTests(unittest.TestCase):
    def test_domain_has_no_outward_imports(self) -> None:
        violations = _find_forbidden_imports(
            PACKAGE / "domain",
            forbidden_prefixes=(
                "security_agent.contracts",
                "security_agent.engine",
                "security_agent.infrastructure",
                "security_agent.interfaces",
                "httpx",
                "fastapi",
                "mcp",
            ),
        )
        self.assertEqual([], violations)

    def test_engine_has_no_adapter_or_ui_imports(self) -> None:
        engine = PACKAGE / "engine"
        if not engine.exists():
            self.skipTest("engine package not created yet")
        violations = _find_forbidden_imports(
            engine,
            forbidden_prefixes=(
                "security_agent.infrastructure",
                "security_agent.interfaces",
                "httpx",
                "fastapi",
                "mcp",
            ),
        )
        self.assertEqual([], violations)

    def test_core_dependency_list_is_small(self) -> None:
        with (ROOT / "pyproject.toml").open("rb") as handle:
            project = tomllib.load(handle)["project"]
        self.assertEqual(["httpx>=0.27,<1"], project["dependencies"])

    def test_supported_python_is_311_or_newer(self) -> None:
        with (ROOT / "pyproject.toml").open("rb") as handle:
            project = tomllib.load(handle)["project"]
        self.assertEqual(">=3.11", project["requires-python"])


def _find_forbidden_imports(
    directory: Path,
    *,
    forbidden_prefixes: tuple[str, ...],
) -> list[str]:
    violations: list[str] = []
    for path in sorted(directory.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            modules: list[str] = []
            if isinstance(node, ast.Import):
                modules.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules.append(node.module)
            for module in modules:
                if module.startswith(forbidden_prefixes):
                    relative = path.relative_to(ROOT)
                    violations.append(f"{relative}:{getattr(node, 'lineno', 0)} imports {module}")
    return violations


if __name__ == "__main__":
    unittest.main()
