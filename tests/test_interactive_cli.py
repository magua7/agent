from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from security_agent.interfaces.product_cli import _interactive, build_parser


class InteractiveCLITests(unittest.TestCase):
    def test_interactive_collects_input_and_delegates_to_shared_run(self) -> None:
        args = build_parser().parse_args(["interactive", "--settings", "private-settings.json"])
        execution = object()
        run = Mock(return_value=execution)
        answers = [
            "Analyze the authorized localhost fixture",
            "Interactive task",
            "127.0.0.1",
            "8000,8080",
            "yes",
        ]
        with (
            patch("builtins.input", side_effect=answers),
            patch("security_agent.interfaces.product_cli._run_task", run),
            patch("security_agent.interfaces.product_cli.asyncio.run", return_value=0) as runner,
        ):
            result = _interactive(args)

        self.assertEqual(0, result)
        run.assert_called_once_with(args)
        runner.assert_called_once_with(execution)
        self.assertEqual("Analyze the authorized localhost fixture", args.objective)
        self.assertEqual("Interactive task", args.title)
        self.assertEqual("127.0.0.1", args.target)
        self.assertEqual("8000,8080", args.ports)
        self.assertFalse(args.as_json)
        self.assertEqual(Path("private-settings.json"), args.settings)

    def test_interactive_refuses_to_run_without_authorization(self) -> None:
        args = build_parser().parse_args(["interactive"])
        run = Mock(return_value=object())
        answers = ["Analyze localhost", "", "", "", "no"]
        with (
            patch("builtins.input", side_effect=answers),
            patch("security_agent.interfaces.product_cli._run_task", run),
        ):
            result = _interactive(args)

        self.assertEqual(2, result)
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
