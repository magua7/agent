from __future__ import annotations

import unittest

from security_agent.domain import TaskType
from security_agent.engine import TaskInterpreter


class TaskInterpreterTests(unittest.TestCase):
    def test_infers_ctf_before_general_security_categories(self) -> None:
        task = TaskInterpreter().interpret("Solve this CTF challenge and recover the flag")

        self.assertIs(task.task_type, TaskType.CTF)
        self.assertEqual(
            ("Produce a reproducible, tool-evidenced solution for the challenge",),
            task.success_criteria,
        )


if __name__ == "__main__":
    unittest.main()
