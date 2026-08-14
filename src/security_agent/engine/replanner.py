"""Auditable versioned retry/replanning strategy."""

from __future__ import annotations

from security_agent.contracts import ReplanReason
from security_agent.domain import NodeStatus, Plan, PlanNode, TaskSpec


class VersionedReplanner:
    """Create a new plan version for a bounded retry when one is safe."""

    async def replan(
        self,
        task: TaskSpec,
        plan: Plan,
        failed_node: PlanNode | None,
        reason: ReplanReason,
    ) -> Plan | None:
        del reason
        if failed_node is None or failed_node.attempts_remaining <= 0:
            return None
        current = plan.get_node(failed_node.id)
        if current.status is NodeStatus.RUNNING:
            current = current.transition(NodeStatus.FAILED)
        if current.status not in {NodeStatus.FAILED, NodeStatus.BLOCKED}:
            return None
        retry = current.transition(NodeStatus.READY)
        nodes = tuple(retry if node.id == retry.id else node for node in plan.nodes)
        return plan.revise(nodes).activate(task)
