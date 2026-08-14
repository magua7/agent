"""Versioned dependency plans and verifier-gated node transitions."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from datetime import datetime
from enum import StrEnum
from typing import ClassVar

from security_agent.domain._validation import (
    merge_unique,
    require_non_blank,
    require_non_negative_int,
    require_positive_int,
    require_utc,
    string_tuple,
)
from security_agent.domain.task import TaskSpec
from security_agent.domain.utils import new_id, utc_now
from security_agent.domain.verification import VerificationResult


class PlanStatus(StrEnum):
    DRAFT = "draft"
    ACTIVE = "active"
    COMPLETED = "completed"
    FAILED = "failed"
    SUPERSEDED = "superseded"
    CANCELLED = "cancelled"


class NodeStatus(StrEnum):
    PENDING = "pending"
    READY = "ready"
    RUNNING = "running"
    BLOCKED = "blocked"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass(frozen=True, slots=True)
class PlanNode:
    """One immutable plan step whose changes are explicit transitions."""

    _TRANSITIONS: ClassVar[dict[NodeStatus, frozenset[NodeStatus]]] = {
        NodeStatus.PENDING: frozenset({NodeStatus.READY, NodeStatus.BLOCKED, NodeStatus.CANCELLED}),
        NodeStatus.READY: frozenset({NodeStatus.RUNNING, NodeStatus.BLOCKED, NodeStatus.CANCELLED}),
        NodeStatus.RUNNING: frozenset(
            {
                NodeStatus.SUCCEEDED,
                NodeStatus.FAILED,
                NodeStatus.BLOCKED,
                NodeStatus.CANCELLED,
            }
        ),
        NodeStatus.FAILED: frozenset({NodeStatus.READY, NodeStatus.BLOCKED, NodeStatus.CANCELLED}),
        NodeStatus.BLOCKED: frozenset({NodeStatus.READY, NodeStatus.CANCELLED}),
        NodeStatus.SUCCEEDED: frozenset(),
        NodeStatus.CANCELLED: frozenset(),
    }

    goal: str
    description: str
    assigned_agent: str
    required_capabilities: tuple[str, ...]
    success_criteria: tuple[str, ...]
    dependencies: tuple[str, ...] = ()
    status: NodeStatus = NodeStatus.PENDING
    attempt_count: int = 0
    max_attempts: int = 3
    evidence_ids: tuple[str, ...] = ()
    finding_ids: tuple[str, ...] = ()
    id: str = field(default_factory=new_id)
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        require_non_blank(self.id, "plan node id")
        require_non_blank(self.goal, "plan node goal")
        require_non_blank(self.description, "plan node description")
        require_non_blank(self.assigned_agent, "assigned_agent")
        if not isinstance(self.status, NodeStatus):
            raise ValueError("plan node status must be a NodeStatus")
        capabilities = string_tuple(
            self.required_capabilities,
            "required_capabilities",
            required=True,
        )
        criteria = string_tuple(
            self.success_criteria,
            "plan node success_criteria",
            required=True,
        )
        dependencies = string_tuple(self.dependencies, "plan node dependencies")
        if self.id in dependencies:
            raise ValueError("a plan node cannot depend on itself")
        require_non_negative_int(self.attempt_count, "attempt_count")
        require_positive_int(self.max_attempts, "max_attempts")
        if self.attempt_count > self.max_attempts:
            raise ValueError("attempt_count cannot exceed max_attempts")
        if self.status is NodeStatus.RUNNING and self.attempt_count == 0:
            raise ValueError("a running node must have at least one attempt")
        if self.status is NodeStatus.READY and self.attempt_count >= self.max_attempts:
            raise ValueError("an exhausted node cannot be ready")
        evidence_ids = string_tuple(self.evidence_ids, "plan node evidence_ids")
        finding_ids = string_tuple(self.finding_ids, "plan node finding_ids")
        if self.status is NodeStatus.SUCCEEDED and not evidence_ids:
            raise ValueError("a succeeded node must reference evidence")
        require_utc(self.created_at, "created_at")
        require_utc(self.updated_at, "updated_at")
        if self.updated_at < self.created_at:
            raise ValueError("updated_at cannot be earlier than created_at")
        object.__setattr__(self, "required_capabilities", capabilities)
        object.__setattr__(self, "success_criteria", criteria)
        object.__setattr__(self, "dependencies", dependencies)
        object.__setattr__(self, "evidence_ids", evidence_ids)
        object.__setattr__(self, "finding_ids", finding_ids)

    @classmethod
    def create(
        cls,
        *,
        goal: str,
        description: str,
        assigned_agent: str,
        required_capabilities: Iterable[str],
        success_criteria: Iterable[str],
        dependencies: Iterable[str] = (),
        max_attempts: int = 3,
        id: str | None = None,
        created_at: datetime | None = None,
    ) -> PlanNode:
        timestamp = utc_now() if created_at is None else created_at
        return cls(
            goal=goal,
            description=description,
            assigned_agent=assigned_agent,
            required_capabilities=tuple(required_capabilities),
            success_criteria=tuple(success_criteria),
            dependencies=tuple(dependencies),
            max_attempts=max_attempts,
            id=new_id() if id is None else id,
            created_at=timestamp,
            updated_at=timestamp,
        )

    @property
    def is_terminal(self) -> bool:
        return self.status in {NodeStatus.SUCCEEDED, NodeStatus.CANCELLED}

    @property
    def attempts_remaining(self) -> int:
        return self.max_attempts - self.attempt_count

    def transition(
        self,
        target: NodeStatus,
        *,
        verification: VerificationResult | None = None,
        at: datetime | None = None,
    ) -> PlanNode:
        """Return a node in ``target`` while enforcing its transition graph.

        Entering ``running`` is the single place that increments attempts.
        Entering ``succeeded`` additionally requires a successful independent
        verification result whose evidence is already linked to the node.
        """
        if not isinstance(target, NodeStatus):
            raise ValueError("target must be a NodeStatus")
        if target not in self._TRANSITIONS[self.status]:
            raise ValueError(f"invalid node transition: {self.status.value} -> {target.value}")
        if target is NodeStatus.RUNNING and self.attempt_count >= self.max_attempts:
            raise ValueError("node has exhausted max_attempts")
        if target is NodeStatus.READY and self.attempt_count >= self.max_attempts:
            raise ValueError("an exhausted node cannot be made ready")
        if target is NodeStatus.SUCCEEDED:
            if verification is None or not verification.success:
                raise ValueError("succeeded requires a successful VerificationResult")
            if not self.evidence_ids or not verification.evidence_ids:
                raise ValueError("succeeded requires verifier-confirmed node evidence")
            if not set(verification.evidence_ids).issubset(self.evidence_ids):
                raise ValueError("verification references evidence not linked to the node")
        timestamp = at or utc_now()
        require_utc(timestamp, "transition timestamp")
        if timestamp < self.updated_at:
            raise ValueError("transition timestamp cannot move backwards")
        attempt_count = self.attempt_count + (1 if target is NodeStatus.RUNNING else 0)
        return replace(self, status=target, attempt_count=attempt_count, updated_at=timestamp)

    def transition_to(
        self,
        target: NodeStatus,
        *,
        verification: VerificationResult | None = None,
        at: datetime | None = None,
    ) -> PlanNode:
        return self.transition(target, verification=verification, at=at)

    def add_evidence(self, *evidence_ids: str, at: datetime | None = None) -> PlanNode:
        timestamp = at or utc_now()
        require_utc(timestamp, "evidence link timestamp")
        if timestamp < self.updated_at:
            raise ValueError("evidence link timestamp cannot move backwards")
        return replace(
            self,
            evidence_ids=merge_unique(self.evidence_ids, evidence_ids, "plan node evidence_ids"),
            updated_at=timestamp,
        )

    def add_findings(self, *finding_ids: str, at: datetime | None = None) -> PlanNode:
        timestamp = at or utc_now()
        require_utc(timestamp, "finding link timestamp")
        if timestamp < self.updated_at:
            raise ValueError("finding link timestamp cannot move backwards")
        return replace(
            self,
            finding_ids=merge_unique(self.finding_ids, finding_ids, "plan node finding_ids"),
            updated_at=timestamp,
        )


@dataclass(frozen=True, slots=True)
class Plan:
    """A structurally valid, versioned DAG."""

    _TRANSITIONS: ClassVar[dict[PlanStatus, frozenset[PlanStatus]]] = {
        PlanStatus.DRAFT: frozenset({PlanStatus.ACTIVE, PlanStatus.FAILED, PlanStatus.CANCELLED}),
        PlanStatus.ACTIVE: frozenset(
            {
                PlanStatus.COMPLETED,
                PlanStatus.FAILED,
                PlanStatus.SUPERSEDED,
                PlanStatus.CANCELLED,
            }
        ),
        PlanStatus.COMPLETED: frozenset(),
        PlanStatus.FAILED: frozenset(),
        PlanStatus.SUPERSEDED: frozenset(),
        PlanStatus.CANCELLED: frozenset(),
    }

    task_id: str
    nodes: tuple[PlanNode, ...]
    version: int = 1
    status: PlanStatus = PlanStatus.DRAFT
    id: str = field(default_factory=new_id)
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        require_non_blank(self.id, "plan id")
        require_non_blank(self.task_id, "plan task_id")
        require_positive_int(self.version, "plan version")
        if not isinstance(self.status, PlanStatus):
            raise ValueError("plan status must be a PlanStatus")
        nodes = tuple(self.nodes)
        if not nodes:
            raise ValueError("a plan must contain at least one node")
        if not all(isinstance(node, PlanNode) for node in nodes):
            raise ValueError("plan nodes must contain only PlanNode values")
        self._validate_graph(nodes)
        require_utc(self.created_at, "created_at")
        require_utc(self.updated_at, "updated_at")
        if self.updated_at < self.created_at:
            raise ValueError("updated_at cannot be earlier than created_at")
        object.__setattr__(self, "nodes", nodes)

    @classmethod
    def create(
        cls,
        *,
        task_id: str,
        nodes: Iterable[PlanNode],
        version: int = 1,
        id: str | None = None,
        created_at: datetime | None = None,
    ) -> Plan:
        timestamp = utc_now() if created_at is None else created_at
        return cls(
            task_id=task_id,
            nodes=tuple(nodes),
            version=version,
            id=new_id() if id is None else id,
            created_at=timestamp,
            updated_at=timestamp,
        )

    @staticmethod
    def _validate_graph(nodes: tuple[PlanNode, ...]) -> None:
        node_ids = tuple(node.id for node in nodes)
        if len(node_ids) != len(set(node_ids)):
            raise ValueError("plan node IDs must be unique")
        known_ids = set(node_ids)
        for node in nodes:
            missing = set(node.dependencies) - known_ids
            if missing:
                raise ValueError(f"node {node.id!r} has missing dependencies: {sorted(missing)!r}")

        dependencies = {node.id: node.dependencies for node in nodes}
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(node_id: str) -> None:
            if node_id in visiting:
                raise ValueError("plan dependency graph must be acyclic")
            if node_id in visited:
                return
            visiting.add(node_id)
            for dependency_id in dependencies[node_id]:
                visit(dependency_id)
            visiting.remove(node_id)
            visited.add(node_id)

        for node_id in node_ids:
            visit(node_id)

        by_id = {node.id: node for node in nodes}
        dependency_satisfied_states = {
            NodeStatus.READY,
            NodeStatus.RUNNING,
            NodeStatus.SUCCEEDED,
            NodeStatus.FAILED,
        }
        for node in nodes:
            if node.status in dependency_satisfied_states and any(
                by_id[dependency].status is not NodeStatus.SUCCEEDED
                for dependency in node.dependencies
            ):
                raise ValueError(
                    f"node {node.id!r} cannot be {node.status.value} before its dependencies succeed"
                )

    def validate_success_criteria(self, criteria: Iterable[str]) -> None:
        required = string_tuple(criteria, "task success_criteria", required=True)
        covered = {criterion for node in self.nodes for criterion in node.success_criteria}
        missing = tuple(criterion for criterion in required if criterion not in covered)
        if missing:
            raise ValueError(f"plan does not cover task success criteria: {missing!r}")

    def validate_for_task(self, task: TaskSpec) -> None:
        if not isinstance(task, TaskSpec):
            raise ValueError("task must be a TaskSpec")
        if task.id != self.task_id:
            raise ValueError("plan task_id does not match task id")
        self.validate_success_criteria(task.success_criteria)

    def activate(
        self,
        task_or_criteria: TaskSpec | Iterable[str],
        *,
        at: datetime | None = None,
    ) -> Plan:
        if self.status is not PlanStatus.DRAFT:
            raise ValueError("only a draft plan can be activated")
        if isinstance(task_or_criteria, TaskSpec):
            self.validate_for_task(task_or_criteria)
        else:
            self.validate_success_criteria(task_or_criteria)
        timestamp = at or utc_now()
        require_utc(timestamp, "activation timestamp")
        if timestamp < self.updated_at:
            raise ValueError("activation timestamp cannot move backwards")
        nodes = tuple(
            node.transition(NodeStatus.READY, at=timestamp)
            if node.status is NodeStatus.PENDING and not node.dependencies
            else node
            for node in self.nodes
        )
        return replace(self, status=PlanStatus.ACTIVE, nodes=nodes, updated_at=timestamp)

    def transition(self, target: PlanStatus, *, at: datetime | None = None) -> Plan:
        if not isinstance(target, PlanStatus):
            raise ValueError("target must be a PlanStatus")
        if target not in self._TRANSITIONS[self.status]:
            raise ValueError(f"invalid plan transition: {self.status.value} -> {target.value}")
        if target is PlanStatus.ACTIVE:
            raise ValueError("activate() requires task success criteria")
        if target is PlanStatus.COMPLETED and not self.all_succeeded:
            raise ValueError("a plan cannot complete while nodes are unfinished")
        timestamp = at or utc_now()
        require_utc(timestamp, "transition timestamp")
        if timestamp < self.updated_at:
            raise ValueError("transition timestamp cannot move backwards")
        return replace(self, status=target, updated_at=timestamp)

    def refresh_readiness(self, *, at: datetime | None = None) -> Plan:
        """Promote pending nodes whose dependencies have all succeeded."""
        if self.status is not PlanStatus.ACTIVE:
            raise ValueError("readiness can only be refreshed on an active plan")
        by_id = {node.id: node for node in self.nodes}
        timestamp = at or utc_now()
        require_utc(timestamp, "readiness timestamp")
        if timestamp < self.updated_at:
            raise ValueError("readiness timestamp cannot move backwards")
        changed = False
        refreshed: list[PlanNode] = []
        for node in self.nodes:
            if node.status is NodeStatus.PENDING and all(
                by_id[dependency].status is NodeStatus.SUCCEEDED for dependency in node.dependencies
            ):
                node = node.transition(NodeStatus.READY, at=timestamp)
                changed = True
            refreshed.append(node)
        if not changed:
            return self
        return replace(self, nodes=tuple(refreshed), updated_at=timestamp)

    def get_node(self, node_id: str) -> PlanNode:
        require_non_blank(node_id, "node_id")
        for node in self.nodes:
            if node.id == node_id:
                return node
        raise KeyError(node_id)

    def replace_node(self, node: PlanNode, *, at: datetime | None = None) -> Plan:
        if not isinstance(node, PlanNode):
            raise ValueError("node must be a PlanNode")
        previous = self.get_node(node.id)
        static_fields = (
            "goal",
            "description",
            "assigned_agent",
            "required_capabilities",
            "success_criteria",
            "dependencies",
            "max_attempts",
            "created_at",
        )
        if any(getattr(previous, name) != getattr(node, name) for name in static_fields):
            raise ValueError("structural node changes require a new plan version")
        timestamp = at or utc_now()
        require_utc(timestamp, "node replacement timestamp")
        if timestamp < max(self.updated_at, node.updated_at):
            raise ValueError("node replacement timestamp cannot move backwards")
        nodes = tuple(node if candidate.id == node.id else candidate for candidate in self.nodes)
        return replace(self, nodes=nodes, updated_at=timestamp)

    def revise(
        self,
        nodes: Iterable[PlanNode],
        *,
        at: datetime | None = None,
    ) -> Plan:
        """Create the next draft version without mutating this historic version."""
        timestamp = at or utc_now()
        require_utc(timestamp, "revision timestamp")
        if timestamp < self.updated_at:
            raise ValueError("revision timestamp cannot move backwards")
        return Plan(
            task_id=self.task_id,
            nodes=tuple(nodes),
            version=self.version + 1,
            status=PlanStatus.DRAFT,
            id=self.id,
            created_at=timestamp,
            updated_at=timestamp,
        )

    @property
    def ready_nodes(self) -> tuple[PlanNode, ...]:
        return tuple(node for node in self.nodes if node.status is NodeStatus.READY)

    @property
    def all_succeeded(self) -> bool:
        return bool(self.nodes) and all(node.status is NodeStatus.SUCCEEDED for node in self.nodes)
