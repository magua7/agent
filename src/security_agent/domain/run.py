"""Run-local state and verifier-gated run transitions."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime
from enum import StrEnum
from typing import ClassVar

from security_agent.domain._validation import (
    require_non_blank,
    require_non_negative_int,
    require_utc,
    string_tuple,
)
from security_agent.domain.evidence import Evidence
from security_agent.domain.finding import Finding, FindingStatus
from security_agent.domain.plan import Plan, PlanStatus
from security_agent.domain.task import TaskSpec
from security_agent.domain.utils import new_id, utc_now
from security_agent.domain.verification import VerificationResult


class RunStatus(StrEnum):
    CREATED = "created"
    PLANNING = "planning"
    RUNNING = "running"
    VERIFYING = "verifying"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass(frozen=True, slots=True)
class RunState:
    """All mutable-looking execution state scoped to one immutable value."""

    _TRANSITIONS: ClassVar[dict[RunStatus, frozenset[RunStatus]]] = {
        RunStatus.CREATED: frozenset({RunStatus.PLANNING, RunStatus.FAILED, RunStatus.CANCELLED}),
        RunStatus.PLANNING: frozenset({RunStatus.RUNNING, RunStatus.FAILED, RunStatus.CANCELLED}),
        RunStatus.RUNNING: frozenset(
            {
                RunStatus.PLANNING,
                RunStatus.VERIFYING,
                RunStatus.FAILED,
                RunStatus.CANCELLED,
            }
        ),
        RunStatus.VERIFYING: frozenset(
            {
                RunStatus.PLANNING,
                RunStatus.RUNNING,
                RunStatus.COMPLETED,
                RunStatus.FAILED,
                RunStatus.CANCELLED,
            }
        ),
        RunStatus.COMPLETED: frozenset(),
        RunStatus.FAILED: frozenset(),
        RunStatus.CANCELLED: frozenset(),
    }

    task: TaskSpec
    plan: Plan | None = None
    status: RunStatus = RunStatus.CREATED
    current_nodes: tuple[str, ...] = ()
    findings: tuple[Finding, ...] = ()
    evidence: tuple[Evidence, ...] = ()
    run_id: str = field(default_factory=new_id)
    started_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)
    finished_at: datetime | None = None
    step_count: int = 0
    replan_count: int = 0
    last_error: str | None = None

    def __post_init__(self) -> None:
        require_non_blank(self.run_id, "run_id")
        if not isinstance(self.task, TaskSpec):
            raise ValueError("run task must be a TaskSpec")
        if not isinstance(self.status, RunStatus):
            raise ValueError("run status must be a RunStatus")
        if self.plan is not None:
            if not isinstance(self.plan, Plan):
                raise ValueError("run plan must be a Plan or None")
            if self.plan.task_id != self.task.id:
                raise ValueError("run plan does not belong to the run task")
        current_nodes = string_tuple(self.current_nodes, "current_nodes")
        if current_nodes and self.plan is None:
            raise ValueError("current_nodes require a plan")
        if self.plan is not None:
            unknown_nodes = set(current_nodes) - {node.id for node in self.plan.nodes}
            if unknown_nodes:
                raise ValueError(f"current_nodes contains unknown node IDs: {unknown_nodes!r}")

        evidence = tuple(self.evidence)
        if not all(isinstance(item, Evidence) for item in evidence):
            raise ValueError("run evidence must contain only Evidence values")
        evidence_ids = tuple(item.id for item in evidence)
        if len(evidence_ids) != len(set(evidence_ids)):
            raise ValueError("run evidence IDs must be unique")
        if any(item.run_id != self.run_id for item in evidence):
            raise ValueError("all evidence must belong to this run")

        findings = tuple(self.findings)
        if not all(isinstance(item, Finding) for item in findings):
            raise ValueError("run findings must contain only Finding values")
        finding_ids = tuple(item.id for item in findings)
        if len(finding_ids) != len(set(finding_ids)):
            raise ValueError("run finding IDs must be unique")
        if any(item.run_id != self.run_id for item in findings):
            raise ValueError("all findings must belong to this run")
        evidence_by_id = {item.id: item for item in evidence}
        for finding in findings:
            if finding.status is FindingStatus.VERIFIED:
                self._validate_verified_finding(finding, evidence_by_id)

        require_utc(self.started_at, "started_at")
        require_utc(self.updated_at, "updated_at")
        if self.updated_at < self.started_at:
            raise ValueError("updated_at cannot be earlier than started_at")
        terminal = self.status in {
            RunStatus.COMPLETED,
            RunStatus.FAILED,
            RunStatus.CANCELLED,
        }
        if terminal != (self.finished_at is not None):
            raise ValueError("finished_at must be set exactly for terminal run states")
        if self.finished_at is not None:
            require_utc(self.finished_at, "finished_at")
            if self.finished_at < self.updated_at:
                raise ValueError("finished_at cannot be earlier than updated_at")
        if self.status is RunStatus.COMPLETED:
            if self.plan is None or not self.plan.all_succeeded:
                raise ValueError("a completed run requires a fully succeeded plan")
            if self.plan.status is not PlanStatus.COMPLETED:
                raise ValueError("a completed run requires a completed plan")
        require_non_negative_int(self.step_count, "step_count")
        require_non_negative_int(self.replan_count, "replan_count")
        if self.last_error is not None:
            require_non_blank(self.last_error, "last_error")
        if self.status is RunStatus.FAILED and self.last_error is None:
            raise ValueError("a failed run must record last_error")
        object.__setattr__(self, "current_nodes", current_nodes)
        object.__setattr__(self, "findings", findings)
        object.__setattr__(self, "evidence", evidence)

    @staticmethod
    def _validate_verified_finding(
        finding: Finding,
        evidence_by_id: dict[str, Evidence],
    ) -> None:
        missing = set(finding.evidence_ids) - evidence_by_id.keys()
        if missing:
            raise ValueError(f"verified finding has dangling evidence IDs: {missing!r}")
        if any(evidence_by_id[item].action_id is None for item in finding.evidence_ids):
            raise ValueError("verified finding evidence must originate from real actions")

    @classmethod
    def create(
        cls,
        task: TaskSpec,
        plan: Plan | None = None,
        *,
        run_id: str | None = None,
        started_at: datetime | None = None,
    ) -> RunState:
        timestamp = utc_now() if started_at is None else started_at
        return cls(
            task=task,
            plan=plan,
            run_id=new_id() if run_id is None else run_id,
            started_at=timestamp,
            updated_at=timestamp,
        )

    @property
    def is_terminal(self) -> bool:
        return self.status in {
            RunStatus.COMPLETED,
            RunStatus.FAILED,
            RunStatus.CANCELLED,
        }

    def transition(
        self,
        target: RunStatus,
        *,
        verification: VerificationResult | None = None,
        error: str | None = None,
        at: datetime | None = None,
    ) -> RunState:
        if not isinstance(target, RunStatus):
            raise ValueError("target must be a RunStatus")
        if target not in self._TRANSITIONS[self.status]:
            raise ValueError(f"invalid run transition: {self.status.value} -> {target.value}")
        timestamp = at or utc_now()
        require_utc(timestamp, "transition timestamp")
        if timestamp < self.updated_at:
            raise ValueError("transition timestamp cannot move backwards")
        if target is RunStatus.RUNNING:
            if self.plan is None or self.plan.status is not PlanStatus.ACTIVE:
                raise ValueError("a run requires an active plan before execution")

        plan = self.plan
        if target is RunStatus.COMPLETED:
            if self.status is not RunStatus.VERIFYING:
                raise ValueError("completed is reachable only from verifying")
            if verification is None or not verification.success:
                raise ValueError("completed requires a successful VerificationResult")
            if plan is None or not plan.all_succeeded:
                raise ValueError("completed requires every plan node to have succeeded")
            if not verification.evidence_ids:
                raise ValueError("completed verification must cite evidence")
            evidence_by_id = {item.id: item for item in self.evidence}
            missing = set(verification.evidence_ids) - evidence_by_id.keys()
            if missing:
                raise ValueError(f"verification has dangling evidence IDs: {missing!r}")
            if any(evidence_by_id[item].action_id is None for item in verification.evidence_ids):
                raise ValueError("completion evidence must originate from real actions")
            if plan.status is PlanStatus.ACTIVE:
                plan = plan.transition(PlanStatus.COMPLETED, at=timestamp)
            elif plan.status is not PlanStatus.COMPLETED:
                raise ValueError("completed requires an active or completed plan")

        finished_at = (
            timestamp
            if target in {RunStatus.COMPLETED, RunStatus.FAILED, RunStatus.CANCELLED}
            else None
        )
        last_error = self.last_error
        if target is RunStatus.FAILED:
            require_non_blank(error or "", "run failure error")
            last_error = error
        elif error is not None:
            require_non_blank(error, "run error")
            last_error = error
        return replace(
            self,
            status=target,
            plan=plan,
            updated_at=timestamp,
            finished_at=finished_at,
            last_error=last_error,
        )

    def with_plan(self, plan: Plan, *, at: datetime | None = None) -> RunState:
        if not isinstance(plan, Plan):
            raise ValueError("plan must be a Plan")
        if plan.task_id != self.task.id:
            raise ValueError("plan does not belong to the run task")
        replanned = False
        if self.plan is not None:
            if plan.id != self.plan.id:
                raise ValueError("plan revisions must retain the stable plan id")
            if plan.version < self.plan.version:
                raise ValueError("a run cannot move to an older plan version")
            replanned = plan.version > self.plan.version
        timestamp = at or utc_now()
        self._validate_update_timestamp(timestamp)
        return replace(
            self,
            plan=plan,
            current_nodes=(),
            replan_count=self.replan_count + (1 if replanned else 0),
            updated_at=timestamp,
        )

    def with_current_nodes(
        self,
        *node_ids: str,
        at: datetime | None = None,
    ) -> RunState:
        timestamp = at or utc_now()
        self._validate_update_timestamp(timestamp)
        return replace(self, current_nodes=node_ids, updated_at=timestamp)

    def add_evidence(self, evidence: Evidence, *, at: datetime | None = None) -> RunState:
        if not isinstance(evidence, Evidence):
            raise ValueError("evidence must be Evidence")
        if evidence.run_id != self.run_id:
            raise ValueError("evidence belongs to a different run")
        for existing in self.evidence:
            if existing.id == evidence.id:
                if existing != evidence:
                    raise ValueError("conflicting evidence uses an existing id")
                return self
        timestamp = at or utc_now()
        self._validate_update_timestamp(timestamp)
        return replace(self, evidence=(*self.evidence, evidence), updated_at=timestamp)

    def add_finding(self, finding: Finding, *, at: datetime | None = None) -> RunState:
        if not isinstance(finding, Finding):
            raise ValueError("finding must be Finding")
        if finding.run_id != self.run_id:
            raise ValueError("finding belongs to a different run")
        if finding.status is FindingStatus.VERIFIED:
            self._validate_verified_finding(
                finding,
                {item.id: item for item in self.evidence},
            )
        for existing in self.findings:
            if existing.id == finding.id:
                if existing != finding:
                    raise ValueError("conflicting finding uses an existing id")
                return self
        timestamp = at or utc_now()
        self._validate_update_timestamp(timestamp)
        return replace(self, findings=(*self.findings, finding), updated_at=timestamp)

    def increment_step(self, *, at: datetime | None = None) -> RunState:
        timestamp = at or utc_now()
        self._validate_update_timestamp(timestamp)
        return replace(self, step_count=self.step_count + 1, updated_at=timestamp)

    def _validate_update_timestamp(self, timestamp: datetime) -> None:
        require_utc(timestamp, "update timestamp")
        if timestamp < self.updated_at:
            raise ValueError("update timestamp cannot move backwards")
