"""Independent hard verification of action provenance and completion."""

from __future__ import annotations

from security_agent.contracts import RunRepository
from security_agent.domain import (
    ActionRecord,
    Evidence,
    FindingDraft,
    FindingStatus,
    NodeStatus,
    Observation,
    PlanNode,
    PlanStatus,
    RunState,
    Severity,
    VerificationResult,
)


class EvidenceVerifier:
    def __init__(self, run_repository: RunRepository) -> None:
        self._runs = run_repository

    async def verify_node(
        self,
        run_id: str,
        node: PlanNode,
        action: ActionRecord,
        evidence: Evidence,
        observation: Observation,
    ) -> VerificationResult:
        missing: list[str] = []
        if action.run_id != run_id or evidence.run_id != run_id:
            missing.append("action and evidence must belong to the current run")
        if action.plan_node_id != node.id:
            missing.append("action must belong to the current plan node")
        if action.success is not True:
            missing.append("a successful tool action is required")
        if not action.is_finished:
            missing.append("the tool action is unfinished")
        if evidence.action_id != action.id:
            missing.append("evidence must link to the real tool action")
        if evidence.id not in action.evidence_ids or evidence.id not in node.evidence_ids:
            missing.append("action and node must both reference the evidence")
        if evidence.source != f"tool:{action.tool_name}":
            missing.append("evidence source does not match the executed tool")
        if evidence.metadata.get("provenance") != "tool_execution":
            missing.append("evidence lacks tool-execution provenance")
        if evidence.metadata.get("tool_success") is not True:
            missing.append("evidence does not record a successful tool result")
        if not evidence.verify_hash():
            missing.append("evidence content hash is invalid")

        expected = set(node.success_criteria)
        assessments = {item.criterion: item for item in observation.criterion_assessments}
        missing.extend(
            f"missing criterion assessment: {item}"
            for item in sorted(expected - assessments.keys())
        )
        unknown = set(assessments) - expected
        missing.extend(f"unknown criterion assessment: {item}" for item in sorted(unknown))
        for criterion in node.success_criteria:
            assessment = assessments.get(criterion)
            if assessment is None:
                continue
            if not assessment.satisfied:
                missing.append(f"criterion was not satisfied: {criterion}")
            if evidence.id not in assessment.evidence_ids:
                missing.append(f"criterion lacks current evidence: {criterion}")
            if not set(assessment.evidence_ids).issubset(node.evidence_ids):
                missing.append(f"criterion cites evidence outside the node: {criterion}")
        for draft in observation.finding_drafts:
            if not draft.evidence_ids:
                missing.append(f"finding draft lacks evidence: {draft.title}")
            if evidence.id not in draft.evidence_ids:
                missing.append(f"finding draft lacks current evidence: {draft.title}")
            if not set(draft.evidence_ids).issubset(node.evidence_ids):
                missing.append(f"finding draft cites evidence outside the node: {draft.title}")

        if missing:
            return VerificationResult.rejected(
                "Node verification rejected.",
                evidence_ids=(evidence.id,),
                missing_requirements=tuple(dict.fromkeys(missing)),
            )
        return VerificationResult.accepted(
            "Every node criterion is backed by a successful, integrity-checked tool action.",
            (evidence.id,),
        )

    async def verify_finding(
        self,
        run_id: str,
        node: PlanNode,
        action: ActionRecord,
        evidence: Evidence,
        draft: FindingDraft,
    ) -> VerificationResult:
        """Independently corroborate supported finding shapes.

        The MVP grants verified status only to the deterministic network-scan
        statement it can reconstruct from typed tool metadata. Other agent or
        model interpretations remain explicitly unverified.
        """

        missing: list[str] = []
        if action.run_id != run_id or evidence.run_id != run_id:
            missing.append("finding provenance belongs to another run")
        if action.plan_node_id != node.id or evidence.action_id != action.id:
            missing.append("finding provenance is not bound to the current node action")
        if action.success is not True or evidence.metadata.get("tool_success") is not True:
            missing.append("finding requires a successful tool result")
        if evidence.id not in draft.evidence_ids or not evidence.verify_hash():
            missing.append("finding must cite intact current evidence")

        capability = evidence.metadata.get("capability")
        tool_metadata = evidence.metadata.get("tool_metadata")
        if capability != "network.scan" or not isinstance(tool_metadata, dict):
            missing.append("no independent semantic verifier exists for this finding capability")
        else:
            target = tool_metadata.get("target")
            raw_ports = tool_metadata.get("open_ports")
            ports = (
                sorted(
                    item
                    for item in raw_ports
                    if isinstance(item, int) and not isinstance(item, bool)
                )
                if isinstance(raw_ports, list)
                else []
            )
            if not isinstance(target, str) or not target or not ports:
                missing.append("network finding metadata has no target/open ports")
            else:
                ports_text = ", ".join(str(port) for port in ports)
                expected = (
                    f"Open TCP services observed on {target}",
                    f"The scanner observed open TCP port(s): {ports_text}.",
                    target,
                )
                proposed = (draft.title, draft.description, draft.subject)
                if proposed != expected:
                    missing.append("network finding text does not match tool metadata")
                if draft.severity is not Severity.INFORMATIONAL or draft.confidence != 1.0:
                    missing.append("network finding severity/confidence is not corroborated")

        if missing:
            return VerificationResult.rejected(
                "Finding verification rejected.",
                evidence_ids=(evidence.id,),
                missing_requirements=tuple(dict.fromkeys(missing)),
            )
        return VerificationResult.accepted(
            "Finding was reconstructed from typed network-scan metadata.",
            (evidence.id,),
        )

    async def verify_run(self, state: RunState) -> VerificationResult:
        missing: list[str] = []
        conflicts: list[str] = []
        if state.plan is None:
            return VerificationResult.rejected(
                "Run has no plan.",
                missing_requirements=("a plan is required",),
            )
        plan = state.plan
        if plan.status not in {PlanStatus.ACTIVE, PlanStatus.COMPLETED}:
            missing.append("plan must be active or completed")
        incomplete = [node.id for node in plan.nodes if node.status is not NodeStatus.SUCCEEDED]
        missing.extend(f"unfinished plan node: {node_id}" for node_id in incomplete)
        covered = {
            criterion
            for node in plan.nodes
            if node.status is NodeStatus.SUCCEEDED
            for criterion in node.success_criteria
        }
        missing.extend(
            f"uncovered task criterion: {criterion}"
            for criterion in state.task.success_criteria
            if criterion not in covered
        )

        evidence_by_id = {item.id: item for item in state.evidence}
        actions = await self._runs.list_actions(state.run_id)
        actions_by_id = {item.id: item for item in actions}
        valid_evidence: set[str] = set()
        evidence_node_ids: dict[str, str] = {}
        all_evidence_node_ids: dict[str, str] = {}
        for evidence in state.evidence:
            if not evidence.verify_hash():
                missing.append(f"corrupt evidence: {evidence.id}")
                continue
            if evidence.action_id is None:
                continue
            action = actions_by_id.get(evidence.action_id)
            if action is None:
                missing.append(f"evidence has no persisted action: {evidence.id}")
                continue
            all_evidence_node_ids[evidence.id] = action.plan_node_id
            if (
                action.success is True
                and action.run_id == state.run_id
                and evidence.id in action.evidence_ids
                and evidence.source == f"tool:{action.tool_name}"
                and evidence.metadata.get("provenance") == "tool_execution"
                and evidence.metadata.get("tool_success") is True
            ):
                valid_evidence.add(evidence.id)
                evidence_node_ids[evidence.id] = action.plan_node_id
        for node in plan.nodes:
            dangling = set(node.evidence_ids) - evidence_by_id.keys()
            if dangling:
                missing.append(f"node has dangling evidence references: {node.id}")
            node_valid = {
                evidence_id
                for evidence_id in node.evidence_ids
                if evidence_id in valid_evidence and evidence_node_ids.get(evidence_id) == node.id
            }
            if not node_valid:
                missing.append(f"node has no valid successful-action evidence: {node.id}")
            wrong_node = {
                evidence_id
                for evidence_id in node.evidence_ids
                if evidence_id in all_evidence_node_ids
                and all_evidence_node_ids[evidence_id] != node.id
            }
            if wrong_node:
                missing.append(f"node has invalid or wrong-node evidence: {node.id}")

        verified_by_fingerprint: dict[str, set[str]] = {}
        for finding in state.findings:
            if finding.status is not FindingStatus.VERIFIED:
                continue
            dangling = set(finding.evidence_ids) - evidence_by_id.keys()
            invalid = set(finding.evidence_ids) - valid_evidence
            if dangling:
                missing.append(f"finding has dangling evidence: {finding.id}")
            if invalid:
                missing.append(f"finding lacks successful-action evidence: {finding.id}")
            verified_by_fingerprint.setdefault(finding.fingerprint, set()).add(
                " ".join(finding.description.split()).casefold()
            )
        for fingerprint, descriptions in verified_by_fingerprint.items():
            if len(descriptions) > 1:
                conflicts.append(f"conflicting verified finding fingerprint: {fingerprint}")

        if not valid_evidence:
            missing.append("the run has no valid tool-produced evidence")
        if missing or conflicts:
            return VerificationResult.rejected(
                "Run verification rejected.",
                evidence_ids=tuple(sorted(valid_evidence)),
                missing_requirements=tuple(dict.fromkeys(missing)),
                conflicts=tuple(conflicts),
            )
        return VerificationResult.accepted(
            "All task criteria, nodes, evidence links, and findings passed verification.",
            tuple(sorted(valid_evidence)),
        )
