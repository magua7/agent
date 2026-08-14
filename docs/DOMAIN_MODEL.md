# Domain Model

## Design conventions

- IDs are opaque UUID strings generated at construction boundaries.
- Timestamps are timezone-aware UTC values.
- Collections crossing a boundary are copied into tuples or plain JSON values.
- Constructors reject invalid facts; transition methods reject invalid state
  changes.
- Domain objects contain no database, HTTP, model-provider, CLI, or UI code.

## TaskSpec and ScopeSpec

`TaskSpec` is the durable interpretation of user intent.

| Field | Type | Invariant |
|---|---|---|
| `id` | string | non-empty |
| `objective` | string | non-blank |
| `task_type` | enum | generic, pentest, incident_response, code_audit, reverse_analysis, ctf |
| `scope` | `ScopeSpec` | explicit network targets and/or file roots for tools |
| `constraints` | tuple[string] | caller-supplied operational constraints |
| `inputs` | JSON object | bounded structured inputs, not hidden global state |
| `success_criteria` | tuple[string] | non-empty and unique |
| `created_at` | UTC datetime | timezone-aware |

`ScopeSpec` separates network and filesystem authorization:

```text
network_targets: exact hostname/IP/CIDR strings
file_roots: absolute or caller-resolved root paths
```

An empty scope is allowed only for tasks that do not execute a network/file
tool. A tool cannot widen scope.

## Plan

| Field | Meaning |
|---|---|
| `id` | stable ID across revisions |
| `task_id` | owning task |
| `version` | positive monotonically increasing integer |
| `status` | draft, active, completed, failed, superseded, cancelled |
| `nodes` | ordered collection of `PlanNode` |
| `created_at`, `updated_at` | audit timestamps |

Before activation a plan validates:

- unique node IDs;
- no missing or self dependencies;
- an acyclic dependency graph;
- at least one node;
- every task success criterion is covered by at least one node criterion.

Readiness is derived: a pending node becomes ready only after every dependency
has succeeded. A failed, blocked, or cancelled dependency cannot make a child
ready.

## PlanNode

Fields:

```text
id, goal, description, status
assigned_agent, required_capabilities
dependencies, success_criteria
attempt_count, max_attempts
evidence_ids, finding_ids
created_at, updated_at
```

`max_attempts` is positive. Evidence/finding references are append-only and
deduplicated. The runtime increments `attempt_count` exactly when transitioning
to `running`.

State transitions:

```text
pending -> ready | blocked | cancelled
ready   -> running | blocked | cancelled
running -> succeeded | failed | blocked | cancelled
failed  -> ready | blocked | cancelled
blocked -> ready | cancelled
succeeded/cancelled -> terminal
```

A node cannot transition to `succeeded` directly from an agent response. Only
the verifier-controlled runtime path performs that transition.

## ActionRecord

Every attempted tool invocation creates one record, including validation,
policy, unavailability, timeout, and execution failures.

```text
id, run_id, plan_node_id, agent_id
tool_name, arguments
started_at, finished_at, duration_ms
success, exit_code, error
evidence_ids
```

`arguments` are an audit-safe redacted copy. Timing is monotonic for duration
and UTC for timestamps. A finished record must have non-negative duration and a
success value.

## Evidence

```text
id, run_id, action_id
type, source, summary
raw_content, content_hash
created_at, metadata
```

Evidence invariants:

- `action_id` is mandatory for evidence used to verify tool execution;
- `content_hash = sha256(raw_content encoded as UTF-8)`;
- `source` identifies the concrete adapter (`tool:<registered-name>`);
- summary is bounded; raw content is not silently truncated;
- metadata is JSON-safe and records provenance such as scanner engine;
- a read verifies the digest and fails closed on corruption.

`EvidencePreview` is a separate boundary DTO containing only ID, summary,
selected metadata, and a bounded prefix. It is never persisted as a substitute
for raw evidence.

## Finding

```text
id, run_id, title, description
severity, confidence
evidence_ids
status, created_at
subject, fingerprint
```

Severity is informational/low/medium/high/critical. Confidence is in `[0, 1]`.
`verified` requires at least one evidence ID. The runtime first confirms every
reference belongs to the same run and a successful real action, then requires a
capability-specific semantic verifier. The MVP can independently reconstruct
its deterministic network-scan finding from typed metadata. Other agent/model
interpretations are persisted as `unverified`, never silently promoted.

`subject` and `fingerprint` provide deterministic conflict/deduplication keys.
Two verified findings with the same fingerprint but materially opposing status
or normalized descriptions cause run verification to fail for human review.

## CriterionAssessment and Observation

An agent observation is a proposal, not an authority:

```text
summary
criterion_assessments[]  # criterion, satisfied, evidence_ids, reason
finding_drafts[]
suggested_replan
```

The verifier requires an assessment for every exact criterion and validates all
evidence links. Unknown criteria and dangling evidence IDs are rejected.

## VerificationResult

```text
success
reason
evidence_ids
missing_requirements
conflicts
```

A failure result is descriptive and may trigger replanning. It does not mutate
the plan itself.

## RunState

```text
run_id, task, plan
status, current_nodes
findings, evidence
started_at, updated_at, finished_at
step_count, replan_count, last_error
```

Run status is `created`, `planning`, `running`, `verifying`, `completed`,
`failed`, or `cancelled`. `completed` is reachable only from `verifying` after a
successful `VerificationResult`. Each state belongs to one `run_id`; there is no
process-wide current run.

## ActionDecision and ToolResult

`ActionDecision` requests a capability and contains validated JSON arguments,
an optional preferred tool name, and a rationale. `ToolResult` is returned by a
tool adapter:

```text
success, output, error, exit_code, metadata
```

Neither type can mutate a run. `ToolExecutor` is the application boundary that
turns a decision/result into an `ActionRecord` and `Evidence`.
