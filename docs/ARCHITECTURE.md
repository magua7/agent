# Security Agent Kernel Architecture

## 1. Purpose

This repository implements a small, evidence-driven runtime for **authorized**
security work. The kernel owns task interpretation, planning, tool dispatch,
evidence capture, verification, retry/replanning, and audit events. It does not
own a web UI, an MCP SDK, a model vendor SDK, or a catalogue of offensive
payloads.

The first executable scenario is deliberately narrow: discover services on an
explicitly authorized localhost target, preserve the real scanner output, turn
that output into an evidence-backed finding, and complete only after an
independent verifier accepts the run.

## 2. Dependency rule

Dependencies point inward. An inner layer never imports an outer layer.

```text
                          composition root / CLI
                         /                      \
                infrastructure                 interfaces
                    /       \                      |
                   v         v                     v
                contracts <- engine ----------> contracts
                    \          |                  /
                     +------> domain <-----------+
```

| Layer | Responsibility | May import |
|---|---|---|
| `domain` | Immutable facts, state transitions, invariants | Python standard library |
| `contracts` | Protocols and boundary DTOs | `domain`, standard library |
| `engine` | Interpreter, planner, agent loop, context, verification, replanning | `domain`, `contracts` |
| `infrastructure` | SQLite, HTTP/model adapters, local tools, skills | `domain`, `contracts` |
| `interfaces` | CLI and future API composition roots | all layers |

Enforced architectural constraints:

- `domain` and `engine` do not import FastAPI, MCP, an LLM SDK, or a concrete
  security tool.
- A tool adapter cannot update plans, findings, or run state.
- An agent cannot access SQLite; it receives a bounded context and returns a
  proposal.
- An LLM response never has authority to mark a node or run complete.
- Web, MCP, and multi-agent support are adapters/strategies, not domain types.

## 3. Runtime components

### Task interpreter

Converts user intent plus explicit scope into a validated `TaskSpec`. It may
infer a task type, but it never infers authorization. Network targets and file
roots must be supplied by the caller.

### Planner

Creates a versioned `Plan` with dependency-aware `PlanNode` objects. The first
implementation supports deterministic local-service plans and structured LLM
plans. All LLM output is parsed and validated as untrusted input.

### Agent and dispatcher

An `Agent` proposes an `ActionDecision` for one node, then reviews the resulting
bounded evidence and returns an `Observation`. The dispatcher selects an agent
by `assigned_agent` and capabilities. Version one registers one default agent;
the interface is already suitable for multiple strategies.

### Tool registry and executor

Agents request a capability such as `network.scan`. The registry selects a tool
that provides it. The executor validates arguments and authorization, emits
events, records an `ActionRecord`, executes the tool, and writes exactly one
provenance-linked `Evidence` record for both success and failure.

The MVP contains no arbitrary shell tool. The network scanner defaults to a
bounded real TCP-connect scan. A host application may inject a trusted
absolute nmap path; only then does it invoke `nmap -sT` without a shell. This
avoids current-directory/PATH executable hijacking. Metadata states the engine
actually used.

### Evidence store and context builder

SQLite stores full raw evidence and its SHA-256 digest. `ContextBuilder` returns
only bounded previews, selected findings, recent actions, relevant skill
guidance, and knowledge snippets. Full content is retrieved explicitly through
the evidence repository/CLI. This prevents large scan, HTML, log, or source
outputs from silently becoming permanent model context.

Skill context follows the same bounded-data rule. The filesystem adapter first
indexes frontmatter, applies the trusted catalog policy, filters unavailable or
lab-only entries, and relevance-ranks a small top-k set. External Skill text and
linked Markdown remain untrusted data; their capability declarations never
register a Tool or bypass execution policy. Detailed rules live in
[SKILLS.md](SKILLS.md).

### Verifier

Verification is independent of the acting agent. Node verification requires:

1. a successful real tool action;
2. evidence linked to that action and run;
3. a valid evidence hash and tool provenance;
4. explicit coverage of every node success criterion.

Finding status is a separate decision: only capability-specific deterministic
checks may promote a draft to `verified`; unsupported interpretations remain
`unverified`. Completion therefore proves the evidence-acquisition workflow
and provenance checks, not arbitrary natural-language semantic truth.

Run verification additionally rejects unfinished nodes, uncovered task
criteria, invalid node evidence references, evidence defects in verified
findings, and conflicting verified findings. Only `VerificationResult.success`
can transition a run to `completed`.

### Replanner

The MVP runtime emits `tool_failure`, `tool_unavailable`, and
`verification_rejected`. The contract reserves `no_evidence`,
`duplicate_action`, and `max_attempts` for richer replanners. Replanning creates
`Plan(version + 1)` and persists the old version unchanged. A retry may reset a
failed node; exhausted nodes remain blocked and make the run fail cleanly.
Step, replan, and wall-clock budgets prevent infinite loops.

### Event bus

The runtime emits typed events through `EventSink`. It does not know whether a
sink is a CLI renderer, log, SQLite event store, SSE stream, or WebSocket. Event
payloads contain IDs and bounded summaries, never API keys or unrestricted raw
evidence.

## 4. Agent loop

```text
validate TaskSpec and explicit authorization scope
    -> create RunState and emit run_started
    -> Planner.generate_plan; validate DAG; persist version 1
    -> while within execution budgets:
         mark dependency-satisfied nodes ready
         select a ready node
         dispatch Agent; request capability, not a binary name
         authorize + validate + execute Tool
         persist ActionRecord and raw Evidence
         Agent observes a bounded Evidence preview
         Verifier verifies the node
              accepted -> node succeeded; persist Findings
              rejected -> retry or create a new Plan version
         verify whole run when no work remains
              accepted -> completed
              rejected -> replan or fail
```

The runtime is sequential at node level in version one. Run-local state,
repository calls, event metadata, and tool contexts all carry `run_id`, so
separate `AgentRuntime.run()` calls can execute concurrently without global
mutable state. A future scheduler can run independent ready nodes concurrently
without changing the domain model.

## 5. Trust and authorization boundaries

- The caller owns authorization and supplies `ScopeSpec`; the runtime enforces
  but cannot manufacture consent.
- Network tools accept only exact hosts/IPs or CIDRs in scope. Hostnames are
  resolved and every destination is checked before a connection is attempted.
- File tools resolve paths and require containment within an authorized root.
- Redirects are disabled in the MVP HTTP tool so a scoped URL cannot silently
  redirect to an out-of-scope host.
- Tool arguments are schema-checked. Secrets in audit arguments are redacted.
- Subprocess calls use argument arrays with `shell=False`.
- LLM text, skill files, knowledge documents, and tool output are untrusted
  data. None can bypass the tool policy or verifier.
- Evidence has a configurable size ceiling. An oversize result is reported as
  a tool failure rather than silently truncated and presented as complete.

## 6. Persistence and audit

SQLite is the only persistence dependency in the MVP. It has separate tables
for runs, versioned plans, plan nodes, actions, evidence, findings, and events.
Connections are short-lived, WAL mode is enabled, and asynchronous contracts
delegate blocking calls to worker threads. Each write is scoped by `run_id`.

Audit reconstruction follows stable links:

```text
Run -> Plan(version) -> PlanNode -> ActionRecord -> Evidence -> Finding
```

Raw evidence and the context preview are different representations. The digest
is always computed from the raw UTF-8 bytes and verified when read.

## 7. Failure semantics

Tool unavailability, policy denial, invalid model output, persistence failure,
timeout, and verification rejection are distinct errors. Expected tool failure
is recorded as action/evidence and can trigger replanning. Corrupt persistence
or an invariant violation fails closed; the runtime does not claim a partial
success.

Cancellation and timeouts are terminal run outcomes. Cleanup never rewrites
historic plans or deletes evidence.

## 8. Composition

`interfaces.bootstrap` is the only place that wires concrete adapters. A normal
CLI/local composition is:

```text
SQLiteStore + EventBus
ToolRegistry(file_read, file_search, http_request, network_scan)
DeterministicPlanner + LocalSecurityAgent
EvidenceVerifier + VersionedReplanner
AgentRuntime
```

Passing `llm_provider=` to `build_local_runtime` adds a
`StructuredLLMPlanner` and `StructuredLLMSecurityAgent`; the deterministic
composition remains the default. The runtime itself is unchanged, and both
compositions share the same Tool Registry, scope policy, and verifier.

## 9. Deliberately deferred

The MVP does not claim a web dashboard, MCP connectivity, vector memory,
distributed queues, user accounts/RBAC, arbitrary shell execution, exploit
automation, or multi-agent orchestration. The extension seams are documented
in `EXTENSION_POINTS.md`.
