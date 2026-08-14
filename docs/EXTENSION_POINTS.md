# Extension Points

The kernel uses small protocols so features can be added without reversing the
dependency direction. Extensions are registered at the composition root.

## Tool

Implement `Tool` with a stable name, description, capability set, small JSON
schema, risk level, and `async execute(context, arguments)`. Register it in
`ToolRegistry`. A tool must return a truthful `ToolResult`; it must not write
findings, plans, or run status.

Examples of future adapters:

- `dns_lookup` -> `network.dns`
- a structured external scanner -> `network.scan`
- `source_search` -> `code.search`
- `pcap_summary` -> `traffic.inspect`

Large runtimes belong in a separate process, plugin, or MCP server. They should
not become core dependencies.

## MCP

An optional MCP package will discover remote MCP tool descriptors and wrap each
one in `MCPToolAdapter(Tool)`. The adapter maps the MCP input schema and result
to kernel boundary objects, then registers normally:

```text
MCP SDK (optional package) -> MCPToolAdapter -> ToolRegistry -> AgentRuntime
```

Only the adapter imports the MCP SDK. Disconnects and protocol errors become
ordinary tool failures with audit evidence. The runtime never imports or calls
the SDK directly.

## LLM provider

Implement `LLMProvider.complete(LLMRequest)`. Provider adapters own transport,
authentication, rate limits, and vendor response normalization. The current
HTTP adapter speaks the OpenAI-compatible chat-completions contract without an
SDK; another provider can replace it without changing planner/runtime code.

Provider responses are untrusted. Structured planners/agents must validate JSON
against domain invariants before returning a plan or decision. API keys must not
enter prompts, events, action arguments, or evidence.

## Agent and multi-agent strategy

Implement `Agent.decide()` and `Agent.observe()`, declare capabilities, and
register it in `AgentRegistry`. `AgentDispatcher` selects by explicit
`assigned_agent` first and required capabilities second.

A future commander is a dispatcher/runtime strategy:

```text
AgentDispatcher
  -> PentestAgent
  -> IncidentAgent
  -> CodeAuditAgent
  -> ReverseAgent
```

`PlanNode.assigned_agent` and `required_capabilities` already preserve routing
intent. No agent subclasses are placed in the domain layer, and agents do not
share mutable conversation globals.

## Skill

`SkillProvider` supplies procedural guidance: *how to approach a task*. The
filesystem adapter discovers standard `SKILL.md` frontmatter while a separate,
repository-owned `policy.json` controls enablement, applicable task types,
roles, risk classes, capability dependencies, and resource loading. Legacy
project-owned `skill.yaml` files remain supported without adding a YAML parser
to Core.

Discovery metadata is not authorization. A Skill cannot execute code, register
a tool, grant its own `allowed-tools`, or widen scope merely by being loaded.
Malformed and unclassified entries are isolated with diagnostics; CI can opt
into strict validation. Selection is bounded and relevance-ranked rather than
injecting every applicable document. See [SKILLS.md](SKILLS.md) for the catalog,
progressive-disclosure, and trust model.

## Knowledge

`KnowledgeProvider` supplies facts/documents: *what the agent can look up*.
Its interface is only `search(query, limit)` and `get(document_id)`. The MVP
ships a null provider so the boundary is exercised without claiming a knowledge
base. A later optional adapter can use Markdown/JSON plus SQLite FTS5. Embedding
and external vector stores remain optional adapters.

Skills may suggest knowledge queries, but the types and lifecycle stay separate.

## Evidence and run repositories

Implement `EvidenceRepository` and `RunRepository` to replace SQLite. Repository
methods consume/return domain objects; an agent never receives a repository.
Alternative storage must preserve append-only plan versions, raw evidence,
hashes, provenance links, and run isolation.

## Events, CLI, Web, and UI

Implement `EventSink.publish(event)` and subscribe at composition time. A future
web package can expose REST commands and SSE events:

```text
POST /api/v1/runs
GET  /api/v1/runs/{id}
GET  /api/v1/runs/{id}/plan
GET  /api/v1/runs/{id}/evidence
GET  /api/v1/runs/{id}/findings
GET  /api/v1/runs/{id}/events
```

The API calls an application service and serializes public DTOs; it does not
import runtime internals from a frontend. A separately built React/Vue/Svelte
client depends only on this JSON/event contract. Running Core or CLI requires no
Node.js installation.

## Planner, verifier, and replanner

Planner and replanner strategies can be replaced independently. Any planner
must produce a validated DAG and version history. Any verifier must preserve the
minimum hard checks (real action provenance, evidence integrity, criteria,
unfinished nodes, finding links, and conflicts); an LLM verifier can add
semantic checks but cannot weaken them.

## Plugin packaging

A future plugin package should expose explicit entry points for tools, agents,
skills, knowledge providers, or event sinks. Discovery occurs only in the
composition root. Plugins receive capability-limited contexts and are never
implicitly trusted because they are installed.
