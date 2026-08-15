"""Composition root: the only module that wires concrete adapters."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from security_agent.contracts import LLMProvider, Planner
from security_agent.engine import (
    AgentRegistry,
    AgentRuntime,
    ContextBuilder,
    DeterministicPlanner,
    EvidenceVerifier,
    LocalSecurityAgent,
    RunLimits,
    StructuredLLMPlanner,
    StructuredLLMSecurityAgent,
    ToolExecutor,
    VersionedReplanner,
)
from security_agent.engine.policy import ExecutionPolicy
from security_agent.infrastructure.events import EventBus, MemoryEventSink
from security_agent.infrastructure.skills import FilesystemSkillProvider, NullKnowledgeProvider
from security_agent.infrastructure.storage import SQLiteStore
from security_agent.infrastructure.tools import build_default_tool_registry

_PACKAGED_SKILLS = Path(__file__).resolve().parents[1] / "builtin_skills"


@dataclass(slots=True)
class RuntimeBundle:
    runtime: AgentRuntime
    store: SQLiteStore
    memory_events: MemoryEventSink | None

    async def close(self) -> None:
        await self.store.close()


async def build_local_runtime(
    database: Path,
    *,
    skills_root: Path | None = None,
    llm_provider: LLMProvider | None = None,
    run_limits: RunLimits | None = None,
    capture_events: bool = True,
) -> RuntimeBundle:
    database.parent.mkdir(parents=True, exist_ok=True)
    store = SQLiteStore(database)
    await store.initialize()
    memory_events = MemoryEventSink() if capture_events else None
    event_sinks = (store, memory_events) if memory_events is not None else (store,)
    events = EventBus(event_sinks, strict=True)
    tools = build_default_tool_registry()
    available_capabilities = frozenset(
        capability for tool in tools.list() for capability in tool.capabilities
    )
    skill_provider = FilesystemSkillProvider(
        skills_root or _PACKAGED_SKILLS,
        available_capabilities=available_capabilities,
    )
    knowledge_provider = NullKnowledgeProvider()
    agents = AgentRegistry()
    agents.register(LocalSecurityAgent())
    planner: Planner
    if llm_provider is None:
        planner = DeterministicPlanner()
    else:
        model_agent = StructuredLLMSecurityAgent(llm_provider)
        agents.register(model_agent)
        planner = StructuredLLMPlanner(llm_provider, default_agent=model_agent.id)
    context = ContextBuilder(
        store,
        store,
        skill_provider,
        knowledge_provider,
    )
    verifier = EvidenceVerifier(store)
    executor = ToolExecutor(
        tools,
        store,
        store,
        events,
        policy=ExecutionPolicy(),
    )
    runtime = AgentRuntime(
        planner=planner,
        dispatcher=agents,
        executor=executor,
        context_builder=context,
        verifier=verifier,
        replanner=VersionedReplanner(),
        run_repository=store,
        event_sink=events,
        skill_provider=skill_provider,
        knowledge_provider=knowledge_provider,
        limits=run_limits,
    )
    return RuntimeBundle(runtime=runtime, store=store, memory_events=memory_events)
