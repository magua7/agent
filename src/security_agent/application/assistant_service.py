"""Unified natural-language entry point for SEC-GO user messages.

The AssistantService is the single product boundary that decides whether a
user message is ordinary chat, a question that needs clarification, or an
executable security task.  Every task intent is rebuilt deterministically as
a validated TaskSpec; an optional model may classify the message, but it can
never expand the operator's stated scope, and its output is always verified
before any Task is created.

Conversations give the assistant bounded multi-turn context: recent message
rows and a compact summary of the most recent Task (status, plan, evidence
summaries, findings, verification).  Scope may only come from targets/paths
the user themselves typed inside the current conversation; assistant replies
and model output never grant scope.
"""

from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, cast
from urllib.parse import urlsplit

from security_agent.application.models import ConversationMessage, ProductTask
from security_agent.application.ports import ConversationRepository
from security_agent.application.task_service import TaskNotFoundError, TaskService
from security_agent.contracts import LLMProvider, LLMRequest
from security_agent.contracts.common import JSONObject, JSONValue, is_json_value
from security_agent.domain import ScopeSpec, TaskSpec, TaskType, new_id

_MAX_MESSAGE_LENGTH = 20_000
_MAX_REPLY_LENGTH = 4_000
_MAX_TITLE_LENGTH = 200
_MAX_TARGETS = 16
_MAX_ROOTS = 16
_MAX_PORTS = 128
_MAX_CRITERIA = 16
_MAX_CRITERION_LENGTH = 2_000
_MAX_TEXT_FIELD = 8_192
_CONTEXT_MESSAGES = 16
_CONTEXT_CONTENT_LENGTH = 2_000
_DEFAULT_PORTS = (22, 80, 443, 8000, 8080)
_DEFAULT_SCAN_REPLY = "准备检查目标。"
_TERMINAL_TASK_STATUSES = frozenset({"completed", "failed", "cancelled"})


class MessageKind(StrEnum):
    CHAT = "chat"
    TASK = "task"
    CLARIFICATION = "clarification"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True, slots=True)
class AssistantResult:
    """The bounded outcome of handling one user message."""

    kind: MessageKind
    reply: str
    conversation_id: str
    task: ProductTask | None = None


@dataclass(frozen=True, slots=True)
class _Interpretation:
    """A validated classification; a task interpretation always carries a TaskSpec."""

    kind: MessageKind
    reply: str
    title: str = ""
    spec: TaskSpec | None = None


@dataclass(slots=True)
class _TransientConversations:
    """In-process fallback when no durable conversation store is configured."""

    _messages: dict[str, list[ConversationMessage]] = field(default_factory=dict)
    _counter: int = 0

    async def ensure_conversation(self, user_id: str, conversation_id: str) -> None:
        del user_id, conversation_id

    async def record_message(
        self,
        conversation_id: str,
        *,
        role: str,
        content: str,
        kind: str,
        task_id: str | None = None,
    ) -> ConversationMessage:
        self._counter += 1
        message = ConversationMessage(
            id=self._counter,
            conversation_id=conversation_id,
            role=role,
            content=content,
            kind=kind,
            task_id=task_id,
        )
        self._messages.setdefault(conversation_id, []).append(message)
        return message

    async def recent_messages(
        self,
        conversation_id: str,
        *,
        limit: int,
    ) -> tuple[ConversationMessage, ...]:
        return tuple(self._messages.get(conversation_id, [])[-limit:])

    async def last_task_id(self, conversation_id: str) -> str | None:
        for message in reversed(self._messages.get(conversation_id, [])):
            if message.task_id is not None:
                return message.task_id
        return None


_PLANNABLE_CAPABILITIES = frozenset({"network.scan", "http.request", "file.read", "file.search"})

_TASK_ACTION = re.compile(
    r"(?:扫描|检测|检查|探测|审计|渗透|测试|scan|check|probe|audit|pentest|recon)",
    re.I,
)
_TARGET_TOKEN = re.compile(
    r"(?<![0-9A-Za-z])(?:localhost|\[?::1\]?|\d{1,3}(?:\.\d{1,3}){3})(?![0-9A-Za-z])",
    re.I,
)
_IP_TOKEN = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_HOSTNAME_SHAPE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?")
_QUESTION_PATTERN = re.compile(
    r"(什么是|是什么|介绍一下|介绍|what is|who are|how does|怎么|如何|为什么|why)"
)
_LOOPBACK_MENTION = re.compile(
    r"(?<![0-9A-Za-z])(?:localhost|127\.\d{1,3}(?:\.\d{1,3}){2}|::1)(?![0-9A-Za-z])",
    re.I,
)
_FOLLOW_UP_HINTS = (
    "刚才",
    "刚刚",
    "发现了什么",
    "有什么发现",
    "结果",
    "进展",
    "汇报",
    "总结",
    "报告",
    "what did you find",
    "findings",
    "how did it go",
    "results",
)
_UNSUPPORTED_HINTS = (
    "shell",
    "反弹",
    "webshell",
    "websocket",
    "mcp",
    "exploit",
    "提权",
    "内网穿透",
    "钓鱼",
    "ddos",
    "挖矿",
    "勒索",
    "sqlmap",
    "metasploit",
    "msf",
    "nuclei",
    "暴力破解",
    "撞库",
    "抓包",
)
_IDENTITY_HINTS = ("你是谁", "who are you", "what are you", "你是什么", "介绍一下自己")
_GREETINGS = ("你好", "您好", "hi", "hello", "hey", "嗨", "在吗")

_IDENTITY_REPLY = (
    "我是 SEC-GO。一个本地运行的证据驱动安全助手。你可以用一句话描述安全任务"
    "(例如「扫描 127.0.0.1 的 80,443」)。我会把它解析为带显式授权范围的任务。"
    "执行时保留工具证据和独立校验结果。"
)
_PORT_SCAN_REPLY = (
    "端口扫描是对目标主机的 TCP 端口发起有限次连接探测。判断哪些端口处于开放状态。"
    "在 SEC-GO 中你可以直接说「扫描 127.0.0.1 的 80,443」。我会创建一个带显式授权"
    "范围、执行证据和独立校验的安全任务。"
)
_DEFINITION_REPLY = (
    "这个问题的详细解释需要启用语言模型。你可以在 settings.json 中将 llm.enabled "
    "设为 true。当前我仍可以执行明确的结构化安全任务。例如「扫描 127.0.0.1 的 80,443」。"
)
_GREETING_REPLY = (
    "你好。我是 SEC-GO 本地安全助手。你可以直接描述任务。例如「扫描 127.0.0.1 的 80,443」。"
)
_MISSING_TARGET_REPLY = (
    "请补充明确的目标和端口。例如「扫描 127.0.0.1 的 80,443」。我会据此创建带授权范围的安全任务。"
)
_UNSUPPORTED_REPLY = (
    "这条请求超出了 SEC-GO 当前的受限工具集(TCP 端口扫描、HTTP 请求、文件读取与搜索)。"
    "本阶段不支持 shell、exploit、WebSocket、MCP 等能力。"
)
_MODEL_DISABLED_REPLY = (
    "LLM 未启用。我暂时只能确定性回答简单问题或执行结构化的扫描任务"
    "(例如「扫描 127.0.0.1 的 80,443」)。如需自然语言对话。请在 settings.json 中启用 llm。"
)
_LLM_FALLBACK_REPLY = (
    "模型暂时不可用或返回了无法通过校验的内容。请换个说法或明确给出目标。"
    "例如「扫描 127.0.0.1 的 80,443」。"
)

_SYSTEM_PROMPT = (
    "You are SEC-GO, a local evidence-driven security assistant. Classify the user message "
    "into exactly one kind: 'chat', 'task', 'clarification', or 'unsupported'.\n"
    "- chat: ordinary conversation, or a question about SEC-GO itself, general knowledge, "
    "or the supplied recent_task summary (for example '刚才发现了什么?'). Answer it directly "
    "in 'reply'. Do NOT create a task when the user only asks about results.\n"
    "- task: the message describes an actionable security task within SEC-GO's bounded "
    "toolset: TCP port scan (network.scan), one HTTP request (http.request), file read "
    "(file.read), or file search (file.search). Include every task field.\n"
    "- clarification: the user seems to want a security task but required details are missing "
    "(for example no target). Ask for exactly what is missing in 'reply' and list the missing "
    "fields in 'missing_fields'. If the user answers with just a target/ports, complete the "
    "task in the next turn.\n"
    "- unsupported: the request needs capabilities SEC-GO does not have (shell, exploit, "
    "WebSocket, MCP, multi-agent, arbitrary tools). Never invent capabilities.\n"
    "For task kind include: 'title' (short), 'task_type' (exactly one of: generic, pentest, "
    "incident_response, code_audit, reverse_analysis, ctf), 'capability' (exactly one of: "
    "network.scan, http.request, file.read, file.search), 'network_targets', 'file_roots', "
    "'inputs', 'success_criteria' (list of strings), 'missing_fields' (empty).\n"
    "Hard scope rule: 'network_targets' and 'file_roots' may contain ONLY hosts, IPs, or "
    "paths that literally appear in a user message of the current conversation. Never "
    "resolve, rewrite, or replace a target. If the user says 127.0.0.1, output 127.0.0.1 "
    "and nothing else. 'inputs.ports' may only contain port numbers the user mentioned in "
    "the conversation; when the user named no ports, omit 'inputs.ports' entirely and the "
    "system applies its safe defaults.\n"
    "Return one JSON object only, with keys: kind, reply, title, task_type, capability, "
    "network_targets, file_roots, inputs, success_criteria, missing_fields. Use empty arrays "
    "for fields that do not apply. 'reply' is always required non-empty text."
)

_RESPONSE_SCHEMA: dict[str, JSONValue] = {
    "type": "object",
    "required": ["kind", "reply"],
    "properties": {
        "kind": {"type": "string", "enum": ["chat", "task", "clarification", "unsupported"]},
        "reply": {"type": "string", "minLength": 1},
        "title": {"type": "string"},
        "task_type": {"type": "string"},
        "capability": {"type": "string"},
        "network_targets": {"type": "array", "items": {"type": "string"}},
        "file_roots": {"type": "array", "items": {"type": "string"}},
        "inputs": {"type": "object"},
        "success_criteria": {"type": "array", "items": {"type": "string"}},
        "missing_fields": {"type": "array", "items": {"type": "string"}},
    },
}


class AssistantService:
    """Route one user message to chat, clarification, unsupported, or a real task."""

    def __init__(
        self,
        tasks: TaskService,
        *,
        llm_provider: LLMProvider | None = None,
        conversations: ConversationRepository | None = None,
    ) -> None:
        self._tasks = tasks
        self._llm = llm_provider
        self._conversations: ConversationRepository = conversations or _TransientConversations()

    @property
    def llm_enabled(self) -> bool:
        return self._llm is not None

    async def handle_message(
        self,
        user_id: str,
        message: str,
        *,
        conversation_id: str | None = None,
    ) -> AssistantResult:
        text = _normalize_message(message)
        conversation = conversation_id or new_id()
        await self._conversations.ensure_conversation(user_id, conversation)
        history = await self._conversations.recent_messages(
            conversation,
            limit=_CONTEXT_MESSAGES,
        )
        recent_task = await self._recent_task_summary(user_id, conversation)
        user_texts = (*(item.content for item in history if item.role == "user"), text)
        if self._llm is None:
            interpretation = _interpret_deterministically(text, history, recent_task)
        else:
            interpretation = await self._interpret_with_llm(
                text,
                history,
                recent_task,
                user_texts,
            )
        await self._conversations.record_message(
            conversation,
            role="user",
            content=text,
            kind=interpretation.kind.value,
        )
        if interpretation.kind is not MessageKind.TASK:
            await self._conversations.record_message(
                conversation,
                role="assistant",
                content=interpretation.reply,
                kind=interpretation.kind.value,
            )
            return AssistantResult(
                kind=interpretation.kind,
                reply=interpretation.reply,
                conversation_id=conversation,
            )
        spec = interpretation.spec
        if spec is None:
            raise RuntimeError("task interpretation lost its validated TaskSpec")
        task = await self._tasks.create_task_from_spec(
            user_id,
            title=interpretation.title,
            description=text,
            spec=spec,
        )
        await self._conversations.record_message(
            conversation,
            role="assistant",
            content=interpretation.reply,
            kind=MessageKind.TASK.value,
            task_id=task.id,
        )
        return AssistantResult(
            kind=MessageKind.TASK,
            reply=interpretation.reply,
            conversation_id=conversation,
            task=task,
        )

    async def _recent_task_summary(
        self,
        user_id: str,
        conversation_id: str,
    ) -> dict[str, Any] | None:
        task_id = await self._conversations.last_task_id(conversation_id)
        if task_id is None:
            return None
        try:
            detail = await self._tasks.get_task_detail(user_id, task_id)
        except TaskNotFoundError:
            return None
        return _bounded_task_summary(detail)

    async def _interpret_with_llm(
        self,
        message: str,
        history: tuple[ConversationMessage, ...],
        recent_task: dict[str, Any] | None,
        user_texts: tuple[str, ...],
    ) -> _Interpretation:
        provider = self._llm
        if provider is None:
            return _Interpretation(MessageKind.CLARIFICATION, _LLM_FALLBACK_REPLY)
        request = LLMRequest(
            operation="assistant_message",
            system_prompt=_SYSTEM_PROMPT,
            payload={
                "message": message,
                "conversation": [
                    {
                        "role": item.role,
                        "content": item.content[:_CONTEXT_CONTENT_LENGTH],
                        "kind": item.kind,
                        "task_id": item.task_id,
                    }
                    for item in history
                ],
                "recent_task": recent_task,
            },
            response_schema=_RESPONSE_SCHEMA,
            temperature=0.0,
        )
        try:
            response = await provider.complete(request)
            payload = response.json_object()
            return _interpret_llm_payload(message, payload, user_texts)
        except Exception:
            # The model boundary is external: an invalid or failing model must
            # never produce a task, so every failure degrades to clarification.
            return _Interpretation(MessageKind.CLARIFICATION, _LLM_FALLBACK_REPLY)


def _interpret_llm_payload(
    message: str,
    payload: JSONObject,
    user_texts: tuple[str, ...],
) -> _Interpretation:
    kind_value = payload.get("kind")
    if not isinstance(kind_value, str) or kind_value not in _KIND_VALUES:
        raise ValueError("kind must be one of chat/task/clarification/unsupported")
    kind = MessageKind(kind_value)
    reply = _required_text(payload.get("reply"), "reply", _MAX_REPLY_LENGTH)
    missing = _string_list_field(payload.get("missing_fields"), "missing_fields")
    if kind is not MessageKind.TASK:
        return _Interpretation(kind=kind, reply=reply)
    if missing:
        return _Interpretation(kind=MessageKind.CLARIFICATION, reply=reply)
    title = _required_text(payload.get("title"), "title", _MAX_TITLE_LENGTH)
    capability_value = payload.get("capability")
    if not isinstance(capability_value, str) or capability_value not in _PLANNABLE_CAPABILITIES:
        raise ValueError("capability is not supported by the current toolset")
    capability = capability_value
    task_type = _task_type(payload.get("task_type"), capability)
    network_targets = _validated_targets(payload.get("network_targets"), user_texts)
    file_roots = _validated_roots(payload.get("file_roots"), user_texts)
    raw_inputs = payload.get("inputs")
    if not isinstance(raw_inputs, dict) or not is_json_value(raw_inputs):
        raise ValueError("inputs must be a JSON object")
    inputs = _rebuild_inputs(capability, raw_inputs, network_targets, file_roots, user_texts)
    criteria = _validated_criteria(payload.get("success_criteria"))
    spec = TaskSpec.create(
        objective=message,
        task_type=task_type,
        scope=ScopeSpec(network_targets=network_targets, file_roots=file_roots),
        success_criteria=criteria,
        constraints=(
            "network and file scope were validated against the operator's messages",
            "no exploit activity",
        ),
        inputs=inputs,
    )
    return _Interpretation(kind=kind, reply=reply, title=title, spec=spec)


def _interpret_deterministically(
    message: str,
    history: tuple[ConversationMessage, ...],
    recent_task: dict[str, Any] | None,
) -> _Interpretation:
    """Offline classifier used when no model provider is configured."""

    folded = message.casefold()
    target_match = _TARGET_TOKEN.search(message)
    if _TASK_ACTION.search(folded) is not None and target_match is not None:
        try:
            return _fallback_scan_task(message, target_match)
        except ValueError:
            return _Interpretation(MessageKind.CLARIFICATION, _MISSING_TARGET_REPLY)
    if target_match is not None and _last_user_kind(history) == MessageKind.CLARIFICATION.value:
        try:
            return _fallback_scan_task(message, target_match)
        except ValueError:
            return _Interpretation(MessageKind.CLARIFICATION, _MISSING_TARGET_REPLY)
    if recent_task is not None and any(hint in folded for hint in _FOLLOW_UP_HINTS):
        return _Interpretation(
            MessageKind.CHAT,
            _format_follow_up_reply(recent_task),
        )
    if any(hint in folded for hint in _IDENTITY_HINTS):
        return _Interpretation(MessageKind.CHAT, _IDENTITY_REPLY)
    if _QUESTION_PATTERN.search(folded) is not None and "端口扫描" in folded:
        return _Interpretation(MessageKind.CHAT, _PORT_SCAN_REPLY)
    if _QUESTION_PATTERN.search(folded) is not None:
        return _Interpretation(MessageKind.CHAT, _DEFINITION_REPLY)
    if any(greeting == folded for greeting in _GREETINGS):
        return _Interpretation(MessageKind.CHAT, _GREETING_REPLY)
    if _unsupported_hint(folded):
        return _Interpretation(MessageKind.UNSUPPORTED, _UNSUPPORTED_REPLY)
    if _TASK_ACTION.search(folded) is not None:
        return _Interpretation(MessageKind.CLARIFICATION, _MISSING_TARGET_REPLY)
    return _Interpretation(MessageKind.CHAT, _MODEL_DISABLED_REPLY)


def _last_user_kind(history: tuple[ConversationMessage, ...]) -> str | None:
    for message in reversed(history):
        if message.role == "user":
            return message.kind
    return None


def _fallback_scan_task(message: str, target_match: re.Match[str]) -> _Interpretation:
    target = _normalize_scan_target(target_match.group(0))
    ports = _fallback_ports(message[target_match.end() :])
    spec = TaskSpec.create(
        objective=message,
        task_type=TaskType.PENTEST,
        scope=ScopeSpec(network_targets=(target,)),
        success_criteria=("Record the observed service state as tool-produced evidence",),
        constraints=(
            "target and ports were parsed verbatim from the operator's message",
            "no exploit activity",
        ),
        inputs={"target": target, "ports": ports},
    )
    return _Interpretation(
        kind=MessageKind.TASK,
        reply=_DEFAULT_SCAN_REPLY,
        title=f"端口扫描 {target}",
        spec=spec,
    )


def _normalize_scan_target(raw: str) -> str:
    candidate = raw.strip()
    if candidate.casefold().rstrip(".") == "localhost":
        return "127.0.0.1"
    try:
        address = ipaddress.ip_address(candidate.strip("[]"))
    except ValueError as exc:
        raise ValueError("message contains an invalid target") from exc
    return str(address)


def _fallback_ports(tail: str) -> list[int]:
    values = [int(item) for item in re.findall(r"\d+", tail) if 1 <= int(item) <= 65_535]
    ports = sorted(set(values))
    if len(ports) > _MAX_PORTS:
        raise ValueError("too many ports in the operator's message")
    return list(ports) if ports else list(_DEFAULT_PORTS)


def _bounded_task_summary(detail: dict[str, Any]) -> dict[str, Any]:
    plan = detail.get("plan")
    plan_nodes: list[dict[str, Any]] = []
    if isinstance(plan, dict):
        plan_nodes = [
            {"goal": str(node["goal"]), "status": str(node["status"])}
            for node in plan.get("nodes", [])
            if isinstance(node, dict) and "goal" in node and "status" in node
        ][:16]
    return {
        "task_id": detail["id"],
        "title": detail["title"],
        "status": detail["status"],
        "plan": plan_nodes,
        "evidence": [
            {"type": item["type"], "summary": item["summary"]}
            for item in detail.get("evidence", [])
            if isinstance(item, dict)
        ][:16],
        "findings": [
            {
                "severity": item["severity"],
                "title": item["title"],
                "description": str(item.get("description", ""))[:500],
                "status": item["status"],
            }
            for item in detail.get("findings", [])
            if isinstance(item, dict)
        ][:16],
        "verification": detail.get("verification"),
        "stats": detail.get("stats"),
    }


def _format_follow_up_reply(detail: dict[str, Any]) -> str:
    title = str(detail.get("title") or "最近任务")
    status = str(detail.get("status") or "")
    if status not in _TERMINAL_TASK_STATUSES:
        return f"任务「{title}」仍在执行中(状态 {status})。"
    if status == "failed":
        return f"任务「{title}」执行失败: {detail.get('last_error') or '未知错误'}。"
    if status == "cancelled":
        return f"任务「{title}」已取消。"
    findings = detail.get("findings") or []
    if findings:
        parts = "; ".join(
            f"[{item['severity']}] {item['title']}" for item in findings[:8]
        )
        base = f"任务「{title}」已完成。发现 {len(findings)} 条: {parts}。"
    else:
        base = f"任务「{title}」已完成。未产生安全发现。"
    verification = detail.get("verification")
    stats = detail.get("stats") or {}
    if isinstance(verification, dict) and verification.get("success") is True:
        base += f" 独立校验通过。证据 {stats.get('evidence_count', 0)} 条。"
    return base


def _validated_targets(value: JSONValue, user_texts: tuple[str, ...]) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ValueError("network_targets must be a list")
    if len(value) > _MAX_TARGETS or not all(
        isinstance(item, str) and item.strip() for item in value
    ):
        raise ValueError("network_targets must contain at most 16 non-empty strings")
    targets = tuple(item.strip() for item in value if isinstance(item, str))
    for target in targets:
        if not _valid_target_shape(target):
            raise ValueError(f"unsupported network target: {target!r}")
        if not any(_target_mentioned(target, text) for text in user_texts):
            raise ValueError(
                f"network target {target!r} does not appear in the operator's messages"
            )
    return targets


def _valid_target_shape(target: str) -> bool:
    if not target or "/" in target or any(character.isspace() for character in target):
        return False
    try:
        ipaddress.ip_address(target.strip("[]"))
    except ValueError:
        return bool(_HOSTNAME_SHAPE.fullmatch(target))
    return True


def _target_mentioned(target: str, message: str) -> bool:
    folded_target = target.strip("[]").rstrip(".").casefold()
    folded_message = message.casefold()
    if folded_target and folded_target in folded_message:
        return True
    if folded_target == "localhost":
        return bool(_LOOPBACK_MENTION.search(folded_message))
    try:
        address = ipaddress.ip_address(folded_target)
    except ValueError:
        return False
    if address.is_loopback and "localhost" in folded_message:
        return True
    return False


def _validated_roots(value: JSONValue, user_texts: tuple[str, ...]) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ValueError("file_roots must be a list")
    if len(value) > _MAX_ROOTS or not all(
        isinstance(item, str) and item.strip() for item in value
    ):
        raise ValueError("file_roots must contain at most 16 non-empty strings")
    roots = tuple(item.strip() for item in value if isinstance(item, str))
    for root in roots:
        if not os.path.isabs(root):
            raise ValueError("file_roots must contain absolute paths")
        if not any(root.casefold() in text.casefold() for text in user_texts):
            raise ValueError(f"file root {root!r} does not appear in the operator's messages")
    return roots


def _rebuild_inputs(
    capability: str,
    raw: JSONObject,
    targets: tuple[str, ...],
    roots: tuple[str, ...],
    user_texts: tuple[str, ...],
) -> JSONObject:
    """Keep only the fields the chosen capability needs, validated against scope."""

    if capability == "network.scan":
        if not targets:
            raise ValueError("network.scan requires at least one network target")
        target = _optional_text(raw.get("target"))
        if target is None:
            target = targets[0]
        elif not _target_in_scope(target, targets):
            raise ValueError("scan target must be inside the declared network targets")
        ports = _validated_ports(raw.get("ports"), _mentioned_ports(user_texts))
        inputs: JSONObject = {"target": target}
        inputs["ports"] = cast(JSONValue, ports)
        return inputs
    if capability == "http.request":
        if not targets:
            raise ValueError("http.request requires at least one network target")
        url = _required_text(raw.get("url"), "inputs.url", _MAX_TEXT_FIELD)
        method = raw.get("method", "GET")
        if not isinstance(method, str) or method.upper() not in {"GET", "HEAD"}:
            raise ValueError("http method must be GET or HEAD")
        host = urlsplit(url).hostname
        if host is None or not _target_in_scope(host, targets):
            raise ValueError("requested URL host must be inside the declared network targets")
        return {"url": url, "method": method.upper()}
    if capability in {"file.read", "file.search"}:
        if targets:
            raise ValueError("file capabilities must not declare network targets")
        if not roots:
            raise ValueError(f"{capability} requires at least one authorized file root")
        if capability == "file.read":
            path = _required_text(raw.get("path"), "inputs.path", _MAX_TEXT_FIELD)
            _require_path_in_roots(path, roots)
            return {"path": path}
        root = _required_text(raw.get("root"), "inputs.root", _MAX_TEXT_FIELD)
        query = _required_text(raw.get("query"), "inputs.query", _MAX_TEXT_FIELD)
        _require_path_in_roots(root, roots)
        return {"root": root, "query": query}
    raise ValueError(f"unsupported capability {capability!r}")


def _validated_ports(value: JSONValue, mentioned: set[int]) -> list[int]:
    if not mentioned:
        # The operator named no ports: only the code-defined safe default set
        # is allowed.  Model-supplied ports are deliberately ignored here.
        return list(_DEFAULT_PORTS)
    if not isinstance(value, list) or not value:
        raise ValueError("ports are required when the operator named ports")
    if len(value) > _MAX_PORTS:
        raise ValueError("ports cannot exceed 128 entries")
    ports = [
        int(item)
        for item in value
        if isinstance(item, int) and not isinstance(item, bool) and 1 <= item <= 65_535
    ]
    if len(ports) != len(value):
        raise ValueError("ports must be integers between 1 and 65535")
    ports = sorted(set(ports))
    if not ports:
        raise ValueError("ports must be non-empty")
    if not set(ports) <= mentioned:
        raise ValueError("ports must only include port numbers named by the operator")
    return ports


def _mentioned_ports(user_texts: tuple[str, ...]) -> set[int]:
    mentioned: set[int] = set()
    for text in user_texts:
        blocked = tuple(match.span() for match in _IP_TOKEN.finditer(text))
        for match in re.finditer(r"\d+", text):
            start, end = match.span()
            if any(start >= left and end <= right for left, right in blocked):
                continue
            value = int(match.group(0))
            if 1 <= value <= 65_535:
                mentioned.add(value)
    return mentioned


def _validated_criteria(value: JSONValue) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise ValueError("success_criteria must be a non-empty list")
    if len(value) > _MAX_CRITERIA or not all(isinstance(item, str) for item in value):
        raise ValueError("success_criteria must contain at most 16 strings")
    criteria = tuple(item.strip() for item in value if isinstance(item, str))
    if any(not item for item in criteria):
        raise ValueError("success criteria must be non-empty text")
    if any(len(item) > _MAX_CRITERION_LENGTH for item in criteria):
        raise ValueError("a success criterion is too long")
    return criteria


def _require_path_in_roots(path: str, roots: tuple[str, ...]) -> None:
    normalized = os.path.normcase(os.path.normpath(os.path.abspath(path)))
    for root in roots:
        base = os.path.normcase(os.path.normpath(root)).rstrip("\\/")
        if normalized == base or normalized.startswith(base + os.sep):
            return
    raise ValueError("file path must be inside an authorized file root")


def _target_in_scope(host: str, targets: tuple[str, ...]) -> bool:
    normalized = host.strip("[]").rstrip(".").casefold()
    return any(normalized == item.strip("[]").rstrip(".").casefold() for item in targets)


def _task_type(value: JSONValue, capability: str) -> TaskType:
    known = {item.value for item in TaskType}
    if isinstance(value, str) and value in known:
        return TaskType(value)
    # Models often confuse the task type with a capability name.  The type
    # never drives planning (inputs and scope do), so normalize it
    # deterministically instead of rejecting an otherwise valid task.
    if capability in {"network.scan", "http.request"}:
        return TaskType.PENTEST
    if capability in {"file.read", "file.search"}:
        return TaskType.CODE_AUDIT
    raise ValueError("task_type must be a known TaskType")


def _string_list_field(value: JSONValue, label: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item for item in value
    ):
        raise ValueError(f"{label} must be a string list")
    return [item for item in value if isinstance(item, str)]


def _required_text(value: JSONValue, label: str, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be non-empty text")
    normalized = value.strip()
    if len(normalized) > maximum:
        raise ValueError(f"{label} cannot exceed {maximum} characters")
    return normalized


def _optional_text(value: JSONValue) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValueError("expected text or null")
    return value.strip()


def _unsupported_hint(folded_message: str) -> bool:
    return any(hint in folded_message for hint in _UNSUPPORTED_HINTS)


def _normalize_message(message: str) -> str:
    if not isinstance(message, str) or not message.strip():
        raise ValueError("message must be non-empty text")
    normalized = message.strip()
    if len(normalized) > _MAX_MESSAGE_LENGTH:
        raise ValueError(f"message cannot exceed {_MAX_MESSAGE_LENGTH} characters")
    return normalized


_KIND_VALUES = frozenset({item.value for item in MessageKind})
