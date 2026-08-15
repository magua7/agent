"""Unified natural-language entry point for SEC-GO user messages.

The AssistantService is the single product boundary that decides whether a
user message is ordinary chat, a question that needs clarification, or an
executable security task.  Every task intent is rebuilt deterministically as
a validated TaskSpec; an optional model may classify the message, but it can
never expand the operator's stated scope, and its output is always verified
before any Task is created.
"""

from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import cast
from urllib.parse import urlsplit

from security_agent.application.models import ProductTask
from security_agent.application.task_service import TaskService
from security_agent.contracts import LLMProvider, LLMRequest
from security_agent.contracts.common import JSONObject, JSONValue, is_json_value
from security_agent.domain import ScopeSpec, TaskSpec, TaskType

_MAX_MESSAGE_LENGTH = 20_000
_MAX_REPLY_LENGTH = 4_000
_MAX_TITLE_LENGTH = 200
_MAX_TARGETS = 16
_MAX_ROOTS = 16
_MAX_PORTS = 128
_MAX_CRITERIA = 16
_MAX_CRITERION_LENGTH = 2_000
_MAX_TEXT_FIELD = 8_192
_DEFAULT_PORTS = (22, 80, 443, 8000, 8080)
_DEFAULT_SCAN_REPLY = "准备检查目标。"


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
    task: ProductTask | None = None


@dataclass(frozen=True, slots=True)
class _Interpretation:
    """A validated classification; a task interpretation always carries a TaskSpec."""

    kind: MessageKind
    reply: str
    title: str = ""
    spec: TaskSpec | None = None


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
    "- chat: ordinary conversation or a question about SEC-GO itself or general knowledge. "
    "Answer it directly in 'reply'.\n"
    "- task: the message fully describes an actionable security task within SEC-GO's bounded "
    "toolset: TCP port scan (network.scan), one HTTP request (http.request), file read "
    "(file.read), or file search (file.search). Include every task field.\n"
    "- clarification: the user seems to want a security task but required details are missing "
    "(for example no target). Ask for exactly what is missing in 'reply' and list the missing "
    "fields in 'missing_fields'.\n"
    "- unsupported: the request needs capabilities SEC-GO does not have (shell, exploit, "
    "WebSocket, MCP, multi-agent, arbitrary tools). Never invent capabilities.\n"
    "Hard scope rule: 'network_targets' and 'file_roots' may contain ONLY hosts, IPs, or "
    "paths that literally appear in the user message. Never resolve, rewrite, or replace a "
    "target. If the user says 127.0.0.1, output 127.0.0.1 and nothing else. 'inputs.ports' "
    "may only contain port numbers the user mentioned.\n"
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

    def __init__(self, tasks: TaskService, *, llm_provider: LLMProvider | None = None) -> None:
        self._tasks = tasks
        self._llm = llm_provider

    @property
    def llm_enabled(self) -> bool:
        return self._llm is not None

    async def handle_message(self, user_id: str, message: str) -> AssistantResult:
        text = _normalize_message(message)
        if self._llm is None:
            interpretation = _interpret_deterministically(text)
        else:
            interpretation = await self._interpret_with_llm(text)
        if interpretation.kind is not MessageKind.TASK:
            return AssistantResult(kind=interpretation.kind, reply=interpretation.reply)
        spec = interpretation.spec
        if spec is None:
            raise RuntimeError("task interpretation lost its validated TaskSpec")
        task = await self._tasks.create_task_from_spec(
            user_id,
            title=interpretation.title,
            description=text,
            spec=spec,
        )
        return AssistantResult(kind=MessageKind.TASK, reply=interpretation.reply, task=task)

    async def _interpret_with_llm(self, message: str) -> _Interpretation:
        provider = self._llm
        if provider is None:
            return _Interpretation(MessageKind.CLARIFICATION, _LLM_FALLBACK_REPLY)
        request = LLMRequest(
            operation="assistant_message",
            system_prompt=_SYSTEM_PROMPT,
            payload={"message": message},
            response_schema=_RESPONSE_SCHEMA,
            temperature=0.0,
        )
        try:
            response = await provider.complete(request)
            payload = response.json_object()
            return _interpret_llm_payload(message, payload)
        except Exception:
            # The model boundary is external: an invalid or failing model must
            # never produce a task, so every failure degrades to clarification.
            return _Interpretation(MessageKind.CLARIFICATION, _LLM_FALLBACK_REPLY)


def _interpret_llm_payload(message: str, payload: JSONObject) -> _Interpretation:
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
    task_type = _task_type(payload.get("task_type"))
    capability_value = payload.get("capability")
    if not isinstance(capability_value, str) or capability_value not in _PLANNABLE_CAPABILITIES:
        raise ValueError("capability is not supported by the current toolset")
    capability = capability_value
    network_targets = _validated_targets(payload.get("network_targets"), message)
    file_roots = _validated_roots(payload.get("file_roots"), message)
    raw_inputs = payload.get("inputs")
    if not isinstance(raw_inputs, dict) or not is_json_value(raw_inputs):
        raise ValueError("inputs must be a JSON object")
    inputs = _rebuild_inputs(capability, raw_inputs, network_targets, file_roots, message)
    criteria = _validated_criteria(payload.get("success_criteria"))
    spec = TaskSpec.create(
        objective=message,
        task_type=task_type,
        scope=ScopeSpec(network_targets=network_targets, file_roots=file_roots),
        success_criteria=criteria,
        constraints=(
            "network and file scope were validated against the operator's message",
            "no exploit activity",
        ),
        inputs=inputs,
    )
    return _Interpretation(kind=kind, reply=reply, title=title, spec=spec)


def _interpret_deterministically(message: str) -> _Interpretation:
    """Offline classifier used when no model provider is configured."""

    folded = message.casefold()
    target_match = _TARGET_TOKEN.search(message)
    if _TASK_ACTION.search(folded) is not None and target_match is not None:
        try:
            return _fallback_scan_task(message, target_match)
        except ValueError:
            return _Interpretation(MessageKind.CLARIFICATION, _MISSING_TARGET_REPLY)
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


def _validated_targets(value: JSONValue, message: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise ValueError("network_targets must be a non-empty list")
    if len(value) > _MAX_TARGETS or not all(
        isinstance(item, str) and item.strip() for item in value
    ):
        raise ValueError("network_targets must contain 1-16 non-empty strings")
    targets = tuple(item.strip() for item in value if isinstance(item, str))
    for target in targets:
        if not _valid_target_shape(target):
            raise ValueError(f"unsupported network target: {target!r}")
        if not _target_mentioned(target, message):
            raise ValueError(f"network target {target!r} does not appear in the operator's message")
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


def _validated_roots(value: JSONValue, message: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ValueError("file_roots must be a list")
    if len(value) > _MAX_ROOTS or not all(isinstance(item, str) and item.strip() for item in value):
        raise ValueError("file_roots must contain at most 16 non-empty strings")
    roots = tuple(item.strip() for item in value if isinstance(item, str))
    for root in roots:
        if not os.path.isabs(root):
            raise ValueError("file_roots must contain absolute paths")
        if root.casefold() not in message.casefold():
            raise ValueError(f"file root {root!r} does not appear in the operator's message")
    return roots


def _rebuild_inputs(
    capability: str,
    raw: JSONObject,
    targets: tuple[str, ...],
    roots: tuple[str, ...],
    message: str,
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
        ports = _validated_ports(raw.get("ports"), _mentioned_ports(message))
        inputs: JSONObject = {"target": target}
        inputs["ports"] = cast(JSONValue, ports)
        return inputs
    if capability == "http.request":
        url = _required_text(raw.get("url"), "inputs.url", _MAX_TEXT_FIELD)
        method = raw.get("method", "GET")
        if not isinstance(method, str) or method.upper() not in {"GET", "HEAD"}:
            raise ValueError("http method must be GET or HEAD")
        host = urlsplit(url).hostname
        if host is None or not _target_in_scope(host, targets):
            raise ValueError("requested URL host must be inside the declared network targets")
        return {"url": url, "method": method.upper()}
    if capability == "file.read":
        path = _required_text(raw.get("path"), "inputs.path", _MAX_TEXT_FIELD)
        _require_path_in_roots(path, roots)
        return {"path": path}
    if capability == "file.search":
        root = _required_text(raw.get("root"), "inputs.root", _MAX_TEXT_FIELD)
        query = _required_text(raw.get("query"), "inputs.query", _MAX_TEXT_FIELD)
        _require_path_in_roots(root, roots)
        return {"root": root, "query": query}
    raise ValueError(f"unsupported capability {capability!r}")


def _validated_ports(value: JSONValue, mentioned: set[int]) -> list[int]:
    if mentioned:
        if not isinstance(value, list) or not value:
            raise ValueError("ports are required when the operator named ports")
    elif value is None:
        return list(_DEFAULT_PORTS)
    elif not isinstance(value, list):
        raise ValueError("ports must be a list of integers")
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
    if mentioned and not set(ports) <= mentioned:
        raise ValueError("ports must only include port numbers named by the operator")
    return ports


def _mentioned_ports(message: str) -> set[int]:
    blocked = tuple(match.span() for match in _IP_TOKEN.finditer(message))
    ports: set[int] = set()
    for match in re.finditer(r"\d+", message):
        start, end = match.span()
        if any(start >= left and end <= right for left, right in blocked):
            continue
        value = int(match.group(0))
        if 1 <= value <= 65_535:
            ports.add(value)
    return ports


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
    if not roots:
        raise ValueError("file capabilities require at least one authorized file root")
    normalized = os.path.normcase(os.path.normpath(os.path.abspath(path)))
    for root in roots:
        base = os.path.normcase(os.path.normpath(root)).rstrip("\\/")
        if normalized == base or normalized.startswith(base + os.sep):
            return
    raise ValueError("file path must be inside an authorized file root")


def _target_in_scope(host: str, targets: tuple[str, ...]) -> bool:
    normalized = host.strip("[]").rstrip(".").casefold()
    return any(normalized == item.strip("[]").rstrip(".").casefold() for item in targets)


def _task_type(value: JSONValue) -> TaskType:
    if not isinstance(value, str) or value not in {item.value for item in TaskType}:
        raise ValueError("task_type must be a known TaskType")
    return TaskType(value)


def _string_list_field(value: JSONValue, label: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
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
