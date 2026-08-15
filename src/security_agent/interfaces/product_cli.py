"""Human-readable SEC-GO CLI backed by the shared Application Service.

``sec-go`` without arguments starts a persistent conversational REPL.  The
structured ``sec-go run`` command stays available for scripts and automation.
Every natural-language line in the REPL goes through AssistantService; slash
commands call the TaskService read model directly.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from collections.abc import Awaitable, Callable, Sequence
from functools import partial
from pathlib import Path
from typing import Any

from security_agent.application.assistant_service import AssistantService, MessageKind
from security_agent.application.bootstrap import (
    ProductServices,
    build_product_services,
    default_database,
    default_settings_path,
    project_root,
)
from security_agent.application.task_service import TaskInputError
from security_agent.domain import RunStatus
from security_agent.engine import RunLimits

_TRUSTED_OPERATOR_NOTICE = (
    "本地受信任操作者模式。执行仍严格受 TaskSpec Scope 和 ExecutionPolicy 限制。"
)
_TERMINAL_EVENT_TYPES = frozenset({"task_completed", "task_failed", "task_cancelled"})
_HELP_TEXT = """\
可用命令:
  /help      显示帮助
  /tasks     列出最近任务
  /status    最近任务状态
  /evidence  最近任务证据
  /findings  最近任务发现
  /report    最近任务报告
  /model     显示模型配置
  /clear     开始新会话
  /exit      退出

自然语言:
  直接描述任务。例如「扫描 127.0.0.1 的 80,443」"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sec-go",
        description="SEC-GO evidence-driven security agent product CLI.",
    )
    commands = parser.add_subparsers(dest="command")

    run = commands.add_parser("run", help="create and execute an authorized localhost task")
    run.add_argument("objective", help='for example: "Analyze localhost security"')
    run.add_argument("--title", default=None)
    run.add_argument("--target", default=None, help="localhost or an explicit loopback IP")
    run.add_argument("--ports", default="22,80,443,8000,8080")
    run.add_argument("--db", type=Path, default=default_database())
    run.add_argument("--skills", type=Path, default=None)
    run.add_argument(
        "--settings",
        type=Path,
        default=default_settings_path(),
        help="private JSON settings file (default: ./settings.json)",
    )
    run.add_argument("--max-seconds", type=float, default=120.0)
    run.add_argument("--json", action="store_true", dest="as_json")

    interactive = commands.add_parser(
        "interactive",
        help="start the conversational REPL (used by start.bat)",
    )
    interactive.add_argument("--db", type=Path, default=default_database())
    interactive.add_argument("--skills", type=Path, default=None)
    interactive.add_argument(
        "--settings",
        type=Path,
        default=default_settings_path(),
        help="private JSON settings file (default: ./settings.json)",
    )
    interactive.add_argument("--max-seconds", type=float, default=120.0)

    serve = commands.add_parser("serve", help="start the local FastAPI service")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument(
        "--settings",
        type=Path,
        default=default_settings_path(),
        help="private JSON settings file (default: ./settings.json)",
    )

    init = commands.add_parser("init", help="initialize the local database and admin account")
    init.add_argument("--db", type=Path, default=default_database())
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        args = parser.parse_args(["interactive"])
    try:
        if args.command == "run":
            return asyncio.run(_run_task(args))
        if args.command == "interactive":
            return asyncio.run(_repl_entry(args))
        if args.command == "init":
            return asyncio.run(_initialize(args.db))
        if args.command == "serve":
            return _serve(args.host, args.port, args.settings)
    except KeyboardInterrupt:
        print("\nSEC-GO interrupted.", file=sys.stderr)
        return 130
    except (EOFError, OSError, RuntimeError, TaskInputError, ValueError) as exc:
        print(f"SEC-GO error: {exc}", file=sys.stderr)
        return 2
    return 2


async def _repl_entry(args: argparse.Namespace) -> int:
    """Build services exactly once, then hand the session to the REPL loop."""

    if args.max_seconds <= 0:
        raise ValueError("--max-seconds must be positive")
    services = await build_product_services(
        args.db,
        skills_root=None if args.skills is None else args.skills.resolve(),
        run_limits=RunLimits(max_steps=10, max_replans=2, max_seconds=args.max_seconds),
        settings_path=args.settings.resolve(),
    )
    try:
        username = os.environ.get("SEC_GO_ADMIN_USERNAME", "admin")
        user = await services.products.get_user_by_username(username)
        if user is None:
            raise RuntimeError("local CLI account initialization failed")
        return await run_repl(services, user.id)
    finally:
        await services.close()


async def run_repl(
    services: ProductServices,
    user_id: str,
    *,
    input_func: Callable[[str], Awaitable[str]] | None = None,
    print_func: Callable[[str], None] | None = None,
    workspace: Path | None = None,
    assistant: AssistantService | None = None,
    poll_interval: float = 0.2,
) -> int:
    """Persistent conversational REPL over one Application Service session.

    Natural language always goes through AssistantService; slash commands
    only read the TaskService projections.  Errors never terminate the loop.
    """

    if poll_interval <= 0:
        raise ValueError("poll_interval must be positive")
    output = print_func if print_func is not None else print
    read = input_func if input_func is not None else _console_input
    current_assistant = assistant if assistant is not None else services.assistant
    if current_assistant is None:
        raise RuntimeError("no AssistantService is available")
    _print_banner(services, workspace, output)
    output(_TRUSTED_OPERATOR_NOTICE)
    output("输入 /help 查看可用命令。")
    conversation_id: str | None = None
    active_task_id: str | None = None
    exit_code = 0
    while True:
        try:
            raw = await read("> ")
        except EOFError:
            break
        except KeyboardInterrupt:
            output("")
            output("再见。")
            exit_code = 130
            break
        line = raw.strip()
        if not line:
            continue
        if line.startswith("/"):
            if line == "/exit" or line.startswith("/exit "):
                output("再见。")
                break
            if line == "/clear" or line.startswith("/clear "):
                conversation_id = None
                output("已开始新会话。")
                continue
            try:
                await _handle_slash_command(services, user_id, line, output)
            except KeyboardInterrupt:
                output("")
                output("再见。")
                exit_code = 130
                break
            except Exception as exc:
                output(f"错误: {exc}")
            continue
        try:
            result = await current_assistant.handle_message(
                user_id,
                line,
                conversation_id=conversation_id,
            )
            conversation_id = result.conversation_id
            output(result.reply)
            if result.kind is MessageKind.TASK and result.task is not None:
                active_task_id = result.task.id
                await _stream_task(
                    services,
                    user_id,
                    result.task.id,
                    output,
                    poll_interval=poll_interval,
                )
                active_task_id = None
        except KeyboardInterrupt:
            if active_task_id is not None:
                await services.tasks.cancel_task(user_id, active_task_id)
                active_task_id = None
                output("任务已取消。")
            else:
                output("")
                output("再见。")
                exit_code = 130
                break
        except Exception as exc:
            output(f"错误: {exc}")
    return exit_code


async def _console_input(prompt: str) -> str:
    # Synchronous input() is intentional: at idle nothing else needs the event
    # loop, and a thread-blocked input() would hang exit after Ctrl+C on some
    # platforms.  Product tasks always finish streaming before the next prompt.
    return input(prompt)  # noqa: ASYNC250 - blocking input at idle is deliberate


def _print_banner(
    services: ProductServices,
    workspace: Path | None,
    output: Callable[[str], None],
) -> None:
    llm = services.settings.llm
    model = llm.model if llm.enabled else "local-deterministic"
    output("SEC-GO")
    output(f"Model: {model}")
    output(f"Workspace: {workspace or project_root()}")
    output("")


async def _stream_task(
    services: ProductServices,
    user_id: str,
    task_id: str,
    output: Callable[[str], None],
    *,
    poll_interval: float,
) -> None:
    seen = 0
    while True:
        page = await services.tasks.list_events(
            user_id,
            task_id,
            after_sequence=seen,
            limit=100,
        )
        for record in page.events:
            projected = await services.tasks.project_event(user_id, task_id, record)
            seen = max(seen, projected["sequence"])
            rendered = _render_event(projected)
            if rendered:
                output(rendered)
            if projected["type"] in _TERMINAL_EVENT_TYPES:
                detail = await services.tasks.get_task_detail(user_id, task_id)
                _print_final_summary(detail, output)
                return
        detail = await services.tasks.get_task_detail(user_id, task_id)
        if detail["status"] in {"completed", "failed", "cancelled"} and not page.events:
            _print_final_summary(detail, output)
            return
        await asyncio.sleep(poll_interval)


def _render_event(projected: dict[str, Any]) -> str | None:
    event_type = projected.get("type")
    payload = projected.get("payload")
    if not isinstance(payload, dict):
        payload = {}
    if event_type == "task_started":
        return "[task] 任务已启动"
    if event_type == "plan_created":
        plan = payload.get("plan")
        if isinstance(plan, dict):
            lines = ["[plan] 规划:"]
            for index, node in enumerate(plan.get("nodes", []), start=1):
                if isinstance(node, dict):
                    lines.append(f"  {index}. {node.get('goal')} ({node.get('status')})")
            return "\n".join(lines)
        return "[plan] 规划已创建"
    if event_type == "plan_updated":
        return "[plan] 计划已更新"
    if event_type == "node_started":
        return f"[plan] 节点开始: {payload.get('node_id')}"
    if event_type == "tool_started":
        tool = payload.get("tool")
        arguments = payload.get("arguments")
        return f"[tool] {tool} 开始 {arguments}"
    if event_type == "tool_completed":
        return (
            f"[tool] {payload.get('tool')} 完成 "
            f"(exit {payload.get('exit_code')}, {payload.get('duration_ms')}ms)"
        )
    if event_type == "tool_failed":
        return f"[tool] {payload.get('tool')} 失败: {payload.get('error')}"
    if event_type == "evidence_created":
        content_hash = str(payload.get("content_hash") or "")[:12]
        return f"[evidence] {payload.get('summary')} (sha256 {content_hash}...)"
    if event_type == "finding_created":
        return f"[finding] [{payload.get('severity')}] {payload.get('title')}"
    if event_type == "verification_finished":
        if payload.get("success") is True:
            return "[verification] passed"
        return f"[verification] failed: {payload.get('reason') or ''}"
    if event_type == "task_completed":
        return "[task] 完成"
    if event_type == "task_failed":
        return f"[task] 失败: {payload.get('error') or payload.get('status')}"
    if event_type == "task_cancelled":
        return "[task] 已取消"
    return None


def _print_final_summary(detail: dict[str, Any], output: Callable[[str], None]) -> None:
    output("")
    output(f"任务结束。状态: {detail['status']}")
    findings = detail.get("findings") or []
    if findings:
        output(f"发现: {len(findings)} 条")
        for finding in findings[:8]:
            output(f"  [{finding['severity']}] {finding['title']}")
    verification = detail.get("verification")
    if isinstance(verification, dict):
        output(f"独立验证: {'passed' if verification.get('success') else 'failed'}")


async def _handle_slash_command(
    services: ProductServices,
    user_id: str,
    line: str,
    output: Callable[[str], None],
) -> None:
    command = line.partition(" ")[0]
    if command == "/help":
        output(_HELP_TEXT)
        return
    if command == "/model":
        llm = services.settings.llm
        if llm.enabled:
            output(f"LLM: enabled\nModel: {llm.model}")
        else:
            output("LLM: disabled\nModel: local-deterministic")
        return
    if command in {"/tasks", "/status", "/evidence", "/findings", "/report"}:
        await _handle_task_command(services, user_id, command, output)
        return
    output(f"未知命令: {command}。输入 /help 查看可用命令。")


async def _handle_task_command(
    services: ProductServices,
    user_id: str,
    command: str,
    output: Callable[[str], None],
) -> None:
    if command == "/tasks":
        tasks = await services.tasks.list_tasks(user_id, limit=10)
        if not tasks:
            output("暂无任务。")
            return
        for task in tasks:
            output(f"{task['status']:10} {task['created_at'][:19]} {task['title']}")
        return
    tasks = await services.tasks.list_tasks(user_id, limit=1)
    if not tasks:
        output("暂无任务。")
        return
    recent_id = str(tasks[0]["task_id"])
    detail = await services.tasks.get_task_detail(user_id, recent_id)
    if command == "/status":
        stats = detail.get("stats") or {}
        verification = detail.get("verification")
        output(f"最近任务: {detail['title']} ({recent_id})")
        output(f"状态: {detail['status']}")
        output(
            "统计: "
            f"步骤 {stats.get('step_count', 0)} "
            f"证据 {stats.get('evidence_count', 0)} "
            f"发现 {stats.get('finding_count', 0)}"
        )
        if isinstance(verification, dict) and verification.get("reason"):
            output(f"验证: {verification['reason']}")
        return
    if command == "/evidence":
        evidence = detail.get("evidence") or []
        if not evidence:
            output("暂无证据。")
            return
        for item in evidence:
            content_hash = str(item.get("content_hash") or "")[:16]
            output(f"{item['id']} {item['type']} {item['summary']} (sha256 {content_hash}...)")
        return
    if command == "/findings":
        findings = detail.get("findings") or []
        if not findings:
            output("暂无发现。")
            return
        for finding in findings:
            output(f"[{finding['severity']}] {finding['title']}")
            output(f"  {finding['description']}")
            output(f"  状态: {finding['status']}")
        return
    if command == "/report":
        report = detail.get("report")
        if report:
            output(report)
        else:
            output(f"任务尚未结束,暂无报告。当前状态: {detail['status']}")


async def _run_task(args: argparse.Namespace) -> int:
    if args.max_seconds <= 0:
        raise ValueError("--max-seconds must be positive")
    ports = _parse_ports(args.ports)
    services = await build_product_services(
        args.db,
        skills_root=None if args.skills is None else args.skills.resolve(),
        run_limits=RunLimits(max_steps=10, max_replans=2, max_seconds=args.max_seconds),
        settings_path=args.settings.resolve(),
    )
    try:
        username = os.environ.get("SEC_GO_ADMIN_USERNAME", "admin")
        user = await services.products.get_user_by_username(username)
        if user is None:
            raise RuntimeError("local CLI account initialization failed")
        title = args.title or _default_title(args.objective)
        task = await services.tasks.create_task(
            user.id,
            title=title,
            description=args.objective,
            target=args.target,
            ports=ports,
        )
        if not args.as_json:
            print("SEC-GO")
            print(f"\nTask:\n{task.id}")
            print(f"\nRun:\n{task.run_id}")
            model = (
                services.settings.llm.model
                if services.settings.llm.enabled
                else "local-deterministic"
            )
            print(f"\nModel:\n{model}")
            print("\nExecution:\nAgent Runtime started...")
        state = await services.tasks.wait(user.id, task.id)
        detail = await services.tasks.get_task_detail(user.id, task.id)
        if args.as_json:
            print(json.dumps(detail, ensure_ascii=False, indent=2, sort_keys=True))
        else:
            _print_detail(detail)
        return 0 if state is not None and state.status is RunStatus.COMPLETED else 2
    finally:
        await services.close()


async def _initialize(database: Path) -> int:
    services = await build_product_services(database)
    try:
        username = os.environ.get("SEC_GO_ADMIN_USERNAME", "admin")
        print(f"SEC-GO initialized: {services.database}")
        print(f"Local account: {username}")
        return 0
    finally:
        await services.close()


def _serve(host: str, port: int, settings_path: Path) -> int:
    if not 1 <= port <= 65_535:
        raise ValueError("--port must be between 1 and 65535")
    try:
        import uvicorn
    except ImportError as exc:
        raise RuntimeError('uvicorn is required; install SEC-GO with the "web" extra') from exc
    from security_agent.interfaces.api import create_app

    app = create_app(
        services_factory=partial(
            build_product_services,
            settings_path=settings_path.expanduser().resolve(),
        )
    )
    uvicorn.run(app, host=host, port=port, workers=1)
    return 0


def _print_detail(detail: dict[str, Any]) -> None:
    print(f"\nStatus:\n{detail['status']}")
    plan = detail.get("plan")
    print("\nPlan:")
    if isinstance(plan, dict):
        for index, node in enumerate(plan.get("nodes", []), start=1):
            print(f"[{index}] {node['goal']} ({node['status']})")
    else:
        print("No plan")

    print("\nEvidence:")
    evidence = detail.get("evidence", [])
    if evidence:
        for item in evidence:
            print(f"{item['id']}: {item['summary']}")
    else:
        print("None")

    print("\nFindings:")
    findings = detail.get("findings", [])
    if findings:
        for finding in findings:
            print(f"[{finding['severity']}] {finding['title']}")
    else:
        print("None")

    report = detail.get("report")
    if report:
        print("\nReport:\n")
        print(report)


def _parse_ports(value: str) -> tuple[int, ...]:
    try:
        ports = tuple(sorted({int(item.strip()) for item in value.split(",") if item.strip()}))
    except ValueError as exc:
        raise ValueError("--ports must be a comma-separated integer list") from exc
    if not ports or len(ports) > 128 or any(port < 1 or port > 65_535 for port in ports):
        raise ValueError("--ports must contain 1-128 unique values between 1 and 65535")
    return ports


def _default_title(objective: str) -> str:
    normalized = " ".join(objective.split())
    return normalized if len(normalized) <= 80 else f"{normalized[:77]}..."


if __name__ == "__main__":
    sys.exit(main())
