"""Human-readable SEC-GO CLI backed by the shared Application Service."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from collections.abc import Sequence
from functools import partial
from pathlib import Path
from typing import Any

from security_agent.application.bootstrap import (
    build_product_services,
    default_database,
    default_settings_path,
)
from security_agent.application.task_service import TaskInputError
from security_agent.domain import RunStatus
from security_agent.engine import RunLimits


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
        help="prompt for an authorized localhost task (used by start.bat)",
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
        parser.print_help()
        return 0
    try:
        if args.command == "run":
            return asyncio.run(_run_task(args))
        if args.command == "interactive":
            return _interactive(args)
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


def _interactive(args: argparse.Namespace) -> int:
    print("SEC-GO CLI")
    print("仅可检查你拥有或已获得明确授权的 localhost/loopback 目标。")
    print(f"模型配置: {args.settings}")
    print()
    objective = _prompt_required("任务描述: ")
    title = input("任务标题 (留空自动生成): ").strip() or None
    target = input("目标 [127.0.0.1]: ").strip() or "127.0.0.1"
    ports = input("端口 [80,443,8000]: ").strip() or "80,443,8000"
    authorized = input("确认你拥有目标或已获得明确授权? [y/N]: ").strip().casefold()
    if authorized not in {"y", "yes", "是"}:
        print("未确认授权, 任务已取消。", file=sys.stderr)
        return 2
    args.objective = objective
    args.title = title
    args.target = target
    args.ports = ports
    args.as_json = False
    return asyncio.run(_run_task(args))


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


def _prompt_required(prompt: str) -> str:
    while True:
        value = input(prompt).strip()
        if value:
            return value
        print("任务描述不能为空。", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
