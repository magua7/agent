"""Human-readable SEC-GO CLI backed by the shared Application Service."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from security_agent.application.bootstrap import build_product_services, default_database
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
    run.add_argument("--max-seconds", type=float, default=120.0)
    run.add_argument("--json", action="store_true", dest="as_json")

    serve = commands.add_parser("serve", help="start the local FastAPI service")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)

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
        if args.command == "init":
            return asyncio.run(_initialize(args.db))
        if args.command == "serve":
            return _serve(args.host, args.port)
    except KeyboardInterrupt:
        print("\nSEC-GO interrupted.", file=sys.stderr)
        return 130
    except (OSError, RuntimeError, TaskInputError, ValueError) as exc:
        print(f"SEC-GO error: {exc}", file=sys.stderr)
        return 2
    return 2


async def _run_task(args: argparse.Namespace) -> int:
    if args.max_seconds <= 0:
        raise ValueError("--max-seconds must be positive")
    ports = _parse_ports(args.ports)
    services = await build_product_services(
        args.db,
        skills_root=None if args.skills is None else args.skills.resolve(),
        run_limits=RunLimits(max_steps=10, max_replans=2, max_seconds=args.max_seconds),
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


def _serve(host: str, port: int) -> int:
    if not 1 <= port <= 65_535:
        raise ValueError("--port must be between 1 and 65535")
    try:
        import uvicorn
    except ImportError as exc:
        raise RuntimeError('uvicorn is required; install SEC-GO with the "web" extra') from exc
    uvicorn.run("security_agent.main:app", host=host, port=port, workers=1)
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
