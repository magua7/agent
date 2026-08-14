"""Minimal machine-readable CLI for the localhost MVP."""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from security_agent.domain import RunState, RunStatus, TaskType
from security_agent.engine import RunLimits, TaskInterpreter
from security_agent.infrastructure.storage import SQLiteStore
from security_agent.interfaces.bootstrap import build_local_runtime
from security_agent.interfaces.skills_cli import add_skills_parser, run_skills_command


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="security-agent",
        description="Evidence-driven runtime for explicitly authorized security tasks.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser(
        "scan-local",
        help="discover services on a loopback target and persist evidence",
    )
    scan.add_argument("--target", default="127.0.0.1")
    scan.add_argument("--ports", default="22,80,443,8000,8080")
    scan.add_argument("--db", type=Path, default=Path("runtime-data/security-agent.sqlite3"))
    scan.add_argument(
        "--skills",
        type=Path,
        default=None,
        help="optional Skill directory (defaults to the packaged sample)",
    )
    scan.add_argument("--max-seconds", type=float, default=120.0)

    show = subparsers.add_parser("show-run", help="show a persisted run summary")
    show.add_argument("run_id")
    show.add_argument("--db", type=Path, default=Path("runtime-data/security-agent.sqlite3"))

    evidence_get = subparsers.add_parser(
        "evidence-get",
        help="retrieve full raw evidence by ID",
    )
    evidence_get.add_argument("evidence_id")
    evidence_get.add_argument(
        "--db",
        type=Path,
        default=Path("runtime-data/security-agent.sqlite3"),
    )

    evidence_search = subparsers.add_parser(
        "evidence-search",
        help="search evidence summaries/content within one run",
    )
    evidence_search.add_argument("run_id")
    evidence_search.add_argument("query")
    evidence_search.add_argument("--limit", type=int, default=20)
    evidence_search.add_argument(
        "--db",
        type=Path,
        default=Path("runtime-data/security-agent.sqlite3"),
    )
    add_skills_parser(subparsers)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "scan-local":
            return asyncio.run(_scan_local(args))
        if args.command == "show-run":
            return asyncio.run(_show_run(args.db, args.run_id))
        if args.command == "evidence-get":
            return asyncio.run(_evidence_get(args.db, args.evidence_id))
        if args.command == "evidence-search":
            return asyncio.run(_evidence_search(args.db, args.run_id, args.query, args.limit))
        if args.command == "skills":
            return asyncio.run(run_skills_command(args))
    except (OSError, ValueError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2
    return 2


async def _scan_local(args: argparse.Namespace) -> int:
    target = _normalize_loopback_target(args.target)
    ports = _parse_ports(args.ports)
    if args.max_seconds <= 0:
        raise ValueError("--max-seconds must be positive")
    interpreter = TaskInterpreter()
    criterion = "Record the observed localhost service state as tool-produced evidence"
    task = interpreter.interpret(
        f"Inspect explicitly authorized localhost services on {target}",
        task_type=TaskType.PENTEST,
        network_targets=(target,),
        inputs={"target": target, "ports": list(ports)},
        success_criteria=(criterion,),
        constraints=("loopback targets only", "no exploit activity"),
    )
    bundle = await build_local_runtime(
        args.db.resolve(),
        skills_root=None if args.skills is None else args.skills.resolve(),
        run_limits=RunLimits(max_steps=10, max_replans=2, max_seconds=args.max_seconds),
    )
    try:
        state = await bundle.runtime.run(task)
        print(json.dumps(_run_summary(state), ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if state.status is RunStatus.COMPLETED else 2
    finally:
        await bundle.close()


async def _show_run(database: Path, run_id: str) -> int:
    store = await _open_store(database)
    try:
        state = await store.get_run(run_id)
        if state is None:
            raise ValueError(f"unknown run_id {run_id!r}")
        print(json.dumps(_run_summary(state), ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    finally:
        await store.close()


async def _evidence_get(database: Path, evidence_id: str) -> int:
    store = await _open_store(database)
    try:
        evidence = await store.get_evidence(evidence_id)
        if evidence is None:
            raise ValueError(f"unknown evidence_id {evidence_id!r}")
        print(
            json.dumps(
                {
                    "id": evidence.id,
                    "run_id": evidence.run_id,
                    "action_id": evidence.action_id,
                    "type": evidence.type.value,
                    "source": evidence.source,
                    "summary": evidence.summary,
                    "content_hash": evidence.content_hash,
                    "raw_content": evidence.raw_content,
                    "metadata": evidence.metadata,
                },
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    finally:
        await store.close()


async def _evidence_search(database: Path, run_id: str, query: str, limit: int) -> int:
    if limit <= 0 or limit > 100:
        raise ValueError("--limit must be between 1 and 100")
    store = await _open_store(database)
    try:
        matches = await store.search_evidence(run_id, query, limit)
        print(
            json.dumps(
                [
                    {
                        "id": item.id,
                        "summary": item.summary,
                        "source": item.source,
                        "content_hash": item.content_hash,
                    }
                    for item in matches
                ],
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    finally:
        await store.close()


async def _open_store(database: Path) -> SQLiteStore:
    store = SQLiteStore(database.resolve())  # noqa: ASYNC240 - composition boundary
    await store.initialize()
    return store


def _normalize_loopback_target(target: str) -> str:
    if target.casefold().rstrip(".") == "localhost":
        # Pin the friendly name to a literal address. This prevents a modified
        # hosts file or resolver from turning the local-only command into a
        # scan of a non-loopback system between validation and execution.
        return "127.0.0.1"
    try:
        address = ipaddress.ip_address(target)
    except ValueError as exc:
        raise ValueError("scan-local accepts only localhost or a loopback IP") from exc
    if not address.is_loopback:
        raise ValueError("scan-local accepts only loopback IP addresses")
    return str(address)


def _parse_ports(value: str) -> tuple[int, ...]:
    try:
        ports = tuple(sorted({int(item.strip()) for item in value.split(",") if item.strip()}))
    except ValueError as exc:
        raise ValueError("--ports must be a comma-separated integer list") from exc
    if not ports or len(ports) > 1024 or any(not 1 <= port <= 65_535 for port in ports):
        raise ValueError("--ports must contain 1-1024 unique values between 1 and 65535")
    return ports


def _run_summary(state: RunState) -> dict[str, Any]:
    plan = state.plan
    return {
        "run_id": state.run_id,
        "task_id": state.task.id,
        "status": state.status.value,
        "plan": None
        if plan is None
        else {
            "id": plan.id,
            "version": plan.version,
            "status": plan.status.value,
            "nodes": [
                {
                    "id": node.id,
                    "goal": node.goal,
                    "status": node.status.value,
                    "attempt_count": node.attempt_count,
                    "evidence_ids": list(node.evidence_ids),
                    "finding_ids": list(node.finding_ids),
                }
                for node in plan.nodes
            ],
        },
        "evidence": [
            {
                "id": item.id,
                "type": item.type.value,
                "summary": item.summary,
                "content_hash": item.content_hash,
            }
            for item in state.evidence
        ],
        "findings": [
            {
                "id": finding.id,
                "title": finding.title,
                "severity": finding.severity.value,
                "confidence": finding.confidence,
                "status": finding.status.value,
                "evidence_ids": list(finding.evidence_ids),
            }
            for finding in state.findings
        ],
        "steps": state.step_count,
        "replans": state.replan_count,
        "error": state.last_error,
    }


if __name__ == "__main__":
    sys.exit(main())
