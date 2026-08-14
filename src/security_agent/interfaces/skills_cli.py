"""Read-only CLI operations for policy-backed Skill catalogs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from security_agent.contracts import (
    SkillDescriptor,
    SkillDiagnostic,
    SkillDiagnosticSeverity,
    SkillDocument,
    SkillPolicy,
)
from security_agent.domain import ScopeSpec, TaskSpec, TaskType
from security_agent.infrastructure.skills import FilesystemSkillProvider
from security_agent.infrastructure.tools import build_default_tool_registry


def add_skills_parser(subparsers: Any) -> None:
    """Register the read-only ``skills`` command family."""

    skills = subparsers.add_parser(
        "skills",
        help="inspect and diagnose a policy-backed Skill catalog",
    )
    actions = skills.add_subparsers(dest="skills_action", required=True)

    list_parser = actions.add_parser("list", help="list catalog metadata without returning bodies")
    _add_root_argument(list_parser)
    list_parser.add_argument(
        "--enabled-only",
        action="store_true",
        help="hide cataloged skills that policy keeps disabled",
    )
    list_parser.add_argument(
        "--exclude-lab-only",
        action="store_true",
        help="hide lab-only skills (active entries may still be listed)",
    )

    doctor = actions.add_parser("doctor", help="validate the complete catalog and trusted policy")
    _add_root_argument(doctor)
    doctor.add_argument(
        "--strict",
        action="store_true",
        help="also return a failing exit code when warnings are present",
    )

    recommend = actions.add_parser(
        "recommend",
        help="rank enabled, capability-compatible skills for a task",
    )
    _add_root_argument(recommend)
    recommend.add_argument("objective", help="task objective used only for local relevance ranking")
    recommend.add_argument(
        "--task-type",
        choices=tuple(item.value for item in TaskType),
        default=TaskType.GENERIC.value,
    )
    recommend.add_argument("--max-results", type=int, default=4)

    show = actions.add_parser("show", help="show trusted metadata for one skill")
    _add_root_argument(show)
    show.add_argument("name")
    show.add_argument(
        "--body",
        action="store_true",
        help="also load the bounded SKILL.md body as untrusted guidance",
    )
    show.add_argument(
        "--allow-disabled",
        action="store_true",
        help="permit explicit body inspection for a policy-disabled skill",
    )
    show.add_argument(
        "--allow-lab-only",
        action="store_true",
        help="permit explicit body inspection for a lab-only skill",
    )

    resource = actions.add_parser(
        "resource",
        help="read one policy-indexed, same-directory Markdown resource",
    )
    _add_root_argument(resource)
    resource.add_argument("name")
    resource.add_argument("path")
    resource.add_argument(
        "--allow-disabled",
        action="store_true",
        help="permit explicit resource inspection for a policy-disabled skill",
    )
    resource.add_argument(
        "--allow-lab-only",
        action="store_true",
        help="permit explicit resource inspection for a lab-only skill",
    )


async def run_skills_command(args: argparse.Namespace) -> int:
    """Execute one read-only Skill catalog command."""

    root = _resolved_root(args.root)
    action = args.skills_action
    if action == "list":
        return await _list_skills(root, args.enabled_only, args.exclude_lab_only)
    if action == "doctor":
        return await _doctor(root, args.strict)
    if action == "recommend":
        return await _recommend(root, args.objective, args.task_type, args.max_results)
    if action == "show":
        return await _show(
            root,
            args.name,
            include_body=args.body,
            allow_disabled=args.allow_disabled,
            allow_lab_only=args.allow_lab_only,
        )
    if action == "resource":
        return await _resource(
            root,
            args.name,
            args.path,
            allow_disabled=args.allow_disabled,
            allow_lab_only=args.allow_lab_only,
        )
    raise ValueError(f"unsupported skills action {action!r}")


def _add_root_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--root",
        type=Path,
        required=True,
        help="explicit catalog root containing policy.json and Skill directories",
    )


def _resolved_root(root: Path) -> Path:
    resolved = root.resolve()
    if not resolved.is_dir():
        raise ValueError(f"skill root is not a directory: {resolved}")
    return resolved


async def _list_skills(root: Path, enabled_only: bool, exclude_lab_only: bool) -> int:
    provider = FilesystemSkillProvider(root)
    descriptors = await provider.list_descriptors(
        include_disabled=not enabled_only,
        include_lab_only=not exclude_lab_only,
    )
    _print_json(
        {
            "root": str(root),
            "count": len(descriptors),
            "skills": [_descriptor_payload(item) for item in descriptors],
            "diagnostics": [_diagnostic_payload(item) for item in provider.diagnostics],
        }
    )
    return 0


async def _doctor(root: Path, strict: bool) -> int:
    provider = FilesystemSkillProvider(root)
    descriptors = await provider.refresh()
    diagnostics = provider.diagnostics
    errors = sum(item.severity is SkillDiagnosticSeverity.ERROR for item in diagnostics)
    warnings = sum(item.severity is SkillDiagnosticSeverity.WARNING for item in diagnostics)
    _print_json(
        {
            "root": str(root),
            "valid_skills": len(descriptors),
            "errors": errors,
            "warnings": warnings,
            "diagnostics": [_diagnostic_payload(item) for item in diagnostics],
        }
    )
    return 2 if errors or (strict and warnings) else 0


async def _recommend(root: Path, objective: str, task_type: str, max_results: int) -> int:
    if not objective.strip():
        raise ValueError("objective must be non-empty")
    if not 1 <= max_results <= 20:
        raise ValueError("--max-results must be between 1 and 20")
    provider = FilesystemSkillProvider(
        root,
        max_selected=max_results,
        available_capabilities=_available_capabilities(),
    )
    selected = await provider.select(
        TaskSpec.create(
            objective=objective,
            task_type=TaskType(task_type),
            scope=ScopeSpec(),
            success_criteria=("Produce a tool-evidenced result for the stated objective",),
        )
    )
    _print_json(
        {
            "root": str(root),
            "objective": objective,
            "task_type": task_type,
            "count": len(selected),
            "skills": [_document_summary(item) for item in selected],
            "diagnostics": [_diagnostic_payload(item) for item in provider.diagnostics],
        }
    )
    return 0


async def _show(
    root: Path,
    name: str,
    *,
    include_body: bool,
    allow_disabled: bool,
    allow_lab_only: bool,
) -> int:
    provider = FilesystemSkillProvider(root)
    descriptors = await provider.list_descriptors()
    descriptor = next((item for item in descriptors if item.name == name), None)
    if descriptor is None:
        raise ValueError(f"unknown skill {name!r}")
    payload: dict[str, object] = _descriptor_payload(descriptor)
    if include_body:
        document = await provider.get_document(
            name,
            allow_disabled=allow_disabled,
            allow_lab_only=allow_lab_only,
        )
        if document is None:
            requirements: list[str] = []
            if not descriptor.policy.enabled:
                requirements.append("--allow-disabled")
            if descriptor.policy.risk_class.value == "lab_only":
                requirements.append("--allow-lab-only")
            suffix = " and ".join(requirements) or "the catalog policy"
            raise ValueError(f"skill body access requires {suffix}")
        payload["body"] = _document_payload(document)
    _print_json(payload)
    return 0


async def _resource(
    root: Path,
    name: str,
    relative_path: str,
    *,
    allow_disabled: bool,
    allow_lab_only: bool,
) -> int:
    provider = FilesystemSkillProvider(root)
    content = await provider.read_resource(
        name,
        relative_path,
        allow_disabled=allow_disabled,
        allow_lab_only=allow_lab_only,
    )
    _print_json(
        {
            "root": str(root),
            "skill": name,
            "path": relative_path,
            "content": content,
        }
    )
    return 0


def _available_capabilities() -> frozenset[str]:
    return frozenset(
        capability
        for tool in build_default_tool_registry().list()
        for capability in tool.capabilities
    )


def _descriptor_payload(descriptor: SkillDescriptor) -> dict[str, object]:
    return {
        "name": descriptor.name,
        "description": descriptor.description,
        "content_hash": descriptor.content_hash,
        "source_format": descriptor.source_format.value,
        "resources": list(descriptor.resources),
        "policy": _policy_payload(descriptor.policy),
    }


def _policy_payload(policy: SkillPolicy) -> dict[str, object]:
    return {
        "group": policy.group_id,
        "enabled": policy.enabled,
        "task_types": [item.value for item in policy.task_types],
        "role": policy.role.value,
        "risk_class": policy.risk_class.value,
        "required_capabilities": list(policy.required_capabilities),
        "human_approval_required": policy.human_approval_required,
        "resource_loading": policy.resource_loading.value,
    }


def _diagnostic_payload(diagnostic: SkillDiagnostic) -> dict[str, object]:
    return {
        "code": diagnostic.code.value,
        "severity": diagnostic.severity.value,
        "skill": diagnostic.skill_name,
        "message": diagnostic.message,
    }


def _document_summary(document: SkillDocument) -> dict[str, object]:
    return {
        "name": document.name,
        "description": document.description,
        "policy": None if document.policy is None else _policy_payload(document.policy),
    }


def _document_payload(document: SkillDocument) -> dict[str, object]:
    return {
        "workflow_guidance": document.workflow_guidance,
        "verification_guidance": document.verification_guidance,
        "references": list(document.references),
        "resources": list(document.resources),
        "untrusted_guidance": True,
    }


def _print_json(value: object) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))
