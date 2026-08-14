"""Skill and knowledge provider ports."""

from __future__ import annotations

import string
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from security_agent.domain import TaskSpec, TaskType


class SkillRole(StrEnum):
    """The structural role a trusted skill may play in a workflow."""

    ROUTER = "router"
    LEAF = "leaf"
    QUALITY_GATE = "quality_gate"
    ORCHESTRATOR = "orchestrator"


class SkillRiskClass(StrEnum):
    """Policy risk classification; this is never an authorization grant."""

    PASSIVE = "passive"
    ACTIVE = "active"
    LAB_ONLY = "lab_only"


class SkillResourceLoading(StrEnum):
    """How much material may be loaded from a skill directory."""

    METADATA_ONLY = "metadata_only"
    LINKED_MARKDOWN = "linked_markdown"


class SkillSourceFormat(StrEnum):
    """On-disk metadata format used to construct a descriptor."""

    FRONTMATTER = "frontmatter"
    LEGACY_MANIFEST = "legacy_manifest"


class SkillDiagnosticSeverity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class SkillDiagnosticCode(StrEnum):
    ROOT_UNAVAILABLE = "root_unavailable"
    POLICY_INVALID = "policy_invalid"
    POLICY_TARGET_MISSING = "policy_target_missing"
    SKILL_INVALID = "skill_invalid"
    SKILL_UNCLASSIFIED = "skill_unclassified"
    SKILL_EXCLUDED = "skill_excluded"


@dataclass(frozen=True, slots=True)
class SkillPolicy:
    """Trusted policy assigned outside the untrusted ``SKILL.md`` body."""

    group_id: str
    enabled: bool
    task_types: tuple[TaskType, ...]
    role: SkillRole
    risk_class: SkillRiskClass
    required_capabilities: tuple[str, ...]
    human_approval_required: bool
    resource_loading: SkillResourceLoading

    def __post_init__(self) -> None:
        if not isinstance(self.group_id, str) or not self.group_id.strip():
            raise ValueError("skill policy group_id must be non-empty")
        object.__setattr__(self, "group_id", self.group_id.strip())
        if not isinstance(self.enabled, bool):
            raise ValueError("skill policy enabled must be boolean")
        task_types = tuple(self.task_types)
        if not all(isinstance(item, TaskType) for item in task_types):
            raise ValueError("skill policy task_types must contain TaskType values")
        if len(set(task_types)) != len(task_types):
            raise ValueError("skill policy task_types must be unique")
        object.__setattr__(self, "task_types", task_types)
        if not isinstance(self.role, SkillRole):
            raise ValueError("skill policy role must be a SkillRole")
        if not isinstance(self.risk_class, SkillRiskClass):
            raise ValueError("skill policy risk_class must be a SkillRiskClass")
        capabilities = tuple(self.required_capabilities)
        if not all(isinstance(item, str) and item.strip() for item in capabilities):
            raise ValueError("skill policy required_capabilities must be non-empty strings")
        capabilities = tuple(item.strip() for item in capabilities)
        if len(set(capabilities)) != len(capabilities):
            raise ValueError("skill policy required_capabilities must be unique")
        object.__setattr__(self, "required_capabilities", capabilities)
        if not isinstance(self.human_approval_required, bool):
            raise ValueError("skill policy human_approval_required must be boolean")
        if not isinstance(self.resource_loading, SkillResourceLoading):
            raise ValueError("skill policy resource_loading must be a SkillResourceLoading")


@dataclass(frozen=True, slots=True)
class SkillDescriptor:
    """Bounded catalog metadata for one discovered skill."""

    name: str
    description: str
    content_hash: str
    policy: SkillPolicy
    source_format: SkillSourceFormat
    resources: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("skill descriptor name must be non-empty")
        if not isinstance(self.description, str) or not self.description.strip():
            raise ValueError("skill descriptor description must be non-empty")
        object.__setattr__(self, "name", self.name.strip())
        object.__setattr__(self, "description", self.description.strip())
        if (
            not isinstance(self.content_hash, str)
            or len(self.content_hash) != 64
            or any(character not in string.hexdigits for character in self.content_hash)
        ):
            raise ValueError("skill descriptor content_hash must be a SHA-256 hex digest")
        object.__setattr__(self, "content_hash", self.content_hash.casefold())
        if not isinstance(self.policy, SkillPolicy):
            raise ValueError("skill descriptor policy must be a SkillPolicy")
        if not isinstance(self.source_format, SkillSourceFormat):
            raise ValueError("skill descriptor source_format must be a SkillSourceFormat")
        resources = tuple(self.resources)
        if not all(isinstance(item, str) and item for item in resources):
            raise ValueError("skill descriptor resources must contain non-empty strings")
        if len(set(resources)) != len(resources):
            raise ValueError("skill descriptor resources must be unique")
        object.__setattr__(self, "resources", resources)


@dataclass(frozen=True, slots=True)
class SkillDiagnostic:
    """A stable, non-secret explanation of a catalog decision or error."""

    code: SkillDiagnosticCode
    severity: SkillDiagnosticSeverity
    message: str
    skill_name: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.code, SkillDiagnosticCode):
            raise ValueError("skill diagnostic code must be a SkillDiagnosticCode")
        if not isinstance(self.severity, SkillDiagnosticSeverity):
            raise ValueError("skill diagnostic severity must be a SkillDiagnosticSeverity")
        if not isinstance(self.message, str) or not self.message.strip():
            raise ValueError("skill diagnostic message must be non-empty")
        object.__setattr__(self, "message", self.message.strip())
        if self.skill_name is not None:
            if not isinstance(self.skill_name, str) or not self.skill_name.strip():
                raise ValueError("skill diagnostic skill_name must be non-empty when present")
            object.__setattr__(self, "skill_name", self.skill_name.strip())


@dataclass(frozen=True, slots=True)
class SkillDocument:
    name: str
    description: str
    applicable_tasks: tuple[TaskType, ...]
    required_capabilities: tuple[str, ...]
    workflow_guidance: str
    verification_guidance: str
    references: tuple[str, ...] = ()
    policy: SkillPolicy | None = None
    resources: tuple[str, ...] = ()
    content_hash: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("skill document name must be non-empty")
        if not isinstance(self.description, str) or not self.description.strip():
            raise ValueError("skill document description must be non-empty")
        if not isinstance(self.workflow_guidance, str) or not self.workflow_guidance.strip():
            raise ValueError("skill document workflow_guidance must be non-empty")
        if (
            not isinstance(self.verification_guidance, str)
            or not self.verification_guidance.strip()
        ):
            raise ValueError("skill document verification_guidance must be non-empty")
        object.__setattr__(self, "name", self.name.strip())
        object.__setattr__(self, "description", self.description.strip())
        applicable = tuple(self.applicable_tasks)
        capabilities = tuple(self.required_capabilities)
        references = tuple(self.references)
        resources = tuple(self.resources)
        if not all(isinstance(item, TaskType) for item in applicable):
            raise ValueError("skill document applicable_tasks must contain TaskType values")
        if not all(isinstance(item, str) and item.strip() for item in capabilities):
            raise ValueError("skill document required_capabilities must contain non-empty strings")
        if not all(isinstance(item, str) and item for item in (*references, *resources)):
            raise ValueError(
                "skill document references and resources must contain non-empty strings"
            )
        object.__setattr__(self, "applicable_tasks", applicable)
        object.__setattr__(
            self, "required_capabilities", tuple(item.strip() for item in capabilities)
        )
        object.__setattr__(self, "references", references)
        object.__setattr__(self, "resources", resources)
        if self.content_hash is not None:
            if (
                not isinstance(self.content_hash, str)
                or len(self.content_hash) != 64
                or any(character not in string.hexdigits for character in self.content_hash)
            ):
                raise ValueError("skill document content_hash must be a SHA-256 hex digest")
            object.__setattr__(self, "content_hash", self.content_hash.casefold())
        if self.policy is not None:
            if not isinstance(self.policy, SkillPolicy):
                raise ValueError("skill document policy must be a SkillPolicy")
            if applicable != self.policy.task_types:
                raise ValueError("skill document applicable_tasks must match policy task_types")
            if tuple(item.strip() for item in capabilities) != self.policy.required_capabilities:
                raise ValueError(
                    "skill document required_capabilities must match policy required_capabilities"
                )


class SkillProvider(Protocol):
    async def select(self, task: TaskSpec) -> tuple[SkillDocument, ...]: ...


@dataclass(frozen=True, slots=True)
class KnowledgeDocument:
    id: str
    title: str
    content: str
    source: str


class KnowledgeProvider(Protocol):
    async def search(self, query: str, limit: int = 10) -> tuple[KnowledgeDocument, ...]: ...

    async def get(self, document_id: str) -> KnowledgeDocument | None: ...
