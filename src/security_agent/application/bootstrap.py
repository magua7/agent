"""Product composition root shared by the SEC-GO Web API and CLI."""

from __future__ import annotations

import asyncio
import os
import secrets
from dataclasses import dataclass
from pathlib import Path

from security_agent.application.auth_service import AuthService
from security_agent.application.run_service import RunService
from security_agent.application.settings import (
    ProductSettings,
    load_product_settings,
)
from security_agent.application.task_service import TaskService
from security_agent.engine import RunLimits
from security_agent.infrastructure.llm import (
    OpenAICompatibleConfig,
    OpenAICompatibleProvider,
)
from security_agent.infrastructure.storage.product import SQLiteProductStore
from security_agent.interfaces.bootstrap import RuntimeBundle, build_local_runtime


@dataclass(slots=True)
class ProductServices:
    auth: AuthService
    tasks: TaskService
    runs: RunService
    products: SQLiteProductStore
    runtime: RuntimeBundle
    database: Path
    settings: ProductSettings
    llm_provider: OpenAICompatibleProvider | None = None

    async def close(self) -> None:
        try:
            await self.runs.close()
        finally:
            try:
                await self.products.close()
            finally:
                try:
                    await self.runtime.close()
                finally:
                    if self.llm_provider is not None:
                        await self.llm_provider.aclose()


async def build_product_services(
    database: Path | None = None,
    *,
    jwt_secret: str | bytes | None = None,
    admin_username: str | None = None,
    admin_password: str | None = None,
    skills_root: Path | None = None,
    run_limits: RunLimits | None = None,
    max_concurrent_runs: int = 2,
    settings_path: Path | None = None,
) -> ProductServices:
    resolved_database = (database or default_database()).expanduser().resolve()
    resolved_database.parent.mkdir(parents=True, exist_ok=True)
    settings = (
        ProductSettings()
        if settings_path is None
        else await asyncio.to_thread(
            _load_resolved_settings,
            settings_path,
        )
    )
    llm_provider = _build_llm_provider(settings)
    try:
        runtime = await build_local_runtime(
            resolved_database,
            skills_root=skills_root or default_skills_root(),
            llm_provider=llm_provider,
            run_limits=run_limits,
            capture_events=False,
        )
    except BaseException:
        if llm_provider is not None:
            await llm_provider.aclose()
        raise
    products = SQLiteProductStore(resolved_database)
    try:
        await products.initialize()
        secret = jwt_secret or _load_or_create_secret(resolved_database.parent)
        auth = AuthService(products, secret)
        await auth.ensure_default_admin(
            username=admin_username or os.environ.get("SEC_GO_ADMIN_USERNAME", "admin"),
            password=admin_password or os.environ.get("SEC_GO_ADMIN_PASSWORD", "secgo"),
        )
        runs = RunService(
            runtime.runtime,
            products,
            runtime.store,
            max_concurrent_runs=max_concurrent_runs,
        )
        tasks = TaskService(products, runs, runtime.store)
        return ProductServices(
            auth=auth,
            tasks=tasks,
            runs=runs,
            products=products,
            runtime=runtime,
            database=resolved_database,
            settings=settings,
            llm_provider=llm_provider,
        )
    except BaseException:
        try:
            await products.close()
        finally:
            try:
                await runtime.close()
            finally:
                if llm_provider is not None:
                    await llm_provider.aclose()
        raise


async def build_default_product_services() -> ProductServices:
    """Build the CLI/Web product using the private root ``settings.json``."""
    return await build_product_services(settings_path=default_settings_path())


def project_root() -> Path:
    configured = os.environ.get("SEC_GO_ROOT")
    if configured:
        return Path(configured).expanduser().resolve()
    source_root = Path(__file__).resolve().parents[3]
    if (source_root / "pyproject.toml").is_file():
        return source_root
    return Path.cwd().resolve()


def default_database() -> Path:
    configured = os.environ.get("SEC_GO_DB")
    if configured:
        return Path(configured)
    data_dir = os.environ.get("SEC_GO_DATA_DIR")
    return (Path(data_dir) if data_dir else project_root() / "data") / "sec-go.db"


def default_settings_path() -> Path:
    return project_root() / "settings.json"


def default_skills_root() -> Path | None:
    configured = os.environ.get("SEC_GO_SKILLS_DIR")
    if configured:
        return Path(configured).expanduser().resolve()
    candidate = project_root() / "skills"
    return candidate if (candidate / "policy.json").is_file() else None


def _load_or_create_secret(data_directory: Path) -> bytes:
    configured = os.environ.get("SEC_GO_SECRET_KEY")
    if configured:
        encoded = configured.encode("utf-8")
        if len(encoded) < 32:
            raise ValueError("SEC_GO_SECRET_KEY must contain at least 32 UTF-8 bytes")
        return encoded
    secret_path = data_directory / ".sec-go-secret"
    try:
        existing = secret_path.read_bytes().strip()
    except FileNotFoundError:
        generated = secrets.token_urlsafe(48).encode("ascii")
        try:
            with secret_path.open("xb") as handle:
                handle.write(generated)
        except FileExistsError:
            existing = secret_path.read_bytes().strip()
        else:
            return generated
    if len(existing) < 32:
        raise ValueError(f"JWT secret file is invalid: {secret_path}")
    return existing


def _build_llm_provider(settings: ProductSettings) -> OpenAICompatibleProvider | None:
    llm = settings.llm
    if not llm.enabled:
        return None
    return OpenAICompatibleProvider(
        OpenAICompatibleConfig(
            base_url=llm.base_url,
            api_key=llm.api_key,
            model=llm.model,
            timeout_seconds=llm.timeout_seconds,
            max_response_bytes=llm.max_response_bytes,
        )
    )


def _load_resolved_settings(path: Path) -> ProductSettings:
    return load_product_settings(path.expanduser().resolve())
