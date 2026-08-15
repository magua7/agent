"""Product composition root shared by the SEC-GO Web API and CLI."""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from pathlib import Path

from security_agent.application.auth_service import AuthService
from security_agent.application.run_service import RunService
from security_agent.application.task_service import TaskService
from security_agent.engine import RunLimits
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

    async def close(self) -> None:
        await self.runs.close()
        await self.products.close()
        await self.runtime.close()


async def build_product_services(
    database: Path | None = None,
    *,
    jwt_secret: str | bytes | None = None,
    admin_username: str | None = None,
    admin_password: str | None = None,
    skills_root: Path | None = None,
    run_limits: RunLimits | None = None,
    max_concurrent_runs: int = 2,
) -> ProductServices:
    resolved_database = (database or default_database()).expanduser().resolve()
    resolved_database.parent.mkdir(parents=True, exist_ok=True)
    runtime = await build_local_runtime(
        resolved_database,
        skills_root=skills_root or default_skills_root(),
        run_limits=run_limits,
        capture_events=False,
    )
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
        )
    except Exception:
        await products.close()
        await runtime.close()
        raise


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
