"""FastAPI application factory and optional production SPA hosting."""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from security_agent.application.bootstrap import (
    ProductServices,
    build_product_services,
    project_root,
)
from security_agent.interfaces.api.auth import router as auth_router
from security_agent.interfaces.api.tasks import router as tasks_router

ServicesFactory = Callable[[], Awaitable[ProductServices]]


def create_app(
    *,
    services: ProductServices | None = None,
    services_factory: ServicesFactory | None = None,
    frontend_dist: Path | None = None,
) -> FastAPI:
    if services is not None and services_factory is not None:
        raise ValueError("provide services or services_factory, not both")
    factory = services_factory or build_product_services

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        owned = services is None
        active = services or await factory()
        app.state.secgo_services = active
        try:
            yield
        finally:
            if owned:
                await active.close()

    app = FastAPI(
        title="SEC-GO API",
        version="0.1.0",
        description="Product API for the evidence-driven Security Agent Kernel.",
        lifespan=lifespan,
    )
    app.include_router(auth_router)
    app.include_router(tasks_router)

    @app.middleware("http")
    async def security_headers(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; "
            "base-uri 'self'; frame-ancestors 'none'",
        )
        if request.url.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    @app.get("/api/health", tags=["system"])
    async def health() -> dict[str, str]:
        return {"status": "ok", "service": "SEC-GO"}

    resolved_dist = (frontend_dist or project_root() / "frontend" / "dist").resolve()
    index_path = resolved_dist / "index.html"
    assets_path = resolved_dist / "assets"
    if index_path.is_file():
        if assets_path.is_dir():
            app.mount("/assets", StaticFiles(directory=assets_path), name="frontend-assets")

        @app.get("/", include_in_schema=False)
        async def frontend_index() -> FileResponse:
            return FileResponse(index_path)

        @app.get("/{requested_path:path}", include_in_schema=False)
        async def frontend_route(requested_path: str) -> FileResponse:
            if requested_path == "api" or requested_path.startswith("api/"):
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
            candidate = (resolved_dist / requested_path).resolve()
            if _is_within(candidate, resolved_dist) and candidate.is_file():
                return FileResponse(candidate)
            return FileResponse(index_path)
    else:

        @app.get("/", include_in_schema=False)
        async def api_root() -> JSONResponse:
            return JSONResponse(
                {
                    "name": "SEC-GO",
                    "api": "/docs",
                    "frontend": "not built; run the Vite development server or npm run build",
                }
            )

    return app


def _is_within(candidate: Path, root: Path) -> bool:
    try:
        candidate.relative_to(root)
    except ValueError:
        return False
    return True
