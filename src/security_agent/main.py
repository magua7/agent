"""Default ASGI entry point for ``uvicorn security_agent.main:app``."""

from __future__ import annotations

import os

from security_agent.interfaces.api import create_app

app = create_app()


def run() -> None:
    try:
        import uvicorn
    except ImportError as exc:
        raise RuntimeError('uvicorn is required; install SEC-GO with the "web" extra') from exc
    uvicorn.run(
        "security_agent.main:app",
        host=os.environ.get("SEC_GO_HOST", "127.0.0.1"),
        port=int(os.environ.get("SEC_GO_PORT", "8000")),
        workers=1,
    )


if __name__ == "__main__":
    run()
