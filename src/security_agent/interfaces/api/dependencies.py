"""FastAPI dependencies kept at the HTTP boundary."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from security_agent.application.auth_service import InvalidTokenError
from security_agent.application.bootstrap import ProductServices
from security_agent.application.models import ProductUser

_bearer = HTTPBearer(auto_error=False)


def get_services(request: Request) -> ProductServices:
    services = getattr(request.app.state, "secgo_services", None)
    if not isinstance(services, ProductServices):
        raise RuntimeError("SEC-GO application services are not initialized")
    return services


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    services: Annotated[ProductServices, Depends(get_services)],
) -> ProductUser:
    if credentials is None or credentials.scheme.casefold() != "bearer":
        raise _unauthorized()
    try:
        user = await services.auth.authenticate_token(credentials.credentials)
    except InvalidTokenError as exc:
        raise _unauthorized() from exc
    if not isinstance(user, ProductUser):
        raise _unauthorized()
    return user


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="invalid or expired bearer token",
        headers={"WWW-Authenticate": "Bearer"},
    )
