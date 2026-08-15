"""Authentication routes."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from security_agent.application.auth_service import InvalidCredentialsError
from security_agent.application.bootstrap import ProductServices
from security_agent.application.models import ProductUser
from security_agent.interfaces.api.dependencies import get_current_user, get_services
from security_agent.interfaces.api.schemas import LoginRequest

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/login")
async def login(
    body: LoginRequest,
    services: Annotated[ProductServices, Depends(get_services)],
) -> dict[str, object]:
    try:
        token = await services.auth.login(body.username, body.password)
    except InvalidCredentialsError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    return {
        "access_token": token.access_token,
        "token_type": token.token_type,
        "expires_in": token.expires_in,
        "user": {
            "id": token.principal.user_id,
            "username": token.principal.username,
        },
    }


@router.get("/me")
async def me(user: Annotated[ProductUser, Depends(get_current_user)]) -> dict[str, str]:
    return {"id": user.id, "username": user.username}
