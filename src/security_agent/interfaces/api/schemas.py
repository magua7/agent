"""HTTP request schemas; application responses remain explicit read projections."""

from __future__ import annotations

from pydantic import BaseModel, Field


class StrictRequest(BaseModel):
    class Config:
        extra = "forbid"


class LoginRequest(StrictRequest):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=128)


class CreateTaskRequest(StrictRequest):
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1, max_length=20_000)
    target: str | None = Field(default=None, max_length=128)
    ports: list[int] | None = None
