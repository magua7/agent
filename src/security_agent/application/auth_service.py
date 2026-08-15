"""Password authentication and compact HS256 JWT support for SEC-GO.

This module deliberately has no FastAPI dependency.  Both the Web interface and
other product adapters can use the same authentication rules.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from importlib import import_module
from typing import Protocol, cast


class AuthenticationError(ValueError):
    """Base class for deliberately non-specific authentication failures."""


class InvalidCredentialsError(AuthenticationError):
    pass


class InvalidTokenError(AuthenticationError):
    pass


class PasswordPolicyError(AuthenticationError):
    pass


class AuthenticatedUser(Protocol):
    @property
    def id(self) -> str: ...

    @property
    def username(self) -> str: ...

    @property
    def password_hash(self) -> str: ...


class AuthRepository(Protocol):
    async def get_user_by_username(self, username: str) -> AuthenticatedUser | None: ...

    async def get_user(self, user_id: str) -> AuthenticatedUser | None: ...

    async def create_user(
        self,
        username: str,
        password_hash: str,
    ) -> AuthenticatedUser: ...


class _BcryptModule(Protocol):
    def gensalt(self, rounds: int = 12) -> bytes: ...

    def hashpw(self, password: bytes, salt: bytes) -> bytes: ...

    def checkpw(self, password: bytes, hashed_password: bytes) -> bool: ...


@dataclass(frozen=True, slots=True)
class TokenPrincipal:
    user_id: str
    username: str
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class AccessToken:
    access_token: str
    expires_in: int
    principal: TokenPrincipal
    token_type: str = "bearer"


def hash_password(password: str, *, rounds: int = 12) -> str:
    encoded = _validated_password(password)
    if not 4 <= rounds <= 16:
        raise ValueError("bcrypt rounds must be between 4 and 16")
    bcrypt = _load_bcrypt()
    return bcrypt.hashpw(encoded, bcrypt.gensalt(rounds=rounds)).decode("ascii")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        encoded = _validated_password(password)
    except PasswordPolicyError:
        return False
    if not isinstance(password_hash, str) or not password_hash.startswith(("$2a$", "$2b$")):
        return False
    try:
        return bool(_load_bcrypt().checkpw(encoded, password_hash.encode("ascii")))
    except (ValueError, UnicodeEncodeError):
        return False


class AuthService:
    """Authenticate users and issue short-lived, locally signed bearer tokens."""

    def __init__(
        self,
        repository: AuthRepository,
        secret: str | bytes,
        *,
        token_ttl: timedelta = timedelta(hours=8),
        issuer: str = "sec-go",
        audience: str = "sec-go-web",
        clock: Callable[[], datetime] | None = None,
        bcrypt_rounds: int = 12,
    ) -> None:
        secret_bytes = secret.encode("utf-8") if isinstance(secret, str) else bytes(secret)
        if len(secret_bytes) < 32:
            raise ValueError("JWT secret must contain at least 32 bytes")
        if token_ttl <= timedelta(0):
            raise ValueError("token_ttl must be positive")
        if not issuer or not audience:
            raise ValueError("issuer and audience must be non-empty")
        if not 4 <= bcrypt_rounds <= 16:
            raise ValueError("bcrypt_rounds must be between 4 and 16")
        self._repository = repository
        self._secret = secret_bytes
        self._token_ttl = token_ttl
        self._issuer = issuer
        self._audience = audience
        self._clock = clock or (lambda: datetime.now(UTC))
        self._bcrypt_rounds = bcrypt_rounds

    async def ensure_default_admin(
        self,
        *,
        username: str = "admin",
        password: str = "secgo",
    ) -> AuthenticatedUser:
        normalized = _validated_username(username)
        existing = await self._repository.get_user_by_username(normalized)
        if existing is not None:
            return existing
        password_hash = await asyncio.to_thread(
            hash_password,
            password,
            rounds=self._bcrypt_rounds,
        )
        return await self._repository.create_user(normalized, password_hash)

    async def login(self, username: str, password: str) -> AccessToken:
        normalized = _validated_username(username)
        user = await self._repository.get_user_by_username(normalized)
        valid = False
        if user is not None:
            valid = await asyncio.to_thread(verify_password, password, user.password_hash)
        if user is None or not valid:
            raise InvalidCredentialsError("invalid username or password")
        return self.issue_token(user)

    def issue_token(self, user: AuthenticatedUser) -> AccessToken:
        now = _aware_utc(self._clock())
        expires_at = now + self._token_ttl
        principal = TokenPrincipal(
            user_id=user.id,
            username=user.username,
            issued_at=now,
            expires_at=expires_at,
        )
        header: dict[str, object] = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "sub": principal.user_id,
            "username": principal.username,
            "iat": int(now.timestamp()),
            "exp": int(expires_at.timestamp()),
            "iss": self._issuer,
            "aud": self._audience,
        }
        encoded_header = _encode_segment(header)
        encoded_payload = _encode_segment(payload)
        signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
        signature = hmac.new(self._secret, signing_input, hashlib.sha256).digest()
        token = f"{encoded_header}.{encoded_payload}.{_b64url_encode(signature)}"
        return AccessToken(
            access_token=token,
            expires_in=max(1, int(self._token_ttl.total_seconds())),
            principal=principal,
        )

    def verify_token(self, token: str) -> TokenPrincipal:
        if not isinstance(token, str) or not token or len(token) > 8_192:
            raise InvalidTokenError("invalid bearer token")
        parts = token.split(".")
        if len(parts) != 3 or any(not part for part in parts):
            raise InvalidTokenError("invalid bearer token")
        encoded_header, encoded_payload, encoded_signature = parts
        try:
            header = _decode_object(encoded_header)
            payload = _decode_object(encoded_payload)
            signature = _b64url_decode(encoded_signature)
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
            raise InvalidTokenError("invalid bearer token") from exc
        if header != {"alg": "HS256", "typ": "JWT"}:
            raise InvalidTokenError("unsupported JWT header")
        signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
        expected = hmac.new(self._secret, signing_input, hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected):
            raise InvalidTokenError("invalid bearer token")

        subject = payload.get("sub")
        username = payload.get("username")
        issued = payload.get("iat")
        expires = payload.get("exp")
        if (
            not isinstance(subject, str)
            or not subject
            or not isinstance(username, str)
            or not username
            or isinstance(issued, bool)
            or not isinstance(issued, int)
            or isinstance(expires, bool)
            or not isinstance(expires, int)
            or payload.get("iss") != self._issuer
            or payload.get("aud") != self._audience
        ):
            raise InvalidTokenError("invalid JWT claims")
        issued_at = datetime.fromtimestamp(issued, UTC)
        expires_at = datetime.fromtimestamp(expires, UTC)
        now = _aware_utc(self._clock())
        if issued_at > now + timedelta(seconds=30) or expires_at <= now or expires_at <= issued_at:
            raise InvalidTokenError("expired or invalid bearer token")
        return TokenPrincipal(subject, username, issued_at, expires_at)

    async def authenticate_token(self, token: str) -> AuthenticatedUser:
        principal = self.verify_token(token)
        user = await self._repository.get_user(principal.user_id)
        if user is None or user.username != principal.username:
            raise InvalidTokenError("token user no longer exists")
        return user


def _validated_username(username: str) -> str:
    if not isinstance(username, str):
        raise InvalidCredentialsError("invalid username or password")
    normalized = username.strip()
    if (
        not normalized
        or len(normalized) > 128
        or any(character.isspace() for character in normalized)
    ):
        raise InvalidCredentialsError("invalid username or password")
    return normalized


def _validated_password(password: str) -> bytes:
    if not isinstance(password, str) or not password:
        raise PasswordPolicyError("password must be non-empty")
    encoded = password.encode("utf-8")
    if len(encoded) > 72:
        raise PasswordPolicyError("password cannot exceed 72 UTF-8 bytes with bcrypt")
    return encoded


def _load_bcrypt() -> _BcryptModule:
    try:
        module = import_module("bcrypt")
    except ImportError as exc:  # pragma: no cover - exercised by clean-install checks
        raise RuntimeError('bcrypt is required; install SEC-GO with the "web" extra') from exc
    return cast(_BcryptModule, module)


def _aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("authentication clock must return an aware datetime")
    return value.astimezone(UTC)


def _encode_segment(value: Mapping[str, object]) -> str:
    raw = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode(
        "utf-8"
    )
    return _b64url_encode(raw)


def _decode_object(value: str) -> dict[str, object]:
    decoded = json.loads(_b64url_decode(value).decode("utf-8"))
    if not isinstance(decoded, dict) or not all(isinstance(key, str) for key in decoded):
        raise ValueError("JWT segment must contain an object")
    return decoded


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    if not value or any(
        character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        for character in value
    ):
        raise ValueError("invalid base64url")
    padding = "=" * (-len(value) % 4)
    return base64.b64decode(value + padding, altchars=b"-_", validate=True)
