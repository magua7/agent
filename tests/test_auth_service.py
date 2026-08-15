from __future__ import annotations

import unittest
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from security_agent.application.auth_service import (
    AuthService,
    InvalidCredentialsError,
    InvalidTokenError,
    PasswordPolicyError,
    hash_password,
    verify_password,
)


@dataclass(frozen=True)
class _User:
    id: str
    username: str
    password_hash: str


class _Repository:
    def __init__(self) -> None:
        self.users: dict[str, _User] = {}
        self.create_count = 0

    async def get_user_by_username(self, username: str) -> _User | None:
        return next((user for user in self.users.values() if user.username == username), None)

    async def get_user(self, user_id: str) -> _User | None:
        return self.users.get(user_id)

    async def create_user(self, username: str, password_hash: str) -> _User:
        self.create_count += 1
        user = _User(f"user-{self.create_count}", username, password_hash)
        self.users[user.id] = user
        return user


class AuthServiceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.now = datetime(2026, 8, 15, 8, 0, tzinfo=UTC)
        self.repository = _Repository()
        self.service = AuthService(
            self.repository,
            "test-secret-that-is-at-least-thirty-two-bytes-long",
            token_ttl=timedelta(minutes=30),
            clock=lambda: self.now,
            bcrypt_rounds=4,
        )

    async def test_default_admin_is_seeded_once_with_bcrypt(self) -> None:
        first = await self.service.ensure_default_admin()
        second = await self.service.ensure_default_admin()

        self.assertEqual(first, second)
        self.assertEqual(1, self.repository.create_count)
        self.assertNotIn("secgo", first.password_hash)
        self.assertTrue(first.password_hash.startswith("$2b$"))
        self.assertTrue(verify_password("secgo", first.password_hash))

    async def test_login_and_bearer_round_trip(self) -> None:
        user = await self.service.ensure_default_admin()
        result = await self.service.login("admin", "secgo")

        self.assertEqual("bearer", result.token_type)
        self.assertEqual(1_800, result.expires_in)
        self.assertEqual(user, await self.service.authenticate_token(result.access_token))
        self.assertEqual(user.id, self.service.verify_token(result.access_token).user_id)

    async def test_wrong_password_token_tampering_and_expiry_fail_closed(self) -> None:
        await self.service.ensure_default_admin()
        with self.assertRaises(InvalidCredentialsError):
            await self.service.login("admin", "wrong")

        token = (await self.service.login("admin", "secgo")).access_token
        replacement = "A" if token[-1] != "A" else "B"
        with self.assertRaises(InvalidTokenError):
            self.service.verify_token(token[:-1] + replacement)

        self.now += timedelta(minutes=31)
        with self.assertRaises(InvalidTokenError):
            self.service.verify_token(token)

    async def test_deleted_user_invalidates_an_otherwise_valid_token(self) -> None:
        user = await self.service.ensure_default_admin()
        token = (await self.service.login("admin", "secgo")).access_token
        del self.repository.users[user.id]

        with self.assertRaises(InvalidTokenError):
            await self.service.authenticate_token(token)

    def test_bcrypt_password_byte_limit_is_explicit(self) -> None:
        with self.assertRaises(PasswordPolicyError):
            hash_password("密" * 25, rounds=4)
        self.assertFalse(verify_password("密" * 25, "$2b$04$invalid"))

    def test_short_signing_secret_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            AuthService(self.repository, "too-short")


if __name__ == "__main__":
    unittest.main()
