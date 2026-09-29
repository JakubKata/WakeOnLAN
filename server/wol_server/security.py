from __future__ import annotations

import asyncio
import hashlib
import hmac
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

MAX_CONCURRENT_HASHES = 4
# Crockford-style base32 without I, L, O, U: easy to read from an e-mail and retype.
RESET_CODE_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
RESET_CODE_LENGTH = 10


class Security:
    """Password hashing and token handling.

    Tokens (sessions, claims, device secrets) are high-entropy, so a keyed
    HMAC is enough to make a leaked database useless without the pepper.
    """

    def __init__(self, pepper: bytes, hasher: PasswordHasher | None = None):
        self._pepper = pepper
        self._hasher = hasher or PasswordHasher()
        self._dummy_hash = self._hasher.hash(secrets.token_urlsafe(16))
        self._hash_slots = asyncio.Semaphore(MAX_CONCURRENT_HASHES)

    async def hash_password(self, password: str) -> str:
        async with self._hash_slots:
            return await asyncio.to_thread(self._hasher.hash, password)

    async def verify_password(self, stored_hash: str | None, password: str) -> bool:
        """Check a password; with no stored hash, burn the same CPU time and fail."""
        async with self._hash_slots:
            ok = await asyncio.to_thread(self._verify, stored_hash or self._dummy_hash, password)
        return ok and stored_hash is not None

    def needs_rehash(self, stored_hash: str) -> bool:
        return self._hasher.check_needs_rehash(stored_hash)

    def _verify(self, stored_hash: str, password: str) -> bool:
        try:
            return self._hasher.verify(stored_hash, password)
        except (VerificationError, InvalidHashError):
            return False

    def token_hash(self, token: str) -> str:
        return hmac.new(self._pepper, token.encode(), hashlib.sha256).hexdigest()

    @staticmethod
    def new_token(nbytes: int = 32) -> str:
        return secrets.token_urlsafe(nbytes)

    @staticmethod
    def new_reset_code() -> str:
        """50 random bits; guessing is bounded by per-code attempts and rate limits."""
        return "".join(secrets.choice(RESET_CODE_ALPHABET) for _ in range(RESET_CODE_LENGTH))
