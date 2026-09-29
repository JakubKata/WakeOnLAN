"""PostgreSQL persistence via an asyncpg connection pool.

Lookups return None when nothing matches; mutations of a missing or foreign
record raise CommandError(NOT_FOUND).
"""

from __future__ import annotations

import hmac
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta

import asyncpg

from ..errors import CommandError
from ..protocol import Err
from . import schema

MAX_SESSIONS_PER_USER = 20
MAX_DEVICES_PER_USER = 10
MAX_TARGETS_PER_USER = 64


@dataclass(frozen=True, slots=True)
class User:
    id: int
    name: str
    email: str
    password_hash: str
    # Bumped by every revocation; a session may only be created for the epoch it was authorized in.
    session_epoch: int


@dataclass(frozen=True, slots=True)
class Device:
    id: str
    user_id: int
    name: str
    last_seen_at: datetime | None


@dataclass(frozen=True, slots=True)
class Target:
    id: int
    device_id: str | None
    mac: str
    name: str


class Database:
    def __init__(self, dsn: str, *, schema: str | None = None, max_connections: int = 10):
        self._dsn = dsn
        self._schema = schema
        self._max_connections = max_connections
        self._pool: asyncpg.Pool | None = None

    async def connect(self) -> None:
        self._pool = await asyncpg.create_pool(
            self._dsn,
            min_size=1,
            max_size=self._max_connections,
            command_timeout=10,
            server_settings={"search_path": self._schema} if self._schema else None,
        )

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None

    @property
    def pool(self) -> asyncpg.Pool:
        if self._pool is None:
            raise RuntimeError("database is not connected")
        return self._pool

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[asyncpg.Connection]:
        async with self.pool.acquire() as conn, conn.transaction():
            yield conn

    async def migrate(self) -> int:
        async with self.transaction() as conn:
            return await schema.migrate(conn)


def _affected(status: str) -> int:
    """Row count from a command status such as ``UPDATE 1`` or ``DELETE 0``."""
    return int(status.rsplit(" ", 1)[-1])


def _require_row(status: str) -> None:
    if _affected(status) == 0:
        raise CommandError(Err.NOT_FOUND)


def _ttl(seconds: int) -> timedelta:
    return timedelta(seconds=seconds)


def _user(row: asyncpg.Record | None) -> User | None:
    if row is None:
        return None
    return User(row["id"], row["name"], row["email"], row["password_hash"], row["session_epoch"])


def _device(row: asyncpg.Record) -> Device:
    return Device(row["id"], row["user_id"], row["name"], row["last_seen_at"])


def _target(row: asyncpg.Record) -> Target:
    return Target(row["id"], row["device_id"], row["mac"], row["name"])


async def _lock_user(conn: asyncpg.Connection, user_id: int) -> None:
    """Serialize per-user limit checks against concurrent inserts."""
    if await conn.fetchval("SELECT 1 FROM users WHERE id = $1 FOR UPDATE", user_id) is None:
        raise CommandError(Err.NOT_FOUND)


async def _owns_device(conn: asyncpg.Connection, user_id: int, device_id: str) -> bool:
    row = await conn.fetchval(
        "SELECT 1 FROM devices WHERE id = $1 AND user_id = $2", device_id, user_id
    )
    return row is not None


async def _insert_session(conn: asyncpg.Connection, user_id: int, token_hash: str, ttl: int) -> None:
    await conn.execute(
        "INSERT INTO sessions (token_hash, user_id, expires_at) VALUES ($1, $2, now() + $3::interval)",
        token_hash, user_id, _ttl(ttl),
    )
    await conn.execute(
        """
        DELETE FROM sessions WHERE user_id = $1 AND token_hash NOT IN (
            SELECT token_hash FROM sessions WHERE user_id = $1
            ORDER BY last_used_at DESC LIMIT $2
        )
        """,
        user_id, MAX_SESSIONS_PER_USER,
    )


async def _revoke_credentials(conn: asyncpg.Connection, user_id: int) -> int:
    """Invalidate everything issued to a user so far; return the new session epoch."""
    epoch = await conn.fetchval(
        "UPDATE users SET session_epoch = session_epoch + 1 WHERE id = $1 RETURNING session_epoch",
        user_id,
    )
    if epoch is None:
        raise CommandError(Err.NOT_FOUND)
    await conn.execute("DELETE FROM sessions WHERE user_id = $1", user_id)
    await conn.execute("DELETE FROM password_resets WHERE user_id = $1", user_id)
    await conn.execute("DELETE FROM claims WHERE user_id = $1", user_id)
    return epoch


class UsersRepo:
    def __init__(self, db: Database):
        self._db = db

    async def register(self, name: str, email: str, password_hash: str, token_hash: str, ttl: int) -> int:
        """Create a user together with its first session, so neither exists without the other."""
        try:
            async with self._db.transaction() as conn:
                user_id = await conn.fetchval(
                    "INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id",
                    name, email, password_hash,
                )
                await _insert_session(conn, user_id, token_hash, ttl)
                return user_id
        except asyncpg.UniqueViolationError:
            raise CommandError(Err.ACCOUNT_EXISTS) from None

    async def by_name(self, name: str) -> User | None:
        return _user(await self._db.pool.fetchrow(
            "SELECT * FROM users WHERE lower(name) = lower($1)", name
        ))

    async def by_email(self, email: str) -> User | None:
        return _user(await self._db.pool.fetchrow(
            "SELECT * FROM users WHERE lower(email) = lower($1)", email
        ))

    async def by_id(self, user_id: int) -> User | None:
        return _user(await self._db.pool.fetchrow("SELECT * FROM users WHERE id = $1", user_id))

    async def rehash_password(self, user_id: int, old_hash: str, new_hash: str) -> None:
        """Upgrade the hash parameters; a no-op if the password changed in the meantime."""
        await self._db.pool.execute(
            "UPDATE users SET password_hash = $1 WHERE id = $2 AND password_hash = $3",
            new_hash, user_id, old_hash,
        )

    async def change_password(self, user_id: int, password_hash: str) -> int:
        """Set a new password and revoke all sessions, reset codes and claims; return the new epoch."""
        async with self._db.transaction() as conn:
            _require_row(await conn.execute(
                "UPDATE users SET password_hash = $1 WHERE id = $2", password_hash, user_id
            ))
            return await _revoke_credentials(conn, user_id)

    async def revoke_all(self, user_id: int) -> int:
        """Revoke all sessions, reset codes and claims; return the new epoch."""
        async with self._db.transaction() as conn:
            return await _revoke_credentials(conn, user_id)

    async def rename(self, user_id: int, new_name: str) -> None:
        try:
            status = await self._db.pool.execute(
                "UPDATE users SET name = $1 WHERE id = $2", new_name, user_id
            )
        except asyncpg.UniqueViolationError:
            raise CommandError(Err.NAME_TAKEN) from None
        _require_row(status)

    async def delete(self, user_id: int) -> list[str]:
        """Delete a user and everything they own; return the ids of the removed devices."""
        async with self._db.transaction() as conn:
            await _lock_user(conn, user_id)
            rows = await conn.fetch("DELETE FROM devices WHERE user_id = $1 RETURNING id", user_id)
            await conn.execute("DELETE FROM users WHERE id = $1", user_id)
            return [row["id"] for row in rows]


class SessionsRepo:
    def __init__(self, db: Database):
        self._db = db

    async def create(self, user_id: int, token_hash: str, ttl: int, *, epoch: int) -> bool:
        """Store a session unless the user's credentials were revoked since ``epoch`` was read."""
        async with self._db.transaction() as conn:
            # FOR SHARE waits for a concurrent revocation to commit and then sees its epoch.
            current = await conn.fetchval(
                "SELECT session_epoch FROM users WHERE id = $1 FOR SHARE", user_id
            )
            if current != epoch:
                return False
            await _insert_session(conn, user_id, token_hash, ttl)
            return True

    async def exists(self, token_hash: str) -> bool:
        return await self._db.pool.fetchval(
            "SELECT 1 FROM sessions WHERE token_hash = $1 AND expires_at > now()", token_hash
        ) is not None

    async def refresh(self, token_hash: str, ttl: int) -> int | None:
        """Extend a valid session and return its user id, or None if unknown or expired."""
        return await self._db.pool.fetchval(
            """
            UPDATE sessions SET last_used_at = now(), expires_at = now() + $2::interval
            WHERE token_hash = $1 AND expires_at > now()
            RETURNING user_id
            """,
            token_hash, _ttl(ttl),
        )

    async def delete(self, token_hash: str) -> None:
        await self._db.pool.execute("DELETE FROM sessions WHERE token_hash = $1", token_hash)

    async def purge_expired(self) -> int:
        return _affected(await self._db.pool.execute("DELETE FROM sessions WHERE expires_at <= now()"))


class PasswordResetsRepo:
    def __init__(self, db: Database):
        self._db = db

    async def create(self, user_id: int, code_hash: str, ttl: int) -> None:
        """Store a reset code, replacing any earlier one of the same user."""
        await self._db.pool.execute(
            """
            INSERT INTO password_resets (user_id, code_hash, expires_at)
            VALUES ($1, $2, now() + $3::interval)
            ON CONFLICT (user_id) DO UPDATE
            SET code_hash = excluded.code_hash, attempts = 0, expires_at = excluded.expires_at
            """,
            user_id, code_hash, _ttl(ttl),
        )

    async def consume(self, user_id: int, code_hash: str, max_attempts: int) -> bool:
        """Use up a valid code; a wrong guess counts against the code and burns it at the limit."""
        async with self._db.transaction() as conn:
            row = await conn.fetchrow(
                "SELECT code_hash, attempts FROM password_resets"
                " WHERE user_id = $1 AND expires_at > now() FOR UPDATE",
                user_id,
            )
            if row is None:
                return False
            if hmac.compare_digest(row["code_hash"], code_hash):
                await conn.execute("DELETE FROM password_resets WHERE user_id = $1", user_id)
                return True
            if row["attempts"] + 1 >= max_attempts:
                await conn.execute("DELETE FROM password_resets WHERE user_id = $1", user_id)
            else:
                await conn.execute(
                    "UPDATE password_resets SET attempts = attempts + 1 WHERE user_id = $1", user_id
                )
            return False

    async def purge_expired(self) -> int:
        return _affected(await self._db.pool.execute(
            "DELETE FROM password_resets WHERE expires_at <= now()"
        ))


class ClaimsRepo:
    def __init__(self, db: Database):
        self._db = db

    async def create(self, user_id: int, token_hash: str, device_name: str, ttl: int) -> None:
        """Store a claim, replacing any earlier unused claim of the same user."""
        async with self._db.transaction() as conn:
            await _lock_user(conn, user_id)
            count = await conn.fetchval("SELECT count(*) FROM devices WHERE user_id = $1", user_id)
            if count >= MAX_DEVICES_PER_USER:
                raise CommandError(Err.LIMIT_REACHED)
            await conn.execute("DELETE FROM claims WHERE user_id = $1", user_id)
            await conn.execute(
                "INSERT INTO claims (token_hash, user_id, device_name, expires_at)"
                " VALUES ($1, $2, $3, now() + $4::interval)",
                token_hash, user_id, device_name, _ttl(ttl),
            )

    async def purge_expired(self) -> int:
        return _affected(await self._db.pool.execute("DELETE FROM claims WHERE expires_at <= now()"))


class DevicesRepo:
    def __init__(self, db: Database):
        self._db = db

    async def redeem_claim(self, claim_hash: str, device_id: str, secret_hash: str) -> Device | None:
        """Consume a claim token and create the device it was issued for."""
        async with self._db.transaction() as conn:
            claim = await conn.fetchrow(
                "DELETE FROM claims WHERE token_hash = $1 AND expires_at > now()"
                " RETURNING user_id, device_name",
                claim_hash,
            )
            if claim is None:
                return None
            row = await conn.fetchrow(
                "INSERT INTO devices (id, user_id, name, secret_hash, last_seen_at)"
                " VALUES ($1, $2, $3, $4, now()) RETURNING *",
                device_id, claim["user_id"], claim["device_name"], secret_hash,
            )
            return _device(row)

    async def authenticate(self, device_id: str, secret_hash: str) -> Device | None:
        """Verify a device secret, settling a pending rotation by whichever secret was used."""
        async with self._db.transaction() as conn:
            row = await conn.fetchrow("SELECT * FROM devices WHERE id = $1 FOR UPDATE", device_id)
            if row is None:
                return None
            current_ok = hmac.compare_digest(row["secret_hash"], secret_hash)
            next_ok = row["next_secret_hash"] is not None and hmac.compare_digest(
                row["next_secret_hash"], secret_hash
            )
            if not (current_ok or next_ok):
                return None
            if next_ok:
                await conn.execute(
                    "UPDATE devices SET secret_hash = next_secret_hash, next_secret_hash = NULL"
                    " WHERE id = $1",
                    device_id,
                )
            elif row["next_secret_hash"] is not None:
                # The device still has the current secret, so it never stored the staged one.
                await conn.execute("UPDATE devices SET next_secret_hash = NULL WHERE id = $1", device_id)
            row = await conn.fetchrow(
                "UPDATE devices SET last_seen_at = now() WHERE id = $1 RETURNING *", device_id
            )
            return _device(row)

    async def list(self, user_id: int) -> list[Device]:
        rows = await self._db.pool.fetch(
            "SELECT * FROM devices WHERE user_id = $1 ORDER BY created_at, id", user_id
        )
        return [_device(row) for row in rows]

    async def rename(self, user_id: int, device_id: str, name: str) -> None:
        _require_row(await self._db.pool.execute(
            "UPDATE devices SET name = $1 WHERE id = $2 AND user_id = $3", name, device_id, user_id
        ))

    async def delete(self, user_id: int, device_id: str) -> None:
        _require_row(await self._db.pool.execute(
            "DELETE FROM devices WHERE id = $1 AND user_id = $2", device_id, user_id
        ))

    async def stage_secret(self, user_id: int, device_id: str, secret_hash: str) -> None:
        _require_row(await self._db.pool.execute(
            "UPDATE devices SET next_secret_hash = $1 WHERE id = $2 AND user_id = $3",
            secret_hash, device_id, user_id,
        ))

    async def promote_secret(self, device_id: str, secret_hash: str) -> bool:
        """Make a staged secret current; True if ``secret_hash`` is the current secret afterwards."""
        # authenticate() may already have promoted it when the device reconnected with it.
        return _affected(await self._db.pool.execute(
            "UPDATE devices SET secret_hash = $2, next_secret_hash = NULL"
            " WHERE id = $1 AND (next_secret_hash = $2 OR secret_hash = $2)",
            device_id, secret_hash,
        )) > 0

    async def owns(self, user_id: int, device_id: str) -> bool:
        async with self._db.pool.acquire() as conn:
            return await _owns_device(conn, user_id, device_id)

    async def touch(self, device_id: str) -> None:
        await self._db.pool.execute("UPDATE devices SET last_seen_at = now() WHERE id = $1", device_id)


class TargetsRepo:
    def __init__(self, db: Database):
        self._db = db

    async def add(self, user_id: int, device_id: str, mac: str, name: str) -> Target:
        async with self._db.transaction() as conn:
            await _lock_user(conn, user_id)
            if not await _owns_device(conn, user_id, device_id):
                raise CommandError(Err.NOT_FOUND)
            count = await conn.fetchval("SELECT count(*) FROM targets WHERE user_id = $1", user_id)
            if count >= MAX_TARGETS_PER_USER:
                raise CommandError(Err.LIMIT_REACHED)
            try:
                row = await conn.fetchrow(
                    "INSERT INTO targets (user_id, device_id, mac, name) VALUES ($1, $2, $3, $4)"
                    " RETURNING *",
                    user_id, device_id, mac, name,
                )
            except asyncpg.UniqueViolationError:
                raise CommandError(Err.DUPLICATE) from None
            return _target(row)

    async def get(self, user_id: int, target_id: int) -> Target | None:
        row = await self._db.pool.fetchrow(
            "SELECT * FROM targets WHERE id = $1 AND user_id = $2", target_id, user_id
        )
        return _target(row) if row else None

    async def list(self, user_id: int) -> list[Target]:
        rows = await self._db.pool.fetch(
            "SELECT * FROM targets WHERE user_id = $1 ORDER BY id", user_id
        )
        return [_target(row) for row in rows]

    async def rename(self, user_id: int, target_id: int, name: str) -> None:
        _require_row(await self._db.pool.execute(
            "UPDATE targets SET name = $1 WHERE id = $2 AND user_id = $3", name, target_id, user_id
        ))

    async def assign(self, user_id: int, target_id: int, device_id: str) -> None:
        async with self._db.transaction() as conn:
            if not await _owns_device(conn, user_id, device_id):
                raise CommandError(Err.NOT_FOUND)
            _require_row(await conn.execute(
                "UPDATE targets SET device_id = $1 WHERE id = $2 AND user_id = $3",
                device_id, target_id, user_id,
            ))

    async def remove(self, user_id: int, target_id: int) -> None:
        _require_row(await self._db.pool.execute(
            "DELETE FROM targets WHERE id = $1 AND user_id = $2", target_id, user_id
        ))
