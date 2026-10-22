"""Forward-only schema migrations tracked in the ``schema_migrations`` table."""

import asyncpg

# Serializes concurrent migrations (e.g. two server instances starting at once).
MIGRATION_LOCK_ID = 0x574F4C5F4D4947

MIGRATIONS: list[str] = [
    """
    CREATE TABLE users (
        id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        name          text NOT NULL,
        email         text NOT NULL,
        password_hash text NOT NULL,
        created_at    timestamptz NOT NULL DEFAULT now()
    );
    CREATE UNIQUE INDEX users_name_key ON users (lower(name));
    CREATE UNIQUE INDEX users_email_key ON users (lower(email));

    CREATE TABLE sessions (
        token_hash   text PRIMARY KEY,
        user_id      bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created_at   timestamptz NOT NULL DEFAULT now(),
        last_used_at timestamptz NOT NULL DEFAULT now(),
        expires_at   timestamptz NOT NULL
    );
    CREATE INDEX sessions_user_id ON sessions (user_id);
    CREATE INDEX sessions_expires_at ON sessions (expires_at);

    CREATE TABLE claims (
        token_hash  text PRIMARY KEY,
        user_id     bigint NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
        device_name text NOT NULL,
        expires_at  timestamptz NOT NULL
    );

    CREATE TABLE devices (
        id               text PRIMARY KEY,
        user_id          bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name             text NOT NULL,
        secret_hash      text NOT NULL,
        next_secret_hash text,
        created_at       timestamptz NOT NULL DEFAULT now(),
        last_seen_at     timestamptz
    );
    CREATE INDEX devices_user_id ON devices (user_id);

    CREATE TABLE targets (
        id        bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        user_id   bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        device_id text REFERENCES devices(id) ON DELETE SET NULL,
        mac       text NOT NULL,
        name      text NOT NULL,
        UNIQUE (user_id, mac)
    );
    CREATE INDEX targets_device_id ON targets (device_id);
    """,
    """
    CREATE TABLE password_resets (
        user_id    bigint PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
        code_hash  text NOT NULL,
        attempts   integer NOT NULL DEFAULT 0,
        expires_at timestamptz NOT NULL
    );
    CREATE INDEX password_resets_expires_at ON password_resets (expires_at);
    """,
    """
    ALTER TABLE users ADD COLUMN session_epoch bigint NOT NULL DEFAULT 0;
    """,
    """
    -- Unbound tokens from the previous protocol cannot enroll devices anymore.
    DELETE FROM claims;
    ALTER TABLE claims ADD COLUMN device_id text NOT NULL;
    ALTER TABLE devices ADD COLUMN enrollment_hash text;
    -- Preserve recovery for devices upgraded during an unconfirmed legacy rotation.
    -- There is no API that can issue another alternate secret.
    ALTER TABLE devices RENAME COLUMN next_secret_hash TO recovery_secret_hash;
    """,
]


class SchemaError(Exception):
    pass


async def migrate(conn: asyncpg.Connection) -> int:
    """Apply pending migrations inside the caller's transaction; return the schema version."""
    await conn.execute("SELECT pg_advisory_xact_lock($1)", MIGRATION_LOCK_ID)
    await conn.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version    integer PRIMARY KEY,
            applied_at timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    version = await conn.fetchval("SELECT coalesce(max(version), 0) FROM schema_migrations")
    if version > len(MIGRATIONS):
        raise SchemaError(f"database schema v{version} is newer than this server supports")

    for number, script in enumerate(MIGRATIONS[version:], start=version + 1):
        await conn.execute(script)
        await conn.execute("INSERT INTO schema_migrations (version) VALUES ($1)", number)
    return len(MIGRATIONS)
