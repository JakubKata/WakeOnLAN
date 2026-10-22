"""Password-change authorization against real PostgreSQL transactions and locks.

These tests intentionally require TEST_DATABASE_URL; repository doubles cannot
establish atomic compare-and-set, rollback, or row-lock ordering guarantees.
"""

import asyncio

import pytest

from helpers import create_user, requires_database, temporary_services
from wol_server.db import repo
from wol_server.errors import CommandError
from wol_server.protocol import Err

pytestmark = requires_database


async def seed_credentials(services, user_id, *, epoch=0):
    assert await services.sessions.create(user_id, "caller", ttl=60, epoch=epoch)
    assert await services.sessions.create(user_id, "other-session", ttl=60, epoch=epoch)
    await services.resets.create(user_id, "reset-code", ttl=60)
    await services.claims.create(user_id, "device-claim", "Office", "device-id", ttl=60)


async def snapshot(connection, user_id):
    """Capture all state that a rejected password operation must leave intact."""
    return {
        "user": dict(await connection.fetchrow(
            "SELECT password_hash, session_epoch FROM users WHERE id = $1", user_id,
        )),
        "sessions": [dict(row) for row in await connection.fetch(
            "SELECT * FROM sessions WHERE user_id = $1 ORDER BY token_hash", user_id,
        )],
        "resets": [dict(row) for row in await connection.fetch(
            "SELECT * FROM password_resets WHERE user_id = $1", user_id,
        )],
        "claims": [dict(row) for row in await connection.fetch(
            "SELECT * FROM claims WHERE user_id = $1", user_id,
        )],
    }


async def wait_for_blocker(pool, blocker_pid):
    """Wait for an actual PostgreSQL lock dependency, not a guessed task delay."""
    while not await pool.fetchval(
        "SELECT EXISTS (SELECT 1 FROM pg_stat_activity"
        " WHERE $1 = ANY(pg_blocking_pids(pid)))", blocker_pid,
    ):
        await asyncio.sleep(0.01)


async def finish_tasks(*tasks):
    for task in tasks:
        if task is not None and not task.done():
            task.cancel()
    await asyncio.gather(*(task for task in tasks if task is not None), return_exceptions=True)


@pytest.mark.parametrize("invalid_session", ["missing", "foreign", "expired"])
def test_invalid_session_rolls_back_password_and_all_credential_changes(invalid_session):
    async def scenario():
        async with asyncio.timeout(10), temporary_services() as services:
            user_id = await create_user(services, "alice", "alice@example.com", "original-hash")
            await seed_credentials(services, user_id)
            token = "missing-token"
            foreign_id = None
            if invalid_session == "foreign":
                foreign_id = await create_user(services, "bob", "bob@example.com", "bob-hash")
                assert await services.sessions.create(foreign_id, "foreign-token", ttl=60, epoch=0)
                token = "foreign-token"
            elif invalid_session == "expired":
                assert await services.sessions.create(user_id, "expired-token", ttl=-1, epoch=0)
                token = "expired-token"
            before = await snapshot(services.db.pool, user_id)
            foreign_before = await snapshot(services.db.pool, foreign_id) if foreign_id else None

            with pytest.raises(CommandError) as error:
                await services.users.change_password(
                    user_id, "unauthorized-hash", expected_epoch=0, session_token_hash=token,
                )
            assert error.value.code is Err.INVALID_CREDENTIALS
            assert await snapshot(services.db.pool, user_id) == before
            if foreign_id:
                assert await snapshot(services.db.pool, foreign_id) == foreign_before

    asyncio.run(scenario())


def test_stale_epoch_cannot_revoke_credentials_created_after_logout_all():
    async def scenario():
        async with asyncio.timeout(10), temporary_services() as services:
            user_id = await create_user(services, "alice", "alice@example.com", "original-hash")
            assert await services.users.revoke_all(user_id) == 1
            await seed_credentials(services, user_id, epoch=1)
            before = await snapshot(services.db.pool, user_id)
            with pytest.raises(CommandError) as error:
                await services.users.change_password(
                    user_id, "stale-hash", expected_epoch=0, session_token_hash="caller",
                )
            assert error.value.code is Err.INVALID_CREDENTIALS
            assert await snapshot(services.db.pool, user_id) == before

    asyncio.run(scenario())


@pytest.mark.parametrize("authorization", ["session", "reset"])
def test_successful_password_change_revokes_credentials_and_returns_next_epoch(authorization):
    async def scenario():
        async with asyncio.timeout(10), temporary_services() as services:
            user_id = await create_user(services, "alice", "alice@example.com", "original-hash")
            await seed_credentials(services, user_id)
            session_token = "caller"
            if authorization == "reset":
                assert await services.resets.consume(user_id, "reset-code", max_attempts=50)
                session_token = None
            epoch = await services.users.change_password(
                user_id, "new-hash", expected_epoch=0, session_token_hash=session_token,
            )
            assert epoch == 1
            after = await snapshot(services.db.pool, user_id)
            assert after["user"] == {"password_hash": "new-hash", "session_epoch": 1}
            assert after["sessions"] == after["resets"] == after["claims"] == []
            assert not await services.sessions.create(user_id, "stale-session", ttl=60, epoch=0)
            assert await services.sessions.create(user_id, "fresh-session", ttl=60, epoch=epoch)

    asyncio.run(scenario())


def test_concurrent_password_changes_with_same_epoch_have_exactly_one_winner():
    async def scenario():
        async with asyncio.timeout(10), temporary_services() as services:
            user_id = await create_user(services, "alice", "alice@example.com", "original-hash")
            await seed_credentials(services, user_id)
            tasks = []
            try:
                # Both operations must reach the locked user row before either
                # can commit, regardless of scheduling or connection-pool timing.
                async with services.db.transaction() as blocker:
                    await blocker.execute("SELECT 1 FROM users WHERE id = $1 FOR UPDATE", user_id)
                    blocker_pid = blocker.get_server_pid()
                    tasks = [asyncio.create_task(services.users.change_password(
                        user_id, password, expected_epoch=0, session_token_hash="caller",
                    )) for password in ("first-hash", "second-hash")]
                    while await services.db.pool.fetchval(
                        # A second updater can wait on the first updater's tuple
                        # lock instead of directly on the original transaction.
                        "WITH RECURSIVE blocked(pid) AS ("
                        " SELECT pid FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid))"
                        " UNION SELECT activity.pid FROM pg_stat_activity AS activity"
                        " JOIN blocked ON blocked.pid = ANY(pg_blocking_pids(activity.pid))"
                        ") SELECT count(*) FROM blocked", blocker_pid,
                    ) < 2:
                        await asyncio.sleep(0.01)
                    assert not any(task.done() for task in tasks)
                results = await asyncio.gather(*tasks, return_exceptions=True)
                winners = [index for index, value in enumerate(results) if value == 1]
                assert len(winners) == 1
                loser = results[1 - winners[0]]
                assert isinstance(loser, CommandError) and loser.code is Err.INVALID_CREDENTIALS
                after = await snapshot(services.db.pool, user_id)
                assert after["user"] == {
                    "password_hash": ("first-hash", "second-hash")[winners[0]], "session_epoch": 1,
                }
                assert after["sessions"] == after["resets"] == after["claims"] == []
            finally:
                await finish_tasks(*tasks)

    asyncio.run(scenario())


def test_password_update_waiting_on_logout_all_rechecks_epoch(monkeypatch):
    async def scenario():
        async with asyncio.timeout(10), temporary_services() as services:
            user_id = await create_user(services, "alice", "alice@example.com", "original-hash")
            await seed_credentials(services, user_id)
            ready, commit = asyncio.Event(), asyncio.Event()
            original_revoke = repo._revoke_credentials
            blocker_pid = None

            async def pause_before_commit(connection, revoked_user):
                nonlocal blocker_pid
                epoch = await original_revoke(connection, revoked_user)
                blocker_pid = connection.get_server_pid()
                ready.set()
                await commit.wait()
                return epoch

            monkeypatch.setattr(repo, "_revoke_credentials", pause_before_commit)
            revocation = asyncio.create_task(services.users.revoke_all(user_id))
            change = None
            try:
                await ready.wait()
                change = asyncio.create_task(services.users.change_password(
                    user_id, "stale-hash", expected_epoch=0, session_token_hash="caller",
                ))
                await wait_for_blocker(services.db.pool, blocker_pid)
                assert not change.done()
                commit.set()
                assert await revocation == 1
                with pytest.raises(CommandError) as error:
                    await change
                assert error.value.code is Err.INVALID_CREDENTIALS
                after = await snapshot(services.db.pool, user_id)
                assert after["user"] == {"password_hash": "original-hash", "session_epoch": 1}
                assert after["sessions"] == after["resets"] == after["claims"] == []
            finally:
                commit.set()
                await finish_tasks(revocation, change)

    asyncio.run(scenario())


def test_session_expired_while_waiting_for_its_lock_cannot_authorize_password_change():
    async def scenario():
        async with asyncio.timeout(10), temporary_services() as services:
            user_id = await create_user(services, "alice", "alice@example.com", "original-hash")
            await seed_credentials(services, user_id)
            task = None
            try:
                async with services.db.transaction() as blocker:
                    await blocker.execute("SELECT 1 FROM sessions WHERE token_hash = 'caller' FOR UPDATE")
                    task = asyncio.create_task(services.users.change_password(
                        user_id, "unauthorized-hash", expected_epoch=0, session_token_hash="caller",
                    ))
                    await wait_for_blocker(services.db.pool, blocker.get_server_pid())
                    # Expiry is AFTER the password transaction began but BEFORE
                    # it acquires this session row. now() would accept the token;
                    # the fresh clock_timestamp() check must reject it.
                    await blocker.execute(
                        "UPDATE sessions SET expires_at = clock_timestamp() WHERE token_hash = 'caller'"
                    )
                    expected = await snapshot(blocker, user_id)
                with pytest.raises(CommandError) as error:
                    await task
                assert error.value.code is Err.INVALID_CREDENTIALS
                assert await snapshot(services.db.pool, user_id) == expected
            finally:
                await finish_tasks(task)

    asyncio.run(scenario())
