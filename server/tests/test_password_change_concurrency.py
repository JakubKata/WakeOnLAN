"""Unit contracts for the real password-update transaction.

The asyncpg boundary is scripted: these tests check repository control flow,
rollback and bound authorization arguments, not PostgreSQL locking semantics.
Live row-lock races are covered in test_password_change_database.py.
"""

import asyncio
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from wol_server.db import UsersRepo
from wol_server.errors import CommandError
from wol_server.protocol import Err


class TransactionBoundary:
    def __init__(self, *, update_result="UPDATE 1", fetch_results=()):
        self.connection = SimpleNamespace(
            execute=AsyncMock(side_effect=[update_result, "DELETE 2", "DELETE 1", "DELETE 1"]),
            fetchval=AsyncMock(side_effect=list(fetch_results)),
        )
        self.committed = False
        self.rolled_back = False

    @asynccontextmanager
    async def transaction(self):
        try:
            yield self.connection
        except BaseException:
            self.rolled_back = True
            raise
        else:
            self.committed = True


def assert_cas_arguments(database):
    # The expected epoch must reach the SQL statement, not merely the Python API.
    assert database.connection.execute.await_args_list[0].args[1:] == ("new-hash", 7, 5)


def test_stale_epoch_rolls_back_without_revoking_new_credentials():
    async def scenario():
        database = TransactionBoundary(update_result="UPDATE 0")
        with pytest.raises(CommandError) as error:
            await UsersRepo(database).change_password(
                7, "new-hash", expected_epoch=5, session_token_hash="old-session",
            )
        assert error.value.code is Err.INVALID_CREDENTIALS
        assert_cas_arguments(database)
        database.connection.fetchval.assert_not_awaited()
        assert database.connection.execute.await_count == 1
        assert database.rolled_back and not database.committed

    asyncio.run(scenario())


@pytest.mark.parametrize("token", ["revoked-session", "", "foreign-session"])
def test_missing_or_foreign_session_rolls_back_tentative_password_write(token):
    async def scenario():
        database = TransactionBoundary(fetch_results=[None])
        with pytest.raises(CommandError) as error:
            await UsersRepo(database).change_password(
                7, "new-hash", expected_epoch=5, session_token_hash=token,
            )
        assert error.value.code is Err.INVALID_CREDENTIALS
        assert_cas_arguments(database)
        # Even an empty token must be checked; only None denotes the reset path.
        assert database.connection.fetchval.await_args.args[1:] == (token, 7)
        assert database.connection.fetchval.await_count == 1
        assert database.connection.execute.await_count == 1
        assert database.rolled_back and not database.committed

    asyncio.run(scenario())


def test_session_expiring_while_waiting_for_lock_rolls_back_password_write():
    async def scenario():
        # The session row was found, but the wall-clock expiry check performed
        # after acquiring its lock says it is no longer usable.
        database = TransactionBoundary(fetch_results=[1, False])
        with pytest.raises(CommandError) as error:
            await UsersRepo(database).change_password(
                7, "new-hash", expected_epoch=5, session_token_hash="expiring-session",
            )
        assert error.value.code is Err.INVALID_CREDENTIALS
        assert_cas_arguments(database)
        assert database.connection.fetchval.await_count == 2
        for call in database.connection.fetchval.await_args_list:
            assert call.args[1:] == ("expiring-session", 7)
        assert database.connection.execute.await_count == 1
        assert database.rolled_back and not database.committed

    asyncio.run(scenario())


@pytest.mark.parametrize("authenticated", [True, False])
def test_authorized_update_revokes_credentials_in_the_same_transaction(authenticated):
    async def scenario():
        database = TransactionBoundary(fetch_results=[1, True, 6] if authenticated else [6])
        options = {"session_token_hash": "current-session"} if authenticated else {}
        assert await UsersRepo(database).change_password(
            7, "new-hash", expected_epoch=5, **options,
        ) == 6
        assert_cas_arguments(database)
        assert database.committed and not database.rolled_back
        # Successful change removes all prior sessions, reset codes and claims.
        mutations = database.connection.execute.await_args_list
        assert [call.args[0] for call in mutations[1:]] == [
            "DELETE FROM sessions WHERE user_id = $1",
            "DELETE FROM password_resets WHERE user_id = $1",
            "DELETE FROM claims WHERE user_id = $1",
        ]
        assert all(call.args[1:] == (7,) for call in mutations[1:])
        reads = database.connection.fetchval.await_args_list
        assert reads[-1].args[1:] == (7,)
        if authenticated:
            assert all(call.args[1:] == ("current-session", 7) for call in reads[:-1])
        else:
            assert len(reads) == 1

    asyncio.run(scenario())


def test_password_update_cannot_omit_expected_epoch():
    async def scenario():
        database = TransactionBoundary()
        with pytest.raises(TypeError):
            await UsersRepo(database).change_password(7, "new-hash")
        database.connection.execute.assert_not_awaited()
        assert not database.committed and not database.rolled_back

    asyncio.run(scenario())
