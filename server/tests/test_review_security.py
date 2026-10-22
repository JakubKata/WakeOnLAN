"""Security boundaries and password-revocation regressions from the review.

Handler tests check authorization snapshots and side effects with explicit
repository doubles; database atomicity is covered separately.
"""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from wol_server.context import Context
from wol_server.db import User
from wol_server.errors import CommandError
from wol_server.handlers import account, build_dispatcher, password_reset
from wol_server.handlers.auth import SESSION_TTL_SECONDS
from wol_server.protocol import Cmd, Err, Message, ack, nack
from wol_server.registry import Registry
from wol_server.session import Role, Session


class Connection:
    peer = "192.0.2.10"
    closed = False

    def close(self):
        self.closed = True


@pytest.mark.parametrize(
    "command,args",
    [
        (Cmd.CREATE_CLAIM, ("Desk", "a" * 43)),
        (Cmd.REMOVE_DEVICE, ("a" * 43,)),
        (Cmd.DELETE_ACCOUNT, ("old-password",)),
        (Cmd.CHANGE_PASSWORD, ("old-password", "new-password")),
        (Cmd.WAKE_UP, (1,)),
    ],
)
def test_authenticated_device_cannot_use_account_commands(command, args):
    """A valid device secret must never grant the owner's account privileges."""
    context = Context(
        SimpleNamespace(),
        Session(Role.DEVICE, "192.0.2.10", user_id=7, device_id="a" * 43),
        Connection(),
    )
    response = asyncio.run(build_dispatcher().dispatch(context, Message(command, args)))
    assert response == nack(Err.UNKNOWN_COMMAND)


@pytest.mark.parametrize(
    "command,args",
    [
        (Cmd.DEVICE_AUTH, ("a" * 43, "b" * 43)),
        (Cmd.DEVICE_CLAIM, ("a" * 22, "b" * 43, "c" * 43)),
        (Cmd.WAKE_ACK, ("request-id",)),
    ],
)
def test_account_connection_cannot_impersonate_device(command, args):
    context = Context(SimpleNamespace(), Session(Role.CLIENT, "192.0.2.10", user_id=7), Connection())
    response = asyncio.run(build_dispatcher().dispatch(context, Message(command, args)))
    assert response == nack(Err.UNKNOWN_COMMAND)


def account_context():
    user = User(7, "alice", "a@example.com", "old-hash", 5)
    services = SimpleNamespace(
        users=SimpleNamespace(
            by_id=AsyncMock(return_value=user),
            by_email=AsyncMock(return_value=user),
            change_password=AsyncMock(return_value=6),
        ),
        security=SimpleNamespace(
            verify_password=AsyncMock(return_value=True),
            hash_password=AsyncMock(return_value="new-hash"),
            new_token=lambda: "new-session-token",
            token_hash=lambda token: "hashed-" + token,
        ),
        sessions=SimpleNamespace(create=AsyncMock(return_value=True), exists=AsyncMock(return_value=True)),
        resets=SimpleNamespace(consume=AsyncMock(return_value=True)),
        limiter=SimpleNamespace(require=Mock()),
        registry=Mock(wraps=Registry()),
        mailer=object(),
    )
    connection = Connection()
    return Context(services, Session(Role.CLIENT, connection.peer, user_id=7, token_hash="old-session"), connection)


@pytest.mark.parametrize("paused_method", ["verify_password", "hash_password"])
def test_password_change_keeps_the_original_authorization_snapshot(paused_method):
    """A revocation during either expensive await must not refresh authority.

    The repository explicitly rejects the stale operation; this test verifies
    what the real handler passes to that atomic boundary, not a fake SQL CAS.
    """
    async def scenario():
        async with asyncio.timeout(3):
            context = account_context()
            services = context.services
            started, resume = asyncio.Event(), asyncio.Event()

            async def delayed(*args):
                started.set()
                await resume.wait()
                return True if paused_method == "verify_password" else "new-hash"

            getattr(services.security, paused_method).side_effect = delayed
            services.users.change_password.side_effect = CommandError(Err.INVALID_CREDENTIALS)
            operation = asyncio.create_task(account.change_password(context, "old-password", "new-password"))
            await started.wait()
            # Later reads would see a newer password/epoch. Neither this nor a
            # changed connection object may replace the captured authorization.
            services.users.by_id.return_value = User(7, "alice", "a@example.com", "reset-hash", 6)
            context.session.token_hash = "replacement-session"
            context.conn.close()
            resume.set()
            with pytest.raises(CommandError) as error:
                await operation
            assert error.value.code is Err.INVALID_CREDENTIALS
            services.users.by_id.assert_awaited_once_with(7)
            services.users.change_password.assert_awaited_once_with(
                7, "new-hash", expected_epoch=5, session_token_hash="old-session",
            )
            services.sessions.create.assert_not_awaited()
            services.registry.kick_user.assert_not_called()
            assert context.session.user_id is None and context.session.token_hash is None
            assert context.session.close_requested

    asyncio.run(scenario())


def test_password_change_requires_an_authorizing_session_token():
    async def scenario():
        context = account_context()
        context.session.token_hash = None
        with pytest.raises(CommandError) as error:
            await account.change_password(context, "old-password", "new-password")
        assert error.value.code is Err.INVALID_CREDENTIALS
        context.services.users.change_password.assert_not_awaited()
        context.services.sessions.create.assert_not_awaited()
        context.services.registry.kick_user.assert_not_called()
        assert context.session.user_id is None and context.session.close_requested

    asyncio.run(scenario())


def test_wrong_old_password_does_not_write_or_close_a_valid_connection():
    async def scenario():
        context = account_context()
        services = context.services
        services.security.verify_password.return_value = False
        with pytest.raises(CommandError) as error:
            await account.change_password(context, "incorrect-old-password", "new-password")
        assert error.value.code is Err.INVALID_CREDENTIALS
        services.security.hash_password.assert_not_awaited()
        services.users.change_password.assert_not_awaited()
        services.sessions.create.assert_not_awaited()
        assert context.session.user_id == 7 and context.session.token_hash == "old-session"
        assert not context.session.close_requested

    asyncio.run(scenario())


def test_successful_password_change_uses_committed_epoch_for_replacement_session():
    async def scenario():
        context = account_context()
        services = context.services
        assert await account.change_password(context, "old-password", "new-password") == ack("new-session-token")
        services.users.change_password.assert_awaited_once_with(
            7, "new-hash", expected_epoch=5, session_token_hash="old-session",
        )
        services.sessions.create.assert_awaited_once_with(
            7, "hashed-new-session-token", SESSION_TTL_SECONDS, epoch=6,
        )
        services.registry.kick_user.assert_called_once_with(7, keep=context.conn)
        assert context.session.token_hash == "hashed-new-session-token"

    asyncio.run(scenario())


def test_revocation_after_password_commit_closes_replacement_session_attempt():
    async def scenario():
        context = account_context()
        services = context.services
        services.sessions.create.return_value = False
        with pytest.raises(CommandError) as error:
            await account.change_password(context, "old-password", "new-password")
        assert error.value.code is Err.INVALID_CREDENTIALS
        services.sessions.create.assert_awaited_once_with(
            7, "hashed-new-session-token", SESSION_TTL_SECONDS, epoch=6,
        )
        assert context.session.user_id is None and context.session.token_hash is None
        assert context.session.close_requested

    asyncio.run(scenario())


def test_password_reset_keeps_epoch_from_before_code_consumption_and_hashing():
    async def scenario():
        async with asyncio.timeout(3):
            context = account_context()
            context.session.user_id = None
            context.session.token_hash = None
            services = context.services
            started, resume = asyncio.Event(), asyncio.Event()

            async def delayed_hash(password):
                started.set()
                await resume.wait()
                return "reset-hash"

            services.security.hash_password.side_effect = delayed_hash
            services.users.change_password.side_effect = CommandError(Err.INVALID_CREDENTIALS)
            operation = asyncio.create_task(password_reset.reset_password(
                context, "a@example.com", "0123456789", "new-password",
            ))
            await started.wait()
            services.resets.consume.assert_awaited_once()
            services.users.by_email.return_value = User(7, "alice", "a@example.com", "later-hash", 6)
            resume.set()
            with pytest.raises(CommandError) as error:
                await operation
            assert error.value.code is Err.INVALID_CREDENTIALS
            services.users.by_email.assert_awaited_once_with("a@example.com")
            services.users.change_password.assert_awaited_once_with(7, "reset-hash", expected_epoch=5)
            services.sessions.create.assert_not_awaited()
            services.registry.kick_user.assert_not_called()

    asyncio.run(scenario())


def test_successful_password_reset_uses_committed_epoch_for_new_session():
    async def scenario():
        context = account_context()
        context.session.user_id = None
        context.session.token_hash = None
        services = context.services
        assert await password_reset.reset_password(
            context, "a@example.com", "0123456789", "new-password",
        ) == ack("new-session-token", "alice")
        services.users.change_password.assert_awaited_once_with(7, "new-hash", expected_epoch=5)
        services.sessions.create.assert_awaited_once_with(
            7, "hashed-new-session-token", SESSION_TTL_SECONDS, epoch=6,
        )
        services.registry.kick_user.assert_called_once_with(7)

    asyncio.run(scenario())
