"""End-to-end tests against a real TLS server on ephemeral ports."""

import asyncio

import pytest

from helpers import requires_database, running_server
from wol_server import dispatcher
from wol_server.app import Timeouts
from wol_server.handlers import devices as devices_handlers
from wol_server.handlers import targets as targets_handlers
from wol_server.protocol import MAX_LINE_BYTES, Cmd, Err, Message, ack, nack
from wol_server.session import Role
from wol_server.transport import Connection

pytestmark = requires_database


def run(coro):
    return asyncio.run(coro)


async def answer_wake(device, *, ack_it=True):
    request = await device.recv()
    assert request.command == Cmd.WAKE_UP
    request_id, mac = request.args
    if ack_it:
        await device.send(Cmd.WAKE_ACK, request_id)
    return mac


def test_register_pair_and_wake(tmp_path):
    async def scenario():
        async with running_server(tmp_path) as h:
            client, _ = await h.registered_client()
            device, device_id, _ = await h.paired_device(client)

            devices = await client.call(Cmd.LIST_DEVICES)
            assert devices.args[0][0]["id"] == device_id and devices.args[0][0]["online"] is True

            added = await client.call(Cmd.ADD_TARGET, device_id, "aa-bb-cc-dd-ee-ff", "Gaming PC")
            target = added.args[0]
            assert target["mac"] == "AA:BB:CC:DD:EE:FF"

            listed = await client.call(Cmd.LIST_TARGETS)
            assert listed.args[0] == [target]

            responder = asyncio.create_task(answer_wake(device))
            assert await client.call(Cmd.WAKE_UP, target["id"]) == ack(target["id"])
            assert await responder == "AA:BB:CC:DD:EE:FF"

    run(scenario())


def test_wake_without_device_ack_reports_unreachable(tmp_path, monkeypatch):
    monkeypatch.setattr(targets_handlers, "DEVICE_REQUEST_TIMEOUT", 0.3)

    async def scenario():
        async with running_server(tmp_path) as h:
            client, _ = await h.registered_client()
            device, device_id, _ = await h.paired_device(client)
            target = (await client.call(Cmd.ADD_TARGET, device_id, "AABBCCDDEEFF", "PC")).args[0]

            responder = asyncio.create_task(answer_wake(device, ack_it=False))
            assert await client.call(Cmd.WAKE_UP, target["id"]) == nack(Err.DEVICE_UNREACHABLE)
            await responder

            await device.close()
            await asyncio.sleep(0.1)
            assert await client.call(Cmd.WAKE_UP, target["id"]) == nack(Err.DEVICE_OFFLINE)

    run(scenario())


def test_device_reconnects_with_secret(tmp_path):
    async def scenario():
        async with running_server(tmp_path) as h:
            client, _ = await h.registered_client()
            first, device_id, secret = await h.paired_device(client)

            intruder = await h.device()
            assert await intruder.call(Cmd.DEVICE_AUTH, device_id, "x" * 43) == nack(Err.INVALID_CREDENTIALS)

            second = await h.device()
            assert await second.call(Cmd.DEVICE_AUTH, device_id, secret) == ack()
            assert await first.recv() is None
            assert await second.call(Cmd.DEVICE_AUTH, device_id, secret) == nack(Err.ALREADY_AUTHENTICATED)

    run(scenario())


def test_claim_token_is_single_use(tmp_path):
    async def scenario():
        async with running_server(tmp_path) as h:
            client, _ = await h.registered_client()
            claim = await client.call(Cmd.CREATE_CLAIM, "ESP")
            first, second = await h.device(), await h.device()
            assert (await first.call(Cmd.DEVICE_CLAIM, claim.args[0])).command == Cmd.ACK
            assert await second.call(Cmd.DEVICE_CLAIM, claim.args[0]) == nack(Err.INVALID_TOKEN)

    run(scenario())


def test_resume_and_password_change_revokes_other_sessions(tmp_path):
    async def scenario():
        async with running_server(tmp_path) as h:
            phone, token = await h.registered_client(password="first password")
            laptop = await h.client()
            assert await laptop.call(Cmd.RESUME, token) == ack("alice")

            changed = await phone.call(Cmd.CHANGE_PASSWORD, "first password", "second password")
            assert changed.command == Cmd.ACK
            new_token = changed.args[0]
            assert await laptop.recv() is None

            stale = await h.client()
            assert await stale.call(Cmd.RESUME, token) == nack(Err.INVALID_TOKEN)
            fresh = await h.client()
            assert await fresh.call(Cmd.RESUME, new_token) == ack("alice")
            relogin = await h.client()
            assert (await relogin.call(Cmd.LOGIN, "ALICE", "second password")).command == Cmd.ACK

    run(scenario())


def test_login_failures_and_throttling(tmp_path):
    async def scenario():
        async with running_server(tmp_path) as h:
            await h.registered_client(password="right password")
            peer = await h.client()
            assert await peer.call(Cmd.LOGIN, "alice", "wrong password") == nack(Err.INVALID_CREDENTIALS)
            assert await peer.call(Cmd.LOGIN, "nobody", "wrong password") == nack(Err.INVALID_CREDENTIALS)
            replies = [await peer.call(Cmd.LOGIN, "alice", "wrong password") for _ in range(12)]
            assert nack(Err.RATE_LIMITED) in replies

    run(scenario())


def test_concurrent_failed_logins_cannot_share_the_last_token(tmp_path):
    async def scenario():
        async with running_server(tmp_path) as h:
            await h.registered_client(password="right password")
            peers = [await h.client() for _ in range(4)]
            for _ in range(9):
                await peers[0].call(Cmd.LOGIN, "alice", "wrong password")

            replies = await asyncio.gather(
                *(peer.call(Cmd.LOGIN, "alice", "wrong password") for peer in peers)
            )
            assert replies.count(nack(Err.INVALID_CREDENTIALS)) == 1
            assert replies.count(nack(Err.RATE_LIMITED)) == 3

    run(scenario())


def test_remove_device_notifies_it(tmp_path):
    async def scenario():
        async with running_server(tmp_path) as h:
            client, _ = await h.registered_client()
            device, device_id, secret = await h.paired_device(client)
            assert await client.call(Cmd.REMOVE_DEVICE, device_id) == ack(device_id)
            assert await device.recv() == Message(Cmd.UNPAIRED)
            assert await device.recv() is None

            again = await h.device()
            assert await again.call(Cmd.DEVICE_AUTH, device_id, secret) == nack(Err.INVALID_CREDENTIALS)

    run(scenario())


def test_rotate_device_secret(tmp_path):
    async def scenario():
        async with running_server(tmp_path) as h:
            client, _ = await h.registered_client()
            device, device_id, old_secret = await h.paired_device(client)

            async def confirm():
                request = await device.recv()
                assert request.command == Cmd.SET_SECRET
                request_id, secret = request.args
                await device.send(Cmd.SECRET_ACK, request_id)
                return secret

            responder = asyncio.create_task(confirm())
            assert await client.call(Cmd.ROTATE_DEVICE_SECRET, device_id) == ack(device_id)
            new_secret = await responder

            old = await h.device()
            assert await old.call(Cmd.DEVICE_AUTH, device_id, old_secret) == nack(Err.INVALID_CREDENTIALS)
            new = await h.device()
            assert await new.call(Cmd.DEVICE_AUTH, device_id, new_secret) == ack()

    run(scenario())


@pytest.mark.parametrize("device_kept_new_secret", [False, True])
def test_unconfirmed_rotation_disconnects_device(tmp_path, monkeypatch, device_kept_new_secret):
    monkeypatch.setattr(devices_handlers, "DEVICE_REQUEST_TIMEOUT", 0.3)

    async def scenario():
        async with running_server(tmp_path) as h:
            client, _ = await h.registered_client()
            device, device_id, old_secret = await h.paired_device(client)

            async def ignore():
                request = await device.recv()
                assert request.command == Cmd.SET_SECRET
                return request.args[1]

            responder = asyncio.create_task(ignore())
            assert await client.call(Cmd.ROTATE_DEVICE_SECRET, device_id) == nack(Err.DEVICE_UNREACHABLE)
            staged = await responder
            assert await device.recv() is None

            kept, lost = (staged, old_secret) if device_kept_new_secret else (old_secret, staged)
            again = await h.device()
            assert await again.call(Cmd.DEVICE_AUTH, device_id, kept) == ack()

            async def confirm():
                request = await again.recv()
                await again.send(Cmd.SECRET_ACK, request.args[0])
                return request.args[1]

            responder = asyncio.create_task(confirm())
            assert await client.call(Cmd.ROTATE_DEVICE_SECRET, device_id) == ack(device_id)
            rotated = await responder

            for stale in (kept, lost):
                peer = await h.device()
                assert await peer.call(Cmd.DEVICE_AUTH, device_id, stale) == nack(Err.INVALID_CREDENTIALS)
            fresh = await h.device()
            assert await fresh.call(Cmd.DEVICE_AUTH, device_id, rotated) == ack()

    run(scenario())


def test_delete_account_unpairs_devices_and_closes_sessions(tmp_path):
    async def scenario():
        async with running_server(tmp_path) as h:
            client, token = await h.registered_client(password="my password!")
            device, _, _ = await h.paired_device(client)
            other = await h.client()
            await other.call(Cmd.RESUME, token)

            assert await client.call(Cmd.DELETE_ACCOUNT, "my password!") == ack()
            assert await client.recv() is None
            assert await other.recv() is None
            assert await device.recv() == Message(Cmd.UNPAIRED)

            newcomer, _ = await h.registered_client()
            assert (await newcomer.call(Cmd.LIST_DEVICES)).args == ([],)

    run(scenario())


def test_malformed_input_is_contained(tmp_path):
    async def scenario():
        async with running_server(tmp_path) as h:
            peer = await h.client()
            assert await peer.call(Cmd.LIST_TARGETS) == nack(Err.UNAUTHENTICATED)
            await peer.send_raw(b"garbage\n")
            assert await peer.recv() == nack(Err.BAD_FRAME)
            assert await peer.call(Cmd.LOGIN, 123, {"x": 1}) == nack(Err.BAD_ARGS)
            assert await peer.call(Cmd.DEVICE_AUTH, "a", "b") == nack(Err.UNKNOWN_COMMAND)
            assert await peer.call(Cmd.PING) == nack(Err.UNAUTHENTICATED)

            await peer.send_raw(b"x" * (MAX_LINE_BYTES * 2) + b"\n")
            assert await peer.recv() == nack(Err.FRAME_TOO_LONG)
            assert await peer.recv() is None

    run(scenario())


def test_silent_handshake_does_not_block_other_clients(tmp_path):
    async def scenario():
        async with running_server(tmp_path) as h:
            port = h.server.port(Role.CLIENT)
            _, idle_writer = await asyncio.open_connection("127.0.0.1", port)
            try:
                peer, _ = await h.registered_client()
                assert await peer.call(Cmd.PING) == Message(Cmd.PONG)
            finally:
                idle_writer.close()

    run(scenario())


def test_device_heartbeat(tmp_path):
    timeouts = Timeouts(device_ping_interval=0.2, device_dead_after=0.5)

    async def scenario():
        async with running_server(tmp_path, timeouts=timeouts) as h:
            client, _ = await h.registered_client()
            device, _, _ = await h.paired_device(client)
            assert await device.recv(timeout=2) == Message(Cmd.PING)
            await device.send(Cmd.PONG)
            assert await device.recv(timeout=2) == Message(Cmd.PING)
            assert await device.recv(timeout=2) == Message(Cmd.PING)
            assert await device.recv(timeout=2) is None

    run(scenario())


def gate_first_call(obj, name):
    """Make the first call of ``obj.name`` pause after it ran, until the returned event is set."""
    original = getattr(obj, name)
    entered, release = asyncio.Event(), asyncio.Event()
    calls = 0

    async def gated(*args, **kwargs):
        nonlocal calls
        calls += 1
        result = await original(*args, **kwargs)
        if calls == 1:
            entered.set()
            await release.wait()
        return result

    setattr(obj, name, gated)
    return entered, release


def test_login_racing_a_password_change_gets_no_session(tmp_path):
    async def scenario():
        async with running_server(tmp_path) as h:
            phone, _ = await h.registered_client(password="old password")
            entered, release = gate_first_call(h.services.security, "verify_password")

            attacker = await h.client()
            await attacker.send(Cmd.LOGIN, "alice", "old password")
            await entered.wait()
            changed = await phone.call(Cmd.CHANGE_PASSWORD, "old password", "new password")
            assert changed.command == Cmd.ACK
            release.set()

            assert await attacker.recv() == nack(Err.INVALID_CREDENTIALS)
            assert await attacker.call(Cmd.LIST_TARGETS) == nack(Err.UNAUTHENTICATED)

    run(scenario())


def test_resume_racing_a_password_change_is_rejected(tmp_path):
    async def scenario():
        async with running_server(tmp_path) as h:
            phone, token = await h.registered_client(password="old password")
            entered, release = gate_first_call(h.services.sessions, "refresh")

            laptop = await h.client()
            await laptop.send(Cmd.RESUME, token)
            await entered.wait()
            changed = await phone.call(Cmd.CHANGE_PASSWORD, "old password", "new password")
            assert changed.command == Cmd.ACK
            release.set()

            assert await laptop.recv() == nack(Err.INVALID_TOKEN)
            assert await laptop.call(Cmd.LIST_TARGETS) == nack(Err.UNAUTHENTICATED)

    run(scenario())


def test_logged_in_connections_recheck_their_session(tmp_path, monkeypatch):
    monkeypatch.setattr(dispatcher, "SESSION_RECHECK_SECONDS", 0.0)

    async def scenario():
        async with running_server(tmp_path) as h:
            peer, _ = await h.registered_client()
            assert (await peer.call(Cmd.LIST_TARGETS)).command == Cmd.ACK
            # As if another server instance had revoked it.
            await h.services.db.pool.execute("DELETE FROM sessions")
            assert await peer.call(Cmd.LIST_TARGETS) == nack(Err.INVALID_TOKEN)
            assert await peer.recv() is None

    run(scenario())


def test_password_change_and_logout_all_revoke_claims(tmp_path):
    async def scenario():
        async with running_server(tmp_path) as h:
            client, _ = await h.registered_client(password="old password")
            first = await client.call(Cmd.CREATE_CLAIM, "ESP")
            changed = await client.call(Cmd.CHANGE_PASSWORD, "old password", "new password")
            assert changed.command == Cmd.ACK
            device = await h.device()
            assert await device.call(Cmd.DEVICE_CLAIM, first.args[0]) == nack(Err.INVALID_TOKEN)

            second = await client.call(Cmd.CREATE_CLAIM, "ESP")
            assert await client.call(Cmd.LOGOUT_ALL) == ack()
            device = await h.device()
            assert await device.call(Cmd.DEVICE_CLAIM, second.args[0]) == nack(Err.INVALID_TOKEN)

    run(scenario())


def test_concurrent_rotations_leave_device_and_server_in_sync(tmp_path):
    async def scenario():
        async with running_server(tmp_path) as h:
            phone, token = await h.registered_client()
            laptop = await h.client()
            assert await laptop.call(Cmd.RESUME, token) == ack("alice")
            device, device_id, _ = await h.paired_device(phone)

            stored = []

            async def device_stores_secrets():
                for _ in range(2):
                    request = await device.recv()
                    assert request.command == Cmd.SET_SECRET
                    request_id, secret = request.args
                    stored.append(secret)
                    await device.send(Cmd.SECRET_ACK, request_id)

            responder = asyncio.create_task(device_stores_secrets())
            replies = await asyncio.gather(
                phone.call(Cmd.ROTATE_DEVICE_SECRET, device_id),
                laptop.call(Cmd.ROTATE_DEVICE_SECRET, device_id),
            )
            await responder
            assert replies == [ack(device_id), ack(device_id)]

            again = await h.device()
            assert await again.call(Cmd.DEVICE_AUTH, device_id, stored[-1]) == ack()

    run(scenario())


def test_device_error_codes_follow_the_spec(tmp_path):
    async def scenario():
        async with running_server(tmp_path) as h:
            alice, _ = await h.registered_client("alice")
            device, device_id, _ = await h.paired_device(alice)
            mallory, _ = await h.registered_client("mallory")

            malformed = await h.device()
            assert await malformed.call(Cmd.DEVICE_AUTH, "short", "x") == nack(Err.INVALID_CREDENTIALS)

            assert await mallory.call(Cmd.ROTATE_DEVICE_SECRET, device_id) == nack(Err.NOT_FOUND)
            assert await mallory.call(Cmd.ROTATE_DEVICE_SECRET, "no-such-device-id") == nack(Err.NOT_FOUND)
            await device.close()
            await asyncio.sleep(0.1)
            assert await alice.call(Cmd.ROTATE_DEVICE_SECRET, device_id) == nack(Err.DEVICE_OFFLINE)
            assert await mallory.call(Cmd.ROTATE_DEVICE_SECRET, device_id) == nack(Err.NOT_FOUND)

    run(scenario())


def test_failed_logins_of_others_do_not_lock_the_owner_out(tmp_path, monkeypatch):
    async def scenario():
        async with running_server(tmp_path) as h:
            await h.registered_client(password="right password")
            attacker = await h.client()
            for _ in range(12):
                await attacker.call(Cmd.LOGIN, "alice", "wrong password")
            assert await attacker.call(Cmd.LOGIN, "alice", "right password") == nack(Err.RATE_LIMITED)

            # The owner comes from another address.
            original_init = Connection.__init__

            def from_elsewhere(self, reader, writer):
                original_init(self, reader, writer)
                self.peer = "198.51.100.7"

            monkeypatch.setattr(Connection, "__init__", from_elsewhere)
            owner = await h.client()
            assert (await owner.call(Cmd.LOGIN, "alice", "right password")).command == Cmd.ACK

    run(scenario())


@pytest.mark.parametrize("command", [Cmd.WAKE_UP, Cmd.REMOVE_TARGET, Cmd.RENAME_TARGET])
def test_cannot_touch_foreign_targets(tmp_path, command):
    async def scenario():
        async with running_server(tmp_path) as h:
            alice, _ = await h.registered_client("alice")
            _, device_id, _ = await h.paired_device(alice)
            target = (await alice.call(Cmd.ADD_TARGET, device_id, "AABBCCDDEEFF", "PC")).args[0]

            mallory, _ = await h.registered_client("mallory")
            args = (target["id"], "pwned") if command == Cmd.RENAME_TARGET else (target["id"],)
            assert await mallory.call(command, *args) == nack(Err.NOT_FOUND)

    run(scenario())
