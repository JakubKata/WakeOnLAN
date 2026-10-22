"""Live-device ownership races, without relying on PostgreSQL scheduling."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from helpers import new_device_credentials
from wol_server.context import Context
from wol_server.db import Device, Target
from wol_server.errors import CommandError
from wol_server.handlers import account, devices, esp, targets
from wol_server.protocol import Cmd, Err, Message
from wol_server.registry import DeviceLink, Registry
from wol_server.session import Role, Session


class FakeConnection:
    peer = "test-device"

    def __init__(self):
        self.closed = False
        self.sent = []

    async def send(self, message):
        self.sent.append(message)

    def close(self):
        self.closed = True


def test_old_owner_cleanup_preserves_replacement_owner():
    async def scenario():
        registry = Registry()
        old, new = FakeConnection(), FakeConnection()
        registry.attach_device(DeviceLink("device", 1, old))
        registry.attach_device(DeviceLink("device", 2, new))
        await registry.unpair_device("device", 1)
        assert registry.device("device").conn is new
        assert old.closed and not new.closed
        assert new.sent == []

    asyncio.run(scenario())


def test_owner_cleanup_revokes_current_reconnection():
    async def scenario():
        registry = Registry()
        old, new = FakeConnection(), FakeConnection()
        registry.attach_device(DeviceLink("device", 1, old))
        registry.attach_device(DeviceLink("device", 1, new))
        await registry.unpair_device("device", 1)
        assert registry.device("device") is None
        assert old.closed and new.closed
        assert new.sent == [Message(Cmd.UNPAIRED)]

    asyncio.run(scenario())


def test_stale_target_cannot_wake_replacement_owner():
    async def scenario():
        registry = Registry()
        link = DeviceLink("device", 2, FakeConnection())
        link.request = AsyncMock(return_value=True)
        registry.attach_device(link)
        services = SimpleNamespace(
            registry=registry,
            limiter=SimpleNamespace(require=Mock()),
            targets=SimpleNamespace(get=AsyncMock(return_value=Target(1, "device", "AABBCCDDEEFF", "PC"))),
        )
        ctx = Context(services, Session(Role.CLIENT, "client", user_id=1), FakeConnection())
        with pytest.raises(CommandError) as exc:
            await targets.wake_up(ctx, 1)
        assert exc.value.code is Err.DEVICE_OFFLINE
        link.request.assert_not_awaited()

    asyncio.run(scenario())


def contexts(monkeypatch):
    device_id, secret = new_device_credentials()
    state = SimpleNamespace(device=Device(device_id, 1, "Device", None))
    registry = Registry()

    async def owns(user_id, requested_id):
        return state.device is not None and (state.device.user_id, state.device.id) == (user_id, requested_id)

    async def remove(*args):
        state.device = None
        return [device_id]

    services = SimpleNamespace(
        registry=registry,
        devices=SimpleNamespace(
            owns=owns,
            delete=remove,
            authenticate=AsyncMock(return_value=state.device),
            redeem_claim=AsyncMock(return_value=state.device),
        ),
        users=SimpleNamespace(delete=remove),
        security=SimpleNamespace(token_hash=lambda value: value),
    )
    monkeypatch.setattr(account, "confirm_password", AsyncMock())
    client = Context(services, Session(Role.CLIENT, "client", user_id=1), FakeConnection())
    device = Context(services, Session(Role.DEVICE, "device"), FakeConnection())
    return state, services, client, device, device_id, secret


async def remove(kind, client, device_id):
    if kind == "device":
        return await devices.remove_device(client, device_id)
    return await account.delete_account(client, "password")


async def admit(kind, ctx, device_id, secret):
    if kind == "auth":
        return await esp.device_auth(ctx, device_id, secret)
    return await esp.device_claim(ctx, "a" * 22, device_id, secret)


@pytest.mark.parametrize("removal", ["device", "account"])
def test_removal_handler_preserves_new_owner(monkeypatch, removal):
    async def scenario():
        state, services, client, _, device_id, _ = contexts(monkeypatch)
        replacement = FakeConnection()

        async def transfer(*args):
            # Simulate a new enrollment completing between DELETE commit and
            # the old owner's cleanup resuming in the event loop.
            state.device = Device(device_id, 2, "New owner", None)
            services.registry.attach_device(DeviceLink(device_id, 2, replacement))
            return [device_id]

        services.devices.delete = services.users.delete = transfer
        await remove(removal, client, device_id)
        assert services.registry.device(device_id).conn is replacement
        assert not replacement.closed and replacement.sent == []

    asyncio.run(scenario())


@pytest.mark.parametrize("removal", ["device", "account"])
@pytest.mark.parametrize("admission", ["auth", "claim"])
def test_stale_admission_cannot_replace_new_owner(monkeypatch, removal, admission):
    async def scenario():
        state, services, client, device, device_id, secret = contexts(monkeypatch)
        read_finished, resume = asyncio.Event(), asyncio.Event()
        original = state.device

        async def stale_result(*args):
            read_finished.set()
            await resume.wait()
            return original

        services.devices.authenticate = services.devices.redeem_claim = stale_result
        task = asyncio.create_task(admit(admission, device, device_id, secret))
        await read_finished.wait()
        await remove(removal, client, device_id)
        replacement = FakeConnection()
        state.device = Device(device_id, 2, "New owner", None)
        services.registry.attach_device(DeviceLink(device_id, 2, replacement))
        resume.set()
        with pytest.raises(CommandError) as exc:
            await task
        assert exc.value.code is (Err.INVALID_CREDENTIALS if admission == "auth" else Err.INVALID_TOKEN)
        assert not device.session.authenticated
        assert services.registry.device(device_id).conn is replacement
        assert not replacement.closed and replacement.sent == []

    asyncio.run(scenario())


@pytest.mark.parametrize("removal", ["device", "account"])
@pytest.mark.parametrize("admission", ["auth", "claim"])
def test_removal_cannot_cross_final_ownership_check(monkeypatch, removal, admission):
    async def scenario():
        state, services, client, device, device_id, secret = contexts(monkeypatch)
        check_started, resume_check, delete_started = asyncio.Event(), asyncio.Event(), asyncio.Event()
        original_remove = services.devices.delete

        async def ownership_check(*args):
            owned = state.device is not None
            check_started.set()
            await resume_check.wait()
            return owned

        async def deletion(*args):
            delete_started.set()
            return await original_remove(*args)

        services.devices.owns = ownership_check
        services.devices.delete = services.users.delete = deletion
        admission_task = asyncio.create_task(admit(admission, device, device_id, secret))
        await check_started.wait()
        removal_task = asyncio.create_task(remove(removal, client, device_id))
        await asyncio.sleep(0)
        assert not delete_started.is_set()
        resume_check.set()
        await admission_task
        await removal_task
        assert delete_started.is_set()
        assert services.registry.device(device_id) is None
        assert device.conn.closed and device.conn.sent == [Message(Cmd.UNPAIRED)]
        assert not services.registry._owner_locks

    asyncio.run(scenario())
