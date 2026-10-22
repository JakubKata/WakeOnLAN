"""Behavioral regressions added by the October 2026 patch review.

These exercise reconnect and removal ordering without a hardware device. The
claim expiry case additionally uses PostgreSQL's real row locks and wall clock.
"""

import asyncio
from types import SimpleNamespace

from helpers import create_user, requires_database, temporary_services
from wol_server.context import Context
from wol_server.handlers.esp import acknowledge
from wol_server.protocol import Cmd, Message
from wol_server.registry import DeviceLink, Registry
from wol_server.session import Role, Session


class RecordingConnection:
    peer = "review-device"

    def __init__(self):
        self.closed = False
        self.sent = []
        self.message_sent = asyncio.Event()

    async def send(self, message):
        self.sent.append(message)
        self.message_sent.set()

    def close(self):
        self.closed = True


def test_reconnect_settles_old_wake_and_ignores_ack_from_replaced_connection():
    async def scenario():
        async with asyncio.timeout(2):
            registry = Registry()
            old_connection, new_connection = RecordingConnection(), RecordingConnection()
            old_link = DeviceLink("device", 1, old_connection)
            registry.attach_device(old_link)
            old_wake = asyncio.create_task(old_link.request(Cmd.WAKE_UP, "AA:BB:CC:DD:EE:FF", timeout=1))
            await old_connection.message_sent.wait()

            new_link = DeviceLink("device", 1, new_connection)
            registry.attach_device(new_link)
            assert await old_wake is False
            assert old_connection.closed

            new_wake = asyncio.create_task(new_link.request(Cmd.WAKE_UP, "AA:BB:CC:DD:EE:FF", timeout=1))
            await new_connection.message_sent.wait()
            request_id = new_connection.sent[0].args[0]
            services = SimpleNamespace(registry=registry)
            session = Session(Role.DEVICE, "review", user_id=1, device_id="device")
            await acknowledge(Context(services, session, old_connection), request_id)
            await asyncio.sleep(0)
            assert not new_wake.done()
            await acknowledge(Context(services, session, new_connection), request_id)
            assert await new_wake is True

    asyncio.run(scenario())


def test_late_wake_ack_cannot_satisfy_a_later_request():
    async def scenario():
        async with asyncio.timeout(2):
            connection = RecordingConnection()
            link = DeviceLink("device", 1, connection)
            assert not await link.request(Cmd.WAKE_UP, "AA:BB:CC:DD:EE:FF", timeout=0.01)
            expired_id = connection.sent[0].args[0]
            connection.message_sent.clear()
            pending = asyncio.create_task(link.request(Cmd.WAKE_UP, "AA:BB:CC:DD:EE:FF", timeout=1))
            await connection.message_sent.wait()
            assert not link.resolve(expired_id)
            assert not pending.done()
            assert link.resolve(connection.sent[-1].args[0])
            assert await pending is True
            assert not link.resolve(connection.sent[-1].args[0])

    asyncio.run(scenario())


def test_delayed_unpair_notification_does_not_close_a_replacement_owner():
    async def scenario():
        async with asyncio.timeout(2):
            registry = Registry()
            old_connection, new_connection = RecordingConnection(), RecordingConnection()
            registry.attach_device(DeviceLink("device", 1, old_connection))
            notification_started, finish_notification = asyncio.Event(), asyncio.Event()

            async def delayed_send(message):
                old_connection.sent.append(message)
                notification_started.set()
                await finish_notification.wait()

            old_connection.send = delayed_send
            removal = asyncio.create_task(registry.unpair_device("device", 1))
            await notification_started.wait()
            registry.attach_device(DeviceLink("device", 2, new_connection))
            finish_notification.set()
            await removal
            assert old_connection.sent == [Message(Cmd.UNPAIRED)]
            assert old_connection.closed
            assert registry.device("device").conn is new_connection
            assert not new_connection.closed
            assert not new_connection.sent

    asyncio.run(scenario())


@requires_database
def test_claim_expired_while_waiting_for_account_lock_is_not_redeemed():
    async def scenario():
        async with asyncio.timeout(5), temporary_services() as services:
            user_id = await create_user(services, "review", "review@example.com", "unused")
            await services.claims.create(user_id, "claim", "Office", "device", ttl=60)
            task = None
            try:
                async with services.db.transaction() as blocker:
                    await blocker.execute("SELECT 1 FROM users WHERE id = $1 FOR UPDATE", user_id)
                    # Other transactions still see the original unexpired claim
                    # until this transaction commits, after redeem_claim waits.
                    await blocker.execute(
                        "UPDATE claims SET expires_at = clock_timestamp() WHERE user_id = $1", user_id,
                    )
                    task = asyncio.create_task(services.devices.redeem_claim("claim", "device", "secret"))
                    while not await services.db.pool.fetchval(
                        "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname = current_database()"
                        " AND wait_event_type = 'Lock' AND query LIKE 'SELECT 1 FROM users%FOR UPDATE')"
                    ):
                        await asyncio.sleep(0.01)
                    assert not task.done()
                assert await task is None
                assert await services.devices.list(user_id) == []
            finally:
                if task is not None and not task.done():
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)

    asyncio.run(scenario())
