"""Connection handling that needs no database: deadlines and connection limits."""

import asyncio
import time

import pytest

from helpers import running_server
from wol_server.app import MAX_PRE_AUTH_BAD_FRAMES, ConnectionLimits, Timeouts
from wol_server.protocol import Cmd, Err, nack
from wol_server.session import Role


def run(coro):
    return asyncio.run(coro)


def test_ping_requires_login(tmp_path):
    async def scenario():
        async with running_server(tmp_path, database=False) as h:
            client, device = await h.client(), await h.device()
            assert await client.call(Cmd.PING) == nack(Err.UNAUTHENTICATED)
            assert await device.call(Cmd.PING) == nack(Err.UNAUTHENTICATED)

    run(scenario())


def test_pre_auth_deadline_is_not_extended_by_chatter(tmp_path):
    timeouts = Timeouts(pre_auth=0.6)

    async def scenario():
        async with running_server(tmp_path, timeouts=timeouts, database=False) as h:
            peer = await h.client()
            started = time.monotonic()
            while time.monotonic() - started < 3:
                try:
                    await peer.send(Cmd.PING)
                except ConnectionError:
                    break
                if await peer.recv() is None:
                    break
                await asyncio.sleep(0.1)
            assert time.monotonic() - started < 1.5

    run(scenario())


def test_bad_frames_before_login_disconnect(tmp_path):
    async def scenario():
        async with running_server(tmp_path, database=False) as h:
            peer = await h.device()
            for _ in range(MAX_PRE_AUTH_BAD_FRAMES):
                await peer.send_raw(b"garbage\n")
                assert await peer.recv() == nack(Err.BAD_FRAME)
            assert await peer.recv() is None

    run(scenario())


def test_ports_have_separate_limits(tmp_path):
    limits = ConnectionLimits(per_ip=2, per_port=2)

    async def scenario():
        async with running_server(tmp_path, limits=limits, database=False) as h:
            await h.client()
            await h.client()
            with pytest.raises(OSError):
                third = await h.client()
                await third.call(Cmd.PING)
            device = await h.device()
            assert await device.call(Cmd.PING) == nack(Err.UNAUTHENTICATED)

    run(scenario())


def test_silent_tcp_connections_are_counted_before_tls(tmp_path):
    limits = ConnectionLimits(pre_auth_per_ip=2)

    async def scenario():
        async with running_server(tmp_path, limits=limits, database=False) as h:
            port = h.server.port(Role.CLIENT)
            silent = [await asyncio.open_connection("127.0.0.1", port) for _ in range(2)]
            await asyncio.sleep(0.1)
            with pytest.raises(OSError):
                peer = await h.client()
                await peer.call(Cmd.PING)

            _, writer = silent.pop()
            writer.close()
            await asyncio.sleep(0.2)
            peer = await h.client()
            assert await peer.call(Cmd.PING) == nack(Err.UNAUTHENTICATED)
            for _, writer in silent:
                writer.close()

    run(scenario())


def test_silent_tcp_connection_times_out_in_handshake(tmp_path):
    timeouts = Timeouts(handshake=0.3)

    async def scenario():
        async with running_server(tmp_path, timeouts=timeouts, database=False) as h:
            reader, writer = await asyncio.open_connection("127.0.0.1", h.server.port(Role.DEVICE))
            try:
                assert await asyncio.wait_for(reader.read(), 2) == b""
            except ConnectionError:
                pass
            finally:
                writer.close()

    run(scenario())
