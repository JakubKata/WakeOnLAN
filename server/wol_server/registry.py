"""Live connections and ordering of device admission against owner revocation."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import secrets
from collections import defaultdict
from collections.abc import AsyncIterator
from weakref import WeakValueDictionary

from .protocol import Cmd, Message
from .transport import Connection

log = logging.getLogger(__name__)


class DeviceLink:
    """An authenticated device connection that can carry acknowledged requests."""

    def __init__(self, device_id: str, user_id: int, conn: Connection):
        self.device_id = device_id
        self.user_id = user_id
        self.conn = conn
        self._pending: dict[str, asyncio.Future[None]] = {}

    async def request(self, command: str, *args: object, timeout: float) -> bool:
        """Send ``command(request_id, *args)`` and wait until the device acknowledges it."""
        request_id = secrets.token_hex(8)
        future: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        self._pending[request_id] = future
        try:
            await self.conn.send(Message(command, (request_id, *args)))
            await asyncio.wait_for(future, timeout)
            return True
        except (TimeoutError, OSError):
            return False
        finally:
            self._pending.pop(request_id, None)

    def resolve(self, request_id: str) -> bool:
        future = self._pending.get(request_id)
        if future is None or future.done():
            return False
        future.set_result(None)
        return True

    def close(self) -> None:
        self.conn.close()
        for future in self._pending.values():
            if not future.done():
                future.set_exception(ConnectionResetError("device disconnected"))


class Registry:
    def __init__(self) -> None:
        self._devices: dict[str, DeviceLink] = {}
        self._clients: defaultdict[int, set[Connection]] = defaultdict(set)
        self._owner_locks: WeakValueDictionary[int, asyncio.Lock] = WeakValueDictionary()

    @contextlib.asynccontextmanager
    async def device_owner(self, user_id: int) -> AsyncIterator[None]:
        """Order database checks and live-device changes for one owner.

        Weak references retain locks only while an operation holds or awaits one.
        All access happens on the event loop, before the first suspension point.
        """
        lock = self._owner_locks.get(user_id)
        if lock is None:
            lock = asyncio.Lock()
            self._owner_locks[user_id] = lock
        async with lock:
            yield

    def attach_device(self, link: DeviceLink) -> None:
        """Register a device, replacing (and closing) its previous connection."""
        previous = self._devices.get(link.device_id)
        self._devices[link.device_id] = link
        if previous is not None and previous is not link:
            log.warning(
                "device %s reconnected from %s, closing old connection from %s",
                link.device_id, link.conn.peer, previous.conn.peer,
            )
            previous.close()

    def detach_device(self, device_id: str, conn: Connection) -> None:
        link = self._devices.get(device_id)
        if link is not None and link.conn is conn:
            del self._devices[device_id]
            link.close()

    def device(self, device_id: str) -> DeviceLink | None:
        return self._devices.get(device_id)

    def is_online(self, device_id: str) -> bool:
        return device_id in self._devices

    async def unpair_device(self, device_id: str, expected_user_id: int) -> None:
        """Drop a removed owner's link without touching a subsequent owner's link."""
        link = self._devices.get(device_id)
        if link is None or link.user_id != expected_user_id:
            return
        del self._devices[device_id]
        with contextlib.suppress(OSError):
            await link.conn.send(Message(Cmd.UNPAIRED))
        link.close()

    def add_client(self, user_id: int, conn: Connection) -> None:
        self._clients[user_id].add(conn)

    def remove_client(self, user_id: int, conn: Connection) -> None:
        connections = self._clients.get(user_id)
        if connections is None:
            return
        connections.discard(conn)
        if not connections:
            del self._clients[user_id]

    def kick_user(self, user_id: int, *, keep: Connection | None = None) -> None:
        """Close every client connection of a user except ``keep``."""
        for conn in list(self._clients.get(user_id, ())):
            if conn is not keep:
                conn.close()
                self.remove_client(user_id, conn)
