from __future__ import annotations

import asyncio
import contextlib
import functools
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass

from .config import Settings
from .context import Context, Services
from .dispatcher import Dispatcher
from .protocol import MAX_LINE_BYTES, Cmd, Err, Message, ProtocolError, nack
from .ratelimit import ConnectionLimiter
from .session import Role, Session
from .transport import CLOSE_TIMEOUT, Connection, FrameTooLong
from .tls import ReloadableTLS

log = logging.getLogger(__name__)

MAX_PRE_AUTH_BAD_FRAMES = 3


@dataclass(frozen=True)
class Timeouts:
    handshake: float = 5.0
    pre_auth: float = 30.0
    client_idle: float = 300.0
    device_ping_interval: float = 30.0
    device_dead_after: float = 90.0
    purge_interval: float = 3600.0


@dataclass(frozen=True)
class ConnectionLimits:
    """Applied to each port separately, so a flood on one port cannot lock out the other."""

    per_ip: int = 20
    per_port: int = 1000
    # Connections still in the TLS handshake or not yet logged in.
    pre_auth_per_ip: int = 5
    pre_auth_per_port: int = 256


class WolServer:
    def __init__(
        self,
        settings: Settings,
        services: Services,
        dispatcher: Dispatcher,
        *,
        timeouts: Timeouts = Timeouts(),
        limits: ConnectionLimits = ConnectionLimits(),
    ):
        self._settings = settings
        self._services = services
        self._dispatcher = dispatcher
        self._timeouts = timeouts
        self._limiters = {role: ConnectionLimiter(limits.per_ip, limits.per_port) for role in Role}
        self._pre_auth_limiters = {
            role: ConnectionLimiter(limits.pre_auth_per_ip, limits.pre_auth_per_port) for role in Role
        }
        self._tls: ReloadableTLS | None = None
        self._connections: set[Connection] = set()
        self._servers: dict[Role, asyncio.Server] = {}
        self._purge_task: asyncio.Task[None] | None = None
        self._tls_reload_task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        self._tls = ReloadableTLS(self._settings)
        ports = {Role.CLIENT: self._settings.client_port, Role.DEVICE: self._settings.device_port}
        for role, port in ports.items():
            # TLS starts in _on_connect, after the connection limits are checked.
            self._servers[role] = await asyncio.start_server(
                functools.partial(self._on_connect, role),
                self._settings.host,
                port,
                limit=MAX_LINE_BYTES,
            )
            log.info("%s port listening on %s:%d", role.value, self._settings.host, self.port(role))
        self._purge_task = asyncio.create_task(self._purge_loop())
        self._tls_reload_task = asyncio.create_task(self._tls_reload_loop())

    def port(self, role: Role) -> int:
        return self._servers[role].sockets[0].getsockname()[1]

    async def serve_forever(self) -> None:
        await asyncio.gather(*(server.serve_forever() for server in self._servers.values()))

    async def close(self) -> None:
        tasks = [task for task in (self._purge_task, self._tls_reload_task) if task is not None]
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        for server in self._servers.values():
            server.close()
        connections = list(self._connections)
        for conn in connections:
            conn.close()
        await asyncio.gather(*(conn.wait_closed() for conn in connections))
        for server in self._servers.values():
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(server.wait_closed(), 5)
        log.info("server stopped")

    async def _on_connect(self, role: Role, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peername = writer.get_extra_info("peername")
        peer: str = peername[0] if peername else "unknown"
        limiter, pre_auth = self._limiters[role], self._pre_auth_limiters[role]
        if not limiter.acquire(peer):
            log.warning("%s connection limit reached, rejecting %s", role.value, peer)
            await _abort(writer)
            return
        if not pre_auth.acquire(peer):
            limiter.release(peer)
            log.warning("%s unauthenticated connection limit reached, rejecting %s", role.value, peer)
            await _abort(writer)
            return

        pre_auth_held = True

        def authenticated() -> None:
            nonlocal pre_auth_held
            if pre_auth_held:
                pre_auth_held = False
                pre_auth.release(peer)

        try:
            try:
                assert self._tls is not None
                await writer.start_tls(self._tls.context, ssl_handshake_timeout=self._timeouts.handshake)
            except OSError as exc:
                log.debug("%s TLS handshake with %s failed: %r", role.value, peer, exc)
                await _abort(writer)
                return
            await self._run_connection(role, Connection(reader, writer), authenticated)
        finally:
            authenticated()
            limiter.release(peer)

    async def _run_connection(self, role: Role, conn: Connection, on_authenticated: Callable[[], None]) -> None:
        self._connections.add(conn)
        ctx = Context(self._services, Session(role, conn.peer), conn)
        log.debug("%s connected from %s", role.value, conn.peer)
        try:
            await self._serve(ctx, on_authenticated)
        except OSError as exc:
            log.debug("%s %s dropped: %r", role.value, conn.peer, exc)
        except Exception:
            log.exception("unexpected error on %s connection from %s", role.value, conn.peer)
        finally:
            await self._cleanup(ctx)
            self._connections.discard(conn)

    async def _serve(self, ctx: Context, on_authenticated: Callable[[], None]) -> None:
        session, conn = ctx.session, ctx.conn
        # Counted from the connection, not from the last message, so chatter cannot extend it.
        auth_deadline = time.monotonic() + self._timeouts.pre_auth
        last_activity = time.monotonic()
        bad_frames = 0
        while not session.close_requested and not conn.closed:
            try:
                message = await conn.read_message(self._read_timeout(session, auth_deadline))
            except TimeoutError:
                if await self._on_idle(ctx, time.monotonic() - last_activity):
                    continue
                log.debug("%s %s timed out", session.role.value, conn.peer)
                return
            except ProtocolError:
                await conn.send(nack(Err.BAD_FRAME))
                if not session.authenticated:
                    bad_frames += 1
                    if bad_frames >= MAX_PRE_AUTH_BAD_FRAMES:
                        log.debug("%s %s sent too many bad frames", session.role.value, conn.peer)
                        return
                continue
            except FrameTooLong:
                await conn.send(nack(Err.FRAME_TOO_LONG))
                return

            if message is None:
                return
            last_activity = time.monotonic()
            reply = await self._dispatcher.dispatch(ctx, message)
            if session.authenticated:
                on_authenticated()
            if reply is not None:
                await conn.send(reply)

    def _read_timeout(self, session: Session, auth_deadline: float) -> float:
        if not session.authenticated:
            return max(0.0, auth_deadline - time.monotonic())
        if session.role is Role.DEVICE:
            return self._timeouts.device_ping_interval
        return self._timeouts.client_idle

    async def _on_idle(self, ctx: Context, idle_seconds: float) -> bool:
        """Keep an authenticated device alive with PINGs; drop everything else that goes quiet."""
        session = ctx.session
        if session.role is not Role.DEVICE or not session.authenticated:
            return False
        if idle_seconds >= self._timeouts.device_dead_after:
            log.info("device %s missed heartbeats, dropping", session.device_id)
            return False
        await ctx.conn.send(Message(Cmd.PING))
        return True

    async def _cleanup(self, ctx: Context) -> None:
        session, registry = ctx.session, self._services.registry
        if session.role is Role.DEVICE and session.device_id is not None:
            registry.detach_device(session.device_id, ctx.conn)
            with contextlib.suppress(Exception):
                await self._services.devices.touch(session.device_id)
        elif session.user_id is not None:
            registry.remove_client(session.user_id, ctx.conn)
        ctx.conn.close()
        await ctx.conn.wait_closed()

    async def _purge_loop(self) -> None:
        while True:
            await asyncio.sleep(self._timeouts.purge_interval)
            try:
                sessions = await self._services.sessions.purge_expired()
                claims = await self._services.claims.purge_expired()
                resets = await self._services.resets.purge_expired()
                log.debug(
                    "purged %d expired sessions, %d claims and %d password resets",
                    sessions, claims, resets,
                )
            except Exception:
                log.exception("purging expired records failed")

    async def _tls_reload_loop(self) -> None:
        assert self._tls is not None
        while True:
            await asyncio.sleep(self._settings.tls_reload_interval)
            await asyncio.to_thread(self._tls.reload_if_changed)


async def _abort(writer: asyncio.StreamWriter) -> None:
    writer.close()
    with contextlib.suppress(Exception):
        await asyncio.wait_for(writer.wait_closed(), CLOSE_TIMEOUT)
