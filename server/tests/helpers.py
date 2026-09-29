from __future__ import annotations

import asyncio
import os
import secrets
import ssl
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import AsyncIterator, Awaitable, Callable

import asyncpg
import pytest
import trustme
from argon2 import PasswordHasher

from wol_server.app import ConnectionLimits, Timeouts, WolServer
from wol_server.config import Settings
from wol_server.context import Services
from wol_server.db import Database
from wol_server.handlers import build_dispatcher
from wol_server.protocol import Cmd, Message
from wol_server.ratelimit import RateLimiter
from wol_server.security import Security
from wol_server.session import Role

PEPPER = b"test-pepper-that-is-long-enough-000"
FAST_HASHER = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)


TEST_DATABASE_URL = os.environ.get("TEST_DATABASE_URL", "")
requires_database = pytest.mark.skipif(
    not TEST_DATABASE_URL, reason="set TEST_DATABASE_URL to run PostgreSQL tests"
)


class FakeMailer:
    """Collects outgoing mail instead of sending it."""

    def __init__(self) -> None:
        self.sent: list[tuple[str, str, str]] = []

    def send_later(self, to: str, subject: str, body: str) -> None:
        self.sent.append((to, subject, body))

    async def close(self) -> None:
        pass


def make_services(
    db: Database, limiter: RateLimiter | None = None, mailer: FakeMailer | None = None
) -> Services:
    return Services.create(db, Security(PEPPER, FAST_HASHER), limiter, mailer)


async def create_user(services: Services, name: str, email: str, password_hash: str) -> int:
    """A bare user row, without the session that ``UsersRepo.register`` adds."""
    return await services.db.pool.fetchval(
        "INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id",
        name, email, password_hash,
    )


@asynccontextmanager
async def temporary_database() -> AsyncIterator[Database]:
    """A migrated database living in a throwaway schema."""
    schema = f"test_{secrets.token_hex(6)}"
    admin = await asyncpg.connect(TEST_DATABASE_URL)
    await admin.execute(f'CREATE SCHEMA "{schema}"')
    db = Database(TEST_DATABASE_URL, schema=schema, max_connections=5)
    try:
        await db.connect()
        await db.migrate()
        yield db
    finally:
        await db.close()
        await admin.execute(f'DROP SCHEMA "{schema}" CASCADE')
        await admin.close()


@asynccontextmanager
async def temporary_services(
    limiter: RateLimiter | None = None, mailer: FakeMailer | None = None
) -> AsyncIterator[Services]:
    async with temporary_database() as db:
        yield make_services(db, limiter, mailer)


class Peer:
    """A test client speaking the line protocol over TLS."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer

    async def send(self, command: str, *args: object) -> None:
        await self.send_raw(Message(command, args).encode())

    async def send_raw(self, data: bytes) -> None:
        self.writer.write(data)
        await self.writer.drain()

    async def recv(self, timeout: float = 5) -> Message | None:
        """The next message, or None once the server has closed the connection."""
        try:
            line = await asyncio.wait_for(self.reader.readline(), timeout)
        except (ConnectionError, ssl.SSLError):
            return None
        return Message.decode(line) if line else None

    async def call(self, command: str, *args: object) -> Message:
        await self.send(command, *args)
        reply = await self.recv()
        assert reply is not None, f"connection closed after {command}"
        return reply

    async def close(self) -> None:
        self.writer.close()
        try:
            await self.writer.wait_closed()
        except (ConnectionError, ssl.SSLError):
            pass


@dataclass
class Harness:
    server: WolServer
    services: Services
    connect: Callable[[Role], Awaitable[Peer]]

    async def client(self) -> Peer:
        return await self.connect(Role.CLIENT)

    async def device(self) -> Peer:
        return await self.connect(Role.DEVICE)

    async def registered_client(self, name: str = "alice", password: str = "correct horse") -> tuple[Peer, str]:
        peer = await self.client()
        reply = await peer.call(Cmd.REGISTER, name, f"{name}@example.com", password)
        assert reply.command == Cmd.ACK, reply
        return peer, reply.args[0]

    async def paired_device(self, client: Peer, name: str = "Desk ESP") -> tuple[Peer, str, str]:
        claim = await client.call(Cmd.CREATE_CLAIM, name)
        assert claim.command == Cmd.ACK, claim
        device = await self.device()
        reply = await device.call(Cmd.DEVICE_CLAIM, claim.args[0])
        assert reply.command == Cmd.ACK, reply
        device_id, secret = reply.args
        return device, device_id, secret


@asynccontextmanager
async def offline_services(
    limiter: RateLimiter | None = None, mailer: FakeMailer | None = None
) -> AsyncIterator[Services]:
    """Services whose database is never connected; enough for transport-level tests."""
    yield make_services(Database("postgresql://unused"), limiter, mailer)


@asynccontextmanager
async def running_server(
    tmp_path: Path,
    *,
    timeouts: Timeouts = Timeouts(),
    limits: ConnectionLimits = ConnectionLimits(),
    limiter: RateLimiter | None = None,
    mailer: FakeMailer | None = None,
    database: bool = True,
) -> AsyncIterator[Harness]:
    ca = trustme.CA()
    cert = ca.issue_cert("localhost", "127.0.0.1")
    cert_file, key_file = tmp_path / "server.crt", tmp_path / "server.key"
    cert.cert_chain_pems[0].write_to_path(cert_file)
    cert.private_key_pem.write_to_path(key_file)

    settings = Settings(
        host="127.0.0.1",
        client_port=0,
        device_port=0,
        cert_file=cert_file,
        key_file=key_file,
        database_url=TEST_DATABASE_URL,
        pepper=PEPPER,
    )
    make = temporary_services if database else offline_services
    async with make(limiter, mailer) as services:
        server = WolServer(settings, services, build_dispatcher(), timeouts=timeouts, limits=limits)
        await server.start()

        client_context = ssl.create_default_context()
        ca.configure_trust(client_context)
        peers: list[Peer] = []

        async def connect(role: Role) -> Peer:
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", server.port(role), ssl=client_context, server_hostname="localhost"
            )
            peer = Peer(reader, writer)
            peers.append(peer)
            return peer

        try:
            yield Harness(server, services, connect)
        finally:
            for peer in peers:
                await peer.close()
            await server.close()
