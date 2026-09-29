import asyncio
import dataclasses

import pytest

from helpers import make_services
from wol_server.context import Context
from wol_server.db import Database
from wol_server.dispatcher import Dispatcher, Router
from wol_server.errors import CommandError
from wol_server.protocol import Err, Message, ack, nack
from wol_server.ratelimit import RateLimiter, Rule
from wol_server.session import Role, Session


class StubConn:
    peer = "192.0.2.1"


router = Router(Role.CLIENT)


@router.route("ECHO", schema=(str, int))
async def echo(ctx, text, number):
    return ack(text, number)


@router.route("HELLO", auth=False, rate_limit="hello")
async def hello(ctx):
    return ack()


@router.route("FAIL")
async def fail(ctx):
    raise CommandError(Err.NOT_FOUND)


@router.route("CRASH")
async def crash(ctx):
    raise RuntimeError("boom")


@pytest.fixture
def make_ctx():
    limiter = RateLimiter({"hello": Rule(capacity=1, refill_seconds=60)})
    services = make_services(Database("postgresql://unused"), limiter)

    def factory(user_id=None, role=Role.CLIENT):
        return Context(services, Session(role, "192.0.2.1", user_id=user_id), StubConn())

    return factory


def dispatch(ctx, command, *args):
    return asyncio.run(Dispatcher([router]).dispatch(ctx, Message(command, args)))


def test_happy_path(make_ctx):
    assert dispatch(make_ctx(user_id=1), "ECHO", "x", 2) == ack("x", 2)


def test_unknown_and_wrong_role(make_ctx):
    assert dispatch(make_ctx(1), "NOPE") == nack(Err.UNKNOWN_COMMAND)
    assert dispatch(make_ctx(role=Role.DEVICE), "HELLO") == nack(Err.UNKNOWN_COMMAND)


def test_auth_requirements(make_ctx):
    assert dispatch(make_ctx(), "ECHO", "x", 1) == nack(Err.UNAUTHENTICATED)
    assert dispatch(make_ctx(user_id=1), "HELLO") == nack(Err.ALREADY_AUTHENTICATED)


@pytest.mark.parametrize("args", [(), ("x",), ("x", 1, 2), (1, 1), ("x", "1"), ("x", True), ("x", 1.0)])
def test_schema_is_strict(make_ctx, args):
    assert dispatch(make_ctx(1), "ECHO", *args) == nack(Err.BAD_ARGS)


def test_rate_limit(make_ctx):
    assert dispatch(make_ctx(), "HELLO") == ack()
    assert dispatch(make_ctx(), "HELLO") == nack(Err.RATE_LIMITED)


def test_errors_become_nacks(make_ctx):
    assert dispatch(make_ctx(1), "FAIL") == nack(Err.NOT_FOUND)
    assert dispatch(make_ctx(1), "CRASH") == nack(Err.INTERNAL)


class StubSessions:
    def __init__(self, alive):
        self.alive = alive
        self.checks = 0

    async def exists(self, token_hash):
        self.checks += 1
        return self.alive


@pytest.mark.parametrize("alive", [True, False])
def test_session_is_rechecked_periodically(make_ctx, alive):
    ctx = make_ctx(user_id=1)
    sessions = StubSessions(alive)
    ctx = Context(dataclasses.replace(ctx.services, sessions=sessions), ctx.session, ctx.conn)
    ctx.session.token_hash = "hash"

    expected = ack("x", 1) if alive else nack(Err.INVALID_TOKEN)
    assert dispatch(ctx, "ECHO", "x", 1) == expected
    assert ctx.session.close_requested is not alive
    if alive:
        assert dispatch(ctx, "ECHO", "x", 1) == expected
        assert sessions.checks == 1


def test_duplicate_routes_rejected():
    other = Router(Role.CLIENT)
    other.route("ECHO")(echo)
    with pytest.raises(ValueError):
        Dispatcher([router, other])
