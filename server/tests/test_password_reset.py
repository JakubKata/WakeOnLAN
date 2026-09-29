import asyncio
import re
from pathlib import Path

import pytest

from helpers import FakeMailer, requires_database, running_server
from wol_server import validation as validate
from wol_server.config import ConfigError, smtp_settings
from wol_server.errors import CommandError
from wol_server.handlers.password_reset import MAX_RESET_ATTEMPTS
from wol_server.protocol import Cmd, Err, ack, nack
from wol_server.ratelimit import DEFAULT_RULES, RateLimiter, Rule
from wol_server.security import RESET_CODE_LENGTH, Security

CODE_IN_MAIL_RE = re.compile(r"^\s+([0-9A-Z]{5}-[0-9A-Z]{5})$", re.MULTILINE)


def run(coro):
    return asyncio.run(coro)


def mailed_code(mailer: FakeMailer) -> str:
    return CODE_IN_MAIL_RE.search(mailer.sent[-1][2]).group(1)


def test_new_reset_code_passes_validation():
    for _ in range(100):
        code = Security.new_reset_code()
        assert len(code) == RESET_CODE_LENGTH
        assert validate.reset_code(code) == code


def test_reset_code_is_forgiving_about_formatting():
    assert validate.reset_code(" 7k3qd-9xw2m ") == "7K3QD9XW2M"
    assert validate.reset_code("OIL00 11111") == "0110011111"
    for bad in ("", "7K3QD", "7K3QD-9XW2MM", "7K3QD-9XW2U", "7K3QD_9XW2M"):
        with pytest.raises(CommandError):
            validate.reset_code(bad)


def test_smtp_settings():
    assert smtp_settings({}) is None
    s = smtp_settings({"SMTP_HOST": "smtp.x.pl", "SMTP_USER": "bot@x.pl", "SMTP_PASSWORD": "p"})
    assert (s.port, s.security, s.sender) == (587, "starttls", "bot@x.pl")
    assert smtp_settings({"SMTP_HOST": "h", "SMTP_SECURITY": "ssl", "SMTP_FROM": "a@b.c"}).port == 465
    with pytest.raises(ConfigError):
        smtp_settings({"SMTP_HOST": "h", "SMTP_SECURITY": "none", "SMTP_USER": "a@b.c"})
    with pytest.raises(ConfigError):
        smtp_settings({"SMTP_HOST": "h"})


@requires_database
def test_reset_flow(tmp_path: Path):
    async def scenario():
        mailer = FakeMailer()
        async with running_server(tmp_path, mailer=mailer) as h:
            phone, old_token = await h.registered_client(password="forgotten one")

            anonymous = await h.client()
            assert await anonymous.call(Cmd.REQUEST_PASSWORD_RESET, "nobody@example.com") == ack()
            assert mailer.sent == []

            assert await anonymous.call(Cmd.REQUEST_PASSWORD_RESET, "ALICE@example.com") == ack()
            assert mailer.sent[-1][0] == "alice@example.com"
            code = mailed_code(mailer)

            reply = await anonymous.call(Cmd.RESET_PASSWORD, "alice@example.com", code.lower(), "brand new pass")
            assert reply.command == Cmd.ACK and reply.args[1] == "alice"
            assert await phone.recv() is None

            reused = await h.client()
            assert await reused.call(
                Cmd.RESET_PASSWORD, "alice@example.com", code, "another pass"
            ) == nack(Err.INVALID_TOKEN)
            assert await reused.call(Cmd.RESUME, old_token) == nack(Err.INVALID_TOKEN)
            assert await reused.call(Cmd.RESUME, reply.args[0]) == ack("alice")

            fresh = await h.client()
            assert await fresh.call(Cmd.LOGIN, "alice", "forgotten one") == nack(Err.INVALID_CREDENTIALS)
            assert (await fresh.call(Cmd.LOGIN, "alice", "brand new pass")).command == Cmd.ACK

    run(scenario())


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


@requires_database
def test_reset_code_burns_after_too_many_wrong_guesses(tmp_path: Path):
    unthrottled = RateLimiter({
        **DEFAULT_RULES,
        "reset_confirm": Rule(capacity=1000, refill_seconds=1),
        "reset_confirm_email": Rule(capacity=1000, refill_seconds=1),
    })

    async def scenario():
        mailer = FakeMailer()
        async with running_server(tmp_path, mailer=mailer, limiter=unthrottled) as h:
            await h.registered_client()
            peer = await h.client()
            await peer.call(Cmd.REQUEST_PASSWORD_RESET, "alice@example.com")
            code = mailed_code(mailer)

            for _ in range(MAX_RESET_ATTEMPTS):
                assert await peer.call(
                    Cmd.RESET_PASSWORD, "alice@example.com", "0000000000", "new password"
                ) == nack(Err.INVALID_TOKEN)
            assert await peer.call(
                Cmd.RESET_PASSWORD, "alice@example.com", code, "new password"
            ) == nack(Err.INVALID_TOKEN)

    run(scenario())


@requires_database
def test_wrong_guesses_are_throttled_without_burning_the_code(tmp_path: Path):
    clock = FakeClock()
    limiter = RateLimiter(clock=clock)

    async def scenario():
        mailer = FakeMailer()
        async with running_server(tmp_path, mailer=mailer, limiter=limiter) as h:
            await h.registered_client()
            peer = await h.client()
            await peer.call(Cmd.REQUEST_PASSWORD_RESET, "alice@example.com")
            code = mailed_code(mailer)

            replies = [
                await peer.call(Cmd.RESET_PASSWORD, "alice@example.com", "0000000000", "new password")
                for _ in range(6)
            ]
            assert replies[-1] == nack(Err.RATE_LIMITED)
            assert nack(Err.INVALID_TOKEN) in replies

            clock.now += 3600
            reply = await peer.call(Cmd.RESET_PASSWORD, "alice@example.com", code, "new password")
            assert reply.command == Cmd.ACK

    run(scenario())


@requires_database
def test_reset_revokes_pending_claims(tmp_path: Path):
    async def scenario():
        mailer = FakeMailer()
        async with running_server(tmp_path, mailer=mailer) as h:
            owner, _ = await h.registered_client()
            claim = await owner.call(Cmd.CREATE_CLAIM, "Planted ESP")
            assert claim.command == Cmd.ACK

            peer = await h.client()
            await peer.call(Cmd.REQUEST_PASSWORD_RESET, "alice@example.com")
            reply = await peer.call(Cmd.RESET_PASSWORD, "alice@example.com", mailed_code(mailer), "new password")
            assert reply.command == Cmd.ACK

            device = await h.device()
            assert await device.call(Cmd.DEVICE_CLAIM, claim.args[0]) == nack(Err.INVALID_TOKEN)

    run(scenario())


@requires_database
def test_new_request_replaces_old_code(tmp_path: Path):
    async def scenario():
        mailer = FakeMailer()
        async with running_server(tmp_path, mailer=mailer) as h:
            await h.registered_client()
            peer = await h.client()
            await peer.call(Cmd.REQUEST_PASSWORD_RESET, "alice@example.com")
            first = mailed_code(mailer)
            await peer.call(Cmd.REQUEST_PASSWORD_RESET, "alice@example.com")
            second = mailed_code(mailer)

            assert await peer.call(
                Cmd.RESET_PASSWORD, "alice@example.com", first, "new password"
            ) == nack(Err.INVALID_TOKEN)
            assert (await peer.call(
                Cmd.RESET_PASSWORD, "alice@example.com", second, "new password"
            )).command == Cmd.ACK

    run(scenario())


@requires_database
def test_reset_disabled_without_smtp(tmp_path: Path):
    async def scenario():
        async with running_server(tmp_path) as h:
            peer = await h.client()
            assert await peer.call(
                Cmd.REQUEST_PASSWORD_RESET, "alice@example.com"
            ) == nack(Err.RESET_UNAVAILABLE)

    run(scenario())
