"""Client commands available before authentication."""

import logging
import time

from .. import validation as validate
from ..context import Context
from ..dispatcher import Router
from ..errors import CommandError
from ..protocol import Cmd, Err, Message, ack
from ..session import Role

log = logging.getLogger(__name__)
router = Router(Role.CLIENT)

SESSION_TTL_SECONDS = 30 * 24 * 3600


async def start_session(ctx: Context, user_id: int, epoch: int) -> str:
    """Issue a new session token and bind this connection to the user.

    ``epoch`` is the user's session epoch read before the credentials were checked;
    if a revocation happened since, no session is created.
    """
    services = ctx.services
    token = services.security.new_token()
    token_hash = services.security.token_hash(token)
    if not await services.sessions.create(user_id, token_hash, SESSION_TTL_SECONDS, epoch=epoch):
        log.warning("credentials of user %d were revoked during login from %s", user_id, ctx.session.peer)
        raise CommandError(Err.INVALID_CREDENTIALS)
    await bind_session(ctx, user_id, token_hash)
    return token


async def bind_session(ctx: Context, user_id: int, token_hash: str) -> None:
    session = ctx.session
    session.user_id = user_id
    session.token_hash = token_hash
    session.verified_at = time.monotonic()
    ctx.services.registry.add_client(user_id, ctx.conn)
    # A revocation that ran before add_client could not kick this connection.
    if not await ctx.services.sessions.exists(token_hash):
        unbind_session(ctx)
        raise CommandError(Err.INVALID_TOKEN)


def unbind_session(ctx: Context) -> None:
    session = ctx.session
    if session.user_id is not None:
        ctx.services.registry.remove_client(session.user_id, ctx.conn)
    session.user_id = None
    session.token_hash = None


@router.route(Cmd.PING)
async def ping(ctx: Context) -> Message:
    return Message(Cmd.PONG)


@router.route(Cmd.REGISTER, schema=(str, str, str), auth=False, rate_limit="register")
async def register(ctx: Context, name: str, email: str, password: str) -> Message:
    name = validate.username(name)
    email = validate.email(email)
    validate.password(password)

    services = ctx.services
    services.limiter.require("register_email", email.casefold())
    password_hash = await services.security.hash_password(password)
    token = services.security.new_token()
    token_hash = services.security.token_hash(token)
    user_id = await services.users.register(name, email, password_hash, token_hash, SESSION_TTL_SECONDS)
    await bind_session(ctx, user_id, token_hash)
    log.info("registered user %d (%s) from %s", user_id, name, ctx.session.peer)
    return ack(token, name)


@router.route(Cmd.LOGIN, schema=(str, str), auth=False, rate_limit="login")
async def login(ctx: Context, name: str, password: str) -> Message:
    services, peer = ctx.services, ctx.session.peer
    well_formed = validate.is_username(name)
    account = name.casefold()
    # Only failures count, per account and address, so nobody can lock another user out.
    # Malformed names cannot match an account and must not fill the limiter with buckets.
    buckets = (("login_account", (account, peer)), ("login_account_global", account)) if well_formed else ()
    if not all(services.limiter.peek(action, key) for action, key in buckets):
        log.warning("login throttled for account %r from %s", name, peer)
        raise CommandError(Err.RATE_LIMITED)
    # Charged before any await so concurrent attempts cannot share the last token.
    for action, key in buckets:
        services.limiter.consume(action, key)

    user = await services.users.by_name(name) if well_formed else None
    if not await services.security.verify_password(user.password_hash if user else None, password):
        log.warning("failed login for %r from %s", name, peer)
        raise CommandError(Err.INVALID_CREDENTIALS)
    for action, key in buckets:
        services.limiter.refund(action, key)

    if services.security.needs_rehash(user.password_hash):
        new_hash = await services.security.hash_password(password)
        await services.users.rehash_password(user.id, user.password_hash, new_hash)
    token = await start_session(ctx, user.id, user.session_epoch)
    log.info("user %d logged in from %s", user.id, peer)
    return ack(token, user.name)


@router.route(Cmd.RESUME, schema=(str,), auth=False, rate_limit="resume")
async def resume(ctx: Context, token: str) -> Message:
    services = ctx.services
    token_hash = services.security.token_hash(validate.token(token))
    user_id = await services.sessions.refresh(token_hash, SESSION_TTL_SECONDS)
    user = await services.users.by_id(user_id) if user_id is not None else None
    if user is None:
        raise CommandError(Err.INVALID_TOKEN)
    await bind_session(ctx, user.id, token_hash)
    return ack(user.name)
