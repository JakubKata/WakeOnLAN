"""Account management for authenticated clients."""

import logging

from .. import validation as validate
from ..context import Context
from ..dispatcher import Router
from ..errors import CommandError
from ..protocol import Cmd, Err, Message, ack
from ..session import Role
from .auth import start_session, unbind_session

log = logging.getLogger(__name__)
router = Router(Role.CLIENT)


async def confirm_password(ctx: Context, password: str) -> None:
    services, user_id = ctx.services, ctx.session.user_id
    services.limiter.require("password_check", user_id)
    user = await services.users.by_id(user_id)
    if user is None or not await services.security.verify_password(user.password_hash, password):
        log.warning("wrong password confirmation for user %d from %s", user_id, ctx.session.peer)
        raise CommandError(Err.INVALID_CREDENTIALS)


def end_connection(ctx: Context) -> None:
    unbind_session(ctx)
    ctx.session.close_requested = True


@router.route(Cmd.LOGOUT)
async def logout(ctx: Context) -> Message:
    await ctx.services.sessions.delete(ctx.session.token_hash)
    end_connection(ctx)
    return ack()


@router.route(Cmd.LOGOUT_ALL)
async def logout_all(ctx: Context) -> Message:
    services, user_id = ctx.services, ctx.session.user_id
    await services.users.revoke_all(user_id)
    services.registry.kick_user(user_id, keep=ctx.conn)
    end_connection(ctx)
    log.info("user %d logged out everywhere", user_id)
    return ack()


@router.route(Cmd.CHANGE_PASSWORD, schema=(str, str))
async def change_password(ctx: Context, old_password: str, new_password: str) -> Message:
    validate.password(new_password)
    await confirm_password(ctx, old_password)

    services, user_id = ctx.services, ctx.session.user_id
    password_hash = await services.security.hash_password(new_password)
    epoch = await services.users.change_password(user_id, password_hash)
    services.registry.kick_user(user_id, keep=ctx.conn)
    log.info("user %d changed password; other sessions revoked", user_id)
    try:
        return ack(await start_session(ctx, user_id, epoch))
    except CommandError:
        # This connection's own session is gone too; it must not stay logged in.
        end_connection(ctx)
        raise


@router.route(Cmd.CHANGE_NAME, schema=(str, str))
async def change_name(ctx: Context, new_name: str, password: str) -> Message:
    new_name = validate.username(new_name)
    await confirm_password(ctx, password)
    await ctx.services.users.rename(ctx.session.user_id, new_name)
    log.info("user %d renamed to %s", ctx.session.user_id, new_name)
    return ack(new_name)


@router.route(Cmd.DELETE_ACCOUNT, schema=(str,))
async def delete_account(ctx: Context, password: str) -> Message:
    await confirm_password(ctx, password)

    services, user_id = ctx.services, ctx.session.user_id
    for device_id in await services.users.delete(user_id):
        await services.registry.unpair_device(device_id)
    services.registry.kick_user(user_id, keep=ctx.conn)
    end_connection(ctx)
    log.info("user %d deleted their account", user_id)
    return ack()
