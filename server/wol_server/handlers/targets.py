"""Wake-on-LAN targets (machines to wake) for authenticated clients."""

import logging

from .. import validation as validate
from ..context import Context
from ..db import Target
from ..dispatcher import Router
from ..errors import CommandError
from ..protocol import Cmd, Err, Message, ack
from ..session import Role
from .devices import DEVICE_REQUEST_TIMEOUT

log = logging.getLogger(__name__)
router = Router(Role.CLIENT)


def serialize(target: Target) -> dict[str, object]:
    return {"id": target.id, "device_id": target.device_id, "mac": target.mac, "name": target.name}


@router.route(Cmd.ADD_TARGET, schema=(str, str, str))
async def add_target(ctx: Context, device_id: str, mac: str, name: str) -> Message:
    target = await ctx.services.targets.add(
        ctx.session.user_id, validate.device_id(device_id), validate.mac(mac), validate.label(name)
    )
    return ack(serialize(target))


@router.route(Cmd.LIST_TARGETS)
async def list_targets(ctx: Context) -> Message:
    targets = await ctx.services.targets.list(ctx.session.user_id)
    return ack([serialize(target) for target in targets])


@router.route(Cmd.RENAME_TARGET, schema=(int, str))
async def rename_target(ctx: Context, target_id: int, name: str) -> Message:
    target_id, name = validate.record_id(target_id), validate.label(name)
    await ctx.services.targets.rename(ctx.session.user_id, target_id, name)
    return ack(target_id, name)


@router.route(Cmd.ASSIGN_TARGET, schema=(int, str))
async def assign_target(ctx: Context, target_id: int, device_id: str) -> Message:
    await ctx.services.targets.assign(
        ctx.session.user_id, validate.record_id(target_id), validate.device_id(device_id)
    )
    return ack(target_id, device_id)


@router.route(Cmd.REMOVE_TARGET, schema=(int,))
async def remove_target(ctx: Context, target_id: int) -> Message:
    await ctx.services.targets.remove(ctx.session.user_id, validate.record_id(target_id))
    return ack(target_id)


@router.route(Cmd.WAKE_UP, schema=(int,))
async def wake_up(ctx: Context, target_id: int) -> Message:
    services, user_id = ctx.services, ctx.session.user_id
    services.limiter.require("wake", user_id)

    target = await services.targets.get(user_id, validate.record_id(target_id))
    if target is None:
        raise CommandError(Err.NOT_FOUND)
    if target.device_id is None:
        raise CommandError(Err.NO_DEVICE)
    link = services.registry.device(target.device_id)
    if link is None:
        raise CommandError(Err.DEVICE_OFFLINE)

    if not await link.request(Cmd.WAKE_UP, target.mac, timeout=DEVICE_REQUEST_TIMEOUT):
        log.warning("device %s did not confirm wake-up of target %d", target.device_id, target_id)
        raise CommandError(Err.DEVICE_UNREACHABLE)
    log.info("user %d woke target %d via device %s", user_id, target_id, target.device_id)
    return ack(target_id)
