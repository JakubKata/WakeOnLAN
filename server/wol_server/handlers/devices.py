"""Device management for authenticated clients."""

import logging

from .. import validation as validate
from ..context import Context
from ..dispatcher import Router
from ..protocol import Cmd, Message, ack
from ..session import Role

log = logging.getLogger(__name__)
router = Router(Role.CLIENT)

CLAIM_TTL_SECONDS = 10 * 60
CLAIM_TOKEN_BYTES = 16


@router.route(Cmd.CREATE_CLAIM, schema=(str, str), rate_limit="create_claim")
async def create_claim(ctx: Context, device_name: str, device_id: str) -> Message:
    """Bind an enrollment token to the identity read over authenticated provisioning."""
    device_name = validate.label(device_name)
    device_id = validate.enrollment_id(device_id)
    services = ctx.services
    token = services.security.new_token(CLAIM_TOKEN_BYTES)
    await services.claims.create(
        ctx.session.user_id, services.security.token_hash(token), device_name, device_id, CLAIM_TTL_SECONDS
    )
    log.info("user %d created a device claim", ctx.session.user_id)
    return ack(token, CLAIM_TTL_SECONDS)


@router.route(Cmd.LIST_DEVICES)
async def list_devices(ctx: Context) -> Message:
    services = ctx.services
    devices = await services.devices.list(ctx.session.user_id)
    return ack([
        {
            "id": device.id,
            "name": device.name,
            "online": services.registry.is_online(device.id),
            "last_seen_at": int(device.last_seen_at.timestamp()) if device.last_seen_at else None,
        }
        for device in devices
    ])


@router.route(Cmd.RENAME_DEVICE, schema=(str, str))
async def rename_device(ctx: Context, device_id: str, name: str) -> Message:
    device_id, name = validate.device_id(device_id), validate.label(name)
    await ctx.services.devices.rename(ctx.session.user_id, device_id, name)
    return ack(device_id, name)


@router.route(Cmd.REMOVE_DEVICE, schema=(str,))
async def remove_device(ctx: Context, device_id: str) -> Message:
    services, device_id = ctx.services, validate.device_id(device_id)
    user_id = ctx.session.user_id
    async with services.registry.device_owner(user_id):
        await services.devices.delete(user_id, device_id)
        await services.registry.unpair_device(device_id, user_id)
    log.info("user %d removed device %s", ctx.session.user_id, device_id)
    return ack(device_id)
