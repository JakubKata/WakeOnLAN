"""Device management for authenticated clients."""

import logging

from .. import validation as validate
from ..context import Context
from ..dispatcher import Router
from ..errors import CommandError
from ..protocol import Cmd, Err, Message, ack
from ..session import Role

log = logging.getLogger(__name__)
router = Router(Role.CLIENT)

CLAIM_TTL_SECONDS = 10 * 60
CLAIM_TOKEN_BYTES = 16
DEVICE_SECRET_BYTES = 32
DEVICE_REQUEST_TIMEOUT = 5.0


@router.route(Cmd.CREATE_CLAIM, schema=(str,), rate_limit="create_claim")
async def create_claim(ctx: Context, device_name: str) -> Message:
    """Issue a one-time token the user enters on a new device (serial console or Kconfig)."""
    device_name = validate.label(device_name)
    services = ctx.services
    token = services.security.new_token(CLAIM_TOKEN_BYTES)
    await services.claims.create(
        ctx.session.user_id, services.security.token_hash(token), device_name, CLAIM_TTL_SECONDS
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
    await services.devices.delete(ctx.session.user_id, device_id)
    await services.registry.unpair_device(device_id)
    log.info("user %d removed device %s", ctx.session.user_id, device_id)
    return ack(device_id)


@router.route(Cmd.ROTATE_DEVICE_SECRET, schema=(str,))
async def rotate_device_secret(ctx: Context, device_id: str) -> Message:
    """Replace a device secret; the old one stays valid until the device confirms."""
    services, user_id = ctx.services, ctx.session.user_id
    device_id = validate.device_id(device_id)
    link = services.registry.device(device_id)
    if link is None or link.user_id != user_id:
        if not await services.devices.owns(user_id, device_id):
            raise CommandError(Err.NOT_FOUND)
        raise CommandError(Err.DEVICE_OFFLINE)

    # Interleaved rotations could leave the device storing a different secret than the server.
    async with link.rotation_lock:
        secret = services.security.new_token(DEVICE_SECRET_BYTES)
        secret_hash = services.security.token_hash(secret)
        await services.devices.stage_secret(user_id, device_id, secret_hash)
        if not await link.request(Cmd.SET_SECRET, secret, timeout=DEVICE_REQUEST_TIMEOUT):
            # Unknown whether the device stored the secret; its next DEVICE_AUTH settles that
            # before another rotation can overwrite the staged one.
            services.registry.detach_device(device_id, link.conn)
            raise CommandError(Err.DEVICE_UNREACHABLE)
        if not await services.devices.promote_secret(device_id, secret_hash):
            log.warning("secret of device %s changed during rotation by user %d", device_id, user_id)
            raise CommandError(Err.DEVICE_UNREACHABLE)
    log.info("user %d rotated the secret of device %s", user_id, device_id)
    return ack(device_id)
