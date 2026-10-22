"""Commands sent by ESP32 devices on the device port."""

import logging

from .. import validation as validate
from ..context import Context
from ..db import Device
from ..dispatcher import Router
from ..errors import CommandError
from ..protocol import Cmd, Err, Message, ack
from ..registry import DeviceLink
from ..session import Role

log = logging.getLogger(__name__)
router = Router(Role.DEVICE)


async def attach(ctx: Context, device: Device, failure: Err) -> None:
    services = ctx.services
    async with services.registry.device_owner(device.user_id):
        # Authentication/claim may have finished after a concurrent removal.
        # Recheck under the same owner lock used by both removal handlers.
        if not await services.devices.owns(device.user_id, device.id):
            raise CommandError(failure)
        ctx.session.device_id = device.id
        ctx.session.user_id = device.user_id
        services.registry.attach_device(DeviceLink(device.id, device.user_id, ctx.conn))


@router.route(Cmd.DEVICE_CLAIM, schema=(str, str, str), auth=False, rate_limit="device_claim")
async def device_claim(ctx: Context, claim_token: str, device_id: str, secret: str) -> Message:
    """Enroll credentials already persisted by the device, so a lost ACK is harmless."""
    services = ctx.services
    claim_hash = services.security.token_hash(validate.token(claim_token))
    validate.enrollment_credentials(device_id, secret)

    device = await services.devices.redeem_claim(claim_hash, device_id, services.security.token_hash(secret))
    if device is None:
        log.warning("invalid or expired claim token from %s", ctx.session.peer)
        raise CommandError(Err.INVALID_TOKEN)

    await attach(ctx, device, Err.INVALID_TOKEN)
    log.info("device %s paired to user %d from %s", device.id, device.user_id, ctx.session.peer)
    return ack(device.id)


@router.route(Cmd.DEVICE_AUTH, schema=(str, str), auth=False, rate_limit="device_auth")
async def device_auth(ctx: Context, device_id: str, secret: str) -> Message:
    services = ctx.services
    well_formed = validate.is_token(device_id) and validate.is_token(secret)
    device = await services.devices.authenticate(
        device_id, services.security.token_hash(secret)
    ) if well_formed else None
    if device is None:
        log.warning("failed device authentication for %r from %s", device_id, ctx.session.peer)
        raise CommandError(Err.INVALID_CREDENTIALS)

    await attach(ctx, device, Err.INVALID_CREDENTIALS)
    log.info("device %s connected from %s", device.id, ctx.session.peer)
    return ack()


@router.route(Cmd.PING)
async def ping(ctx: Context) -> Message:
    return Message(Cmd.PONG)


@router.route(Cmd.PONG)
async def pong(ctx: Context) -> None:
    return None


@router.route(Cmd.WAKE_ACK, schema=(str,))
async def acknowledge(ctx: Context, request_id: str) -> None:
    link = ctx.services.registry.device(ctx.session.device_id)
    if link is None or link.conn is not ctx.conn or not link.resolve(request_id):
        log.debug("unexpected acknowledgement %r from device %s", request_id, ctx.session.device_id)
