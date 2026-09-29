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
from .devices import DEVICE_SECRET_BYTES

log = logging.getLogger(__name__)
router = Router(Role.DEVICE)

DEVICE_ID_BYTES = 12


def attach(ctx: Context, device: Device) -> None:
    ctx.session.device_id = device.id
    ctx.session.user_id = device.user_id
    ctx.services.registry.attach_device(DeviceLink(device.id, device.user_id, ctx.conn))


@router.route(Cmd.DEVICE_CLAIM, schema=(str,), auth=False, rate_limit="device_claim")
async def device_claim(ctx: Context, claim_token: str) -> Message:
    """Redeem a claim token; the reply carries the credentials to store in NVS."""
    services = ctx.services
    claim_hash = services.security.token_hash(validate.token(claim_token))
    device_id = services.security.new_token(DEVICE_ID_BYTES)
    secret = services.security.new_token(DEVICE_SECRET_BYTES)

    device = await services.devices.redeem_claim(claim_hash, device_id, services.security.token_hash(secret))
    if device is None:
        log.warning("invalid or expired claim token from %s", ctx.session.peer)
        raise CommandError(Err.INVALID_TOKEN)

    attach(ctx, device)
    log.info("device %s paired to user %d from %s", device.id, device.user_id, ctx.session.peer)
    return ack(device.id, secret)


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

    attach(ctx, device)
    log.info("device %s connected from %s", device.id, ctx.session.peer)
    return ack()


@router.route(Cmd.PING)
async def ping(ctx: Context) -> Message:
    return Message(Cmd.PONG)


@router.route(Cmd.PONG)
async def pong(ctx: Context) -> None:
    return None


@router.route(Cmd.WAKE_ACK, schema=(str,))
@router.route(Cmd.SECRET_ACK, schema=(str,))
async def acknowledge(ctx: Context, request_id: str) -> None:
    link = ctx.services.registry.device(ctx.session.device_id)
    if link is None or link.conn is not ctx.conn or not link.resolve(request_id):
        log.debug("unexpected acknowledgement %r from device %s", request_id, ctx.session.device_id)
