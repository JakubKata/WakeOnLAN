"""Password recovery by a one-time code sent to the account's e-mail address."""

import logging

from .. import validation as validate
from ..context import Context
from ..dispatcher import Router
from ..errors import CommandError
from ..protocol import Cmd, Err, Message, ack
from ..session import Role
from .auth import start_session

log = logging.getLogger(__name__)
router = Router(Role.CLIENT)

RESET_CODE_TTL_SECONDS = 15 * 60
# Guessing is throttled per (e-mail, address); this only bounds the total. With ~50 bits
# per code a high limit is safe and keeps strangers from burning the owner's code.
MAX_RESET_ATTEMPTS = 50

RESET_MAIL_SUBJECT = "Reset hasła / Password reset"
RESET_MAIL_BODY = """\
Cześć {name},

ktoś (prawdopodobnie Ty) poprosił o reset hasła do konta w WoL Server.
Wpisz w aplikacji ten kod:

    {code}

Kod jest ważny {minutes} minut i działa tylko raz.
Jeśli to nie Ty, zignoruj tę wiadomość - hasło się nie zmieni.

---

Hi {name},

someone (probably you) requested a password reset for your WoL Server account.
Enter this code in the app:

    {code}

The code is valid for {minutes} minutes and works only once.
If this wasn't you, ignore this message - your password stays the same.
"""


def format_code(code: str) -> str:
    half = len(code) // 2
    return f"{code[:half]}-{code[half:]}"


@router.route(
    Cmd.REQUEST_PASSWORD_RESET, schema=(str,), auth=False, rate_limit="reset_request"
)
async def request_password_reset(ctx: Context, email: str) -> Message:
    """Always ACKs the same way, so the reply does not reveal whether the address is registered."""
    services = ctx.services
    if services.mailer is None:
        raise CommandError(Err.RESET_UNAVAILABLE)
    email = validate.email(email)
    # Throttled silently: an error here would tell registered addresses apart.
    if not services.limiter.allow("reset_request_email", email.casefold()):
        log.warning("password reset throttled for %r from %s", email, ctx.session.peer)
        return ack()

    user = await services.users.by_email(email)
    if user is None:
        log.info("password reset for unknown e-mail from %s", ctx.session.peer)
        return ack()

    code = services.security.new_reset_code()
    await services.resets.create(user.id, services.security.token_hash(code), RESET_CODE_TTL_SECONDS)
    services.mailer.send_later(
        user.email,
        RESET_MAIL_SUBJECT,
        RESET_MAIL_BODY.format(
            name=user.name, code=format_code(code), minutes=RESET_CODE_TTL_SECONDS // 60
        ),
    )
    log.info("password reset code issued for user %d from %s", user.id, ctx.session.peer)
    return ack()


@router.route(
    Cmd.RESET_PASSWORD, schema=(str, str, str), auth=False, rate_limit="reset_confirm"
)
async def reset_password(ctx: Context, email: str, code: str, new_password: str) -> Message:
    services = ctx.services
    if services.mailer is None:
        raise CommandError(Err.RESET_UNAVAILABLE)
    validate.password(new_password)
    code = validate.reset_code(code)
    email = validate.email(email)
    services.limiter.require("reset_confirm_email", (email.casefold(), ctx.session.peer))
    user = await services.users.by_email(email)
    code_hash = services.security.token_hash(code)
    if user is None or not await services.resets.consume(user.id, code_hash, MAX_RESET_ATTEMPTS):
        log.warning("invalid password reset code for %r from %s", email, ctx.session.peer)
        raise CommandError(Err.INVALID_TOKEN)

    epoch = await services.users.change_password(
        user.id, await services.security.hash_password(new_password), expected_epoch=user.session_epoch,
    )
    services.registry.kick_user(user.id)
    log.info("user %d reset their password; all sessions revoked", user.id)
    return ack(await start_session(ctx, user.id, epoch), user.name)
