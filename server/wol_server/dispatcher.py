from __future__ import annotations

import logging
import time
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass

from .context import Context
from .errors import CommandError
from .protocol import Err, Message, nack
from .session import Role

log = logging.getLogger(__name__)

Handler = Callable[..., Awaitable[Message | None]]

SESSION_RECHECK_SECONDS = 60.0


@dataclass(frozen=True, slots=True)
class Route:
    handler: Handler
    schema: tuple[type, ...]
    auth: bool | None
    rate_limit: str | None


class Router:
    """Collects the commands one role may send.

    ``auth=True`` requires an authenticated session, ``auth=False`` requires an
    unauthenticated one, ``auth=None`` accepts both. ``schema`` lists the exact
    argument types; ``rate_limit`` names a per-IP bucket in the RateLimiter.
    """

    def __init__(self, role: Role):
        self.role = role
        self.routes: dict[str, Route] = {}

    def route(
        self,
        command: str,
        *,
        schema: tuple[type, ...] = (),
        auth: bool | None = True,
        rate_limit: str | None = None,
    ) -> Callable[[Handler], Handler]:
        def register(handler: Handler) -> Handler:
            if command in self.routes:
                raise ValueError(f"duplicate route {self.role.value}:{command}")
            self.routes[command] = Route(handler, schema, auth, rate_limit)
            return handler

        return register


class Dispatcher:
    def __init__(self, routers: Iterable[Router]):
        self._routes: dict[tuple[Role, str], Route] = {}
        for router in routers:
            for command, route in router.routes.items():
                key = (router.role, command)
                if key in self._routes:
                    raise ValueError(f"duplicate route {router.role.value}:{command}")
                self._routes[key] = route

    async def dispatch(self, ctx: Context, message: Message) -> Message | None:
        """Run the handler for ``message`` and return the reply (None means no reply)."""
        session = ctx.session
        route = self._routes.get((session.role, message.command))
        if route is None:
            return nack(Err.UNKNOWN_COMMAND)
        if route.auth is not None and route.auth != session.authenticated:
            return nack(Err.UNAUTHENTICATED if route.auth else Err.ALREADY_AUTHENTICATED)
        if not _matches(route.schema, message.args):
            return nack(Err.BAD_ARGS)
        if route.rate_limit and not ctx.services.limiter.allow(route.rate_limit, session.peer):
            log.warning("rate limited: %s from %s", message.command, session.peer)
            return nack(Err.RATE_LIMITED)

        try:
            if route.auth and not await _session_still_valid(ctx):
                log.info("session of user %s on %s was revoked", session.user_id, session.peer)
                session.close_requested = True
                return nack(Err.INVALID_TOKEN)
            return await route.handler(ctx, *message.args)
        except CommandError as exc:
            return nack(exc.code)
        except Exception:
            log.exception("%s from %s failed", message.command, session.peer)
            return nack(Err.INTERNAL)


async def _session_still_valid(ctx: Context) -> bool:
    """Re-check a client's session token at most every SESSION_RECHECK_SECONDS."""
    session = ctx.session
    if session.token_hash is None or time.monotonic() - session.verified_at < SESSION_RECHECK_SECONDS:
        return True
    if not await ctx.services.sessions.exists(session.token_hash):
        return False
    session.verified_at = time.monotonic()
    return True


def _matches(schema: tuple[type, ...], args: tuple[object, ...]) -> bool:
    # Exact type match: rejects bool for int and subclasses in general.
    return len(schema) == len(args) and all(type(arg) is kind for arg, kind in zip(args, schema))
