from __future__ import annotations

from dataclasses import dataclass

from .db import ClaimsRepo, Database, DevicesRepo, PasswordResetsRepo, SessionsRepo, TargetsRepo, UsersRepo
from .mailer import Mailer
from .ratelimit import RateLimiter
from .registry import Registry
from .security import Security
from .session import Session
from .transport import Connection


@dataclass(frozen=True)
class Services:
    """Process-wide dependencies shared by every connection."""

    db: Database
    users: UsersRepo
    sessions: SessionsRepo
    resets: PasswordResetsRepo
    claims: ClaimsRepo
    devices: DevicesRepo
    targets: TargetsRepo
    security: Security
    registry: Registry
    limiter: RateLimiter
    mailer: Mailer | None

    @classmethod
    def create(
        cls,
        db: Database,
        security: Security,
        limiter: RateLimiter | None = None,
        mailer: Mailer | None = None,
    ) -> Services:
        return cls(
            db=db,
            users=UsersRepo(db),
            sessions=SessionsRepo(db),
            resets=PasswordResetsRepo(db),
            claims=ClaimsRepo(db),
            devices=DevicesRepo(db),
            targets=TargetsRepo(db),
            security=security,
            registry=Registry(),
            limiter=limiter or RateLimiter(),
            mailer=mailer,
        )


@dataclass(frozen=True)
class Context:
    """Everything a command handler may touch."""

    services: Services
    session: Session
    conn: Connection
