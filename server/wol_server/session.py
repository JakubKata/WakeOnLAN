from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Role(Enum):
    CLIENT = "client"
    DEVICE = "device"


@dataclass(eq=False)
class Session:
    role: Role
    peer: str
    user_id: int | None = None
    token_hash: str | None = None
    device_id: str | None = None
    close_requested: bool = False
    # time.monotonic() of the last check that token_hash still exists in the database.
    verified_at: float = 0.0

    @property
    def authenticated(self) -> bool:
        if self.role is Role.DEVICE:
            return self.device_id is not None
        return self.user_id is not None
