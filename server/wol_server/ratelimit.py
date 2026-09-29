from __future__ import annotations

import time
from collections import Counter
from collections.abc import Callable, Hashable, Mapping
from dataclasses import dataclass

from .errors import CommandError
from .protocol import Err


@dataclass(frozen=True, slots=True)
class Rule:
    """Allow bursts of ``capacity`` requests, then one per ``refill_seconds``."""

    capacity: int
    refill_seconds: float


DEFAULT_RULES: Mapping[str, Rule] = {
    "register": Rule(capacity=5, refill_seconds=120),
    "register_email": Rule(capacity=3, refill_seconds=600),
    "login": Rule(capacity=20, refill_seconds=3),
    # Failed logins only: per (account, address) and, much looser, per account.
    "login_account": Rule(capacity=10, refill_seconds=60),
    "login_account_global": Rule(capacity=100, refill_seconds=36),
    "resume": Rule(capacity=30, refill_seconds=2),
    "password_check": Rule(capacity=5, refill_seconds=60),
    "reset_request": Rule(capacity=5, refill_seconds=300),
    "reset_request_email": Rule(capacity=3, refill_seconds=900),
    "reset_confirm": Rule(capacity=10, refill_seconds=30),
    "reset_confirm_email": Rule(capacity=5, refill_seconds=60),
    "create_claim": Rule(capacity=10, refill_seconds=30),
    "device_claim": Rule(capacity=10, refill_seconds=30),
    "device_auth": Rule(capacity=10, refill_seconds=6),
    "wake": Rule(capacity=10, refill_seconds=6),
}


class RateLimiter:
    """In-memory token buckets keyed by (action, key).

    The dispatcher applies per-address rules named on routes; handlers use
    ``require`` (or ``consume`` + ``refund`` to charge only failures) for other keys.
    """

    MAX_BUCKETS = 50_000
    # A prune scans every bucket, so above MAX_BUCKETS it must not run on every insert.
    PRUNE_INTERVAL_SECONDS = 10.0

    def __init__(self, rules: Mapping[str, Rule] = DEFAULT_RULES, clock: Callable[[], float] = time.monotonic):
        self._rules = rules
        self._clock = clock
        self._buckets: dict[tuple[str, Hashable], tuple[float, float]] = {}
        self._last_prune = float("-inf")

    def allow(self, action: str, key: Hashable) -> bool:
        """Take a token if one is available."""
        allowed = self.peek(action, key)
        if allowed:
            self.consume(action, key)
        return allowed

    def require(self, action: str, key: Hashable) -> None:
        if not self.allow(action, key):
            raise CommandError(Err.RATE_LIMITED)

    def peek(self, action: str, key: Hashable) -> bool:
        """Whether a token is available, without taking it."""
        return self._tokens(action, key) >= 1

    def consume(self, action: str, key: Hashable) -> None:
        """Take a token; the bucket may not go below zero."""
        tokens = self._tokens(action, key)
        now = self._clock()
        self._buckets[(action, key)] = (max(0.0, tokens - 1), now)
        if len(self._buckets) > self.MAX_BUCKETS and now - self._last_prune >= self.PRUNE_INTERVAL_SECONDS:
            self._last_prune = now
            self._prune(now)

    def refund(self, action: str, key: Hashable) -> None:
        """Give back a token taken by ``consume``; the bucket may not exceed its capacity."""
        rule = self._rules[action]
        tokens = self._tokens(action, key)
        self._buckets[(action, key)] = (min(float(rule.capacity), tokens + 1), self._clock())

    def _tokens(self, action: str, key: Hashable) -> float:
        rule = self._rules[action]
        now = self._clock()
        tokens, updated = self._buckets.get((action, key), (float(rule.capacity), now))
        return min(rule.capacity, tokens + (now - updated) / rule.refill_seconds)

    def _prune(self, now: float) -> None:
        """Drop buckets that have refilled completely; they carry no state."""
        for (action, key), (tokens, updated) in list(self._buckets.items()):
            rule = self._rules[action]
            if tokens + (now - updated) / rule.refill_seconds >= rule.capacity:
                del self._buckets[(action, key)]


class ConnectionLimiter:
    def __init__(self, per_ip: int, total: int):
        self._per_ip = per_ip
        self._total = total
        self._counts: Counter[str] = Counter()

    def acquire(self, ip: str) -> bool:
        if self._counts[ip] >= self._per_ip or self._counts.total() >= self._total:
            return False
        self._counts[ip] += 1
        return True

    def release(self, ip: str) -> None:
        self._counts[ip] -= 1
        if self._counts[ip] <= 0:
            del self._counts[ip]
