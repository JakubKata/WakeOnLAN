import pytest

from wol_server.errors import CommandError
from wol_server.protocol import Err
from wol_server.ratelimit import ConnectionLimiter, RateLimiter, Rule


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


def test_token_bucket_burst_and_refill():
    clock = FakeClock()
    limiter = RateLimiter({"a": Rule(capacity=3, refill_seconds=10)}, clock=clock)
    assert [limiter.allow("a", "ip") for _ in range(4)] == [True, True, True, False]
    clock.now = 9
    assert not limiter.allow("a", "ip")
    clock.now = 10.5
    assert limiter.allow("a", "ip")
    assert limiter.allow("a", "other-ip")


def test_peek_consume_and_require():
    clock = FakeClock()
    limiter = RateLimiter({"a": Rule(capacity=2, refill_seconds=10)}, clock=clock)
    assert limiter.peek("a", "k") and limiter.peek("a", "k")
    limiter.consume("a", "k")
    limiter.consume("a", "k")
    assert not limiter.peek("a", "k")
    limiter.consume("a", "k")
    clock.now = 10
    assert limiter.peek("a", "k")
    limiter.require("a", "k")
    with pytest.raises(CommandError) as exc:
        limiter.require("a", "k")
    assert exc.value.code is Err.RATE_LIMITED


def test_refund_returns_a_token_up_to_capacity():
    clock = FakeClock()
    limiter = RateLimiter({"a": Rule(capacity=2, refill_seconds=10)}, clock=clock)
    limiter.consume("a", "k")
    limiter.consume("a", "k")
    assert not limiter.peek("a", "k")
    limiter.refund("a", "k")
    assert limiter.allow("a", "k")
    assert not limiter.peek("a", "k")
    for _ in range(5):
        limiter.refund("a", "k")
    assert [limiter.allow("a", "k") for _ in range(3)] == [True, True, False]


def test_prune_drops_only_full_buckets():
    clock = FakeClock()
    limiter = RateLimiter({"a": Rule(capacity=1, refill_seconds=10)}, clock=clock)
    limiter.MAX_BUCKETS = 2
    limiter.allow("a", 1)
    clock.now = 100
    limiter.allow("a", 2)
    limiter.allow("a", 3)
    assert ("a", 1) not in limiter._buckets
    assert ("a", 3) in limiter._buckets


def test_prune_runs_at_most_once_per_interval():
    clock = FakeClock()
    limiter = RateLimiter({"a": Rule(capacity=1, refill_seconds=1)}, clock=clock)
    limiter.MAX_BUCKETS = 1
    limiter.allow("a", 1)
    limiter.allow("a", 2)
    clock.now = 5
    limiter.allow("a", 3)
    assert ("a", 2) in limiter._buckets
    clock.now = limiter.PRUNE_INTERVAL_SECONDS
    limiter.allow("a", 4)
    assert ("a", 2) not in limiter._buckets and ("a", 3) not in limiter._buckets


def test_connection_limiter():
    limiter = ConnectionLimiter(per_ip=2, total=3)
    assert limiter.acquire("a") and limiter.acquire("a")
    assert not limiter.acquire("a")
    assert limiter.acquire("b")
    assert not limiter.acquire("c")
    limiter.release("a")
    assert limiter.acquire("c")
