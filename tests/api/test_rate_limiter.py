from fakeredis import FakeAsyncRedis

from email_validation.api.security import ApiKeyAuth, RateLimiter, hash_api_key
from tests.fakes import BrokenRedis


class Clock:
    def __init__(self) -> None:
        self.now = 1_700_000_000.0

    def __call__(self) -> float:
        return self.now


def test_hash_api_key() -> None:
    assert hash_api_key("test-key") == (
        "62af8704764faf8ea82fc61ce9c4c3908b6cb97d463a634e9e587d7c885db0ef"
    )


def test_auth_identify() -> None:
    auth = ApiKeyAuth([hash_api_key("k1")])
    assert auth.identify("k1") == hash_api_key("k1")[:12]
    assert auth.identify("wrong") is None
    assert auth.identify(None) is None
    assert auth.identify("") is None


def test_auth_disabled() -> None:
    assert ApiKeyAuth([], enabled=False).identify(None) == "anonymous"


async def test_token_bucket() -> None:
    clock = Clock()
    limiter = RateLimiter(FakeAsyncRedis(), per_minute=3, clock=clock)
    for _ in range(3):
        assert (await limiter.check("k")).allowed
    denied = await limiter.check("k")
    assert denied.allowed is False
    assert denied.retry_after_seconds == 20
    clock.now += 20
    assert (await limiter.check("k")).allowed


async def test_keys_are_independent() -> None:
    limiter = RateLimiter(FakeAsyncRedis(), per_minute=1, clock=Clock())
    assert (await limiter.check("a")).allowed
    assert (await limiter.check("b")).allowed
    assert not (await limiter.check("a")).allowed


async def test_cost_consumes_multiple_tokens() -> None:
    limiter = RateLimiter(FakeAsyncRedis(), per_minute=10, clock=Clock())
    assert (await limiter.check("k", cost=8)).allowed
    assert not (await limiter.check("k", cost=3)).allowed
    assert (await limiter.check("k", cost=2)).allowed


async def test_rate_limiter_fail_open() -> None:
    limiter = RateLimiter(BrokenRedis(), per_minute=1)  # type: ignore[arg-type]
    for _ in range(5):
        assert (await limiter.check("k")).allowed


async def test_rate_limiter_without_redis() -> None:
    limiter = RateLimiter(None, per_minute=1)
    for _ in range(5):
        assert (await limiter.check("k")).allowed
