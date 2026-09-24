import pytest
from redis.asyncio import Redis

from email_validation.api.security import RateLimiter

pytestmark = pytest.mark.integration


async def test_token_bucket_on_real_redis(redis_client: Redis) -> None:
    now = [1_700_000_000.0]
    limiter = RateLimiter(redis_client, per_minute=3, clock=lambda: now[0])
    assert [(await limiter.check("k")).allowed for _ in range(4)] == [True, True, True, False]
    now[0] += 20
    assert (await limiter.check("k")).allowed
    assert 0 < await redis_client.pttl("rl:v1:k") <= 61_000
