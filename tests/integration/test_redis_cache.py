import pytest
from redis.asyncio import Redis

from email_validation.core.dns.cache import MemoryTTLCache, RedisCache, TieredCache
from email_validation.core.dns.resolver import MxOutcome, MxResolver
from tests.fakes import FakeDnsBackend, mx

pytestmark = pytest.mark.integration


async def test_two_replicas_share_l2(redis_client: Redis) -> None:
    responses = {("example.com", "MX"): mx((10, "mx.example.com"))}
    backend_a, backend_b = FakeDnsBackend(responses), FakeDnsBackend(responses)
    replica_a = MxResolver(backend_a, cache=TieredCache(MemoryTTLCache(), RedisCache(redis_client)))
    replica_b = MxResolver(backend_b, cache=TieredCache(MemoryTTLCache(), RedisCache(redis_client)))

    assert (await replica_a.lookup("example.com")).outcome is MxOutcome.OK
    assert (await replica_b.lookup("example.com")).outcome is MxOutcome.OK
    assert len(backend_a.calls) == 1
    assert backend_b.calls == []
    assert 0 < await redis_client.ttl("mx:v1:example.com") <= 3600
