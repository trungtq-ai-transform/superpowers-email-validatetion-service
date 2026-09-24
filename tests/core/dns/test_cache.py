import pytest
from fakeredis import FakeAsyncRedis
from prometheus_client import REGISTRY

from email_validation.core.dns.cache import (
    MemoryTTLCache,
    RedisCache,
    TieredCache,
    cache_key,
    decode_result,
    encode_result,
    l1_ttl,
    l2_ttl,
)
from email_validation.core.dns.resolver import MxLookupResult, MxOutcome
from tests.fakes import BrokenRedis

OK = MxLookupResult(MxOutcome.OK, hosts=("mx.example.com",), ttl=3600)


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class RecordingCache:
    def __init__(self) -> None:
        self.data: dict[str, MxLookupResult] = {}
        self.ttls: dict[str, int] = {}

    async def get(self, key: str) -> MxLookupResult | None:
        return self.data.get(key)

    async def set(self, key: str, value: MxLookupResult, ttl: int) -> None:
        self.data[key] = value
        self.ttls[key] = ttl


def sample(name: str, labels: dict[str, str]) -> float:
    return REGISTRY.get_sample_value(name, labels) or 0.0


def test_cache_key() -> None:
    assert cache_key("example.com") == "mx:v1:example.com"


@pytest.mark.parametrize(
    ("result", "expected_l1", "expected_l2"),
    [
        (MxLookupResult(MxOutcome.OK, ttl=3600), 300, 3600),
        (MxLookupResult(MxOutcome.OK, ttl=30), 30, 60),
        (MxLookupResult(MxOutcome.OK, ttl=0), 1, 60),
        (MxLookupResult(MxOutcome.OK, ttl=999_999), 300, 86400),
        (MxLookupResult(MxOutcome.NULL_MX, ttl=7200), 300, 7200),
        (MxLookupResult(MxOutcome.NO_MX), 300, 300),
        (MxLookupResult(MxOutcome.NXDOMAIN), 300, 300),
        (MxLookupResult(MxOutcome.TEMP_FAIL), 30, 30),
    ],
)
def test_ttl_rules(result: MxLookupResult, expected_l1: int, expected_l2: int) -> None:
    assert l1_ttl(result) == expected_l1
    assert l2_ttl(result) == expected_l2


def test_encode_decode_roundtrip() -> None:
    implicit = MxLookupResult(MxOutcome.OK, hosts=("example.com",), implicit=True, ttl=120)
    assert decode_result(encode_result(implicit)) == implicit
    assert decode_result(encode_result(OK).encode()) == OK


async def test_memory_cache_expiry() -> None:
    clock = FakeClock()
    cache = MemoryTTLCache(maxsize=10, clock=clock)
    await cache.set("k", OK, ttl=10)
    assert await cache.get("k") == OK
    clock.now += 10.01
    assert await cache.get("k") is None


async def test_memory_cache_lru_eviction() -> None:
    cache = MemoryTTLCache(maxsize=2)
    await cache.set("a", OK, 60)
    await cache.set("b", OK, 60)
    await cache.get("a")  # a becomes most recent
    await cache.set("c", OK, 60)
    assert await cache.get("a") == OK
    assert await cache.get("b") is None
    assert await cache.get("c") == OK


async def test_memory_cache_ignores_non_positive_ttl() -> None:
    cache = MemoryTTLCache()
    await cache.set("k", OK, 0)
    assert await cache.get("k") is None


async def test_redis_cache_roundtrip_and_ttl() -> None:
    client = FakeAsyncRedis()
    cache = RedisCache(client)
    await cache.set("mx:v1:example.com", OK, ttl=600)
    assert await cache.get("mx:v1:example.com") == OK
    assert 590 <= await client.ttl("mx:v1:example.com") <= 600


async def test_redis_cache_corrupt_value_is_miss() -> None:
    client = FakeAsyncRedis()
    await client.set("mx:v1:bad.com", b"not json")
    assert await RedisCache(client).get("mx:v1:bad.com") is None


async def test_redis_cache_fail_open() -> None:
    before = sample("cache_errors_total", {"op": "get"})
    cache = RedisCache(BrokenRedis())  # type: ignore[arg-type]
    assert await cache.get("k") is None
    await cache.set("k", OK, 60)  # must not raise
    assert sample("cache_errors_total", {"op": "get"}) == before + 1


async def test_tiered_l1_hit() -> None:
    l1, l2 = RecordingCache(), RecordingCache()
    l1.data["k"] = OK
    before = sample("cache_hits_total", {"tier": "l1"})
    assert await TieredCache(l1, l2).get("k") == OK
    assert sample("cache_hits_total", {"tier": "l1"}) == before + 1


async def test_tiered_l2_hit_populates_l1() -> None:
    l1, l2 = RecordingCache(), RecordingCache()
    l2.data["k"] = OK
    before = sample("cache_hits_total", {"tier": "l2"})
    assert await TieredCache(l1, l2).get("k") == OK
    assert l1.data["k"] == OK
    assert l1.ttls["k"] == 300
    assert sample("cache_hits_total", {"tier": "l2"}) == before + 1


async def test_tiered_miss() -> None:
    before = sample("cache_hits_total", {"tier": "miss"})
    assert await TieredCache(RecordingCache(), RecordingCache()).get("k") is None
    assert sample("cache_hits_total", {"tier": "miss"}) == before + 1


async def test_tiered_set_uses_tier_ttls() -> None:
    l1, l2 = RecordingCache(), RecordingCache()
    await TieredCache(l1, l2).set("k", OK)
    assert l1.ttls["k"] == 300
    assert l2.ttls["k"] == 3600


async def test_tiered_without_l2() -> None:
    l1 = RecordingCache()
    cache = TieredCache(l1)
    await cache.set("k", OK)
    assert await cache.get("k") == OK


def test_resolver_key_prefix_matches_cache() -> None:
    from email_validation.core.dns.cache import KEY_PREFIX
    from email_validation.core.dns.resolver import CACHE_KEY_PREFIX

    assert CACHE_KEY_PREFIX == KEY_PREFIX
