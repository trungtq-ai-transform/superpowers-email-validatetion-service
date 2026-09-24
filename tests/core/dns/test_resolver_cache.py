import asyncio

from email_validation.core.dns.backend import TemporaryDnsError
from email_validation.core.dns.cache import MemoryTTLCache, TieredCache
from email_validation.core.dns.resolver import MxOutcome, MxResolver
from tests.fakes import FakeDnsBackend, mx


def make(responses: dict, delay: float = 0.0) -> tuple[MxResolver, FakeDnsBackend]:  # type: ignore[type-arg]
    backend = FakeDnsBackend(responses, delay=delay)
    return MxResolver(backend, cache=TieredCache(MemoryTTLCache())), backend


async def test_second_lookup_served_from_cache() -> None:
    resolver, backend = make({("example.com", "MX"): mx((10, "mx.example.com"))})
    first = await resolver.lookup("example.com")
    second = await resolver.lookup("EXAMPLE.com")
    assert first == second
    assert backend.calls == [("example.com", "MX")]


async def test_single_flight_for_concurrent_lookups() -> None:
    resolver, backend = make({("example.com", "MX"): mx((10, "mx.example.com"))}, delay=0.05)
    results = await asyncio.gather(*(resolver.lookup("example.com") for _ in range(50)))
    assert {r.outcome for r in results} == {MxOutcome.OK}
    assert backend.calls == [("example.com", "MX")]


async def test_cancelled_caller_does_not_break_followers() -> None:
    resolver, backend = make({("example.com", "MX"): mx((10, "mx.example.com"))}, delay=0.05)
    leader = asyncio.create_task(resolver.lookup("example.com"))
    await asyncio.sleep(0.01)
    follower = asyncio.create_task(resolver.lookup("example.com"))
    await asyncio.sleep(0)
    leader.cancel()
    result = await follower
    assert result.outcome is MxOutcome.OK
    assert len(backend.calls) == 1


async def test_temporary_failure_is_cached_briefly() -> None:
    resolver, backend = make({("example.com", "MX"): TemporaryDnsError})
    assert (await resolver.lookup("example.com")).outcome is MxOutcome.TEMP_FAIL
    assert (await resolver.lookup("example.com")).outcome is MxOutcome.TEMP_FAIL
    assert len(backend.calls) == 1


async def test_without_cache_every_lookup_queries() -> None:
    backend = FakeDnsBackend({("example.com", "MX"): mx((10, "mx.example.com"))})
    resolver = MxResolver(backend)
    await resolver.lookup("example.com")
    await resolver.lookup("example.com")
    assert len(backend.calls) == 2
