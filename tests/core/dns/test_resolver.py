import asyncio

from prometheus_client import REGISTRY

from email_validation.core.dns.backend import NoAnswerError, TemporaryDnsError
from email_validation.core.dns.resolver import MxOutcome, MxResolver, normalize_domain
from tests.fakes import FakeDnsBackend, addr, mx


async def lookup(responses: dict, domain: str = "example.com"):  # type: ignore[no-untyped-def]
    backend = FakeDnsBackend(responses)
    return await MxResolver(backend).lookup(domain), backend


async def test_mx_sorted_by_preference() -> None:
    result, _ = await lookup(
        {("example.com", "MX"): mx((20, "mx2.example.com"), (10, "mx1.example.com"), ttl=1800)}
    )
    assert result.outcome is MxOutcome.OK
    assert result.hosts == ("mx1.example.com", "mx2.example.com")
    assert result.implicit is False
    assert result.ttl == 1800


async def test_duplicate_hosts_removed() -> None:
    result, _ = await lookup(
        {("example.com", "MX"): mx((10, "mx.example.com"), (20, "mx.example.com"))}
    )
    assert result.hosts == ("mx.example.com",)


async def test_null_mx() -> None:
    result, _ = await lookup({("example.com", "MX"): mx((0, "."))})
    assert result.outcome is MxOutcome.NULL_MX
    assert result.hosts == ()


async def test_null_mx_mixed_with_real_mx_uses_real() -> None:
    result, _ = await lookup({("example.com", "MX"): mx((0, "."), (10, "mx.example.com"))})
    assert result.outcome is MxOutcome.OK
    assert result.hosts == ("mx.example.com",)


async def test_no_mx_falls_back_to_a() -> None:
    result, backend = await lookup(
        {
            ("example.com", "MX"): NoAnswerError,
            ("example.com", "A"): addr("192.0.2.1", ttl=120),
            ("example.com", "AAAA"): NoAnswerError,
        }
    )
    assert result.outcome is MxOutcome.OK
    assert result.hosts == ("example.com",)
    assert result.implicit is True
    assert result.ttl == 120
    assert ("example.com", "A") in backend.calls and ("example.com", "AAAA") in backend.calls


async def test_no_mx_falls_back_to_aaaa_only() -> None:
    result, _ = await lookup(
        {
            ("example.com", "MX"): NoAnswerError,
            ("example.com", "A"): NoAnswerError,
            ("example.com", "AAAA"): addr("2001:db8::1"),
        }
    )
    assert result.outcome is MxOutcome.OK
    assert result.implicit is True


async def test_no_mx_no_address() -> None:
    result, _ = await lookup(
        {
            ("example.com", "MX"): NoAnswerError,
            ("example.com", "A"): NoAnswerError,
            ("example.com", "AAAA"): NoAnswerError,
        }
    )
    assert result.outcome is MxOutcome.NO_MX


async def test_empty_mx_answer_treated_as_no_answer() -> None:
    result, _ = await lookup({("example.com", "MX"): mx(), ("example.com", "A"): addr("192.0.2.1")})
    assert result.outcome is MxOutcome.OK
    assert result.implicit is True


async def test_nxdomain() -> None:
    result, _ = await lookup({})
    assert result.outcome is MxOutcome.NXDOMAIN


async def test_temporary_failure_on_mx() -> None:
    result, _ = await lookup({("example.com", "MX"): TemporaryDnsError})
    assert result.outcome is MxOutcome.TEMP_FAIL


async def test_temporary_failure_in_fallback() -> None:
    result, _ = await lookup(
        {
            ("example.com", "MX"): NoAnswerError,
            ("example.com", "A"): TemporaryDnsError,
            ("example.com", "AAAA"): NoAnswerError,
        }
    )
    assert result.outcome is MxOutcome.TEMP_FAIL


async def test_domain_is_normalized_before_query() -> None:
    _, backend = await lookup({("example.com", "MX"): mx((10, "mx.example.com"))}, "Example.COM.")
    assert backend.calls == [("example.com", "MX")]
    assert normalize_domain("Example.COM.") == "example.com"


async def test_concurrency_is_bounded() -> None:
    responses = {(f"d{i}.com", "MX"): mx((10, "mx.x.com")) for i in range(10)}
    backend = FakeDnsBackend(responses, delay=0.02)
    resolver = MxResolver(backend, max_concurrency=2)
    await asyncio.gather(*(resolver.lookup(f"d{i}.com") for i in range(10)))
    assert backend.max_in_flight <= 2


async def test_lookup_metric_incremented() -> None:
    before = REGISTRY.get_sample_value("dns_lookups_total", {"outcome": "nxdomain"}) or 0.0
    await lookup({})
    after = REGISTRY.get_sample_value("dns_lookups_total", {"outcome": "nxdomain"})
    assert after == before + 1


def _temp_fail_count() -> float:
    return REGISTRY.get_sample_value("dns_lookups_total", {"outcome": "temp_fail"}) or 0.0


async def test_slow_lookup_is_bounded_by_lookup_timeout() -> None:
    backend = FakeDnsBackend({("example.com", "MX"): mx((10, "mx.example.com"))}, delay=0.5)
    resolver = MxResolver(backend, lookup_timeout=0.05)
    before = _temp_fail_count()
    loop = asyncio.get_running_loop()
    start = loop.time()
    result = await resolver.lookup("example.com")
    assert loop.time() - start < 0.4
    assert result.outcome is MxOutcome.TEMP_FAIL
    assert _temp_fail_count() == before + 1

    backend.delay = 0.0  # resolver stays usable after a timeout
    again = await resolver.lookup("example.com")
    assert again.outcome is MxOutcome.OK
    assert again.hosts == ("mx.example.com",)


async def test_lookup_timeout_covers_mx_plus_fallback() -> None:
    # Each query alone fits in the timeout; MX NoAnswer + A/AAAA fallback together do not.
    backend = FakeDnsBackend(
        {
            ("example.com", "MX"): NoAnswerError,
            ("example.com", "A"): addr("192.0.2.1"),
        },
        delay=0.06,
    )
    result = await MxResolver(backend, lookup_timeout=0.1).lookup("example.com")
    assert result.outcome is MxOutcome.TEMP_FAIL
