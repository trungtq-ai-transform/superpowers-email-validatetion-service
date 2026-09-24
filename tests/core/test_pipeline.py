import asyncio

from prometheus_client import REGISTRY

from email_validation.core import (
    DisposableRegistry,
    EmailValidator,
    MemoryTTLCache,
    MxResolver,
    Reason,
    Status,
    TieredCache,
    ValidationPolicy,
)
from email_validation.core.dns.backend import TemporaryDnsError
from email_validation.core.models import ValidationContext
from email_validation.core.steps.base import StepOutcome
from tests.fakes import FakeDnsBackend, mx

RESPONSES = {
    ("example.com", "MX"): mx((10, "mx.example.com")),
    ("xn--bcher-kva.de", "MX"): mx((10, "mx.bucher.de")),
    ("mailinator.com", "MX"): mx((10, "mx.mailinator.com")),
    ("flaky.com", "MX"): TemporaryDnsError,
}


def make(delay: float = 0.0) -> tuple[EmailValidator, FakeDnsBackend]:
    backend = FakeDnsBackend(RESPONSES, delay=delay)
    resolver = MxResolver(backend, cache=TieredCache(MemoryTTLCache()))
    registry = DisposableRegistry(["mailinator.com"])
    return EmailValidator(resolver=resolver, registry=registry), backend


async def test_full_valid_idn_with_tag() -> None:
    validator, _ = make()
    r = await validator.validate("User+News@Bücher.de")
    assert r.status is Status.VALID
    assert r.reasons == ()
    assert r.ascii_email == "User+News@xn--bcher-kva.de"
    assert (r.base_local_part, r.tag) == ("User", "News")
    assert r.mx_hosts == ("mx.bucher.de",)


async def test_whitespace_and_case_normalized() -> None:
    validator, backend = make()
    r = await validator.validate("  User@EXAMPLE.com ")
    assert r.status is Status.VALID
    assert r.input == "  User@EXAMPLE.com "
    assert r.normalized == "User@example.com"
    assert backend.calls == [("example.com", "MX")]


async def test_syntax_error_never_queries_dns() -> None:
    validator, backend = make()
    r = await validator.validate("a..b@example.com")
    assert r.status is Status.INVALID
    assert r.reasons == (Reason.SYNTAX_INVALID,)
    assert backend.calls == []


async def test_disposable_reject_skips_dns() -> None:
    validator, backend = make()
    r = await validator.validate("x@mailinator.com")
    assert r.status is Status.INVALID
    assert r.reasons == (Reason.DISPOSABLE,)
    assert r.is_disposable is True
    assert backend.calls == []


async def test_disposable_flag() -> None:
    validator, _ = make()
    r = await validator.validate("x@mailinator.com", ValidationPolicy(disposable_action="flag"))
    assert r.status is Status.VALID
    assert r.is_disposable is True


async def test_nxdomain_and_temp_fail() -> None:
    validator, _ = make()
    assert (await validator.validate("a@nope.com")).reasons == (Reason.DOMAIN_NOT_FOUND,)
    r = await validator.validate("a@flaky.com")
    assert r.status is Status.UNKNOWN
    assert r.reasons == (Reason.DNS_TEMPORARY_FAILURE,)


async def test_per_call_policy_disables_dns() -> None:
    validator, backend = make()
    r = await validator.validate("a@nope.com", validator.policy.with_overrides(check_dns=False))
    assert r.status is Status.VALID
    assert backend.calls == []


async def test_step_exception_becomes_unknown() -> None:
    class Boom:
        name = "boom"

        async def run(self, ctx: ValidationContext, policy: ValidationPolicy) -> StepOutcome:
            raise RuntimeError("bug")

    r = await EmailValidator(steps=[Boom()]).validate("a@example.com")
    assert r.status is Status.UNKNOWN
    assert r.reasons == (Reason.INTERNAL_ERROR,)


async def test_without_resolver_and_registry() -> None:
    r = await EmailValidator().validate("a@mailinator.com")
    assert r.status is Status.VALID
    assert r.mx_hosts == ()


async def test_validate_many_single_flight() -> None:
    validator, backend = make(delay=0.05)
    emails = [f"user{i}@example.com" for i in range(100)] + ["bad"]
    results = await validator.validate_many(emails, concurrency=20)
    assert [r.input for r in results] == emails
    assert results[-1].status is Status.INVALID
    assert all(r.status is Status.VALID for r in results[:-1])
    assert backend.calls == [("example.com", "MX")]


async def test_validate_many_empty() -> None:
    validator, _ = make()
    assert await validator.validate_many([]) == []


async def test_metric_incremented() -> None:
    labels = {"status": "invalid", "reason": "SYNTAX_INVALID"}
    before = REGISTRY.get_sample_value("validations_total", labels) or 0.0
    validator, _ = make()
    await validator.validate("nope")
    assert REGISTRY.get_sample_value("validations_total", labels) == before + 1


async def test_concurrent_validate_is_safe() -> None:
    validator, _ = make()
    results = await asyncio.gather(*(validator.validate("a@example.com") for _ in range(20)))
    assert {r.status for r in results} == {Status.VALID}
