import pytest

from email_validation.core.dns.backend import NoAnswerError, TemporaryDnsError
from email_validation.core.dns.resolver import MxResolver
from email_validation.core.models import Reason, Status, ValidationContext
from email_validation.core.policy import ValidationPolicy
from email_validation.core.steps.base import CONTINUE
from email_validation.core.steps.dns_mx import DnsMxStep
from tests.fakes import FakeDnsBackend, addr, mx


def ctx_for(domain: str) -> ValidationContext:
    ctx = ValidationContext(input=f"a@{domain}")
    ctx.ascii_domain = domain
    return ctx


async def run(responses: dict, policy: ValidationPolicy | None = None):  # type: ignore[no-untyped-def]
    backend = FakeDnsBackend(responses)
    ctx = ctx_for("example.com")
    outcome = await DnsMxStep(MxResolver(backend)).run(ctx, policy or ValidationPolicy())
    return outcome, ctx, backend


async def test_ok_sets_hosts() -> None:
    outcome, ctx, _ = await run({("example.com", "MX"): mx((10, "mx.example.com"))})
    assert outcome == CONTINUE
    assert ctx.mx_hosts == ("mx.example.com",)
    assert ctx.implicit_mx is False


IMPLICIT = {
    ("example.com", "MX"): NoAnswerError,
    ("example.com", "A"): addr("192.0.2.1"),
    ("example.com", "AAAA"): NoAnswerError,
}


async def test_implicit_mx_allowed() -> None:
    outcome, ctx, _ = await run(IMPLICIT)
    assert outcome == CONTINUE
    assert ctx.implicit_mx is True


async def test_implicit_mx_disallowed() -> None:
    outcome, _, _ = await run(IMPLICIT, ValidationPolicy(allow_implicit_mx=False))
    assert outcome.status is Status.INVALID
    assert outcome.reason is Reason.DOMAIN_NO_MX


@pytest.mark.parametrize(
    ("responses", "status", "reason"),
    [
        ({("example.com", "MX"): mx((0, "."))}, Status.INVALID, Reason.DOMAIN_NULL_MX),
        (
            {
                ("example.com", "MX"): NoAnswerError,
                ("example.com", "A"): NoAnswerError,
                ("example.com", "AAAA"): NoAnswerError,
            },
            Status.INVALID,
            Reason.DOMAIN_NO_MX,
        ),
        ({}, Status.INVALID, Reason.DOMAIN_NOT_FOUND),
        (
            {("example.com", "MX"): TemporaryDnsError},
            Status.UNKNOWN,
            Reason.DNS_TEMPORARY_FAILURE,
        ),
    ],
)
async def test_failures(responses: dict, status: Status, reason: Reason) -> None:  # type: ignore[type-arg]
    outcome, _, _ = await run(responses)
    assert outcome.status is status
    assert outcome.reason is reason


async def test_skipped_when_check_dns_false() -> None:
    outcome, _, backend = await run({}, ValidationPolicy(check_dns=False))
    assert outcome == CONTINUE
    assert backend.calls == []


async def test_skipped_for_domain_literal() -> None:
    backend = FakeDnsBackend({})
    ctx = ctx_for("[192.0.2.1]")
    ctx.is_domain_literal = True
    assert await DnsMxStep(MxResolver(backend)).run(ctx, ValidationPolicy()) == CONTINUE
    assert backend.calls == []
