from email_validation.core.disposable.registry import DisposableRegistry
from email_validation.core.models import Reason, Status, ValidationContext
from email_validation.core.policy import ValidationPolicy
from email_validation.core.steps.base import CONTINUE
from email_validation.core.steps.disposable import DisposableStep

STEP = DisposableStep(DisposableRegistry(["mailinator.com"]))


def ctx_for(domain: str, literal: bool = False) -> ValidationContext:
    ctx = ValidationContext(input=f"a@{domain}")
    ctx.ascii_domain = domain
    ctx.is_domain_literal = literal
    return ctx


async def test_reject() -> None:
    ctx = ctx_for("mailinator.com")
    outcome = await STEP.run(ctx, ValidationPolicy())
    assert outcome.status is Status.INVALID
    assert outcome.reason is Reason.DISPOSABLE
    assert ctx.is_disposable is True


async def test_flag() -> None:
    ctx = ctx_for("mailinator.com")
    outcome = await STEP.run(ctx, ValidationPolicy(disposable_action="flag"))
    assert outcome == CONTINUE
    assert ctx.is_disposable is True


async def test_off() -> None:
    ctx = ctx_for("mailinator.com")
    outcome = await STEP.run(ctx, ValidationPolicy(disposable_action="off"))
    assert outcome == CONTINUE
    assert ctx.is_disposable is False


async def test_clean_domain() -> None:
    ctx = ctx_for("example.com")
    assert await STEP.run(ctx, ValidationPolicy()) == CONTINUE
    assert ctx.is_disposable is False


async def test_domain_literal_skipped() -> None:
    ctx = ctx_for("[192.0.2.1]", literal=True)
    assert await STEP.run(ctx, ValidationPolicy()) == CONTINUE
