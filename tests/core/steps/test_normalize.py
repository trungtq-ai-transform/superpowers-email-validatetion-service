from email_validation.core.models import Reason, Status, ValidationContext
from email_validation.core.policy import ValidationPolicy
from email_validation.core.steps.base import CONTINUE
from email_validation.core.steps.normalize import NormalizeStep


async def run(value: str) -> tuple[object, ValidationContext]:
    ctx = ValidationContext(input=value)
    outcome = await NormalizeStep().run(ctx, ValidationPolicy())
    return outcome, ctx


async def test_strips_whitespace_and_newlines() -> None:
    outcome, ctx = await run("  User@Example.com \n")
    assert outcome == CONTINUE
    assert ctx.email == "User@Example.com"


async def test_applies_nfc() -> None:
    _, ctx = await run("üser@example.com")
    assert ctx.email == "üser@example.com"


async def test_empty_is_invalid() -> None:
    for value in ("", "   ", "\t\n"):
        outcome, _ = await run(value)
        assert outcome.stop is True
        assert outcome.status is Status.INVALID
        assert outcome.reason is Reason.SYNTAX_INVALID
