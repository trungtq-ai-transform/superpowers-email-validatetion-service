from typing import Any

import pytest

from email_validation.core.models import Reason, Status, ValidationContext
from email_validation.core.policy import ValidationPolicy
from email_validation.core.steps.base import CONTINUE, StepOutcome
from email_validation.core.steps.syntax import SyntaxStep


async def run(email: str, **policy: Any) -> tuple[StepOutcome, ValidationContext]:
    ctx = ValidationContext(input=email, email=email)
    outcome = await SyntaxStep().run(ctx, ValidationPolicy(**policy))
    return outcome, ctx


VALID = [
    "user@example.com",
    "user+tag@example.com",
    "a.b-c_d@sub.example.co.uk",
    "User+News@Bücher.de",
    "user@例え.jp",
    "用户@例え.jp",
    "user@xn--bcher-kva.de",
]

INVALID_SYNTAX = [
    "plainaddress",
    "@example.com",
    "a@",
    "a..b@example.com",
    ".a@example.com",
    "a.@example.com",
    "a@x",
    "a@-x.com",
    "a b@example.com",
    "a\r\nb@example.com",
    "a\x00b@example.com",
    "a@@example.com",
]


@pytest.mark.parametrize("email", VALID)
async def test_valid(email: str) -> None:
    outcome, ctx = await run(email)
    assert outcome == CONTINUE
    assert ctx.parsed is not None
    assert ctx.is_domain_literal is False


@pytest.mark.parametrize("email", INVALID_SYNTAX)
async def test_invalid_syntax(email: str) -> None:
    outcome, ctx = await run(email)
    assert outcome.stop is True
    assert outcome.status is Status.INVALID
    assert outcome.reason is Reason.SYNTAX_INVALID
    assert ctx.parsed is None


async def test_quoted_local_depends_on_policy() -> None:
    outcome, _ = await run('"john doe"@example.com')
    assert outcome.reason is Reason.SYNTAX_INVALID
    outcome, ctx = await run('"john doe"@example.com', allow_quoted_local=True)
    assert outcome == CONTINUE
    assert ctx.parsed is not None


async def test_domain_literal_depends_on_policy() -> None:
    outcome, _ = await run("user@[192.0.2.1]")
    assert outcome.reason is Reason.SYNTAX_INVALID
    outcome, ctx = await run("user@[192.0.2.1]", allow_domain_literal=True)
    assert outcome == CONTINUE
    assert ctx.is_domain_literal is True


@pytest.mark.parametrize(
    "email",
    [
        "a" * 65 + "@example.com",
        "user@" + "b" * 64 + ".com",
        "a" * 64 + "@" + ".".join(["b" * 63] * 3) + ".com",
    ],
)
async def test_too_long(email: str) -> None:
    outcome, _ = await run(email)
    assert outcome.status is Status.INVALID
    assert outcome.reason is Reason.TOO_LONG


@pytest.mark.parametrize("email", ["user@☃.net", "user@😀.com"])
async def test_idn_invalid(email: str) -> None:
    outcome, _ = await run(email)
    assert outcome.status is Status.INVALID
    assert outcome.reason is Reason.IDN_INVALID


async def test_smtputf8_not_allowed() -> None:
    outcome, _ = await run("用户@example.com", allow_smtputf8=False)
    assert outcome.status is Status.INVALID
    assert outcome.reason is Reason.SMTPUTF8_NOT_ALLOWED
