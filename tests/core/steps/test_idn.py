from typing import Any

import pytest

from email_validation.core.models import ValidationContext
from email_validation.core.policy import ValidationPolicy
from email_validation.core.steps.base import CONTINUE
from email_validation.core.steps.idn import IdnStep, split_subaddress
from email_validation.core.steps.normalize import NormalizeStep
from email_validation.core.steps.syntax import SyntaxStep


async def run(email: str, **policy_kw: Any) -> ValidationContext:
    policy = ValidationPolicy(**policy_kw)
    ctx = ValidationContext(input=email)
    for step in (NormalizeStep(), SyntaxStep(), IdnStep()):
        outcome = await step.run(ctx, policy)
        assert outcome == CONTINUE, f"{step.name} stopped: {outcome}"
    return ctx


async def test_idn_domain_with_tag() -> None:
    ctx = await run("User+News@Bücher.de")
    assert ctx.normalized == "User+News@bücher.de"
    assert ctx.local_part == "User+News"
    assert ctx.base_local_part == "User"
    assert ctx.tag == "News"
    assert ctx.domain == "bücher.de"
    assert ctx.ascii_domain == "xn--bcher-kva.de"
    assert ctx.ascii_email == "User+News@xn--bcher-kva.de"


async def test_japanese_domain() -> None:
    ctx = await run("user@例え.jp")
    assert ctx.domain == "例え.jp"
    assert ctx.ascii_domain is not None
    assert ctx.ascii_domain.startswith("xn--")
    assert ctx.ascii_domain.endswith(".jp")


async def test_punycode_input_keeps_ascii_domain() -> None:
    ctx = await run("user@xn--bcher-kva.de")
    assert ctx.ascii_domain == "xn--bcher-kva.de"


async def test_unicode_local_part_has_no_ascii_email() -> None:
    ctx = await run("用户@例え.jp")
    assert ctx.local_part == "用户"
    assert ctx.ascii_email is None


async def test_domain_literal() -> None:
    ctx = await run("user@[192.0.2.1]", allow_domain_literal=True)
    assert ctx.domain == "[192.0.2.1]"
    assert ctx.is_domain_literal is True


async def test_custom_separator() -> None:
    ctx = await run("john-news@example.com", subaddress_separator="-")
    assert (ctx.base_local_part, ctx.tag) == ("john", "news")


async def test_separator_disabled() -> None:
    ctx = await run("john+news@example.com", subaddress_separator=None)
    assert (ctx.base_local_part, ctx.tag) == ("john+news", None)


async def test_quoted_local_not_split() -> None:
    ctx = await run('"a b+c"@example.com', allow_quoted_local=True)
    assert ctx.tag is None
    assert ctx.base_local_part == ctx.local_part


@pytest.mark.parametrize(
    ("local", "expected"),
    [
        ("user", ("user", None)),
        ("user+tag", ("user", "tag")),
        ("a+b+c", ("a", "b+c")),
        ("+tag", ("+tag", None)),
        ("a+", ("a", None)),
        ('"a b+c"', ('"a b+c"', None)),
    ],
)
def test_split_subaddress(local: str, expected: tuple[str, str | None]) -> None:
    assert split_subaddress(local, "+") == expected


def test_split_subaddress_none_separator() -> None:
    assert split_subaddress("a+b", None) == ("a+b", None)
