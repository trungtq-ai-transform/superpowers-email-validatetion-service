import uuid

import pytest

from email_validation.core import (
    DisposableRegistry,
    DnspythonBackend,
    EmailValidator,
    MxResolver,
    Status,
)
from email_validation.core.dns.resolver import MxOutcome

pytestmark = pytest.mark.network


async def test_gmail_has_mx() -> None:
    result = await MxResolver(DnspythonBackend()).lookup("gmail.com")
    assert result.outcome is MxOutcome.OK
    assert any("google" in host for host in result.hosts)


async def test_random_domain_is_nxdomain() -> None:
    result = await MxResolver(DnspythonBackend()).lookup(f"ev-smoke-{uuid.uuid4().hex}.com")
    assert result.outcome is MxOutcome.NXDOMAIN


async def test_pipeline_end_to_end() -> None:
    validator = EmailValidator(
        resolver=MxResolver(DnspythonBackend()), registry=DisposableRegistry.from_bundled()
    )
    result = await validator.validate("someone+tag@gmail.com")
    assert result.status is Status.VALID
    assert result.tag == "tag"
