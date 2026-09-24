import dns.exception
import dns.resolver
import pytest

from email_validation.core.dns.backend import (
    DnspythonBackend,
    NoAnswerError,
    NXDomainError,
    TemporaryDnsError,
)


@pytest.mark.parametrize(
    ("raised", "expected"),
    [
        (dns.resolver.NXDOMAIN(), NXDomainError),
        (dns.resolver.NoAnswer(), NoAnswerError),
        (dns.exception.Timeout(), TemporaryDnsError),
        (dns.resolver.NoNameservers(), TemporaryDnsError),
    ],
)
async def test_exception_mapping(
    monkeypatch: pytest.MonkeyPatch, raised: Exception, expected: type[Exception]
) -> None:
    backend = DnspythonBackend(nameservers=["192.0.2.53"])

    async def fake_resolve(*args: object, **kwargs: object) -> None:
        raise raised

    monkeypatch.setattr(backend._resolver, "resolve", fake_resolve)
    with pytest.raises(expected):
        await backend.query("example.com", "MX")


def test_configuration_applied() -> None:
    backend = DnspythonBackend(nameservers=["192.0.2.53"], timeout=1.5, lifetime=3.0)
    assert len(backend._resolver.nameservers) == 1
    assert backend._resolver.timeout == 1.5
    assert backend._resolver.lifetime == 3.0
