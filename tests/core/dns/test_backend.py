from types import SimpleNamespace

import dns.exception
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import pytest

from email_validation.core.dns.backend import (
    DnspythonBackend,
    NoAnswerError,
    NXDomainError,
    TemporaryDnsError,
)


def _mx_rdata(text: str) -> dns.rdata.Rdata:
    return dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.MX, text)


def _a_rdata(text: str) -> dns.rdata.Rdata:
    return dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, text)


def _aaaa_rdata(text: str) -> dns.rdata.Rdata:
    return dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.AAAA, text)


class _FakeAnswer:
    """Minimal stand-in for dns.resolver.Answer: iterable of rdata plus .rrset.ttl."""

    def __init__(self, rdatas: list[dns.rdata.Rdata], ttl: int | None) -> None:
        self._rdatas = rdatas
        self.rrset = SimpleNamespace(ttl=ttl) if ttl is not None else None

    def __iter__(self) -> object:
        return iter(self._rdatas)


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


async def test_mx_success_parses_and_normalizes(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = DnspythonBackend(nameservers=["192.0.2.53"])
    answer = _FakeAnswer(
        [_mx_rdata("10 MX1.Example.COM."), _mx_rdata("20 mx2.example.com.")], ttl=3600
    )

    async def fake_resolve(*args: object, **kwargs: object) -> _FakeAnswer:
        return answer

    monkeypatch.setattr(backend._resolver, "resolve", fake_resolve)
    result = await backend.query("example.com", "MX")
    assert result.ttl == 3600
    assert result.mx == ((10, "mx1.example.com"), (20, "mx2.example.com"))


async def test_null_mx_parses_as_dot(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = DnspythonBackend(nameservers=["192.0.2.53"])
    answer = _FakeAnswer([_mx_rdata("0 .")], ttl=300)

    async def fake_resolve(*args: object, **kwargs: object) -> _FakeAnswer:
        return answer

    monkeypatch.setattr(backend._resolver, "resolve", fake_resolve)
    result = await backend.query("example.com", "MX")
    assert result.mx == ((0, "."),)


async def test_a_success_returns_addresses(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = DnspythonBackend(nameservers=["192.0.2.53"])
    answer = _FakeAnswer([_a_rdata("192.0.2.1"), _a_rdata("192.0.2.2")], ttl=120)

    async def fake_resolve(*args: object, **kwargs: object) -> _FakeAnswer:
        return answer

    monkeypatch.setattr(backend._resolver, "resolve", fake_resolve)
    result = await backend.query("example.com", "A")
    assert result.ttl == 120
    assert result.addresses == ("192.0.2.1", "192.0.2.2")


async def test_aaaa_success_returns_addresses(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = DnspythonBackend(nameservers=["192.0.2.53"])
    answer = _FakeAnswer([_aaaa_rdata("2001:db8::1")], ttl=60)

    async def fake_resolve(*args: object, **kwargs: object) -> _FakeAnswer:
        return answer

    monkeypatch.setattr(backend._resolver, "resolve", fake_resolve)
    result = await backend.query("example.com", "AAAA")
    assert result.ttl == 60
    assert result.addresses == ("2001:db8::1",)


async def test_ttl_defaults_to_zero_when_rrset_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = DnspythonBackend(nameservers=["192.0.2.53"])
    answer = _FakeAnswer([_a_rdata("192.0.2.1")], ttl=None)

    async def fake_resolve(*args: object, **kwargs: object) -> _FakeAnswer:
        return answer

    monkeypatch.setattr(backend._resolver, "resolve", fake_resolve)
    result = await backend.query("example.com", "A")
    assert result.ttl == 0
