from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal, Protocol

import dns.asyncresolver
import dns.exception
import dns.name
import dns.resolver

RdType = Literal["MX", "A", "AAAA"]


@dataclass(frozen=True)
class DnsAnswer:
    ttl: int
    mx: tuple[tuple[int, str], ...] = ()
    addresses: tuple[str, ...] = ()


class DnsError(Exception):
    pass


class NXDomainError(DnsError):
    """The domain does not exist."""


class NoAnswerError(DnsError):
    """The domain exists but has no records of the requested type."""


class TemporaryDnsError(DnsError):
    """Timeout, SERVFAIL, no reachable nameservers, or any other transient failure."""


class DnsBackend(Protocol):
    async def query(self, name: str, rdtype: RdType) -> DnsAnswer: ...


class DnspythonBackend:
    def __init__(
        self, nameservers: Sequence[str] = (), timeout: float = 2.0, lifetime: float = 4.0
    ) -> None:
        self._resolver = dns.asyncresolver.Resolver(configure=not nameservers)
        if nameservers:
            self._resolver.nameservers = list(nameservers)
        self._resolver.timeout = timeout
        self._resolver.lifetime = lifetime

    async def query(self, name: str, rdtype: RdType) -> DnsAnswer:
        try:
            answer = await self._resolver.resolve(name, rdtype, search=False)
        except dns.resolver.NXDOMAIN as exc:
            raise NXDomainError(name) from exc
        except dns.resolver.NoAnswer as exc:
            raise NoAnswerError(name) from exc
        except dns.exception.DNSException as exc:
            raise TemporaryDnsError(f"{name} {rdtype}: {exc}") from exc

        ttl = answer.rrset.ttl if answer.rrset is not None else 0
        if rdtype == "MX":
            records = tuple(
                (
                    int(rdata.preference),
                    "."
                    if rdata.exchange == dns.name.root
                    else rdata.exchange.to_text(omit_final_dot=True).lower(),
                )
                for rdata in answer
            )
            return DnsAnswer(ttl=ttl, mx=records)
        return DnsAnswer(ttl=ttl, addresses=tuple(str(rdata.address) for rdata in answer))
