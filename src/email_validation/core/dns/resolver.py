from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from enum import StrEnum

from email_validation.core.dns.backend import (
    DnsAnswer,
    DnsBackend,
    DnsError,
    NoAnswerError,
    NXDomainError,
    TemporaryDnsError,
)
from email_validation.core.metrics import DNS_LOOKUP_SECONDS, DNS_LOOKUPS_TOTAL


class MxOutcome(StrEnum):
    OK = "ok"
    NULL_MX = "null_mx"
    NO_MX = "no_mx"
    NXDOMAIN = "nxdomain"
    TEMP_FAIL = "temp_fail"


@dataclass(frozen=True)
class MxLookupResult:
    outcome: MxOutcome
    hosts: tuple[str, ...] = ()
    implicit: bool = False
    ttl: int = 0


def normalize_domain(domain: str) -> str:
    return domain.lower().rstrip(".")


class MxResolver:
    def __init__(self, backend: DnsBackend, *, max_concurrency: int = 500) -> None:
        self._backend = backend
        self._semaphore = asyncio.Semaphore(max_concurrency)

    async def lookup(self, ascii_domain: str) -> MxLookupResult:
        return await self._resolve(normalize_domain(ascii_domain))

    async def _resolve(self, domain: str) -> MxLookupResult:
        start = time.perf_counter()
        try:
            async with self._semaphore:
                result = await self._resolve_uncached(domain)
        finally:
            DNS_LOOKUP_SECONDS.observe(time.perf_counter() - start)
        DNS_LOOKUPS_TOTAL.labels(outcome=result.outcome.value).inc()
        return result

    async def _resolve_uncached(self, domain: str) -> MxLookupResult:
        try:
            answer = await self._backend.query(domain, "MX")
        except NXDomainError:
            return MxLookupResult(MxOutcome.NXDOMAIN)
        except NoAnswerError:
            return await self._fallback(domain)
        except TemporaryDnsError:
            return MxLookupResult(MxOutcome.TEMP_FAIL)

        if not answer.mx:
            return await self._fallback(domain)
        real = sorted(rec for rec in answer.mx if rec[1] != ".")  # by (preference, host)
        if not real:
            return MxLookupResult(MxOutcome.NULL_MX, ttl=answer.ttl)
        hosts = tuple(dict.fromkeys(host for _, host in real))
        return MxLookupResult(MxOutcome.OK, hosts=hosts, ttl=answer.ttl)

    async def _fallback(self, domain: str) -> MxLookupResult:
        """RFC 5321 section 5.1: no MX means the domain itself is the implicit MX
        if it has A/AAAA records."""
        results = await asyncio.gather(
            self._backend.query(domain, "A"),
            self._backend.query(domain, "AAAA"),
            return_exceptions=True,
        )
        for item in results:
            if isinstance(item, BaseException) and not isinstance(item, DnsError):
                raise item
        answers = [r for r in results if isinstance(r, DnsAnswer) and r.addresses]
        if answers:
            ttl = min(a.ttl for a in answers)
            return MxLookupResult(MxOutcome.OK, hosts=(domain,), implicit=True, ttl=ttl)
        if any(isinstance(r, TemporaryDnsError) for r in results):
            return MxLookupResult(MxOutcome.TEMP_FAIL)
        if any(isinstance(r, NXDomainError) for r in results):
            return MxLookupResult(MxOutcome.NXDOMAIN)
        return MxLookupResult(MxOutcome.NO_MX)
