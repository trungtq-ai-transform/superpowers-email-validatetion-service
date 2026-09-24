from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from email_validation.core.dns.backend import (
    DnsAnswer,
    DnsBackend,
    DnsError,
    NoAnswerError,
    NXDomainError,
    TemporaryDnsError,
)
from email_validation.core.metrics import DNS_LOOKUP_SECONDS, DNS_LOOKUPS_TOTAL

if TYPE_CHECKING:
    from email_validation.core.dns.cache import TieredCache


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


CACHE_KEY_PREFIX = "mx:v1:"  # must equal email_validation.core.dns.cache.KEY_PREFIX


class MxResolver:
    def __init__(
        self,
        backend: DnsBackend,
        *,
        cache: TieredCache | None = None,
        max_concurrency: int = 500,
        lookup_timeout: float = 4.0,
    ) -> None:
        self._backend = backend
        self._lookup_timeout = lookup_timeout
        self._cache = cache
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._inflight: dict[str, asyncio.Task[MxLookupResult]] = {}

    async def lookup(self, ascii_domain: str) -> MxLookupResult:
        domain = normalize_domain(ascii_domain)
        key = CACHE_KEY_PREFIX + domain
        if self._cache is not None:
            cached = await self._cache.get(key)
            if cached is not None:
                return cached
        task = self._inflight.get(key)
        if task is None:
            # Run in a separate task so one caller's cancellation never cancels the
            # shared lookup that other callers (single-flight followers) await.
            task = asyncio.create_task(self._resolve_and_store(key, domain))
            self._inflight[key] = task

            def _forget(_task: asyncio.Task[MxLookupResult], k: str = key) -> None:
                self._inflight.pop(k, None)

            task.add_done_callback(_forget)
        return await asyncio.shield(task)

    async def _resolve_and_store(self, key: str, domain: str) -> MxLookupResult:
        result = await self._resolve(domain)
        if self._cache is not None:
            await self._cache.set(key, result)
        return result

    async def _resolve(self, domain: str) -> MxLookupResult:
        start = time.perf_counter()
        try:
            async with self._semaphore:
                try:
                    # Bounds MX + A/AAAA fallback together, not each query separately.
                    async with asyncio.timeout(self._lookup_timeout):
                        result = await self._resolve_uncached(domain)
                except TimeoutError:
                    result = MxLookupResult(MxOutcome.TEMP_FAIL)
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
