from __future__ import annotations

import asyncio

import redis.exceptions

from email_validation.core.dns.backend import DnsAnswer, DnsError, NXDomainError

Response = DnsAnswer | DnsError | type[DnsError]


def mx(*records: tuple[int, str], ttl: int = 3600) -> DnsAnswer:
    return DnsAnswer(ttl=ttl, mx=tuple(records))


def addr(*ips: str, ttl: int = 300) -> DnsAnswer:
    return DnsAnswer(ttl=ttl, addresses=tuple(ips))


class FakeDnsBackend:
    """Programmable DnsBackend. Unknown (name, rdtype) pairs raise NXDomainError."""

    def __init__(
        self, responses: dict[tuple[str, str], Response] | None = None, delay: float = 0.0
    ) -> None:
        self.responses: dict[tuple[str, str], Response] = dict(responses or {})
        self.delay = delay
        self.calls: list[tuple[str, str]] = []
        self.in_flight = 0
        self.max_in_flight = 0

    async def query(self, name: str, rdtype: str) -> DnsAnswer:
        self.calls.append((name, rdtype))
        self.in_flight += 1
        self.max_in_flight = max(self.max_in_flight, self.in_flight)
        try:
            if self.delay:
                await asyncio.sleep(self.delay)
            response = self.responses.get((name, rdtype), NXDomainError)
            if isinstance(response, DnsAnswer):
                return response
            if isinstance(response, type):
                raise response(name)
            raise response
        finally:
            self.in_flight -= 1


class BrokenRedis:
    """Stands in for redis.asyncio.Redis when the server is unreachable."""

    async def _fail(self, *args: object, **kwargs: object) -> None:
        raise redis.exceptions.ConnectionError("redis is down")

    get = set = ping = eval = evalsha = _fail

    async def aclose(self) -> None:
        return None
