from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import OrderedDict
from collections.abc import Callable
from typing import Protocol

from redis.asyncio import Redis
from redis.exceptions import RedisError

from email_validation.core.dns.resolver import MxLookupResult, MxOutcome
from email_validation.core.metrics import CACHE_ERRORS_TOTAL, CACHE_HITS_TOTAL

logger = logging.getLogger(__name__)

KEY_PREFIX = "mx:v1:"
L1_MAX_TTL = 300
L2_MIN_TTL = 60
L2_MAX_TTL = 86_400
NEGATIVE_TTL = 300
TEMP_FAIL_TTL = 30
_POSITIVE = (MxOutcome.OK, MxOutcome.NULL_MX)
_NEGATIVE = (MxOutcome.NO_MX, MxOutcome.NXDOMAIN)


def cache_key(domain: str) -> str:
    return KEY_PREFIX + domain


def l1_ttl(result: MxLookupResult) -> int:
    if result.outcome in _POSITIVE:
        return max(1, min(result.ttl, L1_MAX_TTL))
    if result.outcome in _NEGATIVE:
        return NEGATIVE_TTL
    return TEMP_FAIL_TTL


def l2_ttl(result: MxLookupResult) -> int:
    if result.outcome in _POSITIVE:
        return min(max(result.ttl, L2_MIN_TTL), L2_MAX_TTL)
    if result.outcome in _NEGATIVE:
        return NEGATIVE_TTL
    return TEMP_FAIL_TTL


def encode_result(result: MxLookupResult) -> str:
    return json.dumps(
        {
            "outcome": result.outcome.value,
            "hosts": list(result.hosts),
            "implicit": result.implicit,
            "ttl": result.ttl,
        }
    )


def decode_result(raw: str | bytes) -> MxLookupResult:
    data = json.loads(raw)
    return MxLookupResult(
        outcome=MxOutcome(data["outcome"]),
        hosts=tuple(data["hosts"]),
        implicit=bool(data["implicit"]),
        ttl=int(data["ttl"]),
    )


class Cache(Protocol):
    async def get(self, key: str) -> MxLookupResult | None: ...

    async def set(self, key: str, value: MxLookupResult, ttl: int) -> None: ...


class MemoryTTLCache:
    """Per-process TTL + LRU cache (L1)."""

    def __init__(self, maxsize: int = 100_000, clock: Callable[[], float] = time.monotonic) -> None:
        self._maxsize = maxsize
        self._clock = clock
        self._data: OrderedDict[str, tuple[float, MxLookupResult]] = OrderedDict()

    async def get(self, key: str) -> MxLookupResult | None:
        entry = self._data.get(key)
        if entry is None:
            return None
        expires_at, value = entry
        if self._clock() >= expires_at:
            del self._data[key]
            return None
        self._data.move_to_end(key)
        return value

    async def set(self, key: str, value: MxLookupResult, ttl: int) -> None:
        if ttl <= 0:
            return
        self._data[key] = (self._clock() + ttl, value)
        self._data.move_to_end(key)
        while len(self._data) > self._maxsize:
            self._data.popitem(last=False)


class RedisCache:
    """Shared cache (L2). Every failure is swallowed: Redis is never a hard dependency."""

    def __init__(self, client: Redis, op_timeout: float = 0.05) -> None:
        self._client = client
        self._op_timeout = op_timeout

    async def get(self, key: str) -> MxLookupResult | None:
        try:
            async with asyncio.timeout(self._op_timeout):
                raw = await self._client.get(key)
        except (RedisError, OSError, TimeoutError) as exc:
            CACHE_ERRORS_TOTAL.labels(op="get").inc()
            logger.warning("redis cache get failed: %s", exc)
            return None
        if raw is None:
            return None
        try:
            return decode_result(raw)
        except (ValueError, KeyError, TypeError):
            CACHE_ERRORS_TOTAL.labels(op="decode").inc()
            return None

    async def set(self, key: str, value: MxLookupResult, ttl: int) -> None:
        try:
            async with asyncio.timeout(self._op_timeout):
                await self._client.set(key, encode_result(value), ex=ttl)
        except (RedisError, OSError, TimeoutError) as exc:
            CACHE_ERRORS_TOTAL.labels(op="set").inc()
            logger.warning("redis cache set failed: %s", exc)


class TieredCache:
    def __init__(self, l1: Cache, l2: Cache | None = None) -> None:
        self._l1 = l1
        self._l2 = l2

    async def get(self, key: str) -> MxLookupResult | None:
        value = await self._l1.get(key)
        if value is not None:
            CACHE_HITS_TOTAL.labels(tier="l1").inc()
            return value
        if self._l2 is not None:
            value = await self._l2.get(key)
            if value is not None:
                CACHE_HITS_TOTAL.labels(tier="l2").inc()
                await self._l1.set(key, value, l1_ttl(value))
                return value
        CACHE_HITS_TOTAL.labels(tier="miss").inc()
        return None

    async def set(self, key: str, value: MxLookupResult) -> None:
        await self._l1.set(key, value, l1_ttl(value))
        if self._l2 is not None:
            await self._l2.set(key, value, l2_ttl(value))
