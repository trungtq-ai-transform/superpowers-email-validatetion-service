from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import math
import re
import sys
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from redis.asyncio import Redis
from redis.exceptions import RedisError

from email_validation.core.metrics import RATE_LIMIT_ERRORS_TOTAL, RATE_LIMIT_REJECTIONS_TOTAL

logger = logging.getLogger(__name__)


def hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


_SHA256_HEX = re.compile(r"[0-9a-f]{64}")


class ApiKeyAuth:
    def __init__(self, hashes: Iterable[str], enabled: bool = True) -> None:
        normalized: list[str] = []
        for index, raw in enumerate(hashes):
            value = raw.strip().lower()
            if not value:
                continue
            if not _SHA256_HEX.fullmatch(value):
                # Never echo the value: it may be a raw key pasted by mistake.
                raise ValueError(
                    f"API key hash at index {index} is not a 64-character hex SHA-256 digest"
                )
            normalized.append(value)
        self._hashes = tuple(normalized)
        self._enabled = enabled

    def identify(self, presented: str | None) -> str | None:
        """Return a non-secret key id for a valid key, else None."""
        if not self._enabled:
            return "anonymous"
        if not presented:
            return None
        digest = hash_api_key(presented)
        match: str | None = None
        for candidate in self._hashes:  # compare against all: constant work per request
            if hmac.compare_digest(digest, candidate):
                match = candidate
        return match[:12] if match else None


# Token bucket. KEYS[1]=bucket; ARGV: capacity, refill tokens per ms, now ms, cost.
_TOKEN_BUCKET_LUA = """
local capacity = tonumber(ARGV[1])
local refill = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local cost = tonumber(ARGV[4])
local data = redis.call('HMGET', KEYS[1], 'tokens', 'ts')
local tokens = tonumber(data[1]) or capacity
local ts = tonumber(data[2]) or now
tokens = math.min(capacity, tokens + math.max(0, now - ts) * refill)
local allowed = 0
local retry_ms = 0
if tokens >= cost then
  tokens = tokens - cost
  allowed = 1
else
  retry_ms = math.ceil((cost - tokens) / refill)
end
redis.call('HSET', KEYS[1], 'tokens', tostring(tokens), 'ts', tostring(now))
redis.call('PEXPIRE', KEYS[1], math.ceil(capacity / refill) + 1000)
return {allowed, retry_ms}
"""


@dataclass(frozen=True)
class RateDecision:
    allowed: bool
    retry_after_seconds: int = 0


class RateLimiter:
    def __init__(
        self,
        redis: Redis | None,
        per_minute: int,
        clock: Callable[[], float] = time.time,
        op_timeout: float = 0.1,
    ) -> None:
        self._redis = redis
        self._capacity = per_minute
        self._refill_per_ms = per_minute / 60_000
        self._clock = clock
        self._op_timeout = op_timeout

    @property
    def capacity(self) -> int:
        """Bucket size: the most tokens a single request can ever be granted."""
        return self._capacity

    @property
    def enabled(self) -> bool:
        return self._redis is not None and self._capacity > 0

    async def check(self, key_id: str, cost: int = 1) -> RateDecision:
        if self._redis is None or not self.enabled:
            return RateDecision(True)
        now_ms = int(self._clock() * 1000)
        try:
            async with asyncio.timeout(self._op_timeout):
                allowed, retry_ms = await self._redis.eval(
                    _TOKEN_BUCKET_LUA,
                    1,
                    f"rl:v1:{key_id}",
                    self._capacity,
                    repr(self._refill_per_ms),
                    now_ms,
                    cost,
                )
        except (RedisError, OSError, TimeoutError) as exc:
            RATE_LIMIT_ERRORS_TOTAL.inc()
            logger.warning("rate limiter unavailable, allowing request: %s", exc)
            return RateDecision(True)
        if int(allowed) == 1:
            return RateDecision(True)
        RATE_LIMIT_REJECTIONS_TOTAL.inc()
        return RateDecision(False, max(1, math.ceil(int(retry_ms) / 1000)))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: python -m email_validation.api.security <api-key>")
    print(hash_api_key(sys.argv[1]))
