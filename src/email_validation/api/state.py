from __future__ import annotations

from dataclasses import dataclass
from typing import cast

from fastapi import Request
from redis.asyncio import Redis

from email_validation.api.security import ApiKeyAuth, RateLimiter
from email_validation.api.settings import Settings
from email_validation.core import (
    DisposableRegistry,
    DnspythonBackend,
    EmailValidator,
    MemoryTTLCache,
    MxResolver,
    RedisCache,
    TieredCache,
)
from email_validation.core.dns.backend import DnsBackend


@dataclass
class AppState:
    settings: Settings
    validator: EmailValidator
    resolver: MxResolver
    registry: DisposableRegistry
    redis: Redis | None
    owns_redis: bool
    auth: ApiKeyAuth
    rate_limiter: RateLimiter


def build_state(
    settings: Settings,
    *,
    dns_backend: DnsBackend | None = None,
    redis_client: Redis | None = None,
    registry: DisposableRegistry | None = None,
) -> AppState:
    owns_redis = redis_client is None and settings.redis_url is not None
    redis = redis_client
    if owns_redis and settings.redis_url is not None:
        redis = Redis.from_url(settings.redis_url, socket_timeout=0.5, socket_connect_timeout=0.5)
    cache = TieredCache(
        MemoryTTLCache(maxsize=settings.l1_cache_size),
        RedisCache(redis) if redis is not None else None,
    )
    backend = dns_backend or DnspythonBackend(
        settings.dns_nameserver_list, timeout=settings.dns_timeout, lifetime=settings.dns_lifetime
    )
    resolver = MxResolver(
        backend,
        cache=cache,
        max_concurrency=settings.dns_max_concurrency,
        lookup_timeout=settings.dns_lifetime,
    )
    if registry is None:
        registry = DisposableRegistry.from_bundled(allowlist=settings.disposable_allowlist_list)
    validator = EmailValidator(settings.to_policy(), resolver=resolver, registry=registry)
    auth = ApiKeyAuth(settings.api_key_hash_list, enabled=settings.auth_enabled)
    rate_limiter = RateLimiter(redis, settings.rate_limit_per_minute)
    return AppState(settings, validator, resolver, registry, redis, owns_redis, auth, rate_limiter)


def get_state(request: Request) -> AppState:
    return cast(AppState, request.app.state.ev)
