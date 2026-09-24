from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator

from fastapi import FastAPI
from redis.asyncio import Redis

from email_validation.api.routes import router
from email_validation.api.settings import Settings
from email_validation.api.state import AppState, build_state
from email_validation.core import DisposableRegistry
from email_validation.core.disposable.registry import http_fetcher
from email_validation.core.dns.backend import DnsBackend


def create_app(
    settings: Settings | None = None,
    *,
    dns_backend: DnsBackend | None = None,
    redis_client: Redis | None = None,
    registry: DisposableRegistry | None = None,
) -> FastAPI:
    settings = settings or Settings()
    state = build_state(
        settings, dns_backend=dns_backend, redis_client=redis_client, registry=registry
    )

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        reload_task: asyncio.Task[None] | None = None
        if settings.disposable_url:
            reload_task = asyncio.create_task(
                state.registry.run_periodic_reload(
                    http_fetcher(settings.disposable_url), settings.disposable_reload_seconds
                )
            )
        try:
            yield
        finally:
            if reload_task is not None:
                reload_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await reload_task
            await _close(state)

    app = FastAPI(title="Email Validation Service", version="0.1.0", lifespan=lifespan)
    app.state.ev = state
    app.include_router(router)
    return app


async def _close(state: AppState) -> None:
    if state.owns_redis and state.redis is not None:
        await state.redis.aclose()
