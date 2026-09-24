from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
from fakeredis import FakeAsyncRedis

from email_validation.api.app import create_app
from email_validation.api.settings import Settings
from tests.fakes import FakeDnsBackend, mx


@pytest.fixture
def dns() -> FakeDnsBackend:
    return FakeDnsBackend(
        {
            ("example.com", "MX"): mx((10, "mx.example.com")),
            ("xn--bcher-kva.de", "MX"): mx((10, "mx.bucher.de")),
            ("mailinator.com", "MX"): mx((10, "mx.mailinator.com")),
        },
        delay=0.01,
    )


@pytest.fixture
def settings() -> Settings:
    return Settings(_env_file=None, redis_url=None)


@pytest.fixture
def redis() -> Any:
    return FakeAsyncRedis()


@pytest.fixture
async def client(
    settings: Settings, dns: FakeDnsBackend, redis: Any
) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(settings, dns_backend=dns, redis_client=redis)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
