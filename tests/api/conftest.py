from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
from fakeredis import FakeAsyncRedis

from email_validation.api.app import create_app
from email_validation.api.security import hash_api_key
from email_validation.api.settings import Settings
from tests.fakes import FakeDnsBackend, mx

TEST_KEY = "test-key"


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
    return Settings(_env_file=None, redis_url=None, api_key_hashes=hash_api_key(TEST_KEY))


@pytest.fixture
def redis() -> Any:
    return FakeAsyncRedis()


@pytest.fixture
async def client(
    settings: Settings, dns: FakeDnsBackend, redis: Any
) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(settings, dns_backend=dns, redis_client=redis)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test", headers={"X-API-Key": TEST_KEY}
    ) as c:
        yield c
