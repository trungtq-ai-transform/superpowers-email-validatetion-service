from typing import Any

import httpx

from email_validation.api.app import create_app
from email_validation.api.security import hash_api_key
from email_validation.api.settings import Settings
from tests.fakes import FakeDnsBackend


async def test_missing_key_is_401(client: httpx.AsyncClient) -> None:
    resp = await client.post(
        "/v1/validate", json={"email": "a@example.com"}, headers={"X-API-Key": ""}
    )
    assert resp.status_code == 401


async def test_wrong_key_is_401(client: httpx.AsyncClient) -> None:
    resp = await client.post(
        "/v1/validate", json={"email": "a@example.com"}, headers={"X-API-Key": "nope"}
    )
    assert resp.status_code == 401


async def test_health_needs_no_key(client: httpx.AsyncClient) -> None:
    assert (await client.get("/healthz", headers={"X-API-Key": ""})).status_code == 200


async def test_rate_limit_429(dns: FakeDnsBackend, redis: Any) -> None:
    settings = Settings(_env_file=None, api_key_hashes=hash_api_key("k"), rate_limit_per_minute=2)
    app = create_app(settings, dns_backend=dns, redis_client=redis)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test", headers={"X-API-Key": "k"}
    ) as c:
        codes = [
            (await c.post("/v1/validate", json={"email": "a@example.com"})).status_code
            for _ in range(3)
        ]
        denied = await c.post("/v1/validate", json={"email": "a@example.com"})
    assert codes == [200, 200, 429]
    assert int(denied.headers["Retry-After"]) >= 1


async def test_batch_cost_counts_emails(dns: FakeDnsBackend, redis: Any) -> None:
    settings = Settings(_env_file=None, api_key_hashes=hash_api_key("k"), rate_limit_per_minute=5)
    app = create_app(settings, dns_backend=dns, redis_client=redis)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test", headers={"X-API-Key": "k"}
    ) as c:
        ok = await c.post("/v1/validate/batch", json={"emails": ["a@example.com"] * 4})
        denied = await c.post("/v1/validate/batch", json={"emails": ["a@example.com"] * 2})
    assert ok.status_code == 200
    assert denied.status_code == 429
