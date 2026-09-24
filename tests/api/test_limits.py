import json
from collections.abc import AsyncIterator
from typing import Any

import httpx

from email_validation.api.app import create_app
from email_validation.api.settings import Settings
from tests.fakes import FakeDnsBackend

TOO_LARGE = {"detail": "request body too large"}


async def test_oversized_content_length_is_413_without_auth(
    client: httpx.AsyncClient, dns: FakeDnsBackend
) -> None:
    body = json.dumps({"email": "a@example.com", "pad": "x" * 20_000})
    resp = await client.post(
        "/v1/validate",
        content=body,
        headers={"X-API-Key": "", "Content-Type": "application/json"},
    )
    assert resp.status_code == 413
    assert resp.json() == TOO_LARGE
    assert "x-request-id" in resp.headers
    assert dns.calls == []


async def test_oversized_batch_body_is_413(client: httpx.AsyncClient, dns: FakeDnsBackend) -> None:
    body = json.dumps({"emails": ["a@example.com"], "pad": "x" * 2_200_000})
    resp = await client.post(
        "/v1/validate/batch", content=body, headers={"Content-Type": "application/json"}
    )
    assert resp.status_code == 413
    assert resp.json() == TOO_LARGE
    assert dns.calls == []


async def test_streamed_oversize_without_content_length_is_413(
    client: httpx.AsyncClient, dns: FakeDnsBackend
) -> None:
    sent_headers: dict[str, str] = {}

    async def chunks() -> AsyncIterator[bytes]:
        yield b'{"email": "a@example.com", "pad": "'
        for _ in range(40):
            yield b"x" * 1024
        yield b'"}'

    async def capture(request: httpx.Request) -> None:
        sent_headers.update(request.headers)

    client.event_hooks["request"].append(capture)
    resp = await client.post(
        "/v1/validate", content=chunks(), headers={"Content-Type": "application/json"}
    )
    assert "content-length" not in sent_headers
    assert resp.status_code == 413
    assert resp.json() == TOO_LARGE
    assert dns.calls == []


async def test_default_limit_applies_to_other_paths(dns: FakeDnsBackend, redis: Any) -> None:
    settings = Settings(_env_file=None, auth_enabled=False, max_body_bytes_default=10)
    app = create_app(settings, dns_backend=dns, redis_client=redis)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        resp = await c.post("/healthz", content=b"x" * 11)
    assert resp.status_code == 413


async def test_normal_requests_unaffected(client: httpx.AsyncClient) -> None:
    single = await client.post("/v1/validate", json={"email": "a@example.com"})
    batch = await client.post(
        "/v1/validate/batch", json={"emails": ["a@example.com", "b@example.com"]}
    )
    health = await client.get("/healthz")
    assert single.status_code == 200
    assert batch.status_code == 200
    assert health.status_code == 200


async def test_streamed_body_under_limit_is_accepted(client: httpx.AsyncClient) -> None:
    async def chunks() -> AsyncIterator[bytes]:
        yield b'{"email": '
        yield b'"a@example.com"}'

    resp = await client.post(
        "/v1/validate", content=chunks(), headers={"Content-Type": "application/json"}
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "valid"


async def test_batch_item_longer_than_1024_is_422(client: httpx.AsyncClient) -> None:
    long_email = "a" * 1020 + "@example.com"
    resp = await client.post("/v1/validate/batch", json={"emails": [long_email]})
    assert resp.status_code == 422
