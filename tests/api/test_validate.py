from typing import Any

import httpx
import pytest

from email_validation.api.app import create_app
from email_validation.api.settings import Settings
from tests.fakes import BrokenRedis, FakeDnsBackend


async def test_validate_valid(client: httpx.AsyncClient) -> None:
    resp = await client.post("/v1/validate", json={"email": "User+News@Bücher.de"})
    assert resp.status_code == 200
    body = resp.json()
    assert body == {
        "input": "User+News@Bücher.de",
        "status": "valid",
        "reasons": [],
        "normalized": "User+News@bücher.de",
        "ascii_email": "User+News@xn--bcher-kva.de",
        "local_part": "User+News",
        "base_local_part": "User",
        "tag": "News",
        "domain": "bücher.de",
        "ascii_domain": "xn--bcher-kva.de",
        "mx_hosts": ["mx.bucher.de"],
        "implicit_mx": False,
        "is_disposable": False,
    }


async def test_invalid_is_200(client: httpx.AsyncClient) -> None:
    resp = await client.post("/v1/validate", json={"email": "not-an-email"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "invalid"
    assert resp.json()["reasons"] == ["SYNTAX_INVALID"]


async def test_empty_email_is_invalid_not_422(client: httpx.AsyncClient) -> None:
    resp = await client.post("/v1/validate", json={"email": ""})
    assert resp.status_code == 200
    assert resp.json()["status"] == "invalid"


@pytest.mark.parametrize(
    "payload",
    [{}, {"email": 123}, {"email": "a@example.com", "options": {"disposable_action": "block"}}],
)
async def test_bad_request_is_422(client: httpx.AsyncClient, payload: dict[str, Any]) -> None:
    assert (await client.post("/v1/validate", json=payload)).status_code == 422


async def test_options_override(client: httpx.AsyncClient) -> None:
    reject = await client.post("/v1/validate", json={"email": "x@mailinator.com"})
    assert reject.json()["reasons"] == ["DISPOSABLE"]
    flag = await client.post(
        "/v1/validate",
        json={"email": "x@mailinator.com", "options": {"disposable_action": "flag"}},
    )
    assert flag.json()["status"] == "valid"
    assert flag.json()["is_disposable"] is True
    no_dns = await client.post(
        "/v1/validate", json={"email": "a@nope.com", "options": {"check_dns": False}}
    )
    assert no_dns.json()["status"] == "valid"


async def test_batch_preserves_order_and_single_flight(
    client: httpx.AsyncClient, dns: FakeDnsBackend
) -> None:
    emails = [f"u{i}@example.com" for i in range(50)] + ["bad", "a@nope.com"]
    resp = await client.post("/v1/validate/batch", json={"emails": emails})
    assert resp.status_code == 200
    results = resp.json()["results"]
    assert [r["input"] for r in results] == emails
    assert results[-2]["status"] == "invalid"
    assert results[-1]["reasons"] == ["DOMAIN_NOT_FOUND"]
    assert dns.calls.count(("example.com", "MX")) == 1


async def test_batch_empty(client: httpx.AsyncClient) -> None:
    resp = await client.post("/v1/validate/batch", json={"emails": []})
    assert resp.status_code == 200
    assert resp.json() == {"results": []}


async def test_batch_too_large_is_413(client: httpx.AsyncClient) -> None:
    resp = await client.post("/v1/validate/batch", json={"emails": ["a@example.com"] * 1001})
    assert resp.status_code == 413


async def test_validate_with_broken_redis(settings: Settings, dns: FakeDnsBackend) -> None:
    app = create_app(settings, dns_backend=dns, redis_client=BrokenRedis())  # type: ignore[arg-type]
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        resp = await c.post("/v1/validate", json={"email": "a@example.com"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "valid"
