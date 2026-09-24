import json
import logging

import httpx
import pytest

from email_validation.api.observability import JsonFormatter, email_fingerprint, request_id_var


async def test_metrics_endpoint(client: httpx.AsyncClient) -> None:
    await client.post("/v1/validate", json={"email": "a@example.com"})
    resp = await client.get("/metrics", headers={"X-API-Key": ""})
    assert resp.status_code == 200
    assert "validations_total" in resp.text
    assert "dns_lookup_seconds" in resp.text


async def test_request_id_echoed(client: httpx.AsyncClient) -> None:
    resp = await client.get("/healthz", headers={"X-Request-ID": "abc-123"})
    assert resp.headers["X-Request-ID"] == "abc-123"


async def test_request_id_generated_when_missing_or_unsafe(client: httpx.AsyncClient) -> None:
    generated = (await client.get("/healthz")).headers["X-Request-ID"]
    assert len(generated) == 32
    unsafe = await client.get("/healthz", headers={"X-Request-ID": "bad value;drop"})
    assert unsafe.headers["X-Request-ID"] != "bad value;drop"
    assert len(unsafe.headers["X-Request-ID"]) == 32


async def test_logs_never_contain_raw_email(
    client: httpx.AsyncClient, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    email = "secret.person+tag@example.com"
    await client.post("/v1/validate", json={"email": email})
    await client.post("/v1/validate/batch", json={"emails": [email]})
    records = [r for r in caplog.records if r.name.startswith("email_validation")]
    assert records, "expected validation log records"
    for record in records:
        rendered = JsonFormatter().format(record)
        assert "secret.person" not in rendered
    single = next(r for r in records if r.getMessage() == "email validated")
    assert single.email_sha256 == email_fingerprint(email)  # type: ignore[attr-defined]
    assert single.domain == "example.com"  # type: ignore[attr-defined]


def test_json_formatter_includes_request_id() -> None:
    token = request_id_var.set("rid-1")
    try:
        record = logging.LogRecord("email_validation.x", logging.INFO, __file__, 1, "hi", (), None)
        record.domain = "example.com"
        payload = json.loads(JsonFormatter().format(record))
    finally:
        request_id_var.reset(token)
    assert payload["request_id"] == "rid-1"
    assert payload["message"] == "hi"
    assert payload["domain"] == "example.com"
    assert payload["level"] == "INFO"
