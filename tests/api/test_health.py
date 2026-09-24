import httpx

from email_validation.api.app import create_app
from email_validation.api.settings import Settings
from email_validation.core import DisposableRegistry
from tests.fakes import BrokenRedis, FakeDnsBackend


async def get(app: object, path: str) -> httpx.Response:
    transport = httpx.ASGITransport(app=app)  # type: ignore[arg-type]
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        return await c.get(path)


async def test_healthz(client: httpx.AsyncClient) -> None:
    resp = await client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


async def test_readyz_ok(client: httpx.AsyncClient) -> None:
    resp = await client.get("/readyz")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["redis"] == "ok"
    assert body["disposable_domains"] > 0


async def test_readyz_degraded(settings: Settings, dns: FakeDnsBackend) -> None:
    app = create_app(settings, dns_backend=dns, redis_client=BrokenRedis())  # type: ignore[arg-type]
    resp = await get(app, "/readyz")
    assert resp.status_code == 200
    assert resp.json()["redis"] == "degraded"


async def test_readyz_redis_disabled(settings: Settings, dns: FakeDnsBackend) -> None:
    resp = await get(create_app(settings, dns_backend=dns), "/readyz")
    assert resp.json()["redis"] == "disabled"


async def test_readyz_503_without_disposable_list(settings: Settings, dns: FakeDnsBackend) -> None:
    app = create_app(settings, dns_backend=dns, registry=DisposableRegistry())
    assert (await get(app, "/readyz")).status_code == 503
