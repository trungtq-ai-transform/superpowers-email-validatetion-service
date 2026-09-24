import os
from collections.abc import AsyncIterator, Iterator

import pytest
from redis.asyncio import Redis

try:  # testcontainers >= 4.x: the top-level module is deprecated
    from testcontainers.community.redis import RedisContainer
except ImportError:  # pragma: no cover - older testcontainers
    from testcontainers.redis import RedisContainer


def _integration_required() -> bool:
    ci = os.environ.get("CI", "").strip().lower()
    return ci not in ("", "0", "false", "no") or os.environ.get("EV_REQUIRE_INTEGRATION") == "1"


@pytest.fixture(scope="session")
def redis_url() -> Iterator[str]:
    try:
        container = RedisContainer("redis:7-alpine").start()
    except Exception as exc:  # Docker not installed / not running
        message = f"Docker unavailable: {exc}"
        if _integration_required():
            pytest.fail(f"{message} (integration tests required by CI / EV_REQUIRE_INTEGRATION)")
        pytest.skip(message)
    try:
        host = container.get_container_host_ip()
        port = container.get_exposed_port(6379)
        yield f"redis://{host}:{port}/0"
    finally:
        container.stop()


@pytest.fixture
async def redis_client(redis_url: str) -> AsyncIterator[Redis]:
    client = Redis.from_url(redis_url)
    await client.flushdb()
    yield client
    await client.aclose()
