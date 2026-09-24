from collections.abc import AsyncIterator, Iterator

import pytest
from redis.asyncio import Redis


@pytest.fixture(scope="session")
def redis_url() -> Iterator[str]:
    redis_module = pytest.importorskip("testcontainers.redis")
    try:
        container = redis_module.RedisContainer("redis:7-alpine").start()
    except Exception as exc:  # Docker not installed / not running
        pytest.skip(f"Docker unavailable: {exc}")
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
