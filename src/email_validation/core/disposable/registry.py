from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable, Iterable
from importlib import resources

import httpx

logger = logging.getLogger(__name__)

Fetcher = Callable[[], Awaitable[str]]


def parse_domain_list(text: str) -> set[str]:
    domains: set[str] = set()
    for line in text.splitlines():
        entry = line.strip().lower()
        if entry and not entry.startswith("#"):
            domains.add(entry.rstrip("."))
    return domains


def http_fetcher(url: str, timeout: float = 10.0) -> Fetcher:
    async def fetch() -> str:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            response = await client.get(url)
            response.raise_for_status()
            return response.text

    return fetch


class DisposableRegistry:
    def __init__(self, domains: Iterable[str] = (), allowlist: Iterable[str] = ()) -> None:
        self._base = frozenset(d.strip().lower().rstrip(".") for d in domains if d.strip())
        self._allow = frozenset(d.strip().lower().rstrip(".") for d in allowlist if d.strip())
        self._domains: frozenset[str] = self._base

    @classmethod
    def from_bundled(cls, allowlist: Iterable[str] = ()) -> DisposableRegistry:
        text = (
            resources.files("email_validation.core.disposable")
            .joinpath("data/disposable_domains.txt")
            .read_text(encoding="utf-8")
        )
        return cls(parse_domain_list(text), allowlist=allowlist)

    def __len__(self) -> int:
        return len(self._domains)

    def contains(self, ascii_domain: str) -> bool:
        labels = ascii_domain.lower().rstrip(".").split(".")
        for i in range(len(labels) - 1):
            candidate = ".".join(labels[i:])
            if candidate in self._allow:
                return False
            if candidate in self._domains:
                return True
        return False

    async def reload(self, fetch: Fetcher) -> bool:
        try:
            fetched = parse_domain_list(await fetch())
        except Exception as exc:
            logger.warning("disposable list reload failed, keeping previous list: %s", exc)
            return False
        if not fetched:
            logger.warning("disposable list download was empty, keeping previous list")
            return False
        self._domains = self._base | fetched  # atomic reference swap
        logger.info("disposable list reloaded", extra={"count": len(self._domains)})
        return True

    async def run_periodic_reload(self, fetch: Fetcher, interval: float) -> None:
        while True:
            await self.reload(fetch)
            await asyncio.sleep(interval)
