import asyncio
import contextlib

from email_validation.core.disposable.registry import DisposableRegistry, parse_domain_list


def test_parse_domain_list() -> None:
    text = "# comment\n\nMailinator.com\n  yopmail.com  \n#x.com\n"
    assert parse_domain_list(text) == {"mailinator.com", "yopmail.com"}


def test_contains_exact_and_parent() -> None:
    reg = DisposableRegistry(["mailinator.com"])
    assert reg.contains("mailinator.com")
    assert reg.contains("MAILINATOR.com")
    assert reg.contains("x.y.mailinator.com")
    assert not reg.contains("notmailinator.com")
    assert not reg.contains("example.com")


def test_allowlist_wins() -> None:
    reg = DisposableRegistry(["mailinator.com"], allowlist=["corp.mailinator.com"])
    assert not reg.contains("corp.mailinator.com")
    assert reg.contains("other.mailinator.com")


def test_bundled_list_loads() -> None:
    reg = DisposableRegistry.from_bundled()
    assert len(reg) > 0
    assert reg.contains("mailinator.com")


async def test_reload_merges_with_base() -> None:
    reg = DisposableRegistry(["mailinator.com"])

    async def fetch() -> str:
        return "newtrash.com\n"

    assert await reg.reload(fetch) is True
    assert reg.contains("newtrash.com")
    assert reg.contains("mailinator.com")


async def test_reload_failure_keeps_old_set() -> None:
    reg = DisposableRegistry(["mailinator.com"])

    async def ok() -> str:
        return "newtrash.com"

    async def boom() -> str:
        raise OSError("network down")

    await reg.reload(ok)
    assert await reg.reload(boom) is False
    assert reg.contains("newtrash.com")


async def test_reload_empty_download_keeps_old_set() -> None:
    reg = DisposableRegistry(["mailinator.com"])

    async def ok() -> str:
        return "newtrash.com"

    async def empty() -> str:
        return "# nothing\n"

    await reg.reload(ok)
    assert await reg.reload(empty) is False
    assert reg.contains("newtrash.com")


async def test_periodic_reload_runs_until_cancelled() -> None:
    reg = DisposableRegistry()
    calls = 0

    async def fetch() -> str:
        nonlocal calls
        calls += 1
        return "a.com"

    task = asyncio.create_task(reg.run_periodic_reload(fetch, interval=0.01))
    await asyncio.sleep(0.05)
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task
    assert calls >= 2
    assert reg.contains("a.com")
