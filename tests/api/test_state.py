import logging

import pytest
from fakeredis import FakeAsyncRedis

from email_validation.api.security import hash_api_key
from email_validation.api.settings import Settings
from email_validation.api.state import build_state
from tests.fakes import FakeDnsBackend

STATE_LOGGER = "email_validation.api.state"


def _warnings(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.name == STATE_LOGGER and r.levelno == logging.WARNING
    ]


def test_warns_when_auth_enabled_without_hashes(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.WARNING, logger=STATE_LOGGER)
    settings = Settings(_env_file=None, auth_enabled=True, api_key_hashes="")
    build_state(settings, dns_backend=FakeDnsBackend(), redis_client=FakeAsyncRedis())
    messages = _warnings(caplog)
    assert len(messages) == 1
    assert "no API key hashes" in messages[0]


def test_warns_when_rate_limit_disabled_without_redis(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.WARNING, logger=STATE_LOGGER)
    settings = Settings(
        _env_file=None, redis_url=None, api_key_hashes=hash_api_key("k"), rate_limit_per_minute=10
    )
    build_state(settings, dns_backend=FakeDnsBackend())
    messages = _warnings(caplog)
    assert len(messages) == 1
    assert "rate limiting is disabled" in messages[0]


def test_no_warnings_when_fully_configured(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.WARNING, logger=STATE_LOGGER)
    settings = Settings(_env_file=None, api_key_hashes=hash_api_key("k"))
    build_state(settings, dns_backend=FakeDnsBackend(), redis_client=FakeAsyncRedis())
    assert _warnings(caplog) == []


def test_no_rate_limit_warning_when_explicitly_disabled(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.WARNING, logger=STATE_LOGGER)
    settings = Settings(
        _env_file=None, redis_url=None, api_key_hashes=hash_api_key("k"), rate_limit_per_minute=0
    )
    build_state(settings, dns_backend=FakeDnsBackend())
    assert _warnings(caplog) == []


def test_malformed_hash_fails_at_startup() -> None:
    settings = Settings(_env_file=None, api_key_hashes=f"{hash_api_key('k')},oops")
    with pytest.raises(ValueError, match="index 1"):
        build_state(settings, dns_backend=FakeDnsBackend())
