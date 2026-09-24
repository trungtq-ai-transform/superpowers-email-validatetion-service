from __future__ import annotations

from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict

from email_validation.core.policy import ValidationPolicy


def _csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="EV_", env_file=".env", extra="ignore")

    redis_url: str | None = None

    dns_nameservers: str = ""  # comma-separated; empty = system resolver
    dns_timeout: float = 2.0
    dns_lifetime: float = 4.0
    dns_max_concurrency: int = 500
    l1_cache_size: int = 100_000

    disposable_url: str | None = None
    disposable_reload_seconds: int = 86_400
    disposable_allowlist: str = ""  # comma-separated

    allow_smtputf8: bool = True
    allow_quoted_local: bool = False
    allow_domain_literal: bool = False
    subaddress_separator: str | None = "+"
    check_dns: bool = True
    allow_implicit_mx: bool = True
    disposable_action: Literal["reject", "flag", "off"] = "reject"

    batch_max: int = 1000
    batch_concurrency: int = 100

    max_body_bytes_validate: int = 16_384
    max_body_bytes_batch: int = 2_097_152
    max_body_bytes_default: int = 65_536

    auth_enabled: bool = True
    api_key_hashes: str = ""  # comma-separated SHA-256 hex digests
    rate_limit_per_minute: int = 6000

    log_level: str = "INFO"
    otel_enabled: bool = False

    @property
    def dns_nameserver_list(self) -> list[str]:
        return _csv(self.dns_nameservers)

    @property
    def disposable_allowlist_list(self) -> list[str]:
        return _csv(self.disposable_allowlist)

    @property
    def api_key_hash_list(self) -> list[str]:
        return _csv(self.api_key_hashes)

    def to_policy(self) -> ValidationPolicy:
        return ValidationPolicy(
            allow_smtputf8=self.allow_smtputf8,
            allow_quoted_local=self.allow_quoted_local,
            allow_domain_literal=self.allow_domain_literal,
            subaddress_separator=self.subaddress_separator or None,
            check_dns=self.check_dns,
            allow_implicit_mx=self.allow_implicit_mx,
            disposable_action=self.disposable_action,
        )
