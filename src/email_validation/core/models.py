from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from email_validator import ValidatedEmail


class Status(StrEnum):
    VALID = "valid"
    INVALID = "invalid"
    UNKNOWN = "unknown"


class Reason(StrEnum):
    SYNTAX_INVALID = "SYNTAX_INVALID"
    TOO_LONG = "TOO_LONG"
    IDN_INVALID = "IDN_INVALID"
    SMTPUTF8_NOT_ALLOWED = "SMTPUTF8_NOT_ALLOWED"
    DISPOSABLE = "DISPOSABLE"
    DOMAIN_NOT_FOUND = "DOMAIN_NOT_FOUND"
    DOMAIN_NO_MX = "DOMAIN_NO_MX"
    DOMAIN_NULL_MX = "DOMAIN_NULL_MX"
    DNS_TEMPORARY_FAILURE = "DNS_TEMPORARY_FAILURE"
    INTERNAL_ERROR = "INTERNAL_ERROR"


@dataclass(frozen=True)
class ValidationResult:
    input: str
    status: Status
    reasons: tuple[Reason, ...]
    normalized: str | None
    ascii_email: str | None
    local_part: str | None
    base_local_part: str | None
    tag: str | None
    domain: str | None
    ascii_domain: str | None
    mx_hosts: tuple[str, ...]
    implicit_mx: bool
    is_disposable: bool


@dataclass
class ValidationContext:
    input: str
    email: str = ""
    parsed: ValidatedEmail | None = None
    is_domain_literal: bool = False
    normalized: str | None = None
    ascii_email: str | None = None
    local_part: str | None = None
    base_local_part: str | None = None
    tag: str | None = None
    domain: str | None = None
    ascii_domain: str | None = None
    mx_hosts: tuple[str, ...] = ()
    implicit_mx: bool = False
    is_disposable: bool = False
    reasons: list[Reason] = field(default_factory=list)

    def to_result(self, status: Status) -> ValidationResult:
        return ValidationResult(
            input=self.input,
            status=status,
            reasons=tuple(self.reasons),
            normalized=self.normalized,
            ascii_email=self.ascii_email,
            local_part=self.local_part,
            base_local_part=self.base_local_part,
            tag=self.tag,
            domain=self.domain,
            ascii_domain=self.ascii_domain,
            mx_hosts=self.mx_hosts,
            implicit_mx=self.implicit_mx,
            is_disposable=self.is_disposable,
        )
