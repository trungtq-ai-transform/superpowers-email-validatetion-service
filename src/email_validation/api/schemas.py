from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from email_validation.core.models import Reason, Status, ValidationResult


class Options(BaseModel):
    check_dns: bool | None = None
    disposable_action: Literal["reject", "flag", "off"] | None = None


class ValidateRequest(BaseModel):
    email: str = Field(max_length=1024)
    options: Options = Field(default_factory=Options)


class BatchRequest(BaseModel):
    emails: list[str] = Field(max_length=100_000)  # hard ceiling; batch_max enforced in route (413)
    options: Options = Field(default_factory=Options)


class ValidationResponse(BaseModel):
    input: str
    status: Status  # StrEnum -> serialized as "valid" / "invalid" / "unknown"
    reasons: list[Reason]
    normalized: str | None
    ascii_email: str | None
    local_part: str | None
    base_local_part: str | None
    tag: str | None
    domain: str | None
    ascii_domain: str | None
    mx_hosts: list[str]
    implicit_mx: bool
    is_disposable: bool

    @classmethod
    def from_result(cls, r: ValidationResult) -> ValidationResponse:
        return cls(
            input=r.input,
            status=r.status,
            reasons=list(r.reasons),
            normalized=r.normalized,
            ascii_email=r.ascii_email,
            local_part=r.local_part,
            base_local_part=r.base_local_part,
            tag=r.tag,
            domain=r.domain,
            ascii_domain=r.ascii_domain,
            mx_hosts=list(r.mx_hosts),
            implicit_mx=r.implicit_mx,
            is_disposable=r.is_disposable,
        )


class BatchResponse(BaseModel):
    results: list[ValidationResponse]
