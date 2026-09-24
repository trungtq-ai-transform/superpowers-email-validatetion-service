from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Literal, get_args

DisposableAction = Literal["reject", "flag", "off"]


@dataclass(frozen=True)
class ValidationPolicy:
    allow_smtputf8: bool = True
    allow_quoted_local: bool = False
    allow_domain_literal: bool = False
    subaddress_separator: str | None = "+"
    check_dns: bool = True
    allow_implicit_mx: bool = True
    disposable_action: DisposableAction = "reject"

    def __post_init__(self) -> None:
        if self.subaddress_separator is not None and len(self.subaddress_separator) != 1:
            raise ValueError("subaddress_separator must be a single character or None")
        if self.disposable_action not in get_args(DisposableAction):
            raise ValueError(f"invalid disposable_action: {self.disposable_action!r}")

    def with_overrides(self, **changes: Any) -> ValidationPolicy:
        """Return a copy with the given fields replaced; None values are ignored."""
        filtered = {key: value for key, value in changes.items() if value is not None}
        return replace(self, **filtered)
