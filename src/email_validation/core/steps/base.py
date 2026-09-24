from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from email_validation.core.models import Reason, Status, ValidationContext
from email_validation.core.policy import ValidationPolicy


@dataclass(frozen=True)
class StepOutcome:
    stop: bool = False
    status: Status | None = None
    reason: Reason | None = None


CONTINUE = StepOutcome()


def invalid(reason: Reason) -> StepOutcome:
    return StepOutcome(stop=True, status=Status.INVALID, reason=reason)


def unknown(reason: Reason) -> StepOutcome:
    return StepOutcome(stop=True, status=Status.UNKNOWN, reason=reason)


class Step(Protocol):
    name: str

    async def run(self, ctx: ValidationContext, policy: ValidationPolicy) -> StepOutcome: ...
