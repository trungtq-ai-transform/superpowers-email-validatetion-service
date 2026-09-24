from __future__ import annotations

from email_validation.core.disposable.registry import DisposableRegistry
from email_validation.core.models import Reason, ValidationContext
from email_validation.core.policy import ValidationPolicy
from email_validation.core.steps.base import CONTINUE, StepOutcome, invalid


class DisposableStep:
    name = "disposable"

    def __init__(self, registry: DisposableRegistry) -> None:
        self._registry = registry

    async def run(self, ctx: ValidationContext, policy: ValidationPolicy) -> StepOutcome:
        if policy.disposable_action == "off" or ctx.is_domain_literal or not ctx.ascii_domain:
            return CONTINUE
        if not self._registry.contains(ctx.ascii_domain):
            return CONTINUE
        ctx.is_disposable = True
        if policy.disposable_action == "reject":
            return invalid(Reason.DISPOSABLE)
        return CONTINUE
