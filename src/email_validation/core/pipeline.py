from __future__ import annotations

import asyncio
import logging
from collections.abc import Sequence

from email_validation.core.disposable.registry import DisposableRegistry
from email_validation.core.dns.resolver import MxResolver
from email_validation.core.metrics import VALIDATIONS_TOTAL
from email_validation.core.models import Reason, Status, ValidationContext, ValidationResult
from email_validation.core.policy import ValidationPolicy
from email_validation.core.steps.base import Step
from email_validation.core.steps.disposable import DisposableStep
from email_validation.core.steps.dns_mx import DnsMxStep
from email_validation.core.steps.idn import IdnStep
from email_validation.core.steps.normalize import NormalizeStep
from email_validation.core.steps.syntax import SyntaxStep

logger = logging.getLogger(__name__)


def default_steps(resolver: MxResolver | None, registry: DisposableRegistry | None) -> list[Step]:
    steps: list[Step] = [NormalizeStep(), SyntaxStep(), IdnStep()]
    if registry is not None:
        steps.append(DisposableStep(registry))
    if resolver is not None:
        steps.append(DnsMxStep(resolver))
    return steps


class EmailValidator:
    def __init__(
        self,
        policy: ValidationPolicy | None = None,
        *,
        resolver: MxResolver | None = None,
        registry: DisposableRegistry | None = None,
        steps: Sequence[Step] | None = None,
    ) -> None:
        self._policy = policy or ValidationPolicy()
        self._steps = list(steps) if steps is not None else default_steps(resolver, registry)

    @property
    def policy(self) -> ValidationPolicy:
        return self._policy

    async def validate(
        self, email: str, policy: ValidationPolicy | None = None
    ) -> ValidationResult:
        active = policy or self._policy
        ctx = ValidationContext(input=email)
        status = Status.VALID
        for step in self._steps:
            try:
                outcome = await step.run(ctx, active)
            except Exception:
                logger.exception("validation step failed", extra={"step": step.name})
                ctx.reasons.append(Reason.INTERNAL_ERROR)
                status = Status.UNKNOWN
                break
            if outcome.reason is not None:
                ctx.reasons.append(outcome.reason)
            if outcome.stop:
                status = outcome.status or Status.INVALID
                break
        result = ctx.to_result(status)
        first_reason = result.reasons[0].value if result.reasons else "none"
        VALIDATIONS_TOTAL.labels(status=status.value, reason=first_reason).inc()
        return result

    async def validate_many(
        self,
        emails: Sequence[str],
        policy: ValidationPolicy | None = None,
        concurrency: int = 100,
    ) -> list[ValidationResult]:
        semaphore = asyncio.Semaphore(concurrency)

        async def one(email: str) -> ValidationResult:
            async with semaphore:
                return await self.validate(email, policy)

        return list(await asyncio.gather(*(one(e) for e in emails)))
