from __future__ import annotations

from email_validation.core.models import ValidationContext
from email_validation.core.policy import ValidationPolicy
from email_validation.core.steps.base import CONTINUE, StepOutcome


def split_subaddress(local: str, separator: str | None) -> tuple[str, str | None]:
    """Split `user+tag` at the first separator.

    No split when: separator disabled, local-part is quoted, local-part starts
    with the separator, or the tag would be empty (`a+` -> base `a`, tag None).
    """
    if separator is None or local.startswith('"') or local.startswith(separator):
        return local, None
    base, found, tag = local.partition(separator)
    if not found or not tag:
        return base, None
    return base, tag


class IdnStep:
    name = "idn"

    async def run(self, ctx: ValidationContext, policy: ValidationPolicy) -> StepOutcome:
        parsed = ctx.parsed
        if parsed is None:
            return CONTINUE
        ctx.normalized = parsed.normalized
        ctx.local_part = parsed.local_part
        ctx.domain = parsed.domain
        ctx.ascii_domain = parsed.ascii_domain
        ctx.ascii_email = parsed.ascii_email
        ctx.base_local_part, ctx.tag = split_subaddress(
            parsed.local_part, policy.subaddress_separator
        )
        return CONTINUE
