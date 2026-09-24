from __future__ import annotations

import unicodedata

from email_validation.core.models import Reason, ValidationContext
from email_validation.core.policy import ValidationPolicy
from email_validation.core.steps.base import CONTINUE, StepOutcome, invalid


class NormalizeStep:
    name = "normalize"

    async def run(self, ctx: ValidationContext, policy: ValidationPolicy) -> StepOutcome:
        ctx.email = unicodedata.normalize("NFC", ctx.input.strip())
        if not ctx.email:
            return invalid(Reason.SYNTAX_INVALID)
        return CONTINUE
