from __future__ import annotations

from email_validation.core.dns.resolver import MxOutcome, MxResolver
from email_validation.core.models import Reason, ValidationContext
from email_validation.core.policy import ValidationPolicy
from email_validation.core.steps.base import CONTINUE, StepOutcome, invalid, unknown

_FAILURES = {
    MxOutcome.NULL_MX: invalid(Reason.DOMAIN_NULL_MX),
    MxOutcome.NO_MX: invalid(Reason.DOMAIN_NO_MX),
    MxOutcome.NXDOMAIN: invalid(Reason.DOMAIN_NOT_FOUND),
    MxOutcome.TEMP_FAIL: unknown(Reason.DNS_TEMPORARY_FAILURE),
}


class DnsMxStep:
    name = "dns_mx"

    def __init__(self, resolver: MxResolver) -> None:
        self._resolver = resolver

    async def run(self, ctx: ValidationContext, policy: ValidationPolicy) -> StepOutcome:
        if not policy.check_dns or ctx.is_domain_literal or not ctx.ascii_domain:
            return CONTINUE
        result = await self._resolver.lookup(ctx.ascii_domain)
        if result.outcome is not MxOutcome.OK:
            return _FAILURES[result.outcome]
        if result.implicit and not policy.allow_implicit_mx:
            return invalid(Reason.DOMAIN_NO_MX)
        ctx.mx_hosts = result.hosts
        ctx.implicit_mx = result.implicit
        return CONTINUE
