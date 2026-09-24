from __future__ import annotations

import idna
from email_validator import EmailNotValidError, validate_email

from email_validation.core.models import Reason, ValidationContext
from email_validation.core.policy import ValidationPolicy
from email_validation.core.steps.base import CONTINUE, StepOutcome, invalid

MAX_ADDRESS_OCTETS = 254
MAX_LOCAL_OCTETS = 64
MAX_LABEL_OCTETS = 63
MAX_DOMAIN_OCTETS = 253


class IdnConversionError(ValueError):
    pass


def to_ascii_domain(domain: str) -> str:
    """Convert a domain to its A-label form.

    Plain ASCII domains without `xn--` labels are only lowercased, so ordinary
    syntax errors are reported by email-validator as SYNTAX_INVALID rather than
    being misreported as IDN errors.
    """
    labels = domain.split(".")
    if domain.isascii() and not any(label.lower().startswith("xn--") for label in labels):
        return domain.lower()
    try:
        return idna.encode(domain, uts46=True).decode("ascii")
    except (idna.IDNAError, UnicodeError) as exc:
        raise IdnConversionError(str(exc)) from exc


class SyntaxStep:
    name = "syntax"

    async def run(self, ctx: ValidationContext, policy: ValidationPolicy) -> StepOutcome:
        email = ctx.email
        if "@" not in email:
            return invalid(Reason.SYNTAX_INVALID)
        local, _, domain = email.rpartition("@")
        local_octets = len(local.encode("utf-8"))
        if local_octets > MAX_LOCAL_OCTETS:
            return invalid(Reason.TOO_LONG)
        if not local.isascii() and not policy.allow_smtputf8:
            return invalid(Reason.SMTPUTF8_NOT_ALLOWED)

        if not domain.startswith("["):
            try:
                ascii_domain = to_ascii_domain(domain)
            except IdnConversionError:
                return invalid(Reason.IDN_INVALID)
            if len(ascii_domain) > MAX_DOMAIN_OCTETS or any(
                len(label) > MAX_LABEL_OCTETS for label in ascii_domain.split(".")
            ):
                return invalid(Reason.TOO_LONG)
            if local_octets + 1 + len(ascii_domain) > MAX_ADDRESS_OCTETS:
                return invalid(Reason.TOO_LONG)

        try:
            parsed = validate_email(
                email,
                check_deliverability=False,
                allow_smtputf8=policy.allow_smtputf8,
                allow_quoted_local=policy.allow_quoted_local,
                allow_domain_literal=policy.allow_domain_literal,
            )
        except EmailNotValidError:
            return invalid(Reason.SYNTAX_INVALID)

        ctx.parsed = parsed
        ctx.is_domain_literal = getattr(parsed, "domain_address", None) is not None
        return CONTINUE
