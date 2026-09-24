import pytest

from email_validation.core.policy import ValidationPolicy


def test_defaults() -> None:
    p = ValidationPolicy()
    assert p.allow_smtputf8 is True
    assert p.allow_quoted_local is False
    assert p.allow_domain_literal is False
    assert p.subaddress_separator == "+"
    assert p.check_dns is True
    assert p.allow_implicit_mx is True
    assert p.disposable_action == "reject"


def test_with_overrides_ignores_none() -> None:
    p = ValidationPolicy().with_overrides(check_dns=False, disposable_action=None)
    assert p.check_dns is False
    assert p.disposable_action == "reject"


def test_invalid_separator_rejected() -> None:
    with pytest.raises(ValueError):
        ValidationPolicy(subaddress_separator="++")


def test_invalid_disposable_action_rejected() -> None:
    with pytest.raises(ValueError):
        ValidationPolicy(disposable_action="block")  # type: ignore[arg-type]
