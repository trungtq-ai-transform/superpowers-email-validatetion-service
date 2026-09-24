from email_validation.core.models import Reason, Status, ValidationContext, ValidationResult


def test_status_values() -> None:
    assert [s.value for s in Status] == ["valid", "invalid", "unknown"]


def test_reason_values_equal_names() -> None:
    for reason in Reason:
        assert reason.value == reason.name
    assert Reason.INTERNAL_ERROR.value == "INTERNAL_ERROR"


def test_context_to_result_copies_fields() -> None:
    ctx = ValidationContext(input=" A+b@Example.com ")
    ctx.normalized = "A+b@example.com"
    ctx.ascii_email = "A+b@example.com"
    ctx.local_part = "A+b"
    ctx.base_local_part = "A"
    ctx.tag = "b"
    ctx.domain = "example.com"
    ctx.ascii_domain = "example.com"
    ctx.mx_hosts = ("mx.example.com",)
    ctx.reasons.append(Reason.DOMAIN_NO_MX)

    result = ctx.to_result(Status.INVALID)

    assert isinstance(result, ValidationResult)
    assert result.input == " A+b@Example.com "
    assert result.status is Status.INVALID
    assert result.reasons == (Reason.DOMAIN_NO_MX,)
    assert result.base_local_part == "A"
    assert result.tag == "b"
    assert result.mx_hosts == ("mx.example.com",)
    assert result.implicit_mx is False
    assert result.is_disposable is False
