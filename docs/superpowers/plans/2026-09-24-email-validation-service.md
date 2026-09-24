# Email Validation Service Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Xây dựng thư viện Python async + REST API FastAPI để xác thực email theo RFC 5322/5321/6531 (gồm `user+tag`), IDN (IDNA2008), DNS MX (Null MX, fallback A/AAAA) và disposable domain, chạy nhiều replica với cache DNS L1 in-memory + L2 Redis.

**Architecture:** `email_validation.core` là pipeline async gồm các Step độc lập (normalize → syntax → idn → disposable → dns_mx), fail-fast, trả `ValidationResult` với status `valid|invalid|unknown`. DNS đi qua `DnsBackend` (dnspython trong production, fake trong test) → `MxResolver` (single-flight + `TieredCache`). `email_validation.api` là lớp FastAPI mỏng: auth API key, rate limit token bucket trên Redis, metrics Prometheus, log JSON.

**Tech Stack:** Python 3.12, uv, email-validator 2.x, idna, dnspython 2.x, redis-py (asyncio), FastAPI, uvicorn, pydantic v2, pydantic-settings, prometheus-client, httpx; test: pytest, pytest-asyncio, fakeredis[lua], testcontainers; ruff, mypy --strict; locust.

**Spec:** `docs/superpowers/specs/2026-09-24-email-validation-service-design.md`

## Global Constraints

- Python `>=3.12` (file `.python-version` = `3.12`); mọi lệnh chạy qua `uv run ...`.
- `email_validation.core` KHÔNG import từ `email_validation.api`.
- Mã `Reason` là hợp đồng API, giá trị chuỗi = tên: `SYNTAX_INVALID`, `TOO_LONG`, `IDN_INVALID`, `SMTPUTF8_NOT_ALLOWED`, `DISPOSABLE`, `DOMAIN_NOT_FOUND`, `DOMAIN_NO_MX`, `DOMAIN_NULL_MX`, `DNS_TEMPORARY_FAILURE`, cộng thêm `INTERNAL_ERROR` (làm rõ spec §5.3: ngoại lệ bất ngờ trong step → `unknown` + `INTERNAL_ERROR`).
- Giới hạn độ dài: địa chỉ ≤ 254 octet, local-part ≤ 64 octet (UTF-8), nhãn domain ≤ 63, domain ≤ 253 (đo trên dạng A-label).
- Lỗi DNS tạm thời → `unknown`, không bao giờ `invalid`.
- Cache key `mx:v1:{ascii_domain}`. TTL L1: OK/NULL_MX `min(ttl,300)`, NO_MX/NXDOMAIN 300, TEMP_FAIL 30; L2: OK/NULL_MX `clamp(ttl,60,86400)`, NO_MX/NXDOMAIN 300, TEMP_FAIL 30. L1 tối đa 100 000 mục. Timeout thao tác Redis 50 ms.
- DNS: timeout 2.0 s/truy vấn, lifetime 4.0 s, max_concurrency 500.
- Redis lỗi → không bao giờ làm request lỗi (cache và rate limit đều fail-open).
- API trả 200 cho mọi kết quả validation; 401 sai/thiếu key; 413 batch > 1000; 422 sai schema; 429 kèm `Retry-After`.
- Env prefix `EV_`. Rate limit mặc định 6 000/phút/key; batch tối đa 1 000, concurrency 100. Disposable reload mặc định 86 400 s.
- Không log email đầy đủ — chỉ `domain` và SHA-256 của input.
- Local-part giữ nguyên hoa/thường; chỉ domain lowercase.
- Commit message kết thúc bằng dòng `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>` (bỏ qua trong các khối lệnh bên dưới cho gọn — luôn thêm vào).

## Review Focus

1. **Input có khoảng trắng/hoa thường lẫn lộn** (`"  User@EXAMPLE.com "`) → `valid`, `normalized="User@example.com"`, DNS tra `example.com` (cache dùng chung giữa các biến thể). Test: Task 7 `test_whitespace_and_case_normalized`.
2. **Ký tự điều khiển / CRLF trong email** (`"a\r\nb@example.com"`, `"a\x00b@example.com"`) → `invalid` `SYNTAX_INVALID`, không crash, không tới DNS. Test: Task 2 bảng `INVALID_SYNTAX`.
3. **Sub-addressing biên** (`+tag@x`, `a+@x`, `a+b+c@x`, quoted `"a b+c"@x`) → quy tắc tách ổn định, không tạo tag rỗng. Test: Task 3 `test_split_subaddress`.
4. **Batch nhiều email cùng domain** → chỉ 1 truy vấn MX (single-flight), thứ tự kết quả giữ nguyên; batch rỗng → `{"results": []}`. Test: Task 7 `test_validate_many_single_flight`, Task 8 `test_batch_empty`.
5. **Redis chết giữa chừng** → `/v1/validate` vẫn 200, `/readyz` báo `redis: "degraded"`, rate limit bỏ qua. Test: Task 8 `test_validate_with_broken_redis`, `test_readyz_degraded`; Task 9 `test_rate_limiter_fail_open`.

---

## File Structure

```
.python-version                         # 3.12
pyproject.toml                          # deps, ruff, mypy, pytest config
.gitignore / .dockerignore
src/email_validation/
  __init__.py
  core/
    __init__.py                         # public exports
    models.py                           # Status, Reason, ValidationResult, ValidationContext
    policy.py                           # ValidationPolicy
    metrics.py                          # Prometheus metric objects
    pipeline.py                         # EmailValidator, default_steps
    steps/
      __init__.py
      base.py                           # Step, StepOutcome, CONTINUE, invalid(), unknown()
      normalize.py                      # NormalizeStep
      syntax.py                         # SyntaxStep (+ length/IDN/SMTPUTF8 pre-checks)
      idn.py                            # IdnStep, split_subaddress
      disposable.py                     # DisposableStep
      dns_mx.py                         # DnsMxStep
    dns/
      __init__.py
      backend.py                        # DnsBackend, DnsAnswer, DNS errors, DnspythonBackend
      resolver.py                       # MxResolver, MxOutcome, MxLookupResult
      cache.py                          # MemoryTTLCache, RedisCache, TieredCache, TTL rules
    disposable/
      __init__.py
      registry.py                       # DisposableRegistry, parse_domain_list, http_fetcher
      data/disposable_domains.txt
  api/
    __init__.py
    settings.py                         # Settings (EV_*)
    schemas.py                          # pydantic request/response
    state.py                            # AppState, build_state, get_state
    security.py                         # ApiKeyAuth, RateLimiter, hash_api_key
    observability.py                    # JsonFormatter, RequestIdMiddleware, setup_otel
    routes.py                           # endpoints
    app.py                              # create_app, lifespan
tests/
  __init__.py
  fakes.py                              # FakeDnsBackend, mx(), addr(), BrokenRedis
  core/...  api/...  integration/...  smoke/...
perf/locustfile.py
Dockerfile, docker-compose.yml, deploy/k8s/*.yaml, README.md
```

---

### Task 1: Project scaffold, models, policy

**Files:**
- Create: `.python-version`, `pyproject.toml`, `.gitignore`
- Create: `src/email_validation/__init__.py`, `src/email_validation/core/__init__.py`, `src/email_validation/core/models.py`, `src/email_validation/core/policy.py`
- Create: `tests/__init__.py`, `tests/core/__init__.py`
- Test: `tests/core/test_models.py`, `tests/core/test_policy.py`

**Interfaces:**
- Produces: `Status`, `Reason`, `ValidationResult`, `ValidationContext` (field names exactly as below; `ctx.to_result(status) -> ValidationResult`); `ValidationPolicy` (frozen dataclass, `with_overrides(**changes) -> ValidationPolicy` ignoring `None` values); `DisposableAction = Literal["reject", "flag", "off"]`.

- [ ] **Step 1: Create project config files**

`.python-version`:
```
3.12
```

`.gitignore`:
```
.venv/
__pycache__/
*.pyc
.pytest_cache/
.mypy_cache/
.ruff_cache/
dist/
build/
*.egg-info/
.env
```

`pyproject.toml`:
```toml
[project]
name = "email-validation"
version = "0.1.0"
description = "Enterprise email validation: RFC syntax, IDN, DNS MX, disposable domains"
requires-python = ">=3.12"
dependencies = [
    "email-validator>=2.2,<3",
    "idna>=3.7",
    "dnspython>=2.6,<3",
    "redis>=5.0",
    "fastapi>=0.115",
    "uvicorn[standard]>=0.30",
    "pydantic>=2.7,<3",
    "pydantic-settings>=2.3",
    "prometheus-client>=0.20",
    "httpx>=0.27",
]

[project.optional-dependencies]
otel = [
    "opentelemetry-sdk>=1.25",
    "opentelemetry-instrumentation-fastapi>=0.46b0",
    "opentelemetry-exporter-otlp-proto-http>=1.25",
]

[dependency-groups]
dev = [
    "pytest>=8.2",
    "pytest-asyncio>=0.24",
    "fakeredis[lua]>=2.23",
    "testcontainers[redis]>=4.7",
    "ruff>=0.6",
    "mypy>=1.11",
    "locust>=2.29",
]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/email_validation"]

[tool.pytest.ini_options]
asyncio_mode = "auto"
asyncio_default_fixture_loop_scope = "function"
testpaths = ["tests"]
pythonpath = ["."]
markers = [
    "network: uses real DNS (run with -m network)",
    "integration: requires Docker (run with -m integration)",
]
addopts = "-m 'not network and not integration'"

[tool.ruff]
line-length = 100
target-version = "py312"

[tool.ruff.lint]
select = ["E", "F", "I", "B", "UP", "ASYNC", "SIM"]

[tool.mypy]
strict = true
mypy_path = "src"
packages = ["email_validation"]

[[tool.mypy.overrides]]
module = ["opentelemetry.*", "fakeredis.*", "testcontainers.*", "locust.*"]
ignore_missing_imports = true
```

Create empty files: `src/email_validation/__init__.py`, `src/email_validation/core/__init__.py`, `tests/__init__.py`, `tests/core/__init__.py`.

- [ ] **Step 2: Install environment**

Run: `uv sync`
Expected: uv downloads Python 3.12 if needed, creates `.venv`, writes `uv.lock`, exits 0.

- [ ] **Step 3: Write failing tests**

`tests/core/test_models.py`:
```python
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
```

`tests/core/test_policy.py`:
```python
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
```

- [ ] **Step 4: Run tests to verify they fail**

Run: `uv run pytest tests/core -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'email_validation.core.models'`

- [ ] **Step 5: Implement models and policy**

`src/email_validation/core/models.py`:
```python
from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from email_validator import ValidatedEmail


class Status(StrEnum):
    VALID = "valid"
    INVALID = "invalid"
    UNKNOWN = "unknown"


class Reason(StrEnum):
    SYNTAX_INVALID = "SYNTAX_INVALID"
    TOO_LONG = "TOO_LONG"
    IDN_INVALID = "IDN_INVALID"
    SMTPUTF8_NOT_ALLOWED = "SMTPUTF8_NOT_ALLOWED"
    DISPOSABLE = "DISPOSABLE"
    DOMAIN_NOT_FOUND = "DOMAIN_NOT_FOUND"
    DOMAIN_NO_MX = "DOMAIN_NO_MX"
    DOMAIN_NULL_MX = "DOMAIN_NULL_MX"
    DNS_TEMPORARY_FAILURE = "DNS_TEMPORARY_FAILURE"
    INTERNAL_ERROR = "INTERNAL_ERROR"


@dataclass(frozen=True)
class ValidationResult:
    input: str
    status: Status
    reasons: tuple[Reason, ...]
    normalized: str | None
    ascii_email: str | None
    local_part: str | None
    base_local_part: str | None
    tag: str | None
    domain: str | None
    ascii_domain: str | None
    mx_hosts: tuple[str, ...]
    implicit_mx: bool
    is_disposable: bool


@dataclass
class ValidationContext:
    input: str
    email: str = ""
    parsed: ValidatedEmail | None = None
    is_domain_literal: bool = False
    normalized: str | None = None
    ascii_email: str | None = None
    local_part: str | None = None
    base_local_part: str | None = None
    tag: str | None = None
    domain: str | None = None
    ascii_domain: str | None = None
    mx_hosts: tuple[str, ...] = ()
    implicit_mx: bool = False
    is_disposable: bool = False
    reasons: list[Reason] = field(default_factory=list)

    def to_result(self, status: Status) -> ValidationResult:
        return ValidationResult(
            input=self.input,
            status=status,
            reasons=tuple(self.reasons),
            normalized=self.normalized,
            ascii_email=self.ascii_email,
            local_part=self.local_part,
            base_local_part=self.base_local_part,
            tag=self.tag,
            domain=self.domain,
            ascii_domain=self.ascii_domain,
            mx_hosts=self.mx_hosts,
            implicit_mx=self.implicit_mx,
            is_disposable=self.is_disposable,
        )
```

`src/email_validation/core/policy.py`:
```python
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
```

- [ ] **Step 6: Run tests, lint, types**

Run: `uv run pytest tests/core -v`
Expected: PASS (6 tests)

Run: `uv run ruff check . && uv run ruff format --check . && uv run mypy`
Expected: no errors (run `uv run ruff format .` first if format check fails)

- [ ] **Step 7: Commit**

```bash
git add .python-version pyproject.toml uv.lock .gitignore src tests
git commit -m "feat: scaffold project with core models and validation policy"
```

---

### Task 2: Step base, NormalizeStep, SyntaxStep

**Files:**
- Create: `src/email_validation/core/steps/__init__.py` (empty), `base.py`, `normalize.py`, `syntax.py`
- Create: `tests/core/steps/__init__.py` (empty)
- Test: `tests/core/steps/test_normalize.py`, `tests/core/steps/test_syntax.py`

**Interfaces:**
- Consumes: `ValidationContext`, `Reason`, `Status` (Task 1), `ValidationPolicy` (Task 1).
- Produces:
  - `StepOutcome(stop: bool = False, status: Status | None = None, reason: Reason | None = None)` (frozen), `CONTINUE = StepOutcome()`, `invalid(reason) -> StepOutcome`, `unknown(reason) -> StepOutcome`.
  - `Step` Protocol: `name: str`; `async def run(self, ctx: ValidationContext, policy: ValidationPolicy) -> StepOutcome`.
  - `NormalizeStep` sets `ctx.email` (stripped, NFC).
  - `SyntaxStep` reads `ctx.email`, sets `ctx.parsed` (`email_validator.ValidatedEmail`) and `ctx.is_domain_literal`.

- [ ] **Step 1: Write failing tests**

`tests/core/steps/test_normalize.py`:
```python
from email_validation.core.models import Reason, Status, ValidationContext
from email_validation.core.policy import ValidationPolicy
from email_validation.core.steps.base import CONTINUE
from email_validation.core.steps.normalize import NormalizeStep


async def run(value: str) -> tuple[object, ValidationContext]:
    ctx = ValidationContext(input=value)
    outcome = await NormalizeStep().run(ctx, ValidationPolicy())
    return outcome, ctx


async def test_strips_whitespace_and_newlines() -> None:
    outcome, ctx = await run("  User@Example.com \n")
    assert outcome == CONTINUE
    assert ctx.email == "User@Example.com"


async def test_applies_nfc() -> None:
    _, ctx = await run("üser@example.com")
    assert ctx.email == "üser@example.com"


async def test_empty_is_invalid() -> None:
    for value in ("", "   ", "\t\n"):
        outcome, _ = await run(value)
        assert outcome.stop is True
        assert outcome.status is Status.INVALID
        assert outcome.reason is Reason.SYNTAX_INVALID
```

`tests/core/steps/test_syntax.py`:
```python
from typing import Any

import pytest

from email_validation.core.models import Reason, Status, ValidationContext
from email_validation.core.policy import ValidationPolicy
from email_validation.core.steps.base import CONTINUE, StepOutcome
from email_validation.core.steps.syntax import SyntaxStep


async def run(email: str, **policy: Any) -> tuple[StepOutcome, ValidationContext]:
    ctx = ValidationContext(input=email, email=email)
    outcome = await SyntaxStep().run(ctx, ValidationPolicy(**policy))
    return outcome, ctx


VALID = [
    "user@example.com",
    "user+tag@example.com",
    "a.b-c_d@sub.example.co.uk",
    "User+News@Bücher.de",
    "user@例え.jp",
    "用户@例え.jp",
    "user@xn--bcher-kva.de",
]

INVALID_SYNTAX = [
    "plainaddress",
    "@example.com",
    "a@",
    "a..b@example.com",
    ".a@example.com",
    "a.@example.com",
    "a@x",
    "a@-x.com",
    "a b@example.com",
    "a\r\nb@example.com",
    "a\x00b@example.com",
    "a@@example.com",
]


@pytest.mark.parametrize("email", VALID)
async def test_valid(email: str) -> None:
    outcome, ctx = await run(email)
    assert outcome == CONTINUE
    assert ctx.parsed is not None
    assert ctx.is_domain_literal is False


@pytest.mark.parametrize("email", INVALID_SYNTAX)
async def test_invalid_syntax(email: str) -> None:
    outcome, ctx = await run(email)
    assert outcome.stop is True
    assert outcome.status is Status.INVALID
    assert outcome.reason is Reason.SYNTAX_INVALID
    assert ctx.parsed is None


async def test_quoted_local_depends_on_policy() -> None:
    outcome, _ = await run('"john doe"@example.com')
    assert outcome.reason is Reason.SYNTAX_INVALID
    outcome, ctx = await run('"john doe"@example.com', allow_quoted_local=True)
    assert outcome == CONTINUE
    assert ctx.parsed is not None


async def test_domain_literal_depends_on_policy() -> None:
    outcome, _ = await run("user@[192.0.2.1]")
    assert outcome.reason is Reason.SYNTAX_INVALID
    outcome, ctx = await run("user@[192.0.2.1]", allow_domain_literal=True)
    assert outcome == CONTINUE
    assert ctx.is_domain_literal is True


@pytest.mark.parametrize(
    "email",
    [
        "a" * 65 + "@example.com",
        "user@" + "b" * 64 + ".com",
        "a" * 64 + "@" + ".".join(["b" * 63] * 3) + ".com",
    ],
)
async def test_too_long(email: str) -> None:
    outcome, _ = await run(email)
    assert outcome.status is Status.INVALID
    assert outcome.reason is Reason.TOO_LONG


@pytest.mark.parametrize("email", ["user@☃.net", "user@😀.com"])
async def test_idn_invalid(email: str) -> None:
    outcome, _ = await run(email)
    assert outcome.status is Status.INVALID
    assert outcome.reason is Reason.IDN_INVALID


async def test_smtputf8_not_allowed() -> None:
    outcome, _ = await run("用户@example.com", allow_smtputf8=False)
    assert outcome.status is Status.INVALID
    assert outcome.reason is Reason.SMTPUTF8_NOT_ALLOWED
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/core/steps -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'email_validation.core.steps'`

- [ ] **Step 3: Implement base, normalize, syntax**

`src/email_validation/core/steps/base.py`:
```python
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
```

`src/email_validation/core/steps/normalize.py`:
```python
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
```

`src/email_validation/core/steps/syntax.py`:
```python
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
        ctx.is_domain_literal = parsed.domain_address is not None
        return CONTINUE
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/core/steps -v`
Expected: PASS. If a single parametrized case fails because email-validator's behavior differs from the table (e.g. a version accepts a case), check `validate_email(<case>, check_deliverability=False)` in `uv run python`, and fix the table only if the library behavior is RFC-correct; otherwise add an explicit pre-check in `SyntaxStep`.

Run: `uv run ruff check . && uv run mypy`
Expected: no errors

- [ ] **Step 5: Commit**

```bash
git add src/email_validation/core/steps tests/core/steps
git commit -m "feat(core): add normalize and RFC syntax steps with length, IDN and SMTPUTF8 checks"
```

---

### Task 3: IdnStep and sub-addressing

**Files:**
- Create: `src/email_validation/core/steps/idn.py`
- Test: `tests/core/steps/test_idn.py`

**Interfaces:**
- Consumes: `ctx.parsed` from `SyntaxStep` (Task 2); `NormalizeStep`, `SyntaxStep`.
- Produces: `IdnStep` fills `ctx.normalized`, `ctx.local_part`, `ctx.base_local_part`, `ctx.tag`, `ctx.domain`, `ctx.ascii_domain`, `ctx.ascii_email`. `split_subaddress(local: str, separator: str | None) -> tuple[str, str | None]`.

- [ ] **Step 1: Write failing tests**

`tests/core/steps/test_idn.py`:
```python
from typing import Any

import pytest

from email_validation.core.models import ValidationContext
from email_validation.core.policy import ValidationPolicy
from email_validation.core.steps.base import CONTINUE
from email_validation.core.steps.idn import IdnStep, split_subaddress
from email_validation.core.steps.normalize import NormalizeStep
from email_validation.core.steps.syntax import SyntaxStep


async def run(email: str, **policy_kw: Any) -> ValidationContext:
    policy = ValidationPolicy(**policy_kw)
    ctx = ValidationContext(input=email)
    for step in (NormalizeStep(), SyntaxStep(), IdnStep()):
        outcome = await step.run(ctx, policy)
        assert outcome == CONTINUE, f"{step.name} stopped: {outcome}"
    return ctx


async def test_idn_domain_with_tag() -> None:
    ctx = await run("User+News@Bücher.de")
    assert ctx.normalized == "User+News@bücher.de"
    assert ctx.local_part == "User+News"
    assert ctx.base_local_part == "User"
    assert ctx.tag == "News"
    assert ctx.domain == "bücher.de"
    assert ctx.ascii_domain == "xn--bcher-kva.de"
    assert ctx.ascii_email == "User+News@xn--bcher-kva.de"


async def test_japanese_domain() -> None:
    ctx = await run("user@例え.jp")
    assert ctx.domain == "例え.jp"
    assert ctx.ascii_domain is not None
    assert ctx.ascii_domain.startswith("xn--")
    assert ctx.ascii_domain.endswith(".jp")


async def test_punycode_input_keeps_ascii_domain() -> None:
    ctx = await run("user@xn--bcher-kva.de")
    assert ctx.ascii_domain == "xn--bcher-kva.de"


async def test_unicode_local_part_has_no_ascii_email() -> None:
    ctx = await run("用户@例え.jp")
    assert ctx.local_part == "用户"
    assert ctx.ascii_email is None


async def test_domain_literal() -> None:
    ctx = await run("user@[192.0.2.1]", allow_domain_literal=True)
    assert ctx.domain == "[192.0.2.1]"
    assert ctx.is_domain_literal is True


async def test_custom_separator() -> None:
    ctx = await run("john-news@example.com", subaddress_separator="-")
    assert (ctx.base_local_part, ctx.tag) == ("john", "news")


async def test_separator_disabled() -> None:
    ctx = await run("john+news@example.com", subaddress_separator=None)
    assert (ctx.base_local_part, ctx.tag) == ("john+news", None)


async def test_quoted_local_not_split() -> None:
    ctx = await run('"a b+c"@example.com', allow_quoted_local=True)
    assert ctx.tag is None
    assert ctx.base_local_part == ctx.local_part


@pytest.mark.parametrize(
    ("local", "expected"),
    [
        ("user", ("user", None)),
        ("user+tag", ("user", "tag")),
        ("a+b+c", ("a", "b+c")),
        ("+tag", ("+tag", None)),
        ("a+", ("a", None)),
        ('"a b+c"', ('"a b+c"', None)),
    ],
)
def test_split_subaddress(local: str, expected: tuple[str, str | None]) -> None:
    assert split_subaddress(local, "+") == expected


def test_split_subaddress_none_separator() -> None:
    assert split_subaddress("a+b", None) == ("a+b", None)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/core/steps/test_idn.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'email_validation.core.steps.idn'`

- [ ] **Step 3: Implement IdnStep**

`src/email_validation/core/steps/idn.py`:
```python
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
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/core/steps -v && uv run mypy`
Expected: PASS, no type errors

- [ ] **Step 5: Commit**

```bash
git add src/email_validation/core/steps/idn.py tests/core/steps/test_idn.py
git commit -m "feat(core): add IDN step with A-label/U-label fields and sub-address split"
```

---

### Task 4: DNS backend, metrics, MxResolver

**Files:**
- Create: `src/email_validation/core/metrics.py`
- Create: `src/email_validation/core/dns/__init__.py` (empty), `backend.py`, `resolver.py`
- Create: `tests/fakes.py`, `tests/core/dns/__init__.py` (empty)
- Test: `tests/core/dns/test_backend.py`, `tests/core/dns/test_resolver.py`

**Interfaces:**
- Produces:
  - `DnsAnswer(ttl: int, mx: tuple[tuple[int, str], ...] = (), addresses: tuple[str, ...] = ())` — MX exchange is lowercase without trailing dot, `"."` for the root (Null MX).
  - Errors: `DnsError`, `NXDomainError`, `NoAnswerError`, `TemporaryDnsError` (all subclass `DnsError`).
  - `DnsBackend` Protocol: `async def query(self, name: str, rdtype: RdType) -> DnsAnswer` where `RdType = Literal["MX", "A", "AAAA"]`.
  - `DnspythonBackend(nameservers: Sequence[str] = (), timeout: float = 2.0, lifetime: float = 4.0)`.
  - `MxOutcome` (`OK`, `NULL_MX`, `NO_MX`, `NXDOMAIN`, `TEMP_FAIL`), `MxLookupResult(outcome, hosts: tuple[str, ...], implicit: bool, ttl: int)`.
  - `MxResolver(backend: DnsBackend, *, max_concurrency: int = 500)`, `async lookup(ascii_domain: str) -> MxLookupResult`. (Task 5 adds a `cache` keyword.)
  - `normalize_domain(domain: str) -> str` (lowercase, strip trailing dot).
  - Metrics in `email_validation.core.metrics`: `VALIDATIONS_TOTAL{status,reason}`, `DNS_LOOKUP_SECONDS`, `DNS_LOOKUPS_TOTAL{outcome}`, `CACHE_HITS_TOTAL{tier}`, `CACHE_ERRORS_TOTAL{op}`, `RATE_LIMIT_REJECTIONS_TOTAL`, `RATE_LIMIT_ERRORS_TOTAL`.
  - `tests/fakes.py`: `FakeDnsBackend(responses, delay=0.0)` with `.calls: list[tuple[str, str]]`, `.max_in_flight: int`; helpers `mx(*records, ttl=3600)`, `addr(*ips, ttl=300)`.

- [ ] **Step 1: Write metrics module and test fakes**

`src/email_validation/core/metrics.py`:
```python
from prometheus_client import Counter, Histogram

VALIDATIONS_TOTAL = Counter(
    "validations_total", "Email validations by final status and first reason", ["status", "reason"]
)
DNS_LOOKUP_SECONDS = Histogram(
    "dns_lookup_seconds",
    "Uncached MX lookup latency",
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 4.0, 8.0),
)
DNS_LOOKUPS_TOTAL = Counter("dns_lookups_total", "Uncached MX lookups by outcome", ["outcome"])
CACHE_HITS_TOTAL = Counter("cache_hits_total", "MX cache lookups by tier (l1, l2, miss)", ["tier"])
CACHE_ERRORS_TOTAL = Counter("cache_errors_total", "Redis cache errors by operation", ["op"])
RATE_LIMIT_REJECTIONS_TOTAL = Counter("rate_limit_rejections_total", "Requests rejected (429)")
RATE_LIMIT_ERRORS_TOTAL = Counter("rate_limit_errors_total", "Rate limiter backend errors")
```

`tests/fakes.py`:
```python
from __future__ import annotations

import asyncio

from email_validation.core.dns.backend import DnsAnswer, DnsError, NXDomainError

Response = DnsAnswer | DnsError | type[DnsError]


def mx(*records: tuple[int, str], ttl: int = 3600) -> DnsAnswer:
    return DnsAnswer(ttl=ttl, mx=tuple(records))


def addr(*ips: str, ttl: int = 300) -> DnsAnswer:
    return DnsAnswer(ttl=ttl, addresses=tuple(ips))


class FakeDnsBackend:
    """Programmable DnsBackend. Unknown (name, rdtype) pairs raise NXDomainError."""

    def __init__(self, responses: dict[tuple[str, str], Response] | None = None,
                 delay: float = 0.0) -> None:
        self.responses: dict[tuple[str, str], Response] = dict(responses or {})
        self.delay = delay
        self.calls: list[tuple[str, str]] = []
        self.in_flight = 0
        self.max_in_flight = 0

    async def query(self, name: str, rdtype: str) -> DnsAnswer:
        self.calls.append((name, rdtype))
        self.in_flight += 1
        self.max_in_flight = max(self.max_in_flight, self.in_flight)
        try:
            if self.delay:
                await asyncio.sleep(self.delay)
            response = self.responses.get((name, rdtype), NXDomainError)
            if isinstance(response, DnsAnswer):
                return response
            if isinstance(response, type):
                raise response(name)
            raise response
        finally:
            self.in_flight -= 1
```

- [ ] **Step 2: Write failing tests**

`tests/core/dns/test_resolver.py`:
```python
import asyncio

from prometheus_client import REGISTRY

from email_validation.core.dns.backend import NoAnswerError, TemporaryDnsError
from email_validation.core.dns.resolver import MxOutcome, MxResolver, normalize_domain
from tests.fakes import FakeDnsBackend, addr, mx


async def lookup(responses: dict, domain: str = "example.com"):  # type: ignore[no-untyped-def]
    backend = FakeDnsBackend(responses)
    return await MxResolver(backend).lookup(domain), backend


async def test_mx_sorted_by_preference() -> None:
    result, _ = await lookup(
        {("example.com", "MX"): mx((20, "mx2.example.com"), (10, "mx1.example.com"), ttl=1800)}
    )
    assert result.outcome is MxOutcome.OK
    assert result.hosts == ("mx1.example.com", "mx2.example.com")
    assert result.implicit is False
    assert result.ttl == 1800


async def test_duplicate_hosts_removed() -> None:
    result, _ = await lookup(
        {("example.com", "MX"): mx((10, "mx.example.com"), (20, "mx.example.com"))}
    )
    assert result.hosts == ("mx.example.com",)


async def test_null_mx() -> None:
    result, _ = await lookup({("example.com", "MX"): mx((0, "."))})
    assert result.outcome is MxOutcome.NULL_MX
    assert result.hosts == ()


async def test_null_mx_mixed_with_real_mx_uses_real() -> None:
    result, _ = await lookup({("example.com", "MX"): mx((0, "."), (10, "mx.example.com"))})
    assert result.outcome is MxOutcome.OK
    assert result.hosts == ("mx.example.com",)


async def test_no_mx_falls_back_to_a() -> None:
    result, backend = await lookup(
        {
            ("example.com", "MX"): NoAnswerError,
            ("example.com", "A"): addr("192.0.2.1", ttl=120),
            ("example.com", "AAAA"): NoAnswerError,
        }
    )
    assert result.outcome is MxOutcome.OK
    assert result.hosts == ("example.com",)
    assert result.implicit is True
    assert result.ttl == 120
    assert ("example.com", "A") in backend.calls and ("example.com", "AAAA") in backend.calls


async def test_no_mx_falls_back_to_aaaa_only() -> None:
    result, _ = await lookup(
        {
            ("example.com", "MX"): NoAnswerError,
            ("example.com", "A"): NoAnswerError,
            ("example.com", "AAAA"): addr("2001:db8::1"),
        }
    )
    assert result.outcome is MxOutcome.OK
    assert result.implicit is True


async def test_no_mx_no_address() -> None:
    result, _ = await lookup(
        {
            ("example.com", "MX"): NoAnswerError,
            ("example.com", "A"): NoAnswerError,
            ("example.com", "AAAA"): NoAnswerError,
        }
    )
    assert result.outcome is MxOutcome.NO_MX


async def test_empty_mx_answer_treated_as_no_answer() -> None:
    result, _ = await lookup(
        {("example.com", "MX"): mx(), ("example.com", "A"): addr("192.0.2.1")}
    )
    assert result.outcome is MxOutcome.OK
    assert result.implicit is True


async def test_nxdomain() -> None:
    result, _ = await lookup({})
    assert result.outcome is MxOutcome.NXDOMAIN


async def test_temporary_failure_on_mx() -> None:
    result, _ = await lookup({("example.com", "MX"): TemporaryDnsError})
    assert result.outcome is MxOutcome.TEMP_FAIL


async def test_temporary_failure_in_fallback() -> None:
    result, _ = await lookup(
        {
            ("example.com", "MX"): NoAnswerError,
            ("example.com", "A"): TemporaryDnsError,
            ("example.com", "AAAA"): NoAnswerError,
        }
    )
    assert result.outcome is MxOutcome.TEMP_FAIL


async def test_domain_is_normalized_before_query() -> None:
    _, backend = await lookup({("example.com", "MX"): mx((10, "mx.example.com"))}, "Example.COM.")
    assert backend.calls == [("example.com", "MX")]
    assert normalize_domain("Example.COM.") == "example.com"


async def test_concurrency_is_bounded() -> None:
    responses = {(f"d{i}.com", "MX"): mx((10, "mx.x.com")) for i in range(10)}
    backend = FakeDnsBackend(responses, delay=0.02)
    resolver = MxResolver(backend, max_concurrency=2)
    await asyncio.gather(*(resolver.lookup(f"d{i}.com") for i in range(10)))
    assert backend.max_in_flight <= 2


async def test_lookup_metric_incremented() -> None:
    before = REGISTRY.get_sample_value("dns_lookups_total", {"outcome": "nxdomain"}) or 0.0
    await lookup({})
    after = REGISTRY.get_sample_value("dns_lookups_total", {"outcome": "nxdomain"})
    assert after == before + 1
```

`tests/core/dns/test_backend.py`:
```python
import dns.exception
import dns.resolver
import pytest

from email_validation.core.dns.backend import (
    DnspythonBackend,
    NoAnswerError,
    NXDomainError,
    TemporaryDnsError,
)


@pytest.mark.parametrize(
    ("raised", "expected"),
    [
        (dns.resolver.NXDOMAIN(), NXDomainError),
        (dns.resolver.NoAnswer(), NoAnswerError),
        (dns.exception.Timeout(), TemporaryDnsError),
        (dns.resolver.NoNameservers(), TemporaryDnsError),
    ],
)
async def test_exception_mapping(
    monkeypatch: pytest.MonkeyPatch, raised: Exception, expected: type[Exception]
) -> None:
    backend = DnspythonBackend(nameservers=["192.0.2.53"])

    async def fake_resolve(*args: object, **kwargs: object) -> None:
        raise raised

    monkeypatch.setattr(backend._resolver, "resolve", fake_resolve)
    with pytest.raises(expected):
        await backend.query("example.com", "MX")


def test_configuration_applied() -> None:
    backend = DnspythonBackend(nameservers=["192.0.2.53"], timeout=1.5, lifetime=3.0)
    assert len(backend._resolver.nameservers) == 1
    assert backend._resolver.timeout == 1.5
    assert backend._resolver.lifetime == 3.0
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `uv run pytest tests/core/dns -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'email_validation.core.dns'`

- [ ] **Step 4: Implement backend**

`src/email_validation/core/dns/backend.py`:
```python
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal, Protocol

import dns.asyncresolver
import dns.exception
import dns.name
import dns.resolver

RdType = Literal["MX", "A", "AAAA"]


@dataclass(frozen=True)
class DnsAnswer:
    ttl: int
    mx: tuple[tuple[int, str], ...] = ()
    addresses: tuple[str, ...] = ()


class DnsError(Exception):
    pass


class NXDomainError(DnsError):
    """The domain does not exist."""


class NoAnswerError(DnsError):
    """The domain exists but has no records of the requested type."""


class TemporaryDnsError(DnsError):
    """Timeout, SERVFAIL, no reachable nameservers, or any other transient failure."""


class DnsBackend(Protocol):
    async def query(self, name: str, rdtype: RdType) -> DnsAnswer: ...


class DnspythonBackend:
    def __init__(
        self, nameservers: Sequence[str] = (), timeout: float = 2.0, lifetime: float = 4.0
    ) -> None:
        self._resolver = dns.asyncresolver.Resolver(configure=not nameservers)
        if nameservers:
            self._resolver.nameservers = list(nameservers)
        self._resolver.timeout = timeout
        self._resolver.lifetime = lifetime

    async def query(self, name: str, rdtype: RdType) -> DnsAnswer:
        try:
            answer = await self._resolver.resolve(name, rdtype, search=False)
        except dns.resolver.NXDOMAIN as exc:
            raise NXDomainError(name) from exc
        except dns.resolver.NoAnswer as exc:
            raise NoAnswerError(name) from exc
        except dns.exception.DNSException as exc:
            raise TemporaryDnsError(f"{name} {rdtype}: {exc}") from exc

        ttl = answer.rrset.ttl if answer.rrset is not None else 0
        if rdtype == "MX":
            records = tuple(
                (
                    int(rdata.preference),
                    "."
                    if rdata.exchange == dns.name.root
                    else rdata.exchange.to_text(omit_final_dot=True).lower(),
                )
                for rdata in answer
            )
            return DnsAnswer(ttl=ttl, mx=records)
        return DnsAnswer(ttl=ttl, addresses=tuple(str(rdata.address) for rdata in answer))
```

- [ ] **Step 5: Implement resolver**

`src/email_validation/core/dns/resolver.py`:
```python
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from enum import StrEnum

from email_validation.core.dns.backend import (
    DnsAnswer,
    DnsBackend,
    DnsError,
    NoAnswerError,
    NXDomainError,
    TemporaryDnsError,
)
from email_validation.core.metrics import DNS_LOOKUP_SECONDS, DNS_LOOKUPS_TOTAL


class MxOutcome(StrEnum):
    OK = "ok"
    NULL_MX = "null_mx"
    NO_MX = "no_mx"
    NXDOMAIN = "nxdomain"
    TEMP_FAIL = "temp_fail"


@dataclass(frozen=True)
class MxLookupResult:
    outcome: MxOutcome
    hosts: tuple[str, ...] = ()
    implicit: bool = False
    ttl: int = 0


def normalize_domain(domain: str) -> str:
    return domain.lower().rstrip(".")


class MxResolver:
    def __init__(self, backend: DnsBackend, *, max_concurrency: int = 500) -> None:
        self._backend = backend
        self._semaphore = asyncio.Semaphore(max_concurrency)

    async def lookup(self, ascii_domain: str) -> MxLookupResult:
        return await self._resolve(normalize_domain(ascii_domain))

    async def _resolve(self, domain: str) -> MxLookupResult:
        start = time.perf_counter()
        try:
            async with self._semaphore:
                result = await self._resolve_uncached(domain)
        finally:
            DNS_LOOKUP_SECONDS.observe(time.perf_counter() - start)
        DNS_LOOKUPS_TOTAL.labels(outcome=result.outcome.value).inc()
        return result

    async def _resolve_uncached(self, domain: str) -> MxLookupResult:
        try:
            answer = await self._backend.query(domain, "MX")
        except NXDomainError:
            return MxLookupResult(MxOutcome.NXDOMAIN)
        except NoAnswerError:
            return await self._fallback(domain)
        except TemporaryDnsError:
            return MxLookupResult(MxOutcome.TEMP_FAIL)

        if not answer.mx:
            return await self._fallback(domain)
        real = sorted(rec for rec in answer.mx if rec[1] != ".")  # by (preference, host)
        if not real:
            return MxLookupResult(MxOutcome.NULL_MX, ttl=answer.ttl)
        hosts = tuple(dict.fromkeys(host for _, host in real))
        return MxLookupResult(MxOutcome.OK, hosts=hosts, ttl=answer.ttl)

    async def _fallback(self, domain: str) -> MxLookupResult:
        """RFC 5321 §5.1: no MX -> the domain itself is the implicit MX if it has A/AAAA."""
        results = await asyncio.gather(
            self._backend.query(domain, "A"),
            self._backend.query(domain, "AAAA"),
            return_exceptions=True,
        )
        for item in results:
            if isinstance(item, BaseException) and not isinstance(item, DnsError):
                raise item
        answers = [r for r in results if isinstance(r, DnsAnswer) and r.addresses]
        if answers:
            ttl = min(a.ttl for a in answers)
            return MxLookupResult(MxOutcome.OK, hosts=(domain,), implicit=True, ttl=ttl)
        if any(isinstance(r, TemporaryDnsError) for r in results):
            return MxLookupResult(MxOutcome.TEMP_FAIL)
        if any(isinstance(r, NXDomainError) for r in results):
            return MxLookupResult(MxOutcome.NXDOMAIN)
        return MxLookupResult(MxOutcome.NO_MX)
```

- [ ] **Step 6: Run tests**

Run: `uv run pytest tests/core/dns -v && uv run ruff check . && uv run mypy`
Expected: PASS, no lint/type errors

- [ ] **Step 7: Commit**

```bash
git add src/email_validation/core/metrics.py src/email_validation/core/dns tests/fakes.py tests/core/dns
git commit -m "feat(core): add DNS backend abstraction and MX resolver with Null MX and A/AAAA fallback"
```

---

### Task 5: Two-tier cache and single-flight in MxResolver

**Files:**
- Create: `src/email_validation/core/dns/cache.py`
- Modify: `src/email_validation/core/dns/resolver.py` (constructor + `lookup`)
- Modify: `tests/fakes.py` (add `BrokenRedis`)
- Create: `tests/integration/__init__.py` (empty), `tests/integration/conftest.py`
- Test: `tests/core/dns/test_cache.py`, `tests/core/dns/test_resolver_cache.py`, `tests/integration/test_redis_cache.py`

**Interfaces:**
- Consumes: `MxLookupResult`, `MxOutcome`, `MxResolver` (Task 4); metrics `CACHE_HITS_TOTAL`, `CACHE_ERRORS_TOTAL`.
- Produces:
  - `Cache` Protocol: `async get(key) -> MxLookupResult | None`, `async set(key, value, ttl: int) -> None`.
  - `MemoryTTLCache(maxsize: int = 100_000, clock: Callable[[], float] = time.monotonic)`.
  - `RedisCache(client: redis.asyncio.Redis, op_timeout: float = 0.05)`.
  - `TieredCache(l1: Cache, l2: Cache | None = None)` with `async get(key)`, `async set(key, value)` (computes per-tier TTL).
  - `l1_ttl(result) -> int`, `l2_ttl(result) -> int`, `encode_result(result) -> str`, `decode_result(raw: str | bytes) -> MxLookupResult`, `cache_key(domain) -> str` (`"mx:v1:" + domain`).
  - `MxResolver(backend, *, cache: TieredCache | None = None, max_concurrency: int = 500)`.
  - `tests/fakes.py::BrokenRedis` — every async method raises `redis.exceptions.ConnectionError`.
  - `tests/integration/conftest.py` fixtures: `redis_url` (session), `redis_client` (function; flushed).

- [ ] **Step 1: Add BrokenRedis to fakes**

Append to `tests/fakes.py`:
```python
import redis.exceptions


class BrokenRedis:
    """Stands in for redis.asyncio.Redis when the server is unreachable."""

    async def _fail(self, *args: object, **kwargs: object) -> None:
        raise redis.exceptions.ConnectionError("redis is down")

    get = set = ping = eval = evalsha = _fail

    async def aclose(self) -> None:
        return None
```
(Move `import redis.exceptions` to the top import block of the file.)

- [ ] **Step 2: Write failing cache tests**

`tests/core/dns/test_cache.py`:
```python
import pytest
from fakeredis import FakeAsyncRedis
from prometheus_client import REGISTRY

from email_validation.core.dns.cache import (
    MemoryTTLCache,
    RedisCache,
    TieredCache,
    cache_key,
    decode_result,
    encode_result,
    l1_ttl,
    l2_ttl,
)
from email_validation.core.dns.resolver import MxLookupResult, MxOutcome
from tests.fakes import BrokenRedis

OK = MxLookupResult(MxOutcome.OK, hosts=("mx.example.com",), ttl=3600)


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class RecordingCache:
    def __init__(self) -> None:
        self.data: dict[str, MxLookupResult] = {}
        self.ttls: dict[str, int] = {}

    async def get(self, key: str) -> MxLookupResult | None:
        return self.data.get(key)

    async def set(self, key: str, value: MxLookupResult, ttl: int) -> None:
        self.data[key] = value
        self.ttls[key] = ttl


def sample(name: str, labels: dict[str, str]) -> float:
    return REGISTRY.get_sample_value(name, labels) or 0.0


def test_cache_key() -> None:
    assert cache_key("example.com") == "mx:v1:example.com"


@pytest.mark.parametrize(
    ("result", "expected_l1", "expected_l2"),
    [
        (MxLookupResult(MxOutcome.OK, ttl=3600), 300, 3600),
        (MxLookupResult(MxOutcome.OK, ttl=30), 30, 60),
        (MxLookupResult(MxOutcome.OK, ttl=0), 1, 60),
        (MxLookupResult(MxOutcome.OK, ttl=999_999), 300, 86400),
        (MxLookupResult(MxOutcome.NULL_MX, ttl=7200), 300, 7200),
        (MxLookupResult(MxOutcome.NO_MX), 300, 300),
        (MxLookupResult(MxOutcome.NXDOMAIN), 300, 300),
        (MxLookupResult(MxOutcome.TEMP_FAIL), 30, 30),
    ],
)
def test_ttl_rules(result: MxLookupResult, expected_l1: int, expected_l2: int) -> None:
    assert l1_ttl(result) == expected_l1
    assert l2_ttl(result) == expected_l2


def test_encode_decode_roundtrip() -> None:
    implicit = MxLookupResult(MxOutcome.OK, hosts=("example.com",), implicit=True, ttl=120)
    assert decode_result(encode_result(implicit)) == implicit
    assert decode_result(encode_result(OK).encode()) == OK


async def test_memory_cache_expiry() -> None:
    clock = FakeClock()
    cache = MemoryTTLCache(maxsize=10, clock=clock)
    await cache.set("k", OK, ttl=10)
    assert await cache.get("k") == OK
    clock.now += 10.01
    assert await cache.get("k") is None


async def test_memory_cache_lru_eviction() -> None:
    cache = MemoryTTLCache(maxsize=2)
    await cache.set("a", OK, 60)
    await cache.set("b", OK, 60)
    await cache.get("a")  # a becomes most recent
    await cache.set("c", OK, 60)
    assert await cache.get("a") == OK
    assert await cache.get("b") is None
    assert await cache.get("c") == OK


async def test_memory_cache_ignores_non_positive_ttl() -> None:
    cache = MemoryTTLCache()
    await cache.set("k", OK, 0)
    assert await cache.get("k") is None


async def test_redis_cache_roundtrip_and_ttl() -> None:
    client = FakeAsyncRedis()
    cache = RedisCache(client)
    await cache.set("mx:v1:example.com", OK, ttl=600)
    assert await cache.get("mx:v1:example.com") == OK
    assert 590 <= await client.ttl("mx:v1:example.com") <= 600


async def test_redis_cache_corrupt_value_is_miss() -> None:
    client = FakeAsyncRedis()
    await client.set("mx:v1:bad.com", b"not json")
    assert await RedisCache(client).get("mx:v1:bad.com") is None


async def test_redis_cache_fail_open() -> None:
    before = sample("cache_errors_total", {"op": "get"})
    cache = RedisCache(BrokenRedis())  # type: ignore[arg-type]
    assert await cache.get("k") is None
    await cache.set("k", OK, 60)  # must not raise
    assert sample("cache_errors_total", {"op": "get"}) == before + 1


async def test_tiered_l1_hit() -> None:
    l1, l2 = RecordingCache(), RecordingCache()
    l1.data["k"] = OK
    before = sample("cache_hits_total", {"tier": "l1"})
    assert await TieredCache(l1, l2).get("k") == OK
    assert sample("cache_hits_total", {"tier": "l1"}) == before + 1


async def test_tiered_l2_hit_populates_l1() -> None:
    l1, l2 = RecordingCache(), RecordingCache()
    l2.data["k"] = OK
    before = sample("cache_hits_total", {"tier": "l2"})
    assert await TieredCache(l1, l2).get("k") == OK
    assert l1.data["k"] == OK
    assert l1.ttls["k"] == 300
    assert sample("cache_hits_total", {"tier": "l2"}) == before + 1


async def test_tiered_miss() -> None:
    before = sample("cache_hits_total", {"tier": "miss"})
    assert await TieredCache(RecordingCache(), RecordingCache()).get("k") is None
    assert sample("cache_hits_total", {"tier": "miss"}) == before + 1


async def test_tiered_set_uses_tier_ttls() -> None:
    l1, l2 = RecordingCache(), RecordingCache()
    await TieredCache(l1, l2).set("k", OK)
    assert l1.ttls["k"] == 300
    assert l2.ttls["k"] == 3600


async def test_tiered_without_l2() -> None:
    l1 = RecordingCache()
    cache = TieredCache(l1)
    await cache.set("k", OK)
    assert await cache.get("k") == OK
```

`tests/core/dns/test_resolver_cache.py`:
```python
import asyncio

from email_validation.core.dns.backend import TemporaryDnsError
from email_validation.core.dns.cache import MemoryTTLCache, TieredCache
from email_validation.core.dns.resolver import MxOutcome, MxResolver
from tests.fakes import FakeDnsBackend, mx


def make(responses: dict, delay: float = 0.0) -> tuple[MxResolver, FakeDnsBackend]:  # type: ignore[type-arg]
    backend = FakeDnsBackend(responses, delay=delay)
    return MxResolver(backend, cache=TieredCache(MemoryTTLCache())), backend


async def test_second_lookup_served_from_cache() -> None:
    resolver, backend = make({("example.com", "MX"): mx((10, "mx.example.com"))})
    first = await resolver.lookup("example.com")
    second = await resolver.lookup("EXAMPLE.com")
    assert first == second
    assert backend.calls == [("example.com", "MX")]


async def test_single_flight_for_concurrent_lookups() -> None:
    resolver, backend = make({("example.com", "MX"): mx((10, "mx.example.com"))}, delay=0.05)
    results = await asyncio.gather(*(resolver.lookup("example.com") for _ in range(50)))
    assert {r.outcome for r in results} == {MxOutcome.OK}
    assert backend.calls == [("example.com", "MX")]


async def test_cancelled_caller_does_not_break_followers() -> None:
    resolver, backend = make({("example.com", "MX"): mx((10, "mx.example.com"))}, delay=0.05)
    leader = asyncio.create_task(resolver.lookup("example.com"))
    await asyncio.sleep(0.01)
    follower = asyncio.create_task(resolver.lookup("example.com"))
    await asyncio.sleep(0)
    leader.cancel()
    result = await follower
    assert result.outcome is MxOutcome.OK
    assert len(backend.calls) == 1


async def test_temporary_failure_is_cached_briefly() -> None:
    resolver, backend = make({("example.com", "MX"): TemporaryDnsError})
    assert (await resolver.lookup("example.com")).outcome is MxOutcome.TEMP_FAIL
    assert (await resolver.lookup("example.com")).outcome is MxOutcome.TEMP_FAIL
    assert len(backend.calls) == 1


async def test_without_cache_every_lookup_queries() -> None:
    backend = FakeDnsBackend({("example.com", "MX"): mx((10, "mx.example.com"))})
    resolver = MxResolver(backend)
    await resolver.lookup("example.com")
    await resolver.lookup("example.com")
    assert len(backend.calls) == 2
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `uv run pytest tests/core/dns -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'email_validation.core.dns.cache'`

- [ ] **Step 4: Implement cache**

`src/email_validation/core/dns/cache.py`:
```python
from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import OrderedDict
from collections.abc import Callable
from typing import Protocol

from redis.asyncio import Redis
from redis.exceptions import RedisError

from email_validation.core.dns.resolver import MxLookupResult, MxOutcome
from email_validation.core.metrics import CACHE_ERRORS_TOTAL, CACHE_HITS_TOTAL

logger = logging.getLogger(__name__)

KEY_PREFIX = "mx:v1:"
L1_MAX_TTL = 300
L2_MIN_TTL = 60
L2_MAX_TTL = 86_400
NEGATIVE_TTL = 300
TEMP_FAIL_TTL = 30
_POSITIVE = (MxOutcome.OK, MxOutcome.NULL_MX)
_NEGATIVE = (MxOutcome.NO_MX, MxOutcome.NXDOMAIN)


def cache_key(domain: str) -> str:
    return KEY_PREFIX + domain


def l1_ttl(result: MxLookupResult) -> int:
    if result.outcome in _POSITIVE:
        return max(1, min(result.ttl, L1_MAX_TTL))
    if result.outcome in _NEGATIVE:
        return NEGATIVE_TTL
    return TEMP_FAIL_TTL


def l2_ttl(result: MxLookupResult) -> int:
    if result.outcome in _POSITIVE:
        return min(max(result.ttl, L2_MIN_TTL), L2_MAX_TTL)
    if result.outcome in _NEGATIVE:
        return NEGATIVE_TTL
    return TEMP_FAIL_TTL


def encode_result(result: MxLookupResult) -> str:
    return json.dumps(
        {
            "outcome": result.outcome.value,
            "hosts": list(result.hosts),
            "implicit": result.implicit,
            "ttl": result.ttl,
        }
    )


def decode_result(raw: str | bytes) -> MxLookupResult:
    data = json.loads(raw)
    return MxLookupResult(
        outcome=MxOutcome(data["outcome"]),
        hosts=tuple(data["hosts"]),
        implicit=bool(data["implicit"]),
        ttl=int(data["ttl"]),
    )


class Cache(Protocol):
    async def get(self, key: str) -> MxLookupResult | None: ...

    async def set(self, key: str, value: MxLookupResult, ttl: int) -> None: ...


class MemoryTTLCache:
    """Per-process TTL + LRU cache (L1)."""

    def __init__(self, maxsize: int = 100_000, clock: Callable[[], float] = time.monotonic) -> None:
        self._maxsize = maxsize
        self._clock = clock
        self._data: OrderedDict[str, tuple[float, MxLookupResult]] = OrderedDict()

    async def get(self, key: str) -> MxLookupResult | None:
        entry = self._data.get(key)
        if entry is None:
            return None
        expires_at, value = entry
        if self._clock() >= expires_at:
            del self._data[key]
            return None
        self._data.move_to_end(key)
        return value

    async def set(self, key: str, value: MxLookupResult, ttl: int) -> None:
        if ttl <= 0:
            return
        self._data[key] = (self._clock() + ttl, value)
        self._data.move_to_end(key)
        while len(self._data) > self._maxsize:
            self._data.popitem(last=False)


class RedisCache:
    """Shared cache (L2). Every failure is swallowed: Redis is never a hard dependency."""

    def __init__(self, client: Redis, op_timeout: float = 0.05) -> None:
        self._client = client
        self._op_timeout = op_timeout

    async def get(self, key: str) -> MxLookupResult | None:
        try:
            async with asyncio.timeout(self._op_timeout):
                raw = await self._client.get(key)
        except (RedisError, OSError, TimeoutError) as exc:
            CACHE_ERRORS_TOTAL.labels(op="get").inc()
            logger.warning("redis cache get failed: %s", exc)
            return None
        if raw is None:
            return None
        try:
            return decode_result(raw)
        except (ValueError, KeyError, TypeError):
            CACHE_ERRORS_TOTAL.labels(op="decode").inc()
            return None

    async def set(self, key: str, value: MxLookupResult, ttl: int) -> None:
        try:
            async with asyncio.timeout(self._op_timeout):
                await self._client.set(key, encode_result(value), ex=ttl)
        except (RedisError, OSError, TimeoutError) as exc:
            CACHE_ERRORS_TOTAL.labels(op="set").inc()
            logger.warning("redis cache set failed: %s", exc)


class TieredCache:
    def __init__(self, l1: Cache, l2: Cache | None = None) -> None:
        self._l1 = l1
        self._l2 = l2

    async def get(self, key: str) -> MxLookupResult | None:
        value = await self._l1.get(key)
        if value is not None:
            CACHE_HITS_TOTAL.labels(tier="l1").inc()
            return value
        if self._l2 is not None:
            value = await self._l2.get(key)
            if value is not None:
                CACHE_HITS_TOTAL.labels(tier="l2").inc()
                await self._l1.set(key, value, l1_ttl(value))
                return value
        CACHE_HITS_TOTAL.labels(tier="miss").inc()
        return None

    async def set(self, key: str, value: MxLookupResult) -> None:
        await self._l1.set(key, value, l1_ttl(value))
        if self._l2 is not None:
            await self._l2.set(key, value, l2_ttl(value))
```

Note: `cache.py` imports `MxLookupResult` from `resolver.py`. To avoid an import cycle, `resolver.py` imports `TieredCache` only under `TYPE_CHECKING` and builds the cache key from its own `CACHE_KEY_PREFIX` constant; a test (Step 5) asserts it equals `cache.KEY_PREFIX`.

- [ ] **Step 5: Add cache and single-flight to MxResolver**

In `src/email_validation/core/dns/resolver.py`, add to the imports:
```python
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from email_validation.core.dns.cache import TieredCache
```
Add module constant after `normalize_domain`:
```python
CACHE_KEY_PREFIX = "mx:v1:"  # must equal email_validation.core.dns.cache.KEY_PREFIX
```
Replace `__init__` and `lookup` with:
```python
    def __init__(
        self,
        backend: DnsBackend,
        *,
        cache: TieredCache | None = None,
        max_concurrency: int = 500,
    ) -> None:
        self._backend = backend
        self._cache = cache
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._inflight: dict[str, asyncio.Task[MxLookupResult]] = {}

    async def lookup(self, ascii_domain: str) -> MxLookupResult:
        domain = normalize_domain(ascii_domain)
        key = CACHE_KEY_PREFIX + domain
        if self._cache is not None:
            cached = await self._cache.get(key)
            if cached is not None:
                return cached
        task = self._inflight.get(key)
        if task is None:
            # Run in a separate task so one caller's cancellation never cancels the
            # shared lookup that other callers (single-flight followers) await.
            task = asyncio.create_task(self._resolve_and_store(key, domain))
            self._inflight[key] = task
            task.add_done_callback(lambda _t, k=key: self._inflight.pop(k, None))
        return await asyncio.shield(task)

    async def _resolve_and_store(self, key: str, domain: str) -> MxLookupResult:
        result = await self._resolve(domain)
        if self._cache is not None:
            await self._cache.set(key, result)
        return result
```
Add to `tests/core/dns/test_cache.py`:
```python
def test_resolver_key_prefix_matches_cache() -> None:
    from email_validation.core.dns.cache import KEY_PREFIX
    from email_validation.core.dns.resolver import CACHE_KEY_PREFIX

    assert CACHE_KEY_PREFIX == KEY_PREFIX
```

- [ ] **Step 6: Run unit tests**

Run: `uv run pytest tests/core -v && uv run ruff check . && uv run mypy`
Expected: PASS, no errors

- [ ] **Step 7: Add integration fixtures and Redis test**

`tests/integration/conftest.py`:
```python
from collections.abc import AsyncIterator, Iterator

import pytest
from redis.asyncio import Redis


@pytest.fixture(scope="session")
def redis_url() -> Iterator[str]:
    redis_module = pytest.importorskip("testcontainers.redis")
    try:
        container = redis_module.RedisContainer("redis:7-alpine").start()
    except Exception as exc:  # Docker not installed / not running
        pytest.skip(f"Docker unavailable: {exc}")
    try:
        host = container.get_container_host_ip()
        port = container.get_exposed_port(6379)
        yield f"redis://{host}:{port}/0"
    finally:
        container.stop()


@pytest.fixture
async def redis_client(redis_url: str) -> AsyncIterator[Redis]:
    client = Redis.from_url(redis_url)
    await client.flushdb()
    yield client
    await client.aclose()
```

`tests/integration/test_redis_cache.py`:
```python
import pytest
from redis.asyncio import Redis

from email_validation.core.dns.cache import MemoryTTLCache, RedisCache, TieredCache
from email_validation.core.dns.resolver import MxOutcome, MxResolver
from tests.fakes import FakeDnsBackend, mx

pytestmark = pytest.mark.integration


async def test_two_replicas_share_l2(redis_client: Redis) -> None:
    responses = {("example.com", "MX"): mx((10, "mx.example.com"))}
    backend_a, backend_b = FakeDnsBackend(responses), FakeDnsBackend(responses)
    replica_a = MxResolver(backend_a, cache=TieredCache(MemoryTTLCache(), RedisCache(redis_client)))
    replica_b = MxResolver(backend_b, cache=TieredCache(MemoryTTLCache(), RedisCache(redis_client)))

    assert (await replica_a.lookup("example.com")).outcome is MxOutcome.OK
    assert (await replica_b.lookup("example.com")).outcome is MxOutcome.OK
    assert len(backend_a.calls) == 1
    assert backend_b.calls == []
    assert 0 < await redis_client.ttl("mx:v1:example.com") <= 3600
```

Run: `uv run pytest -m integration -v`
Expected: PASS when Docker is running; otherwise SKIPPED with "Docker unavailable" (Docker is not installed on the current dev machine — that is acceptable here; CI must run it).

- [ ] **Step 8: Commit**

```bash
git add src/email_validation/core/dns tests/fakes.py tests/core/dns tests/integration
git commit -m "feat(core): add L1/L2 MX cache with fail-open Redis and single-flight lookups"
```

---

### Task 6: Disposable registry and DisposableStep

**Files:**
- Create: `src/email_validation/core/disposable/__init__.py` (empty), `registry.py`, `data/disposable_domains.txt`
- Create: `src/email_validation/core/steps/disposable.py`
- Create: `tests/core/disposable/__init__.py` (empty)
- Test: `tests/core/disposable/test_registry.py`, `tests/core/steps/test_disposable_step.py`

**Interfaces:**
- Consumes: `ValidationContext`, `ValidationPolicy`, `StepOutcome` helpers.
- Produces:
  - `parse_domain_list(text: str) -> set[str]`
  - `DisposableRegistry(domains: Iterable[str] = (), allowlist: Iterable[str] = ())`, `from_bundled(allowlist=()) -> DisposableRegistry`, `__len__`, `contains(ascii_domain: str) -> bool`, `async reload(fetch: Fetcher) -> bool`, `async run_periodic_reload(fetch: Fetcher, interval: float) -> None`.
  - `Fetcher = Callable[[], Awaitable[str]]`; `http_fetcher(url: str, timeout: float = 10.0) -> Fetcher`.
  - `DisposableStep(registry: DisposableRegistry)`.

- [ ] **Step 1: Create bundled list**

`src/email_validation/core/disposable/data/disposable_domains.txt`:
```
# Bundled starter list of disposable email domains (one per line, A-label form).
# Production deployments should set EV_DISPOSABLE_URL to a maintained list, e.g.
# https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/main/disposable_email_blocklist.conf
10minutemail.com
dispostable.com
fakeinbox.com
getnada.com
guerrillamail.com
guerrillamail.net
mailinator.com
maildrop.cc
mintemail.com
sharklasers.com
temp-mail.org
throwawaymail.com
trashmail.com
yopmail.com
```

- [ ] **Step 2: Write failing tests**

`tests/core/disposable/test_registry.py`:
```python
import asyncio

from email_validation.core.disposable.registry import DisposableRegistry, parse_domain_list


def test_parse_domain_list() -> None:
    text = "# comment\n\nMailinator.com\n  yopmail.com  \n#x.com\n"
    assert parse_domain_list(text) == {"mailinator.com", "yopmail.com"}


def test_contains_exact_and_parent() -> None:
    reg = DisposableRegistry(["mailinator.com"])
    assert reg.contains("mailinator.com")
    assert reg.contains("MAILINATOR.com")
    assert reg.contains("x.y.mailinator.com")
    assert not reg.contains("notmailinator.com")
    assert not reg.contains("example.com")


def test_allowlist_wins() -> None:
    reg = DisposableRegistry(["mailinator.com"], allowlist=["corp.mailinator.com"])
    assert not reg.contains("corp.mailinator.com")
    assert reg.contains("other.mailinator.com")


def test_bundled_list_loads() -> None:
    reg = DisposableRegistry.from_bundled()
    assert len(reg) > 0
    assert reg.contains("mailinator.com")


async def test_reload_merges_with_base() -> None:
    reg = DisposableRegistry(["mailinator.com"])

    async def fetch() -> str:
        return "newtrash.com\n"

    assert await reg.reload(fetch) is True
    assert reg.contains("newtrash.com")
    assert reg.contains("mailinator.com")


async def test_reload_failure_keeps_old_set() -> None:
    reg = DisposableRegistry(["mailinator.com"])

    async def ok() -> str:
        return "newtrash.com"

    async def boom() -> str:
        raise OSError("network down")

    await reg.reload(ok)
    assert await reg.reload(boom) is False
    assert reg.contains("newtrash.com")


async def test_reload_empty_download_keeps_old_set() -> None:
    reg = DisposableRegistry(["mailinator.com"])

    async def ok() -> str:
        return "newtrash.com"

    async def empty() -> str:
        return "# nothing\n"

    await reg.reload(ok)
    assert await reg.reload(empty) is False
    assert reg.contains("newtrash.com")


async def test_periodic_reload_runs_until_cancelled() -> None:
    reg = DisposableRegistry()
    calls = 0

    async def fetch() -> str:
        nonlocal calls
        calls += 1
        return "a.com"

    task = asyncio.create_task(reg.run_periodic_reload(fetch, interval=0.01))
    await asyncio.sleep(0.05)
    task.cancel()
    assert calls >= 2
    assert reg.contains("a.com")
```

`tests/core/steps/test_disposable_step.py`:
```python
from email_validation.core.disposable.registry import DisposableRegistry
from email_validation.core.models import Reason, Status, ValidationContext
from email_validation.core.policy import ValidationPolicy
from email_validation.core.steps.base import CONTINUE
from email_validation.core.steps.disposable import DisposableStep

STEP = DisposableStep(DisposableRegistry(["mailinator.com"]))


def ctx_for(domain: str, literal: bool = False) -> ValidationContext:
    ctx = ValidationContext(input=f"a@{domain}")
    ctx.ascii_domain = domain
    ctx.is_domain_literal = literal
    return ctx


async def test_reject() -> None:
    ctx = ctx_for("mailinator.com")
    outcome = await STEP.run(ctx, ValidationPolicy())
    assert outcome.status is Status.INVALID
    assert outcome.reason is Reason.DISPOSABLE
    assert ctx.is_disposable is True


async def test_flag() -> None:
    ctx = ctx_for("mailinator.com")
    outcome = await STEP.run(ctx, ValidationPolicy(disposable_action="flag"))
    assert outcome == CONTINUE
    assert ctx.is_disposable is True


async def test_off() -> None:
    ctx = ctx_for("mailinator.com")
    outcome = await STEP.run(ctx, ValidationPolicy(disposable_action="off"))
    assert outcome == CONTINUE
    assert ctx.is_disposable is False


async def test_clean_domain() -> None:
    ctx = ctx_for("example.com")
    assert await STEP.run(ctx, ValidationPolicy()) == CONTINUE
    assert ctx.is_disposable is False


async def test_domain_literal_skipped() -> None:
    ctx = ctx_for("[192.0.2.1]", literal=True)
    assert await STEP.run(ctx, ValidationPolicy()) == CONTINUE
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `uv run pytest tests/core/disposable tests/core/steps/test_disposable_step.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 4: Implement registry and step**

`src/email_validation/core/disposable/registry.py`:
```python
from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable, Iterable
from importlib import resources

import httpx

logger = logging.getLogger(__name__)

Fetcher = Callable[[], Awaitable[str]]


def parse_domain_list(text: str) -> set[str]:
    domains: set[str] = set()
    for line in text.splitlines():
        entry = line.strip().lower()
        if entry and not entry.startswith("#"):
            domains.add(entry.rstrip("."))
    return domains


def http_fetcher(url: str, timeout: float = 10.0) -> Fetcher:
    async def fetch() -> str:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            response = await client.get(url)
            response.raise_for_status()
            return response.text

    return fetch


class DisposableRegistry:
    def __init__(self, domains: Iterable[str] = (), allowlist: Iterable[str] = ()) -> None:
        self._base = frozenset(d.strip().lower().rstrip(".") for d in domains if d.strip())
        self._allow = frozenset(d.strip().lower().rstrip(".") for d in allowlist if d.strip())
        self._domains: frozenset[str] = self._base

    @classmethod
    def from_bundled(cls, allowlist: Iterable[str] = ()) -> DisposableRegistry:
        text = (
            resources.files("email_validation.core.disposable")
            .joinpath("data/disposable_domains.txt")
            .read_text(encoding="utf-8")
        )
        return cls(parse_domain_list(text), allowlist=allowlist)

    def __len__(self) -> int:
        return len(self._domains)

    def contains(self, ascii_domain: str) -> bool:
        labels = ascii_domain.lower().rstrip(".").split(".")
        for i in range(len(labels) - 1):
            candidate = ".".join(labels[i:])
            if candidate in self._allow:
                return False
            if candidate in self._domains:
                return True
        return False

    async def reload(self, fetch: Fetcher) -> bool:
        try:
            fetched = parse_domain_list(await fetch())
        except Exception as exc:
            logger.warning("disposable list reload failed, keeping previous list: %s", exc)
            return False
        if not fetched:
            logger.warning("disposable list download was empty, keeping previous list")
            return False
        self._domains = self._base | fetched  # atomic reference swap
        logger.info("disposable list reloaded", extra={"count": len(self._domains)})
        return True

    async def run_periodic_reload(self, fetch: Fetcher, interval: float) -> None:
        while True:
            await self.reload(fetch)
            await asyncio.sleep(interval)
```

`src/email_validation/core/steps/disposable.py`:
```python
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
```

- [ ] **Step 5: Run tests**

Run: `uv run pytest tests/core -v && uv run ruff check . && uv run mypy`
Expected: PASS, no errors

- [ ] **Step 6: Commit**

```bash
git add src/email_validation/core/disposable src/email_validation/core/steps/disposable.py tests/core
git commit -m "feat(core): add disposable domain registry with background reload and step"
```

---

### Task 7: DnsMxStep and EmailValidator pipeline

**Files:**
- Create: `src/email_validation/core/steps/dns_mx.py`, `src/email_validation/core/pipeline.py`
- Modify: `src/email_validation/core/__init__.py` (public exports)
- Test: `tests/core/steps/test_dns_mx.py`, `tests/core/test_pipeline.py`

**Interfaces:**
- Consumes: all steps (Tasks 2, 3, 6), `MxResolver`, `MxOutcome` (Tasks 4–5), `DisposableRegistry` (Task 6), `VALIDATIONS_TOTAL`.
- Produces:
  - `DnsMxStep(resolver: MxResolver)`.
  - `default_steps(resolver: MxResolver | None, registry: DisposableRegistry | None) -> list[Step]`.
  - `EmailValidator(policy: ValidationPolicy | None = None, *, resolver: MxResolver | None = None, registry: DisposableRegistry | None = None, steps: Sequence[Step] | None = None)`, `.policy` property, `async validate(email: str, policy: ValidationPolicy | None = None) -> ValidationResult`, `async validate_many(emails: Sequence[str], policy: ValidationPolicy | None = None, concurrency: int = 100) -> list[ValidationResult]`.
  - `email_validation.core` exports: `EmailValidator`, `ValidationPolicy`, `ValidationResult`, `Status`, `Reason`, `MxResolver`, `DnspythonBackend`, `TieredCache`, `MemoryTTLCache`, `RedisCache`, `DisposableRegistry`.

- [ ] **Step 1: Write failing tests**

`tests/core/steps/test_dns_mx.py`:
```python
import pytest

from email_validation.core.dns.backend import NoAnswerError, TemporaryDnsError
from email_validation.core.dns.resolver import MxResolver
from email_validation.core.models import Reason, Status, ValidationContext
from email_validation.core.policy import ValidationPolicy
from email_validation.core.steps.base import CONTINUE
from email_validation.core.steps.dns_mx import DnsMxStep
from tests.fakes import FakeDnsBackend, addr, mx


def ctx_for(domain: str) -> ValidationContext:
    ctx = ValidationContext(input=f"a@{domain}")
    ctx.ascii_domain = domain
    return ctx


async def run(responses: dict, policy: ValidationPolicy | None = None):  # type: ignore[no-untyped-def]
    backend = FakeDnsBackend(responses)
    ctx = ctx_for("example.com")
    outcome = await DnsMxStep(MxResolver(backend)).run(ctx, policy or ValidationPolicy())
    return outcome, ctx, backend


async def test_ok_sets_hosts() -> None:
    outcome, ctx, _ = await run({("example.com", "MX"): mx((10, "mx.example.com"))})
    assert outcome == CONTINUE
    assert ctx.mx_hosts == ("mx.example.com",)
    assert ctx.implicit_mx is False


IMPLICIT = {
    ("example.com", "MX"): NoAnswerError,
    ("example.com", "A"): addr("192.0.2.1"),
    ("example.com", "AAAA"): NoAnswerError,
}


async def test_implicit_mx_allowed() -> None:
    outcome, ctx, _ = await run(IMPLICIT)
    assert outcome == CONTINUE
    assert ctx.implicit_mx is True


async def test_implicit_mx_disallowed() -> None:
    outcome, _, _ = await run(IMPLICIT, ValidationPolicy(allow_implicit_mx=False))
    assert outcome.status is Status.INVALID
    assert outcome.reason is Reason.DOMAIN_NO_MX


@pytest.mark.parametrize(
    ("responses", "status", "reason"),
    [
        ({("example.com", "MX"): mx((0, "."))}, Status.INVALID, Reason.DOMAIN_NULL_MX),
        (
            {
                ("example.com", "MX"): NoAnswerError,
                ("example.com", "A"): NoAnswerError,
                ("example.com", "AAAA"): NoAnswerError,
            },
            Status.INVALID,
            Reason.DOMAIN_NO_MX,
        ),
        ({}, Status.INVALID, Reason.DOMAIN_NOT_FOUND),
        (
            {("example.com", "MX"): TemporaryDnsError},
            Status.UNKNOWN,
            Reason.DNS_TEMPORARY_FAILURE,
        ),
    ],
)
async def test_failures(responses: dict, status: Status, reason: Reason) -> None:  # type: ignore[type-arg]
    outcome, _, _ = await run(responses)
    assert outcome.status is status
    assert outcome.reason is reason


async def test_skipped_when_check_dns_false() -> None:
    outcome, _, backend = await run({}, ValidationPolicy(check_dns=False))
    assert outcome == CONTINUE
    assert backend.calls == []


async def test_skipped_for_domain_literal() -> None:
    backend = FakeDnsBackend({})
    ctx = ctx_for("[192.0.2.1]")
    ctx.is_domain_literal = True
    assert await DnsMxStep(MxResolver(backend)).run(ctx, ValidationPolicy()) == CONTINUE
    assert backend.calls == []
```

`tests/core/test_pipeline.py`:
```python
import asyncio

from prometheus_client import REGISTRY

from email_validation.core import (
    DisposableRegistry,
    EmailValidator,
    MemoryTTLCache,
    MxResolver,
    Reason,
    Status,
    TieredCache,
    ValidationPolicy,
)
from email_validation.core.dns.backend import TemporaryDnsError
from email_validation.core.models import ValidationContext
from email_validation.core.steps.base import StepOutcome
from tests.fakes import FakeDnsBackend, mx

RESPONSES = {
    ("example.com", "MX"): mx((10, "mx.example.com")),
    ("xn--bcher-kva.de", "MX"): mx((10, "mx.bucher.de")),
    ("mailinator.com", "MX"): mx((10, "mx.mailinator.com")),
    ("flaky.com", "MX"): TemporaryDnsError,
}


def make(delay: float = 0.0) -> tuple[EmailValidator, FakeDnsBackend]:
    backend = FakeDnsBackend(RESPONSES, delay=delay)
    resolver = MxResolver(backend, cache=TieredCache(MemoryTTLCache()))
    registry = DisposableRegistry(["mailinator.com"])
    return EmailValidator(resolver=resolver, registry=registry), backend


async def test_full_valid_idn_with_tag() -> None:
    validator, _ = make()
    r = await validator.validate("User+News@Bücher.de")
    assert r.status is Status.VALID
    assert r.reasons == ()
    assert r.ascii_email == "User+News@xn--bcher-kva.de"
    assert (r.base_local_part, r.tag) == ("User", "News")
    assert r.mx_hosts == ("mx.bucher.de",)


async def test_whitespace_and_case_normalized() -> None:
    validator, backend = make()
    r = await validator.validate("  User@EXAMPLE.com ")
    assert r.status is Status.VALID
    assert r.input == "  User@EXAMPLE.com "
    assert r.normalized == "User@example.com"
    assert backend.calls == [("example.com", "MX")]


async def test_syntax_error_never_queries_dns() -> None:
    validator, backend = make()
    r = await validator.validate("a..b@example.com")
    assert r.status is Status.INVALID
    assert r.reasons == (Reason.SYNTAX_INVALID,)
    assert backend.calls == []


async def test_disposable_reject_skips_dns() -> None:
    validator, backend = make()
    r = await validator.validate("x@mailinator.com")
    assert r.status is Status.INVALID
    assert r.reasons == (Reason.DISPOSABLE,)
    assert r.is_disposable is True
    assert backend.calls == []


async def test_disposable_flag() -> None:
    validator, _ = make()
    r = await validator.validate(
        "x@mailinator.com", ValidationPolicy(disposable_action="flag")
    )
    assert r.status is Status.VALID
    assert r.is_disposable is True


async def test_nxdomain_and_temp_fail() -> None:
    validator, _ = make()
    assert (await validator.validate("a@nope.com")).reasons == (Reason.DOMAIN_NOT_FOUND,)
    r = await validator.validate("a@flaky.com")
    assert r.status is Status.UNKNOWN
    assert r.reasons == (Reason.DNS_TEMPORARY_FAILURE,)


async def test_per_call_policy_disables_dns() -> None:
    validator, backend = make()
    r = await validator.validate("a@nope.com", validator.policy.with_overrides(check_dns=False))
    assert r.status is Status.VALID
    assert backend.calls == []


async def test_step_exception_becomes_unknown() -> None:
    class Boom:
        name = "boom"

        async def run(self, ctx: ValidationContext, policy: ValidationPolicy) -> StepOutcome:
            raise RuntimeError("bug")

    r = await EmailValidator(steps=[Boom()]).validate("a@example.com")
    assert r.status is Status.UNKNOWN
    assert r.reasons == (Reason.INTERNAL_ERROR,)


async def test_without_resolver_and_registry() -> None:
    r = await EmailValidator().validate("a@mailinator.com")
    assert r.status is Status.VALID
    assert r.mx_hosts == ()


async def test_validate_many_single_flight() -> None:
    validator, backend = make(delay=0.05)
    emails = [f"user{i}@example.com" for i in range(100)] + ["bad"]
    results = await validator.validate_many(emails, concurrency=20)
    assert [r.input for r in results] == emails
    assert results[-1].status is Status.INVALID
    assert all(r.status is Status.VALID for r in results[:-1])
    assert backend.calls == [("example.com", "MX")]


async def test_validate_many_empty() -> None:
    validator, _ = make()
    assert await validator.validate_many([]) == []


async def test_metric_incremented() -> None:
    labels = {"status": "invalid", "reason": "SYNTAX_INVALID"}
    before = REGISTRY.get_sample_value("validations_total", labels) or 0.0
    validator, _ = make()
    await validator.validate("nope")
    assert REGISTRY.get_sample_value("validations_total", labels) == before + 1


async def test_concurrent_validate_is_safe() -> None:
    validator, _ = make()
    results = await asyncio.gather(*(validator.validate("a@example.com") for _ in range(20)))
    assert {r.status for r in results} == {Status.VALID}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/core/steps/test_dns_mx.py tests/core/test_pipeline.py -v`
Expected: FAIL with `ModuleNotFoundError` / `ImportError: cannot import name 'EmailValidator'`

- [ ] **Step 3: Implement DnsMxStep**

`src/email_validation/core/steps/dns_mx.py`:
```python
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
```

- [ ] **Step 4: Implement pipeline and exports**

`src/email_validation/core/pipeline.py`:
```python
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


def default_steps(
    resolver: MxResolver | None, registry: DisposableRegistry | None
) -> list[Step]:
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

    async def validate(self, email: str, policy: ValidationPolicy | None = None) -> ValidationResult:
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
```

`src/email_validation/core/__init__.py`:
```python
from email_validation.core.disposable.registry import DisposableRegistry
from email_validation.core.dns.backend import DnspythonBackend
from email_validation.core.dns.cache import MemoryTTLCache, RedisCache, TieredCache
from email_validation.core.dns.resolver import MxResolver
from email_validation.core.models import Reason, Status, ValidationResult
from email_validation.core.pipeline import EmailValidator
from email_validation.core.policy import ValidationPolicy

__all__ = [
    "DisposableRegistry",
    "DnspythonBackend",
    "EmailValidator",
    "MemoryTTLCache",
    "MxResolver",
    "Reason",
    "RedisCache",
    "Status",
    "TieredCache",
    "ValidationPolicy",
    "ValidationResult",
]
```

- [ ] **Step 5: Run full core suite**

Run: `uv run pytest -v && uv run ruff check . && uv run mypy`
Expected: all PASS, no errors

- [ ] **Step 6: Commit**

```bash
git add src/email_validation/core tests/core
git commit -m "feat(core): add DNS MX step and fail-fast EmailValidator pipeline"
```

---

### Task 8: REST API — settings, schemas, state, routes

**Files:**
- Create: `src/email_validation/api/__init__.py` (empty), `settings.py`, `schemas.py`, `state.py`, `routes.py`, `app.py`
- Create: `tests/api/__init__.py` (empty), `tests/api/conftest.py`
- Test: `tests/api/test_validate.py`, `tests/api/test_health.py`

**Interfaces:**
- Consumes: `email_validation.core` exports (Task 7), `DnsBackend` (Task 4), `http_fetcher` (Task 6).
- Produces:
  - `Settings` (pydantic-settings, prefix `EV_`) with fields listed below; helper properties `dns_nameserver_list`, `disposable_allowlist_list`; `to_policy() -> ValidationPolicy`.
  - `AppState` dataclass (`settings`, `validator`, `resolver`, `registry`, `redis`, `owns_redis`); `build_state(settings, *, dns_backend=None, redis_client=None, registry=None) -> AppState`; `get_state(request) -> AppState`.
  - `create_app(settings: Settings | None = None, *, dns_backend: DnsBackend | None = None, redis_client: Redis | None = None, registry: DisposableRegistry | None = None) -> FastAPI`.
  - Test fixtures: `dns` (`FakeDnsBackend`), `settings`, `redis`, `client` (`httpx.AsyncClient`).

- [ ] **Step 1: Write fixtures and failing tests**

`tests/api/conftest.py`:
```python
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
from fakeredis import FakeAsyncRedis

from email_validation.api.app import create_app
from email_validation.api.settings import Settings
from tests.fakes import FakeDnsBackend, mx


@pytest.fixture
def dns() -> FakeDnsBackend:
    return FakeDnsBackend(
        {
            ("example.com", "MX"): mx((10, "mx.example.com")),
            ("xn--bcher-kva.de", "MX"): mx((10, "mx.bucher.de")),
            ("mailinator.com", "MX"): mx((10, "mx.mailinator.com")),
        },
        delay=0.01,
    )


@pytest.fixture
def settings() -> Settings:
    return Settings(_env_file=None, redis_url=None)


@pytest.fixture
def redis() -> Any:
    return FakeAsyncRedis()


@pytest.fixture
async def client(
    settings: Settings, dns: FakeDnsBackend, redis: Any
) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(settings, dns_backend=dns, redis_client=redis)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
```

`tests/api/test_validate.py`:
```python
from typing import Any

import httpx
import pytest

from email_validation.api.app import create_app
from email_validation.api.settings import Settings
from tests.fakes import BrokenRedis, FakeDnsBackend


async def test_validate_valid(client: httpx.AsyncClient) -> None:
    resp = await client.post("/v1/validate", json={"email": "User+News@Bücher.de"})
    assert resp.status_code == 200
    body = resp.json()
    assert body == {
        "input": "User+News@Bücher.de",
        "status": "valid",
        "reasons": [],
        "normalized": "User+News@bücher.de",
        "ascii_email": "User+News@xn--bcher-kva.de",
        "local_part": "User+News",
        "base_local_part": "User",
        "tag": "News",
        "domain": "bücher.de",
        "ascii_domain": "xn--bcher-kva.de",
        "mx_hosts": ["mx.bucher.de"],
        "implicit_mx": False,
        "is_disposable": False,
    }


async def test_invalid_is_200(client: httpx.AsyncClient) -> None:
    resp = await client.post("/v1/validate", json={"email": "not-an-email"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "invalid"
    assert resp.json()["reasons"] == ["SYNTAX_INVALID"]


async def test_empty_email_is_invalid_not_422(client: httpx.AsyncClient) -> None:
    resp = await client.post("/v1/validate", json={"email": ""})
    assert resp.status_code == 200
    assert resp.json()["status"] == "invalid"


@pytest.mark.parametrize(
    "payload",
    [{}, {"email": 123}, {"email": "a@example.com", "options": {"disposable_action": "block"}}],
)
async def test_bad_request_is_422(client: httpx.AsyncClient, payload: dict[str, Any]) -> None:
    assert (await client.post("/v1/validate", json=payload)).status_code == 422


async def test_options_override(client: httpx.AsyncClient) -> None:
    reject = await client.post("/v1/validate", json={"email": "x@mailinator.com"})
    assert reject.json()["reasons"] == ["DISPOSABLE"]
    flag = await client.post(
        "/v1/validate",
        json={"email": "x@mailinator.com", "options": {"disposable_action": "flag"}},
    )
    assert flag.json()["status"] == "valid"
    assert flag.json()["is_disposable"] is True
    no_dns = await client.post(
        "/v1/validate", json={"email": "a@nope.com", "options": {"check_dns": False}}
    )
    assert no_dns.json()["status"] == "valid"


async def test_batch_preserves_order_and_single_flight(
    client: httpx.AsyncClient, dns: FakeDnsBackend
) -> None:
    emails = [f"u{i}@example.com" for i in range(50)] + ["bad", "a@nope.com"]
    resp = await client.post("/v1/validate/batch", json={"emails": emails})
    assert resp.status_code == 200
    results = resp.json()["results"]
    assert [r["input"] for r in results] == emails
    assert results[-2]["status"] == "invalid"
    assert results[-1]["reasons"] == ["DOMAIN_NOT_FOUND"]
    assert dns.calls.count(("example.com", "MX")) == 1


async def test_batch_empty(client: httpx.AsyncClient) -> None:
    resp = await client.post("/v1/validate/batch", json={"emails": []})
    assert resp.status_code == 200
    assert resp.json() == {"results": []}


async def test_batch_too_large_is_413(client: httpx.AsyncClient) -> None:
    resp = await client.post("/v1/validate/batch", json={"emails": ["a@example.com"] * 1001})
    assert resp.status_code == 413


async def test_validate_with_broken_redis(settings: Settings, dns: FakeDnsBackend) -> None:
    app = create_app(settings, dns_backend=dns, redis_client=BrokenRedis())  # type: ignore[arg-type]
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        resp = await c.post("/v1/validate", json={"email": "a@example.com"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "valid"
```

`tests/api/test_health.py`:
```python
import httpx

from email_validation.api.app import create_app
from email_validation.api.settings import Settings
from email_validation.core import DisposableRegistry
from tests.fakes import BrokenRedis, FakeDnsBackend


async def get(app: object, path: str) -> httpx.Response:
    transport = httpx.ASGITransport(app=app)  # type: ignore[arg-type]
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        return await c.get(path)


async def test_healthz(client: httpx.AsyncClient) -> None:
    resp = await client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


async def test_readyz_ok(client: httpx.AsyncClient) -> None:
    resp = await client.get("/readyz")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["redis"] == "ok"
    assert body["disposable_domains"] > 0


async def test_readyz_degraded(settings: Settings, dns: FakeDnsBackend) -> None:
    app = create_app(settings, dns_backend=dns, redis_client=BrokenRedis())  # type: ignore[arg-type]
    resp = await get(app, "/readyz")
    assert resp.status_code == 200
    assert resp.json()["redis"] == "degraded"


async def test_readyz_redis_disabled(settings: Settings, dns: FakeDnsBackend) -> None:
    resp = await get(create_app(settings, dns_backend=dns), "/readyz")
    assert resp.json()["redis"] == "disabled"


async def test_readyz_503_without_disposable_list(
    settings: Settings, dns: FakeDnsBackend
) -> None:
    app = create_app(settings, dns_backend=dns, registry=DisposableRegistry())
    assert (await get(app, "/readyz")).status_code == 503
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/api -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'email_validation.api'`

- [ ] **Step 3: Implement settings**

`src/email_validation/api/settings.py`:
```python
from __future__ import annotations

from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict

from email_validation.core.policy import ValidationPolicy


def _csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="EV_", env_file=".env", extra="ignore")

    redis_url: str | None = None

    dns_nameservers: str = ""  # comma-separated; empty = system resolver
    dns_timeout: float = 2.0
    dns_lifetime: float = 4.0
    dns_max_concurrency: int = 500
    l1_cache_size: int = 100_000

    disposable_url: str | None = None
    disposable_reload_seconds: int = 86_400
    disposable_allowlist: str = ""  # comma-separated

    allow_smtputf8: bool = True
    allow_quoted_local: bool = False
    allow_domain_literal: bool = False
    subaddress_separator: str | None = "+"
    check_dns: bool = True
    allow_implicit_mx: bool = True
    disposable_action: Literal["reject", "flag", "off"] = "reject"

    batch_max: int = 1000
    batch_concurrency: int = 100

    log_level: str = "INFO"

    @property
    def dns_nameserver_list(self) -> list[str]:
        return _csv(self.dns_nameservers)

    @property
    def disposable_allowlist_list(self) -> list[str]:
        return _csv(self.disposable_allowlist)

    def to_policy(self) -> ValidationPolicy:
        return ValidationPolicy(
            allow_smtputf8=self.allow_smtputf8,
            allow_quoted_local=self.allow_quoted_local,
            allow_domain_literal=self.allow_domain_literal,
            subaddress_separator=self.subaddress_separator or None,
            check_dns=self.check_dns,
            allow_implicit_mx=self.allow_implicit_mx,
            disposable_action=self.disposable_action,
        )
```

- [ ] **Step 4: Implement schemas**

`src/email_validation/api/schemas.py`:
```python
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from email_validation.core.models import Reason, Status, ValidationResult


class Options(BaseModel):
    check_dns: bool | None = None
    disposable_action: Literal["reject", "flag", "off"] | None = None


class ValidateRequest(BaseModel):
    email: str = Field(max_length=1024)
    options: Options = Field(default_factory=Options)


class BatchRequest(BaseModel):
    emails: list[str] = Field(max_length=100_000)  # hard ceiling; batch_max enforced in route (413)
    options: Options = Field(default_factory=Options)


class ValidationResponse(BaseModel):
    input: str
    status: Status  # StrEnum -> serialized as "valid" / "invalid" / "unknown"
    reasons: list[Reason]
    normalized: str | None
    ascii_email: str | None
    local_part: str | None
    base_local_part: str | None
    tag: str | None
    domain: str | None
    ascii_domain: str | None
    mx_hosts: list[str]
    implicit_mx: bool
    is_disposable: bool

    @classmethod
    def from_result(cls, r: ValidationResult) -> ValidationResponse:
        return cls(
            input=r.input,
            status=r.status,
            reasons=list(r.reasons),
            normalized=r.normalized,
            ascii_email=r.ascii_email,
            local_part=r.local_part,
            base_local_part=r.base_local_part,
            tag=r.tag,
            domain=r.domain,
            ascii_domain=r.ascii_domain,
            mx_hosts=list(r.mx_hosts),
            implicit_mx=r.implicit_mx,
            is_disposable=r.is_disposable,
        )


class BatchResponse(BaseModel):
    results: list[ValidationResponse]
```

- [ ] **Step 5: Implement state**

`src/email_validation/api/state.py`:
```python
from __future__ import annotations

from dataclasses import dataclass
from typing import cast

from fastapi import Request
from redis.asyncio import Redis

from email_validation.api.settings import Settings
from email_validation.core import (
    DisposableRegistry,
    DnspythonBackend,
    EmailValidator,
    MemoryTTLCache,
    MxResolver,
    RedisCache,
    TieredCache,
)
from email_validation.core.dns.backend import DnsBackend


@dataclass
class AppState:
    settings: Settings
    validator: EmailValidator
    resolver: MxResolver
    registry: DisposableRegistry
    redis: Redis | None
    owns_redis: bool


def build_state(
    settings: Settings,
    *,
    dns_backend: DnsBackend | None = None,
    redis_client: Redis | None = None,
    registry: DisposableRegistry | None = None,
) -> AppState:
    owns_redis = redis_client is None and settings.redis_url is not None
    redis = redis_client
    if owns_redis and settings.redis_url is not None:
        redis = Redis.from_url(
            settings.redis_url, socket_timeout=0.5, socket_connect_timeout=0.5
        )
    cache = TieredCache(
        MemoryTTLCache(maxsize=settings.l1_cache_size),
        RedisCache(redis) if redis is not None else None,
    )
    backend = dns_backend or DnspythonBackend(
        settings.dns_nameserver_list, timeout=settings.dns_timeout, lifetime=settings.dns_lifetime
    )
    resolver = MxResolver(backend, cache=cache, max_concurrency=settings.dns_max_concurrency)
    if registry is None:
        registry = DisposableRegistry.from_bundled(allowlist=settings.disposable_allowlist_list)
    validator = EmailValidator(settings.to_policy(), resolver=resolver, registry=registry)
    return AppState(settings, validator, resolver, registry, redis, owns_redis)


def get_state(request: Request) -> AppState:
    return cast(AppState, request.app.state.ev)
```

- [ ] **Step 6: Implement routes and app**

`src/email_validation/api/routes.py`:
```python
from __future__ import annotations

import asyncio

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from redis.exceptions import RedisError

from email_validation.api.schemas import (
    BatchRequest,
    BatchResponse,
    ValidateRequest,
    ValidationResponse,
)
from email_validation.api.state import get_state

router = APIRouter()


@router.post("/v1/validate", response_model=ValidationResponse)
async def validate(body: ValidateRequest, request: Request) -> ValidationResponse:
    state = get_state(request)
    policy = state.validator.policy.with_overrides(**body.options.model_dump())
    result = await state.validator.validate(body.email, policy)
    return ValidationResponse.from_result(result)


@router.post("/v1/validate/batch", response_model=BatchResponse)
async def validate_batch(body: BatchRequest, request: Request) -> BatchResponse:
    state = get_state(request)
    if len(body.emails) > state.settings.batch_max:
        raise HTTPException(413, f"batch exceeds {state.settings.batch_max} emails")
    policy = state.validator.policy.with_overrides(**body.options.model_dump())
    results = await state.validator.validate_many(
        body.emails, policy, concurrency=state.settings.batch_concurrency
    )
    return BatchResponse(results=[ValidationResponse.from_result(r) for r in results])


@router.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/readyz")
async def readyz(request: Request) -> JSONResponse:
    state = get_state(request)
    redis_status = "disabled"
    if state.redis is not None:
        try:
            async with asyncio.timeout(0.2):
                await state.redis.ping()
            redis_status = "ok"
        except (RedisError, OSError, TimeoutError):
            redis_status = "degraded"
    loaded = len(state.registry)
    body = {
        "status": "ok" if loaded > 0 else "not_ready",
        "redis": redis_status,
        "disposable_domains": loaded,
    }
    return JSONResponse(body, status_code=200 if loaded > 0 else 503)
```

`src/email_validation/api/app.py`:
```python
from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator

from fastapi import FastAPI
from redis.asyncio import Redis

from email_validation.api.routes import router
from email_validation.api.settings import Settings
from email_validation.api.state import AppState, build_state
from email_validation.core import DisposableRegistry
from email_validation.core.disposable.registry import http_fetcher
from email_validation.core.dns.backend import DnsBackend


def create_app(
    settings: Settings | None = None,
    *,
    dns_backend: DnsBackend | None = None,
    redis_client: Redis | None = None,
    registry: DisposableRegistry | None = None,
) -> FastAPI:
    settings = settings or Settings()
    state = build_state(
        settings, dns_backend=dns_backend, redis_client=redis_client, registry=registry
    )

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        reload_task: asyncio.Task[None] | None = None
        if settings.disposable_url:
            reload_task = asyncio.create_task(
                state.registry.run_periodic_reload(
                    http_fetcher(settings.disposable_url), settings.disposable_reload_seconds
                )
            )
        try:
            yield
        finally:
            if reload_task is not None:
                reload_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await reload_task
            await _close(state)

    app = FastAPI(title="Email Validation Service", version="0.1.0", lifespan=lifespan)
    app.state.ev = state
    app.include_router(router)
    return app


async def _close(state: AppState) -> None:
    if state.owns_redis and state.redis is not None:
        await state.redis.aclose()
```

- [ ] **Step 7: Run tests**

Run: `uv run pytest -v && uv run ruff check . && uv run mypy`
Expected: all PASS, no errors

- [ ] **Step 8: Manual run check**

Run: `uv run uvicorn email_validation.api.app:create_app --factory --port 8000` (in background), then
`curl -s -X POST localhost:8000/v1/validate -H "content-type: application/json" -d "{\"email\":\"someone+x@gmail.com\"}"`
Expected: JSON with `"status":"valid"` and Google MX hosts (requires network). Stop the server.

- [ ] **Step 9: Commit**

```bash
git add src/email_validation/api tests/api
git commit -m "feat(api): add FastAPI service with validate, batch and health endpoints"
```

---

### Task 9: API key authentication and Redis rate limiting

**Files:**
- Create: `src/email_validation/api/security.py`
- Modify: `src/email_validation/api/settings.py` (auth + rate-limit fields), `src/email_validation/api/state.py` (build `auth`, `rate_limiter`), `src/email_validation/api/routes.py` (dependencies), `tests/api/conftest.py` (API key)
- Test: `tests/api/test_security.py`, `tests/api/test_rate_limiter.py`, `tests/integration/test_rate_limiter_redis.py`

**Interfaces:**
- Consumes: `Settings`, `AppState`, `get_state` (Task 8); `RATE_LIMIT_REJECTIONS_TOTAL`, `RATE_LIMIT_ERRORS_TOTAL` (Task 4).
- Produces:
  - `hash_api_key(key: str) -> str` (SHA-256 hex); `python -m email_validation.api.security <key>` prints the hash.
  - `ApiKeyAuth(hashes: Iterable[str], enabled: bool = True)`, `.identify(presented: str | None) -> str | None` (returns key id = first 12 hex chars of the hash, `"anonymous"` when disabled).
  - `RateDecision(allowed: bool, retry_after_seconds: int)`; `RateLimiter(redis: Redis | None, per_minute: int, clock: Callable[[], float] = time.time, op_timeout: float = 0.1)`, `async check(key_id: str, cost: int = 1) -> RateDecision`.
  - `AppState` gains `auth: ApiKeyAuth`, `rate_limiter: RateLimiter`.
  - Settings gains `auth_enabled: bool = True`, `api_key_hashes: str = ""` (comma-separated), `rate_limit_per_minute: int = 6000`, property `api_key_hash_list`.

- [ ] **Step 1: Write failing unit tests**

`tests/api/test_rate_limiter.py`:
```python
from fakeredis import FakeAsyncRedis

from email_validation.api.security import ApiKeyAuth, RateLimiter, hash_api_key
from tests.fakes import BrokenRedis


class Clock:
    def __init__(self) -> None:
        self.now = 1_700_000_000.0

    def __call__(self) -> float:
        return self.now


def test_hash_api_key() -> None:
    assert hash_api_key("test-key") == (
        "62af8704764faf8ea82fc61ce9c4c3908b6cb97d463a634e9e587d7c885db0ef"
    )


def test_auth_identify() -> None:
    auth = ApiKeyAuth([hash_api_key("k1")])
    assert auth.identify("k1") == hash_api_key("k1")[:12]
    assert auth.identify("wrong") is None
    assert auth.identify(None) is None
    assert auth.identify("") is None


def test_auth_disabled() -> None:
    assert ApiKeyAuth([], enabled=False).identify(None) == "anonymous"


async def test_token_bucket() -> None:
    clock = Clock()
    limiter = RateLimiter(FakeAsyncRedis(), per_minute=3, clock=clock)
    for _ in range(3):
        assert (await limiter.check("k")).allowed
    denied = await limiter.check("k")
    assert denied.allowed is False
    assert denied.retry_after_seconds == 20
    clock.now += 20
    assert (await limiter.check("k")).allowed


async def test_keys_are_independent() -> None:
    limiter = RateLimiter(FakeAsyncRedis(), per_minute=1, clock=Clock())
    assert (await limiter.check("a")).allowed
    assert (await limiter.check("b")).allowed
    assert not (await limiter.check("a")).allowed


async def test_cost_consumes_multiple_tokens() -> None:
    limiter = RateLimiter(FakeAsyncRedis(), per_minute=10, clock=Clock())
    assert (await limiter.check("k", cost=8)).allowed
    assert not (await limiter.check("k", cost=3)).allowed
    assert (await limiter.check("k", cost=2)).allowed


async def test_rate_limiter_fail_open() -> None:
    limiter = RateLimiter(BrokenRedis(), per_minute=1)  # type: ignore[arg-type]
    for _ in range(5):
        assert (await limiter.check("k")).allowed


async def test_rate_limiter_without_redis() -> None:
    limiter = RateLimiter(None, per_minute=1)
    for _ in range(5):
        assert (await limiter.check("k")).allowed
```

`tests/api/test_security.py`:
```python
from typing import Any

import httpx

from email_validation.api.app import create_app
from email_validation.api.security import hash_api_key
from email_validation.api.settings import Settings
from tests.fakes import FakeDnsBackend


async def test_missing_key_is_401(client: httpx.AsyncClient) -> None:
    resp = await client.post(
        "/v1/validate", json={"email": "a@example.com"}, headers={"X-API-Key": ""}
    )
    assert resp.status_code == 401


async def test_wrong_key_is_401(client: httpx.AsyncClient) -> None:
    resp = await client.post(
        "/v1/validate", json={"email": "a@example.com"}, headers={"X-API-Key": "nope"}
    )
    assert resp.status_code == 401


async def test_health_needs_no_key(client: httpx.AsyncClient) -> None:
    assert (await client.get("/healthz", headers={"X-API-Key": ""})).status_code == 200


async def test_rate_limit_429(dns: FakeDnsBackend, redis: Any) -> None:
    settings = Settings(
        _env_file=None, api_key_hashes=hash_api_key("k"), rate_limit_per_minute=2
    )
    app = create_app(settings, dns_backend=dns, redis_client=redis)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test", headers={"X-API-Key": "k"}
    ) as c:
        codes = [
            (await c.post("/v1/validate", json={"email": "a@example.com"})).status_code
            for _ in range(3)
        ]
        denied = await c.post("/v1/validate", json={"email": "a@example.com"})
    assert codes == [200, 200, 429]
    assert int(denied.headers["Retry-After"]) >= 1


async def test_batch_cost_counts_emails(dns: FakeDnsBackend, redis: Any) -> None:
    settings = Settings(
        _env_file=None, api_key_hashes=hash_api_key("k"), rate_limit_per_minute=5
    )
    app = create_app(settings, dns_backend=dns, redis_client=redis)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test", headers={"X-API-Key": "k"}
    ) as c:
        ok = await c.post("/v1/validate/batch", json={"emails": ["a@example.com"] * 4})
        denied = await c.post("/v1/validate/batch", json={"emails": ["a@example.com"] * 2})
    assert ok.status_code == 200
    assert denied.status_code == 429
```

- [ ] **Step 2: Update fixtures for auth**

In `tests/api/conftest.py`, replace the `settings` and `client` fixtures:
```python
from email_validation.api.security import hash_api_key

TEST_KEY = "test-key"


@pytest.fixture
def settings() -> Settings:
    return Settings(_env_file=None, redis_url=None, api_key_hashes=hash_api_key(TEST_KEY))


@pytest.fixture
async def client(
    settings: Settings, dns: FakeDnsBackend, redis: Any
) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(settings, dns_backend=dns, redis_client=redis)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test", headers={"X-API-Key": TEST_KEY}
    ) as c:
        yield c
```
Also add `headers={"X-API-Key": "test-key"}` to the `httpx.AsyncClient(...)` in `tests/api/test_validate.py::test_validate_with_broken_redis`.

- [ ] **Step 3: Run tests to verify they fail**

Run: `uv run pytest tests/api -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'email_validation.api.security'`

- [ ] **Step 4: Implement security module**

`src/email_validation/api/security.py`:
```python
from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import math
import sys
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from redis.asyncio import Redis
from redis.exceptions import RedisError

from email_validation.core.metrics import RATE_LIMIT_ERRORS_TOTAL, RATE_LIMIT_REJECTIONS_TOTAL

logger = logging.getLogger(__name__)


def hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


class ApiKeyAuth:
    def __init__(self, hashes: Iterable[str], enabled: bool = True) -> None:
        self._hashes = tuple(h.strip().lower() for h in hashes if h.strip())
        self._enabled = enabled

    def identify(self, presented: str | None) -> str | None:
        """Return a non-secret key id for a valid key, else None."""
        if not self._enabled:
            return "anonymous"
        if not presented:
            return None
        digest = hash_api_key(presented)
        match: str | None = None
        for candidate in self._hashes:  # compare against all: constant work per request
            if hmac.compare_digest(digest, candidate):
                match = candidate
        return match[:12] if match else None


# Token bucket. KEYS[1]=bucket; ARGV: capacity, refill tokens per ms, now ms, cost.
_TOKEN_BUCKET_LUA = """
local capacity = tonumber(ARGV[1])
local refill = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local cost = tonumber(ARGV[4])
local data = redis.call('HMGET', KEYS[1], 'tokens', 'ts')
local tokens = tonumber(data[1]) or capacity
local ts = tonumber(data[2]) or now
tokens = math.min(capacity, tokens + math.max(0, now - ts) * refill)
local allowed = 0
local retry_ms = 0
if tokens >= cost then
  tokens = tokens - cost
  allowed = 1
else
  retry_ms = math.ceil((cost - tokens) / refill)
end
redis.call('HSET', KEYS[1], 'tokens', tostring(tokens), 'ts', tostring(now))
redis.call('PEXPIRE', KEYS[1], math.ceil(capacity / refill) + 1000)
return {allowed, retry_ms}
"""


@dataclass(frozen=True)
class RateDecision:
    allowed: bool
    retry_after_seconds: int = 0


class RateLimiter:
    def __init__(
        self,
        redis: Redis | None,
        per_minute: int,
        clock: Callable[[], float] = time.time,
        op_timeout: float = 0.1,
    ) -> None:
        self._redis = redis
        self._capacity = per_minute
        self._refill_per_ms = per_minute / 60_000
        self._clock = clock
        self._op_timeout = op_timeout

    async def check(self, key_id: str, cost: int = 1) -> RateDecision:
        if self._redis is None or self._capacity <= 0:
            return RateDecision(True)
        now_ms = int(self._clock() * 1000)
        try:
            async with asyncio.timeout(self._op_timeout):
                allowed, retry_ms = await self._redis.eval(  # type: ignore[misc]
                    _TOKEN_BUCKET_LUA,
                    1,
                    f"rl:v1:{key_id}",
                    self._capacity,
                    repr(self._refill_per_ms),
                    now_ms,
                    cost,
                )
        except (RedisError, OSError, TimeoutError) as exc:
            RATE_LIMIT_ERRORS_TOTAL.inc()
            logger.warning("rate limiter unavailable, allowing request: %s", exc)
            return RateDecision(True)
        if int(allowed) == 1:
            return RateDecision(True)
        RATE_LIMIT_REJECTIONS_TOTAL.inc()
        return RateDecision(False, max(1, math.ceil(int(retry_ms) / 1000)))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: python -m email_validation.api.security <api-key>")
    print(hash_api_key(sys.argv[1]))
```

- [ ] **Step 5: Wire into settings, state, routes**

In `settings.py`, add fields (after `batch_concurrency`) and property:
```python
    auth_enabled: bool = True
    api_key_hashes: str = ""  # comma-separated SHA-256 hex digests
    rate_limit_per_minute: int = 6000

    @property
    def api_key_hash_list(self) -> list[str]:
        return _csv(self.api_key_hashes)
```

In `state.py`: import `from email_validation.api.security import ApiKeyAuth, RateLimiter`; add fields to `AppState` after `owns_redis`:
```python
    auth: ApiKeyAuth
    rate_limiter: RateLimiter
```
and change the `return` of `build_state` to:
```python
    auth = ApiKeyAuth(settings.api_key_hash_list, enabled=settings.auth_enabled)
    rate_limiter = RateLimiter(redis, settings.rate_limit_per_minute)
    return AppState(
        settings, validator, resolver, registry, redis, owns_redis, auth, rate_limiter
    )
```

In `routes.py`, add imports and dependencies, and change the two POST handlers:
```python
from fastapi import Depends, Security
from fastapi.security import APIKeyHeader

from email_validation.api.state import AppState

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def authenticate(
    request: Request, api_key: str | None = Security(_api_key_header)
) -> str:
    key_id = get_state(request).auth.identify(api_key)
    if key_id is None:
        raise HTTPException(
            401, "invalid or missing API key", headers={"WWW-Authenticate": "ApiKey"}
        )
    return key_id


async def _enforce_rate_limit(state: AppState, key_id: str, cost: int) -> None:
    decision = await state.rate_limiter.check(key_id, cost)
    if not decision.allowed:
        raise HTTPException(
            429, "rate limit exceeded", headers={"Retry-After": str(decision.retry_after_seconds)}
        )


@router.post("/v1/validate", response_model=ValidationResponse)
async def validate(
    body: ValidateRequest, request: Request, key_id: str = Depends(authenticate)
) -> ValidationResponse:
    state = get_state(request)
    await _enforce_rate_limit(state, key_id, 1)
    policy = state.validator.policy.with_overrides(**body.options.model_dump())
    result = await state.validator.validate(body.email, policy)
    return ValidationResponse.from_result(result)


@router.post("/v1/validate/batch", response_model=BatchResponse)
async def validate_batch(
    body: BatchRequest, request: Request, key_id: str = Depends(authenticate)
) -> BatchResponse:
    state = get_state(request)
    if len(body.emails) > state.settings.batch_max:
        raise HTTPException(413, f"batch exceeds {state.settings.batch_max} emails")
    if body.emails:
        await _enforce_rate_limit(state, key_id, len(body.emails))
    policy = state.validator.policy.with_overrides(**body.options.model_dump())
    results = await state.validator.validate_many(
        body.emails, policy, concurrency=state.settings.batch_concurrency
    )
    return BatchResponse(results=[ValidationResponse.from_result(r) for r in results])
```

- [ ] **Step 6: Run tests**

Run: `uv run pytest -v && uv run ruff check . && uv run mypy`
Expected: all PASS, no errors. If `test_token_bucket` fails only under fakeredis because of Lua number formatting, verify with the integration test below against real Redis before changing the script.

- [ ] **Step 7: Integration test against real Redis**

`tests/integration/test_rate_limiter_redis.py`:
```python
import pytest
from redis.asyncio import Redis

from email_validation.api.security import RateLimiter

pytestmark = pytest.mark.integration


async def test_token_bucket_on_real_redis(redis_client: Redis) -> None:
    now = [1_700_000_000.0]
    limiter = RateLimiter(redis_client, per_minute=3, clock=lambda: now[0])
    assert [(await limiter.check("k")).allowed for _ in range(4)] == [True, True, True, False]
    now[0] += 20
    assert (await limiter.check("k")).allowed
    assert 0 < await redis_client.pttl("rl:v1:k") <= 61_000
```

Run: `uv run pytest -m integration -v`
Expected: PASS with Docker, SKIPPED without.

- [ ] **Step 8: Commit**

```bash
git add src/email_validation/api tests/api tests/integration
git commit -m "feat(api): add API key auth and Redis token-bucket rate limiting"
```

---

### Task 10: Observability — JSON logs, request id, metrics endpoint, OpenTelemetry

**Files:**
- Create: `src/email_validation/api/observability.py`
- Modify: `src/email_validation/api/settings.py` (`otel_enabled`), `src/email_validation/api/app.py` (middleware, logging, otel), `src/email_validation/api/routes.py` (`/metrics`, result logging)
- Test: `tests/api/test_observability.py`

**Interfaces:**
- Consumes: `create_app`, routes (Tasks 8–9), `ValidationResult`.
- Produces: `request_id_var: ContextVar[str | None]`, `JsonFormatter`, `configure_logging(level: str) -> None`, `RequestIdMiddleware(app)`, `setup_otel(app: FastAPI) -> None`, `email_fingerprint(value: str) -> str`; `GET /metrics` (no auth).

- [ ] **Step 1: Write failing tests**

`tests/api/test_observability.py`:
```python
import json
import logging

import httpx
import pytest

from email_validation.api.observability import JsonFormatter, email_fingerprint, request_id_var


async def test_metrics_endpoint(client: httpx.AsyncClient) -> None:
    await client.post("/v1/validate", json={"email": "a@example.com"})
    resp = await client.get("/metrics", headers={"X-API-Key": ""})
    assert resp.status_code == 200
    assert "validations_total" in resp.text
    assert "dns_lookup_seconds" in resp.text


async def test_request_id_echoed(client: httpx.AsyncClient) -> None:
    resp = await client.get("/healthz", headers={"X-Request-ID": "abc-123"})
    assert resp.headers["X-Request-ID"] == "abc-123"


async def test_request_id_generated_when_missing_or_unsafe(client: httpx.AsyncClient) -> None:
    generated = (await client.get("/healthz")).headers["X-Request-ID"]
    assert len(generated) == 32
    unsafe = await client.get("/healthz", headers={"X-Request-ID": "bad value;drop"})
    assert unsafe.headers["X-Request-ID"] != "bad value;drop"
    assert len(unsafe.headers["X-Request-ID"]) == 32


async def test_logs_never_contain_raw_email(
    client: httpx.AsyncClient, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    email = "secret.person+tag@example.com"
    await client.post("/v1/validate", json={"email": email})
    await client.post("/v1/validate/batch", json={"emails": [email]})
    records = [r for r in caplog.records if r.name.startswith("email_validation")]
    assert records, "expected validation log records"
    for record in records:
        rendered = JsonFormatter().format(record)
        assert "secret.person" not in rendered
    single = next(r for r in records if r.getMessage() == "email validated")
    assert single.email_sha256 == email_fingerprint(email)  # type: ignore[attr-defined]
    assert single.domain == "example.com"  # type: ignore[attr-defined]


def test_json_formatter_includes_request_id() -> None:
    token = request_id_var.set("rid-1")
    try:
        record = logging.LogRecord("email_validation.x", logging.INFO, __file__, 1, "hi", (), None)
        record.domain = "example.com"
        payload = json.loads(JsonFormatter().format(record))
    finally:
        request_id_var.reset(token)
    assert payload["request_id"] == "rid-1"
    assert payload["message"] == "hi"
    assert payload["domain"] == "example.com"
    assert payload["level"] == "INFO"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/api/test_observability.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'email_validation.api.observability'`

- [ ] **Step 3: Implement observability module**

`src/email_validation/api/observability.py`:
```python
from __future__ import annotations

import hashlib
import json
import logging
import re
import uuid
from contextvars import ContextVar
from typing import Any

from fastapi import FastAPI
from starlette.types import ASGIApp, Message, Receive, Scope, Send

logger = logging.getLogger(__name__)

request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)

_SAFE_REQUEST_ID = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_EXTRA_FIELDS = ("domain", "email_sha256", "status", "reasons", "step", "count")


def email_fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": request_id_var.get(),
        }
        for field in _EXTRA_FIELDS:
            if hasattr(record, field):
                payload[field] = getattr(record, field)
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, default=str)


def configure_logging(level: str) -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level.upper())


class RequestIdMiddleware:
    """Pure ASGI middleware: propagate or generate X-Request-ID."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        incoming = dict(scope["headers"]).get(b"x-request-id", b"").decode("latin-1")
        request_id = incoming if _SAFE_REQUEST_ID.match(incoming) else uuid.uuid4().hex
        token = request_id_var.set(request_id)

        async def send_with_id(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.append((b"x-request-id", request_id.encode("latin-1")))
                message["headers"] = headers
            await send(message)

        try:
            await self.app(scope, receive, send_with_id)
        finally:
            request_id_var.reset(token)


def setup_otel(app: FastAPI) -> None:
    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError:
        logger.warning("EV_OTEL_ENABLED is set but the 'otel' extra is not installed")
        return
    provider = TracerProvider(resource=Resource.create({"service.name": "email-validation"}))
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
    trace.set_tracer_provider(provider)
    FastAPIInstrumentor.instrument_app(app)
```
(The OTLP exporter reads the standard `OTEL_EXPORTER_OTLP_ENDPOINT` env var.)

- [ ] **Step 4: Wire into settings, app, routes**

`settings.py` — add field: `otel_enabled: bool = False`.

`app.py` — add imports:
```python
from email_validation.api.observability import (
    RequestIdMiddleware,
    configure_logging,
    setup_otel,
)
```
At the start of `lifespan` (before creating the reload task) add `configure_logging(settings.log_level)` (logging is configured in lifespan, not in `create_app`, so tests using `ASGITransport` keep pytest's log capture). After `app.include_router(router)` add:
```python
    app.add_middleware(RequestIdMiddleware)
    if settings.otel_enabled:
        setup_otel(app)
```

`routes.py` — add imports and logger:
```python
import logging

from fastapi.responses import Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from email_validation.api.observability import email_fingerprint
from email_validation.core.models import ValidationResult

logger = logging.getLogger(__name__)


def _log_result(result: ValidationResult, level: int = logging.INFO) -> None:
    logger.log(
        level,
        "email validated",
        extra={
            "domain": result.ascii_domain,
            "email_sha256": email_fingerprint(result.input),
            "status": result.status.value,
            "reasons": [r.value for r in result.reasons],
        },
    )


@router.get("/metrics", include_in_schema=False)
async def metrics() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
```
In `validate`, call `_log_result(result)` before returning. In `validate_batch`, after computing `results`:
```python
    for r in results:
        _log_result(r, logging.DEBUG)
    logger.info("batch validated", extra={"count": len(results)})
```

- [ ] **Step 5: Run tests**

Run: `uv run pytest -v && uv run ruff check . && uv run mypy`
Expected: all PASS, no errors

- [ ] **Step 6: Commit**

```bash
git add src/email_validation/api tests/api
git commit -m "feat(api): add JSON logging, request ids, Prometheus endpoint and optional OTel"
```

---

### Task 11: Packaging, deployment, smoke and load tests, README

**Files:**
- Create: `Dockerfile`, `.dockerignore`, `docker-compose.yml`
- Create: `deploy/k8s/deployment.yaml`, `deploy/k8s/service.yaml`, `deploy/k8s/hpa.yaml`
- Create: `perf/locustfile.py`
- Create: `tests/smoke/__init__.py` (empty), `tests/smoke/test_real_dns.py`
- Create: `README.md`

**Interfaces:**
- Consumes: `create_app` (factory), `DnspythonBackend`, `MxResolver`, `EmailValidator`, `DisposableRegistry`.
- Produces: container image entrypoint `uvicorn email_validation.api.app:create_app --factory --host 0.0.0.0 --port 8000`.

- [ ] **Step 1: Smoke tests against real DNS**

`tests/smoke/test_real_dns.py`:
```python
import uuid

import pytest

from email_validation.core import (
    DisposableRegistry,
    DnspythonBackend,
    EmailValidator,
    MxResolver,
    Status,
)
from email_validation.core.dns.resolver import MxOutcome

pytestmark = pytest.mark.network


async def test_gmail_has_mx() -> None:
    result = await MxResolver(DnspythonBackend()).lookup("gmail.com")
    assert result.outcome is MxOutcome.OK
    assert any("google" in host for host in result.hosts)


async def test_random_domain_is_nxdomain() -> None:
    result = await MxResolver(DnspythonBackend()).lookup(f"ev-smoke-{uuid.uuid4().hex}.com")
    assert result.outcome is MxOutcome.NXDOMAIN


async def test_pipeline_end_to_end() -> None:
    validator = EmailValidator(
        resolver=MxResolver(DnspythonBackend()), registry=DisposableRegistry.from_bundled()
    )
    result = await validator.validate("someone+tag@gmail.com")
    assert result.status is Status.VALID
    assert result.tag == "tag"
```

Run: `uv run pytest -m network -v`
Expected: PASS (requires internet access)

- [ ] **Step 2: Load test script**

`perf/locustfile.py`:
```python
"""Load test. Run: uv run locust -f perf/locustfile.py --host http://localhost:8000

Report p95 for "validate[hot]" (cache warm, target < 20 ms) and "validate[cold]"
(uncached random domains, bounded by DNS lifetime 4 s).
"""

import os
import random
import uuid

from locust import HttpUser, between, task

API_KEY = os.environ.get("EV_LOAD_API_KEY", "dev-key")
HOT = ["user+news@gmail.com", "someone@outlook.com", "a.b@yahoo.com", "x@icloud.com"]


class ValidateUser(HttpUser):
    wait_time = between(0, 0.01)

    @task(9)
    def hot(self) -> None:
        self.client.post(
            "/v1/validate",
            json={"email": random.choice(HOT)},
            headers={"X-API-Key": API_KEY},
            name="validate[hot]",
        )

    @task(1)
    def cold(self) -> None:
        self.client.post(
            "/v1/validate",
            json={"email": f"u@{uuid.uuid4().hex[:12]}.com"},
            headers={"X-API-Key": API_KEY},
            name="validate[cold]",
        )
```

- [ ] **Step 3: Container and compose**

`.dockerignore`:
```
.venv
.git
.pytest_cache
.mypy_cache
.ruff_cache
tests
perf
docs
```

`Dockerfile`:
```dockerfile
FROM python:3.12-slim AS build
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv
WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
COPY pyproject.toml uv.lock .python-version ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
COPY README.md ./
RUN uv sync --frozen --no-dev

FROM python:3.12-slim
RUN useradd --system --uid 10001 app
WORKDIR /app
COPY --from=build /app /app
ENV PATH="/app/.venv/bin:$PATH" PYTHONUNBUFFERED=1
USER 10001
EXPOSE 8000
CMD ["uvicorn", "email_validation.api.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
```

`docker-compose.yml` (local dev; API key is `dev-key`):
```yaml
services:
  redis:
    image: redis:7-alpine
    ports: ["6379:6379"]
  app:
    build: .
    ports: ["8000:8000"]
    environment:
      EV_REDIS_URL: redis://redis:6379/0
      # sha256("dev-key") — local development only
      EV_API_KEY_HASHES: 7e9f8fd111802be56c379d597842e29b2cebd35ff2133d431a49fa556a18704e
      EV_LOG_LEVEL: INFO
    depends_on: [redis]
```

- [ ] **Step 4: Kubernetes manifests**

`deploy/k8s/deployment.yaml` (set `image` to your registry path at deploy time; `ev-secrets` must hold `EV_REDIS_URL` and `EV_API_KEY_HASHES`):
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: email-validation
  labels: {app: email-validation}
spec:
  replicas: 3
  selector:
    matchLabels: {app: email-validation}
  template:
    metadata:
      labels: {app: email-validation}
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "8000"
        prometheus.io/path: /metrics
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
      containers:
        - name: app
          image: email-validation:0.1.0
          ports: [{containerPort: 8000, name: http}]
          envFrom:
            - secretRef: {name: ev-secrets}
          env:
            - {name: EV_LOG_LEVEL, value: INFO}
            - {name: EV_DISPOSABLE_URL, value: "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/main/disposable_email_blocklist.conf"}
          resources:
            requests: {cpu: 250m, memory: 256Mi}
            limits: {cpu: "1", memory: 512Mi}
          livenessProbe:
            httpGet: {path: /healthz, port: http}
            periodSeconds: 10
          readinessProbe:
            httpGet: {path: /readyz, port: http}
            periodSeconds: 5
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
```

`deploy/k8s/service.yaml`:
```yaml
apiVersion: v1
kind: Service
metadata:
  name: email-validation
spec:
  selector: {app: email-validation}
  ports: [{name: http, port: 80, targetPort: http}]
```

`deploy/k8s/hpa.yaml`:
```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: email-validation
spec:
  scaleTargetRef: {apiVersion: apps/v1, kind: Deployment, name: email-validation}
  minReplicas: 3
  maxReplicas: 20
  metrics:
    - type: Resource
      resource:
        name: cpu
        target: {type: Utilization, averageUtilization: 70}
```

- [ ] **Step 5: README**

`README.md`:
````markdown
# Email Validation Service

Async Python library + REST API validating email addresses: RFC 5322/5321/6531 syntax
(incl. `user+tag`), IDN (IDNA2008), DNS MX (Null MX, A/AAAA fallback), disposable domains.
Design: `docs/superpowers/specs/2026-09-24-email-validation-service-design.md`.

## Library

```python
from email_validation.core import (
    DisposableRegistry, DnspythonBackend, EmailValidator, MxResolver, MemoryTTLCache, TieredCache,
)

validator = EmailValidator(
    resolver=MxResolver(DnspythonBackend(), cache=TieredCache(MemoryTTLCache())),
    registry=DisposableRegistry.from_bundled(),
)
result = await validator.validate("User+News@Bücher.de")
print(result.status, result.ascii_email, result.tag, result.mx_hosts)
```

## Service

```bash
uv sync
uv run python -m email_validation.api.security my-secret-key   # prints hash
EV_API_KEY_HASHES=<hash> uv run uvicorn email_validation.api.app:create_app --factory
curl -X POST localhost:8000/v1/validate -H "X-API-Key: my-secret-key" \
     -H "content-type: application/json" -d '{"email":"someone+tag@gmail.com"}'
```

Local stack with Redis: `docker compose up --build` (API key `dev-key`).

Result `status` is `valid`, `invalid` or `unknown` (temporary DNS failure — retry later,
do not reject the user). HTTP is 200 for every validation result.

## Configuration (env, prefix `EV_`)

| Variable | Default | |
|---|---|---|
| `EV_REDIS_URL` | unset | Shared L2 cache + rate limiting; service runs without it |
| `EV_API_KEY_HASHES` | empty | Comma-separated SHA-256 of API keys (auth on by default) |
| `EV_AUTH_ENABLED` | `true` | |
| `EV_RATE_LIMIT_PER_MINUTE` | `6000` | Per key; batch counts each email |
| `EV_DNS_NAMESERVERS` | system | Comma-separated |
| `EV_DNS_TIMEOUT` / `EV_DNS_LIFETIME` | `2.0` / `4.0` | Seconds |
| `EV_DISPOSABLE_ACTION` | `reject` | `reject`, `flag`, `off` |
| `EV_DISPOSABLE_URL` | unset | Remote list, reloaded every `EV_DISPOSABLE_RELOAD_SECONDS` (86400) |
| `EV_ALLOW_IMPLICIT_MX` | `true` | Accept domains with A/AAAA but no MX |
| `EV_ALLOW_SMTPUTF8` / `EV_ALLOW_QUOTED_LOCAL` / `EV_ALLOW_DOMAIN_LITERAL` | `true` / `false` / `false` | |
| `EV_BATCH_MAX` | `1000` | |
| `EV_OTEL_ENABLED` | `false` | Needs `uv sync --extra otel`; uses `OTEL_EXPORTER_OTLP_ENDPOINT` |

## Tests

```bash
uv run pytest                 # unit + API (offline)
uv run pytest -m integration  # needs Docker (real Redis)
uv run pytest -m network      # real DNS
uv run ruff check . && uv run mypy
uv run locust -f perf/locustfile.py --host http://localhost:8000
```
````

- [ ] **Step 6: Full verification**

Run: `uv run pytest -v && uv run ruff check . && uv run ruff format --check . && uv run mypy`
Expected: all unit/API tests PASS, no lint/format/type errors.

Run: `uv run pytest -m network -v`
Expected: 3 PASS (needs internet).

If Docker is available: `docker compose up --build -d`, then
`curl -s -X POST localhost:8000/v1/validate -H "X-API-Key: dev-key" -H "content-type: application/json" -d "{\"email\":\"someone+tag@gmail.com\"}"`
Expected: `"status":"valid"`; `curl -s localhost:8000/readyz` shows `"redis":"ok"`. Then run locust for 60 s with 50 users and record p95 for `validate[hot]` (target < 20 ms). `docker compose down`.
If Docker is not available (current dev machine), state that these steps were skipped.

- [ ] **Step 7: Commit**

```bash
git add Dockerfile .dockerignore docker-compose.yml deploy perf tests/smoke README.md
git commit -m "chore: add container, k8s manifests, smoke and load tests, README"
```
