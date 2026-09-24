# Email Validation Service — Thiết kế (v1)

- **Ngày:** 2026-09-24
- **Trạng thái:** Chờ review
- **Ngôn ngữ/Runtime:** Python 3.12, asyncio

## 1. Mục tiêu

Xây dựng dịch vụ xác thực email cấp doanh nghiệp:

1. Kiểm tra cú pháp theo RFC 5322 / RFC 5321, chấp nhận sub-addressing `user+tag`, hỗ trợ SMTPUTF8 (RFC 6531).
2. Hỗ trợ Tên miền quốc tế hóa (IDN) theo IDNA2008 (chuyển đổi U-label ↔ A-label/punycode).
3. Kiểm tra bản ghi DNS MX (kèm Null MX RFC 7505 và fallback A/AAAA theo RFC 5321 §5.1).
4. Chặn/gắn cờ domain email dùng một lần (disposable).

**Tiêu chí thành công**

- Phân loại đúng toàn bộ bộ test cú pháp/IDN/DNS trong mục 8.
- Lỗi DNS tạm thời không bao giờ khiến địa chỉ hợp lệ bị đánh `invalid` (trả `unknown`).
- Chạy nhiều replica phía sau load balancer; cache DNS dùng chung qua Redis; dịch vụ vẫn hoạt động khi Redis lỗi.
- p95 latency `POST /v1/validate` < 20 ms khi cache nóng; bị chặn trên bởi DNS lifetime (4 s) khi cache lạnh.

**Ngoài phạm vi v1:** SMTP mailbox probing (RCPT TO), role account (`admin@`, `info@`…), gợi ý sửa lỗi gõ (did-you-mean), xử lý bulk CSV qua job queue.

## 2. Quyết định kiến trúc

| Quyết định | Lựa chọn | Lý do |
|---|---|---|
| Hình thức phân phối | Thư viện lõi `core` + REST API FastAPI mỏng | Hệ thống khác gọi HTTP; code Python nội bộ import trực tiếp |
| Cú pháp & IDN | Bọc `email-validator` (`check_deliverability=False`) | Thư viện đã kiểm chứng, hỗ trợ RFC 5322/6531, IDNA2008 qua `idna` |
| DNS | Tự xây bằng `dnspython` (`dns.asyncresolver`) | Cần async, cache 2 tầng, single-flight, phân loại lỗi chi tiết |
| Mô hình concurrency | asyncio end-to-end | DNS là I/O-bound; đạt thông lượng cao trên ít process |
| Cache | L1 in-memory TTL-LRU + L2 Redis | Nhiều replica cần chia sẻ kết quả DNS |

Phụ thuộc chính: `email-validator`, `idna`, `dnspython`, `redis` (redis-py asyncio), `fastapi`, `uvicorn`, `pydantic`, `pydantic-settings`, `prometheus-client`. Phiên bản được pin trong lockfile (`uv.lock`).

## 3. Tổng quan kiến trúc

```
Client ──HTTP──► api/ (FastAPI)  ──►  core.EmailValidator (async pipeline, fail-fast)
                                        1. NormalizeStep   trim, Unicode NFC
                                        2. SyntaxStep      email-validator + ValidationPolicy
                                        3. IdnStep         A-label/U-label, tách base_local_part/tag
                                        4. DisposableStep  DisposableRegistry
                                        5. DnsMxStep       MxResolver
                                              └─ TieredCache: L1 MemoryTTLCache → L2 RedisCache → DNS
                                      ◄── ValidationResult
```

Địa chỉ sai cú pháp dừng ở bước 2 và không bao giờ tạo truy vấn DNS.

## 4. Cấu trúc module

```
src/email_validation/
├── core/                      # Không import bất kỳ thứ gì từ api/
│   ├── models.py              # ValidationResult, Status, Reason, ValidationContext
│   ├── policy.py              # ValidationPolicy
│   ├── pipeline.py            # EmailValidator
│   ├── steps/
│   │   ├── base.py            # Step Protocol, StepOutcome
│   │   ├── normalize.py
│   │   ├── syntax.py
│   │   ├── idn.py
│   │   ├── disposable.py
│   │   └── dns_mx.py
│   ├── dns/
│   │   ├── resolver.py        # MxResolver, MxLookupResult
│   │   └── cache.py           # Cache Protocol, MemoryTTLCache, RedisCache, TieredCache
│   └── disposable/
│       ├── registry.py        # DisposableRegistry
│       └── data/disposable_domains.txt
└── api/
    ├── app.py                 # create_app(), lifespan
    ├── routes.py
    ├── schemas.py
    ├── security.py            # API key, rate limit
    └── settings.py            # Settings (pydantic-settings, env prefix EV_)
```

## 5. Thành phần lõi

### 5.1 Models

```python
class Status(StrEnum):
    VALID = "valid"
    INVALID = "invalid"
    UNKNOWN = "unknown"

class Reason(StrEnum):            # Mã ổn định, là một phần của hợp đồng API
    SYNTAX_INVALID = "SYNTAX_INVALID"
    TOO_LONG = "TOO_LONG"
    IDN_INVALID = "IDN_INVALID"
    SMTPUTF8_NOT_ALLOWED = "SMTPUTF8_NOT_ALLOWED"
    DISPOSABLE = "DISPOSABLE"
    DOMAIN_NOT_FOUND = "DOMAIN_NOT_FOUND"
    DOMAIN_NO_MX = "DOMAIN_NO_MX"
    DOMAIN_NULL_MX = "DOMAIN_NULL_MX"
    DNS_TEMPORARY_FAILURE = "DNS_TEMPORARY_FAILURE"

@dataclass(frozen=True)
class ValidationResult:
    input: str
    status: Status
    reasons: tuple[Reason, ...]
    normalized: str | None        # dạng Unicode, domain lowercase
    ascii_email: str | None       # local@A-label; None nếu local-part non-ASCII
    local_part: str | None        # "user+tag"
    base_local_part: str | None   # "user"
    tag: str | None               # "tag" (None nếu không có '+')
    domain: str | None            # U-label, ví dụ "bücher.de"
    ascii_domain: str | None      # A-label, ví dụ "xn--bcher-kva.de"
    mx_hosts: tuple[str, ...]     # sắp xếp theo preference tăng dần
    implicit_mx: bool             # True nếu dựa vào A/AAAA fallback
    is_disposable: bool
```

`ValidationContext` là đối tượng có thể thay đổi, chứa input và các trường đang được điền dần; `pipeline` chuyển nó thành `ValidationResult` ở cuối.

### 5.2 ValidationPolicy

| Trường | Mặc định | Ý nghĩa |
|---|---|---|
| `allow_smtputf8` | `True` | Cho phép local-part Unicode (RFC 6531) |
| `allow_quoted_local` | `False` | Cho phép local-part dạng `"john doe"@x.com` |
| `allow_domain_literal` | `False` | Cho phép `user@[192.0.2.1]` |
| `subaddress_separator` | `"+"` | Ký tự tách tag; `None` để tắt tách |
| `check_dns` | `True` | Bật bước DNS MX |
| `allow_implicit_mx` | `True` | Chấp nhận domain không có MX nhưng có A/AAAA |
| `disposable_action` | `"reject"` | `"reject"` → invalid; `"flag"` → valid + `is_disposable=True`; `"off"` → bỏ qua |

Policy mặc định được nạp từ `Settings`; mỗi request API có thể ghi đè `check_dns` và `disposable_action`.

### 5.3 Pipeline & Step

```python
class Step(Protocol):
    name: str
    async def run(self, ctx: ValidationContext, policy: ValidationPolicy) -> StepOutcome: ...

@dataclass(frozen=True)
class StepOutcome:
    stop: bool = False                  # True → dừng pipeline
    status: Status | None = None        # status cuối khi stop=True
    reason: Reason | None = None

class EmailValidator:
    def __init__(self, policy: ValidationPolicy, resolver: MxResolver | None,
                 registry: DisposableRegistry | None, steps: Sequence[Step] | None = None): ...
    async def validate(self, email: str, policy: ValidationPolicy | None = None) -> ValidationResult: ...
    async def validate_many(self, emails: Sequence[str], concurrency: int = 100) -> list[ValidationResult]: ...
```

Nếu không step nào dừng pipeline, status là `valid`. Một ngoại lệ bất ngờ trong step được bắt ở pipeline, ghi log và trả `unknown` (không để lọt thành HTTP 500 cho một email).

### 5.4 Các step

- **NormalizeStep:** strip khoảng trắng, Unicode NFC. Từ chối input rỗng (`SYNTAX_INVALID`).
- **SyntaxStep:** gọi `email_validator.validate_email(..., check_deliverability=False, allow_smtputf8=..., allow_quoted_local=..., allow_domain_literal=...)`. Ánh xạ lỗi: vượt giới hạn độ dài (địa chỉ > 254, local-part > 64, nhãn domain > 63 octet) → `TOO_LONG`; lỗi IDNA → `IDN_INVALID`; local-part Unicode khi `allow_smtputf8=False` → `SMTPUTF8_NOT_ALLOWED`; còn lại → `SYNTAX_INVALID`. Tất cả là `invalid`, dừng pipeline.
- **IdnStep:** điền `domain` (U-label), `ascii_domain` (A-label), `ascii_email`; tách `local_part` tại dấu `subaddress_separator` **đầu tiên**: `a+b+c@x` → base `a`, tag `b+c`. Local-part bắt đầu bằng `+` (`+tag@x`) không tách (base = toàn bộ, tag = None).
- **DisposableStep:** `registry.contains(ascii_domain)` khớp domain và mọi domain cha (`x.mailinator.com` khớp `mailinator.com`). Áp dụng `disposable_action`.
- **DnsMxStep:** bỏ qua khi `check_dns=False` hoặc domain literal. Gọi `resolver.lookup(ascii_domain)` và ánh xạ kết quả như mục 6.1.

## 6. DNS & Cache

### 6.1 MxResolver

```python
class MxOutcome(StrEnum):
    OK = "ok"; NULL_MX = "null_mx"; NO_MX = "no_mx"; NXDOMAIN = "nxdomain"; TEMP_FAIL = "temp_fail"

@dataclass(frozen=True)
class MxLookupResult:
    outcome: MxOutcome
    hosts: tuple[str, ...]
    implicit: bool
    ttl: int

class MxResolver:
    async def lookup(self, ascii_domain: str) -> MxLookupResult: ...
```

| Phản hồi DNS | MxLookupResult | Kết quả validation |
|---|---|---|
| MX có bản ghi | `OK`, hosts sắp theo preference | `valid` |
| Đúng một MX `0 .` | `NULL_MX` | `invalid`, `DOMAIN_NULL_MX` |
| NoAnswer cho MX, có A/AAAA | `OK`, hosts=`(domain,)`, implicit=True | `valid` nếu `allow_implicit_mx`, ngược lại `invalid`, `DOMAIN_NO_MX` |
| NoAnswer cho MX và A/AAAA | `NO_MX` | `invalid`, `DOMAIN_NO_MX` |
| NXDOMAIN | `NXDOMAIN` | `invalid`, `DOMAIN_NOT_FOUND` |
| Timeout / SERVFAIL / NoNameservers | `TEMP_FAIL` | `unknown`, `DNS_TEMPORARY_FAILURE` |

Cấu hình resolver: `nameservers` (mặc định: resolver hệ thống), `timeout=2.0` s mỗi truy vấn, `lifetime=4.0` s tổng, `max_concurrency=500` (giới hạn bằng `asyncio.Semaphore`). Truy vấn A và AAAA của bước fallback chạy song song.

### 6.2 Cache

```python
class Cache(Protocol):
    async def get(self, key: str) -> MxLookupResult | None: ...
    async def set(self, key: str, value: MxLookupResult, ttl: int) -> None: ...
```

- **Key:** `mx:v1:{ascii_domain}`. Giá trị trong Redis được serialize JSON.
- **TTL theo outcome:**

| Outcome | L1 (MemoryTTLCache, tối đa 100 000 mục) | L2 (RedisCache) |
|---|---|---|
| `OK`, `NULL_MX` | `min(dns_ttl, 300)` | `clamp(dns_ttl, 60, 86400)` |
| `NO_MX`, `NXDOMAIN` | 300 | 300 |
| `TEMP_FAIL` | 30 | 30 |

- **TieredCache:** đọc L1 → L2 (trúng L2 thì ghi lại L1) → resolver (ghi cả L1 và L2).
- **Single-flight:** trong một process, các lookup đồng thời cho cùng domain chờ chung một `asyncio.Future`. Không dùng khóa phân tán giữa replica.
- **Redis lỗi:** mọi lỗi kết nối/timeout của Redis (timeout thao tác 50 ms) bị bắt, tăng metric `cache_errors_total`, tiếp tục như cache miss. Dịch vụ không phụ thuộc cứng vào Redis.

## 7. Disposable registry

- Lưu `frozenset[str]` các A-label domain.
- Nguồn: file đóng gói `data/disposable_domains.txt` (luôn nạp) + URL tùy chọn `EV_DISPOSABLE_URL` (mỗi dòng một domain, bỏ dòng trống và dòng bắt đầu bằng `#`).
- Reload nền mỗi `EV_DISPOSABLE_RELOAD_SECONDS` (mặc định 86400) bằng cách tạo set mới rồi gán thay thế (atomic swap). Tải lỗi → giữ set cũ, log cảnh báo.
- Allowlist tùy chọn `EV_DISPOSABLE_ALLOWLIST` để loại trừ domain khỏi danh sách.

## 8. REST API

### 8.1 Endpoint

| Method | Path | Mô tả |
|---|---|---|
| POST | `/v1/validate` | Xác thực một email |
| POST | `/v1/validate/batch` | Xác thực tối đa 1 000 email |
| GET | `/healthz` | Liveness, luôn 200 nếu process chạy |
| GET | `/readyz` | Readiness: registry đã nạp; Redis ping (Redis lỗi → vẫn 200 nhưng báo `redis: "degraded"`) |
| GET | `/metrics` | Prometheus |

**Request**

```json
{ "email": "User+News@Bücher.de", "options": { "check_dns": true, "disposable_action": "reject" } }
```

**Response 200**

```json
{
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
  "mx_hosts": ["mx.example.net"],
  "implicit_mx": false,
  "is_disposable": false
}
```

Local-part giữ nguyên chữ hoa/thường (RFC 5321 coi local-part phân biệt hoa thường); chỉ domain được lowercase.

Batch: `{"emails": [...], "options": {...}}` → `{"results": [ ... ]}` cùng thứ tự input. Chạy song song với semaphore (`EV_BATCH_CONCURRENCY`, mặc định 100); các email cùng domain dùng chung lookup nhờ single-flight.

### 8.2 Mã HTTP

- `200`: mọi kết quả validation (kể cả `invalid`/`unknown`).
- `401`: thiếu/sai API key. `413`/`422`: batch > 1 000 hoặc body sai schema. `429`: vượt rate limit (kèm `Retry-After`).

### 8.3 Bảo mật

- Header `X-API-Key`; server lưu SHA-256 của các key hợp lệ trong `EV_API_KEY_HASHES`, so sánh bằng `hmac.compare_digest`.
- Rate limit token bucket theo key trên Redis (`EV_RATE_LIMIT_PER_MINUTE`, mặc định 6 000; batch tính theo số email). Redis lỗi → không áp rate limit (fail-open) và tăng metric.
- Không log email đầy đủ: chỉ log domain và SHA-256 của địa chỉ.

## 9. Vận hành

- **Cấu hình:** `pydantic-settings`, prefix `EV_` (ví dụ `EV_REDIS_URL`, `EV_DNS_NAMESERVERS`, `EV_DNS_TIMEOUT`, `EV_DNS_LIFETIME`, `EV_DNS_MAX_CONCURRENCY`).
- **Metrics:** `validations_total{status,reason}`, `dns_lookup_seconds` (histogram), `dns_lookups_total{outcome}`, `cache_hits_total{tier}`, `cache_errors_total`, `rate_limit_rejections_total`.
- **Logging:** JSON có `request_id` (header `X-Request-ID` hoặc tự sinh). OpenTelemetry tracing bật được qua `EV_OTEL_ENABLED`.
- **Triển khai:** Dockerfile multi-stage chạy `uvicorn email_validation.api.app:create_app --factory`, user không phải root. Manifest Kubernetes: Deployment (liveness `/healthz`, readiness `/readyz`), Service, HPA theo CPU. `docker-compose.yml` cho local: app + Redis.
- **Công cụ phát triển:** `uv`, `ruff` (lint + format), `mypy --strict`, `pytest`, `pytest-asyncio`.

## 10. Kiểm thử

- **Unit (offline, mặc định chạy):**
  - Bảng test cú pháp: hợp lệ (`user+tag@example.com`, `a.b-c_d@sub.example.co.uk`), không hợp lệ (`a..b@x.com`, `.a@x.com`, `a@x`, `a@-x.com`, thiếu `@`), quoted local-part theo policy, giới hạn độ dài 64/254/63.
  - Sub-addressing: `a+b+c@x` → base `a`, tag `b+c`; `+tag@x` không tách; separator `None`.
  - IDN: `user@bücher.de`, `user@例え.jp`, domain đã ở dạng `xn--`, nhãn vi phạm IDNA2008 → `IDN_INVALID`; local-part Unicode với `allow_smtputf8` bật/tắt.
  - MxResolver với fake resolver lập trình được: MX nhiều bản ghi (sắp xếp), Null MX, NoAnswer → A/AAAA, NoAnswer toàn bộ, NXDOMAIN, Timeout, SERVFAIL.
  - Cache: TTL hết hạn, TTL theo outcome, L2 trúng ghi lại L1, single-flight (N lookup đồng thời → 1 truy vấn), Redis ném lỗi → vẫn trả kết quả.
  - DisposableRegistry: khớp domain cha, allowlist, reload lỗi giữ set cũ.
  - Pipeline: fail-fast (syntax lỗi → resolver không được gọi), ngoại lệ trong step → `unknown`.
- **Integration:** Redis thật qua `testcontainers`; API qua `httpx.AsyncClient` (auth, 401/422/429, batch giữ thứ tự).
- **Smoke (`@pytest.mark.network`, không chạy mặc định):** DNS thật cho `gmail.com` (có MX) và domain `.invalid` (NXDOMAIN).
- **Hiệu năng:** kịch bản `locust` đo p95 khi cache nóng và cache lạnh.
