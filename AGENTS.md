# AGENTS.md

Dịch vụ xác thực email gồm một thư viện Python async (`email_validation.core`) và một lớp
FastAPI mỏng (`email_validation.api`). Kiểm tra cú pháp RFC 5322/5321/6531 (kể cả `user+tag`),
IDN (IDNA2008), DNS MX (Null MX, dự phòng A/AAAA) và domain email dùng một lần (disposable).
Chạy nhiều replica dùng chung Redis. Thiết kế:
`docs/superpowers/specs/2026-09-24-email-validation-service-design.md`.

## Lệnh thường dùng

Python 3.12 qua `uv` (`.python-version`). Luôn chạy công cụ bằng `uv run`.

```bash
uv sync                                    # cài dependency (gồm nhóm dev)
uv run pytest                              # test offline: unit + API (network/integration bị loại qua addopts)
uv run pytest tests/core/steps/test_syntax.py::test_too_long -v   # chạy một test
uv run pytest -k single_flight             # chạy theo tên
uv run pytest -m integration               # Redis thật qua testcontainers (cần Docker)
EV_REQUIRE_INTEGRATION=1 uv run pytest -m integration   # báo lỗi thay vì bỏ qua khi không có Docker
uv run pytest -m network                   # smoke test với DNS thật
uv run ruff check . && uv run ruff format --check . && uv run mypy   # cả ba phải qua (mypy --strict)

uv run python -m email_validation.api.security <api-key>   # in SHA-256 để đặt vào EV_API_KEY_HASHES
EV_API_KEY_HASHES=<hash> uv run uvicorn email_validation.api.app:create_app --factory
docker compose up --build                  # app + Redis, API key "dev-key"
```

CI (`.github/workflows/ci.yml`) chạy lint/type-check, test offline và test tích hợp
(với `EV_REQUIRE_INTEGRATION=1`) mỗi lần push lên `master` và mỗi pull request.

## Kiến trúc

**Pipeline** (`core/pipeline.py`): `EmailValidator` chạy lần lượt các `Step`:
normalize → syntax → idn → disposable → dns_mx. Mỗi `Step.run(ctx, policy)` ghi vào một
`ValidationContext` dùng chung và trả về `StepOutcome`; `stop=True` kết thúc pipeline
(fail-fast, nên địa chỉ sai cú pháp không bao giờ tới bước DNS). Mọi exception trong một step
đều thành `unknown` + `INTERNAL_ERROR`. `default_steps` chỉ thêm bước disposable/DNS khi có
truyền registry/resolver. `SyntaxStep` tự kiểm tra trước độ dài, IDN và SMTPUTF8 (độ dài đo
trên dạng A-label), rồi mới gọi `email-validator` với `check_deliverability=False`; kết quả
lưu vào `ctx.parsed` để `IdnStep` điền các trường kết quả và tách `user+tag`.

**Ý nghĩa kết quả**: `valid | invalid | unknown`. Lỗi DNS tạm thời là `unknown`
(`DNS_TEMPORARY_FAILURE`), không bao giờ là `invalid`. Giá trị `Reason` là hợp đồng API
(value == name).

**DNS** (`core/dns/`): giao thức `DnsBackend` (`DnspythonBackend`; trong test dùng
`tests/fakes.py::FakeDnsBackend`) → `MxResolver.lookup()`: chuẩn hóa domain → `TieredCache`
(L1 TTL-LRU trong bộ nhớ, L2 Redis) → single-flight (mỗi domain một `asyncio.Task` dùng chung,
các caller chờ qua `asyncio.shield`) → semaphore + `lookup_timeout` → MX, Null MX, nếu không có
MX thì tra song song A/AAAA (`implicit=True`). TTL theo từng outcome nằm trong `cache.py`
(`l1_ttl`/`l2_ttl`). `cache.py` import `resolver.py`; chiều ngược lại chỉ import khi
`TYPE_CHECKING`, nên tiền tố key `mx:v1:` được khai báo ở cả hai nơi và có test bảo vệ.

**API** (`api/`): `create_app()` dựng `AppState` ngay trong `build_state()` (test dùng
`httpx.ASGITransport`, vốn không chạy lifespan). Lifespan chỉ cấu hình log JSON, khởi động task
reload danh sách disposable và đóng Redis client do app tự tạo. Thứ tự middleware:
`RequestIdMiddleware` ngoài cùng, rồi `BodySizeLimitMiddleware` (trả 413 trước khi xác thực và
parse JSON). Route: dependency `authenticate` (hash SHA-256 của key, so sánh bằng
`hmac.compare_digest`) → rate limit token bucket trên Redis (script Lua trong `security.py`;
chi phí batch = số email; trả 413 nếu batch vượt dung lượng bucket) → áp tùy chọn theo request
qua `policy.with_overrides()` (giá trị `None` bị bỏ qua). `/healthz`, `/readyz`, `/metrics`
không cần xác thực.

**Redis không bao giờ là phụ thuộc bắt buộc**: cache và rate limiter bắt
`RedisError`/`OSError`/`TimeoutError` rồi chạy tiếp (fail-open) kèm metric; `/readyz` báo
`redis: "degraded"`.

## Nên

- Giữ `email_validation.core` không import bất cứ thứ gì từ `email_validation.api`.
- Thêm kiểm tra mới dưới dạng một `Step` và nối vào `default_steps`; chỉ thêm mã `Reason` mới,
  không đổi hay xóa mã cũ.
- Thêm setting mới vào `api/settings.py` (tiền tố env `EV_`) **và** bảng cấu hình trong README.
- Trong test dùng `FakeDnsBackend`, `fakeredis.FakeAsyncRedis` và `BrokenRedis`
  (`tests/fakes.py`); đánh dấu test dùng DNS thật là `@pytest.mark.network`, test cần Docker là
  `@pytest.mark.integration`.
- Đọc các thuộc tính tùy chọn của `ValidatedEmail` bằng `getattr(..., None)` — email-validator
  2.3 ném `AttributeError` với thuộc tính chưa được gán (ví dụ `domain_address`).
- Chỉ log `domain` và `email_fingerprint(input)` (SHA-256); dùng các trường `extra=` đã có trong
  whitelist ở `api/observability.py`.
- Giữ output test sạch: await các task đã cancel, đóng client, không có warning.
- Chạy đủ bộ ba ruff + mypy + pytest trước mỗi commit; viết test thất bại trước khi code.

## Không nên

- Không trả mã khác 200 cho kết quả xác thực — `invalid`/`unknown` vẫn là 200; 4xx chỉ dành cho
  xác thực, rate limit, kích thước body và lỗi schema.
- Không xếp timeout/SERVFAIL vào `invalid`, và không cache chúng lâu hơn TTL của TEMP_FAIL.
- Không log địa chỉ email gốc, API key hay hash của key.
- Không để Redis lỗi làm request lỗi, và không bắt buộc phải có Redis mới khởi động được.
- Không await task single-flight dùng chung mà thiếu `asyncio.shield`, và không cancel nó từ
  phía caller.
- Không đổi định dạng cache key mà không tăng phiên bản `mx:v1:` ở cả hai nơi.
- Không dựa vào `max_length` của pydantic để bảo vệ bộ nhớ — body đã được parse trước khi
  validate; `BodySizeLimitMiddleware` mới là lớp chặn.
- Không chuyển local-part về chữ thường (chỉ chuẩn hóa domain).
- Không gọi DNS hay Redis thật trong lượt chạy test mặc định.
- Không commit `.env`, `.superpowers/` hay `.claude/settings.local.json`.
