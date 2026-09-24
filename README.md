# Email Validation Service

Async Python library + REST API validating email addresses: RFC 5322/5321/6531 syntax
(incl. `user+tag`), IDN (IDNA2008), DNS MX (Null MX, A/AAAA fallback), disposable domains.
Design: `docs/superpowers/specs/2026-09-24-email-validation-service-design.md`.

## Library

```python
from email_validation.core import (
    DisposableRegistry,
    DnspythonBackend,
    EmailValidator,
    MxResolver,
    MemoryTTLCache,
    TieredCache,
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
| `EV_RATE_LIMIT_PER_MINUTE` | `6000` | Per key; batch counts each email (a batch larger than this → 413) |
| `EV_DNS_NAMESERVERS` | system | Comma-separated |
| `EV_DNS_TIMEOUT` / `EV_DNS_LIFETIME` | `2.0` / `4.0` | Seconds |
| `EV_DNS_MAX_CONCURRENCY` | `500` | Max concurrent DNS lookups |
| `EV_L1_CACHE_SIZE` | `100000` | In-process MX cache entries (L1 of `TieredCache`) |
| `EV_CHECK_DNS` | `true` | Disable to skip MX lookups (syntax-only validation) |
| `EV_DISPOSABLE_ACTION` | `reject` | `reject`, `flag`, `off` |
| `EV_DISPOSABLE_URL` | unset | Remote list, reloaded every `EV_DISPOSABLE_RELOAD_SECONDS` (86400) |
| `EV_DISPOSABLE_ALLOWLIST` | empty | Comma-separated domains exempt from disposable checks |
| `EV_ALLOW_IMPLICIT_MX` | `true` | Accept domains with A/AAAA but no MX |
| `EV_ALLOW_SMTPUTF8` / `EV_ALLOW_QUOTED_LOCAL` / `EV_ALLOW_DOMAIN_LITERAL` | `true` / `false` / `false` | |
| `EV_SUBADDRESS_SEPARATOR` | `+` | Set empty to disable `+tag` stripping |
| `EV_BATCH_MAX` | `1000` | Max emails per batch request |
| `EV_BATCH_CONCURRENCY` | `100` | Concurrent validations within a batch request |
| `EV_MAX_BODY_BYTES_VALIDATE` | `16384` | Max request body for `POST /v1/validate` (larger → 413) |
| `EV_MAX_BODY_BYTES_BATCH` | `2097152` | Max request body for `POST /v1/validate/batch` (larger → 413) |
| `EV_MAX_BODY_BYTES_DEFAULT` | `65536` | Max request body for every other path |
| `EV_LOG_LEVEL` | `INFO` | Python logging level |
| `EV_OTEL_ENABLED` | `false` | Needs `uv sync --extra otel`; uses `OTEL_EXPORTER_OTLP_ENDPOINT` |

Request bodies are size-checked before authentication and parsing (by `Content-Length`
and while streaming chunked bodies), so oversized requests get 413 without being buffered.
Also set a matching body-size limit at the ingress / load balancer (e.g. nginx
`client_max_body_size 2m`, or `nginx.ingress.kubernetes.io/proxy-body-size: "2m"`) so
oversized requests are dropped before they reach the pods.

## Tests

```bash
uv run pytest                 # unit + API (offline)
uv run pytest -m integration  # needs Docker (real Redis)
uv run pytest -m network      # real DNS
uv run ruff check . && uv run mypy
uv run locust -f perf/locustfile.py --host http://localhost:8000
```

Without Docker the integration tests are skipped locally. CI must run
`EV_REQUIRE_INTEGRATION=1 uv run pytest -m integration` on a runner with Docker: with
`EV_REQUIRE_INTEGRATION=1` (or a truthy `CI` env var) a missing Docker daemon fails the run
instead of skipping it.
