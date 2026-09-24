from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, Depends, HTTPException, Request, Security
from fastapi.responses import JSONResponse, Response
from fastapi.security import APIKeyHeader
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from redis.exceptions import RedisError

from email_validation.api.observability import email_fingerprint
from email_validation.api.schemas import (
    BatchRequest,
    BatchResponse,
    ValidateRequest,
    ValidationResponse,
)
from email_validation.api.state import AppState, get_state
from email_validation.core.models import ValidationResult

router = APIRouter()

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

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


async def authenticate(request: Request, api_key: str | None = Security(_api_key_header)) -> str:
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
            429,
            "rate limit exceeded",
            headers={"Retry-After": str(decision.retry_after_seconds)},
        )


@router.post("/v1/validate", response_model=ValidationResponse)
async def validate(
    body: ValidateRequest, request: Request, key_id: str = Depends(authenticate)
) -> ValidationResponse:
    state = get_state(request)
    await _enforce_rate_limit(state, key_id, 1)
    policy = state.validator.policy.with_overrides(**body.options.model_dump())
    result = await state.validator.validate(body.email, policy)
    _log_result(result)
    return ValidationResponse.from_result(result)


@router.post("/v1/validate/batch", response_model=BatchResponse)
async def validate_batch(
    body: BatchRequest, request: Request, key_id: str = Depends(authenticate)
) -> BatchResponse:
    state = get_state(request)
    if len(body.emails) > state.settings.batch_max:
        raise HTTPException(413, f"batch exceeds {state.settings.batch_max} emails")
    limiter = state.rate_limiter
    if limiter.enabled and len(body.emails) > limiter.capacity:
        # Can never fit in the bucket: 429 + Retry-After would make clients retry forever.
        raise HTTPException(
            413,
            f"batch of {len(body.emails)} exceeds rate limit capacity"
            f" of {limiter.capacity} per minute",
        )
    if body.emails:
        await _enforce_rate_limit(state, key_id, len(body.emails))
    policy = state.validator.policy.with_overrides(**body.options.model_dump())
    results = await state.validator.validate_many(
        body.emails, policy, concurrency=state.settings.batch_concurrency
    )
    for r in results:
        _log_result(r, logging.DEBUG)
    logger.info("batch validated", extra={"count": len(results)})
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


@router.get("/metrics", include_in_schema=False)
async def metrics() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
