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
