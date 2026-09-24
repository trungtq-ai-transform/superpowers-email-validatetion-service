from __future__ import annotations

import json
from collections.abc import Mapping

from starlette.types import ASGIApp, Message, Receive, Scope, Send

_TOO_LARGE_BODY = json.dumps({"detail": "request body too large"}).encode("utf-8")


class _BodyTooLarge(Exception):
    """Raised from the wrapped ``receive`` once the running body size exceeds the limit."""


class BodySizeLimitMiddleware:
    """Pure ASGI middleware: reject request bodies larger than a per-path limit with 413.

    Checked up front against ``Content-Length`` and again while streaming (chunked or
    missing ``Content-Length``), so an oversized body is never fully buffered.
    """

    def __init__(self, app: ASGIApp, limits: Mapping[str, int], default: int) -> None:
        self.app = app
        self._limits = dict(limits)
        self._default = default

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limit = self._limits.get(scope["path"], self._default)
        declared = _content_length(scope)
        if declared is not None and declared > limit:
            await _send_413(send)
            return

        received = 0
        exceeded = False
        response_started = False

        async def limited_receive() -> Message:
            nonlocal received, exceeded
            if exceeded:
                raise _BodyTooLarge
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    exceeded = True
                    raise _BodyTooLarge
            return message

        async def guarded_send(message: Message) -> None:
            nonlocal response_started
            if exceeded:
                # The app is answering the aborted read (e.g. 400/500); answer 413 instead.
                if not response_started:
                    response_started = True
                    await _send_413(send)
                return
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, guarded_send)
        except _BodyTooLarge:
            if not response_started:
                response_started = True
                await _send_413(send)


def _content_length(scope: Scope) -> int | None:
    for name, value in scope["headers"]:
        if name == b"content-length":
            try:
                return int(value)
            except ValueError:
                return None
    return None


async def _send_413(send: Send) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(_TOO_LARGE_BODY)).encode("latin-1")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": _TOO_LARGE_BODY})
