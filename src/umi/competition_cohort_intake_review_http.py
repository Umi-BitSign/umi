"""Private, bounded HTTP delivery for native intake review exports.

The host installs this router beside its intake owner. It is deliberately not
enabled by the public intake API. Both peers load the bearer credential privately;
the independent reviewer also verifies the response's configured owner signature.
"""

from __future__ import annotations

import asyncio
import hmac
import sqlite3

import httpx
from fastapi import APIRouter, HTTPException, Request, Response

from .competition_cohort_intake_export import (
    MAX_EXPORT_BYTES,
    IntakeReviewExporter,
    IntakeReviewRequest,
    _bounds,
)
from .concurrency import wait_for_owned
from .protocol import canonical_json_bytes

PATH = "/internal/cohorts/intake-review"
MAX_REQUEST_BYTES = 16384


def _credential(value: str) -> str:
    if (
        type(value) is not str
        or not 32 <= len(value) <= 256
        or any(not (33 <= ord(c) <= 126) for c in value)
    ):
        raise ValueError("intake review needs a private bearer credential")
    return value


def intake_review_routes(exporter: IntakeReviewExporter, *, token: str) -> APIRouter:
    expected = "Bearer " + _credential(token)
    router, capacity = APIRouter(), asyncio.Semaphore(1)

    @router.post(PATH)
    async def review(request: Request):
        supplied = request.headers.get("authorization", "")
        if not hmac.compare_digest(supplied.encode(), expected.encode()):
            raise HTTPException(401, "intake review authentication required")
        if request.headers.get("content-type", "").split(";", 1)[0].strip() != "application/json":
            raise HTTPException(415, "application/json required")

        async def body():
            raw = bytearray()
            async for part in request.stream():
                if len(raw) + len(part) > MAX_REQUEST_BYTES:
                    raise HTTPException(413, "intake review request too large")
                raw.extend(part)
            return bytes(raw)

        acquired = False
        try:
            await asyncio.wait_for(capacity.acquire(), timeout=1)
            acquired = True
            raw = await asyncio.wait_for(body(), timeout=10)
            try:
                value = IntakeReviewRequest.model_validate_json(raw)
            except ValueError as error:
                raise HTTPException(422, "invalid intake review request") from error
            output = await wait_for_owned(exporter.respond(value), timeout=exporter.timeout_seconds)
            return Response(
                output, media_type="application/json", headers={"cache-control": "no-store"}
            )
        except (OSError, ValueError, RuntimeError, sqlite3.Error) as error:
            raise HTTPException(503, "intake review unavailable; retry unchanged") from error
        finally:
            if acquired:
                capacity.release()

    return router


class IntakeReviewHTTPClient:
    """One configured HTTPS owner; redirects cannot forward its private token."""

    def __init__(
        self,
        client: httpx.AsyncClient,
        origin: str,
        *,
        token: str,
        maximum_bytes: int = MAX_EXPORT_BYTES,
        timeout_seconds: int = 30,
    ):
        _bounds(maximum_bytes, timeout_seconds)
        url = httpx.URL(origin)
        if (
            url.scheme != "https"
            or not url.host
            or url.userinfo
            or url.query
            or url.fragment
            or url.path not in ("", "/")
        ):
            raise ValueError("intake review requires a configured HTTPS origin")
        self.client, self.url = client, str(url.copy_with(path=PATH))
        self.token = _credential(token)
        self.maximum_bytes, self.timeout_seconds = maximum_bytes, timeout_seconds

    async def __call__(self, request: IntakeReviewRequest) -> bytes:
        raw = canonical_json_bytes(request)
        if len(raw) > MAX_REQUEST_BYTES:
            raise ValueError("intake review request exceeds its byte bound")
        async with self.client.stream(
            "POST",
            self.url,
            content=raw,
            headers={"authorization": "Bearer " + self.token, "content-type": "application/json"},
            follow_redirects=False,
            timeout=self.timeout_seconds,
        ) as response:
            if response.status_code != 200:
                raise OSError("intake owner has not supplied a review export")
            if (
                response.headers.get("content-type", "").split(";", 1)[0].strip()
                != "application/json"
            ):
                raise ValueError("intake owner response is not JSON")
            result = bytearray()
            async for part in response.aiter_bytes():
                if len(result) + len(part) > self.maximum_bytes:
                    raise ValueError("intake owner response exceeds its byte bound")
                result.extend(part)
            return bytes(result)
