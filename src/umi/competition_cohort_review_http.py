"""Private bounded delivery shared by native cohort phase review exports.

The host installs explicit typed routes beside their native owner. These routes
are not enabled by the public API. Bearer transport and owner-signed responses
protect original evidence while independent reviewers retain native proof checks.
"""

from __future__ import annotations

import asyncio
import hmac
import sqlite3
from typing import Annotated, Generic, Protocol, TypeVar

import httpx
from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import Field, model_validator

from .competition_cohort_review_export import MAX_EXPORT_BYTES, review_export_limits
from .concurrency import wait_for_owned
from .open_competition import Hotkey
from .private_files import Directory
from .protocol import StrictProtocolModel, canonical_json_bytes

MAX_REQUEST_BYTES = 16384
RequestT = TypeVar("RequestT", bound=StrictProtocolModel, contravariant=True)


class CohortReviewPeerConfig(StrictProtocolModel):
    signer: Hotkey
    origin: Annotated[str, Field(min_length=1, max_length=2048)]
    token_file: Directory
    timeout_seconds: Annotated[int, Field(ge=1, le=1200)] = 1200

    @model_validator(mode="after")
    def endpoint(self):
        url = httpx.URL(self.origin)
        if (
            url.scheme != "https"
            or not url.host
            or url.userinfo
            or url.query
            or url.fragment
            or url.path not in ("", "/")
        ):
            raise ValueError("cohort reviewer must be a configured HTTPS origin")
        return self


class PhaseReviewExporter(Protocol[RequestT]):
    timeout_seconds: int
    maximum_bytes: int

    async def respond(self, request: RequestT) -> bytes: ...


def _credential(value: str) -> str:
    if (
        type(value) is not str
        or not 32 <= len(value) <= 256
        or any(not (33 <= ord(c) <= 126) for c in value)
    ):
        raise ValueError("phase review needs a private bearer credential")
    return value


def phase_review_routes(
    exporter: PhaseReviewExporter[RequestT],
    *,
    token: str,
    path: str,
    request_model: type[RequestT],
    maximum_request_bytes: int = MAX_REQUEST_BYTES,
) -> APIRouter:
    _request_limit(maximum_request_bytes)
    expected = "Bearer " + _credential(token)
    router, capacity = APIRouter(), asyncio.Semaphore(1)

    @router.post(path)
    async def review(request: Request):
        supplied = request.headers.get("authorization", "")
        if not hmac.compare_digest(supplied.encode(), expected.encode()):
            raise HTTPException(401, "phase review authentication required")
        if request.headers.get("content-type", "").split(";", 1)[0].strip() != "application/json":
            raise HTTPException(415, "application/json required")

        async def body():
            raw = bytearray()
            async for part in request.stream():
                if len(raw) + len(part) > maximum_request_bytes:
                    raise HTTPException(413, "phase review request too large")
                raw.extend(part)
            return bytes(raw)

        acquired = False
        try:
            await asyncio.wait_for(capacity.acquire(), timeout=1)
            acquired = True
            raw = await asyncio.wait_for(body(), timeout=10)
            try:
                value = request_model.model_validate_json(raw)
            except ValueError as error:
                raise HTTPException(422, "invalid phase review request") from error
            output = await wait_for_owned(exporter.respond(value), timeout=exporter.timeout_seconds)
            if type(output) is not bytes or len(output) > exporter.maximum_bytes:
                raise ValueError("phase export response exceeds its byte bound")
            return Response(
                output, media_type="application/json", headers={"cache-control": "no-store"}
            )
        except (OSError, ValueError, RuntimeError, sqlite3.Error, asyncio.TimeoutError) as error:
            raise HTTPException(503, "phase review unavailable; retry unchanged") from error
        finally:
            if acquired:
                capacity.release()

    return router


class PhaseReviewHTTPClient(Generic[RequestT]):
    """One configured HTTPS owner; redirects cannot forward its private token."""

    def __init__(
        self,
        client: httpx.AsyncClient,
        origin: str,
        *,
        token: str,
        path: str,
        maximum_bytes: int = MAX_EXPORT_BYTES,
        timeout_seconds: int = 30,
        maximum_request_bytes: int = MAX_REQUEST_BYTES,
    ):
        review_export_limits(maximum_bytes, timeout_seconds)
        _request_limit(maximum_request_bytes)
        url = httpx.URL(origin)
        if (
            url.scheme != "https"
            or not url.host
            or url.userinfo
            or url.query
            or url.fragment
            or url.path not in ("", "/")
        ):
            raise ValueError("phase review requires a configured HTTPS origin")
        self.client, self.url = client, str(url.copy_with(path=path))
        self.token = _credential(token)
        self.maximum_bytes, self.timeout_seconds = maximum_bytes, timeout_seconds
        self.maximum_request_bytes = maximum_request_bytes

    async def __call__(self, request: RequestT) -> bytes:
        try:
            return await self._receive(request)
        except httpx.TransportError as error:
            raise OSError("phase review transport unavailable; retry unchanged") from error

    async def _receive(self, request: RequestT) -> bytes:
        raw = canonical_json_bytes(request)
        if len(raw) > self.maximum_request_bytes:
            raise ValueError("phase review request exceeds its byte bound")
        async with self.client.stream(
            "POST",
            self.url,
            content=raw,
            headers={"authorization": "Bearer " + self.token, "content-type": "application/json"},
            follow_redirects=False,
            timeout=self.timeout_seconds,
        ) as response:
            if response.status_code != 200:
                raise OSError("phase owner has not supplied a review export")
            if (
                response.headers.get("content-type", "").split(";", 1)[0].strip()
                != "application/json"
            ):
                raise ValueError("phase owner response is not JSON")
            result = bytearray()
            async for part in response.aiter_bytes():
                if len(result) + len(part) > self.maximum_bytes:
                    raise ValueError("phase owner response exceeds its byte bound")
                result.extend(part)
            return bytes(result)


def _request_limit(value: int) -> None:
    if type(value) is not int or not 1024 <= value <= 32 * 1024**2:
        raise ValueError("phase review request capacity is outside bounds")
