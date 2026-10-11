"""Private bounded delivery shared by native cohort phase review exports.

The host installs explicit typed routes beside their native owner. These routes
are not enabled by the public API. Bearer transport and owner-signed responses
protect original evidence while independent reviewers retain native proof checks.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import sqlite3
import traceback
from collections.abc import Callable
from typing import Annotated, Generic, Literal, Protocol, TypeVar

import httpx
from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import Field, model_serializer, model_validator
from starlette.types import Receive, Scope, Send

from .competition_cohort_review_budget import PhaseReviewBudget
from .competition_cohort_review_export import MAX_EXPORT_BYTES, review_export_limits
from .competition_cohort_review_origin import private_review_origin
from .competition_progress import _failure_details
from .concurrency import wait_for_owned
from .host_memory_admission import HostMemoryAdmission
from .host_memory_request_bounds import stage_evidence_budget
from .host_memory_runtime import selected_memory
from .open_competition import Hotkey
from .private_files import Directory
from .protocol import StrictProtocolModel, canonical_json_bytes

MAX_REQUEST_BYTES = 16384
RequestT = TypeVar("RequestT", bound=StrictProtocolModel, contravariant=True)
logger = logging.getLogger(__name__)


class PhaseReviewHTTPUnavailable(OSError):
    """Retain the HTTP boundary without exposing a private response or URL."""

    def __init__(self, status_code: int):
        self.reason_code = f"phase_owner_http_{status_code}"
        super().__init__("phase owner has not supplied a review export")


class CohortReviewPeerConfig(StrictProtocolModel):
    signer: Hotkey
    origin: Annotated[str, Field(min_length=1, max_length=2048)]
    token_file: Directory
    timeout_seconds: Annotated[int, Field(ge=1, le=3600)] = 2400
    phase_review_budget: PhaseReviewBudget | None = None

    @model_serializer(mode="wrap")
    def preserve_legacy(self, handler):
        value = handler(self)
        if self.phase_review_budget is None:
            value.pop("phase_review_budget", None)
        return value

    @model_validator(mode="after")
    def endpoint(self):
        private_review_origin(self.origin)
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


def _discard_error_frames(error: BaseException) -> None:
    # A ValidationError can own its rejected input independently of traceback
    # locals. Break completed error chains before replacing the HTTP boundary;
    # the original error then dies when its except suite ends.
    pending, seen = [error], set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        pending.extend(e for e in (current.__cause__, current.__context__) if e is not None)
        traceback.clear_frames(current.__traceback__)
        current.__traceback__ = current.__cause__ = current.__context__ = None


class _OwnedReviewResponse(Response):
    """Retain capacity until ASGI finishes sending and this owner drops bytes."""

    def __init__(
        self,
        content: bytes,
        capacity: asyncio.Semaphore,
        release: Callable[[], None] | None = None,
    ):
        super().__init__(
            content, media_type="application/json", headers={"cache-control": "no-store"}
        )
        self._capacity: asyncio.Semaphore | None = capacity
        self._release: Callable[[], None] | None = release or capacity.release

    def _close(self) -> None:
        self.body = b""
        self._capacity = None
        release, self._release = getattr(self, "_release", None), None
        if release is not None:
            release()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        try:
            await send(
                {
                    "type": "http.response.start",
                    "status": self.status_code,
                    "headers": self.raw_headers,
                }
            )
            # Uvicorn may queue an entire body in its transport before send()
            # returns. Bounded chunks preserve flow control; the full source
            # buffer remains leased until the final ASGI send completes.
            for offset in range(0, len(self.body), 64 * 1024):
                await send(
                    {
                        "type": "http.response.body",
                        "body": self.body[offset : offset + 64 * 1024],
                        "more_body": True,
                    }
                )
            await send({"type": "http.response.body", "body": b"", "more_body": False})
        except BaseException as error:
            # A failed send frame may retain its message. Clear completed
            # frames before release; this frame retains only self, whose body
            # is explicitly dropped below, and bounded wire chunks.
            _discard_error_frames(error)
            raise
        finally:
            self._close()

    def __del__(self):
        # An unstarted response may be abandoned by middleware. Its last
        # reference still owns the buffer and therefore also owns the lease.
        self._close()


def phase_review_routes(
    exporter: PhaseReviewExporter[RequestT],
    *,
    token: str,
    path: str,
    request_model: type[RequestT],
    maximum_request_bytes: int = MAX_REQUEST_BYTES,
    concurrency: int = 1,
    admission: HostMemoryAdmission | None = None,
    admission_lane: Literal["owner_export", "transient"] | None = None,
    admission_operation: str | None = None,
    admission_scope: Callable | None = None,
) -> APIRouter:
    # This transport also serves reviewer vote routes. Only explicitly marked
    # owner exports take the reserved owner lane; otherwise a reviewer would
    # occupy that lane while waiting for its owner's response.
    if admission is None:
        selected = selected_memory()
        if admission_lane is not None or getattr(selected, "requests_stage", False):
            admission = selected
    if admission is not None and exporter.maximum_bytes > admission.policy.maximum_aggregate_bytes:
        raise ValueError("owner export exceeds its qualified host aggregate capacity")
    _request_limit(maximum_request_bytes)
    if type(concurrency) is not int or not 1 <= concurrency <= 8:
        raise ValueError("phase review concurrency must be between 1 and 8")
    expected = "Bearer " + _credential(token)
    router, capacity = APIRouter(), asyncio.Semaphore(concurrency)

    @router.post(path)
    async def review(request: Request):
        supplied = request.headers.get("authorization", "")
        if not hmac.compare_digest(supplied.encode(), expected.encode()):
            raise HTTPException(401, "phase review authentication required")
        if request.headers.get("content-type", "").split(";", 1)[0].strip() != "application/json":
            raise HTTPException(415, "application/json required")

        if (
            getattr(admission, "requests_stage", False)
            and admission_operation not in admission.policy.operations
        ):
            raise HTTPException(503, "operation is outside the qualified C5 requests stage")

        async def body():
            raw = bytearray()
            async for part in request.stream():
                if len(raw) + len(part) > maximum_request_bytes:
                    raise HTTPException(413, "phase review request too large")
                raw.extend(part)
            return bytes(raw)

        acquired, transferred, lease = False, False, None
        output = b""

        def release():
            nonlocal acquired, lease
            if lease is not None:
                lease.close()
                lease = None
            if acquired:
                acquired = False
                capacity.release()

        try:
            # Exporters already bound their own operation to timeout_seconds.
            # Let concurrent reviewers queue behind that bounded operation;
            # rejecting the queue after one second can starve every retry when
            # a large retained export legitimately takes longer to produce.
            await capacity.acquire()
            acquired = True
            raw = await asyncio.wait_for(body(), timeout=10)
            try:
                value = request_model.model_validate_json(raw)
            except ValueError as error:
                raise HTTPException(422, "invalid phase review request") from error
            if admission is not None:
                if getattr(admission, "requests_stage", False):
                    cohort, phase = (
                        (None, None) if admission_scope is None else admission_scope(value)
                    )
                    admission.authorize(
                        admission_operation, cohort, phase, lane=admission_lane or "transient"
                    )
                    if admission_lane is not None:
                        lease = await admission.acquire(
                            admission_lane,
                            operation=admission_operation,
                            cohort=cohort,
                            phase=phase,
                        )
                else:
                    lease = await admission.acquire(admission_lane or "owner_export")
            with stage_evidence_budget():
                output = await wait_for_owned(
                    exporter.respond(value), timeout=exporter.timeout_seconds
                )
            if type(output) is not bytes or len(output) > exporter.maximum_bytes:
                raise ValueError("phase export response exceeds its byte bound")
            response = _OwnedReviewResponse(output, capacity, release)
            transferred = True
            return response
        except (OSError, ValueError, RuntimeError, sqlite3.Error, asyncio.TimeoutError) as error:
            logger.warning(
                "phase_review_unavailable path=%s error_type=%s details=%s",
                path,
                type(error).__name__,
                json.dumps(_failure_details(error), separators=(",", ":")),
            )
            _discard_error_frames(error)
        except BaseException as error:
            _discard_error_frames(error)
            raise
        finally:
            if not transferred:
                output = b""
                release()
        # Do not attach the native exception: schema errors may retain rejected
        # aggregate graphs even after their completed traceback frames clear.
        raise HTTPException(503, "phase review unavailable; retry unchanged") from None

    return router


class PhaseReviewHTTPClient(Generic[RequestT]):
    """One configured private origin; redirects cannot forward its token."""

    def __init__(
        self,
        client: httpx.AsyncClient,
        origin: str,
        *,
        token: str,
        path: str,
        maximum_bytes: int = MAX_EXPORT_BYTES,
        timeout_seconds: int = 2400,
        maximum_request_bytes: int = MAX_REQUEST_BYTES,
        aggregate_evidence: bool = False,
    ):
        review_export_limits(maximum_bytes, timeout_seconds, aggregate_evidence=aggregate_evidence)
        _request_limit(maximum_request_bytes)
        url = private_review_origin(origin)
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
                raise PhaseReviewHTTPUnavailable(response.status_code)
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
    if type(value) is not int or not 1024 <= value <= 64 * 1024**2 + 1024:
        raise ValueError("phase review request capacity is outside bounds")
