"""Public hotkey-signed intake for the no-weight successor rehearsal.

No endpoint or model URL is fetched by intake. The service module connects the
owned-finality provider; fixture CLI operation remains loopback-only rehearsal.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Annotated, Literal

from fastapi import FastAPI, HTTPException, Query, Request
from pydantic import Field, ValidationError, model_validator
from starlette.concurrency import run_in_threadpool
from starlette.responses import JSONResponse
from starlette.types import Lifespan
from typing_extensions import Self

from .competition_store import AdmissionCapacityError, CompetitionStore
from .open_competition import RegistrationSnapshot, SignedSubmission, StrictProtocolModel, digest
from .protocol import canonical_json_bytes

MAX_SUBMISSION_BYTES = 2 * 1024 * 1024


class CompetitionApiLimits(StrictProtocolModel):
    """Process-local request bounds, separate from economic policy."""

    maximum_concurrent_submissions: Annotated[int, Field(ge=1, le=256)] = 8
    maximum_concurrent_reads: Annotated[int, Field(ge=1, le=256)] = 16
    maximum_concurrent_readiness: Annotated[int, Field(ge=1, le=32)] = 2
    maximum_concurrent_registration_collections: Annotated[int, Field(ge=1, le=32)] = 1
    maximum_page_offset: Annotated[int, Field(ge=0, le=1_000_000)] = 65_536
    maximum_page_size: Annotated[int, Field(ge=1, le=100)] = 100
    capacity_wait_seconds: Annotated[float, Field(ge=0.01, le=10)] = 1.0
    maximum_http_connections: Annotated[int, Field(ge=3, le=4096)] = 64
    socket_backlog: Annotated[int, Field(ge=1, le=4096)] = 128

    @model_validator(mode="after")
    def reserve_transport_capacity(self) -> Self:
        required = (
            self.maximum_concurrent_submissions
            + self.maximum_concurrent_reads
            + self.maximum_concurrent_readiness
        )
        if self.maximum_http_connections < required:
            raise ValueError("HTTP connection limit cannot cover the application capacities")
        return self


def create_app(
    store: CompetitionStore,
    snapshot_provider: Callable[[], Awaitable[RegistrationSnapshot]],
    *,
    lifespan: Lifespan[FastAPI] | None = None,
    registration_source: Literal[
        "rehearsal_snapshot", "verifier_attested_finality"
    ] = "rehearsal_snapshot",
    limits: CompetitionApiLimits | None = None,
) -> FastAPI:
    if registration_source not in {"rehearsal_snapshot", "verifier_attested_finality"}:
        raise ValueError("unsupported registration source")
    limits = CompetitionApiLimits.model_validate_json(
        canonical_json_bytes(limits or CompetitionApiLimits())
    )
    app = FastAPI(
        title="UMI open competition rehearsal", docs_url=None, redoc_url=None, lifespan=lifespan
    )
    capacities = {
        "submission": asyncio.Semaphore(limits.maximum_concurrent_submissions),
        "read": asyncio.Semaphore(limits.maximum_concurrent_reads),
        "readiness": asyncio.Semaphore(limits.maximum_concurrent_readiness),
    }

    @app.middleware("http")
    async def bound_public_requests(request: Request, call_next):
        if request.url.path == "/v1/competition/readiness":
            capacity = capacities["readiness"]
        elif request.method == "POST" and request.url.path == "/v1/competition/submissions":
            capacity = capacities["submission"]
        else:
            capacity = capacities["read"]
        acquired = False
        try:
            try:
                await asyncio.wait_for(capacity.acquire(), timeout=limits.capacity_wait_seconds)
                acquired = True
            except asyncio.TimeoutError:
                return JSONResponse(
                    status_code=503,
                    content={"detail": "service busy; retry the same request later"},
                )
            return await call_next(request)
        finally:
            if acquired:
                capacity.release()

    @app.get("/v1/competition/status")
    async def status():
        admission = await run_in_threadpool(store.admission_capacity_status)
        return {
            "schema": "umi-competition-status/1",
            "mode": "intake_no_weight"
            if registration_source == "verifier_attested_finality"
            else "rehearsal_no_weight",
            "registration_source": registration_source,
            "policy_sha256": digest(store.policy),
            "policy": store.policy.model_dump(mode="json", by_alias=True),
            "baseline": await run_in_threadpool(store.baseline_summary),
            "admission_accepting_new": admission["accepting_new"],
            "chain_submission_authorized": False,
        }

    @app.get("/v1/competition/submissions")
    async def submissions(
        offset: int = Query(default=0, ge=0, le=limits.maximum_page_offset),
        limit: int = Query(
            default=min(20, limits.maximum_page_size),
            ge=1,
            le=limits.maximum_page_size,
        ),
    ):
        return {
            "items": await run_in_threadpool(store.admission_summaries, offset=offset, limit=limit),
            "offset": offset,
            "limit": limit,
        }

    @app.get("/v1/competition/submissions/{submission_sha256}")
    async def submission_by_digest(submission_sha256: str):
        try:
            item = await run_in_threadpool(store.submission_by_digest, submission_sha256)
        except ValueError as error:
            raise HTTPException(404, "submission not found") from error
        if item is None:
            raise HTTPException(404, "submission not found")
        return item

    @app.get("/v1/competition/rounds/{round_sha256}")
    async def round_status(
        round_sha256: str,
        offset: int = Query(default=0, ge=0, le=limits.maximum_page_offset),
        limit: int = Query(
            default=min(20, limits.maximum_page_size),
            ge=1,
            le=limits.maximum_page_size,
        ),
    ):
        try:
            return await run_in_threadpool(
                store.round_status, round_sha256, offset=offset, limit=limit
            )
        except ValueError as error:
            raise HTTPException(404, "round not found") from error

    @app.get("/v1/competition/settlements/{round_sha256}")
    async def settlement_status(round_sha256: str):
        try:
            item = await run_in_threadpool(store.settlement_status, round_sha256)
        except ValueError as error:
            raise HTTPException(404, "settlement not found") from error
        if item is None:
            raise HTTPException(404, "settlement not found")
        return item

    @app.post("/v1/competition/submissions")
    async def submit(request: Request):
        if request.headers.get("content-type", "").split(";", 1)[0].strip() != "application/json":
            raise HTTPException(415, "application/json required")

        async def read_body() -> bytes:
            body = bytearray()
            async for chunk in request.stream():
                if len(body) + len(chunk) > MAX_SUBMISSION_BYTES:
                    raise HTTPException(413, "submission too large")
                body.extend(chunk)
            return bytes(body)

        try:
            body = await asyncio.wait_for(read_body(), timeout=10)
            signed = await run_in_threadpool(SignedSubmission.model_validate_json, body)
        except asyncio.TimeoutError as error:
            raise HTTPException(408, "submission body deadline exceeded") from error
        except (ValidationError, ValueError) as error:
            # Never echo an invalid uploaded object (which may contain a secret).
            raise HTTPException(422, "invalid signed competition submission") from error
        # Signature validation above precedes the historical lookup. Return
        # the saved source and snapshot, never promote a fixture receipt or
        # renew an old admission when current finality is unavailable.
        historical = await run_in_threadpool(store.submission_by_digest, digest(signed.submission))
        if historical is not None:
            return historical["receipt"]
        try:
            snapshot = await asyncio.wait_for(snapshot_provider(), timeout=20)
        except Exception as error:
            raise HTTPException(
                503, "registration snapshot unavailable; retry unchanged"
            ) from error
        try:
            return await run_in_threadpool(
                store.admit,
                signed,
                snapshot,
                snapshot.block,
                registration_source=registration_source,
            )
        except AdmissionCapacityError as error:
            raise HTTPException(
                503, "intake unavailable; retry the same signed submission later"
            ) from error
        except ValueError as error:
            raise HTTPException(409, str(error)) from error

    return app
