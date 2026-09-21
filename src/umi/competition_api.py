"""Public hotkey-signed intake for the no-weight successor phase.

No endpoint or model URL is fetched by intake. The service module connects the
owned-finality provider; fixture CLI operation remains loopback-only rehearsal.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Annotated, Literal

from fastapi import FastAPI, HTTPException, Query, Request
from pydantic import Field, ValidationError
from starlette.concurrency import run_in_threadpool
from starlette.responses import JSONResponse, Response
from starlette.types import Lifespan

from .competition_intake_archive import LoadedIntakeArchive
from .competition_launch import PublicIntakeDeployment, PublicRoundSchedule
from .competition_store import (
    AdmissionCapacityError,
    CompetitionStore,
    HistoricalIntakeArchiveBinding,
)
from .competition_submission_checkpoint import SubmissionCheckpointError
from .open_competition import RegistrationSnapshot, SignedSubmission, StrictProtocolModel, digest
from .protocol import canonical_json_bytes

__all__ = ("CompetitionApiLimits", "PublicIntakeDeployment", "PublicRoundSchedule", "create_app")

MAX_SUBMISSION_BYTES = 2 * 1024 * 1024


class CompetitionApiLimits(StrictProtocolModel):
    """Process-local request bounds, separate from economic policy."""

    maximum_concurrent_submissions: Annotated[int, Field(ge=1, le=256)] = 8
    maximum_concurrent_reads: Annotated[int, Field(ge=1, le=256)] = 16
    maximum_concurrent_readiness: Annotated[int, Field(ge=1, le=32)] = 2
    maximum_concurrent_registration_collections: Literal[1] = 1
    maximum_page_offset: Annotated[int, Field(ge=0, le=1_000_000)] = 65_536
    maximum_page_size: Annotated[int, Field(ge=1, le=100)] = 100
    capacity_wait_seconds: Annotated[float, Field(ge=0.01, le=10)] = 1.0
    socket_backlog: Annotated[int, Field(ge=1, le=4096)] = 128


def create_app(
    store: CompetitionStore,
    snapshot_provider: Callable[[], Awaitable[RegistrationSnapshot]],
    *,
    status_snapshot_provider: Callable[[], Awaitable[RegistrationSnapshot]] | None = None,
    lifespan: Lifespan[FastAPI] | None = None,
    registration_source: Literal[
        "rehearsal_snapshot", "verifier_attested_finality"
    ] = "rehearsal_snapshot",
    limits: CompetitionApiLimits | None = None,
    public_deployment: PublicIntakeDeployment | None = None,
    historical_archives: tuple[LoadedIntakeArchive, ...] = (),
) -> FastAPI:
    if registration_source not in {"rehearsal_snapshot", "verifier_attested_finality"}:
        raise ValueError("unsupported registration source")
    limits = CompetitionApiLimits.model_validate_json(
        canonical_json_bytes(limits or CompetitionApiLimits())
    )
    if public_deployment is not None:
        public_deployment = PublicIntakeDeployment.model_validate_json(
            canonical_json_bytes(public_deployment)
        )
    status_snapshot_provider = status_snapshot_provider or snapshot_provider
    archives_by_policy = {
        digest(archive.manifest.policy): archive for archive in historical_archives
    }
    if len(archives_by_policy) != len(historical_archives) or digest(store.policy) in (
        archives_by_policy
    ):
        raise ValueError("historical intake archives must name unique superseded policies")
    archive_bindings = tuple(
        HistoricalIntakeArchiveBinding(
            schema="umi-historical-intake-archive-binding/1",
            policy_sha256=digest(archive.manifest.policy),
            manifest_sha256=archive.manifest_sha256,
        )
        for archive in sorted(historical_archives, key=lambda item: digest(item.manifest.policy))
    )
    if (
        historical_archives or store.historical_intake_archive_bindings is not None
    ) and store.historical_intake_archive_bindings != archive_bindings:
        raise ValueError("public archive routes differ from the ledger-bound archive manifests")
    title = (
        "UMI open competition intake"
        if registration_source == "verifier_attested_finality"
        else "UMI open competition rehearsal"
    )
    app = FastAPI(title=title, docs_url=None, redoc_url=None, lifespan=lifespan)
    app.state.competition_store = store
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
                    headers={"cache-control": "no-store"},
                )
            response = await call_next(request)
            response.headers["cache-control"] = "no-store"
            return response
        finally:
            if acquired:
                capacity.release()

    @app.get("/v1/competition/launch-amendments")
    async def launch_amendments():
        return {"amendments": await run_in_threadpool(store.public_launch_amendments)}

    @app.get("/v1/competition/status")
    async def status():
        try:
            durable = await run_in_threadpool(store.durable_admission_status)
        except SubmissionCheckpointError as error:
            raise HTTPException(503, "durable admission state unavailable") from error
        admission = durable["admission_capacity"]
        submission_head = durable["retained_submission_head"]
        admission_accepting_new = admission["accepting_new"]
        admission_phase = "capacity_only"
        admission_checked_block = None
        if public_deployment is not None:
            try:
                snapshot = await asyncio.wait_for(status_snapshot_provider(), timeout=20)
            except Exception:
                admission_accepting_new = False
                admission_phase = "unverified"
            else:
                admission_checked_block = snapshot.block
                if snapshot.block < public_deployment.round_schedule.intake_opened_block:
                    admission_accepting_new = False
                    admission_phase = "not_open"
                elif not public_deployment.launch_identity().accepts_at(snapshot.block) or (
                    snapshot.block > store.policy.valid_through_block
                ):
                    admission_accepting_new = False
                    admission_phase = "closed"
                elif not admission_accepting_new:
                    admission_phase = "capacity_exhausted"
                else:
                    admission_phase = "open"
        result = {
            "schema": "umi-competition-status/2",
            "mode": "intake_no_weight"
            if registration_source == "verifier_attested_finality"
            else "rehearsal_no_weight",
            "registration_source": registration_source,
            "policy_sha256": digest(store.policy),
            "policy": store.policy.model_dump(mode="json", by_alias=True),
            "baseline": await run_in_threadpool(store.baseline_summary),
            "accepted_submission_count": admission["records"],
            "retained_submission_head": submission_head,
            "admission_accepting_new": admission_accepting_new,
            "admission_capacity_available": admission["accepting_new"],
            "admission_phase": admission_phase,
            "admission_checked_block": admission_checked_block,
            "chain_submission_authorized": False,
            "historical_intake_archives": [archive.summary() for archive in historical_archives],
            # Deal-preserving predecessors whose signed submissions this ledger still admits.
            "honored_policy_sha256s": list(store.lineage.admitted_policy_sha256s),
            "deal_sha256": store.lineage.deal_sha256,
        }
        if public_deployment is not None:
            result.update(
                {
                    "deployment": public_deployment.model_dump(mode="json", by_alias=True),
                    "round_schedule": public_deployment.round_schedule.model_dump(
                        mode="json", by_alias=True
                    ),
                    "assignment_delivery_ready": public_deployment.assignment_delivery_ready,
                    "model_intake_ready": public_deployment.model_intake_ready,
                    "evaluation_ready": public_deployment.evaluation_ready,
                    "rewards_active": False,
                }
            )
            if public_deployment.round_stride_blocks is not None:
                result["continuous_intake"] = True
                result["next_intake_schedule"] = (
                    public_deployment.launch_identity()
                    .next_intake_schedule(admission_checked_block)
                    .model_dump(mode="json", by_alias=True)
                    if admission_checked_block is not None and admission_accepting_new
                    else None
                )
        return result

    @app.get("/v1/competition/submissions")
    async def submissions(
        offset: int = Query(default=0, ge=0, le=limits.maximum_page_offset),
        limit: int = Query(
            default=min(20, limits.maximum_page_size),
            ge=1,
            le=limits.maximum_page_size,
        ),
    ):
        try:
            items = await run_in_threadpool(store.admission_summaries, offset=offset, limit=limit)
        except SubmissionCheckpointError as error:
            raise HTTPException(503, "durable admission state unavailable") from error
        return {"items": items, "offset": offset, "limit": limit}

    @app.get("/v1/competition/submissions/{submission_sha256}")
    async def submission_by_digest(submission_sha256: str):
        try:
            item = await run_in_threadpool(store.submission_by_digest, submission_sha256)
        except SubmissionCheckpointError as error:
            raise HTTPException(503, "durable admission state unavailable") from error
        except ValueError as error:
            raise HTTPException(404, "submission not found") from error
        if item is None:
            raise HTTPException(404, "submission not found")
        return item

    @app.get("/v1/competition/archives")
    async def intake_archives():
        return {"items": [archive.summary() for archive in historical_archives]}

    @app.get("/v1/competition/archives/{policy_sha256}/manifest")
    async def archived_manifest(policy_sha256: str):
        archive = archives_by_policy.get(policy_sha256)
        if archive is None:
            raise HTTPException(404, "intake archive not found")
        return Response(
            content=archive.canonical_manifest_bytes(),
            media_type="application/json",
        )

    @app.get("/v1/competition/archives/{policy_sha256}/submissions")
    async def archived_submissions(
        policy_sha256: str,
        offset: int = Query(default=0, ge=0, le=limits.maximum_page_offset),
        limit: int = Query(
            default=min(20, limits.maximum_page_size),
            ge=1,
            le=limits.maximum_page_size,
        ),
    ):
        archive = archives_by_policy.get(policy_sha256)
        if archive is None:
            raise HTTPException(404, "intake archive not found")
        return {
            "policy_sha256": policy_sha256,
            "items": await run_in_threadpool(
                archive.admission_summaries, offset=offset, limit=limit
            ),
            "offset": offset,
            "limit": limit,
        }

    @app.get("/v1/competition/archives/{policy_sha256}/submissions/{submission_sha256}")
    async def archived_submission_by_digest(policy_sha256: str, submission_sha256: str):
        archive = archives_by_policy.get(policy_sha256)
        if archive is None:
            raise HTTPException(404, "intake archive not found")
        try:
            item = await run_in_threadpool(archive.canonical_submission_bytes, submission_sha256)
        except ValueError as error:
            raise HTTPException(404, "archived submission not found") from error
        if item is None:
            raise HTTPException(404, "archived submission not found")
        return Response(content=item, media_type="application/json")

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
        try:
            historical = await run_in_threadpool(
                store.submission_by_digest, digest(signed.submission)
            )
        except SubmissionCheckpointError as error:
            raise HTTPException(
                503, "intake unavailable; retry the same signed submission later"
            ) from error
        if historical is not None:
            return historical["receipt"]
        if public_deployment is not None and (
            signed.submission.track not in public_deployment.eligible_tracks
        ):
            if signed.submission.track == "model":
                raise HTTPException(409, "model contribution intake is not open")
            raise HTTPException(409, "submission track is not open")
        try:
            snapshot = await asyncio.wait_for(snapshot_provider(), timeout=20)
        except Exception as error:
            raise HTTPException(
                503, "registration snapshot unavailable; retry unchanged"
            ) from error
        if (
            public_deployment is not None
            and snapshot.block >= public_deployment.round_schedule.intake_opened_block
            and (
                not public_deployment.launch_identity().accepts_at(snapshot.block)
                or snapshot.block > store.policy.valid_through_block
            )
        ):
            raise HTTPException(
                409,
                "first-round endpoint intake is closed"
                if public_deployment.round_stride_blocks is None
                else "competition intake is closed",
            )
        if (
            public_deployment is not None
            and snapshot.block < public_deployment.round_schedule.intake_opened_block
        ):
            raise HTTPException(409, "first-round endpoint intake is not open")
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
        except SubmissionCheckpointError as error:
            raise HTTPException(
                503, "intake unavailable; retry the same signed submission later"
            ) from error
        except ValueError as error:
            raise HTTPException(409, str(error)) from error

    return app
