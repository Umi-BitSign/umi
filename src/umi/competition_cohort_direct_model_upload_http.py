"""Public metadata exchange for direct-to-R2 model delivery."""

from __future__ import annotations

import asyncio
import sqlite3
import time
from collections.abc import Mapping
from functools import partial

from fastapi import APIRouter, HTTPException, Request
from pydantic import ValidationError

from .competition_cohort_direct_model_owner import (
    DirectModelUploadOwner,
    DirectModelUploadPending,
)
from .competition_cohort_direct_model_upload import (
    DirectModelUploadReservationRequest,
    SignedDirectModelUploadCompletion,
    SignedDirectModelUploadPartRequest,
)
from .concurrency import run_owned_thread
from .open_competition import digest


def _now_unix_ms() -> int:
    return time.time_ns() // 1_000_000


def _hex32(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


async def _json_body(request: Request, *, maximum_bytes: int) -> bytes:
    if request.headers.get("content-type", "").split(";", 1)[0].strip() != "application/json":
        raise HTTPException(415, "application/json required")

    async def collect() -> bytes:
        value = bytearray()
        async for part in request.stream():
            if len(value) + len(part) > maximum_bytes:
                raise HTTPException(413, "direct model upload request too large")
            value.extend(part)
        return bytes(value)

    try:
        return await asyncio.wait_for(collect(), timeout=10)
    except (asyncio.TimeoutError, TimeoutError) as error:
        raise HTTPException(408, "direct model upload request timed out") from error


def direct_model_upload_routes(
    owners: DirectModelUploadOwner | Mapping[str, DirectModelUploadOwner],
    *,
    now_unix_ms=_now_unix_ms,
) -> APIRouter:
    router = APIRouter()
    if isinstance(owners, DirectModelUploadOwner):
        selected = {owners.config.cohort_sha256: owners}
    else:
        selected = dict(owners)
    if (
        not selected
        or any(key != owner.config.cohort_sha256 for key, owner in selected.items())
        or len({id(owner) for owner in selected.values()}) != len(selected)
    ):
        raise ValueError("direct model upload routes require unique cohort owners")

    def owner_for(cohort: str) -> DirectModelUploadOwner:
        try:
            return selected[cohort]
        except KeyError as error:
            raise HTTPException(404, "direct model upload cohort not found") from error

    @router.post("/v1/competition/cohorts/{cohort}/direct-model-uploads")
    async def reserve(cohort: str, request: Request):
        owner = owner_for(cohort)
        try:
            value = DirectModelUploadReservationRequest.model_validate_json(
                await _json_body(request, maximum_bytes=4 * 1024**2)
            )
            if value.request.consent.consent.cohort_sha256 != cohort:
                raise ValueError("direct model upload belongs to another cohort")
            return await owner.reserve(value.request, value.payload, now_unix_ms=now_unix_ms())
        except DirectModelUploadPending as error:
            raise HTTPException(
                503, "direct model upload creation pending; retry unchanged"
            ) from error
        except (ValidationError, ValueError) as error:
            raise HTTPException(422, "invalid direct model upload reservation") from error
        except (OSError, RuntimeError, sqlite3.Error) as error:
            raise HTTPException(503, "direct model upload unavailable; retry unchanged") from error

    @router.post("/v1/competition/cohorts/{cohort}/direct-model-uploads/{reservation}/parts")
    async def parts(cohort: str, reservation: str, request: Request):
        owner = owner_for(cohort)
        try:
            if not _hex32(reservation):
                raise ValueError("direct model upload reservation identity differs")
            value = SignedDirectModelUploadPartRequest.model_validate_json(
                await _json_body(request, maximum_bytes=16 * 1024)
            )
            if value.request.reservation_sha256 != reservation:
                raise ValueError("direct model upload part request path differs")
            return await run_owned_thread(
                partial(owner.issue_capabilities, value, now_unix_ms=now_unix_ms())
            )
        except (ValidationError, ValueError) as error:
            raise HTTPException(422, "invalid direct model upload part request") from error
        except (FileNotFoundError, OSError, RuntimeError, sqlite3.Error) as error:
            raise HTTPException(503, "direct model upload capabilities unavailable") from error

    @router.post("/v1/competition/cohorts/{cohort}/direct-model-uploads/{reservation}/complete")
    async def complete(cohort: str, reservation: str, request: Request):
        owner = owner_for(cohort)
        try:
            if not _hex32(reservation):
                raise ValueError("direct model upload reservation identity differs")
            value = SignedDirectModelUploadCompletion.model_validate_json(
                await _json_body(request, maximum_bytes=4 * 1024**2)
            )
            if value.completion.reservation_sha256 != reservation:
                raise ValueError("direct model upload completion path differs")
            return await owner.complete(value, now_unix_ms=now_unix_ms())
        except (ValidationError, ValueError) as error:
            raise HTTPException(422, "invalid direct model upload completion") from error
        except (FileNotFoundError, OSError, RuntimeError, sqlite3.Error) as error:
            raise HTTPException(503, "direct model upload completion unavailable") from error

    @router.get("/v1/competition/cohorts/{cohort}/direct-model-uploads/{reservation}")
    async def status(cohort: str, reservation: str):
        owner = owner_for(cohort)
        try:
            if not _hex32(reservation):
                raise FileNotFoundError("direct model upload reservation is unavailable")
            value = await run_owned_thread(owner.status, reservation)
            if digest(value.reservation.reservation) != reservation:
                raise ValueError("direct model upload status identity differs")
            return value
        except FileNotFoundError as error:
            raise HTTPException(404, "direct model upload reservation not found") from error
        except (ValueError, OSError, RuntimeError, sqlite3.Error) as error:
            raise HTTPException(503, "direct model upload status unavailable") from error

    return router
