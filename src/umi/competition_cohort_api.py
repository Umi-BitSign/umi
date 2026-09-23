"""Public discovery and explicitly signed participation for recoverable cohorts."""

from __future__ import annotations

import asyncio
import sqlite3
from collections.abc import Awaitable, Callable

from fastapi import APIRouter, HTTPException, Request
from pydantic import ValidationError

from .competition_chain import RegistrationCapture
from .competition_cohort_intake import CohortIntake, history_tip
from .competition_cohort_participation import CohortParticipationRequest
from .competition_store import AdmissionCapacityError
from .concurrency import run_owned_thread


def cohort_routes(
    intake: CohortIntake,
    capture: Callable[[], Awaitable[RegistrationCapture]],
    *,
    maximum_body_bytes: int,
) -> APIRouter:
    router = APIRouter()

    def allowed(cohort: str):
        if cohort not in intake.bindings:
            raise HTTPException(404, "recoverable cohort not found")

    @router.get("/v1/competition/cohorts")
    async def cohorts():
        entries = []
        for binding in intake.config.cohorts:
            cohort = binding.cohort_sha256
            try:
                history = await run_owned_thread(intake.history, cohort)
            except (ValueError, OSError, sqlite3.Error) as error:
                raise HTTPException(503, "cohort history unavailable; retry later") from error
            entries.append(
                {
                    "cohort_sha256": cohort,
                    "sequence": history.plan.sequence,
                    "recovery_tip_sha256": history_tip(history),
                    "history_url": f"/v1/competition/cohorts/{cohort}/history",
                    "participation_url": f"/v1/competition/cohorts/{cohort}/participation",
                }
            )
        return {"schema": "umi-public-cohorts/1", "cohorts": entries}

    @router.get("/v1/competition/cohorts/{cohort}/history")
    async def history(cohort: str):
        allowed(cohort)
        try:
            value = await run_owned_thread(intake.history, cohort)
        except (ValueError, OSError, sqlite3.Error) as error:
            raise HTTPException(503, "cohort history unavailable; retry later") from error
        return value.model_dump(mode="json", by_alias=True)

    @router.post("/v1/competition/cohorts/{cohort}/participation")
    async def participate(cohort: str, request: Request):
        allowed(cohort)
        if request.headers.get("content-type", "").split(";", 1)[0].strip() != "application/json":
            raise HTTPException(415, "application/json required")

        async def body():
            value = bytearray()
            async for part in request.stream():
                if len(value) + len(part) > maximum_body_bytes:
                    raise HTTPException(413, "cohort participation request too large")
                value.extend(part)
            return bytes(value)

        try:
            signed = CohortParticipationRequest.model_validate_json(
                await asyncio.wait_for(body(), timeout=10)
            )
        except asyncio.TimeoutError as error:
            raise HTTPException(408, "request body timed out; retry unchanged") from error
        except (ValueError, ValidationError) as error:
            raise HTTPException(422, "invalid signed cohort participation request") from error
        if signed.consent.consent.cohort_sha256 != cohort:
            raise HTTPException(409, "consent belongs to another cohort")
        try:
            prior = await run_owned_thread(intake.receipt, signed)
        except (ValueError, OSError, sqlite3.Error) as error:
            raise HTTPException(
                503, "retained cohort intake unavailable; retry unchanged"
            ) from error
        if prior is not None:
            return prior
        try:
            current = await asyncio.wait_for(capture(), timeout=20)
        except Exception as error:
            raise HTTPException(
                503, "registration observation unavailable; retry unchanged"
            ) from error
        try:
            return await run_owned_thread(intake.retain, signed, current)
        except (AdmissionCapacityError, OSError, sqlite3.Error) as error:
            raise HTTPException(503, "cohort intake unavailable; retry unchanged") from error
        except ValueError as error:
            raise HTTPException(409, "cohort intake or submission is not eligible") from error

    return router
