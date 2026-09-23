"""Public discovery and explicitly signed participation for recoverable cohorts."""

from __future__ import annotations

import asyncio
import re
import sqlite3
from collections.abc import Awaitable, Callable

from fastapi import APIRouter, HTTPException, Request
from pydantic import ValidationError

from .competition_chain import RegistrationCapture
from .competition_cohort_admission_queue import CohortAdmissionQueue
from .competition_cohort_intake import CohortIntake, history_tip
from .competition_cohort_intake_records import read_participation
from .competition_cohort_participation import CohortAdmissionStatus, CohortParticipationRequest
from .competition_execution import ExecutionBoundary
from .competition_store import AdmissionCapacityError
from .concurrency import run_owned_thread
from .open_competition import digest


def cohort_routes(
    intake: CohortIntake,
    capture: Callable[[], Awaitable[RegistrationCapture]],
    *,
    maximum_body_bytes: int,
    archive: Callable[[ExecutionBoundary], Awaitable[tuple[bytes, bytes]]] | None = None,
) -> APIRouter:
    router = APIRouter()
    queue = CohortAdmissionQueue(intake)

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
                    "admissions_url": f"/v1/competition/cohorts/{cohort}/admissions",
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

    @router.get("/v1/competition/cohorts/{cohort}/admissions/{consent}")
    async def admission(cohort: str, consent: str):
        allowed(cohort)
        if re.fullmatch("[0-9a-f]{64}", consent) is None:
            raise HTTPException(404, "cohort participation not found")
        try:
            certificate = await run_owned_thread(queue.certificate, cohort, consent)
        except FileNotFoundError as error:
            raise HTTPException(404, "cohort participation not found") from error
        except (ValueError, OSError, sqlite3.Error) as error:
            raise HTTPException(503, "admission certificate unavailable; retry later") from error
        return CohortAdmissionStatus(
            schema="umi-cohort-admission-status/1",
            policy_sha256=digest(intake.policy),
            cohort_sha256=cohort,
            consent_sha256=consent,
            status="pending_attestation" if certificate is None else "admission_certified",
            certificate=certificate,
        ).model_dump(mode="json", by_alias=True)

    async def preserve(signed, receipt):
        # Production supplies its owned archive provider. Generic rehearsal
        # routers may omit it; those records stay pending without proof bytes.
        if archive is not None:
            cohort = signed.consent.consent.cohort_sha256
            consent = digest(signed.consent.consent)
            try:
                try:
                    await run_owned_thread(queue.evidence, cohort, consent)
                except FileNotFoundError:
                    raw = await run_owned_thread(queue.record, cohort, consent)
                    original = read_participation(raw).observation
                    evidence, metadata = await archive(original)
                    await run_owned_thread(
                        queue.attach_evidence, cohort, consent, evidence, metadata
                    )
            except (ValueError, OSError, sqlite3.Error) as error:
                raise HTTPException(
                    503, "admission evidence unavailable; retry unchanged"
                ) from error
        return receipt

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
            return await preserve(signed, prior)
        try:
            current = await asyncio.wait_for(capture(), timeout=20)
        except Exception as error:
            raise HTTPException(
                503, "registration observation unavailable; retry unchanged"
            ) from error
        try:
            receipt = await run_owned_thread(intake.retain, signed, current)
        except (AdmissionCapacityError, OSError, sqlite3.Error) as error:
            raise HTTPException(503, "cohort intake unavailable; retry unchanged") from error
        except ValueError as error:
            raise HTTPException(409, "cohort intake or submission is not eligible") from error
        return await preserve(signed, receipt)

    return router
