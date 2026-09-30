"""Public, challenge-bound phase history for cohort miners; no private review inputs."""

from __future__ import annotations

import asyncio
import sqlite3
from collections.abc import Callable

import httpx
from fastapi import APIRouter, HTTPException, Query, Response

from .competition_client import validate_intake_origin
from .competition_cohort_history_http import CohortHistoryExporter, CohortHistoryRequest
from .competition_cohort_review_export import MAX_EXPORT_BYTES
from .concurrency import wait_for_owned


def public_history_routes(current: Callable[[], CohortHistoryExporter | None]) -> APIRouter:
    router = APIRouter()
    capacity = asyncio.Semaphore(2)

    @router.get("/v1/competition/cohorts/{cohort}/authority")
    async def authority(cohort: str, challenge: str = Query(pattern=r"^[0-9a-f]{64}$")):
        try:
            request = CohortHistoryRequest(
                schema="umi-cohort-history-request/1", cohort_sha256=cohort, challenge=challenge
            )
        except ValueError as error:
            raise HTTPException(422, "invalid cohort history request") from error
        exporter = current()
        if exporter is None:
            raise HTTPException(503, "cohort history owner unavailable")
        if cohort not in exporter.intake.bindings:
            raise HTTPException(404, "cohort not found")
        acquired = False
        try:
            await asyncio.wait_for(capacity.acquire(), timeout=0.1)
            acquired = True
            # Only signed phase decisions and their hash-bound observations.
            # Never expose intake originals, model assets or reference packages.
            raw = await wait_for_owned(exporter.respond(request), timeout=exporter.timeout_seconds)
            if type(raw) is not bytes or len(raw) > MAX_EXPORT_BYTES:
                raise ValueError("public history exceeds its byte limit")
            return Response(
                raw, media_type="application/json", headers={"Cache-Control": "no-store"}
            )
        except (OSError, ValueError, RuntimeError, sqlite3.Error, asyncio.TimeoutError) as error:
            raise HTTPException(503, "cohort history unavailable; retry later") from error
        finally:
            if acquired:
                capacity.release()

    return router


class PublicCohortHistoryClient:
    """No shared secret or persistent socket; each owned read is bounded."""

    def __init__(self, origin: str, *, timeout_seconds: int, transport=None):
        self.origin = validate_intake_origin(origin)
        if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 3600:
            raise ValueError("invalid public history timeout")
        self.timeout = timeout_seconds
        self.transport = transport

    async def __call__(self, request: CohortHistoryRequest) -> bytes:
        async def fetch():
            async with (
                httpx.AsyncClient(
                    transport=self.transport,
                    trust_env=False,
                    follow_redirects=False,
                    timeout=httpx.Timeout(self.timeout, connect=min(self.timeout, 10)),
                ) as client,
                client.stream(
                    "GET",
                    f"{self.origin}/v1/competition/cohorts/{request.cohort_sha256}/authority",
                    params={"challenge": request.challenge},
                    headers={"Accept-Encoding": "identity"},
                ) as response,
            ):
                if response.status_code != 200:
                    raise OSError("public cohort history unavailable")
                if (
                    response.headers.get("content-type", "").split(";", 1)[0].strip()
                    != "application/json"
                    or response.headers.get("content-encoding", "identity") != "identity"
                ):
                    raise ValueError("invalid public cohort history encoding")
                raw = bytearray()
                async for part in response.aiter_bytes():
                    if len(raw) + len(part) > MAX_EXPORT_BYTES:
                        raise ValueError("public cohort history exceeds its byte limit")
                    raw.extend(part)
                return bytes(raw)

        try:
            return await wait_for_owned(fetch(), timeout=self.timeout)
        except (httpx.HTTPError, asyncio.TimeoutError) as error:
            raise OSError("public cohort history transport unavailable") from error
