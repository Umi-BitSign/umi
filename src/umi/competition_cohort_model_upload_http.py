"""Bounded streaming delivery of files bound by an enrolled upload manifest."""

import asyncio
import sqlite3

from fastapi import APIRouter, HTTPException, Request

from .competition_cohort_model_upload import CHUNK_BYTES, CohortModelUploads, ModelUploadChunk
from .competition_cohort_participation import CohortParticipationRequest
from .competition_progress import report_admission_failure
from .concurrency import run_owned_thread
from .open_competition import Signature


def model_upload_routes(owner: CohortModelUploads, capture, *, capture_timeout_seconds=120):
    if (
        type(capture_timeout_seconds) not in (int, float)
        or not 1 <= capture_timeout_seconds <= 3600
    ):
        raise ValueError("model upload capture timeout must be between 1 and 3600 seconds")
    router = APIRouter()
    slots = asyncio.Semaphore(owner.config.maximum_concurrent_uploads)

    async def lookup(key):
        try:
            return await run_owned_thread(owner.retained, key)
        except FileNotFoundError as error:
            raise HTTPException(404, "model delivery not found") from error
        except (OSError, ValueError, sqlite3.Error) as error:
            raise HTTPException(503, "model delivery state unavailable") from error

    @router.post("/v1/competition/cohorts/{cohort}/model-uploads")
    async def reserve(cohort: str, request: Request):
        if cohort not in owner.intake.bindings:
            raise HTTPException(404, "cohort not found")
        if request.headers.get("content-type", "").split(";", 1)[0] != "application/json":
            raise HTTPException(415, "application/json required")

        async def read():
            body = bytearray()
            async for part in request.stream():
                if len(body) + len(part) > 4 * 1024**2:
                    raise HTTPException(413, "model delivery manifest too large")
                body.extend(part)
            return bytes(body)

        stage = "body"
        try:
            signed = CohortParticipationRequest.model_validate_json(
                await asyncio.wait_for(read(), timeout=10)
            )
            if signed.consent.consent.cohort_sha256 != cohort:
                raise ValueError("wrong cohort")
            stage = "retry"
            key = await run_owned_thread(owner.retry, signed)
            if key is None:
                stage = "capture"
                current = await asyncio.wait_for(capture(), timeout=capture_timeout_seconds)
                stage = "reserve"
                key = await run_owned_thread(owner.reserve, signed, current)
            stage = "status"
            return await run_owned_thread(owner.status, key)
        except asyncio.TimeoutError as error:
            report_admission_failure("model_delivery", stage, error)
            raise HTTPException(503, "model delivery unavailable; retry unchanged") from error
        except ValueError as error:
            report_admission_failure("model_delivery", stage, error)
            raise HTTPException(422, "invalid model delivery request") from error
        except (OSError, RuntimeError, sqlite3.Error) as error:
            report_admission_failure("model_delivery", stage, error)
            raise HTTPException(503, "model delivery pending; retry unchanged") from error

    @router.get("/v1/competition/model-uploads/{key}")
    async def status(key: str):
        await lookup(key)
        try:
            return await run_owned_thread(owner.status, key)
        except (OSError, ValueError, sqlite3.Error) as error:
            raise HTTPException(503, "model delivery state unavailable") from error

    @router.put("/v1/competition/model-uploads/{key}/files/{index}")
    async def upload(key: str, index: int, request: Request, offset: int = 0):
        signed = await lookup(key)
        files = signed.signed_submission.submission.model_bundle.files
        if not 0 <= index < len(files):
            raise HTTPException(404, "file is outside model manifest")
        if request.headers.get("content-type") != "application/octet-stream" or (
            request.headers.get("content-encoding", "identity") != "identity"
        ):
            raise HTTPException(415, "unencoded application/octet-stream required")
        try:
            size = int(request.headers.get("content-length", ""))
            if (
                not 0 <= size <= CHUNK_BYTES
                or offset < 0
                or offset + size > files[index].size_bytes
            ):
                raise ValueError("chunk exceeds file")
            raw_signature = request.headers.get("x-umi-signature", "")
            if len(raw_signature) > 2048:
                raise ValueError("signature too large")
            signature = Signature.model_validate_json(raw_signature)
            chunk = ModelUploadChunk(
                schema="umi-cohort-model-upload-chunk/1",
                upload_sha256=key,
                file_index=index,
                offset=offset,
                size_bytes=size,
                sha256=request.headers.get("x-umi-chunk-sha256", ""),
            )
        except ValueError as error:
            raise HTTPException(422, "invalid signed file chunk") from error
        try:
            await asyncio.wait_for(slots.acquire(), timeout=0.1)
        except asyncio.TimeoutError as error:
            raise HTTPException(503, "model delivery busy; retry unchanged") from error
        try:
            body = bytearray()
            stream = request.stream().__aiter__()
            while True:
                try:
                    part = await asyncio.wait_for(
                        anext(stream), timeout=owner.config.idle_timeout_seconds
                    )
                except StopAsyncIteration:
                    break
                if len(body) + len(part) > size:
                    raise HTTPException(413, "chunk exceeds declared length")
                body.extend(part)
            await run_owned_thread(owner.put_chunk, chunk, signature, bytes(body))
            # The recurring service worker verifies full files and publishes the bundle.
            return await run_owned_thread(owner.status, key)
        except asyncio.TimeoutError as error:
            raise HTTPException(408, "file transfer idle; retry the same file") from error
        except ValueError as error:
            raise HTTPException(422, "file differs from model manifest") from error
        except (OSError, sqlite3.Error) as error:
            report_admission_failure("model_delivery", "chunk", error)
            raise HTTPException(503, "model delivery pending; retry unchanged") from error
        finally:
            slots.release()

    return router
