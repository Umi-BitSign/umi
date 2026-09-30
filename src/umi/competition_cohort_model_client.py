"""Resumable public model delivery followed by the original cohort consent."""

from __future__ import annotations

import asyncio
import hashlib
import math
import os
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Annotated, Any, TypeVar

import httpx
from pydantic import Field, StrictBool, StrictInt

from .competition_artifacts import _artifact, _directory, verify_bundle_directory
from .competition_client import (
    MAX_SUBMISSION_BYTES,
    CompetitionSubmissionError,
    validate_intake_origin,
)
from .competition_cohort_client import submit_cohort_participation
from .competition_cohort_model_upload import CHUNK_BYTES, ModelUploadChunk
from .competition_cohort_participation import CohortParticipationReceipt, CohortParticipationRequest
from .concurrency import run_owned_thread
from .open_competition import (
    BundleFile,
    CompetitionPolicy,
    ModelBundle,
    digest,
    identity,
    sign_object,
)
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

_Result = TypeVar("_Result")
_Fingerprint = tuple[int, int, int, int, int]
_Report = Callable[[dict], None]


class _UploadStatus(StrictProtocolModel):
    upload_sha256: Hex32
    model_sha256: Hex32
    complete_files: Annotated[tuple[StrictInt, ...], Field(max_length=4096)]
    file_offsets: Annotated[tuple[StrictInt, ...], Field(max_length=4096)]
    total_files: StrictInt
    payload_preserved: StrictBool
    participation_admitted: StrictBool
    artifact_review_certified: StrictBool


def _fingerprint(info: os.stat_result) -> _Fingerprint:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _snapshot(source: Path, bundle: ModelBundle) -> tuple[_Fingerprint, ...]:
    result = []
    with _directory(source) as root:
        for record in bundle.files:
            with _artifact(root, record) as (_, info):
                result.append(_fingerprint(info))
    return tuple(result)


def _verify_source(
    source: Path, bundle: ModelBundle, policy: CompetitionPolicy
) -> tuple[_Fingerprint, ...]:
    before = _snapshot(source, bundle)
    verify_bundle_directory(bundle, source, policy)
    if before != _snapshot(source, bundle):
        raise ValueError("model source changed during verification")
    return before


def _read_chunk(source: Path, record: BundleFile, expected: _Fingerprint, offset: int) -> bytes:
    with _directory(source) as root, _artifact(root, record) as (stream, info):
        if _fingerprint(info) != expected:
            raise ValueError("model source changed; rerun with the original bundle")
        stream.seek(offset)
        size = min(CHUNK_BYTES, record.size_bytes - offset)
        data = stream.read(size)
        if len(data) != size or _fingerprint(os.fstat(stream.fileno())) != expected:
            raise ValueError("model source changed during upload")
        return data


def _status(raw: bytes, key: str, bundle: ModelBundle) -> _UploadStatus:
    try:
        result = _UploadStatus.model_validate_json(raw)
        sizes = tuple(record.size_bytes for record in bundle.files)
        complete = set(result.complete_files)
        if (
            result.upload_sha256 != key
            or result.model_sha256 != digest(bundle)
            or result.total_files != len(sizes)
            or len(result.file_offsets) != len(sizes)
            or len(complete) != len(result.complete_files)
            or any(not 0 <= i < len(sizes) for i in complete)
            or any(
                not 0 <= offset <= size
                for offset, size in zip(result.file_offsets, sizes, strict=True)
            )
            or any(result.file_offsets[i] != sizes[i] for i in complete)
            or (result.payload_preserved and len(complete) != len(sizes))
            or result.participation_admitted
            or result.artifact_review_certified
        ):
            raise ValueError("upload status differs from original model")
        return result
    except ValueError as error:
        raise CompetitionSubmissionError("invalid_model_upload_status") from error


async def _retry(
    operation: Callable[[], Awaitable[_Result]], delay: float, report: _Report
) -> _Result:
    wait = delay
    while True:
        try:
            return await operation()
        except CompetitionSubmissionError as error:
            if error.reason_code not in {
                "model_upload_transport_unavailable",
                "intake_transport_unavailable",
            } and error.status_code not in {408, 429, 500, 502, 503, 504}:
                raise
            report(
                {
                    "status": "model_delivery_retry",
                    "reason_code": error.reason_code,
                    "http_status": error.status_code,
                    "retry_seconds": wait,
                }
            )
            await asyncio.sleep(wait)
            wait = min(60, wait * 2)


async def _exchange(
    client: httpx.AsyncClient, method: str, path: str, *, body=b"", headers=None
) -> bytes:
    async def send():
        async with client.stream(method, path, content=body, headers=headers) as response:
            if response.status_code != 200:
                raise CompetitionSubmissionError(
                    "model_upload_rejected", status_code=response.status_code
                )
            if (
                response.headers.get("content-type", "").split(";", 1)[0].strip()
                != "application/json"
                or response.headers.get("content-encoding", "identity") != "identity"
            ):
                raise CompetitionSubmissionError("invalid_model_upload_encoding")
            data = bytearray()
            async for chunk in response.aiter_bytes():
                if len(data) + len(chunk) > 512 * 1024:
                    raise CompetitionSubmissionError("model_upload_status_too_large")
                data.extend(chunk)
            return bytes(data)

    try:
        return await asyncio.wait_for(send(), timeout=120)
    except (httpx.HTTPError, asyncio.TimeoutError) as error:
        raise CompetitionSubmissionError("model_upload_transport_unavailable") from error


async def submit_cohort_model(
    *,
    origin: str,
    policy: CompetitionPolicy,
    request: CohortParticipationRequest,
    source: Path,
    wallet: Any,
    transport: httpx.AsyncBaseTransport | None = None,
    retry_seconds: float = 2,
    report: _Report = lambda _: None,
) -> CohortParticipationReceipt:
    """Resume bounded signed chunks; enroll only after native byte preservation.

    Transient failures retry without a cohort deadline. Cancellation leaves server
    offsets intact; rerun with the same request and source. No request is renewed
    or re-signed, and this intake receipt is not certification or reward activation.
    """
    import bittensor as bt

    origin = validate_intake_origin(origin)
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    request = CohortParticipationRequest.model_validate_json(canonical_json_bytes(request))
    sub = request.signed_submission.submission
    body = canonical_json_bytes(request)
    signer = bt.resolve_signer(wallet, role="hotkey")
    if (
        sub.policy_sha256 != digest(policy)
        or sub.track != "model"
        or sub.model_bundle is None
        or identity(signer.ss58_address) != identity(sub.hotkey)
        or len(body) > MAX_SUBMISSION_BYTES
        or not math.isfinite(retry_seconds)
        or not 0 < retry_seconds <= 60
    ):
        raise ValueError("model upload requires matching policy, model request and hotkey")
    bundle = sub.model_bundle
    source = Path(os.path.abspath(source))  # Preserve symlinks for the no-follow reader.
    fingerprints = await run_owned_thread(_verify_source, source, bundle, policy)
    key = digest(request)
    path = f"/v1/competition/model-uploads/{key}"

    async with httpx.AsyncClient(
        base_url=origin,
        transport=transport,
        timeout=httpx.Timeout(60, connect=10),
        follow_redirects=False,
        trust_env=False,
        headers={"Accept": "application/json", "Accept-Encoding": "identity"},
    ) as client:

        async def status_request(method, url, **kwargs):
            async def attempt():
                return _status(await _exchange(client, method, url, **kwargs), key, bundle)

            return await _retry(attempt, retry_seconds, report)

        current = await status_request(
            "POST",
            f"/v1/competition/cohorts/{request.consent.consent.cohort_sha256}/model-uploads",
            body=body,
            headers={"Content-Type": "application/json"},
        )
        pending_report_at = 0.0
        while not current.payload_preserved:
            previous = current.file_offsets
            for index, record in enumerate(bundle.files):
                offset = current.file_offsets[index]
                if index in current.complete_files or (offset == record.size_bytes and offset > 0):
                    continue
                data = await run_owned_thread(
                    _read_chunk, source, record, fingerprints[index], offset
                )
                chunk = ModelUploadChunk(
                    schema="umi-cohort-model-upload-chunk/1",
                    upload_sha256=key,
                    file_index=index,
                    offset=offset,
                    size_bytes=len(data),
                    sha256=hashlib.sha256(data).hexdigest(),
                )
                signature = sign_object(chunk, wallet)
                current = await status_request(
                    "PUT",
                    f"{path}/files/{index}?offset={offset}",
                    body=data,
                    headers={
                        "Content-Type": "application/octet-stream",
                        "Content-Length": str(len(data)),
                        "X-UMI-Chunk-SHA256": chunk.sha256,
                        "X-UMI-Signature": canonical_json_bytes(signature).decode(),
                    },
                )
                report(
                    {
                        "status": "model_upload_progress",
                        "upload_sha256": key,
                        "uploaded_bytes": sum(current.file_offsets),
                        "total_bytes": sum(f.size_bytes for f in bundle.files),
                    }
                )
            if current.payload_preserved:
                break
            uploaded = all(
                offset == record.size_bytes
                for offset, record in zip(current.file_offsets, bundle.files, strict=True)
            )
            if uploaded and time.monotonic() >= pending_report_at:
                report({"status": "model_preservation_pending", "upload_sha256": key})
                pending_report_at = time.monotonic() + 60
            if current.file_offsets == previous or uploaded:
                await asyncio.sleep(retry_seconds)
            current = await status_request("GET", path)

    report(
        {"status": "model_payload_preserved", "upload_sha256": key, "model_sha256": digest(bundle)}
    )
    return await _retry(
        lambda: submit_cohort_participation(
            origin=origin, policy=policy, request=request, transport=transport
        ),
        retry_seconds,
        report,
    )
