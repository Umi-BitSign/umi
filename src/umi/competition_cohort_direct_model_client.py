"""Miner-side direct multipart model delivery selected by a signed cohort plan."""

from __future__ import annotations

import asyncio
import bisect
import hashlib
import math
import os
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any

import httpx

from .competition_artifacts import _artifact, _directory
from .competition_client import MAX_SUBMISSION_BYTES, CompetitionSubmissionError
from .competition_cohort_client import submit_cohort_participation
from .competition_cohort_direct_model_upload import (
    DirectModelPayload,
    DirectModelUploadCompletion,
    DirectModelUploadObject,
    DirectModelUploadPart,
    DirectModelUploadPartCapabilities,
    DirectModelUploadPartRequest,
    DirectModelUploadReservationRequest,
    DirectModelUploadRestartRequest,
    DirectModelUploadStatus,
    SignedDirectModelPayload,
    SignedDirectModelUploadCompletion,
    SignedDirectModelUploadPartRequest,
    SignedDirectModelUploadReservation,
    SignedDirectModelUploadRestartRequest,
)
from .competition_cohort_model_client import (
    _Fingerprint,
    _fingerprint,
    _retry,
    _snapshot,
    _verify_source,
)
from .competition_cohort_participation import (
    CohortParticipationReceipt,
    CohortParticipationRequest,
)
from .competition_cohort_recovery import ModelDeliveryProfile
from .concurrency import run_owned_thread
from .open_competition import CompetitionPolicy, ModelBundle, digest, identity, sign_object
from .protocol import canonical_json_bytes

_READ_BYTES = 8 * 1024**2
_Report = Callable[[dict], None]


def _payload_digest(
    source: Path,
    bundle: ModelBundle,
    fingerprints: tuple[_Fingerprint, ...],
) -> str:
    value = hashlib.sha256()
    with _directory(source) as root:
        for record, expected in zip(bundle.files, fingerprints, strict=True):
            with _artifact(root, record) as (stream, info):
                if _fingerprint(info) != expected:
                    raise ValueError("model source changed; rerun with the original bundle")
                remaining = record.size_bytes
                while remaining:
                    data = stream.read(min(_READ_BYTES, remaining))
                    if not data:
                        raise ValueError("model source ended before its signed manifest")
                    value.update(data)
                    remaining -= len(data)
                if _fingerprint(os.fstat(stream.fileno())) != expected:
                    raise ValueError("model source changed during payload hashing")
    return value.hexdigest()


def _offsets(bundle: ModelBundle) -> tuple[int, ...]:
    result = []
    total = 0
    for record in bundle.files:
        result.append(total)
        total += record.size_bytes
    return tuple(result)


def _read_payload_chunk(
    source: Path,
    bundle: ModelBundle,
    fingerprints: tuple[_Fingerprint, ...],
    offsets: tuple[int, ...],
    offset: int,
    maximum_bytes: int,
) -> bytes:
    total = sum(record.size_bytes for record in bundle.files)
    if not 0 <= offset < total or not 1 <= maximum_bytes <= _READ_BYTES:
        raise ValueError("direct model source range differs")
    index = bisect.bisect_right(offsets, offset) - 1
    record = bundle.files[index]
    within = offset - offsets[index]
    size = min(maximum_bytes, record.size_bytes - within)
    with _directory(source) as root, _artifact(root, record) as (stream, info):
        if _fingerprint(info) != fingerprints[index]:
            raise ValueError("model source changed; rerun with the original bundle")
        stream.seek(within)
        data = stream.read(size)
        if len(data) != size or _fingerprint(os.fstat(stream.fileno())) != fingerprints[index]:
            raise ValueError("model source changed during direct upload")
        return data


async def _part_stream(
    source: Path,
    bundle: ModelBundle,
    fingerprints: tuple[_Fingerprint, ...],
    offsets: tuple[int, ...],
    *,
    offset: int,
    size_bytes: int,
) -> AsyncIterator[bytes]:
    remaining = size_bytes
    current = offset
    while remaining:
        data = await run_owned_thread(
            _read_payload_chunk,
            source,
            bundle,
            fingerprints,
            offsets,
            current,
            min(_READ_BYTES, remaining),
        )
        current += len(data)
        remaining -= len(data)
        yield data


async def _json_exchange(
    client: httpx.AsyncClient,
    method: str,
    path: str,
    *,
    body: bytes = b"",
    maximum_bytes: int = 4 * 1024**2,
) -> bytes:
    try:
        async with client.stream(
            method,
            path,
            content=body,
            headers={"Content-Type": "application/json"} if body else None,
        ) as response:
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
            value = bytearray()
            async for part in response.aiter_bytes():
                if len(value) + len(part) > maximum_bytes:
                    raise CompetitionSubmissionError("model_upload_status_too_large")
                value.extend(part)
            return bytes(value)
    except (httpx.HTTPError, asyncio.TimeoutError):
        # Capability URLs are bearer credentials. Never retain them in an exception chain.
        raise CompetitionSubmissionError("model_upload_transport_unavailable") from None


async def _upload_part(
    client: httpx.AsyncClient,
    capability,
    source: Path,
    bundle: ModelBundle,
    fingerprints: tuple[_Fingerprint, ...],
    offsets: tuple[int, ...],
    payload: DirectModelPayload,
) -> DirectModelUploadPart:
    offset = (capability.part_number - 1) * payload.part_size_bytes
    try:
        async with client.stream(
            "PUT",
            capability.url,
            content=_part_stream(
                source,
                bundle,
                fingerprints,
                offsets,
                offset=offset,
                size_bytes=capability.size_bytes,
            ),
            headers={
                "Content-Type": "application/octet-stream",
                "Content-Length": str(capability.size_bytes),
                "Accept-Encoding": "identity",
            },
        ) as response:
            if response.status_code != 200:
                raise CompetitionSubmissionError(
                    "model_upload_rejected", status_code=response.status_code
                )
            if response.headers.get("content-encoding", "identity") != "identity":
                raise CompetitionSubmissionError("invalid_model_upload_encoding")
            received = 0
            async for chunk in response.aiter_bytes():
                received += len(chunk)
                if received > 64 * 1024:
                    raise CompetitionSubmissionError("model_upload_status_too_large")
            return DirectModelUploadPart(
                part_number=capability.part_number,
                size_bytes=capability.size_bytes,
                etag=response.headers.get("etag", ""),
            )
    except CompetitionSubmissionError:
        raise
    except (httpx.HTTPError, asyncio.TimeoutError):
        raise CompetitionSubmissionError("model_upload_transport_unavailable") from None


async def submit_direct_cohort_model(
    *,
    origin: str,
    policy: CompetitionPolicy,
    request: CohortParticipationRequest,
    source: Path,
    wallet: Any,
    delivery: ModelDeliveryProfile,
    fingerprints: tuple[_Fingerprint, ...] | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
    object_transport: httpx.AsyncBaseTransport | None = None,
    retry_seconds: float = 2,
    report: _Report = lambda _: None,
) -> CohortParticipationReceipt:
    """Upload directly to R2, verify remotely, then submit the retained consent."""

    import bittensor as bt

    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    request = CohortParticipationRequest.model_validate_json(canonical_json_bytes(request))
    delivery = ModelDeliveryProfile.model_validate_json(canonical_json_bytes(delivery))
    submission = request.signed_submission.submission
    signer = bt.resolve_signer(wallet, role="hotkey")
    if (
        delivery.mechanism != "direct_r2_multipart_v1"
        or delivery.part_size_bytes is None
        or delivery.maximum_concurrent_parts is None
        or submission.policy_sha256 != digest(policy)
        or submission.track != "model"
        or submission.model_bundle is None
        or identity(signer.ss58_address) != identity(submission.hotkey)
        or len(canonical_json_bytes(request)) > MAX_SUBMISSION_BYTES
        or not math.isfinite(retry_seconds)
        or not 0 < retry_seconds <= 60
    ):
        raise ValueError("direct model upload requires its signed cohort profile and hotkey")
    bundle = submission.model_bundle
    source = Path(os.path.abspath(source))
    if fingerprints is None:
        fingerprints = await run_owned_thread(_verify_source, source, bundle, policy)
    elif fingerprints != await run_owned_thread(_snapshot, source, bundle):
        raise ValueError("model source changed after verification")
    payload_sha256 = await run_owned_thread(_payload_digest, source, bundle, fingerprints)
    total_bytes = sum(record.size_bytes for record in bundle.files)
    payload = DirectModelPayload(
        schema="umi-direct-model-payload/1",
        upload_sha256=digest(request),
        model_sha256=digest(bundle),
        payload_sha256=payload_sha256,
        total_bytes=total_bytes,
        file_count=len(bundle.files),
        part_size_bytes=delivery.part_size_bytes,
        total_parts=math.ceil(total_bytes / delivery.part_size_bytes),
    )
    signed_payload = SignedDirectModelPayload(
        schema="umi-signed-direct-model-payload/1",
        payload=payload,
        signature=sign_object(payload, wallet),
    )
    reservation_request = DirectModelUploadReservationRequest(
        schema="umi-direct-model-upload-reservation-request/1",
        request=request,
        payload=signed_payload,
    )
    cohort = request.consent.consent.cohort_sha256
    offsets = _offsets(bundle)
    async with (
        httpx.AsyncClient(
            base_url=origin,
            transport=transport,
            timeout=httpx.Timeout(120, connect=10),
            follow_redirects=False,
            trust_env=False,
            headers={"Accept": "application/json", "Accept-Encoding": "identity"},
        ) as intake,
        httpx.AsyncClient(
            transport=object_transport,
            timeout=httpx.Timeout(None, connect=15),
            follow_redirects=False,
            trust_env=False,
        ) as objects,
    ):
        raw = await _retry(
            lambda: _json_exchange(
                intake,
                "POST",
                f"/v1/competition/cohorts/{cohort}/direct-model-uploads",
                body=canonical_json_bytes(reservation_request),
            ),
            retry_seconds,
            report,
        )
        try:
            reservation = SignedDirectModelUploadReservation.model_validate_json(raw)
            body = reservation.reservation
            if (
                body.cohort_sha256 != cohort
                or body.payload != payload
                or identity(body.hotkey) != identity(submission.hotkey)
                or identity(reservation.signature.hotkey)
                not in {identity(e.hotkey) for e in policy.evaluators}
            ):
                raise ValueError("direct upload reservation differs")
        except ValueError as error:
            raise CompetitionSubmissionError("invalid_model_upload_status") from error
        reservation_sha256 = digest(body)

        async def current_status() -> DirectModelUploadStatus:
            raw_status = await _retry(
                lambda: _json_exchange(
                    intake,
                    "GET",
                    f"/v1/competition/cohorts/{cohort}/direct-model-uploads/{reservation_sha256}",
                ),
                retry_seconds,
                report,
            )
            try:
                status = DirectModelUploadStatus.model_validate_json(raw_status)
                if status.reservation != reservation:
                    raise ValueError("direct upload status reservation differs")
            except ValueError:
                raise CompetitionSubmissionError("invalid_model_upload_status") from None
            if status.hold_reason_code is not None:
                raise CompetitionSubmissionError(status.hold_reason_code)
            return status

        async def restart_expired_generation() -> None:
            nonlocal reservation, body, reservation_sha256
            restart_request = DirectModelUploadRestartRequest(
                schema="umi-direct-model-upload-restart-request/1",
                reservation_sha256=reservation_sha256,
                generation=body.generation,
                reason_code="provider_upload_unavailable",
            )
            signed_restart = SignedDirectModelUploadRestartRequest(
                schema="umi-signed-direct-model-upload-restart-request/1",
                request=restart_request,
                signature=sign_object(restart_request, wallet),
            )
            previous_generation = body.generation
            raw_restart = await _retry(
                lambda: _json_exchange(
                    intake,
                    "POST",
                    f"/v1/competition/cohorts/{cohort}/direct-model-uploads/"
                    f"{reservation_sha256}/restart",
                    body=canonical_json_bytes(signed_restart),
                ),
                retry_seconds,
                report,
            )
            try:
                replacement = SignedDirectModelUploadReservation.model_validate_json(raw_restart)
                replacement_body = replacement.reservation
                if (
                    replacement_body.cohort_sha256 != cohort
                    or replacement_body.payload != payload
                    or replacement_body.generation <= previous_generation
                    or identity(replacement_body.hotkey) != identity(submission.hotkey)
                    or identity(replacement.signature.hotkey)
                    not in {identity(e.hotkey) for e in policy.evaluators}
                ):
                    raise ValueError("direct upload restart reservation differs")
            except ValueError:
                raise CompetitionSubmissionError("invalid_model_upload_status") from None
            reservation = replacement
            body = replacement_body
            reservation_sha256 = digest(body)
            report(
                {
                    "status": "model_upload_generation_restarted",
                    "upload_sha256": payload.upload_sha256,
                    "generation": body.generation,
                }
            )

        status = await current_status()
        if status.object_complete:
            while not status.payload_verified:
                report(
                    {
                        "status": "model_preservation_pending",
                        "upload_sha256": payload.upload_sha256,
                    }
                )
                await asyncio.sleep(max(15, retry_seconds))
                status = await current_status()
            report(
                {
                    "status": "model_payload_preserved",
                    "upload_sha256": payload.upload_sha256,
                    "model_sha256": payload.model_sha256,
                }
            )
            return await _retry(
                lambda: submit_cohort_participation(
                    origin=origin, policy=policy, request=request, transport=transport
                ),
                retry_seconds,
                report,
            )

        completed: dict[int, DirectModelUploadPart] = {}
        pending = list(range(1, payload.total_parts + 1))
        wait = retry_seconds
        while pending:
            batch = tuple(pending[: delivery.maximum_concurrent_parts])
            part_request = DirectModelUploadPartRequest(
                schema="umi-direct-model-upload-part-request/1",
                reservation_sha256=reservation_sha256,
                generation=body.generation,
                part_numbers=batch,
            )
            signed_part_request = SignedDirectModelUploadPartRequest(
                schema="umi-signed-direct-model-upload-part-request/1",
                request=part_request,
                signature=sign_object(part_request, wallet),
            )
            request_bytes = canonical_json_bytes(signed_part_request)
            raw = await _retry(
                lambda request_bytes=request_bytes: _json_exchange(
                    intake,
                    "POST",
                    f"/v1/competition/cohorts/{cohort}/direct-model-uploads/"
                    f"{reservation_sha256}/parts",
                    body=request_bytes,
                ),
                retry_seconds,
                report,
            )
            try:
                capabilities = DirectModelUploadPartCapabilities.model_validate_json(raw)
                if (
                    capabilities.reservation_sha256 != reservation_sha256
                    or capabilities.generation != body.generation
                    or tuple(value.part_number for value in capabilities.capabilities) != batch
                    or any(
                        value.reservation_sha256 != reservation_sha256
                        or value.generation != body.generation
                        or value.size_bytes
                        != min(
                            payload.part_size_bytes,
                            payload.total_bytes - (value.part_number - 1) * payload.part_size_bytes,
                        )
                        for value in capabilities.capabilities
                    )
                ):
                    raise CompetitionSubmissionError("invalid_model_upload_status")
            except ValueError:
                # Validation errors may embed the bearer capability URL.
                raise CompetitionSubmissionError("invalid_model_upload_status") from None
            results = await asyncio.gather(
                *(
                    _upload_part(
                        objects,
                        capability,
                        source,
                        bundle,
                        fingerprints,
                        offsets,
                        payload,
                    )
                    for capability in capabilities.capabilities
                ),
                return_exceptions=True,
            )
            retry = False
            restart = False
            for result in results:
                if isinstance(result, DirectModelUploadPart):
                    completed[result.part_number] = result
                elif isinstance(result, CompetitionSubmissionError) and result.status_code == 404:
                    restart = True
                elif isinstance(result, CompetitionSubmissionError) and (
                    result.reason_code == "model_upload_transport_unavailable"
                    or result.status_code in {403, 408, 429, 500, 502, 503, 504}
                ):
                    retry = True
                elif isinstance(result, BaseException):
                    raise result
                else:
                    raise RuntimeError("direct upload part returned an invalid result")
            if restart:
                await restart_expired_generation()
                completed.clear()
                pending = list(range(1, payload.total_parts + 1))
                wait = retry_seconds
                continue
            pending = [number for number in pending if number not in completed]
            report(
                {
                    "status": "model_upload_progress",
                    "upload_sha256": payload.upload_sha256,
                    "uploaded_bytes": sum(part.size_bytes for part in completed.values()),
                    "total_bytes": payload.total_bytes,
                }
            )
            if retry:
                report(
                    {
                        "status": "model_delivery_retry",
                        "reason_code": "model_upload_transport_unavailable",
                        "http_status": None,
                        "retry_seconds": wait,
                    }
                )
                await asyncio.sleep(wait)
                wait = min(60, wait * 2)
            else:
                wait = retry_seconds

        if fingerprints != await run_owned_thread(_snapshot, source, bundle):
            raise ValueError("model source changed during direct upload")
        completion = DirectModelUploadCompletion(
            schema="umi-direct-model-upload-completion/1",
            reservation_sha256=reservation_sha256,
            generation=body.generation,
            parts=tuple(completed[number] for number in range(1, payload.total_parts + 1)),
        )
        signed_completion = SignedDirectModelUploadCompletion(
            schema="umi-signed-direct-model-upload-completion/1",
            completion=completion,
            signature=sign_object(completion, wallet),
        )
        raw = await _retry(
            lambda: _json_exchange(
                intake,
                "POST",
                f"/v1/competition/cohorts/{cohort}/direct-model-uploads/"
                f"{reservation_sha256}/complete",
                body=canonical_json_bytes(signed_completion),
            ),
            retry_seconds,
            report,
        )
        completed_object = DirectModelUploadObject.model_validate_json(raw)
        if completed_object.reservation_sha256 != reservation_sha256:
            raise CompetitionSubmissionError("invalid_model_upload_status")
        while True:
            status = await current_status()
            if status.payload_verified:
                break
            report(
                {
                    "status": "model_preservation_pending",
                    "upload_sha256": payload.upload_sha256,
                }
            )
            await asyncio.sleep(max(15, retry_seconds))

    report(
        {
            "status": "model_payload_preserved",
            "upload_sha256": payload.upload_sha256,
            "model_sha256": payload.model_sha256,
        }
    )
    return await _retry(
        lambda: submit_cohort_participation(
            origin=origin, policy=policy, request=request, transport=transport
        ),
        retry_seconds,
        report,
    )
