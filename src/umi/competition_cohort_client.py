"""HTTPS intake of an already signed recoverable-cohort participation request."""

from __future__ import annotations

import asyncio

import httpx

from .competition_client import (
    CompetitionSubmissionError,
    post_intake_document,
    validate_intake_origin,
)
from .competition_cohort_participation import (
    CohortAdmissionStatus,
    CohortParticipationReceipt,
    CohortParticipationRequest,
)
from .competition_cohort_recovery import verify_recovery_quorum
from .open_competition import CompetitionPolicy, digest
from .protocol import canonical_json_bytes


async def submit_cohort_participation(
    *,
    origin: str,
    policy: CompetitionPolicy,
    request: CohortParticipationRequest,
    transport: httpx.AsyncBaseTransport | None = None,
) -> CohortParticipationReceipt:
    """An intake claim awaits independent attestation; it authorizes no rewards.

    A retry sends identical signed bytes, including after the old submission
    interval. Only explicit cohort consent authorizes that continued participation.
    """
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    request = CohortParticipationRequest.model_validate_json(canonical_json_bytes(request))
    sub, consent = request.signed_submission.submission, request.consent.consent
    if sub.policy_sha256 != digest(policy):
        raise ValueError("cohort participation belongs to another policy")
    raw = await post_intake_document(
        origin=origin,
        path=f"/v1/competition/cohorts/{consent.cohort_sha256}/participation",
        body=canonical_json_bytes(request),
        transport=transport,
    )
    try:
        receipt = CohortParticipationReceipt.model_validate_json(raw)
    except ValueError as error:
        raise CompetitionSubmissionError("invalid_receipt") from error
    admission = receipt.proposed_admission
    if (
        admission.cohort_sha256 != consent.cohort_sha256
        or admission.consent_sha256 != digest(consent)
        or admission.submission_sha256 != digest(sub)
        or admission.admitted_at_block < max(consent.signed_at_block, sub.valid_from_block)
        or admission.uid >= policy.maximum_uids
    ):
        raise CompetitionSubmissionError("receipt_binding_mismatch")
    return receipt


async def fetch_cohort_admission(
    *,
    origin: str,
    policy: CompetitionPolicy,
    request: CohortParticipationRequest,
    transport: httpx.AsyncBaseTransport | None = None,
) -> CohortAdmissionStatus:
    """Read the participation certificate and verify its quorum and exact consent."""
    origin = validate_intake_origin(origin)
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    request = CohortParticipationRequest.model_validate_json(canonical_json_bytes(request))
    sub, consent = request.signed_submission.submission, request.consent.consent
    if sub.policy_sha256 != digest(policy):
        raise ValueError("cohort participation belongs to another policy")
    path = f"/v1/competition/cohorts/{consent.cohort_sha256}/admissions/{digest(consent)}"

    async def fetch():
        async with (
            httpx.AsyncClient(
                transport=transport,
                timeout=httpx.Timeout(20, connect=5),
                trust_env=False,
                follow_redirects=False,
            ) as client,
            client.stream(
                "GET", origin + path, headers={"Accept-Encoding": "identity"}
            ) as response,
        ):
            if response.status_code != 200:
                raise CompetitionSubmissionError(
                    "admission_unavailable", status_code=response.status_code
                )
            if (
                response.headers.get("content-type", "").split(";", 1)[0].strip()
                != "application/json"
            ):
                raise CompetitionSubmissionError("invalid_admission_content_type")
            if response.headers.get("content-encoding", "identity") != "identity":
                raise CompetitionSubmissionError("encoded_admission_not_allowed")
            data = bytearray()
            async for chunk in response.aiter_bytes():
                if len(data) + len(chunk) > 128 * 1024:
                    raise CompetitionSubmissionError("admission_byte_limit_exceeded")
                data.extend(chunk)
            return bytes(data)

    try:
        raw = await asyncio.wait_for(fetch(), timeout=25)
    except (httpx.HTTPError, asyncio.TimeoutError) as error:
        raise CompetitionSubmissionError("admission_transport_unavailable") from error
    try:
        status = CohortAdmissionStatus.model_validate_json(raw)
        if (status.policy_sha256, status.cohort_sha256, status.consent_sha256) != (
            digest(policy),
            consent.cohort_sha256,
            digest(consent),
        ):
            raise ValueError("admission status differs from its request")
        if status.certificate is not None:
            body = status.certificate.admission
            if (
                body.submission_sha256 != digest(sub)
                or body.uid >= policy.maximum_uids
                or (body.admitted_at_block < max(consent.signed_at_block, sub.valid_from_block))
            ):
                raise ValueError("admission certificate differs from its request")
            verify_recovery_quorum(body, status.certificate.signatures, policy)
        return status
    except ValueError as error:
        raise CompetitionSubmissionError("invalid_admission_certificate") from error
