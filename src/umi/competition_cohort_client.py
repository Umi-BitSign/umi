"""HTTPS intake of an already signed recoverable-cohort participation request."""

from __future__ import annotations

import httpx

from .competition_client import CompetitionSubmissionError, post_intake_document
from .competition_cohort_participation import CohortParticipationReceipt, CohortParticipationRequest
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
