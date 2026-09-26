"""Review one endpoint attempt without discarding completed case responses.

These decisions select a retained response or require a replacement attempt.
They do not supply a replacement transport window, prove original receipt
timing, close requests, classify an outcome, or authorize weights.
"""

from __future__ import annotations

import hashlib
from typing import Annotated, Literal

from pydantic import Field

from .competition_cohort_endpoint import (
    endpoint_obligation_sha256,
    validate_recoverable_endpoint_transport,
)
from .competition_cohort_endpoint_recovery import (
    CohortEndpointRecoverySelection,
    CohortRecoveredEndpointCase,
)
from .competition_cohort_endpoint_retirement import CohortRetiredEndpointCase
from .competition_cohort_execution_journal import CohortExecutionAssignment
from .competition_cohort_miner import CohortMinerGrant
from .competition_cohort_order_queue import check_delivery_receipt
from .competition_cohort_order_signer import CohortOrderHistory, order_slot, review_order
from .competition_cohort_orders import recoverable_order_job
from .competition_cohort_recovery import verify_recovery_quorum
from .config import Limits
from .endpoint_response_recovery import verify_recovered_response
from .endpoint_retirement import verify_retirement_receipt
from .open_competition import CompetitionPolicy, Signature, digest, identity
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes, request_digest

MAX_CASE_REVIEW_BYTES = 64 * 1024**2


class CohortEndpointCaseReview(StrictProtocolModel):
    schema_: Literal["umi-cohort-endpoint-case-review/1"] = Field(alias="schema")
    assignment: CohortExecutionAssignment
    selection: CohortEndpointRecoverySelection
    retirement: CohortRetiredEndpointCase
    recovered: CohortRecoveredEndpointCase | None


class CohortEndpointCaseDecision(StrictProtocolModel):
    schema_: Literal["umi-cohort-endpoint-case-decision/1"] = Field(alias="schema")
    policy_sha256: Hex32
    cohort_sha256: Hex32
    obligation_sha256: Hex32
    case_id: Hex32
    attempt_number: Annotated[int, Field(ge=1, le=2**53 - 1)]
    review_sha256: Hex32
    request_sha256: Hex32
    disposition: Literal["retain_response", "retry_required"]
    response_sha256: Hex32 | None
    # A retry decision has no lease. Admission must independently supply a
    # current transport window and fence any replaced host/model process.
    transport_authorized: Literal[False] = False
    original_receipt_timing_proven: Literal[False] = False
    chain_submission_authorized: Literal[False] = False


class SignedCohortEndpointCaseDecision(StrictProtocolModel):
    decision: CohortEndpointCaseDecision
    signatures: Annotated[tuple[Signature, ...], Field(min_length=1, max_length=64)]


def case_decision_slot(decision: CohortEndpointCaseDecision) -> str:
    """One decision per obligation/attempt, independent of signature variants."""
    decision = CohortEndpointCaseDecision.model_validate_json(canonical_json_bytes(decision))
    return digest(
        {
            "schema": "umi-cohort-endpoint-case-decision-slot/1",
            "obligation": decision.obligation_sha256,
            "attempt": decision.attempt_number,
        }
    )


def validate_case_review(
    review: CohortEndpointCaseReview, policy: CompetitionPolicy
) -> tuple[CohortEndpointCaseReview, CohortEndpointCaseDecision]:
    """Replay signed bindings; callers separately own current authority/finality."""
    raw = canonical_json_bytes(review)
    if len(raw) > MAX_CASE_REVIEW_BYTES:
        raise ValueError("endpoint case review exceeds its byte bound")
    review = CohortEndpointCaseReview.model_validate_json(raw)
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    assignment, selected, retired = review.assignment, review.selection, review.retirement
    order = assignment.certificate.order
    verify_recovery_quorum(order, assignment.certificate.signatures, policy)
    miner = order.submission.submission.hotkey
    if any(identity(s.hotkey) == identity(miner) for s in assignment.certificate.signatures):
        raise ValueError("miner cannot authorize its own endpoint decision")
    receipt = check_delivery_receipt(assignment.certificate, assignment.delivery)
    evaluator = receipt.receipt.evaluator_hotkey
    job = recoverable_order_job(order, evaluator)
    attempt = validate_recoverable_endpoint_transport(
        selected.order, policy, selected.transport_policy
    ).order
    if (
        attempt.job != job
        or selected.assignment_slot != order_slot(order)
        or retired.selection_sha256 != digest(selected)
    ):
        raise ValueError("endpoint decision differs from its selected assignment")
    indices = [i for i, case in enumerate(job.cases) if case.case_id == retired.case_id]
    if len(indices) != 1:
        raise ValueError("endpoint decision case is not uniquely assigned")
    request = attempt.requests[indices[0]]
    grant = CohortMinerGrant(
        schema="umi-cohort-miner-grant/1", assignment=assignment, attempt=selected.order
    )
    closed = verify_retirement_receipt(
        retired.retirement,
        request=request,
        grant_sha256=digest(grant),
        miner_hotkey=miner,
        evaluator_hotkey=evaluator,
    ).receipt
    if closed.result == "no_response_retained":
        if (
            review.recovered is not None
            or retired.observed_block <= request.deadline_block
            or retired.observed_round < request.response_close_round
        ):
            raise ValueError("endpoint retry conflicts with response or expiry evidence")
        disposition = "retry_required"
    else:
        recovered = review.recovered
        if (
            recovered is None
            or recovered.selection_sha256 != digest(selected)
            or recovered.case_id != retired.case_id
        ):
            raise ValueError("endpoint decision lacks its exact retained response")
        verify_recovered_response(
            recovered.response,
            request=request,
            validator_hotkey=evaluator,
            miner_hotkey=miner,
            limits=Limits.from_policy(selected.transport_policy),
        )
        if hashlib.sha256(bytes.fromhex(recovered.response.envelope_hex)).hexdigest() != (
            closed.response_sha256
        ):
            raise ValueError("endpoint retirement conflicts with retained response")
        # Signed miner failures are retained exactly like successful responses.
        # Decryption, timing classification and scoring belong to later replay.
        disposition = "retain_response"
    return review, CohortEndpointCaseDecision(
        schema="umi-cohort-endpoint-case-decision/1",
        policy_sha256=digest(policy),
        cohort_sha256=job.round.cohort_sha256,
        obligation_sha256=endpoint_obligation_sha256(job, retired.case_id),
        case_id=retired.case_id,
        attempt_number=attempt.attempt_number,
        review_sha256=digest(review),
        request_sha256=request_digest(request),
        disposition=disposition,
        response_sha256=closed.response_sha256,
    )


def review_case_decision(
    review: CohortEndpointCaseReview,
    policy: CompetitionPolicy,
    source: CohortOrderHistory,
    *,
    observed_block: int,
    observed_round: int,
) -> CohortEndpointCaseDecision:
    """Check an independently observed current head before a new decision vote."""
    review, decision = validate_case_review(review, policy)
    if (
        type(observed_block) is not int
        or type(observed_round) is not int
        or observed_block < review.retirement.observed_block
        or observed_round < review.retirement.observed_round
    ):
        raise ValueError("endpoint decision precedes independently observed retirement")
    assignment = review.assignment
    review_order(
        assignment.certificate.order, assignment.participant, source, policy, observed_block
    )
    return decision


def certify_case_decision(
    review: CohortEndpointCaseReview,
    signatures: tuple[Signature, ...],
    policy: CompetitionPolicy,
) -> SignedCohortEndpointCaseDecision:
    review, body = validate_case_review(review, policy)
    if not 1 <= len(signatures) <= 64:
        raise ValueError("endpoint decision signature count is outside bounds")
    signatures = tuple(
        sorted(
            (Signature.model_validate_json(canonical_json_bytes(s)) for s in signatures),
            key=lambda s: identity(s.hotkey),
        )
    )
    miner = review.assignment.certificate.order.submission.submission.hotkey
    if any(identity(s.hotkey) == identity(miner) for s in signatures):
        raise ValueError("miner cannot certify its own endpoint decision")
    verify_recovery_quorum(body, signatures, policy)
    return SignedCohortEndpointCaseDecision(decision=body, signatures=signatures)


def verify_case_decision(
    certificate: SignedCohortEndpointCaseDecision,
    review: CohortEndpointCaseReview,
    policy: CompetitionPolicy,
) -> SignedCohortEndpointCaseDecision:
    certificate = SignedCohortEndpointCaseDecision.model_validate_json(
        canonical_json_bytes(certificate)
    )
    expected = certify_case_decision(review, certificate.signatures, policy)
    if certificate != expected:
        raise ValueError("endpoint decision certificate differs from reviewed evidence")
    return certificate
