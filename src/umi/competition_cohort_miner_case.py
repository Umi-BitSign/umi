"""Single-case replacement grants with separately retained parent attempts.

A replacement has a fresh bounded transport window. Its parent is located by
an immutable archive key, rather than recursively embedded in each new grant.
The miner still verifies current phase authority and owned transport proofs.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, TypeAdapter

from .competition_authorization import validate_transport_cohort
from .competition_cohort_endpoint import endpoint_obligation_sha256, validate_endpoint_request_pairs
from .competition_cohort_endpoint_decision_contracts import SignedCohortEndpointCaseDecision
from .competition_cohort_execution import RecoverableExecutionJob
from .competition_cohort_execution_journal import CohortExecutionAssignment
from .competition_cohort_miner_contracts import CohortMinerGrant
from .competition_cohort_order_signer import order_slot
from .competition_cohort_recovery import verify_recovery_quorum
from .endpoint_retirement import SignedEndpointRetirementReceipt, verify_retirement_receipt
from .open_competition import (
    CompetitionPolicy,
    Signature,
    digest,
    has_case_coverage,
    identity,
    verify_signature,
)
from .policy import ScoringPolicy, scoring_policy_hash
from .protocol import (
    Hex32,
    StrictProtocolModel,
    TranslationRequest,
    canonical_json_bytes,
    request_digest,
)


class RecoverableEndpointCaseOrder(StrictProtocolModel):
    schema_: Literal["umi-recoverable-endpoint-case-order/1"] = Field(alias="schema")
    job: RecoverableExecutionJob
    transport_policy_sha256: Hex32
    case_id: Hex32
    attempt_number: Annotated[int, Field(ge=2, le=2**53 - 1)]
    requests: tuple[TranslationRequest]
    parent_grant_slot: Hex32
    parent_grant_sha256: Hex32
    prior_decision: SignedCohortEndpointCaseDecision
    prior_retirement: SignedEndpointRetirementReceipt
    chain_submission_authorized: Literal[False] = False


class SignedRecoverableEndpointCaseOrder(StrictProtocolModel):
    order: RecoverableEndpointCaseOrder
    signatures: Annotated[tuple[Signature, ...], Field(min_length=1, max_length=64)]


class CohortCaseMinerGrant(StrictProtocolModel):
    schema_: Literal["umi-cohort-miner-grant/2"] = Field(alias="schema")
    assignment: CohortExecutionAssignment
    attempt: SignedRecoverableEndpointCaseOrder


MinerGrant = Annotated[CohortMinerGrant | CohortCaseMinerGrant, Field(discriminator="schema_")]
_GRANT = TypeAdapter(MinerGrant)


def parse_miner_grant(raw: bytes | str) -> MinerGrant:
    if len(raw) > 16 * 1024**2:
        raise ValueError("cohort miner grant exceeds its byte bound")
    return _GRANT.validate_json(raw)


def grant_slot(grant: MinerGrant) -> str:
    if isinstance(grant, CohortMinerGrant):
        return digest(
            {
                "schema": "umi-cohort-miner-grant-slot/1",
                "assignment_slot": order_slot(grant.assignment.certificate.order),
                "evaluator": identity(grant.attempt.order.job.evaluator_hotkey),
            }
        )
    body = grant.attempt.order
    return digest(
        {
            "schema": "umi-cohort-miner-grant-slot/2",
            "obligation": endpoint_obligation_sha256(body.job, body.case_id),
            "attempt": body.attempt_number,
        }
    )


def validate_case_attempt(
    signed: SignedRecoverableEndpointCaseOrder,
    policy: CompetitionPolicy,
    transport: ScoringPolicy,
) -> SignedRecoverableEndpointCaseOrder:
    raw = canonical_json_bytes(signed)
    if len(raw) > 16 * 1024**2:
        raise ValueError("endpoint replacement exceeds its byte bound")
    signed = SignedRecoverableEndpointCaseOrder.model_validate_json(raw)
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    transport = ScoringPolicy.model_validate_json(canonical_json_bytes(transport))
    validate_transport_cohort(policy, transport)
    body, job = signed.order, signed.order.job
    verify_recovery_quorum(body, signed.signatures, policy)
    miner, evaluator = identity(job.submission.submission.hotkey), identity(job.evaluator_hotkey)
    if (
        job.mode != "endpoint_incumbent"
        or miner == evaluator
        or evaluator not in {identity(e.hotkey) for e in policy.evaluators}
        or evaluator not in {identity(v.validator_hotkey) for v in transport.validator_registry}
        or any(identity(s.hotkey) == miner for s in signed.signatures)
        or body.transport_policy_sha256 != scoring_policy_hash(transport)
        or not has_case_coverage(job.cases, policy)
    ):
        raise ValueError("endpoint replacement scope or signer differs")
    cases = [c for c in job.cases if c.case_id == body.case_id]
    if len(cases) != 1:
        raise ValueError("endpoint replacement case is not uniquely assigned")
    validate_endpoint_request_pairs(
        job, ((cases[0], body.requests[0]),), body.attempt_number, transport
    )
    cert, retirement = body.prior_decision, body.prior_retirement
    prior = cert.decision
    verify_recovery_quorum(prior, cert.signatures, policy)
    verify_signature(retirement.receipt, retirement.signature)
    if (
        any(identity(s.hotkey) == miner for s in cert.signatures)
        or identity(retirement.signature.hotkey) != miner
        or identity(retirement.receipt.miner_hotkey) != miner
        or identity(retirement.receipt.evaluator_hotkey) != evaluator
        or prior.policy_sha256 != digest(policy)
        or prior.cohort_sha256 != job.round.cohort_sha256
        or prior.obligation_sha256 != endpoint_obligation_sha256(job, body.case_id)
        or prior.case_id != body.case_id
        or prior.attempt_number + 1 != body.attempt_number
        or prior.disposition != "retry_required"
        or prior.response_sha256 is not None
        or retirement.receipt.result != "no_response_retained"
        or retirement.receipt.response_sha256 is not None
        or retirement.receipt.grant_sha256 != body.parent_grant_sha256
        or retirement.receipt.request_digest != prior.request_sha256
    ):
        raise ValueError("endpoint replacement lacks an exact certified unresolved parent")
    return signed


def verify_replacement_parent(grant: CohortCaseMinerGrant, parent: MinerGrant) -> None:
    """Bind the new request to the miner's retained, signed and fenced parent."""
    body, previous = grant.attempt.order, parent.attempt.order
    if (
        grant.assignment != parent.assignment
        or previous.job != body.job
        or grant_slot(parent) != body.parent_grant_slot
        or digest(parent) != body.parent_grant_sha256
        or previous.attempt_number + 1 != body.attempt_number
    ):
        raise ValueError("endpoint replacement parent differs from retained assignment")
    if isinstance(parent, CohortCaseMinerGrant):
        if previous.case_id != body.case_id:
            raise ValueError("endpoint replacement changes its case")
        request = previous.requests[0]
    else:
        matches = [i for i, case in enumerate(previous.job.cases) if case.case_id == body.case_id]
        if len(matches) != 1:
            raise ValueError("endpoint replacement parent has no unique case")
        request = previous.requests[matches[0]]
    if body.prior_decision.decision.request_sha256 != request_digest(request):
        raise ValueError("endpoint replacement decision changed its parent request")
    verify_retirement_receipt(
        body.prior_retirement,
        request=request,
        grant_sha256=digest(parent),
        miner_hotkey=body.job.submission.submission.hotkey,
        evaluator_hotkey=body.job.evaluator_hotkey,
    )
    if body.requests[0].issued_block <= request.deadline_block:
        raise ValueError("endpoint replacement overlaps its retired parent window")
