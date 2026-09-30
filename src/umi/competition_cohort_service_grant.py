"""Catalog-bound single-case requests using native cohort and transport checks.

Quorum reviewers authenticate the accepted owner record before voting. Parsing
or replaying a grant does not establish that source authentication, dispatch
timing, successful execution or earned credit. The miner checks live authority.
"""

from __future__ import annotations

import hashlib
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .competition_authorization import validate_transport_cohort
from .competition_cohort_endpoint import validate_endpoint_request
from .competition_cohort_endpoint_decision_contracts import SignedCohortEndpointCaseDecision
from .competition_cohort_intake import history_tip
from .competition_cohort_order_signer import CohortOrderHistory
from .competition_cohort_recovery import verify_recovery_quorum
from .competition_cohort_request_window import EndpointRequestWindow
from .competition_cohort_service_work import (
    MAX_SERVICE_REQUEST_BYTES,
    ServiceWorkAssignment,
    review_service_assignment,
    review_service_catalog,
)
from .endpoint_retirement import SignedEndpointRetirementReceipt, verify_retirement_receipt
from .open_competition import CompetitionPolicy, Hotkey, Signature, digest, identity
from .policy import ScoringPolicy
from .protocol import (
    Hex32,
    StrictProtocolModel,
    TranslationRequest,
    base64url_encode,
    canonical_json_bytes,
    request_digest,
)

MAX_SERVICE_GRANT_BYTES = MAX_SERVICE_REQUEST_BYTES


class ServiceRequestBody(StrictProtocolModel):
    schema_: Literal["umi-cohort-service-request/1"] = Field(alias="schema")
    assignment: ServiceWorkAssignment
    evaluator_hotkey: Hotkey
    attempt_number: Annotated[int, Field(ge=1, le=2**53 - 1)] = 1
    request: TranslationRequest
    window: EndpointRequestWindow
    parent_grant_slot: Hex32 | None = None
    parent_grant_sha256: Hex32 | None = None
    prior_decision: SignedCohortEndpointCaseDecision | None = None
    prior_retirement: SignedEndpointRetirementReceipt | None = None
    chain_submission_authorized: Literal[False] = False

    @model_validator(mode="after")
    def parent_shape(self):
        fields = (
            self.parent_grant_slot,
            self.parent_grant_sha256,
            self.prior_decision,
            self.prior_retirement,
        )
        if any((v is not None) != (self.attempt_number > 1) for v in fields):
            raise ValueError("service replacement requires complete parent evidence")
        return self


class ServiceMinerGrant(StrictProtocolModel):
    schema_: Literal["umi-cohort-miner-service-grant/1"] = Field(alias="schema")
    body: ServiceRequestBody
    signatures: Annotated[tuple[Signature, ...], Field(min_length=1, max_length=64)]


def service_obligation(assignment: ServiceWorkAssignment, evaluator: str) -> str:
    return digest(
        {
            "schema": "umi-cohort-service-obligation/1",
            "work": assignment.admission.work_sha256,
            "submission": digest(assignment.admission.submission.submission),
            "evaluator": identity(evaluator),
        }
    )


def service_wire_ids(assignment: ServiceWorkAssignment, evaluator: str, attempt: int):
    if type(attempt) is not int or not 1 <= attempt <= 2**53 - 1:
        raise ValueError("invalid service attempt number")
    material = canonical_json_bytes([service_obligation(assignment, evaluator), attempt])
    return tuple(
        base64url_encode(hashlib.sha256(domain + material).digest()[:16])
        for domain in (
            b"umi-cohort-service-batch-v1\0",
            b"umi-cohort-service-challenge-v1\0",
        )
    )


def service_grant_slot(body: ServiceRequestBody) -> str:
    return digest(
        [
            "umi-cohort-service-request-slot/1",
            service_obligation(body.assignment, body.evaluator_hotkey),
            body.attempt_number,
        ]
    )


def review_service_request_current(body, policy, source: CohortOrderHistory, block: int):
    """Only an authenticated open request phase can admit fresh service work."""
    assignment = body.assignment
    review_service_catalog(
        assignment.catalog,
        assignment.round,
        policy,
        source,
        expected_tip_sha256=history_tip(source.history),
        current_block=block,
    )
    if block < max(assignment.admission.observation.block, body.request.issued_block):
        raise ValueError("service request authority predates admission or issuance")


def validate_service_body(
    body: ServiceRequestBody, policy: CompetitionPolicy, transport: ScoringPolicy
):
    raw = canonical_json_bytes(body)
    if len(raw) > MAX_SERVICE_GRANT_BYTES - 32 * 1024:
        raise ValueError("service request exceeds its byte bound")
    body = ServiceRequestBody.model_validate_json(raw)
    assignment = review_service_assignment(body.assignment, policy)
    validate_transport_cohort(policy, transport)
    admission = assignment.admission
    miner, evaluator = (
        identity(admission.submission.submission.hotkey),
        identity(body.evaluator_hotkey),
    )
    if (
        evaluator == miner
        or evaluator not in {identity(e.hotkey) for e in policy.evaluators}
        or evaluator not in {identity(v.validator_hotkey) for v in transport.validator_registry}
        or body.request.issued_block < admission.observation.block
    ):
        raise ValueError("service request evaluator or issuance differs")
    case = assignment.catalog.catalog.work[admission.ordinal - 1]
    validate_endpoint_request(
        case,
        body.request,
        service_wire_ids(assignment, body.evaluator_hotkey, body.attempt_number),
        transport,
    )
    body.window.check(body.request, transport)
    if body.attempt_number > 1:
        prior = body.prior_decision.decision
        retirement = body.prior_retirement
        verify_recovery_quorum(prior, body.prior_decision.signatures, policy)
        # Exact request/signature binding of retirement is checked against the
        # separately retained parent, never a recursively embedded lineage.
        if (
            any(identity(s.hotkey) == miner for s in body.prior_decision.signatures)
            or prior.policy_sha256 != digest(policy)
            or prior.cohort_sha256 != assignment.round.cohort_sha256
            or prior.obligation_sha256 != service_obligation(assignment, body.evaluator_hotkey)
            or prior.case_id != case.case_id
            or prior.attempt_number + 1 != body.attempt_number
            or prior.disposition != "retry_required"
            or prior.response_sha256 is not None
            or retirement.receipt.result != "no_response_retained"
            or retirement.receipt.response_sha256 is not None
        ):
            raise ValueError("service replacement lacks certified unresolved work")
    return body


def verify_service_grant(grant: ServiceMinerGrant, policy, transport):
    raw = canonical_json_bytes(grant)
    if len(raw) > MAX_SERVICE_GRANT_BYTES:
        raise ValueError("service grant exceeds its byte bound")
    grant = ServiceMinerGrant.model_validate_json(raw)
    body = validate_service_body(grant.body, policy, transport)
    verify_recovery_quorum(body, grant.signatures, policy)
    miner = identity(body.assignment.admission.submission.submission.hotkey)
    if any(identity(s.hotkey) == miner for s in grant.signatures):
        raise ValueError("miner cannot authorize its own service request")
    return grant


def verify_service_parent(grant: ServiceMinerGrant, parent: ServiceMinerGrant):
    verify_service_parent_body(grant.body, parent)


def verify_service_parent_body(body: ServiceRequestBody, parent: ServiceMinerGrant):
    previous = parent.body
    if (
        body.assignment != previous.assignment
        or identity(body.evaluator_hotkey) != identity(previous.evaluator_hotkey)
        or body.parent_grant_slot != service_grant_slot(previous)
        or body.parent_grant_sha256 != digest(parent)
        or body.attempt_number != previous.attempt_number + 1
        or body.prior_decision.decision.request_sha256 != request_digest(previous.request)
        or body.request.issued_block <= previous.request.deadline_block
    ):
        raise ValueError("service replacement changed its retained parent")
    verify_retirement_receipt(
        body.prior_retirement,
        request=previous.request,
        grant_sha256=digest(parent),
        miner_hotkey=body.assignment.admission.submission.submission.hotkey,
        evaluator_hotkey=body.evaluator_hotkey,
    )
