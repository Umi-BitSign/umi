"""Retained assignment authority for a current endpoint registration proof.

This scope permits origin discovery, not delivery of a translation request.
Individual requests still require live transport authorization and retry fencing.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from .competition_cohort_execution_journal import CohortExecutionAssignment
from .competition_cohort_intake import history_tip
from .competition_cohort_order_queue import check_delivery_receipt
from .competition_cohort_order_signer import CohortOrderHistory, review_order
from .competition_cohort_orders import recoverable_order_job
from .competition_cohort_recovery import verify_recovery_quorum
from .competition_cohort_service_work import (
    ServiceWorkAssignment,
    review_service_assignment,
    review_service_catalog,
)
from .open_competition import CompetitionPolicy, SignedSubmission, identity
from .protocol import StrictProtocolModel, canonical_json_bytes

MAX_ORIGIN_SCOPE_BYTES = 16 * 1024**2


class CohortEndpointOriginScope(StrictProtocolModel):
    schema_: Literal["umi-cohort-endpoint-origin-scope/1"] = Field(alias="schema")
    assignment: CohortExecutionAssignment
    source: CohortOrderHistory
    chain_submission_authorized: Literal[False] = False


class CohortServiceOriginScope(StrictProtocolModel):
    schema_: Literal["umi-cohort-service-origin-scope/1"] = Field(alias="schema")
    assignment: ServiceWorkAssignment
    source: CohortOrderHistory
    chain_submission_authorized: Literal[False] = False


def review_origin_recovery_scope(scope, signed, policy, block):
    if not isinstance(scope, CohortServiceOriginScope):
        return review_endpoint_origin_scope(scope, signed, policy, block)
    raw = canonical_json_bytes(scope)
    if len(raw) > MAX_ORIGIN_SCOPE_BYTES:
        raise ValueError("service origin scope exceeds its byte bound")
    scope = CohortServiceOriginScope.model_validate_json(raw)
    assignment = review_service_assignment(scope.assignment, policy)
    if assignment.admission.submission != signed:
        raise ValueError("service origin scope changed its accepted submission")
    review_service_catalog(
        assignment.catalog,
        assignment.round,
        policy,
        scope.source,
        expected_tip_sha256=history_tip(scope.source.history),
        current_block=block,
    )
    if block < assignment.admission.observation.block:
        raise ValueError("service origin observation precedes its admission")
    return scope


def review_endpoint_origin_scope(
    scope: CohortEndpointOriginScope,
    signed: SignedSubmission,
    policy: CompetitionPolicy,
    block: int,
) -> CohortEndpointOriginScope:
    raw = canonical_json_bytes(scope)
    if len(raw) > MAX_ORIGIN_SCOPE_BYTES:
        raise ValueError("endpoint origin scope exceeds its byte bound")
    scope = CohortEndpointOriginScope.model_validate_json(raw)
    assignment = scope.assignment
    order = assignment.certificate.order
    receipt = check_delivery_receipt(assignment.certificate, assignment.delivery)
    job = recoverable_order_job(order, receipt.receipt.evaluator_hotkey)
    if (
        job.mode != "endpoint_incumbent"
        or order.submission != signed
        or any(
            identity(s.hotkey) == identity(signed.submission.hotkey)
            for s in assignment.certificate.signatures
        )
    ):
        raise ValueError("endpoint origin scope differs from its delivered assignment")
    verify_recovery_quorum(order, assignment.certificate.signatures, policy)
    review_order(order, assignment.participant, scope.source, policy, block)
    return scope
