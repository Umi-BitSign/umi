"""Retained assignment authority for a current endpoint registration proof.

This scope permits origin discovery, not delivery of a translation request.
Individual requests still require live transport authorization and retry fencing.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from .competition_cohort_execution_journal import CohortExecutionAssignment
from .competition_cohort_order_queue import check_delivery_receipt
from .competition_cohort_order_signer import CohortOrderHistory, review_order
from .competition_cohort_orders import recoverable_order_job
from .competition_cohort_recovery import verify_recovery_quorum
from .open_competition import CompetitionPolicy, SignedSubmission, identity
from .protocol import StrictProtocolModel, canonical_json_bytes

MAX_ORIGIN_SCOPE_BYTES = 16 * 1024**2


class CohortEndpointOriginScope(StrictProtocolModel):
    schema_: Literal["umi-cohort-endpoint-origin-scope/1"] = Field(alias="schema")
    assignment: CohortExecutionAssignment
    source: CohortOrderHistory
    chain_submission_authorized: Literal[False] = False


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
