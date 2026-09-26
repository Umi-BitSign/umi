"""Immutable evaluator selections and attempt-addressed endpoint evidence."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, TypeAdapter

from .competition_cohort_endpoint import SignedRecoverableEndpointOrder, endpoint_obligation_sha256
from .competition_cohort_miner_case import CohortCaseMinerGrant, grant_slot
from .competition_cohort_miner_contracts import CohortMinerGrant
from .competition_cohort_order_signer import order_slot
from .endpoint_response_recovery import RecoveredEndpointResponse
from .open_competition import digest
from .policy import ScoringPolicy
from .protocol import Hex32, StrictProtocolModel


class CohortEndpointRecoverySelection(StrictProtocolModel):
    schema_: Literal["umi-cohort-endpoint-recovery-selection/1"] = Field(alias="schema")
    assignment_slot: Hex32
    order: SignedRecoverableEndpointOrder
    transport_policy: ScoringPolicy


class CohortRecoveredEndpointCase(StrictProtocolModel):
    schema_: Literal["umi-cohort-recovered-endpoint-case/1"] = Field(alias="schema")
    selection_sha256: Hex32
    case_id: Hex32
    origin_evidence_sha256: Hex32
    response: RecoveredEndpointResponse
    # This is deliberately not a RecoverableEndpointTranscript or a score.
    original_receipt_timing_proven: Literal[False] = False
    chain_submission_authorized: Literal[False] = False


class CohortEndpointReplacementSelection(StrictProtocolModel):
    schema_: Literal["umi-cohort-endpoint-replacement-selection/1"] = Field(alias="schema")
    grant: CohortCaseMinerGrant
    transport_policy: ScoringPolicy

    @property
    def assignment_slot(self):
        return order_slot(self.grant.assignment.certificate.order)

    @property
    def order(self):
        return self.grant.attempt


EndpointSelection = Annotated[
    CohortEndpointRecoverySelection | CohortEndpointReplacementSelection,
    Field(discriminator="schema_"),
]
_SELECTION = TypeAdapter(EndpointSelection)


def parse_endpoint_selection(raw):
    if len(raw) > 16 * 1024**2:
        raise ValueError("endpoint selection exceeds its byte bound")
    return _SELECTION.validate_json(raw)


def selection_slot(selected: EndpointSelection) -> str:
    if isinstance(selected, CohortEndpointReplacementSelection):
        return grant_slot(selected.grant)
    return selected.assignment_slot


def selection_grant(selected: EndpointSelection, assignment):
    if isinstance(selected, CohortEndpointReplacementSelection):
        if selected.grant.assignment != assignment:
            raise ValueError("endpoint replacement assignment changed")
        return selected.grant
    return CohortMinerGrant(
        schema="umi-cohort-miner-grant/1", assignment=assignment, attempt=selected.order
    )


def selected_requests(selected: EndpointSelection):
    body = selected.order.order
    if isinstance(selected, CohortEndpointReplacementSelection):
        return ((body.case_id, body.requests[0]),)
    return tuple((c.case_id, r) for c, r in zip(body.job.cases, body.requests, strict=True))


def selected_request(selected: EndpointSelection, case_id: str):
    matches = [request for case, request in selected_requests(selected) if case == case_id]
    if len(matches) != 1:
        raise ValueError("response recovery case is not uniquely assigned")
    return matches[0]


def case_record_key(selected: EndpointSelection, case_id: str) -> str:
    selected_request(selected, case_id)
    body = selected.order.order
    obligation = endpoint_obligation_sha256(body.job, case_id)
    if isinstance(selected, CohortEndpointRecoverySelection):
        # Preserve historical first-attempt records and queue keys verbatim.
        return obligation
    return digest(["umi-cohort-endpoint-attempt-record/1", obligation, body.attempt_number])
