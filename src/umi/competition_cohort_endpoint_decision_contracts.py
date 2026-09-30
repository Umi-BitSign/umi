"""Stable signed endpoint decision bodies without runtime dependencies."""

from typing import Annotated, Literal

from pydantic import Field

from .open_competition import Signature
from .protocol import Hex32, StrictProtocolModel


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
