"""References to exact terminal case evidence; no phase or reward authority."""

from typing import Annotated, Literal

from pydantic import Field

from .protocol import Hex32, StrictProtocolModel


class EndpointTerminalCase(StrictProtocolModel):
    case_id: Hex32
    selection_slot: Hex32
    selection_sha256: Hex32
    review_sha256: Hex32
    decision_sha256: Hex32


class EndpointTerminalSelection(StrictProtocolModel):
    schema_: Literal["umi-cohort-endpoint-terminal-selection/1"] = Field(alias="schema")
    assignment_sha256: Hex32
    job_sha256: Hex32
    cases: Annotated[tuple[EndpointTerminalCase, ...], Field(min_length=1, max_length=2048)]
    request_closure_authorized: Literal[False] = False
    chain_submission_authorized: Literal[False] = False
