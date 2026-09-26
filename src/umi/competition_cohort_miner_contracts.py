"""Stable miner grant and acknowledgement contracts shared by recovery consumers."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field

from .competition_cohort_endpoint import SignedRecoverableEndpointOrder
from .competition_cohort_execution_journal import CohortExecutionAssignment
from .open_competition import Hotkey, Signature
from .protocol import Hex32, StrictProtocolModel


class CohortMinerGrant(StrictProtocolModel):
    schema_: Literal["umi-cohort-miner-grant/1"] = Field(alias="schema")
    assignment: CohortExecutionAssignment
    attempt: SignedRecoverableEndpointOrder


class CohortMinerGrantReceipt(StrictProtocolModel):
    schema_: Literal["umi-cohort-miner-grant-receipt/1"] = Field(alias="schema")
    grant_sha256: Hex32
    miner_hotkey: Hotkey
    observed_block: Annotated[int, Field(ge=0)]
    status: Literal["retained"] = "retained"
    chain_submission_authorized: Literal[False] = False


class SignedCohortMinerGrantReceipt(StrictProtocolModel):
    receipt: CohortMinerGrantReceipt
    signature: Signature
