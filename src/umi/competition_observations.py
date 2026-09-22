"""Signed execution observations shared by scored-result and void review paths."""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from .competition_dispatch_repair import EndpointUnavailableEvidence, unavailable_observations
from .competition_endpoint_execution import EndpointPairedEvidence, endpoint_execution_observations
from .competition_execution import ModelExecutionEvidence, revealed_execution_observations
from .open_competition import Hotkey, Signature
from .protocol import Hex32, StrictProtocolModel


class ExecutionAnnouncement(StrictProtocolModel):
    schema_: Literal["umi-execution-announcement/1"] = Field(alias="schema")
    order_sha256: Hex32
    evaluator_hotkey: Hotkey
    evidence: ModelExecutionEvidence | EndpointPairedEvidence | EndpointUnavailableEvidence


class SignedExecutionAnnouncement(StrictProtocolModel):
    announcement: ExecutionAnnouncement
    signature: Signature


def execution_observations(evidence, suite, policy, *, current_block):
    if isinstance(evidence, EndpointUnavailableEvidence):
        return unavailable_observations(evidence, suite, policy, current_block=current_block)
    if isinstance(evidence, EndpointPairedEvidence):
        return endpoint_execution_observations(evidence, suite, policy, current_block=current_block)
    return revealed_execution_observations(evidence, suite, policy, current_block=current_block)
