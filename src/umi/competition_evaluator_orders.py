"""Reference-free signed orders shared by evaluator and outcome verification."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field

from .competition_authorization import SignedEndpointAuthorization
from .competition_execution import ExecutionCase
from .competition_runner import OfflineRuntime
from .open_competition import EvaluationRound, Hotkey, ModelBundle, Signature, SignedSubmission
from .protocol import StrictProtocolModel


class EvaluationOrder(StrictProtocolModel):
    schema_: Literal["umi-evaluation-order/1"] = Field(alias="schema")
    round: EvaluationRound
    submission: SignedSubmission
    incumbent: ModelBundle
    runtime: OfflineRuntime
    cases: Annotated[tuple[ExecutionCase, ...], Field(min_length=3, max_length=2048)]
    evaluators: Annotated[tuple[Hotkey, ...], Field(min_length=1, max_length=64)]
    publication: SignedEndpointAuthorization | None = None
    no_weight: Literal[True] = True


class SignedEvaluationOrder(StrictProtocolModel):
    order: EvaluationOrder
    signatures: Annotated[tuple[Signature, ...], Field(min_length=1, max_length=64)]
