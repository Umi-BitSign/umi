"""Typed command input documents and bounded JSON loading."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, TypeVar, overload

from pydantic import BaseModel, Field, TypeAdapter

from ..competition_endpoint_execution import EndpointPairedEvidence, RetainedRevealPulse
from ..competition_execution import ModelExecutionEvidence
from ..competition_outcomes import OutcomeEvidence
from ..open_competition import (
    AttestedResult,
    EvaluationRound,
    EvaluationSuite,
    SignedSubmission,
    StrictProtocolModel,
)

MAX_JSON_BYTES = 64 * 1024 * 1024

ModelT = TypeVar("ModelT", bound=BaseModel)
ValueT = TypeVar("ValueT")


class ReplayEntry(StrictProtocolModel):
    submission: SignedSubmission
    evaluation: AttestedResult


class ProjectionInput(StrictProtocolModel):
    round: EvaluationRound
    suite: EvaluationSuite
    entries: Annotated[tuple[ReplayEntry, ...], Field(min_length=1, max_length=512)]


class IndependentReplayEntry(StrictProtocolModel):
    """A frozen roster entry with scored evidence or an independently certified void."""

    submission: SignedSubmission
    evidence: OutcomeEvidence


class SettlementInput(StrictProtocolModel):
    round: EvaluationRound
    suite: EvaluationSuite
    entries: Annotated[tuple[IndependentReplayEntry, ...], Field(min_length=1, max_length=512)]


class ExecutionInputs(StrictProtocolModel):
    executions: Annotated[
        tuple[ModelExecutionEvidence | EndpointPairedEvidence, ...],
        Field(min_length=1, max_length=64),
    ]


class ExecutionRevealPulses(StrictProtocolModel):
    pulses: Annotated[tuple[RetainedRevealPulse, ...], Field(max_length=2048)]


class PublicationRoster(StrictProtocolModel):
    submissions: Annotated[tuple[SignedSubmission, ...], Field(min_length=1, max_length=512)]


class PublicationEvidenceInputs(StrictProtocolModel):
    entries: Annotated[tuple[IndependentReplayEntry, ...], Field(min_length=1, max_length=512)]


@overload
def load_json(path: str, model: type[ModelT]) -> ModelT: ...


@overload
def load_json(path: str, model: TypeAdapter[ValueT]) -> ValueT: ...


def load_json(path: str, model: type[ModelT] | TypeAdapter[ValueT]) -> ModelT | ValueT:
    """Validate a bounded document without exposing its contents on failure."""
    with Path(path).open("rb") as stream:
        data = stream.read(MAX_JSON_BYTES + 1)
    if len(data) > MAX_JSON_BYTES:
        raise ValueError("rehearsal JSON exceeds the byte limit")
    return (
        model.validate_json(data)
        if isinstance(model, TypeAdapter)
        else model.model_validate_json(data)
    )
