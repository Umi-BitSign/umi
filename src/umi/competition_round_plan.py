"""Private round plans and cutoff proposals shared by transport and storage."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, model_serializer, model_validator

from .competition_launch import PublicRoundSchedule
from .competition_publication import CutoffPublication
from .open_competition import (
    AttestedDependenceCalibration,
    EvaluationSuite,
    SignedSubmission,
    Track,
)
from .protocol import StrictProtocolModel

Block = Annotated[int, Field(ge=0, le=2**53 - 1)]


class RoundPlan(StrictProtocolModel):
    """Private operator input with explicit windows, never a remote request."""

    schema_: Literal["umi-round-plan/2"] = Field(alias="schema")
    suite: EvaluationSuite
    dependence_calibration: AttestedDependenceCalibration | None = None
    public_schedule: PublicRoundSchedule
    eligible_tracks: Annotated[tuple[Track, ...], Field(min_length=1, max_length=2)]
    intake_opened_block: Block
    not_before_block: Block
    admission_close_by_block: Block
    signing_close_block: Block
    evaluation_close_block: Block
    reveal_block: Block
    evidence_cutoff_block: Block
    valid_through_block: Block

    @model_serializer(mode="wrap")
    def preserve_legacy_bytes(self, handler):
        value = handler(self)
        if self.dependence_calibration is None:
            value.pop("dependence_calibration", None)
        return value

    @model_validator(mode="after")
    def windows(self):
        schedule = self.public_schedule
        if not (
            self.intake_opened_block
            <= self.not_before_block
            <= self.admission_close_by_block
            < self.signing_close_block
            < self.evaluation_close_block
            < self.reveal_block
            <= self.evidence_cutoff_block
            <= self.valid_through_block
        ):
            raise ValueError("round plan windows are not ordered")
        if (
            self.intake_opened_block,
            self.not_before_block,
            self.admission_close_by_block,
            self.signing_close_block,
            self.evaluation_close_block,
            self.reveal_block,
            self.evidence_cutoff_block,
            self.valid_through_block,
        ) != (
            schedule.intake_opened_block,
            schedule.roster_close_earliest_block,
            schedule.roster_close_latest_block,
            schedule.work_signing_close_block,
            schedule.evaluation_close_block,
            schedule.protected_reference_reveal_block,
            schedule.evidence_cutoff_block,
            schedule.round_valid_through_block,
        ):
            raise ValueError("round plan differs from its public schedule")
        if tuple(sorted(set(self.eligible_tracks))) != self.eligible_tracks:
            raise ValueError("eligible tracks must be sorted and unique")
        return self


class RoundProposal(StrictProtocolModel):
    schema_: Literal["umi-round-proposal/1"] = Field(alias="schema")
    cutoff: CutoffPublication
    submissions: Annotated[tuple[SignedSubmission, ...], Field(min_length=1, max_length=512)]
    signing_close_block: Block
    chain_submission_authorized: Literal[False] = False
