"""Canonical public launch identity shared by intake and round preparation."""

from typing import Annotated, Literal

from pydantic import Field, model_validator
from typing_extensions import Self

from .protocol import StrictProtocolModel


class PublicRoundSchedule(StrictProtocolModel):
    """Published block schedule for one competition round."""

    schema_: Literal["umi-public-round-schedule/1"] = Field(alias="schema")
    intake_opened_block: Annotated[int, Field(ge=0, le=2**53 - 1)]
    roster_close_earliest_block: Annotated[int, Field(ge=0, le=2**53 - 1)]
    roster_close_latest_block: Annotated[int, Field(ge=0, le=2**53 - 1)]
    work_signing_close_block: Annotated[int, Field(ge=0, le=2**53 - 1)]
    evaluation_close_block: Annotated[int, Field(ge=0, le=2**53 - 1)]
    protected_reference_reveal_block: Annotated[int, Field(ge=0, le=2**53 - 1)]
    evidence_cutoff_block: Annotated[int, Field(ge=0, le=2**53 - 1)]
    round_valid_through_block: Annotated[int, Field(ge=0, le=2**53 - 1)]

    @model_validator(mode="after")
    def ordered(self) -> Self:
        if not (
            self.intake_opened_block
            < self.roster_close_earliest_block
            <= self.roster_close_latest_block
            < self.work_signing_close_block
            < self.evaluation_close_block
            < self.protected_reference_reveal_block
            < self.evidence_cutoff_block
            < self.round_valid_through_block
        ):
            raise ValueError("public round schedule is not ordered")
        return self


class PublicLaunchIdentity(StrictProtocolModel):
    """Immutable public semantics of one launch, independent of its deployment."""

    schema_: Literal["umi-competition-public-launch/1"] = Field(alias="schema")
    round_schedule: PublicRoundSchedule
    eligible_tracks: Annotated[
        tuple[Literal["endpoint", "model"], ...], Field(min_length=1, max_length=2)
    ]

    @model_validator(mode="after")
    def canonical_tracks(self) -> Self:
        if tuple(sorted(set(self.eligible_tracks))) != self.eligible_tracks:
            raise ValueError("launch eligible tracks must be sorted and unique")
        return self


class PublicIntakeDeployment(StrictProtocolModel):
    """Public identity of the deployed intake, separate from repository HEAD."""

    schema_: Literal["umi-competition-intake-deployment/2"] = Field(alias="schema")
    repository: Literal["https://github.com/Umi-BitSign/umi"]
    umi_git_revision: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
    umi_source_tree_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    deployed_at_utc: Annotated[
        str,
        Field(pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"),
    ]
    round_schedule: PublicRoundSchedule
    eligible_tracks: Annotated[
        tuple[Literal["endpoint", "model"], ...], Field(min_length=1, max_length=2)
    ]
    assignment_delivery_ready: bool
    model_intake_ready: bool

    @model_validator(mode="after")
    def eligibility(self) -> Self:
        self.launch_identity()
        if self.model_intake_ready != ("model" in self.eligible_tracks):
            raise ValueError("model intake readiness differs from eligible tracks")
        return self

    def launch_identity(self) -> PublicLaunchIdentity:
        return PublicLaunchIdentity(
            schema="umi-competition-public-launch/1",
            round_schedule=self.round_schedule,
            eligible_tracks=self.eligible_tracks,
        )
