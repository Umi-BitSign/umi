"""Canonical public launch identity shared by intake and round preparation."""

from typing import Annotated, Literal

from pydantic import Field, model_serializer, model_validator
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

    schema_: Literal["umi-competition-public-launch/1", "umi-competition-public-launch/2"] = Field(
        alias="schema"
    )
    round_schedule: PublicRoundSchedule
    eligible_tracks: Annotated[
        tuple[Literal["endpoint", "model"], ...], Field(min_length=1, max_length=2)
    ]
    round_stride_blocks: Annotated[int, Field(ge=1, le=2**53 - 1)] | None = None

    @model_serializer(mode="wrap")
    def preserve_legacy_bytes(self, handler):
        value = handler(self)
        if self.round_stride_blocks is None:
            value.pop("round_stride_blocks", None)
        return value

    @model_validator(mode="after")
    def canonical_tracks(self) -> Self:
        if tuple(sorted(set(self.eligible_tracks))) != self.eligible_tracks:
            raise ValueError("launch eligible tracks must be sorted and unique")
        if (self.schema_ == "umi-competition-public-launch/2") != (
            self.round_stride_blocks is not None
        ):
            raise ValueError("continuous intake requires a version 2 launch and explicit cadence")
        if self.round_stride_blocks is not None and self.round_stride_blocks <= (
            self.round_schedule.evidence_cutoff_block
            - self.round_schedule.roster_close_earliest_block
        ):
            raise ValueError("round cadence overlaps the preceding evidence window")
        return self

    def accepts_at(self, block: int) -> bool:
        """Admission stays open between version-2 cohorts; eligibility is separate."""
        if type(block) is not int or not 0 <= block <= 2**53 - 1:
            raise ValueError("admission block must be a protocol block number")
        return self.round_schedule.intake_opened_block <= block and (
            self.round_stride_blocks is not None
            or block <= self.round_schedule.roster_close_latest_block
        )

    def schedule_for_cycle(self, cycle: int) -> PublicRoundSchedule:
        """Derive a published cohort without changing the continuous intake opening."""
        if type(cycle) is not int or cycle < 0:
            raise ValueError("round cycle must be a nonnegative integer")
        if self.round_stride_blocks is None and cycle != 0:
            raise ValueError("a version 1 launch has only one cycle")
        shift = cycle * (self.round_stride_blocks or 0)
        body = self.round_schedule.model_dump(mode="json", by_alias=True)
        for key in PublicRoundSchedule.model_fields:
            if key not in {"schema_", "intake_opened_block"}:
                body[key] += shift
        return PublicRoundSchedule.model_validate(body)

    def contains_schedule(self, schedule: PublicRoundSchedule) -> bool:
        """Accept only exact cadence-derived cutoffs, including all settlement windows."""
        if self.round_stride_blocks is None:
            return schedule == self.round_schedule
        offset = schedule.roster_close_earliest_block - (
            self.round_schedule.roster_close_earliest_block
        )
        if offset < 0 or offset % self.round_stride_blocks:
            return False
        return schedule == self.schedule_for_cycle(offset // self.round_stride_blocks)

    def next_intake_schedule(self, block: int) -> PublicRoundSchedule:
        """Next guaranteed cohort deadline; late polling margins are never promised."""
        if type(block) is not int or not 0 <= block <= 2**53 - 1:
            raise ValueError("admission block must be a protocol block number")
        if self.round_stride_blocks is None:
            return self.round_schedule
        after_first = max(0, block - self.round_schedule.roster_close_earliest_block)
        cycle = (after_first + self.round_stride_blocks - 1) // self.round_stride_blocks
        return self.schedule_for_cycle(cycle)


class IntakeScheduleHold(StrictProtocolModel):
    """Operator scheduling state; never an admission or reward authorization."""

    schema_: Literal["umi-competition-intake-schedule-hold/1"] = Field(alias="schema")
    cohort_number: Annotated[int, Field(ge=1, le=2**31 - 1)]
    state: Literal["preparing"] = "preparing"
    reason_code: Literal["cohort_setup_in_progress"] = "cohort_setup_in_progress"
    automatic_advance: Literal[False] = False
    submission_close_block: None = None
    evaluation_start_block: None = None
    cohort_eligibility_confirmed: Literal[False] = False


class PublicIntakeDeployment(StrictProtocolModel):
    """Public identity of the deployed intake, separate from repository HEAD."""

    schema_: Literal[
        "umi-competition-intake-deployment/2", "umi-competition-intake-deployment/3"
    ] = Field(alias="schema")
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
    evaluation_ready: bool = False
    round_stride_blocks: Annotated[int, Field(ge=1, le=2**53 - 1)] | None = None
    intake_schedule_hold: IntakeScheduleHold | None = None

    @model_serializer(mode="wrap")
    def preserve_legacy_bytes(self, handler):
        value = handler(self)
        if self.round_stride_blocks is None:
            value.pop("round_stride_blocks", None)
        if self.intake_schedule_hold is None:
            value.pop("intake_schedule_hold", None)
        return value

    @model_validator(mode="after")
    def eligibility(self) -> Self:
        if self.intake_schedule_hold is not None and (
            self.round_stride_blocks is None or self.evaluation_ready
        ):
            raise ValueError(
                "schedule hold requires continuous intake without evaluation readiness"
            )
        if (self.schema_ == "umi-competition-intake-deployment/3") != (
            self.round_stride_blocks is not None
        ):
            raise ValueError("continuous deployment requires version 3 and explicit cadence")
        self.launch_identity()
        if self.model_intake_ready != ("model" in self.eligible_tracks):
            raise ValueError("model intake readiness differs from eligible tracks")
        if self.assignment_delivery_ready and "endpoint" not in self.eligible_tracks:
            raise ValueError("assignment delivery requires an eligible endpoint track")
        if self.evaluation_ready and (
            ("endpoint" in self.eligible_tracks and not self.assignment_delivery_ready)
            or ("model" in self.eligible_tracks and not self.model_intake_ready)
        ):
            raise ValueError("evaluation readiness requires every eligible track to be ready")
        return self

    def next_intake_schedule(self, block: int) -> PublicRoundSchedule | None:
        """A held future cohort has no published cutoff, regardless of elapsed cycles."""
        if self.intake_schedule_hold is not None:
            return None
        return self.launch_identity().next_intake_schedule(block)

    def launch_identity(self) -> PublicLaunchIdentity:
        return PublicLaunchIdentity(
            schema=(
                "umi-competition-public-launch/1"
                if self.round_stride_blocks is None
                else "umi-competition-public-launch/2"
            ),
            round_schedule=self.round_schedule,
            eligible_tracks=self.eligible_tracks,
            round_stride_blocks=self.round_stride_blocks,
        )
