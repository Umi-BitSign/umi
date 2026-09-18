"""Immutable, policy-bound competition settlement records with no weight authority."""

from __future__ import annotations

import hashlib
from typing import Annotated, Literal

from pydantic import Field, model_serializer, model_validator
from typing_extensions import Self

from .open_competition import (
    DEPENDENCE_SUITE_SCHEMA,
    AttestedDependenceCalibration,
    EvaluationSuite,
    Hex32,
    Hotkey,
    RegistrationSnapshot,
    StrictProtocolModel,
    WeightProjection,
    digest,
)
from .protocol import canonical_json_bytes

Block = Annotated[int, Field(ge=0, le=2**53 - 1)]


class EvidenceCutoffSchedule(StrictProtocolModel):
    """An explicitly supplied cutoff bound to one complete round object."""

    schema_: Literal["umi-competition-evidence-cutoff/1"] = Field(alias="schema")
    policy_sha256: Hex32
    round_sha256: Hex32
    evidence_cutoff_block: Block


class PromotionHeadBinding(StrictProtocolModel):
    sequence: Annotated[int, Field(ge=0, le=2**53 - 1)]
    promotion_sha256: Hex32
    model_sha256: Hex32
    contributor_hotkey: Hotkey | None


class SettlementResultBinding(StrictProtocolModel):
    submission_sha256: Hex32
    result_sha256: Hex32
    independent_evidence_sha256: Hex32
    first_observed_block: Block


class SettlementVoidBinding(StrictProtocolModel):
    submission_sha256: Hex32
    void_decision_sha256: Hex32
    void_evidence_sha256: Hex32
    first_observed_block: Block


class CompetitionSettlement(StrictProtocolModel):
    """A durable replay record. It grants no permission to submit its projected row."""

    schema_: Literal[
        "umi-competition-settlement/1",
        "umi-competition-settlement/2",
        "umi-competition-settlement/3",
    ] = Field(alias="schema")
    policy_sha256: Hex32
    round_sha256: Hex32
    cutoff_schedule: EvidenceCutoffSchedule
    roster: Annotated[tuple[Hex32, ...], Field(min_length=1, max_length=512)]
    results: Annotated[
        tuple[SettlementResultBinding | SettlementVoidBinding, ...],
        Field(min_length=1, max_length=512),
    ]
    suite: EvaluationSuite
    registration_snapshot: RegistrationSnapshot
    promotion_head: PromotionHeadBinding
    projection: WeightProjection
    dependence_calibration: AttestedDependenceCalibration | None = None
    observed_block: Block
    chain_submission_authorized: Literal[False] = False

    @model_serializer(mode="wrap")
    def preserve_legacy_bytes(self, handler):
        value = handler(self)
        if self.dependence_calibration is None:
            value.pop("dependence_calibration", None)
        return value

    @model_validator(mode="after")
    def validate_bindings(self) -> Self:
        has_void = any(isinstance(item, SettlementVoidBinding) for item in self.results)
        is_dependence = self.suite.schema_ == DEPENDENCE_SUITE_SCHEMA
        if is_dependence:
            if (
                self.schema_ != "umi-competition-settlement/3"
                or self.dependence_calibration is None
            ):
                raise ValueError("dependence settlement requires version 3 and its calibration")
        elif (
            self.schema_ == "umi-competition-settlement/3"
            or self.dependence_calibration is not None
        ):
            raise ValueError("legacy settlement cannot carry dependence calibration")
        elif has_void != (self.schema_ == "umi-competition-settlement/2"):
            raise ValueError(
                "mixed void settlements require version 2; scored settlements use version 1"
            )
        result_submissions = [item.submission_sha256 for item in self.results]
        if list(self.roster) != sorted(set(self.roster)):
            raise ValueError("settlement roster must be sorted and unique")
        if result_submissions != list(self.roster):
            raise ValueError("settlement results must cover the complete roster in order")
        if self.cutoff_schedule.policy_sha256 != self.policy_sha256:
            raise ValueError("settlement cutoff belongs to another policy")
        if self.cutoff_schedule.round_sha256 != self.round_sha256:
            raise ValueError("settlement cutoff belongs to another round")
        if self.suite.policy_sha256 != self.policy_sha256:
            raise ValueError("settlement suite belongs to another policy")
        if self.dependence_calibration is not None and (
            self.dependence_calibration.calibration.policy_sha256 != self.policy_sha256
            or self.dependence_calibration.calibration.suite_sha256 != digest(self.suite)
        ):
            raise ValueError("settlement dependence calibration binding mismatch")
        if (
            self.projection.policy_sha256 != self.policy_sha256
            or self.projection.round_sha256 != self.round_sha256
            or self.projection.snapshot_sha256 != digest(self.registration_snapshot)
        ):
            raise ValueError("settlement projection binding mismatch")
        if self.observed_block < self.cutoff_schedule.evidence_cutoff_block:
            raise ValueError("settlement observation predates its evidence cutoff")
        if any(
            item.first_observed_block > self.cutoff_schedule.evidence_cutoff_block
            for item in self.results
        ):
            raise ValueError("settlement contains evidence first observed after cutoff")
        return self


def evidence_cutoff_schedule_digest(schedule: EvidenceCutoffSchedule) -> str:
    schedule = EvidenceCutoffSchedule.model_validate_json(canonical_json_bytes(schedule))
    return hashlib.sha256(
        b"umi-competition-evidence-cutoff-v1\0" + canonical_json_bytes(schedule)
    ).hexdigest()


def competition_settlement_digest(settlement: CompetitionSettlement) -> str:
    settlement = CompetitionSettlement.model_validate_json(canonical_json_bytes(settlement))
    domain = (
        b"umi-competition-settlement-v3\0"
        if settlement.schema_ == "umi-competition-settlement/3"
        else (
            b"umi-competition-settlement-v2\0"
            if settlement.schema_ == "umi-competition-settlement/2"
            else b"umi-competition-settlement-v1\0"
        )
    )
    return hashlib.sha256(domain + canonical_json_bytes(settlement)).hexdigest()


__all__ = [
    "CompetitionSettlement",
    "EvidenceCutoffSchedule",
    "PromotionHeadBinding",
    "SettlementResultBinding",
    "SettlementVoidBinding",
    "competition_settlement_digest",
    "evidence_cutoff_schedule_digest",
]
