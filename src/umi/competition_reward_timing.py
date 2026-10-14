"""Forward activation timing attested by the original recovery quorum.

These facts are signed as part of an adoption, never edited into an old series.
The producer must derive them from native chain proofs. The consumer checks the
quorum and immutable cohort binding; neither elapsed local time nor a nominal
block cadence is evidence of age. Transaction reconciliation remains separate.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, model_validator

from .competition_cohort_recovery import Block
from .open_competition import digest
from .protocol import Hex32, StrictProtocolModel

THREE_DAYS_MS = 3 * 24 * 60 * 60 * 1000
Timestamp = Annotated[int, Field(gt=0, le=2**53 - 1)]


class RewardActivationAge(StrictProtocolModel):
    schema_: Literal["umi-reward-activation-age/1"] = Field(alias="schema")
    rule: Literal["skip_activation_delay_if_older_than_three_days"]
    cohort_start_block: Block
    cohort_start_hash: Hex32
    cohort_start_timestamp_ms: Timestamp
    start_evidence_sha256: Hex32
    observed_at_block: Block
    observed_block_hash: Hex32
    observed_timestamp_ms: Timestamp
    observation_evidence_sha256: Hex32

    @model_validator(mode="after")
    def chronological(self):
        if (
            self.observed_at_block < self.cohort_start_block
            or self.observed_timestamp_ms < self.cohort_start_timestamp_ms
            or (
                self.observed_at_block == self.cohort_start_block
                and (
                    self.observed_block_hash != self.cohort_start_hash
                    or self.observed_timestamp_ms != self.cohort_start_timestamp_ms
                )
            )
        ):
            raise ValueError("activation age changes the order of its chain observations")
        return self

    def check_plan(self, plan):
        if self.cohort_start_block != plan.not_before_block:
            raise ValueError("activation age differs from the signed cohort start")

    @property
    def skips_activation_delay(self) -> bool:
        return self.observed_timestamp_ms - self.cohort_start_timestamp_ms > THREE_DAYS_MS


def activation_effective_block(series, decision, committed_at_block, reward_adoptions=None):
    """Deterministic START boundary for the exact signed activation.

    The caller supplies an authenticated decision and adoption selection. A
    newer adoption never changes an old decision, even in historical replay.
    Suspension END drains and transaction mortality do not use this function.
    """
    if decision.kind not in {"activate", "revise_activation", "resume_activation"}:
        return None
    activation = decision.activation
    if activation.reward_adoption_sha256 is not None:
        if reward_adoptions is None:
            raise ValueError("activation timing lacks its selected signed adoption")
        adopted = reward_adoptions.get(activation.reward_adoption_sha256).adoption
        if (
            adopted.cohort_sha256 != activation.cohort_sha256
            or adopted.allocation_sha256 != activation.allocation_sha256
            or adopted.package_sha256 != activation.package_sha256
            or adopted.effective_allocation_sha256 != activation.effective_allocation_sha256
            or adopted.issued_at_block > decision.observed_at_block
            or decision.observed_at_block > committed_at_block
        ):
            raise ValueError("activation timing changes its signed activation boundary")
        if adopted.activation_age is not None:
            plan = next(p for p in series.cohorts if digest(p) == activation.cohort_sha256)
            adopted.activation_age.check_plan(plan)
            if adopted.activation_age.skips_activation_delay:
                return committed_at_block
    return (
        committed_at_block
        + series.maximum_proof_lag_blocks
        + series.maximum_transaction_lifetime_blocks
    )
