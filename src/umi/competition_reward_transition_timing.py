"""Elapsed finalized chain time for an explicitly signed successor release.

This is distinct from accumulated validator opportunity and cohort intake age.
The first matching live row and the later observation are native proof facts;
local clocks and nominal block times cannot substitute for either timestamp.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field, model_validator

from .competition_cohort_recovery import Block
from .competition_reward_timing import Timestamp
from .open_competition import digest, identity
from .protocol import Hex32, StrictProtocolModel

REWARD_TRANSITION_WAIT_MS = 24 * 60 * 60 * 1000


class RewardPredecessorLiveAge(StrictProtocolModel):
    schema_: Literal["umi-reward-predecessor-live-age/1"] = Field(alias="schema")
    series_sha256: Hex32
    chain_config_sha256: Hex32
    predecessor_activation_sha256: Hex32
    validator_account_id: Hex32
    live_at_block: Block
    live_block_hash: Hex32
    live_timestamp_ms: Timestamp
    live_endpoint_sha256: Hex32
    observed_at_block: Block
    observed_block_hash: Hex32
    observed_timestamp_ms: Timestamp
    observation_evidence_sha256: Hex32

    @model_validator(mode="after")
    def chronological(self):
        if (
            self.observed_at_block < self.live_at_block
            or self.observed_timestamp_ms < self.live_timestamp_ms
            or (
                self.observed_at_block == self.live_at_block
                and (
                    self.observed_block_hash != self.live_block_hash
                    or self.observed_timestamp_ms != self.live_timestamp_ms
                )
            )
        ):
            raise ValueError("reward live age changes its finalized observation order")
        return self

    @property
    def remaining_ms(self) -> int:
        return max(
            0, REWARD_TRANSITION_WAIT_MS - (self.observed_timestamp_ms - self.live_timestamp_ms)
        )

    @property
    def ready(self) -> bool:
        return self.remaining_ms == 0

    def check_boundary(self, *, series, predecessor, issued_at_block):
        if (
            self.series_sha256 != digest(series)
            or predecessor.activation is None
            or self.predecessor_activation_sha256 != digest(predecessor.activation)
            or self.validator_account_id not in {identity(k) for k in series.validators}
            or self.live_at_block < predecessor.observed_at_block
            or self.observed_at_block > issued_at_block
            or not self.ready
        ):
            raise ValueError("automatic reward release lacks its exact 24-hour live boundary")
