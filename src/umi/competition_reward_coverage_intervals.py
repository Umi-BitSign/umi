"""Adjacent reward-opportunity intervals; no wall-clock or payment inference."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field

from .competition_reward_coverage import OwnedRewardCoverageEndpoint, validate_reward_coverage
from .open_competition import digest, identity
from .protocol import BlockHash, Hex32, StrictProtocolModel, canonical_json_bytes

Count = Annotated[int, Field(ge=0, le=2**53 - 1)]
Positive = Annotated[int, Field(ge=1, le=2**53 - 1)]


class RewardCoverageRule(StrictProtocolModel):
    """Explicit host selections; installing these bytes does not approve policy.

    There is no default interval cap or minimum. Series admission and minimum
    certification must independently bind the approved parameters before use.
    """

    schema_: Literal["umi-reward-coverage-rule/1"] = Field(alias="schema")
    series_sha256: Hex32
    runtime_profile_sha256: Hex32
    maximum_interval_ms: Positive


class CoveragePoint(StrictProtocolModel):
    """A storage hint; only native endpoint replay establishes these facts."""

    series_sha256: Hex32
    runtime_profile_sha256: Hex32
    activation_sha256: Hex32
    allocation_sha256: Hex32
    projection_sha256: Hex32
    validator_account_id: Hex32
    chain_config_sha256: Hex32
    block: Positive
    block_hash: BlockHash
    parent_hash: BlockHash
    state_root: BlockHash
    timestamp_ms: Count
    covered: bool

    def key(self) -> str:
        # Identity does not depend on a proof's encoding, capture time or the
        # receipt used to establish finality after a later restart.
        return digest(
            {
                "series": self.series_sha256,
                "validator": self.validator_account_id,
                "block_hash": self.block_hash,
            }
        )


class RewardCoverageInterval(StrictProtocolModel):
    """Retained arithmetic, not a native certificate or transaction permission."""

    schema_: Literal["umi-reward-coverage-interval/1"] = Field(alias="schema")
    rule_sha256: Hex32
    activation_sha256: Hex32
    validator_account_id: Hex32
    left: Hex32
    right: Hex32
    credited_ms: Positive

    def key(self) -> str:
        return digest({"rule": self.rule_sha256, "left": self.left, "right": self.right})


def coverage_point(value: OwnedRewardCoverageEndpoint, rule: RewardCoverageRule) -> CoveragePoint:
    rule = RewardCoverageRule.model_validate_json(canonical_json_bytes(rule))
    validate_reward_coverage(
        value,
        expected_series_sha256=rule.series_sha256,
        expected_runtime_profile_sha256=rule.runtime_profile_sha256,
    )
    e, prepared = value.eligibility, value.prepared
    ref = e.control.snapshot
    return CoveragePoint(
        series_sha256=rule.series_sha256,
        runtime_profile_sha256=e.runtime_profile_sha256,
        activation_sha256=digest(prepared.activation),
        allocation_sha256=digest(prepared.allocation),
        projection_sha256=digest(value.projection),
        validator_account_id=identity(e.subject.registrations[e.subject.validator_uid].hotkey),
        chain_config_sha256=e.control.chain_config_sha256,
        block=ref.block_number,
        block_hash=ref.block_hash,
        parent_hash=ref.parent_hash,
        state_root=ref.state_root,
        timestamp_ms=e.timestamp_ms,
        covered=value.covered,
    )


def _interval(left: CoveragePoint, right: CoveragePoint, rule: RewardCoverageRule):
    """Pure policy arithmetic over untrusted hints; the native boundary is below."""
    rule = RewardCoverageRule.model_validate_json(canonical_json_bytes(rule))
    left = CoveragePoint.model_validate_json(canonical_json_bytes(left))
    right = CoveragePoint.model_validate_json(canonical_json_bytes(right))
    if any(
        p.series_sha256 != rule.series_sha256
        or p.runtime_profile_sha256 != rule.runtime_profile_sha256
        for p in (left, right)
    ) or (left.validator_account_id, left.chain_config_sha256) != (
        right.validator_account_id,
        right.chain_config_sha256,
    ):
        raise ValueError("coverage interval changes its selected proof domain")
    if right.block != left.block + 1 or right.parent_hash != left.block_hash:
        raise ValueError("coverage interval requires adjacent finalized ancestry")
    elapsed = right.timestamp_ms - left.timestamp_ms
    if elapsed <= 0:
        raise ValueError("coverage interval timestamps are not increasing")
    if (
        not left.covered
        or not right.covered
        or (left.activation_sha256, left.allocation_sha256)
        != (right.activation_sha256, right.allocation_sha256)
    ):
        return None
    return RewardCoverageInterval(
        schema="umi-reward-coverage-interval/1",
        rule_sha256=digest(rule),
        activation_sha256=left.activation_sha256,
        validator_account_id=left.validator_account_id,
        left=left.key(),
        right=right.key(),
        credited_ms=min(elapsed, rule.maximum_interval_ms),
    )


def coverage_interval(
    left: OwnedRewardCoverageEndpoint, right: OwnedRewardCoverageEndpoint, rule: RewardCoverageRule
) -> RewardCoverageInterval | None:
    """Both endpoints must independently pass the complete native coverage path."""
    return _interval(coverage_point(left, rule), coverage_point(right, rule), rule)
