"""Convert already owned live-row and current-finality facts for quorum signing.

The producer retains its earliest verified live endpoint. On later polls only
the fresh control observation changes; no opportunity intervals or model bytes
are reread. Independent signers must obtain these facts through their own native
owners before signing. Conversion alone grants no publication authority.
"""

from __future__ import annotations

from .competition_reward_control import validate_owned_reward_control
from .competition_reward_control_archive import (
    OwnedHistoricalRewardControl,
    validate_historical_reward_control,
)
from .competition_reward_coverage_intervals import coverage_point
from .competition_reward_transition_timing import RewardPredecessorLiveAge
from .open_competition import digest, identity


def predecessor_live_age_from_owned_control(
    *, series, predecessor, live_endpoint, observation, chain_config_sha256, rule
) -> RewardPredecessorLiveAge:
    validate = (
        validate_historical_reward_control
        if isinstance(observation, OwnedHistoricalRewardControl)
        else validate_owned_reward_control
    )
    validate(
        observation,
        expected_control_hotkey=series.control_hotkey,
        expected_chain_config_sha256=chain_config_sha256,
    )
    point = coverage_point(live_endpoint, rule)
    eligibility = getattr(live_endpoint, "eligibility", None)
    updated = (
        eligibility.subject.validator_last_update
        if eligibility is not None
        else live_endpoint.validator_last_update
    )
    if (
        predecessor.activation is None
        or predecessor.series_sha256 != digest(series)
        or observation.control_sha256 != digest(predecessor)
        or point.series_sha256 != digest(series)
        or point.chain_config_sha256 != chain_config_sha256
        or point.activation_sha256 != digest(predecessor.activation)
        or point.validator_account_id not in {identity(k) for k in series.validators}
        or not point.covered
        or live_endpoint.row_matches is not True
        or type(updated) is not int
        or updated != point.block
        or point.block < predecessor.observed_at_block
    ):
        raise ValueError("reward live age lacks its exact owned predecessor row-write endpoint")
    return RewardPredecessorLiveAge(
        schema="umi-reward-predecessor-live-age/1",
        series_sha256=point.series_sha256,
        chain_config_sha256=point.chain_config_sha256,
        predecessor_activation_sha256=point.activation_sha256,
        validator_account_id=point.validator_account_id,
        live_at_block=point.block,
        live_block_hash=point.block_hash.removeprefix("0x"),
        live_timestamp_ms=point.timestamp_ms,
        live_endpoint_sha256=point.key(),
        observed_at_block=observation.snapshot.block_number,
        observed_block_hash=observation.snapshot.block_hash.removeprefix("0x"),
        observed_timestamp_ms=observation.timestamp_ms,
        observation_evidence_sha256=observation.evidence_sha256,
    )
