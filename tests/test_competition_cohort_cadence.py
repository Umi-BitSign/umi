"""Regression: a qualified cohort must not drift out of its transport window."""

import pytest

from umi.competition_dispatch_capacity import (
    DispatchCapacityJob,
    DispatchTimingBudget,
    DispatchTimingLimits,
    plan_dispatch_capacity,
)
from umi.competition_scheduling import _clock
from umi.policy import ScoringPolicy, scoring_policy_hash
from umi.window import QUICKNET_GENESIS_MS, QUICKNET_PERIOD_MS

from .test_policy import make_policy


def transport(stride=None, allowance=21600, response=300):
    legacy = make_policy()
    return ScoringPolicy.competition_transport(
        activation_block=9119670,
        implementation_pins=legacy.implementation_pins,
        validator=legacy.validator_registry[0],
        issue_allowance_seconds=allowance,
        response_window_seconds=response,
        window_stride_blocks=stride,
    )


def capacity(
    policy,
    cycle,
    miners,
    *,
    cohort_stride=2880,
    evaluation_span=2120,
    request_timeout_seconds=315,
    publication_delay_ms=3600000,
):
    roster = 9119790 + cycle * cohort_stride
    issued = roster + 12
    index = (issued - policy.activation_block) // policy.clock.window_stride_blocks
    announcement = policy.activation_block + index * policy.clock.window_stride_blocks
    announced_ms = 1_800_000_000_000
    schedule = _clock(policy).derive(
        index,
        netuid=78,
        announcement_block_hash="0x" + "ab" * 32,
        announcement_timestamp_ms=announced_ms,
        scoring_policy_hash=scoring_policy_hash(policy),
    )
    issue_close = QUICKNET_GENESIS_MS + (schedule.issue_close_round - 1) * QUICKNET_PERIOD_MS
    response_close = QUICKNET_GENESIS_MS + (schedule.response_close_round - 1) * QUICKNET_PERIOD_MS
    deadline = issued + schedule.response_deadline_blocks
    if deadline > roster + evaluation_span:
        raise ValueError("request deadline exceeds cohort evaluation close")
    now = announced_ms + (issued - announcement) * 12000
    jobs = [
        DispatchCapacityJob(
            assignment_key=f"{miner * 6 + case:064x}",
            miner_account=f"{miner + 1:064x}",
            publication_sha256=f"{miner + 1:064x}",
            issued_block=issued,
            deadline_block=deadline,
            issue_close_ms=issue_close,
            response_close_ms=response_close,
        )
        for miner in range(miners)
        for case in range(6)
    ]
    # Bounded regression costs from the Linux qualification, not a new performance claim.
    budget = DispatchTimingBudget(
        proof_collection_ms=750,
        origin_collection_ms=3900,
        publication_ingestion_ms=5600,
        local_cycle_ms=250,
        publication_delay_ms=publication_delay_ms,
        block_advance_numerator=1,
        block_advance_denominator_ms=10000,
        finality_headroom_blocks=12,
        measurement_sha256="ab" * 32,
    )
    limits = DispatchTimingLimits(
        maximum_concurrency=128,
        page_size=100,
        poll_seconds=1,
        discovery_grace_seconds=5,
        request_timeout_seconds=request_timeout_seconds,
    )
    plan = plan_dispatch_capacity(
        jobs, limits=limits, budget=budget, now_ms=now, observed_block=issued
    )
    return issue_close - plan.last_start_upper_bound_ms, deadline - plan.finish_block_upper_bound


@pytest.mark.parametrize("miners", [174, 192])
def test_aligned_stride_keeps_capacity_across_seven_consecutive_cohorts(miners):
    aligned = transport(stride=2880)
    margins = [capacity(aligned, cycle, miners) for cycle in range(7)]
    assert all(ms > 0 and blocks > 0 for ms, blocks in margins)
    assert len(set(margins)) == 1


@pytest.mark.parametrize("cycle", [1, 2, 4, 5])
def test_minimum_transport_stride_drifts_out_of_later_cohorts(cycle):
    original = transport()
    assert capacity(original, 0, 174)[0] > 0
    with pytest.raises(ValueError, match="original issue window"):
        capacity(original, cycle, 174)


def test_increasing_issue_allowance_alone_exceeds_the_frozen_cohort_deadline():
    with pytest.raises(ValueError, match="request deadline exceeds"):
        capacity(transport(allowance=28800), 0, 174)


@pytest.mark.parametrize("miners", [174, 192, 256])
def test_future_18h_issue_and_15m_response_keep_daily_cohort_margins(miners):
    policy = transport(stride=7200, allowance=64800, response=900)
    margins = [
        capacity(
            policy,
            cycle,
            miners,
            cohort_stride=7200,
            evaluation_span=6300,
            request_timeout_seconds=615,
            publication_delay_ms=7200000,
        )
        for cycle in range(7)
    ]
    assert all(ms > 0 and blocks > 0 for ms, blocks in margins)
    assert len(set(margins)) == 1
