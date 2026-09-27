"""Pure interval boundaries; hints in these tests do not establish native coverage."""

import pytest

from umi.competition_reward_coverage_intervals import (
    CoveragePoint,
    RewardCoverageRule,
    _interval,
    coverage_interval,
)
from umi.open_competition import digest


def rule(**changes):
    return RewardCoverageRule(
        schema="umi-reward-coverage-rule/1",
        series_sha256="aa" * 32,
        runtime_profile_sha256="bb" * 32,
        maximum_interval_ms=changes.pop("maximum_interval_ms", 12000),
        **changes,
    )


def point(**changes):
    value = CoveragePoint(
        series_sha256="aa" * 32,
        runtime_profile_sha256="bb" * 32,
        activation_sha256="cc" * 32,
        allocation_sha256="dd" * 32,
        projection_sha256="ee" * 32,
        validator_account_id="ff" * 32,
        chain_config_sha256="11" * 32,
        block=100,
        block_hash="0x" + "01" * 32,
        parent_hash="0x" + "00" * 32,
        state_root="0x" + "02" * 32,
        timestamp_ms=100_000,
        covered=True,
    )
    return value.model_copy(update=changes)


def following(**changes):
    return point(
        **dict(
            block=101,
            block_hash="0x" + "03" * 32,
            parent_hash=point().block_hash,
            timestamp_ms=112_000,
            **changes,
        )
    )


@pytest.mark.parametrize(
    "elapsed,cap,credit",
    [
        (1, 12000, 1),
        (11999, 12000, 11999),
        (12000, 12000, 12000),
        (12001, 12000, 12000),
        (4 * 60 * 60 * 1000, 12000, 12000),
        (20000, 5000, 5000),
    ],
)
def test_interval_counts_only_capped_positive_chain_time(elapsed, cap, credit):
    right = following().model_copy(update={"timestamp_ms": 100_000 + elapsed})
    result = _interval(point(), right, rule(maximum_interval_ms=cap))
    assert result.credited_ms == credit
    assert result.rule_sha256 == digest(rule(maximum_interval_ms=cap))


@pytest.mark.parametrize(
    "change",
    [
        {"block": 102},
        {"block": 100},
        {"parent_hash": "0x" + "f0" * 32},
        {"timestamp_ms": 100_000},
        {"timestamp_ms": 99_999},
        {"series_sha256": "af" * 32},
        {"runtime_profile_sha256": "af" * 32},
        {"validator_account_id": "af" * 32},
        {"chain_config_sha256": "af" * 32},
    ],
)
def test_gaps_reordering_ambiguous_time_and_domain_changes_hold(change):
    with pytest.raises(ValueError):
        _interval(point(), following().model_copy(update=change), rule())


@pytest.mark.parametrize(
    "change",
    [
        {"covered": False},
        {"activation_sha256": "fa" * 32},
        {"allocation_sha256": "fa" * 32},
    ],
)
def test_uncovered_state_or_new_activation_never_borrows_prior_time(change):
    assert _interval(point(), following().model_copy(update=change), rule()) is None
    assert _interval(point().model_copy(update={"covered": False}), following(), rule()) is None


def test_projection_can_change_with_proved_recipient_registration():
    result = _interval(point(), following(projection_sha256="fa" * 32), rule())
    assert result.credited_ms == 12000


@pytest.mark.parametrize("cap", [0, -1, True, 1.5, 2**53])
def test_rule_requires_explicit_bounded_integer_cap(cap):
    with pytest.raises(ValueError):
        rule(maximum_interval_ms=cap)


def test_point_identity_deduplicates_proof_receipts_but_not_other_blocks_or_validators():
    left = point()
    assert left.key() == left.model_copy(update={"projection_sha256": "fa" * 32}).key()
    assert left.key() != following().key()
    assert left.key() != point(validator_account_id="fa" * 32).key()
    assert left.key() != point(series_sha256="fa" * 32).key()


def test_pure_hints_cannot_enter_native_interval_consumer():
    with pytest.raises(ValueError, match="native provenance"):
        coverage_interval(point(), following(), rule())
