"""Exact public-score exclusion before bands; historical and service preservation."""

from fractions import Fraction

import pytest

from umi.competition_cohort_model_award import GeometricModelAward, derive_geometric_model_award
from umi.competition_cohort_reward_allocation import derive_effective_reward_allocation
from umi.competition_geometric_rewards import GeometricRewardParameters
from umi.open_competition import digest, identity
from umi.protocol import canonical_json_bytes

from .test_competition_geometric_rewards import fraction, original_evidence, package_boundary
from .test_open_competition import wallet


def award_for_points(points, **kwargs):
    evidence, _ = original_evidence([Fraction(value) / 100 for value in points], **kwargs)
    return derive_geometric_model_award(evidence, GeometricRewardParameters())


@pytest.mark.parametrize(
    "lower,expected_count",
    [("29.995", 1), ("29.990", 1), ("29.989999999", 2)],
)
def test_point_threshold_uses_exact_inclusive_difference(lower, expected_count):
    award = award_for_points(["30", lower])
    assert len(award.credits) == expected_count
    assert sum(fraction(credit.weight) for credit in award.credits) == 1
    assert len(award.candidates) == len(award.acceptances) == 2


def test_highest_score_wins_even_if_lower_was_accepted_first_across_band_edge():
    award = award_for_points(["29.995", "30.004"])
    assert [credit.submission_sha256 for credit in award.credits] == [digest(["submission", 1])]
    assert award.credits[0].band_index == 6
    assert fraction(award.credits[0].weight) == 1


def test_excluded_score_cannot_chain_exclusion_to_a_distant_model():
    award = award_for_points(["30", "29.995", "29.988"])
    assert [credit.submission_sha256 for credit in award.credits] == [
        digest(["submission", 0]),
        digest(["submission", 2]),
    ]
    assert [fraction(credit.weight) for credit in award.credits] == [Fraction(4, 7), Fraction(3, 7)]


def test_content_alias_cannot_displace_original_content_score():
    award = award_for_points(["29.98", "30.00", "29.999"], contents=[0, 0, 1])
    assert [credit.submission_sha256 for credit in award.credits] == [
        digest(["submission", 2]),
        digest(["submission", 0]),
    ]


def test_excluded_public_model_keeps_its_independent_service_earnings():
    alice, charlie = (wallet(name).hotkey.ss58_address for name in ("Alice", "Charlie"))
    package = package_boundary(["0.30", "0.29995"], hotkeys=[alice, charlie], service_credit=123)
    original = canonical_json_bytes(package.service)
    allocation = derive_effective_reward_allocation(package, GeometricRewardParameters())
    amounts = {identity(row.hotkey): row.raw_weight for row in allocation.recipients}
    assert amounts == {identity(alice): 32768, identity(charlie): 123}
    assert allocation.burn_weight == 32767 - 123
    assert canonical_json_bytes(package.service) == original


def test_original_parameters_and_awards_keep_exact_bytes_and_tied_model_shares():
    original = {
        "schema": "umi-geometric-reward-parameters/1",
        "band_width_bps": 500,
        "band_decay_bps": 7500,
        "within_band_decay_bps": 7500,
    }
    raw = canonical_json_bytes(original)
    parameters = GeometricRewardParameters.model_validate_json(raw)
    assert canonical_json_bytes(parameters) == raw
    evidence, _ = original_evidence(["0.30", "0.30"])
    award = derive_geometric_model_award(evidence, parameters)
    assert [fraction(credit.weight) for credit in award.credits] == [Fraction(4, 7), Fraction(3, 7)]
    saved = canonical_json_bytes(award)
    assert canonical_json_bytes(GeometricModelAward.model_validate_json(saved)) == saved
    revised = derive_geometric_model_award(award, GeometricRewardParameters())
    assert len(revised.credits) == 1
    assert revised.acceptances == award.acceptances and revised.candidates == award.candidates
    assert canonical_json_bytes(award) == saved


@pytest.mark.parametrize("value", [True, -1, 10001, 1.0, None])
def test_new_tolerance_requires_bounded_signed_integer(value):
    with pytest.raises(ValueError):
        GeometricRewardParameters(score_duplicate_tolerance_bps=value)


def test_legacy_version_refuses_silently_added_duplicate_semantics():
    with pytest.raises(ValueError):
        GeometricRewardParameters(
            schema="umi-geometric-reward-parameters/1", score_duplicate_tolerance_bps=1
        )
