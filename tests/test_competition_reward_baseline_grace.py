"""Signed prospective grace affects rewards, never history or baseline quality."""

import json
from fractions import Fraction

import pytest

from umi.competition_cohort_baseline import select_cohort_baseline_candidate
from umi.competition_cohort_model_award import GeometricModelAward, derive_geometric_model_award
from umi.competition_cohort_reward_allocation import derive_effective_reward_allocation
from umi.competition_geometric_rewards import (
    GeometricRewardParameters,
    baseline_eligibility_threshold,
    cohort_reward_parameters,
    validate_cohort_reward_parameters,
)
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_geometric_rewards import fraction, original_evidence, package_boundary


def test_old_parameter_bytes_and_defaults_are_unchanged():
    for version in (1, 2):
        old = {
            "schema": f"umi-geometric-reward-parameters/{version}",
            "band_width_bps": 500,
            "band_decay_bps": 7500,
            "within_band_decay_bps": 7500,
        }
        if version == 2:
            old["score_duplicate_tolerance_bps"] = 1
        raw = canonical_json_bytes(old)
        parameters = GeometricRewardParameters.model_validate_json(raw)
        assert canonical_json_bytes(parameters) == raw
        assert parameters.baseline_grace_bps is None
        assert baseline_eligibility_threshold(Fraction(3, 5), parameters) == Fraction(3, 5)
    assert GeometricRewardParameters().schema_ == "umi-geometric-reward-parameters/2"


def test_new_cohort_defaults_are_exact_and_prospective():
    old = cohort_reward_parameters(6)
    assert old.schema_ == "umi-geometric-reward-parameters/2"
    assert old.band_decay_bps == old.within_band_decay_bps == 7500
    for sequence in (7, 8, 10, 1000):
        selected = cohort_reward_parameters(sequence)
        assert selected.schema_ == (
            "umi-geometric-reward-parameters/3"
            if sequence == 7
            else "umi-geometric-reward-parameters/4"
        )
        assert (selected.cpu_efficiency_rule is not None) == (sequence >= 8)
        assert selected.band_width_bps == 250
        assert selected.band_decay_bps == selected.within_band_decay_bps == 8500
        assert selected.baseline_grace_bps == 100
        validate_cohort_reward_parameters(selected, sequence)
    with pytest.raises(ValueError, match="C7"):
        validate_cohort_reward_parameters(selected, 6)
    with pytest.raises(ValueError, match="version three"):
        GeometricRewardParameters(baseline_grace_bps=100)


@pytest.mark.parametrize(
    "baseline,expected",
    [
        (Fraction(3, 5), Fraction(297, 500)),
        (Fraction(1), Fraction(99, 100)),
        (Fraction(0), Fraction(0)),
        (Fraction(1, 3), Fraction(33, 100)),
    ],
)
def test_relative_grace_uses_exact_fractions(baseline, expected):
    assert baseline_eligibility_threshold(baseline, cohort_reward_parameters(7)) == expected


def test_boundary_awards_preserve_original_strict_eligibility():
    original, _ = original_evidence(
        [Fraction(3, 5), Fraction(299, 500), Fraction(297, 500), Fraction(593999, 1000000)],
        baseline=Fraction(3, 5),
    )
    raw = canonical_json_bytes(original)
    legacy = derive_geometric_model_award(original, cohort_reward_parameters(6))
    effective = derive_geometric_model_award(original, cohort_reward_parameters(7))
    assert len(legacy.credits) == 1
    assert [fraction(c.score) for c in effective.credits] == [
        Fraction(3, 5),
        Fraction(299, 500),
        Fraction(297, 500),
    ]
    assert sum(fraction(c.weight) for c in effective.credits) == 1
    assert effective.candidates == original.candidates
    assert sum(c.eligible for c in effective.candidates) == 1
    assert canonical_json_bytes(original) == raw
    assert GeometricModelAward.model_validate_json(canonical_json_bytes(effective)) == effective


def test_grace_cannot_rewrite_strict_evidence_or_canonical_content_priority():
    original, _ = original_evidence(["0.593", "0.61"], contents=[1, 1], baseline="0.6")
    assert not derive_geometric_model_award(original, cohort_reward_parameters(7)).credits
    original, _ = original_evidence(["0.594"], baseline="0.6")
    forged = original.model_copy(
        update={"candidates": (original.candidates[0].model_copy(update={"eligible": True}),)}
    )
    with pytest.raises(ValueError, match="not canonical"):
        derive_geometric_model_award(forged, cohort_reward_parameters(7))


def test_effective_allocation_conserves_service_and_model_budgets():
    package = package_boundary(["0.595"], baseline="0.6")
    before = canonical_json_bytes(package.allocation)
    legacy = derive_effective_reward_allocation(package, cohort_reward_parameters(6))
    effective = derive_effective_reward_allocation(package, cohort_reward_parameters(7))
    assert not legacy.model_award.credits
    assert len(effective.model_award.credits) == 1
    assert effective.service_certificate_sha256 == legacy.service_certificate_sha256
    assert effective.quality_manifest_sha256 == legacy.quality_manifest_sha256
    assert sum(r.raw_weight for r in effective.recipients) + effective.burn_weight == 65535
    assert (
        legacy.burn_weight - effective.burn_weight
        == package.service.statement.allocation.model_budget
    )
    assert canonical_json_bytes(package.allocation) == before
    assert digest(effective) != digest(legacy)


def test_grace_only_awards_never_lower_successor_reference():
    original, _ = original_evidence(["0.595", "0.594"], baseline="0.6")
    effective = derive_geometric_model_award(original, cohort_reward_parameters(7))
    assert len(effective.credits) == 2
    assert select_cohort_baseline_candidate(effective) is None
    original, _ = original_evidence(["0.595", "0.6"], baseline="0.6")
    effective = derive_geometric_model_award(original, cohort_reward_parameters(7))
    candidate = select_cohort_baseline_candidate(effective)
    assert fraction(candidate.aggregate) == fraction(candidate.baseline_aggregate) == Fraction(3, 5)


def test_changed_grace_requires_a_different_valid_effective_award():
    original, _ = original_evidence(["0.595"], baseline="0.6")
    effective = derive_geometric_model_award(original, cohort_reward_parameters(7))
    value = json.loads(canonical_json_bytes(effective))
    value["parameters"]["baseline_grace_bps"] = 0
    with pytest.raises(ValueError, match="canonical evidence"):
        GeometricModelAward.model_validate_json(canonical_json_bytes(value))
