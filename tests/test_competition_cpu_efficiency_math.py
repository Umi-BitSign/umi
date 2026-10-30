"""Bounded execution rewards, matched-case fairness and failure resistance."""

from dataclasses import replace
from fractions import Fraction

import pytest

from umi.competition_cpu_efficiency_math import (
    MAX_CASES,
    MAX_EFFICIENCY_PPM,
    MAX_ELAPSED_MS,
    MAX_MODELS,
    MIN_EFFICIENCY_PPM,
    PPM,
    CpuCaseTiming,
    apply_efficiency_weights,
    cpu_efficiency_measurement,
    efficiency_multiplier_ppm,
    multiplier_from_slowdown,
    normalized_cpu_slowdown,
)

ONE_TASK = {"continuous": Fraction(1)}
TWO_TASKS = {"continuous": Fraction(10, 13), "fingerspelling": Fraction(3, 13)}


def timing(candidate=1000, reference=1000, *, case_id="case", stratum="continuous"):
    return CpuCaseTiming(case_id, stratum, candidate, reference, True, True)


def measurement(cases, weights=ONE_TASK, *, deadline=MAX_ELAPSED_MS):
    return cpu_efficiency_measurement(cases, weights, maximum_inference_ms=deadline)


@pytest.mark.parametrize(
    "candidate,reference,expected",
    [
        (1000, 1000, PPM),
        (1000, 2000, 1_071_773),
        (1000, 4000, 1_148_698),
        (1000, 8000, MAX_EFFICIENCY_PPM),
        (2000, 1000, 933_032),
        (4000, 1000, 870_550),
        (8000, 1000, MIN_EFFICIENCY_PPM),
    ],
)
def test_approved_power_and_fifteen_percent_bounds(candidate, reference, expected):
    result = measurement([timing(candidate, reference)])
    assert result.multiplier_ppm == expected
    assert result.normalized_slowdown == Fraction(candidate, reference)
    assert result.candidate_failed_cases == 0


def test_integer_rounding_is_canonical_and_monotone_across_time_ratios():
    previous = MAX_EFFICIENCY_PPM
    for elapsed in (1, 100, 250, 500, 999, 1000, 1001, 2000, 4000, 5000, 8000):
        result = measurement([timing(elapsed, 1000)])
        value = result.multiplier_ppm
        assert MIN_EFFICIENCY_PPM <= value <= previous
        previous = value
        if MIN_EFFICIENCY_PPM < value < MAX_EFFICIENCY_PPM:
            # A portable floor is uniquely identified by these inequalities.
            assert value**10 * elapsed <= PPM**10 * 1000
            assert (value + 1) ** 10 * elapsed > PPM**10 * 1000


def test_task_weights_and_each_case_keep_their_share_despite_duration_and_count():
    cases = [
        timing(1, 2, case_id="short-continuous"),
        timing(2000, 1000, case_id="long-continuous"),
        timing(1, 10, case_id="fingerspelling", stratum="fingerspelling"),
    ]
    result = measurement(cases, TWO_TASKS)
    assert result.normalized_slowdown == Fraction(64, 65)
    assert measurement(reversed(cases), dict(reversed(tuple(TWO_TASKS.items())))) == result
    # Doubling a task's case count with the same distribution must not increase
    # its weight; neither may changing each case's physical time scale.
    repeated = cases + [replace(case, case_id=case.case_id + "-other") for case in cases]
    scaled = [
        replace(
            case,
            candidate_elapsed_ms=case.candidate_elapsed_ms * 10,
            reference_elapsed_ms=case.reference_elapsed_ms * 10,
        )
        for case in cases
    ]
    assert measurement(repeated, TWO_TASKS) == result
    assert measurement(scaled, TWO_TASKS) == result


def test_failure_is_charged_deadline_and_cannot_become_an_efficiency_bonus():
    invalid = replace(timing(0, 1000), candidate_valid=False)
    failure_only = measurement([invalid], deadline=10_000)
    assert failure_only.normalized_slowdown == 10
    assert failure_only.multiplier_ppm == MIN_EFFICIENCY_PPM
    assert failure_only.candidate_failed_cases == 1
    # Even many extremely quick valid answers cannot turn one empty/crashed/
    # failed answer into a speed bonus after its deadline charge is averaged.
    mixed = [invalid] + [timing(1, 1000, case_id=str(i)) for i in range(20)]
    result = measurement(mixed, deadline=1000)
    assert result.normalized_slowdown < 1
    assert result.multiplier_ppm == PPM
    assert result.candidate_failed_cases == 1


def test_invalid_reference_is_neutral_and_not_a_free_speed_comparison():
    reference_failed = replace(timing(1, 80_000_000), reference_valid=False)
    result = measurement([reference_failed])
    assert result.normalized_slowdown == 1
    assert result.multiplier_ppm == PPM
    both_failed = replace(reference_failed, candidate_valid=False)
    result = measurement([both_failed])
    assert result.normalized_slowdown == 1
    assert result.multiplier_ppm == PPM
    assert result.candidate_failed_cases == 1


def test_valid_flags_do_not_override_inference_deadlines():
    candidate_late = measurement([timing(1001, 100)], deadline=1000)
    assert candidate_late.normalized_slowdown == 10
    assert candidate_late.candidate_failed_cases == 1
    reference_late = measurement([timing(1, 1001)], deadline=1000)
    assert reference_late.normalized_slowdown == 1
    assert reference_late.multiplier_ppm == PPM


def test_zero_millisecond_resolution_has_a_fixed_floor_not_infinite_speed():
    result = measurement([timing(0, 0)])
    assert result.normalized_slowdown == 1
    assert result.multiplier_ppm == PPM
    assert measurement([timing(0, 1)]) == result


def test_tiny_fast_model_cannot_turn_zero_quality_credit_into_payment():
    # Quality qualification and duplicate filtering supply zero credit first.
    # Even the maximum speed factor must leave that credit at exactly zero.
    weights = apply_efficiency_weights(
        (Fraction(0), Fraction(2, 3), Fraction(1, 3)),
        (MAX_EFFICIENCY_PPM, PPM, PPM),
    )
    assert weights == (Fraction(0), Fraction(2, 3), Fraction(1, 3))
    assert apply_efficiency_weights((Fraction(0), Fraction(0)), (PPM, PPM)) == (
        Fraction(0),
        Fraction(0),
    )
    assert apply_efficiency_weights((), ()) == ()


def test_reward_adjustment_uses_one_global_normalization_and_preserves_order():
    result = apply_efficiency_weights(
        (Fraction(1), Fraction(1)), (MAX_EFFICIENCY_PPM, MIN_EFFICIENCY_PPM)
    )
    assert result == (Fraction(23, 40), Fraction(17, 40))
    assert sum(result, Fraction()) == 1
    original = (Fraction(4, 7), Fraction(2, 7), Fraction(1, 7))
    assert apply_efficiency_weights(original, (PPM, PPM, PPM)) == original
    assert apply_efficiency_weights(original, (MAX_EFFICIENCY_PPM,) * 3) == original


def test_convenience_readers_return_the_same_single_measurement():
    cases = [timing(250, 1000)]
    result = measurement(cases)
    assert (
        normalized_cpu_slowdown(cases, ONE_TASK, maximum_inference_ms=MAX_ELAPSED_MS)
        == result.normalized_slowdown
    )
    assert (
        efficiency_multiplier_ppm(cases, ONE_TASK, maximum_inference_ms=MAX_ELAPSED_MS)
        == result.multiplier_ppm
    )
    assert (
        multiplier_from_slowdown(
            result.normalized_slowdown, candidate_failed_cases=result.candidate_failed_cases
        )
        == result.multiplier_ppm
    )


@pytest.mark.parametrize(
    "slowdown,failures",
    [(Fraction(0), 0), (Fraction(-1), 0), (1.0, 0), (1, 0), (Fraction(1), -1)],
)
def test_retained_summary_requires_exact_positive_slowdown_and_failure_count(slowdown, failures):
    with pytest.raises(ValueError):
        multiplier_from_slowdown(slowdown, candidate_failed_cases=failures)


@pytest.mark.parametrize(
    "weights",
    [
        {},
        {"continuous": 1},
        {"continuous": 1.0},
        {"continuous": Fraction(1, 2)},
        {"continuous": Fraction(2), "fingerspelling": Fraction(-1)},
        {"continuous": Fraction(1), "fingerspelling": Fraction(0)},
        {"": Fraction(1)},
        {1: Fraction(1)},
    ],
)
def test_noncanonical_task_weights_are_rejected(weights):
    with pytest.raises(ValueError, match="task weights"):
        measurement([timing()], weights)


@pytest.mark.parametrize("deadline", [0, -1, True, 1.0, MAX_ELAPSED_MS + 1])
def test_invalid_deadlines_are_rejected(deadline):
    with pytest.raises(ValueError, match="maximum inference"):
        measurement([timing()], deadline=deadline)


@pytest.mark.parametrize(
    "change",
    [
        {"candidate_elapsed_ms": -1},
        {"reference_elapsed_ms": MAX_ELAPSED_MS + 1},
        {"candidate_elapsed_ms": True},
        {"reference_elapsed_ms": 1.0},
        {"candidate_valid": 1},
        {"reference_valid": None},
        {"case_id": ""},
        {"case_id": 1},
        {"stratum": "unweighted"},
    ],
)
def test_invalid_paired_evidence_is_rejected(change):
    with pytest.raises(ValueError):
        measurement([replace(timing(), **change)])


def test_missing_duplicate_and_excessive_cases_are_not_silently_neutral():
    with pytest.raises(ValueError, match="every weighted task"):
        measurement([])
    with pytest.raises(ValueError, match="every weighted task"):
        measurement([timing()], TWO_TASKS)
    with pytest.raises(ValueError, match="unique"):
        measurement([timing(), timing()])
    with pytest.raises(ValueError, match="explicit paired"):
        measurement([{}])
    cases = [timing(case_id=str(i)) for i in range(MAX_CASES)]
    assert measurement(iter(cases)).multiplier_ppm == PPM
    with pytest.raises(ValueError, match="case count"):
        measurement(iter([*cases, timing(case_id="one-too-many")]))


@pytest.mark.parametrize(
    "weights,multipliers",
    [
        ((Fraction(1),), ()),
        ((Fraction(-1),), (PPM,)),
        ((1,), (PPM,)),
        ((1.0,), (PPM,)),
        ((Fraction(1),), (MIN_EFFICIENCY_PPM - 1,)),
        ((Fraction(1),), (MAX_EFFICIENCY_PPM + 1,)),
        ((Fraction(1),), (True,)),
        ((Fraction(1),), (1_000_000.0,)),
        ((Fraction(1),) * (MAX_MODELS + 1), (PPM,) * (MAX_MODELS + 1)),
    ],
)
def test_invalid_reward_weights_are_rejected(weights, multipliers):
    with pytest.raises(ValueError):
        apply_efficiency_weights(weights, multipliers)
