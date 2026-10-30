"""CPU efficiency preserves quality qualification and signed historical rewards."""

from fractions import Fraction
from types import SimpleNamespace

import pytest

from umi.competition_cohort_model_award import (
    MODEL_AWARD_ADAPTER,
    GeometricModelAward,
    ModelAwardEvidence,
    derive_geometric_model_award,
)
from umi.competition_cohort_reward_allocation import (
    CohortRewardAllocation,
    derive_effective_reward_allocation,
)
from umi.competition_cpu_efficiency_evidence import (
    CpuEfficiencyRun,
    combine_cpu_efficiency_runs,
)
from umi.competition_geometric_rewards import cohort_reward_parameters
from umi.competition_reward_adoption import derive_adopted_reward_allocation
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_geometric_rewards import fraction, original_evidence, package_boundary


def with_timings(evidence, *, slowdown_by_score=None, contract="ab" * 32, failed_scores=()):
    """Synthetic compact evidence; native signature/replay tests cover its authority."""
    slowdown_by_score = slowdown_by_score or {}
    candidates = []
    for index, candidate in enumerate(evidence.candidates):
        score = fraction(candidate.aggregate)
        slowdown = slowdown_by_score.get(score, Fraction(1))
        run = CpuEfficiencyRun(
            evaluator_identity="12" * 32,
            terminal_sha256=digest(["terminal", index]),
            profile_sha256="34" * 32,
            observations_sha256=digest(["observations", index]),
            slowdown_numerator=str(slowdown.numerator),
            slowdown_denominator=str(slowdown.denominator),
            candidate_failed_cases=int(score in failed_scores),
            case_count=16,
        )
        candidates.append(
            candidate.model_copy(
                update={"cpu_efficiency": combine_cpu_efficiency_runs(contract, (run,))}
            )
        )
    value = evidence.model_copy(
        update={"candidates": tuple(candidates), "cpu_efficiency_adoption_sha256": contract}
    )
    return ModelAwardEvidence.model_validate_json(
        canonical_json_bytes(
            value.model_dump(
                mode="json", by_alias=True, include=set(ModelAwardEvidence.model_fields)
            )
        )
    )


def test_speed_changes_weights_after_quality_ranks_and_global_normalization():
    evidence, _ = original_evidence([Fraction(81, 100), Fraction(4, 5)], baseline=Fraction(1, 2))
    evidence = with_timings(
        evidence,
        slowdown_by_score={Fraction(81, 100): Fraction(1, 2), Fraction(4, 5): Fraction(2)},
    )
    saved = canonical_json_bytes(evidence)
    original = derive_geometric_model_award(evidence, cohort_reward_parameters(7))
    efficient = derive_geometric_model_award(evidence, cohort_reward_parameters(8))
    assert original.schema_ == "umi-cohort-model-award/4"
    assert efficient.schema_ == "umi-cohort-model-award/5"
    assert [c.efficiency_multiplier_ppm for c in efficient.credits] == [1_071_773, 933_032]
    assert [fraction(c.weight) for c in original.credits] == [Fraction(20, 37), Fraction(17, 37)]
    a, b = 20 * 1_071_773, 17 * 933_032
    assert [fraction(c.weight) for c in efficient.credits] == [
        Fraction(a, a + b),
        Fraction(b, a + b),
    ]
    for before, after in zip(original.credits, efficient.credits, strict=True):
        excluded = {"weight", "efficiency_multiplier_ppm"}
        assert before.model_dump(exclude=excluded) == after.model_dump(exclude=excluded)
    assert canonical_json_bytes(evidence) == saved


def test_fast_wrong_or_duplicate_models_cannot_buy_reward_eligibility():
    evidence, _ = original_evidence(
        [Fraction(4, 5), Fraction(4, 5), Fraction(79, 200), Fraction(99, 250)],
        baseline=Fraction(2, 5),
    )
    evidence = with_timings(
        evidence,
        slowdown_by_score={Fraction(79, 200): Fraction(1, 1000)},
    )
    award = derive_geometric_model_award(evidence, cohort_reward_parameters(8))
    by_ordinal = sorted(evidence.acceptances, key=lambda item: item.acceptance.accepted_ordinal)
    assert [credit.submission_sha256 for credit in award.credits] == [
        by_ordinal[0].acceptance.submission_sha256,
        by_ordinal[3].acceptance.submission_sha256,
    ]
    assert [fraction(c.score) for c in award.credits] == [Fraction(4, 5), Fraction(99, 250)]
    # Grace changes allocation eligibility only; the retained measured quality
    # and strict incumbent comparison must remain exactly as certified.
    grace = next(c for c in award.candidates if fraction(c.aggregate) == Fraction(99, 250))
    assert grace.eligible is False
    assert fraction(grace.baseline_aggregate) == Fraction(2, 5)


def test_content_deduplication_precedes_speed_and_keeps_first_acceptance():
    evidence, _ = original_evidence(
        [Fraction(79, 200), Fraction(9, 10), Fraction(4, 5)],
        contents=[0, 0, 1],
        baseline=Fraction(2, 5),
    )
    evidence = with_timings(evidence, slowdown_by_score={Fraction(9, 10): Fraction(1, 1000)})
    result = derive_geometric_model_award(evidence, cohort_reward_parameters(8))
    assert [fraction(c.score) for c in result.credits] == [Fraction(4, 5)]


def test_failed_case_prevents_bonus_and_zero_base_credit_stays_zero():
    evidence, _ = original_evidence([Fraction(81, 100), Fraction(4, 5)])
    evidence = with_timings(
        evidence,
        slowdown_by_score={Fraction(81, 100): Fraction(1, 1000), Fraction(4, 5): Fraction(1, 1000)},
        failed_scores=(Fraction(81, 100),),
    )
    parameters = cohort_reward_parameters(8).model_copy(update={"within_band_decay_bps": 0})
    result = derive_geometric_model_award(evidence, parameters)
    assert [credit.efficiency_multiplier_ppm for credit in result.credits] == [1_000_000, 1_150_000]
    assert [fraction(credit.weight) for credit in result.credits] == [Fraction(1), Fraction(0)]


def test_zero_measured_quality_cannot_earn_speed_bonus_even_against_zero_baseline():
    evidence, _ = original_evidence([Fraction(1, 100), Fraction(0)], baseline=Fraction(0))
    evidence = with_timings(evidence, slowdown_by_score={Fraction(0): Fraction(1, 1000)})
    original = derive_geometric_model_award(evidence, cohort_reward_parameters(7))
    efficient = derive_geometric_model_award(evidence, cohort_reward_parameters(8))
    assert len(original.credits) == len(efficient.credits) == 2
    assert [fraction(c.weight) for c in efficient.credits] == [
        fraction(c.weight) for c in original.credits
    ]
    zero = next(c for c in efficient.credits if fraction(c.score) == 0)
    assert zero.efficiency_multiplier_ppm == 1_000_000


def test_enabled_rule_requires_complete_contract_bound_timing_for_all_candidates():
    evidence, _ = original_evidence([Fraction(4, 5), Fraction(1, 10)], baseline=Fraction(1, 2))
    with pytest.raises(ValueError, match="matching timing evidence"):
        derive_geometric_model_award(evidence, cohort_reward_parameters(8))
    complete = with_timings(evidence)
    missing = complete.model_copy(
        update={
            "candidates": (
                complete.candidates[0].model_copy(update={"cpu_efficiency": None}),
                *complete.candidates[1:],
            )
        }
    )
    with pytest.raises(ValueError, match="selected contract"):
        derive_geometric_model_award(missing, cohort_reward_parameters(8))
    changed = complete.model_copy(update={"cpu_efficiency_adoption_sha256": "cd" * 32})
    with pytest.raises(ValueError, match="selected contract"):
        derive_geometric_model_award(changed, cohort_reward_parameters(8))


def test_historical_serialization_and_parameters_do_not_add_a_speed_adjustment():
    evidence, _ = original_evidence([Fraction(4, 5), Fraction(3, 4)])
    for sequence in (6, 7):
        original = derive_geometric_model_award(evidence, cohort_reward_parameters(sequence))
        raw = canonical_json_bytes(original)
        assert b"cpu_efficiency" not in raw
        assert b"efficiency_multiplier_ppm" not in raw
        assert canonical_json_bytes(MODEL_AWARD_ADAPTER.validate_json(raw)) == raw
        timed = derive_geometric_model_award(
            with_timings(evidence, slowdown_by_score={Fraction(4, 5): Fraction(1, 1000)}),
            cohort_reward_parameters(sequence),
        )
        assert timed.credits == original.credits
        assert timed.schema_ == original.schema_


def test_wrong_versions_and_tampered_derived_factors_are_rejected():
    evidence, _ = original_evidence([Fraction(4, 5)])
    award = derive_geometric_model_award(with_timings(evidence), cohort_reward_parameters(8))
    wrong_version = award.model_copy(update={"schema_": "umi-cohort-model-award/4"})
    with pytest.raises(ValueError, match="versioned parameters"):
        MODEL_AWARD_ADAPTER.validate_json(canonical_json_bytes(wrong_version))
    changed = award.model_copy(
        update={
            "credits": (
                award.credits[0].model_copy(update={"efficiency_multiplier_ppm": 1_150_000}),
            )
        }
    )
    with pytest.raises(ValueError, match="canonical evidence"):
        MODEL_AWARD_ADAPTER.validate_json(canonical_json_bytes(changed))


def timed_package():
    package = package_boundary([Fraction(4, 5), Fraction(3, 4)], baseline=Fraction(1, 2))
    body = {"measurement_contract": "synthetic-round-binding"}
    evidence = with_timings(
        package.allocation.model_award,
        slowdown_by_score={Fraction(4, 5): Fraction(1, 2)},
        contract=digest(body),
    )
    original = package.allocation.model_award
    original = original.model_copy(
        update={
            "candidates": evidence.candidates,
            "cpu_efficiency_adoption_sha256": evidence.cpu_efficiency_adoption_sha256,
        }
    )
    package.allocation = package.allocation.model_copy(update={"model_award": original})
    package.inputs.roster = SimpleNamespace(
        round=SimpleNamespace(cpu_efficiency_adoption=SimpleNamespace(adoption=body))
    )
    return package


def test_effective_allocation_binds_round_contract_and_preserves_original_service():
    package = timed_package()
    original_bytes = canonical_json_bytes(package.allocation)
    service_bytes = canonical_json_bytes(package.service)
    result = derive_effective_reward_allocation(package, cohort_reward_parameters(8))
    assert result.schema_ == "umi-cohort-reward-allocation/6"
    assert isinstance(result.model_award, GeometricModelAward)
    assert result.model_award.schema_ == "umi-cohort-model-award/5"
    assert sum(item.raw_weight for item in result.recipients) + result.burn_weight == 65535
    for recipient in package.service.statement.allocation.recipients:
        assert recipient in result.recipients
    assert canonical_json_bytes(package.allocation) == original_bytes
    assert canonical_json_bytes(package.service) == service_bytes
    assert derive_effective_reward_allocation(package, cohort_reward_parameters(8)) == result
    with pytest.raises(ValueError, match="version differs"):
        CohortRewardAllocation.model_validate_json(
            canonical_json_bytes(
                result.model_copy(update={"schema_": "umi-cohort-reward-allocation/5"})
            )
        )
    package.inputs.roster.round.cpu_efficiency_adoption = None
    with pytest.raises(ValueError, match="original round contract"):
        derive_effective_reward_allocation(package, cohort_reward_parameters(8))


def test_shared_adoption_reader_reuses_compact_evidence_without_archive_access():
    package = timed_package()
    parameters = cohort_reward_parameters(8)
    expected = derive_effective_reward_allocation(package, parameters)

    class NoArchiveReads:
        def __iter__(self):
            raise AssertionError("completed execution evidence must not be replayed")

        def __getitem__(self, key):
            raise AssertionError("completed execution evidence must not be reopened")

    package.objects = NoArchiveReads()
    adoption = SimpleNamespace(parameters=parameters, signed_score_correction=None)
    assert derive_adopted_reward_allocation(package, adoption, object()) == expected
    assert derive_adopted_reward_allocation(package, adoption, object()) == expected
    package.inputs.roster.round.cpu_efficiency_adoption = None
    with pytest.raises(ValueError, match="original round contract"):
        derive_adopted_reward_allocation(package, adoption, object())


@pytest.mark.parametrize("parameter_sequence", [7, 8])
def test_quality_only_correction_cannot_discard_or_reuse_old_cpu_timings(parameter_sequence):
    package = timed_package()
    # No correction payload is even accessed: its schema cannot carry fresh
    # execution timing, including when an attempted downgrade removes the rule.
    adoption = SimpleNamespace(
        parameters=cohort_reward_parameters(parameter_sequence), signed_score_correction=object()
    )
    with pytest.raises(ValueError, match="fresh versioned timing evidence"):
        derive_adopted_reward_allocation(package, adoption, object())
