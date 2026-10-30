"""Compact timing publication; no inference, original proof replay or chain claims."""

from fractions import Fraction
from types import SimpleNamespace

import pytest

from umi import competition_cohort_model_scores as scores
from umi.competition_cohort_reward_allocation import derive_effective_reward_allocation
from umi.competition_cpu_efficiency_evidence import combine_cpu_efficiency_runs
from umi.competition_geometric_rewards import cohort_reward_parameters
from umi.competition_public_results_directory import atomic_write, owned_directory
from umi.competition_reward_adoption import RewardModelAdoption
from umi.open_competition import digest, identity
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_model_scores import sample_scores
from .test_competition_cpu_efficiency_rewards import with_timings
from .test_competition_geometric_rewards import fraction, package_boundary


def timed_public(original):
    """Synthetic measured-only envelope for transport/cache compatibility tests."""
    return scores.PublicModelScores.model_validate_json(
        canonical_json_bytes(
            original.model_copy(
                update={
                    "schema_": "umi-public-cohort-model-results/4",
                    "cpu_efficiency_adoption_sha256": "ef" * 32,
                    "efficiency_weight_applied": False,
                    "items": tuple(
                        row.model_copy(
                            update={
                                "efficiency_multiplier_ppm": 1_000_000,
                                "normalized_cpu_slowdown": scores.PublicCpuSlowdown.make(1),
                            }
                        )
                        if row.status == "scored"
                        else row
                        for row in original.items
                    ),
                }
            )
        )
    )


def compact_projection(package):
    """Construct original public metadata from a compact synthetic allocation."""
    allocation = package.allocation
    award = allocation.model_award
    ordered = sorted((fraction(c.aggregate) for c in award.candidates), reverse=True)
    weights = {identity(row.hotkey): row.raw_weight for row in allocation.recipients}
    return scores.PublicModelScores(
        schema="umi-public-cohort-model-results/4",
        cohort_sha256=award.acceptances[0].acceptance.cohort_sha256,
        round_sha256=allocation.round_sha256,
        policy_sha256=allocation.policy_sha256,
        allocation_sha256=digest(allocation),
        certified_history_tip_sha256="ab" * 32,
        source_metadata_sha256="cd" * 32,
        certification="quorum_certified_native_allocation",
        cpu_efficiency_adoption_sha256=award.cpu_efficiency_adoption_sha256,
        efficiency_weight_applied=False,
        items=tuple(
            scores.PublicModelScore(
                submission_sha256=c.submission_sha256,
                model_sha256=c.model_sha256,
                uid=index,
                hotkey=c.recipient_hotkey,
                status="scored",
                aggregate=scores.ModelScore.make(c.aggregate),
                baseline_aggregate=scores.ModelScore.make(c.baseline_aggregate),
                score_rank=ordered.index(fraction(c.aggregate)) + 1,
                baseline_eligible=c.eligible,
                model_reward_status="below_baseline"
                if not c.eligible
                else (
                    "selected_by_certified_rule"
                    if c.submission_sha256 == award.winner_submission_sha256
                    else "not_selected_by_certified_rule"
                ),
                certified_raw_weight_for_hotkey=weights.get(identity(c.recipient_hotkey), 0),
                **scores._public_cpu_efficiency(c),
            )
            for index, c in enumerate(award.candidates)
        ),
    )


def publication_case():
    values = [Fraction(4, 5), Fraction(4, 5), Fraction(79, 200), Fraction(99, 250)]
    package = package_boundary(values, baseline=Fraction(2, 5))
    body = {"measurement_contract": "synthetic-publication-boundary"}
    original = package.allocation.model_award
    measured = with_timings(
        original,
        contract=digest(body),
        slowdown_by_score={Fraction(4, 5): Fraction(1, 2), Fraction(79, 200): Fraction(2)},
        failed_scores=(Fraction(99, 250),),
    )
    package.allocation = package.allocation.model_copy(
        update={
            "model_award": original.model_copy(
                update={
                    "candidates": measured.candidates,
                    "cpu_efficiency_adoption_sha256": measured.cpu_efficiency_adoption_sha256,
                }
            )
        }
    )
    package.inputs.roster = SimpleNamespace(
        round=SimpleNamespace(cpu_efficiency_adoption=SimpleNamespace(adoption=body))
    )
    native = compact_projection(package)
    parameters = cohort_reward_parameters(8)
    effective = derive_effective_reward_allocation(package, parameters)
    adoption = RewardModelAdoption(
        schema="umi-standing-model-reward-adoption/1",
        series_sha256="12" * 32,
        policy_sha256=native.policy_sha256,
        cohort_sha256=native.cohort_sha256,
        authority_sha256=effective.model_award.authority_sha256,
        package_sha256="34" * 32,
        allocation_sha256=native.allocation_sha256,
        service_certificate_sha256=effective.service_certificate_sha256,
        quality_manifest_sha256=effective.quality_manifest_sha256,
        effective_allocation_sha256=digest(effective),
        parameters=parameters,
        revision=1,
        predecessor_adoption_sha256=None,
        issued_at_block=100,
        lifetime="until_first_verified_live_reward_then_locked",
    )
    return native, adoption, effective


def test_adopted_timing_projection_preserves_quality_and_zero_award_dispositions(tmp_path):
    native, adoption, effective = publication_case()
    original_bytes = canonical_json_bytes(native)
    result = scores.project_adopted_model_scores(native, adoption, effective)
    assert native.efficiency_weight_applied is False
    assert result.efficiency_weight_applied is True
    assert result.schema_ == "umi-public-cohort-model-results/4"
    assert result.cpu_efficiency_adoption_sha256 == native.cpu_efficiency_adoption_sha256
    for before, after in zip(native.items, result.items, strict=True):
        for field in (
            "aggregate",
            "baseline_aggregate",
            "score_rank",
            "efficiency_multiplier_ppm",
            "normalized_cpu_slowdown",
        ):
            assert getattr(before, field) == getattr(after, field)
    dispositions = {row.submission_sha256: row.model_reward_status for row in result.items}
    for row in result.items:
        value = Fraction(int(row.aggregate.numerator), int(row.aggregate.denominator))
        assert row.efficiency_multiplier_ppm is not None
        if value == Fraction(79, 200):
            assert row.model_reward_status == "below_baseline"
            assert row.normalized_cpu_slowdown.decimal == 2
        if value == Fraction(99, 250):
            assert row.efficiency_multiplier_ppm <= 1_000_000
    assert list(dispositions.values()).count("not_selected_by_certified_rule") == 1
    assert len(effective.model_award.credits) == 2
    assert canonical_json_bytes(native) == original_bytes
    for private in (b"evaluator_identity", b"observations_sha256", b"terminal_sha256", b"case_id"):
        assert private not in canonical_json_bytes(result)
    root = tmp_path / "public"
    owned_directory(root, create=True)
    owned_directory(root / "model-results", create=True)
    atomic_write(
        root / "model-results" / (result.cohort_sha256 + ".json"), canonical_json_bytes(result)
    )
    cache = scores.PublicModelScoreCache(root)
    cache.sample()
    assert cache.read(result.cohort_sha256)["efficiency_weight_applied"] is True


@pytest.mark.parametrize(
    "field,value",
    [
        ("cpu_efficiency_adoption_sha256", None),
        ("efficiency_weight_applied", None),
        ("efficiency_weight_applied", True),
        ("schema_", "umi-public-cohort-model-results/1"),
    ],
)
def test_timed_projection_requires_explicit_matching_contract_and_application(field, value):
    native, _, _ = publication_case()
    changed = native.model_copy(update={field: value})
    with pytest.raises(ValueError, match="CPU"):
        scores.PublicModelScores.model_validate_json(canonical_json_bytes(changed))


@pytest.mark.parametrize(
    "field,value",
    [
        ("efficiency_multiplier_ppm", None),
        ("efficiency_multiplier_ppm", 1_150_001),
        ("normalized_cpu_slowdown", None),
    ],
)
def test_timing_is_required_for_each_scored_candidate(field, value):
    native, _, _ = publication_case()
    changed = native.model_copy(
        update={
            "items": (
                native.items[0].model_copy(update={field: value}),
                *native.items[1:],
            )
        }
    )
    with pytest.raises(ValueError):
        scores.PublicModelScores.model_validate_json(canonical_json_bytes(changed))


@pytest.mark.parametrize("change", ["contract", "factor", "slowdown"])
def test_adoption_cannot_replace_original_measurements(change):
    native, adoption, effective = publication_case()
    if change == "contract":
        native = native.model_copy(update={"cpu_efficiency_adoption_sha256": "fe" * 32})
    else:
        update = (
            {"efficiency_multiplier_ppm": 1_100_000}
            if change == "factor"
            else {"normalized_cpu_slowdown": scores.PublicCpuSlowdown.make(Fraction(3, 2))}
        )
        native = native.model_copy(
            update={
                "items": (
                    native.items[0].model_copy(update=update),
                    *native.items[1:],
                )
            }
        )
    with pytest.raises(ValueError, match=r"allocation|certified model"):
        scores.project_adopted_model_scores(native, adoption, effective)


def test_exact_slowdown_combines_all_evaluators_before_publication():
    native, _, effective = publication_case()
    candidate = effective.model_award.candidates[0]
    first = candidate.cpu_efficiency.runs[0].model_copy(
        update={"slowdown_numerator": "1", "slowdown_denominator": "2"}
    )
    second = first.model_copy(
        update={
            "evaluator_identity": "56" * 32,
            "terminal_sha256": "78" * 32,
            "slowdown_numerator": "2",
            "slowdown_denominator": "1",
        }
    )
    summary = combine_cpu_efficiency_runs(native.cpu_efficiency_adoption_sha256, (first, second))
    result = scores._public_cpu_efficiency(candidate.model_copy(update={"cpu_efficiency": summary}))
    assert result["normalized_cpu_slowdown"] == scores.PublicCpuSlowdown.make(Fraction(5, 4))
    assert result["efficiency_multiplier_ppm"] == summary.multiplier_ppm


@pytest.mark.parametrize(
    "numerator,denominator,decimal",
    [
        ("2", "4", 0.5),
        ("1", "2", 0.6),
        ("0", "1", 0.0),
        ("86400001", "1", 86400001.0),
    ],
)
def test_public_slowdown_requires_canonical_positive_exact_ratio(numerator, denominator, decimal):
    with pytest.raises(ValueError):
        scores.PublicCpuSlowdown(numerator=numerator, denominator=denominator, decimal=decimal)


def test_512_model_timing_projection_fits_bounded_publication():
    base = timed_public(sample_scores())
    row = base.items[0]
    expanded = base.model_copy(
        update={
            "items": tuple(
                row.model_copy(
                    update={"submission_sha256": digest(["model", index]), "uid": index % 256}
                )
                for index in range(512)
            )
        }
    )
    raw = canonical_json_bytes(expanded)
    assert len(raw) < scores.MAX_PUBLIC_BYTES
    assert canonical_json_bytes(scores.PublicModelScores.model_validate_json(raw)) == raw
    assert scores._projection_semantics(expanded) == scores.CPU_EFFICIENCY_SEMANTICS
    assert scores._projection_semantics(sample_scores()) == scores.SEMANTICS
