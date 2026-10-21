"""Use native signed full-roster quality/artifact replay, with synthetic inference."""

from fractions import Fraction

import pytest

from umi.competition_cohort_baseline import select_cohort_baseline_candidate
from umi.competition_cohort_model_award import derive_geometric_model_award
from umi.competition_geometric_rewards import GeometricRewardParameters
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_model_award import award
from .test_competition_cohort_model_award import base_policy as base_policy
from .test_competition_cohort_model_award import legacy_scenario as legacy_scenario
from .test_competition_cohort_model_award import model_case as model_case
from .test_competition_cohort_model_award import policy as policy
from .test_competition_cohort_model_award import receipt_scenario as receipt_scenario
from .test_competition_cohort_model_award import recovery as recovery
from .test_competition_cohort_model_award import runtime as runtime
from .test_open_competition import wallet

pytestmark = pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True)


@pytest.mark.parametrize("model_case", [("equal", 1), ("above", 1)], indirect=True)
async def test_native_equal_or_above_baseline_is_a_candidate_without_promotion_authority(
    model_case,
):
    value = award(model_case)
    original = canonical_json_bytes(value)
    candidate = select_cohort_baseline_candidate(value)
    assert candidate is not None
    assert candidate.model_award_sha256 == digest(value)
    assert candidate.original_baseline_model_sha256 == value.baseline_model_sha256
    assert Fraction(
        int(candidate.aggregate.numerator), int(candidate.aggregate.denominator)
    ) >= Fraction(
        int(candidate.baseline_aggregate.numerator), int(candidate.baseline_aggregate.denominator)
    )
    assert not candidate.reference_promotion_authorized
    assert not candidate.chain_submission_authorized
    assert canonical_json_bytes(value) == original


@pytest.mark.parametrize("model_case", [("below", 1)], indirect=True)
async def test_no_qualifying_model_does_not_silently_replace_the_reference(model_case):
    assert select_cohort_baseline_candidate(award(model_case)) is None


@pytest.mark.parametrize("model_case", [("best", 2)], indirect=True)
async def test_best_public_quality_selects_reference_independently_of_reward_pool(model_case):
    original = award(model_case)
    winner = select_cohort_baseline_candidate(original)
    assert winner.contributor_hotkey == wallet("Bob").hotkey.ss58_address
    for width in (100, 250, 500):
        for decay in (5000, 7500, 10000):
            parameters = GeometricRewardParameters(
                band_width_bps=width, band_decay_bps=decay, within_band_decay_bps=decay
            )
            changed = derive_geometric_model_award(original, parameters)
            candidate = select_cohort_baseline_candidate(changed)
            assert candidate.model_sha256 == winner.model_sha256
            assert candidate.submission_sha256 == winner.submission_sha256
            assert candidate.aggregate == winner.aggregate


@pytest.mark.parametrize("model_case", [("equal", 2)], indirect=True)
async def test_exact_score_tie_keeps_original_first_complete_acceptance(model_case):
    value = award(model_case)
    expected = min(value.acceptances, key=lambda c: c.acceptance.accepted_ordinal)
    candidate = select_cohort_baseline_candidate(value)
    assert candidate.submission_sha256 == expected.acceptance.submission_sha256
    assert candidate.acceptance_sha256 == digest(expected)
    assert candidate.rights_evidence_sha256 == expected.acceptance.rights_evidence_sha256
    assert (
        candidate.reconstruction_evidence_sha256
        == expected.acceptance.reconstruction_evidence_sha256
    )
