"""C7 prospective economics preserve C6 and broaden the same eligible pool."""

from fractions import Fraction

from umi.competition_cohort_model_award import derive_geometric_model_award
from umi.competition_geometric_rewards import (
    GeometricRewardParameters,
    cohort_reward_parameters,
)
from umi.protocol import canonical_json_bytes

from .test_competition_geometric_rewards import fraction, original_evidence


def test_new_schema_defaults_match_announced_successor_policy():
    assert GeometricRewardParameters(schema="umi-geometric-reward-parameters/3") == (
        cohort_reward_parameters(7)
    )
    legacy = GeometricRewardParameters()
    assert legacy.band_width_bps == 500
    assert legacy.band_decay_bps == legacy.within_band_decay_bps == 7500
    assert legacy.baseline_grace_bps is None


def test_c7_parameters_broaden_c6_distribution_without_changing_eligibility():
    # C6's 21 distinct selected score groups, plus a below-baseline sentinel.
    scores = (
        "266/585",
        "817/1872",
        "265/624",
        "49/117",
        "1933/4680",
        "383/936",
        "361/936",
        "55/144",
        "17/45",
        "881/2340",
        "44/117",
        "341/936",
        "839/2340",
        "1663/4680",
        "83/234",
        "1633/4680",
        "3239/9360",
        "809/2340",
        "107/312",
        "263/780",
        "121/360",
        "33/100",
    )
    evidence, _ = original_evidence([Fraction(x) for x in scores], baseline=Fraction(121, 360))
    before = canonical_json_bytes(evidence)
    c6 = derive_geometric_model_award(evidence, cohort_reward_parameters(6))
    c7 = derive_geometric_model_award(evidence, cohort_reward_parameters(7))
    assert canonical_json_bytes(evidence) == before
    assert len(c6.credits) == len(c7.credits) == 21
    assert {c.submission_sha256 for c in c6.credits} == {c.submission_sha256 for c in c7.credits}
    assert sum(fraction(c.weight) for c in c7.credits) == 1
    assert fraction(c6.credits[0].weight) == Fraction(1024, 3367)
    assert fraction(c7.credits[0].weight) == Fraction(3200000, 13287477)
    assert fraction(c7.credits[2].weight) == Fraction(18496000000, 338737651161)
    assert fraction(c7.credits[-1].weight) > fraction(c6.credits[-1].weight)


def test_historical_parameter_bytes_and_c6_default_stay_unchanged():
    raw = (
        b'{"band_decay_bps":7500,"band_width_bps":250,'
        b'"schema":"umi-geometric-reward-parameters/2",'
        b'"score_duplicate_tolerance_bps":1,"within_band_decay_bps":7500}'
    )
    retained = GeometricRewardParameters.model_validate_json(raw)
    assert canonical_json_bytes(retained) == raw
    assert retained == cohort_reward_parameters(6)
    for sequence in (7, 8, 9, 10, 100):
        future = cohort_reward_parameters(sequence)
        assert future.band_width_bps == 250
        assert future.band_decay_bps == future.within_band_decay_bps == 8500
        assert future.score_duplicate_tolerance_bps == 1
