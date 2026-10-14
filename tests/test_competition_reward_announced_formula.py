"""Reproduce the published C5 example; this is not actual package replay."""

from fractions import Fraction

from umi.competition_cohort_model_award import derive_geometric_model_award
from umi.competition_geometric_rewards import GeometricRewardParameters
from umi.open_competition import digest

from .test_competition_geometric_rewards import fraction, original_evidence

# Admission UIDs, displayed benchmark scores, exact public alpha per 100 total.
# The posted example reserves 50 alpha for public models and 50 for service.
EXAMPLE = (
    (104, "37.097383", "3200/259"),
    (101, "35.171239", "2400/259"),
    (103, "33.568675", "614400/124579"),
    (171, "33.529392", "460800/124579"),
    (246, "33.163817", "345600/124579"),
    (102, "31.258906", "259200/124579"),
    (45, "31.015425", "194400/124579"),
    (133, "30.212197", "145800/124579"),
    (119, "27.445193", "1800/259"),
    (93, "26.261761", "1350/259"),
    (250, "23.287610", "0"),
    (110, "23.088838", "0"),
    (172, "21.454069", "0"),
    (165, "21.454069", "0"),
)


def test_runtime_formula_reproduces_posted_c5_table_exactly():
    evidence, _ = original_evidence(
        [Fraction(score) / 100 for _, score, _ in EXAMPLE],
        baseline=Fraction("26.261761") / 100,
    )
    award = derive_geometric_model_award(evidence, GeometricRewardParameters())
    amounts = {c.submission_sha256: 50 * fraction(c.weight) for c in award.credits}
    assert len(amounts) == 10
    for index, (uid, _, expected) in enumerate(EXAMPLE):
        assert amounts.get(digest(["submission", index]), Fraction()) == Fraction(expected), uid
    assert sum(amounts.values()) == 50
    bands = {}
    for credit in award.credits:
        bands.setdefault(credit.band_index, []).append(fraction(credit.weight))
    assert {band: len(weights) for band, weights in bands.items()} == {7: 2, 6: 6, 5: 2}
    assert {band: sum(weights) for band, weights in bands.items()} == {
        7: Fraction(16, 37),
        6: Fraction(12, 37),
        5: Fraction(9, 37),
    }
