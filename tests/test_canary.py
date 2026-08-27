from __future__ import annotations

import hashlib
from fractions import Fraction

import pytest

from umi.canary import (
    canary_count,
    evaluate_canary,
    validate_canary_pair,
    wer_canary_stratum,
)
from umi.protocol import GroundTruthItem, base64url_encode


def _wer_canary() -> GroundTruthItem:
    return GroundTruthItem.model_validate(
        {
            "challenge_id": base64url_encode(b"C" * 16),
            "metric": "wer",
            "canary": True,
            "references": ["alpha beta", "alpha gamma", "alpha delta"],
            "canary_evidence": {
                "actual_references": ["red green", "orange purple", "black white"],
                "actual_script_sha256": "11" * 32,
                "reserved_script_sha256": "22" * 32,
                "mismatched_references": ["alpha beta", "alpha gamma", "alpha delta"],
            },
            "normalized_script_sha256": "11" * 32,
            "retirement_script_sha256s": ["11" * 32, "22" * 32],
            "consent_manifest_sha256": "33" * 32,
        }
    )


def test_canary_count_uses_exact_ceiling_arithmetic() -> None:
    assert canary_count(12, Fraction(1, 10)) == 2
    assert canary_count(1, Fraction(1, 10)) == 1
    assert canary_count(10, Fraction(1, 10)) == 1
    assert canary_count(11, Fraction(1, 10)) == 2

    with pytest.raises(ValueError, match="clip count"):
        canary_count(0, Fraction(1, 10))
    with pytest.raises((TypeError, ValueError), match="clip count"):
        canary_count(True, Fraction(1, 10))
    with pytest.raises((TypeError, ValueError), match="clip count"):
        canary_count(1.5, Fraction(1, 10))  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="exact fraction"):
        canary_count(12, 0.1)  # type: ignore[arg-type]


def test_wer_canary_stratum_reproduces_the_low_digest_bit_formula() -> None:
    window_id = "10" * 32
    batch_id = base64url_encode(bytes(range(16)))
    digest = hashlib.sha256(
        b"umi-canary-stratum-v1\0" + bytes.fromhex(window_id) + bytes(range(16))
    ).digest()
    expected = "short_utterance" if digest[-1] & 1 == 0 else "continuous"
    assert wer_canary_stratum(window_id, batch_id) == expected

    with pytest.raises(ValueError, match=r"16.*bytes"):
        wer_canary_stratum(window_id, base64url_encode(b"short"))


def test_canary_pair_requires_every_cross_reference_score_below_point_one() -> None:
    validate_canary_pair(_wer_canary())

    ten_actual = "a b c d e f g h i j"
    ten_mismatch = "a k l m n o p q r s"
    boundary = GroundTruthItem.model_validate(
        {
            "challenge_id": base64url_encode(b"D" * 16),
            "metric": "wer",
            "canary": True,
            "references": [ten_mismatch] * 3,
            "canary_evidence": {
                "actual_references": [ten_actual] * 3,
                "actual_script_sha256": "11" * 32,
                "reserved_script_sha256": "22" * 32,
                "mismatched_references": [ten_mismatch] * 3,
            },
            "normalized_script_sha256": "11" * 32,
            "retirement_script_sha256s": ["11" * 32, "22" * 32],
            "consent_manifest_sha256": "33" * 32,
        }
    )
    with pytest.raises(ValueError, match="not separated"):
        validate_canary_pair(boundary)


def test_canary_hit_threshold_is_inclusive_and_missing_hypothesis_is_zero() -> None:
    item = _wer_canary()
    result = evaluate_canary(
        item,
        "alpha x",
        cer_threshold=Fraction(1, 2),
        wer_threshold=Fraction(1, 2),
    )
    assert result.score == Fraction(1, 2)
    assert result.hit
    assert result.trace is not None

    missing = evaluate_canary(
        item,
        None,
        cer_threshold=Fraction(1, 2),
        wer_threshold=Fraction(1, 2),
    )
    assert missing.score == 0
    assert not missing.hit
    assert missing.trace is None


def test_canary_evaluation_rejects_an_ordinary_ground_truth_item() -> None:
    ordinary = GroundTruthItem.model_validate(
        {
            "challenge_id": base64url_encode(b"E" * 16),
            "metric": "wer",
            "canary": False,
            "references": ["one", "two", "three"],
            "canary_evidence": None,
            "normalized_script_sha256": "11" * 32,
            "retirement_script_sha256s": ["11" * 32],
            "consent_manifest_sha256": "33" * 32,
        }
    )
    with pytest.raises(ValueError, match="not a canary"):
        evaluate_canary(
            ordinary,
            "one",
            cer_threshold=Fraction(1, 2),
            wer_threshold=Fraction(1, 2),
        )
