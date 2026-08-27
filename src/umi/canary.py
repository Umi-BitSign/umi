"""Deterministic canary construction checks and post-reveal hit evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from typing import Literal

from .encoding import raw_sha256, sha256_domain
from .protocol import GroundTruthItem, base64url_decode
from .scoring import MetricScoreTrace, score_cer_with_trace, score_wer_with_trace


def canary_count(emission_bearing_clips: int, fraction: Fraction) -> int:
    if (
        isinstance(emission_bearing_clips, bool)
        or not isinstance(emission_bearing_clips, int)
        or emission_bearing_clips <= 0
    ):
        raise ValueError("emission-bearing clip count must be positive")
    if not isinstance(fraction, Fraction) or not 0 < fraction <= 1:
        raise ValueError("canary fraction must be an exact fraction in (0, 1]")
    numerator = emission_bearing_clips * fraction.numerator
    count = (numerator + fraction.denominator - 1) // fraction.denominator
    return max(1, count)


def wer_canary_stratum(
    window_id: str | bytes,
    batch_id: str,
) -> Literal["short_utterance", "continuous"]:
    decoded_batch_id = base64url_decode(batch_id)
    if len(decoded_batch_id) != 16:
        raise ValueError("batch ID must encode exactly 16 opaque bytes")
    digest = sha256_domain(
        b"umi-canary-stratum-v1\0",
        raw_sha256(window_id, field="window ID"),
        decoded_batch_id,
    )
    return "short_utterance" if digest[-1] & 1 == 0 else "continuous"


def validate_canary_pair(
    item: GroundTruthItem,
    *,
    separation_score: Fraction = Fraction(1, 10),
) -> None:
    if not item.canary or item.canary_evidence is None:
        raise ValueError("ground-truth item is not a canary")
    if not isinstance(separation_score, Fraction) or not 0 <= separation_score <= 1:
        raise ValueError("canary separation score must be an exact unit fraction")
    scorer = score_cer_with_trace if item.metric == "cer" else score_wer_with_trace
    for actual in item.canary_evidence.actual_references:
        for mismatch in item.canary_evidence.mismatched_references:
            pair_score = scorer(actual, (mismatch, mismatch, mismatch)).score
            if pair_score >= separation_score:
                raise ValueError("canary actual and mismatched references are not separated")


@dataclass(frozen=True)
class CanaryResult:
    challenge_id: str
    metric: Literal["cer", "wer"]
    threshold: Fraction
    score: Fraction
    hit: bool
    trace: MetricScoreTrace | None


def evaluate_canary(
    item: GroundTruthItem,
    hypothesis: str | None,
    *,
    cer_threshold: Fraction,
    wer_threshold: Fraction,
) -> CanaryResult:
    validate_canary_pair(item)
    threshold = cer_threshold if item.metric == "cer" else wer_threshold
    if not isinstance(threshold, Fraction) or not 0 <= threshold <= 1:
        raise ValueError("canary hit threshold must use exact unit-interval arithmetic")
    if hypothesis is None:
        return CanaryResult(
            challenge_id=item.challenge_id,
            metric=item.metric,
            threshold=threshold,
            score=Fraction(0, 1),
            hit=False,
            trace=None,
        )
    trace = (
        score_cer_with_trace(hypothesis, item.references)
        if item.metric == "cer"
        else score_wer_with_trace(hypothesis, item.references)
    )
    return CanaryResult(
        challenge_id=item.challenge_id,
        metric=item.metric,
        threshold=threshold,
        score=trace.score,
        hit=trace.score >= threshold,
        trace=trace,
    )


__all__ = [
    "CanaryResult",
    "canary_count",
    "evaluate_canary",
    "validate_canary_pair",
    "wer_canary_stratum",
]
