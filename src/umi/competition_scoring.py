"""Single-reference scoring for the explicit competition v2 profile.

Keep the legacy scoring module byte-identical: existing bootstrap images and
historical policies bind its source digest. Reuse its exact normalization and
distance primitives without padding a reference or weakening its entry points.
"""

from fractions import Fraction

from .scoring import Metric, clamp_unit, levenshtein, normalization_trace


def score_single_reference(metric: Metric, hypothesis: str, reference: str) -> Fraction:
    if metric not in {"wer", "cer"}:
        raise ValueError("unsupported single-reference metric")
    reference_trace = normalization_trace(reference)
    if not reference_trace.normalized:
        raise ValueError("reference must contain a canonical scoring unit")
    hypothesis_trace = normalization_trace(hypothesis)
    if metric == "wer":
        expected, actual = reference_trace.tokens, hypothesis_trace.tokens
    else:
        expected = reference_trace.graphemes_without_whitespace
        actual = hypothesis_trace.graphemes_without_whitespace
    return clamp_unit(Fraction(1) - Fraction(levenshtein(actual, expected), max(1, len(expected))))
