"""Deterministic, exact scoring primitives for UMI protocol version 0.1."""

from __future__ import annotations

import hashlib
import platform
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass
from fractions import Fraction
from importlib.metadata import version
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal, TypeVar

import regex

Metric = Literal["wer", "cer"]
ExactValue = int | Fraction
_Unit = TypeVar("_Unit")

_APOSTROPHES = frozenset(("'", "\N{RIGHT SINGLE QUOTATION MARK}"))
_GRAPHEME_PATTERN = regex.compile(r"\X")
_ZERO = Fraction(0, 1)
_ONE = Fraction(1, 1)

STRATUM_WEIGHTS = MappingProxyType(
    {
        "fingerspelling": Fraction(3, 20),
        "short_utterance": Fraction(7, 20),
        "continuous": Fraction(1, 2),
    }
)


def scoring_environment() -> dict[str, str]:
    """Identify every runtime input that can change normalization or segmentation."""

    return {
        "schema": "umi-component-scoring-environment/1",
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "unicode_data_version": unicodedata.unidata_version,
        "regex_distribution_version": version("regex"),
        "scoring_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }


def _fraction_record(value: Fraction) -> dict[str, int]:
    return {"numerator": value.numerator, "denominator": value.denominator}


@dataclass(frozen=True, slots=True)
class NormalizationTrace:
    """Every deterministic text transformation used by WER and CER."""

    original: str
    nfkc: str
    lowercased: str
    normalized: str
    tokens: tuple[str, ...]
    graphemes_without_whitespace: tuple[str, ...]

    def to_record(self) -> dict[str, Any]:
        return {
            "original": self.original,
            "nfkc": self.nfkc,
            "lowercased": self.lowercased,
            "normalized": self.normalized,
            "tokens": list(self.tokens),
            "graphemes_without_whitespace": list(self.graphemes_without_whitespace),
        }


@dataclass(frozen=True, slots=True)
class ReferenceScoreTrace:
    """One hypothesis-to-reference comparison."""

    index: int
    text: NormalizationTrace
    units: tuple[str, ...]
    distance: int
    denominator: int
    error_rate: Fraction
    score: Fraction

    def to_record(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "text": self.text.to_record(),
            "units": list(self.units),
            "distance": self.distance,
            "denominator": self.denominator,
            "error_rate": _fraction_record(self.error_rate),
            "score": _fraction_record(self.score),
        }


@dataclass(frozen=True, slots=True)
class MetricScoreTrace:
    """Auditable result of best-reference WER or CER scoring."""

    metric: Metric
    hypothesis: NormalizationTrace
    hypothesis_units: tuple[str, ...]
    references: tuple[ReferenceScoreTrace, ...]
    best_reference_index: int
    best_reference_indices: tuple[int, ...]
    score: Fraction

    def to_record(self) -> dict[str, Any]:
        return {
            "metric": self.metric,
            "hypothesis": self.hypothesis.to_record(),
            "hypothesis_units": list(self.hypothesis_units),
            "references": [reference.to_record() for reference in self.references],
            "best_reference_index": self.best_reference_index,
            "best_reference_indices": list(self.best_reference_indices),
            "score": _fraction_record(self.score),
        }


@dataclass(frozen=True, slots=True)
class StratumContributionTrace:
    """One exact term in the weighted-accuracy calculation."""

    stratum: str
    mean: Fraction
    weight: Fraction
    contribution: Fraction

    def to_record(self) -> dict[str, Any]:
        return {
            "stratum": self.stratum,
            "mean": _fraction_record(self.mean),
            "weight": _fraction_record(self.weight),
            "contribution": _fraction_record(self.contribution),
        }


@dataclass(frozen=True, slots=True)
class WeightedAccuracyTrace:
    """Exact 15/35/50 aggregation over the three protocol strata."""

    strata: tuple[StratumContributionTrace, ...]
    score: Fraction

    def to_record(self) -> dict[str, Any]:
        return {
            "strata": [stratum.to_record() for stratum in self.strata],
            "score": _fraction_record(self.score),
        }


def _as_fraction(value: ExactValue) -> Fraction:
    if isinstance(value, bool):
        raise TypeError("boolean values are not exact protocol scores")
    if isinstance(value, Fraction):
        return value
    if isinstance(value, int):
        return Fraction(value, 1)
    raise TypeError("protocol arithmetic requires int or fractions.Fraction")


def clamp_unit(value: ExactValue) -> Fraction:
    """Return an exact value clamped to the closed unit interval."""

    exact = _as_fraction(value)
    return min(_ONE, max(_ZERO, exact))


def _is_letter_or_number(character: str) -> bool:
    return unicodedata.category(character)[0] in ("L", "N")


def grapheme_clusters(text: str) -> tuple[str, ...]:
    """Segment ``text`` into Unicode extended grapheme clusters."""

    if not isinstance(text, str):
        raise TypeError("text must be str")
    return tuple(_GRAPHEME_PATTERN.findall(text))


def normalization_trace(text: str) -> NormalizationTrace:
    """Normalize text using the ordered UMI 0.1 normalization pipeline."""

    if not isinstance(text, str):
        raise TypeError("text must be str")

    nfkc = unicodedata.normalize("NFKC", text)
    lowercased = nfkc.lower()
    normalized_characters: list[str] = []

    for index, character in enumerate(lowercased):
        if _is_letter_or_number(character):
            normalized_characters.append(character)
            continue

        is_internal_apostrophe = (
            character in _APOSTROPHES
            and index > 0
            and index + 1 < len(lowercased)
            and _is_letter_or_number(lowercased[index - 1])
            and _is_letter_or_number(lowercased[index + 1])
        )
        normalized_characters.append(character if is_internal_apostrophe else " ")

    normalized = " ".join("".join(normalized_characters).split())
    tokens = tuple(normalized.split())
    without_whitespace = regex.sub(r"\s+", "", normalized)

    return NormalizationTrace(
        original=text,
        nfkc=nfkc,
        lowercased=lowercased,
        normalized=normalized,
        tokens=tokens,
        graphemes_without_whitespace=grapheme_clusters(without_whitespace),
    )


def normalize_text(text: str) -> str:
    """Return the canonical normalized string without trace metadata."""

    return normalization_trace(text).normalized


def levenshtein(left: Sequence[_Unit], right: Sequence[_Unit]) -> int:
    """Compute exact insertion/deletion/substitution distance for any unit type."""

    if len(left) < len(right):
        left, right = right, left
    if not right:
        return len(left)

    previous = list(range(len(right) + 1))
    for left_index, left_unit in enumerate(left, start=1):
        current = [left_index]
        for right_index, right_unit in enumerate(right, start=1):
            insertion = current[right_index - 1] + 1
            deletion = previous[right_index] + 1
            substitution = previous[right_index - 1] + (left_unit != right_unit)
            current.append(min(insertion, deletion, substitution))
        previous = current
    return previous[-1]


def _validated_references(references: Sequence[str]) -> tuple[str, ...]:
    if isinstance(references, (str, bytes)):
        raise TypeError("references must be a sequence of strings")
    committed = tuple(references)
    if not 3 <= len(committed) <= 5:
        raise ValueError("a clip must have between 3 and 5 committed references")
    if any(not isinstance(reference, str) for reference in committed):
        raise TypeError("every reference must be str")
    return committed


def _score_with_trace(
    metric: Metric, hypothesis: str, references: Sequence[str]
) -> MetricScoreTrace:
    committed = _validated_references(references)
    hypothesis_trace = normalization_trace(hypothesis)
    hypothesis_units = (
        hypothesis_trace.tokens
        if metric == "wer"
        else hypothesis_trace.graphemes_without_whitespace
    )

    reference_traces: list[ReferenceScoreTrace] = []
    for index, reference in enumerate(committed):
        text_trace = normalization_trace(reference)
        units = text_trace.tokens if metric == "wer" else text_trace.graphemes_without_whitespace
        distance = levenshtein(hypothesis_units, units)
        denominator = max(1, len(units))
        error_rate = Fraction(distance, denominator)
        score = clamp_unit(_ONE - error_rate)
        reference_traces.append(
            ReferenceScoreTrace(
                index=index,
                text=text_trace,
                units=units,
                distance=distance,
                denominator=denominator,
                error_rate=error_rate,
                score=score,
            )
        )

    best_score = max(reference.score for reference in reference_traces)
    best_indices = tuple(
        reference.index for reference in reference_traces if reference.score == best_score
    )
    return MetricScoreTrace(
        metric=metric,
        hypothesis=hypothesis_trace,
        hypothesis_units=hypothesis_units,
        references=tuple(reference_traces),
        best_reference_index=best_indices[0],
        best_reference_indices=best_indices,
        score=best_score,
    )


def score_wer_with_trace(hypothesis: str, references: Sequence[str]) -> MetricScoreTrace:
    """Score token WER against three to five references and retain the trace."""

    return _score_with_trace("wer", hypothesis, references)


def score_cer_with_trace(hypothesis: str, references: Sequence[str]) -> MetricScoreTrace:
    """Score grapheme CER against three to five references and retain the trace."""

    return _score_with_trace("cer", hypothesis, references)


def score_wer(hypothesis: str, references: Sequence[str]) -> Fraction:
    """Return the best-reference token WER similarity as an exact fraction."""

    return score_wer_with_trace(hypothesis, references).score


def score_cer(hypothesis: str, references: Sequence[str]) -> Fraction:
    """Return the best-reference grapheme CER similarity as an exact fraction."""

    return score_cer_with_trace(hypothesis, references).score


def mean_score(scores: Sequence[ExactValue]) -> Fraction:
    """Calculate an exact mean of already assigned clip scores."""

    if not scores:
        raise ValueError("cannot calculate the mean of zero assigned scores")
    exact_scores = tuple(clamp_unit(score) for score in scores)
    return clamp_unit(sum(exact_scores, _ZERO) / len(exact_scores))


def weighted_accuracy_with_trace(
    fingerspelling: ExactValue,
    short_utterance: ExactValue,
    continuous: ExactValue,
) -> WeightedAccuracyTrace:
    """Apply the exact protocol weights to the three stratum means."""

    means = {
        "fingerspelling": clamp_unit(fingerspelling),
        "short_utterance": clamp_unit(short_utterance),
        "continuous": clamp_unit(continuous),
    }
    strata = tuple(
        StratumContributionTrace(
            stratum=stratum,
            mean=mean,
            weight=STRATUM_WEIGHTS[stratum],
            contribution=mean * STRATUM_WEIGHTS[stratum],
        )
        for stratum, mean in means.items()
    )
    return WeightedAccuracyTrace(
        strata=strata,
        score=clamp_unit(sum((item.contribution for item in strata), _ZERO)),
    )


def weighted_accuracy(
    fingerspelling: ExactValue,
    short_utterance: ExactValue,
    continuous: ExactValue,
) -> Fraction:
    """Return exact 15/35/50 weighted accuracy for the three stratum means."""

    return weighted_accuracy_with_trace(fingerspelling, short_utterance, continuous).score


def utility_score(accuracy: ExactValue, quality_floor: ExactValue) -> Fraction:
    """Return ``max(0, accuracy - quality_floor)^2`` using exact arithmetic."""

    margin = max(_ZERO, clamp_unit(accuracy) - clamp_unit(quality_floor))
    return clamp_unit(margin * margin)


__all__ = [
    "STRATUM_WEIGHTS",
    "MetricScoreTrace",
    "NormalizationTrace",
    "ReferenceScoreTrace",
    "StratumContributionTrace",
    "WeightedAccuracyTrace",
    "clamp_unit",
    "grapheme_clusters",
    "levenshtein",
    "mean_score",
    "normalization_trace",
    "normalize_text",
    "score_cer",
    "score_cer_with_trace",
    "score_wer",
    "score_wer_with_trace",
    "utility_score",
    "weighted_accuracy",
    "weighted_accuracy_with_trace",
]
