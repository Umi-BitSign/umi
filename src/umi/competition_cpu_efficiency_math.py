"""Exact, bounded CPU efficiency adjustments after quality qualification.

The caller authenticates complete, comparable timing evidence and applies the
quality floor and duplicate rules first. This module grants no execution or
reward authority. It never derives timings from model-reported measurements.
"""

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from fractions import Fraction

PPM = 1_000_000
MIN_EFFICIENCY_PPM = 850_000
MAX_EFFICIENCY_PPM = 1_150_000
MAX_CASES = 2048
MAX_MODELS = 512
MAX_ELAPSED_MS = 86_400_000


@dataclass(frozen=True)
class CpuCaseTiming:
    case_id: str
    stratum: str
    candidate_elapsed_ms: int
    reference_elapsed_ms: int
    candidate_valid: bool
    reference_valid: bool


@dataclass(frozen=True)
class CpuEfficiencyMeasurement:
    normalized_slowdown: Fraction
    multiplier_ppm: int
    candidate_failed_cases: int


def _integer(value, *, minimum: int, maximum: int, name: str) -> None:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer from {minimum} through {maximum}")


def _normalized_slowdown(
    cases: Iterable[CpuCaseTiming],
    task_weights: Mapping[str, Fraction],
    maximum_inference_ms: int,
) -> tuple[Fraction, int]:
    _integer(
        maximum_inference_ms,
        minimum=1,
        maximum=MAX_ELAPSED_MS,
        name="maximum inference milliseconds",
    )
    weights = dict(task_weights)
    if (
        not weights
        or len(weights) > MAX_CASES
        or any(type(key) is not str or not key for key in weights)
        or any(type(weight) is not Fraction or weight <= 0 for weight in weights.values())
        or sum(weights.values(), Fraction()) != 1
    ):
        raise ValueError("task weights must be positive exact fractions summing to one")
    totals: dict[str, Fraction] = {}
    counts: dict[str, int] = {}
    seen: set[str] = set()
    failures = 0
    for case in cases:
        if len(seen) == MAX_CASES:
            raise ValueError("CPU timing evidence exceeds the supported case count")
        if type(case) is not CpuCaseTiming:
            raise ValueError("CPU timing evidence requires explicit paired case timings")
        if type(case.case_id) is not str or not case.case_id or case.case_id in seen:
            raise ValueError("CPU timing case identities must be nonempty and unique")
        if type(case.stratum) is not str or case.stratum not in weights:
            raise ValueError("CPU timing task differs from its exact scoring weights")
        for elapsed in (case.candidate_elapsed_ms, case.reference_elapsed_ms):
            _integer(elapsed, minimum=0, maximum=MAX_ELAPSED_MS, name="elapsed milliseconds")
        if type(case.candidate_valid) is not bool or type(case.reference_valid) is not bool:
            raise ValueError("CPU timing validity must be explicit boolean evidence")
        seen.add(case.case_id)
        candidate_valid = case.candidate_valid and case.candidate_elapsed_ms <= maximum_inference_ms
        reference_valid = case.reference_valid and case.reference_elapsed_ms <= maximum_inference_ms
        failures += int(not candidate_valid)
        if not reference_valid:
            # An authenticated failed reference has no usable speed comparison.
            # Missing or incomparable evidence must be rejected by the caller;
            # it is not a reference failure and must never reach this branch.
            slowdown = Fraction(1)
        else:
            charged = max(1, case.candidate_elapsed_ms) if candidate_valid else maximum_inference_ms
            slowdown = Fraction(charged, max(1, case.reference_elapsed_ms))
            if not candidate_valid:
                slowdown = max(Fraction(1), slowdown)
        totals[case.stratum] = totals.get(case.stratum, Fraction()) + slowdown
        counts[case.stratum] = counts.get(case.stratum, 0) + 1
    if totals.keys() != weights.keys():
        raise ValueError("CPU timing evidence must cover every weighted task")
    return (
        sum(
            (weights[task] * totals[task] / counts[task] for task in weights),
            Fraction(),
        ),
        failures,
    )


def _multiplier_ppm(slowdown: Fraction, *, candidate_failed_cases: int) -> int:
    # floor(PPM * (1 / slowdown) ** (1 / 10)), with integer comparisons only.
    # The bounded binary search takes at most 19 iterations regardless of time
    # ratios; there is no platform-dependent floating-point or Decimal root.
    numerator = PPM**10 * slowdown.denominator
    denominator = slowdown.numerator
    if MIN_EFFICIENCY_PPM**10 * denominator >= numerator:
        result = MIN_EFFICIENCY_PPM
    elif MAX_EFFICIENCY_PPM**10 * denominator <= numerator:
        result = MAX_EFFICIENCY_PPM
    else:
        low, high = MIN_EFFICIENCY_PPM, MAX_EFFICIENCY_PPM
        while high - low > 1:
            middle = (low + high) // 2
            if middle**10 * denominator <= numerator:
                low = middle
            else:
                high = middle
        result = low
    # A fast invalid/empty/failed answer can never create an efficiency bonus,
    # even when other valid cases are much faster than their references.
    return min(PPM, result) if candidate_failed_cases else result


def multiplier_from_slowdown(slowdown: Fraction, *, candidate_failed_cases: int) -> int:
    """Canonicalize retained aggregate timing without reopening case evidence."""
    if type(slowdown) is not Fraction or slowdown <= 0:
        raise ValueError("CPU slowdown must be a positive exact fraction")
    _integer(
        candidate_failed_cases,
        minimum=0,
        maximum=MAX_CASES * 64,
        name="candidate failed cases",
    )
    return _multiplier_ppm(slowdown, candidate_failed_cases=candidate_failed_cases)


def cpu_efficiency_measurement(
    cases: Iterable[CpuCaseTiming],
    task_weights: Mapping[str, Fraction],
    *,
    maximum_inference_ms: int,
) -> CpuEfficiencyMeasurement:
    """Measure one exact task-weighted mean of matched-case slowdown ratios.

    Each task first averages its case ratios, preventing longer clips or extra
    cases from silently changing the signed task weights. Valid elapsed times
    have a one-millisecond floor. Invalid candidates are charged the deadline;
    their contribution cannot be faster than the reference. A failed reference
    contributes neutral slowdown, never an inferred speed advantage. Inputs
    explicitly marked valid but over the deadline are treated as failed.
    """
    slowdown, failures = _normalized_slowdown(cases, task_weights, maximum_inference_ms)
    return CpuEfficiencyMeasurement(
        normalized_slowdown=slowdown,
        multiplier_ppm=_multiplier_ppm(slowdown, candidate_failed_cases=failures),
        candidate_failed_cases=failures,
    )


def normalized_cpu_slowdown(
    cases: Iterable[CpuCaseTiming],
    task_weights: Mapping[str, Fraction],
    *,
    maximum_inference_ms: int,
) -> Fraction:
    """Return slowdown only; use cpu_efficiency_measurement when needing both."""
    return _normalized_slowdown(cases, task_weights, maximum_inference_ms)[0]


def efficiency_multiplier_ppm(
    cases: Iterable[CpuCaseTiming],
    task_weights: Mapping[str, Fraction],
    *,
    maximum_inference_ms: int,
) -> int:
    """Return the canonical bounded multiplier for complete paired evidence."""
    return cpu_efficiency_measurement(
        cases, task_weights, maximum_inference_ms=maximum_inference_ms
    ).multiplier_ppm


def apply_efficiency_weights(
    base_weights: Sequence[Fraction], multipliers_ppm: Sequence[int]
) -> tuple[Fraction, ...]:
    """Adjust qualified credits once and normalize before budget apportionment.

    Zero credits stay zero. An empty or wholly zero input has no eligible reward
    recipient and remains empty or zero; speed cannot manufacture eligibility.
    Hotkey aggregation and integer reward-budget apportionment remain downstream.
    """
    if len(base_weights) != len(multipliers_ppm) or len(base_weights) > MAX_MODELS:
        raise ValueError("efficiency weights require matching bounded credit counts")
    adjusted = []
    for weight, multiplier in zip(base_weights, multipliers_ppm, strict=True):
        if type(weight) is not Fraction or weight < 0:
            raise ValueError("base reward weights must be nonnegative exact fractions")
        _integer(
            multiplier,
            minimum=MIN_EFFICIENCY_PPM,
            maximum=MAX_EFFICIENCY_PPM,
            name="efficiency multiplier ppm",
        )
        adjusted.append(weight * Fraction(multiplier, PPM))
    total = sum(adjusted, Fraction())
    return tuple(weight / total if total else weight for weight in adjusted)
