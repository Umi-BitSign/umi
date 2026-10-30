"""Compact CPU timing conclusions retained by the existing quality certificate.

These models are mathematical evidence, not authority. Native replay authenticates
the prepared contract and original execution terminals before constructing them.
No model, archive or timing payload is reopened during reward allocation.
"""

import hashlib
from fractions import Fraction
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .competition_cpu_efficiency_math import (
    MAX_CASES,
    MAX_ELAPSED_MS,
    CpuCaseTiming,
    cpu_efficiency_measurement,
    multiplier_from_slowdown,
)
from .competition_cpu_timing import comparable_cpu_timings
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

SLOWDOWN_PRECISION = 1_000_000_000
PositiveIntegerText = Annotated[str, Field(pattern=r"^[1-9][0-9]*$", max_length=20)]


def retained_cpu_slowdown(value: Fraction) -> Fraction:
    """Round upward once per evaluator, bounding evidence without a speed premium.

    The signed policy fixes this precision and rounding rule. Per-case math and
    measured quality remain exact; only this retained timing ratio is quantized.
    """
    if type(value) is not Fraction or not Fraction(1, MAX_ELAPSED_MS) <= value <= MAX_ELAPSED_MS:
        raise ValueError("CPU slowdown exceeds the supported elapsed-time range")
    scaled = (value.numerator * SLOWDOWN_PRECISION + value.denominator - 1) // value.denominator
    return Fraction(scaled, SLOWDOWN_PRECISION)


class CpuEfficiencyRun(StrictProtocolModel):
    evaluator_identity: Hex32
    terminal_sha256: Hex32
    profile_sha256: Hex32
    observations_sha256: Hex32
    slowdown_numerator: PositiveIntegerText
    slowdown_denominator: PositiveIntegerText
    candidate_failed_cases: Annotated[int, Field(ge=0, le=MAX_CASES)]
    case_count: Annotated[int, Field(ge=1, le=MAX_CASES)]

    @property
    def normalized_slowdown(self) -> Fraction:
        return Fraction(int(self.slowdown_numerator), int(self.slowdown_denominator))

    @model_validator(mode="after")
    def canonical_measurement(self):
        value = self.normalized_slowdown
        if (
            self.candidate_failed_cases > self.case_count
            or str(value.numerator) != self.slowdown_numerator
            or str(value.denominator) != self.slowdown_denominator
            or SLOWDOWN_PRECISION % value.denominator != 0
            or not Fraction(1, MAX_ELAPSED_MS) <= value <= MAX_ELAPSED_MS
        ):
            raise ValueError("CPU efficiency run is not a canonical bounded measurement")
        return self


class CpuEfficiencySummary(StrictProtocolModel):
    schema_: Literal["umi-cpu-efficiency-summary/1"] = Field(
        default="umi-cpu-efficiency-summary/1", alias="schema"
    )
    contract_sha256: Hex32
    runs: Annotated[tuple[CpuEfficiencyRun, ...], Field(min_length=1, max_length=64)]
    multiplier_ppm: Annotated[int, Field(ge=850000, le=1150000)]

    @model_validator(mode="after")
    def canonical_summary(self):
        keys = tuple(run.evaluator_identity for run in self.runs)
        if keys != tuple(sorted(set(keys))):
            raise ValueError("CPU efficiency must retain each selected evaluator once in order")
        if len({run.case_count for run in self.runs}) != 1:
            raise ValueError("CPU efficiency evaluators must cover the same complete cases")
        if len({run.terminal_sha256 for run in self.runs}) != len(self.runs):
            raise ValueError("CPU efficiency must not repeat a terminal")
        expected = _summary_multiplier(self.runs)
        if self.multiplier_ppm != expected:
            raise ValueError("CPU efficiency multiplier differs from authenticated measurements")
        return self


def _summary_multiplier(runs):
    # Normalize on each evaluator before combining. Raw seconds on different
    # machines are never compared, and no evaluator's fastest run is selected.
    slowdown = sum((run.normalized_slowdown for run in runs), Fraction()) / len(runs)
    return multiplier_from_slowdown(
        slowdown,
        candidate_failed_cases=sum(run.candidate_failed_cases for run in runs),
    )


def combine_cpu_efficiency_runs(contract_sha256, runs) -> CpuEfficiencySummary:
    ordered = tuple(sorted(runs, key=lambda run: run.evaluator_identity))
    if not ordered:
        raise ValueError("CPU efficiency needs complete evaluator measurements")
    return CpuEfficiencySummary(
        contract_sha256=contract_sha256,
        runs=ordered,
        multiplier_ppm=_summary_multiplier(ordered),
    )


def summarize_evaluator_efficiency(
    outputs,
    cases,
    task_weights,
    *,
    contract_sha256,
    evaluator_identity,
    terminal_sha256,
    maximum_inference_ms,
) -> CpuEfficiencyRun:
    """Consume the already replayed outputs in the first quality review pass."""
    selected = {case.case_id: case for case in cases}
    by_role = {
        role: {output.case_id: output for output in outputs[role]}
        for role in ("candidate", "incumbent")
    }
    if not selected or any(
        set(by_role[role]) != set(selected) or len(by_role[role]) != len(outputs[role])
        for role in by_role
    ):
        raise ValueError("CPU efficiency requires every original matched case")
    timings, observations, profiles = [], [], set()
    for case in cases:
        candidate = by_role["candidate"][case.case_id]
        reference = by_role["incumbent"][case.case_id]
        pair = (candidate.cpu_timing, reference.cpu_timing)
        if any(timing is None for timing in pair):
            raise ValueError("CPU efficiency timing evidence is missing; explicit repair required")
        for output, timing in zip((candidate, reference), pair, strict=True):
            if (
                timing.contract_sha256 != contract_sha256
                or timing.elapsed_ms != output.elapsed_ms
                or output.status == "infrastructure_failure"
            ):
                raise ValueError("CPU efficiency cannot use invalid or unrelated timing evidence")
        if pair[0].context.profile_sha256 != pair[1].context.profile_sha256:
            raise ValueError("CPU efficiency reference and candidate profiles are incomparable")
        comparable_cpu_timings(*pair)
        profiles.add(pair[0].context.profile_sha256)
        timings.append(
            CpuCaseTiming(
                case_id=case.case_id,
                stratum=case.stratum,
                candidate_elapsed_ms=pair[0].speed_elapsed_ms,
                reference_elapsed_ms=pair[1].speed_elapsed_ms,
                candidate_valid=(
                    candidate.status == "ok"
                    and candidate.elapsed_ms <= maximum_inference_ms
                    and bool(candidate.hypothesis.strip())
                ),
                reference_valid=(
                    reference.status == "ok"
                    and reference.elapsed_ms <= maximum_inference_ms
                    and bool(reference.hypothesis.strip())
                ),
            )
        )
        observations.append(
            {
                "case_id": case.case_id,
                "candidate": candidate.model_dump(mode="json", by_alias=True),
                "incumbent": reference.model_dump(mode="json", by_alias=True),
            }
        )
    if len(profiles) != 1:
        raise ValueError("CPU efficiency run changes its comparable hardware/resource profile")
    measurement = cpu_efficiency_measurement(
        timings, task_weights, maximum_inference_ms=maximum_inference_ms
    )
    ratio = retained_cpu_slowdown(measurement.normalized_slowdown)
    return CpuEfficiencyRun(
        evaluator_identity=evaluator_identity,
        terminal_sha256=terminal_sha256,
        profile_sha256=next(iter(profiles)),
        observations_sha256=hashlib.sha256(canonical_json_bytes(observations)).hexdigest(),
        slowdown_numerator=str(ratio.numerator),
        slowdown_denominator=str(ratio.denominator),
        candidate_failed_cases=measurement.candidate_failed_cases,
        case_count=len(timings),
    )
