"""Timing stays authenticated, complete and separate from measured quality."""

from fractions import Fraction
from types import SimpleNamespace

import pytest

from umi.competition_cpu_efficiency_evidence import (
    CpuEfficiencyRun,
    CpuEfficiencySummary,
    combine_cpu_efficiency_runs,
    retained_cpu_slowdown,
    summarize_evaluator_efficiency,
)
from umi.competition_cpu_efficiency_math import MAX_ELAPSED_MS, multiplier_from_slowdown
from umi.competition_cpu_timing import CpuTimingEvidence, CpuTimingInfrastructureError
from umi.open_competition import CaseOutput
from umi.protocol import canonical_json_bytes

from .test_competition_cpu_timing import CONTRACT, bundle_cache, conditions, context, sample


def output(case_id, elapsed_ms, *, hypothesis="answer", status="ok", ctx=None):
    ctx = ctx or context()
    before = sample(ctx)
    timing = CpuTimingEvidence(
        schema="umi-cpu-timing-evidence/1",
        contract_sha256=CONTRACT,
        context=ctx,
        bundle_cache=bundle_cache(started=before.finished_us),
        conditions=conditions(
            ctx, started=before.finished_us, finished=before.finished_us + elapsed_ms * 1000
        ),
        before=before,
        after=sample(
            ctx,
            now=before.finished_us + elapsed_ms * 1000,
            ticks=100 + elapsed_ms // 10,
            busy=50 + elapsed_ms // 20,
            usage=elapsed_ms * 1000,
        ),
        started_monotonic_us=before.finished_us,
        model_started_monotonic_us=before.finished_us,
        finished_monotonic_us=before.finished_us + elapsed_ms * 1000,
    )
    return CaseOutput(
        case_id=case_id,
        status=status,
        hypothesis=hypothesis,
        elapsed_ms=elapsed_ms,
        cpu_timing=timing,
    )


def observation(**changes):
    cases = (
        SimpleNamespace(case_id="1" * 64, stratum="continuous"),
        SimpleNamespace(case_id="2" * 64, stratum="fingerspelling"),
    )
    arguments = dict(
        outputs={
            "candidate": [output(case.case_id, 5000) for case in cases],
            "incumbent": [output(case.case_id, 10000) for case in cases],
        },
        cases=cases,
        task_weights={"continuous": Fraction(10, 13), "fingerspelling": Fraction(3, 13)},
        contract_sha256=CONTRACT,
        evaluator_identity="3" * 64,
        terminal_sha256="4" * 64,
        maximum_inference_ms=20000,
    )
    return arguments | changes


def test_compact_summary_uses_already_replayed_outputs_and_exact_task_weights():
    run = summarize_evaluator_efficiency(**observation())
    assert run.normalized_slowdown == Fraction(1, 2)
    assert run.case_count == 2
    summary = combine_cpu_efficiency_runs(CONTRACT, (run,))
    assert summary.multiplier_ppm == 1071773
    assert CpuEfficiencySummary.model_validate_json(canonical_json_bytes(summary)) == summary


def test_retained_timing_counts_match_native_suite_capacity():
    from umi.open_competition import EvaluationSuite

    maximum = EvaluationSuite.model_json_schema()["properties"]["cases"]["maxItems"]
    assert maximum == 2048
    raw = summarize_evaluator_efficiency(**observation()).model_dump(mode="json", by_alias=True)
    raw.update(case_count=maximum, candidate_failed_cases=maximum)
    run = CpuEfficiencyRun.model_validate_json(canonical_json_bytes(raw))
    assert run.case_count == run.candidate_failed_cases == maximum
    assert combine_cpu_efficiency_runs(CONTRACT, (run,)).multiplier_ppm == 1_000_000
    raw["case_count"] = maximum + 1
    with pytest.raises(ValueError):
        CpuEfficiencyRun.model_validate_json(canonical_json_bytes(raw))


@pytest.mark.parametrize("hypothesis,status", [("", "ok"), ("  ", "ok"), ("", "miner_failure")])
def test_empty_fast_or_failed_output_cannot_earn_a_bonus(hypothesis, status):
    args = observation()
    for index, case in enumerate(args["cases"]):
        args["outputs"]["candidate"][index] = output(
            case.case_id, 100, hypothesis=hypothesis, status=status
        )
    run = summarize_evaluator_efficiency(**args)
    assert run.candidate_failed_cases == 2
    assert run.normalized_slowdown == 2
    assert combine_cpu_efficiency_runs(CONTRACT, (run,)).multiplier_ppm == 933032


@pytest.mark.parametrize(
    "change", ["missing", "duplicate", "contract", "profile", "hardware", "infra"]
)
def test_incomplete_or_incomparable_receipts_cannot_be_silently_neutral(change):
    args = observation()
    candidate = args["outputs"]["candidate"]
    if change == "missing":
        candidate[0] = candidate[0].model_copy(update={"cpu_timing": None})
    elif change == "duplicate":
        candidate.append(candidate[0])
    elif change == "contract":
        args["contract_sha256"] = "5" * 64
    elif change in {"profile", "hardware"}:
        ctx = context(**{change + "_sha256": "6" * 64})
        candidate[0] = output(candidate[0].case_id, 5000, ctx=ctx)
    else:
        candidate[0] = output(
            candidate[0].case_id, 5000, status="infrastructure_failure", hypothesis=""
        )
    with pytest.raises((ValueError, CpuTimingInfrastructureError)):
        summarize_evaluator_efficiency(**args)


def test_evaluators_are_normalized_individually_then_combined_without_fastest_selection():
    fast = summarize_evaluator_efficiency(**observation())
    slow = CpuEfficiencyRun(
        evaluator_identity="7" * 64,
        terminal_sha256="8" * 64,
        profile_sha256="9" * 64,
        observations_sha256="a" * 64,
        slowdown_numerator="3",
        slowdown_denominator="2",
        candidate_failed_cases=0,
        case_count=2,
    )
    assert combine_cpu_efficiency_runs(CONTRACT, (slow, fast)).multiplier_ppm == 1000000
    with pytest.raises(ValueError, match="once in order"):
        combine_cpu_efficiency_runs(CONTRACT, (fast, fast))
    body = combine_cpu_efficiency_runs(CONTRACT, (fast, slow)).model_dump(
        mode="json", by_alias=True
    )
    body["multiplier_ppm"] = 1150000
    with pytest.raises(ValueError, match="differs"):
        CpuEfficiencySummary.model_validate_json(canonical_json_bytes(body))


def test_original_outputs_keep_exact_bytes_and_cannot_claim_an_unmeasured_duration():
    original = CaseOutput(case_id="1" * 64, status="ok", hypothesis="answer", elapsed_ms=10000)
    assert canonical_json_bytes(original) == canonical_json_bytes(
        {"case_id": "1" * 64, "status": "ok", "hypothesis": "answer", "elapsed_ms": 10000}
    )
    raw = output("1" * 64, 10000).model_dump(mode="json", by_alias=True)
    raw["elapsed_ms"] = 1
    with pytest.raises(ValueError, match="duration"):
        CaseOutput.model_validate_json(canonical_json_bytes(raw))


@pytest.mark.parametrize(
    "ratio",
    [
        Fraction(1, MAX_ELAPSED_MS),
        Fraction(1, 3),
        Fraction(1, 2),
        Fraction(2),
        Fraction(MAX_ELAPSED_MS),
    ],
)
def test_retained_slowdown_rounds_conservatively_with_bounded_storage(ratio):
    retained = retained_cpu_slowdown(ratio)
    assert ratio <= retained < ratio + Fraction(1, 1_000_000_000)
    assert 1_000_000_000 % retained.denominator == 0
    assert max(len(str(retained.numerator)), len(str(retained.denominator))) <= 20
    assert multiplier_from_slowdown(retained, candidate_failed_cases=0) <= multiplier_from_slowdown(
        ratio, candidate_failed_cases=0
    )


def test_first_quality_pass_retains_policy_precision_not_an_unbounded_fraction():
    args = observation()
    args["outputs"]["incumbent"] = [output(case.case_id, 15000) for case in args["cases"]]
    run = summarize_evaluator_efficiency(**args)
    assert run.normalized_slowdown == Fraction(333333334, 1_000_000_000)
    assert CpuEfficiencyRun.model_validate_json(canonical_json_bytes(run)) == run


@pytest.mark.parametrize(
    "numerator,denominator",
    [("1", "3"), ("2", "4"), ("1", "1000000000"), ("86400001", "1"), ("1" * 21, "1")],
)
def test_retained_runs_reject_unbounded_or_noncanonical_ratios(numerator, denominator):
    raw = summarize_evaluator_efficiency(**observation()).model_dump(mode="json", by_alias=True)
    raw.update(slowdown_numerator=numerator, slowdown_denominator=denominator)
    with pytest.raises(ValueError):
        CpuEfficiencyRun.model_validate_json(canonical_json_bytes(raw))
