"""CPU consumption rewards preserve latency deadlines and historical semantics."""

import pytest

from umi.competition_cpu_timing import CpuTimingInfrastructureError, comparable_cpu_timings
from umi.protocol import canonical_json_bytes

from .test_competition_cpu_timing import scheduler_evidence, validate


def work_evidence():
    return scheduler_evidence().model_copy(update={"schema_": "umi-cpu-timing-evidence/3"})


def test_cpu_work_uses_aggregate_counter_and_allocation_not_elapsed():
    value = work_evidence()
    validate(value, measurement_semantics="umi-exclusive-cold-model-cpu-timing/3")
    assert value.efficiency_cost_ms == 5_000
    assert value.speed_elapsed_ms == 10_000
    # Six CPU-seconds spread over two or six allocated cores represent the same
    # aggregate cost; matched comparisons always require identical allocations.
    altered = value.model_copy(
        update={
            "after": value.after.model_copy(
                update={"cgroup_usage_usec": value.before.cgroup_usage_usec + 6_000_001}
            )
        }
    )
    assert altered.efficiency_cost_ms == 3_001


def test_counter_reset_is_never_a_fast_result():
    value = work_evidence()
    altered = value.model_copy(
        update={
            "before": value.before.model_copy(
                update={"cgroup_usage_usec": value.after.cgroup_usage_usec + 1}
            )
        }
    )
    with pytest.raises(CpuTimingInfrastructureError, match="counter_reset"):
        _ = altered.efficiency_cost_ms


def change_probe(value, *, cpu_factor=1, wall_factor=1):
    conditions = value.conditions
    probes = {}
    for name in ("before_probe", "after_probe"):
        probe = getattr(conditions, name)
        probes[name] = probe.model_copy(
            update={
                "workers": tuple(
                    worker.model_copy(
                        update={
                            "thread_cpu_us": worker.thread_cpu_us * cpu_factor,
                            "wall_us": worker.wall_us * wall_factor,
                        }
                    )
                    for worker in probe.workers
                )
            }
        )
    return value.model_copy(update={"conditions": conditions.model_copy(update=probes)})


def test_cpu_work_compares_cpu_probe_cost_but_legacy_still_compares_wall():
    value = work_evidence()
    comparable_cpu_timings(value, change_probe(value, wall_factor=2))
    with pytest.raises(CpuTimingInfrastructureError, match="incomparable_reference_calibration"):
        comparable_cpu_timings(value, change_probe(value, cpu_factor=2))
    legacy = scheduler_evidence()
    with pytest.raises(CpuTimingInfrastructureError, match="incomparable_reference_calibration"):
        comparable_cpu_timings(legacy, change_probe(legacy, wall_factor=2))


def test_cpu_work_still_rejects_foreign_cpu_consumption():
    value = work_evidence()
    value = value.model_copy(
        update={
            "after": value.after.model_copy(
                update={"scheduler_runtime_ns": (6_000_000_000, 6_000_000_000)}
            )
        }
    )
    with pytest.raises(CpuTimingInfrastructureError, match="external_cpu_contention"):
        validate(value, measurement_semantics="umi-exclusive-cold-model-cpu-timing/3")


def test_cpu_work_cannot_reinterpret_old_signed_evidence():
    old = scheduler_evidence()
    raw = canonical_json_bytes(old)
    assert old.efficiency_cost_ms == old.speed_elapsed_ms
    with pytest.raises(CpuTimingInfrastructureError, match="measurement_semantics_mismatch"):
        validate(old, measurement_semantics="umi-exclusive-cold-model-cpu-timing/3")
    with pytest.raises(CpuTimingInfrastructureError, match="incomparable_reference"):
        comparable_cpu_timings(old, work_evidence())
    assert canonical_json_bytes(type(old).model_validate_json(raw)) == raw
