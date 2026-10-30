"""Synthetic evidence rejects incomparable conditions without repeating inference."""

import pytest

from umi.competition_cpu_conditions import comparable_conditions
from umi.competition_cpu_timing import CpuTimingInfrastructureError

from .test_competition_cpu_timing import evidence, validate


def replace_condition(value, **updates):
    return value.model_copy(update={"conditions": value.conditions.model_copy(update=updates)})


def scale_probe(probe, scale):
    return probe.model_copy(
        update={
            "workers": tuple(
                worker.model_copy(
                    update={
                        "wall_us": int(worker.wall_us * scale),
                        "thread_cpu_us": int(worker.thread_cpu_us * scale),
                    }
                )
                for worker in probe.workers
            )
        }
    )


@pytest.mark.parametrize(
    "field,reason",
    [
        ("topology", "topology_binding"),
        ("observer", "observer_stalled"),
        ("probe_work", "probe_changed"),
        ("probe_gap", "probe_not_contemporaneous"),
        ("invocation", "invalid_bundle_cache"),
        ("scope", "pressure_interval_or_scope"),
        ("pressure", "external_pressure"),
        ("reset", "counter_reset"),
    ],
)
def test_unusable_host_conditions_are_infrastructure(field, reason):
    value = evidence()
    observed = value.conditions
    if field == "topology":
        value = replace_condition(value, topology_sha256="0" * 64)
    elif field == "observer":
        value = replace_condition(
            value, observer=observed.observer.model_copy(update={"maximum_lateness_us": 100_001})
        )
    elif field == "probe_work":
        value = replace_condition(value, after_probe=scale_probe(observed.after_probe, 1.2))
    elif field == "probe_gap":
        value = replace_condition(
            value,
            after_probe=observed.after_probe.model_copy(
                update={
                    "started_us": value.after.finished_us + 1_000_001,
                    "finished_us": value.after.finished_us + 1_100_001,
                }
            ),
        )
    elif field == "invocation":
        value = replace_condition(value, invocation_sha256="0" * 64)
    elif field == "scope":
        value = replace_condition(
            value,
            after_pressure=observed.after_pressure.model_copy(
                update={"scope_identity_sha256": "0" * 64}
            ),
        )
    elif field == "pressure":
        value = replace_condition(
            value,
            after_pressure=observed.after_pressure.model_copy(
                update={"external_memory_full_us": 100_001}
            ),
        )
    else:
        value = replace_condition(
            value,
            before_pressure=observed.before_pressure.model_copy(update={"host_swap_in_pages": 1}),
        )
    with pytest.raises(CpuTimingInfrastructureError, match=reason):
        validate(value)


def test_own_memory_limit_faults_and_host_psi_are_not_subtracted_or_excused():
    value = evidence()
    value = replace_condition(
        value,
        after_pressure=value.conditions.after_pressure.model_copy(
            update={
                "host_memory_full_us": 8_000_000,
                "host_io_full_us": 8_000_000,
                "model_memory_full_us": 8_000_000,
                "model_io_full_us": 8_000_000,
                "model_oom": 1,
                "model_oom_kill": 1,
                "model_memory_max": 1,
                "model_major_faults": 10000,
                "model_read_bytes": 2**30,
            }
        ),
    )
    validate(value)


def test_consistent_slow_host_cannot_compare_with_fast_reference():
    baseline = evidence().conditions
    candidate = baseline.model_copy(
        update={
            "before_probe": scale_probe(baseline.before_probe, 1.2),
            "after_probe": scale_probe(baseline.after_probe, 1.2),
        }
    )
    with pytest.raises(CpuTimingInfrastructureError, match="incomparable_reference_calibration"):
        comparable_conditions(candidate, baseline)


def test_probe_is_fixed_work_not_fastest_worker_or_core_affinity():
    value = evidence()
    probe = value.conditions.after_probe
    workers = list(probe.workers)
    workers[1] = workers[1].model_copy(update={"wall_us": 200000})
    value = replace_condition(
        value, after_probe=probe.model_copy(update={"workers": tuple(workers)})
    )
    with pytest.raises(CpuTimingInfrastructureError, match="probe_changed"):
        validate(value)
