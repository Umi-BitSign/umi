"""Replayable contemporaneous host conditions; never adjust measured seconds."""

from __future__ import annotations

import hashlib
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .protocol import Hex32, StrictProtocolModel

Counter = Annotated[int, Field(ge=0, le=2**53 - 1, strict=True)]
Positive = Annotated[int, Field(gt=0, le=2**53 - 1, strict=True)]
PROBE_RULE = "parallel_sha256_4096x65536_load_balanced/1"
PRESSURE_RULE = "disjoint_external_cgroup_siblings_full_pressure/1"
PROBE_RESULT = hashlib.sha256(bytes(65536)).hexdigest()


class CpuConditionLimits(StrictProtocolModel):
    # Prospective policy tolerances, not calibrated confidence claims.
    maximum_probe_variation_bps: Literal[1000] = 1000
    maximum_observer_lateness_us: Literal[100_000] = 100_000
    maximum_external_pressure_bps: Literal[100] = 100
    maximum_probe_boundary_gap_us: Literal[1_000_000] = 1_000_000
    maximum_pressure_snapshot_us: Literal[50_000] = 50_000


class ProbeWorker(StrictProtocolModel):
    worker: Annotated[int, Field(ge=0, le=7, strict=True)]
    wall_us: Annotated[int, Field(gt=0, le=5_000_000, strict=True)]
    thread_cpu_us: Annotated[int, Field(gt=0, le=5_000_000, strict=True)]
    result_sha256: Hex32


class FixedCpuProbe(StrictProtocolModel):
    schema_: Literal["umi-fixed-cpu-condition-probe/1"] = Field(alias="schema")
    rule: Literal["parallel_sha256_4096x65536_load_balanced/1"] = PROBE_RULE
    measurement_profile_sha256: Hex32
    invocation_sha256: Hex32
    boundary: Literal["before", "after"]
    cpu_ids: Annotated[tuple[int, ...], Field(min_length=1, max_length=8)]
    started_us: Positive
    finished_us: Positive
    workers: Annotated[tuple[ProbeWorker, ...], Field(min_length=1, max_length=8)]

    @model_validator(mode="after")
    def shape(self):
        if not 0 < self.finished_us - self.started_us <= 5_000_000:
            raise ValueError("CPU condition probe exceeded its bounded window")
        if self.cpu_ids != tuple(sorted(set(self.cpu_ids))) or any(
            type(cpu) is not int or not 0 <= cpu <= 8191 for cpu in self.cpu_ids
        ):
            raise ValueError("invalid condition probe CPU set")
        if tuple(worker.worker for worker in self.workers) != tuple(range(len(self.cpu_ids))):
            raise ValueError("condition probe worker count differs from CPU allowance")
        if any(worker.result_sha256 != PROBE_RESULT for worker in self.workers):
            raise ValueError("trusted fixed probe returned different work")
        return self


class ObserverLag(StrictProtocolModel):
    started_us: Positive
    finished_us: Positive
    ticks: Counter
    maximum_lateness_us: Counter


class PressureSnapshot(StrictProtocolModel):
    started_us: Positive
    finished_us: Positive
    scope_identity_sha256: Hex32
    external_memory_full_us: Counter
    external_io_full_us: Counter
    host_memory_full_us: Counter
    host_io_full_us: Counter
    model_memory_full_us: Counter
    model_io_full_us: Counter
    model_memory_high: Counter
    model_memory_max: Counter
    model_oom: Counter
    model_oom_kill: Counter
    model_major_faults: Counter
    model_read_bytes: Counter
    host_swap_in_pages: Counter
    host_swap_out_pages: Counter


class CpuConditionEvidence(StrictProtocolModel):
    schema_: Literal["umi-cpu-condition-evidence/1"] = Field(alias="schema")
    invocation_sha256: Hex32
    topology_sha256: Hex32
    pressure_rule: Literal["disjoint_external_cgroup_siblings_full_pressure/1"] = PRESSURE_RULE
    before_probe: FixedCpuProbe
    after_probe: FixedCpuProbe
    observer: ObserverLag
    before_pressure: PressureSnapshot
    after_pressure: PressureSnapshot


def _fail(reason):
    # Lazy import avoids a cycle: the timing record embeds this evidence.
    from .competition_cpu_timing import CpuTimingInfrastructureError

    raise CpuTimingInfrastructureError(reason)


def _within(value, reference, bps=1000):
    return reference * (10_000 - bps) <= value * 10_000 <= reference * (10_000 + bps)


def _probe_work(probe):
    # Normal scheduler balancing is intentional. Do not pretend a Python
    # worker is a particular core, or select the fastest worker as the result.
    return (
        max(worker.wall_us for worker in probe.workers),
        sum(worker.thread_cpu_us for worker in probe.workers),
    )


def validate_conditions(evidence, timing):
    limits = CpuConditionLimits()
    if evidence.topology_sha256 != timing.context.topology_sha256:
        _fail("cpu_conditions_topology_binding_mismatch")
    probes = evidence.before_probe, evidence.after_probe
    for probe, boundary in zip(probes, ("before", "after"), strict=True):
        if (
            probe.boundary != boundary
            or probe.invocation_sha256 != evidence.invocation_sha256
            or probe.measurement_profile_sha256 != timing.context.profile_sha256
            or probe.cpu_ids != timing.context.cpu_ids
        ):
            _fail("cpu_condition_probe_binding_mismatch")
    if not (
        probes[0].finished_us <= timing.before.started_us
        and timing.after.finished_us <= probes[1].started_us
        and timing.started_monotonic_us - probes[0].finished_us
        <= limits.maximum_probe_boundary_gap_us
        and probes[1].started_us - timing.after.finished_us <= limits.maximum_probe_boundary_gap_us
    ):
        _fail("cpu_condition_probe_not_contemporaneous")
    if any(
        not _within(right, left)
        for left, right in zip(_probe_work(probes[0]), _probe_work(probes[1]), strict=True)
    ):
        _fail("cpu_condition_probe_changed_during_invocation")
    observer = evidence.observer
    if not (
        observer.started_us <= timing.model_started_monotonic_us
        and observer.finished_us >= timing.finished_monotonic_us
        and observer.maximum_lateness_us <= limits.maximum_observer_lateness_us
    ):
        _fail("cpu_condition_host_observer_stalled")
    first, last = evidence.before_pressure, evidence.after_pressure
    if not (
        first.finished_us <= timing.before.started_us
        and timing.after.finished_us <= last.started_us
        and first.scope_identity_sha256 == last.scope_identity_sha256
    ):
        _fail("cpu_condition_pressure_interval_or_scope_changed")
    for snapshot in (first, last):
        if (
            not 0
            <= snapshot.finished_us - snapshot.started_us
            <= limits.maximum_pressure_snapshot_us
        ):
            _fail("cpu_condition_pressure_snapshot_too_slow")
    changes = {}
    for field in PressureSnapshot.model_fields:
        if field in {"started_us", "finished_us", "scope_identity_sha256"}:
            continue
        changes[field] = getattr(last, field) - getattr(first, field)
        if changes[field] < 0:
            _fail("cpu_condition_pressure_counter_reset")
    duration = timing.finished_monotonic_us - timing.model_started_monotonic_us
    # PSI is not additive by subtraction. Only disjoint external scopes gate;
    # host/model PSI and own resource costs are retained diagnostic evidence.
    # Own OOM, faults and quota contention remain model costs.
    for field in ("external_memory_full_us", "external_io_full_us"):
        if changes[field] * 10_000 > duration * limits.maximum_external_pressure_bps:
            _fail("cpu_condition_external_pressure")
    return changes


def comparable_conditions(candidate, baseline):
    if candidate.topology_sha256 != baseline.topology_sha256:
        _fail("cpu_condition_incomparable_topology")
    for own in (candidate.before_probe, candidate.after_probe):
        for reference in (baseline.before_probe, baseline.after_probe):
            if len(own.cpu_ids) != len(reference.cpu_ids) or any(
                not _within(a, b)
                for a, b in zip(_probe_work(own), _probe_work(reference), strict=True)
            ):
                _fail("cpu_condition_incomparable_reference_calibration")
