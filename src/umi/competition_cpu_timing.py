"""Bounded host CPU timing observations for prospective efficiency contracts.

The wall clock measures a cold sandbox invocation, never CPU work in place of
latency. These are evaluator observations, not remote hardware attestations.
An authenticated contract selects the profile and noise limits. Existing cohort
evidence without this extension keeps its original meaning.

The caller owns an existing model-slot lock for the complete invocation and a
persistent, otherwise empty cgroup parent. That parent must outlive Podman's
short-lived container cgroup so even a fast exit retains final CPU accounting.
This module neither provisions cgroups nor acquires an additional scheduler lock.
"""

from __future__ import annotations

import hashlib
import os
import time
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .competition_cpu_cache import CpuBundleCacheEvidence, validate_bundle_cache_evidence
from .competition_cpu_conditions import (
    CpuConditionEvidence,
    comparable_conditions,
    validate_conditions,
)
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

_SAFE = 2**53 - 1
Counter = Annotated[int, Field(ge=0, le=_SAFE, strict=True)]
Positive = Annotated[int, Field(gt=0, le=_SAFE, strict=True)]
CpuId = Annotated[int, Field(ge=0, le=8191, strict=True)]


class CpuTimingInfrastructureError(RuntimeError):
    """An unusable measurement needs infrastructure recovery, never a slow score."""

    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


def _fail(reason: str):
    raise CpuTimingInfrastructureError(reason)


def _cpu_ids(values):
    values = tuple(values)
    if (
        not values
        or len(values) > 8192
        or any(type(cpu) is not int or not 0 <= cpu <= 8191 for cpu in values)
        or tuple(sorted(set(values))) != values
    ):
        _fail("cpu_timing_invalid_cpu_set")
    return values


def parse_cpu_set(raw: str) -> tuple[int, ...]:
    if not raw.strip() or len(raw) > 4096:
        _fail("cpu_timing_invalid_cpu_set")
    found = set()
    for part in raw.strip().split(","):
        pair = part.split("-")
        if len(pair) not in {1, 2} or any(not item.isdecimal() for item in pair):
            _fail("cpu_timing_invalid_cpu_set")
        first, last = int(pair[0]), int(pair[-1])
        if not 0 <= first <= last <= 8191:
            _fail("cpu_timing_invalid_cpu_set")
        members = set(range(first, last + 1))
        if found & members:
            _fail("cpu_timing_duplicate_cpu")
        found.update(members)
    return _cpu_ids(sorted(found))


class CpuSlotPlan(StrictProtocolModel):
    slot_name: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.-]{1,128}$")]
    cpu_ids: Annotated[tuple[CpuId, ...], Field(min_length=1, max_length=8)]


def plan_cpu_slots(slot_names, allowed_cpus, cpus_per_slot, *, background_cpus):
    """Map existing shared lock names to disjoint sets; never grant a lease.

    Provisioning must independently establish equivalent CPU classes and keep
    unrelated workloads off these sets. The resulting cpusets alone do not
    establish exclusivity. Every consumer must use the same immutable plan and
    must hold its existing slot lock before using that slot's CPUs.
    """
    allowed = _cpu_ids(allowed_cpus)
    background = tuple(background_cpus)
    if background:
        _cpu_ids(background)
    names = tuple(slot_names)
    if (
        type(cpus_per_slot) is not int
        or not 1 <= cpus_per_slot <= 8
        or not 1 <= len(names) <= 32
        or len(set(names)) != len(names)
        or not set(background).issubset(allowed)
    ):
        _fail("cpu_timing_invalid_slot_plan")
    usable = tuple(cpu for cpu in allowed if cpu not in background)
    if len(usable) < len(names) * cpus_per_slot:
        _fail("cpu_timing_insufficient_disjoint_cpus")
    return tuple(
        CpuSlotPlan(slot_name=name, cpu_ids=usable[i * cpus_per_slot : (i + 1) * cpus_per_slot])
        for i, name in enumerate(names)
    )


class CpuTicks(StrictProtocolModel):
    cpu_id: CpuId
    total: Counter
    busy: Counter
    steal: Counter

    @model_validator(mode="after")
    def valid_totals(self):
        if self.busy + self.steal > self.total:
            raise ValueError("CPU busy and steal exceed total ticks")
        return self


class CpuTimingContext(StrictProtocolModel):
    profile_sha256: Hex32
    hardware_sha256: Hex32
    cpu_class_sha256: Hex32
    topology_sha256: Hex32
    cpu_ids: Annotated[tuple[CpuId, ...], Field(min_length=1, max_length=8)]
    cpu_quota_usec: Positive
    cpu_period_usec: Positive
    memory_max_bytes: Positive
    memory_swap_max_bytes: Counter
    cgroup_device: Counter
    cgroup_inode: Positive
    clock_ticks_per_second: Annotated[int, Field(gt=0, le=1_000_000, strict=True)]

    @model_validator(mode="after")
    def exact_resources(self):
        _cpu_ids(self.cpu_ids)
        if self.cpu_quota_usec != len(self.cpu_ids) * self.cpu_period_usec:
            raise ValueError("timing CPU quota must exactly match its selected CPU count")
        if self.memory_swap_max_bytes != 0:
            raise ValueError("timed model execution cannot use swap")
        return self


class CpuTimingSample(StrictProtocolModel):
    started_us: Positive
    finished_us: Positive
    context: CpuTimingContext
    cpu_ticks: Annotated[tuple[CpuTicks, ...], Field(min_length=1, max_length=8)]
    cgroup_usage_usec: Counter
    cgroup_throttled_usec: Counter
    cgroup_throttled_periods: Counter
    populated: bool

    @model_validator(mode="after")
    def sample_shape(self):
        if self.finished_us < self.started_us:
            raise ValueError("timing sample clock rolled backwards")
        if tuple(row.cpu_id for row in self.cpu_ticks) != self.context.cpu_ids:
            raise ValueError("timing sample CPU counters differ from its exact CPU set")
        return self


class CpuTimingLimits(StrictProtocolModel):
    maximum_external_busy_bps: Annotated[int, Field(ge=0, le=10_000, strict=True)]
    maximum_steal_bps: Annotated[int, Field(ge=0, le=10_000, strict=True)]
    maximum_boundary_overhead_ms: Annotated[int, Field(ge=0, le=10_000, strict=True)]
    maximum_snapshot_ms: Annotated[int, Field(gt=0, le=10_000, strict=True)]
    maximum_clock_disagreement_bps: Annotated[int, Field(ge=0, le=10_000, strict=True)]


def cpu_timing_limits_v1() -> CpuTimingLimits:
    """Normative limits for isolated cold-model CPU timing."""
    return CpuTimingLimits(
        maximum_external_busy_bps=100,
        maximum_steal_bps=50,
        maximum_boundary_overhead_ms=100,
        maximum_snapshot_ms=50,
        maximum_clock_disagreement_bps=100,
    )


class CpuTimingEvidence(StrictProtocolModel):
    schema_: Literal["umi-cpu-timing-evidence/1"] = Field(alias="schema")
    contract_sha256: Hex32
    context: CpuTimingContext
    before: CpuTimingSample
    after: CpuTimingSample
    started_monotonic_us: Positive
    model_started_monotonic_us: Positive
    finished_monotonic_us: Positive
    launch_gate_elapsed_us: Counter = 0
    conditions: CpuConditionEvidence
    bundle_cache: CpuBundleCacheEvidence

    @property
    def elapsed_ms(self) -> int:
        return (self.finished_monotonic_us - self.started_monotonic_us + 999) // 1000

    @property
    def speed_elapsed_ms(self) -> int:
        return (self.finished_monotonic_us - self.model_started_monotonic_us + 999) // 1000

    @model_validator(mode="after")
    def preserved_context(self):
        if self.before.context != self.context or self.after.context != self.context:
            raise ValueError("CPU timing context changed during execution")
        if not (
            self.before.finished_us
            <= self.started_monotonic_us
            <= self.model_started_monotonic_us
            < self.finished_monotonic_us
            <= self.after.started_us
        ):
            raise ValueError("CPU timing samples do not enclose the invocation")
        if (
            self.launch_gate_elapsed_us
            != self.model_started_monotonic_us - self.started_monotonic_us
        ):
            raise ValueError("CPU launch gate differs from its measured boundaries")
        return self


def _delta(after, before):
    if after < before:
        _fail("cpu_timing_counter_reset")
    return after - before


def timing_accounting(evidence: CpuTimingEvidence) -> dict[str, int]:
    """Reconstruct integer diagnostics; no quality or efficiency decision here."""
    before, after = evidence.before, evidence.after
    ticks = evidence.context.clock_ticks_per_second
    cpus = len(evidence.context.cpu_ids)
    delta = {field: 0 for field in ("total", "busy", "steal")}
    for left, right in zip(before.cpu_ticks, after.cpu_ticks, strict=True):
        for field in delta:
            delta[field] += _delta(getattr(right, field), getattr(left, field))
    usage = _delta(after.cgroup_usage_usec, before.cgroup_usage_usec)
    _delta(after.cgroup_throttled_usec, before.cgroup_throttled_usec)
    _delta(after.cgroup_throttled_periods, before.cgroup_throttled_periods)
    sample_spans = before.finished_us - before.started_us + after.finished_us - after.started_us
    # Each sampled CPU can straddle two scheduler ticks; CPU and /proc counters
    # are read sequentially within the retained bounded snapshot intervals.
    tolerance = (2 * cpus * 1_000_000 + ticks - 1) // ticks + cpus * sample_spans
    busy = delta["busy"] * 1_000_000 // ticks
    total = delta["total"] * 1_000_000 // ticks
    steal = delta["steal"] * 1_000_000 // ticks
    if usage > busy + tolerance:
        _fail("cpu_timing_cpu_accounting_mismatch")
    if total == 0:
        _fail("cpu_timing_insufficient_clock_samples")
    return dict(
        model_cpu_usec=usage,
        total_cpu_usec=total,
        host_busy_usec=busy,
        steal_usec=steal,
        external_busy_lower_usec=max(0, busy - usage - tolerance),
        accounting_tolerance_usec=tolerance,
        measurement_capacity_usec=cpus * (after.finished_us - before.started_us),
        scored_capacity_usec=cpus
        * (evidence.finished_monotonic_us - evidence.model_started_monotonic_us),
    )


def validate_cpu_timing(evidence, *, contract_sha256, profile_sha256, limits):
    """Validate trusted policy bindings and reject contaminated observations.

    Own quota throttling/thread contention remains measured model cost. It is
    deliberately not treated as external noise or subtracted from wall time.
    """
    if not isinstance(evidence, CpuTimingEvidence) or not isinstance(limits, CpuTimingLimits):
        _fail("cpu_timing_missing_evidence_or_policy")
    try:
        evidence = CpuTimingEvidence.model_validate_json(canonical_json_bytes(evidence))
        limits = CpuTimingLimits.model_validate_json(canonical_json_bytes(limits))
    except ValueError as error:
        raise CpuTimingInfrastructureError("cpu_timing_invalid_observed_context") from error
    if (
        evidence.contract_sha256 != contract_sha256
        or evidence.context.profile_sha256 != profile_sha256
    ):
        _fail("cpu_timing_contract_or_profile_mismatch")
    if evidence.before.populated or evidence.after.populated:
        _fail("cpu_timing_parent_not_empty_at_boundary")
    if evidence.launch_gate_elapsed_us > 5_000_000:
        _fail("cpu_timing_launch_gate_delay")
    for sample in (evidence.before, evidence.after):
        if sample.finished_us - sample.started_us > limits.maximum_snapshot_ms * 1000:
            _fail("cpu_timing_snapshot_too_slow")
    overhead = (
        evidence.started_monotonic_us
        - evidence.before.finished_us
        + evidence.after.started_us
        - evidence.finished_monotonic_us
    )
    if overhead > limits.maximum_boundary_overhead_ms * 1000:
        _fail("cpu_timing_boundary_gap")
    values = timing_accounting(evidence)
    expected = values["measurement_capacity_usec"]
    disagreement = abs(values["total_cpu_usec"] - expected)
    if max(0, disagreement - values["accounting_tolerance_usec"]) * 10_000 > (
        expected * limits.maximum_clock_disagreement_bps
    ):
        _fail("cpu_timing_cpu_clock_disagreement")
    # A long host launch gate must not dilute contention during short model
    # execution. Full-interval counters remain conservative; only the scored
    # interval supplies the allowed external-noise budget.
    if values["external_busy_lower_usec"] * 10_000 > (
        values["scored_capacity_usec"] * limits.maximum_external_busy_bps
    ):
        _fail("cpu_timing_external_cpu_contention")
    if values["steal_usec"] * 10_000 > (values["scored_capacity_usec"] * limits.maximum_steal_bps):
        _fail("cpu_timing_hypervisor_steal")
    try:
        validate_bundle_cache_evidence(
            evidence.bundle_cache,
            model_sha256=evidence.bundle_cache.model_sha256,
            invocation_sha256=evidence.conditions.invocation_sha256,
            measured_start_us=evidence.started_monotonic_us,
        )
    except (AttributeError, ValueError) as error:
        raise CpuTimingInfrastructureError("cpu_timing_invalid_bundle_cache") from error
    validate_conditions(evidence.conditions, evidence)
    return values


def comparable_cpu_timings(candidate, baseline):
    """Equivalent allocated cores may have different IDs and cgroup inodes."""
    left, right = candidate.context, baseline.context
    fields = (
        "profile_sha256",
        "hardware_sha256",
        "cpu_class_sha256",
        "topology_sha256",
        "cpu_quota_usec",
        "cpu_period_usec",
        "memory_max_bytes",
        "memory_swap_max_bytes",
        "clock_ticks_per_second",
    )
    if (
        candidate.contract_sha256 != baseline.contract_sha256
        or any(getattr(left, key) != getattr(right, key) for key in fields)
        or len(left.cpu_ids) != len(right.cpu_ids)
    ):
        _fail("cpu_timing_incomparable_reference")
    for observed in (candidate, baseline):
        try:
            validate_bundle_cache_evidence(
                observed.bundle_cache,
                model_sha256=observed.bundle_cache.model_sha256,
                invocation_sha256=observed.conditions.invocation_sha256,
                measured_start_us=observed.started_monotonic_us,
            )
        except (AttributeError, ValueError) as error:
            raise CpuTimingInfrastructureError("cpu_timing_invalid_bundle_cache") from error
    comparable_conditions(candidate.conditions, baseline.conditions)


def validate_runtime_resources(context, *, cpus, memory_bytes):
    """Bind the selected local timing context to the authenticated CPU runtime."""
    if (
        type(cpus) is not int
        or type(memory_bytes) is not int
        or (len(context.cpu_ids) != cpus or context.memory_max_bytes != memory_bytes)
    ):
        _fail("cpu_timing_signed_runtime_mismatch")


def finish_cpu_timing(
    *,
    contract_sha256,
    context,
    before,
    after,
    started_monotonic_us,
    finished_monotonic_us,
    limits,
    launch_gate_elapsed_us=0,
    model_started_monotonic_us=None,
    conditions,
    bundle_cache=None,
):
    try:
        value = CpuTimingEvidence(
            schema="umi-cpu-timing-evidence/1",
            contract_sha256=contract_sha256,
            context=context,
            before=before,
            after=after,
            started_monotonic_us=started_monotonic_us,
            finished_monotonic_us=finished_monotonic_us,
            model_started_monotonic_us=(
                started_monotonic_us
                if model_started_monotonic_us is None
                else model_started_monotonic_us
            ),
            launch_gate_elapsed_us=launch_gate_elapsed_us,
            conditions=conditions,
            bundle_cache=bundle_cache,
        )
    except ValueError as error:
        raise CpuTimingInfrastructureError("cpu_timing_invalid_observed_context") from error
    validate_cpu_timing(
        value, contract_sha256=contract_sha256, profile_sha256=context.profile_sha256, limits=limits
    )
    return value


def _small_read(path, maximum):
    with Path(path).open("rb") as stream:
        value = stream.read(maximum + 1)
    if len(value) > maximum:
        _fail("cpu_timing_kernel_metadata_too_large")
    return value.decode("ascii", errors="strict")


def parse_proc_stat(raw: str, cpu_ids) -> tuple[CpuTicks, ...]:
    selected = _cpu_ids(cpu_ids)
    rows = {}
    for line in raw.splitlines():
        fields = line.split()
        if not fields or not fields[0].startswith("cpu") or not fields[0][3:].isdecimal():
            continue
        cpu = int(fields[0][3:])
        if cpu not in selected:
            continue
        if cpu in rows or len(fields) < 9 or any(not v.isdecimal() for v in fields[1:]):
            _fail("cpu_timing_invalid_proc_stat")
        values = [int(v) for v in fields[1:9]]
        # guest/guest_nice are already included in user/nice; never count twice.
        rows[cpu] = CpuTicks(
            cpu_id=cpu,
            total=sum(values),
            busy=sum(values[i] for i in (0, 1, 2, 5, 6)),
            steal=values[7],
        )
    if set(rows) != set(selected):
        _fail("cpu_timing_missing_cpu_counters")
    return tuple(rows[cpu] for cpu in selected)


def hardware_fingerprints(cpuinfo: str, cpu_ids) -> tuple[str, str]:
    """Stable visible CPU identity/class; excludes varying MHz and BogoMIPS.

    The profile must separately qualify NUMA placement, governor, SMT sharing
    and host isolation. A CPU-info digest alone cannot establish fairness.
    """
    if len(cpuinfo.encode()) > 2 * 1024**2:
        _fail("cpu_timing_kernel_metadata_too_large")
    selected = _cpu_ids(cpu_ids)
    keys = {
        "vendor_id",
        "cpu family",
        "model",
        "model name",
        "stepping",
        "microcode",
        "flags",
        "CPU implementer",
        "CPU architecture",
        "CPU variant",
        "CPU part",
        "CPU revision",
        "Features",
    }
    rows = {}
    for block in cpuinfo.strip().split("\n\n"):
        fields = dict(
            (k.strip(), v.strip())
            for line in block.splitlines()
            if ":" in line
            for k, v in (line.split(":", 1),)
        )
        identifier = fields.get("processor", "")
        if not identifier.isdecimal():
            continue
        cpu = int(identifier)
        properties = {key: fields[key] for key in sorted(keys & fields.keys())}
        if cpu in rows or not properties:
            _fail("cpu_timing_invalid_cpu_identity")
        rows[cpu] = properties
    if not set(selected).issubset(rows):
        _fail("cpu_timing_missing_cpu_identity")
    classes = [rows[cpu] for cpu in selected]
    if any(item != classes[0] for item in classes):
        _fail("cpu_timing_heterogeneous_cpu_set")
    hardware = {
        "schema": "umi-visible-cpu-hardware/1",
        "processors": [{"cpu_id": cpu, "properties": rows[cpu]} for cpu in sorted(rows)],
    }
    return (
        hashlib.sha256(canonical_json_bytes(hardware)).hexdigest(),
        hashlib.sha256(canonical_json_bytes(classes[0])).hexdigest(),
    )


def _key_values(raw):
    values = {}
    for line in raw.splitlines():
        row = line.split()
        if len(row) != 2 or row[0] in values or not row[1].isdecimal():
            _fail("cpu_timing_invalid_cgroup_counters")
        values[row[0]] = int(row[1])
    return values


class CpuTimingSampler:
    """Read-only sampler for an owned persistent cgroup; no sysfs writes.

    The caller must retain the existing slot lease until after final sampling.
    Cgroup existence and matching limits do not prove that exclusive ownership.
    Shared ancestors must have no CPU quota. Their cumulative throttle counters
    also detect temporary quota restrictions restored between readbacks.
    """

    def __init__(
        self,
        context,
        cgroup_path,
        *,
        cgroup_root=Path("/sys/fs/cgroup"),
        proc_stat_path=Path("/proc/stat"),
        cpuinfo_path=Path("/proc/cpuinfo"),
        clock=None,
        owned_parent=None,
    ):
        self.context, self.path = context, Path(cgroup_path)
        self.proc_stat_path = Path(proc_stat_path)
        self.cpuinfo_path = Path(cpuinfo_path)
        self.clock = clock or (lambda: time.monotonic_ns() // 1000)
        self.root = root = Path(cgroup_root)
        self.owned_parent = Path(owned_parent) if owned_parent is not None else self.path
        self._ancestors = []
        self._ancestor_counters = {}
        if not root.is_absolute() or not self.path.is_absolute() or ".." in self.path.parts:
            _fail("cpu_timing_invalid_cgroup_path")
        try:
            relative = self.path.relative_to(root)
        except ValueError as error:
            raise CpuTimingInfrastructureError("cpu_timing_invalid_cgroup_path") from error
        if not relative.parts or len(relative.parts) > 64:
            _fail("cpu_timing_invalid_cgroup_depth")
        if self.owned_parent not in {self.path, self.path.parent} or self.owned_parent == root:
            _fail("cpu_timing_invalid_owned_parent")
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        descriptor = None
        try:
            descriptor = os.open(root, flags)
            path = root
            for part in relative.parts:
                observed = os.fstat(descriptor)
                self._ancestors.append((path, descriptor, (observed.st_dev, observed.st_ino)))
                descriptor = None
                parent_descriptor = self._ancestors[-1][1]
                descriptor = os.open(part, flags, dir_fd=parent_descriptor)
                path = path / part
            self.descriptor = descriptor
            descriptor = None
            observed = os.fstat(self.descriptor)
            if (observed.st_dev, observed.st_ino) != (context.cgroup_device, context.cgroup_inode):
                _fail("cpu_timing_cgroup_identity_changed")
        except CpuTimingInfrastructureError:
            self.close()
            raise
        except (OSError, ValueError) as error:
            self.close()
            raise CpuTimingInfrastructureError("cpu_timing_kernel_context_unavailable") from error
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def close(self):
        descriptor = getattr(self, "descriptor", None)
        if descriptor is not None:
            os.close(descriptor)
            self.descriptor = None
        for _, descriptor, _ in self._ancestors:
            os.close(descriptor)
        self._ancestors.clear()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    @staticmethod
    def _read_at(parent_descriptor, name):
        descriptor = os.open(
            name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_descriptor
        )
        with os.fdopen(descriptor, "rb") as stream:
            raw = stream.read(4097)
        if len(raw) > 4096:
            _fail("cpu_timing_kernel_metadata_too_large")
        return raw.decode("ascii", errors="strict").strip()

    def _read(self, name):
        return self._read_at(self.descriptor, name)

    def _check_ancestors(self):
        for path, descriptor, identity in self._ancestors:
            current = path.stat(follow_symlinks=False)
            observed = os.fstat(descriptor)
            if (current.st_dev, current.st_ino) != identity or (
                observed.st_dev,
                observed.st_ino,
            ) != identity:
                _fail("cpu_timing_ancestor_identity_changed")
            try:
                quota = self._read_at(descriptor, "cpu.max").split()
            except FileNotFoundError:
                # The actual cgroupfs root cannot have a local bandwidth cap.
                # Missing controls anywhere below that trusted root fail closed.
                if path == self.root:
                    continue
                raise
            if path == self.owned_parent:
                if quota != [
                    str(self.context.cpu_quota_usec),
                    str(self.context.cpu_period_usec),
                ]:
                    _fail("cpu_timing_cpu_quota_changed")
                continue
            if (
                len(quota) != 2
                or quota[0] != "max"
                or not quota[1].isdecimal()
                or not 1_000 <= int(quota[1]) <= 1_000_000
            ):
                _fail("cpu_timing_ancestor_cpu_quota_limited")
            counters = _key_values(self._read_at(descriptor, "cpu.stat"))
            current_counters = counters["nr_throttled"], counters["throttled_usec"]
            previous = self._ancestor_counters.setdefault(path, current_counters)
            if any(after < before for before, after in zip(previous, current_counters, strict=True)):
                _fail("cpu_timing_ancestor_counter_reset")
            if current_counters != previous:
                _fail("cpu_timing_ancestor_cpu_throttled")

    def _check_context(self):
        self._check_ancestors()
        observed = os.fstat(self.descriptor)
        context = self.context
        if (observed.st_dev, observed.st_ino) != (context.cgroup_device, context.cgroup_inode):
            _fail("cpu_timing_cgroup_identity_changed")
        current = self.path.stat(follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (observed.st_dev, observed.st_ino):
            _fail("cpu_timing_cgroup_identity_changed")
        if self._read("cgroup.type") != "domain":
            _fail("cpu_timing_cgroup_not_domain")
        quota = self._read("cpu.max").split()
        if quota != [str(context.cpu_quota_usec), str(context.cpu_period_usec)]:
            _fail("cpu_timing_cpu_quota_changed")
        if parse_cpu_set(self._read("cpuset.cpus.effective")) != context.cpu_ids:
            _fail("cpu_timing_cpuset_changed")
        if self._read("memory.max") != str(context.memory_max_bytes) or self._read(
            "memory.swap.max"
        ) != str(context.memory_swap_max_bytes):
            _fail("cpu_timing_memory_profile_changed")

    def sample(self):
        try:
            started = self.clock()
            self._check_context()
            hardware, cpu_class = hardware_fingerprints(
                _small_read(self.cpuinfo_path, 2 * 1024**2), self.context.cpu_ids
            )
            if (hardware, cpu_class) != (
                self.context.hardware_sha256,
                self.context.cpu_class_sha256,
            ):
                _fail("cpu_timing_hardware_identity_changed")
            ticks = parse_proc_stat(
                _small_read(self.proc_stat_path, 2 * 1024**2), self.context.cpu_ids
            )
            cpu = _key_values(self._read("cpu.stat"))
            events = _key_values(self._read("cgroup.events"))
            if events["populated"] not in {0, 1}:
                _fail("cpu_timing_invalid_cgroup_population")
            self._check_context()
            return CpuTimingSample(
                started_us=started,
                finished_us=self.clock(),
                context=self.context,
                cpu_ticks=ticks,
                cgroup_usage_usec=cpu["usage_usec"],
                cgroup_throttled_usec=cpu["throttled_usec"],
                cgroup_throttled_periods=cpu["nr_throttled"],
                populated=bool(events["populated"]),
            )
        except CpuTimingInfrastructureError:
            raise
        except (OSError, ValueError, KeyError, TypeError) as error:
            raise CpuTimingInfrastructureError("cpu_timing_kernel_sample_unavailable") from error

    def check_context(self):
        """Read back an already opened cgroup's immutable resource binding."""
        try:
            self._check_context()
        except CpuTimingInfrastructureError:
            raise
        except (OSError, ValueError, KeyError, TypeError) as error:
            raise CpuTimingInfrastructureError("cpu_timing_kernel_context_unavailable") from error
