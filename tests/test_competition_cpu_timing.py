"""CPU timing fixtures only: no real cgroups, production state or model execution."""

import pytest
from pydantic import ValidationError

from umi import competition_cpu_timing as timing
from umi.competition_cpu_conditions import (
    PROBE_RESULT,
    CpuConditionEvidence,
    FixedCpuProbe,
    ObserverLag,
    PressureSnapshot,
)
from umi.protocol import canonical_json_bytes

CONTRACT = "a" * 64
PROFILE = "b" * 64


def context(**changes):
    value = dict(
        profile_sha256=PROFILE,
        hardware_sha256="c" * 64,
        cpu_class_sha256="d" * 64,
        topology_sha256="e" * 64,
        cpu_ids=(0, 1),
        cpu_quota_usec=200_000,
        cpu_period_usec=100_000,
        memory_max_bytes=8 * 1024**3,
        memory_swap_max_bytes=0,
        cgroup_device=1,
        cgroup_inode=100,
        clock_ticks_per_second=100,
    )
    return timing.CpuTimingContext(**(value | changes))


def limits(**changes):
    value = dict(
        maximum_external_busy_bps=100,
        maximum_steal_bps=50,
        maximum_boundary_overhead_ms=100,
        maximum_snapshot_ms=50,
        maximum_clock_disagreement_bps=100,
    )
    return timing.CpuTimingLimits(**(value | changes))


def sample(
    ctx, *, now=1_000_000, ticks=100, busy=50, steal=0, usage=0, throttled=0, populated=False
):
    return timing.CpuTimingSample(
        started_us=now,
        finished_us=now,
        context=ctx,
        cpu_ticks=tuple(
            timing.CpuTicks(cpu_id=i, total=ticks, busy=busy, steal=steal) for i in ctx.cpu_ids
        ),
        cgroup_usage_usec=usage,
        cgroup_throttled_usec=throttled,
        cgroup_throttled_periods=throttled // 100_000,
        populated=populated,
    )


def bundle_cache(*, model="a" * 64, started=1_000_000, invocation="f" * 64):
    from umi.competition_cpu_cache import CpuBundleCacheEvidence

    return CpuBundleCacheEvidence(
        schema="umi-cpu-bundle-cache-evidence/1",
        model_sha256=model,
        invocation_sha256=invocation,
        file_count=1,
        total_bytes=1,
        total_pages=1,
        page_size=4096,
        started_monotonic_us=started - 300_000,
        finished_monotonic_us=started - 250_000,
    )


def conditions(ctx, *, started=1_000_000, finished=11_000_000, invocation="f" * 64):
    def probe(boundary, begin):
        return FixedCpuProbe(
            schema="umi-fixed-cpu-condition-probe/1",
            measurement_profile_sha256=ctx.profile_sha256,
            invocation_sha256=invocation,
            boundary=boundary,
            cpu_ids=ctx.cpu_ids,
            started_us=begin,
            finished_us=begin + 100_000,
            workers=tuple(
                dict(worker=i, wall_us=100_000, thread_cpu_us=100_000, result_sha256=PROBE_RESULT)
                for i in range(len(ctx.cpu_ids))
            ),
        )

    def pressure(now):
        values = {
            field: 0
            for field in PressureSnapshot.model_fields
            if field not in {"started_us", "finished_us", "scope_identity_sha256"}
        }
        return PressureSnapshot(
            started_us=now, finished_us=now, scope_identity_sha256="9" * 64, **values
        )

    return CpuConditionEvidence(
        schema="umi-cpu-condition-evidence/1",
        invocation_sha256=invocation,
        topology_sha256=ctx.topology_sha256,
        before_probe=probe("before", started - 200_000),
        after_probe=probe("after", finished + 200),
        observer=ObserverLag(
            started_us=started - 1, finished_us=finished + 1, ticks=1, maximum_lateness_us=0
        ),
        before_pressure=pressure(started - 100),
        after_pressure=pressure(finished + 100),
    )


def evidence(*, ctx=None, before=None, after=None):
    ctx = ctx or context()
    return timing.finish_cpu_timing(
        contract_sha256=CONTRACT,
        context=ctx,
        before=before or sample(ctx),
        after=after or sample(ctx, now=11_000_000, ticks=1100, busy=550, usage=10_000_000),
        started_monotonic_us=1_000_000,
        finished_monotonic_us=11_000_000,
        limits=limits(),
        conditions=conditions(ctx),
        bundle_cache=bundle_cache(),
    )


def validate(value, **options):
    return timing.validate_cpu_timing(
        value, contract_sha256=CONTRACT, profile_sha256=PROFILE, limits=limits(), **options
    )


def test_ordinary_challenge_uses_wall_time_not_cpu_work():
    value = evidence()
    assert value.elapsed_ms == 10_000
    assert validate(value)["model_cpu_usec"] == 10_000_000
    assert validate(value)["measurement_capacity_usec"] == 20_000_000
    assert timing.CpuTimingEvidence.model_validate_json(canonical_json_bytes(value)) == value


def test_self_threading_and_quota_throttling_are_not_external_noise():
    ctx = context()
    after = sample(ctx, now=11_000_000, ticks=1100, busy=550, usage=10_000_000, throttled=9_000_000)
    value = evidence(ctx=ctx, after=after)
    assert value.elapsed_ms == 10_000
    assert validate(value)["external_busy_lower_usec"] == 0


@pytest.mark.parametrize(
    "change,reason",
    [
        ({"usage": 5_000_000}, "external_cpu_contention"),
        ({"steal": 20}, "hypervisor_steal"),
        ({"usage": 12_000_000}, "cpu_accounting_mismatch"),
        ({"ticks": 800}, "cpu_clock_disagreement"),
        ({"populated": True}, "parent_not_empty_at_boundary"),
    ],
)
def test_noisy_or_mismatched_measurement_is_infrastructure_failure(change, reason):
    ctx = context()
    values = dict(now=11_000_000, ticks=1100, busy=550, usage=10_000_000)
    with pytest.raises(timing.CpuTimingInfrastructureError, match=reason):
        evidence(ctx=ctx, after=sample(ctx, **(values | change)))


def test_missing_evidence_cannot_become_neutral_or_speed_credit():
    with pytest.raises(timing.CpuTimingInfrastructureError, match="missing_evidence"):
        validate(None)


@pytest.mark.parametrize(
    "busy,steal,reason",
    [
        (60, 0, "external_cpu_contention"),
        (55, 1, "hypervisor_steal"),
    ],
)
def test_long_launch_gate_cannot_dilute_noise_during_short_scored_execution(busy, steal, reason):
    ctx = context()
    with pytest.raises(timing.CpuTimingInfrastructureError, match=reason):
        timing.finish_cpu_timing(
            contract_sha256=CONTRACT,
            context=ctx,
            before=sample(ctx),
            after=sample(ctx, now=5_100_000, ticks=510, busy=busy, steal=steal, usage=100_000),
            started_monotonic_us=1_000_000,
            model_started_monotonic_us=5_000_000,
            finished_monotonic_us=5_100_000,
            launch_gate_elapsed_us=4_000_000,
            conditions=conditions(ctx, finished=5_100_000),
            bundle_cache=bundle_cache(),
            limits=limits(),
        )


def test_policy_binding_does_not_trust_evidence_selected_limits():
    value = evidence()
    with pytest.raises(timing.CpuTimingInfrastructureError, match="contract_or_profile"):
        timing.validate_cpu_timing(
            value, contract_sha256="f" * 64, profile_sha256=PROFILE, limits=limits()
        )


def test_changed_context_and_cpu_counter_reset_refuse():
    ctx = context()
    before = sample(ctx, usage=20_000_000)
    with pytest.raises(timing.CpuTimingInfrastructureError, match="counter_reset"):
        evidence(ctx=ctx, before=before)
    after = sample(
        context(cgroup_inode=101), now=11_000_000, ticks=1100, busy=550, usage=10_000_000
    )
    with pytest.raises(timing.CpuTimingInfrastructureError, match="invalid_observed_context"):
        evidence(ctx=ctx, after=after)


def test_gap_and_slow_snapshot_cannot_hide_unmetered_work():
    value = evidence()
    altered = value.model_copy(
        update={"started_monotonic_us": 2_000_000, "model_started_monotonic_us": 2_000_000}
    )
    with pytest.raises(timing.CpuTimingInfrastructureError, match="boundary_gap"):
        validate(altered)
    before = value.before.model_copy(update={"started_us": 900_000})
    altered = value.model_copy(update={"before": before})
    with pytest.raises(timing.CpuTimingInfrastructureError, match="snapshot_too_slow"):
        validate(altered)


def test_equivalent_disjoint_core_sets_are_comparable_but_hardware_changes_are_not():
    baseline = evidence()
    candidate = evidence(ctx=context(cpu_ids=(2, 3), cgroup_inode=101))
    timing.comparable_cpu_timings(candidate, baseline)
    different = evidence(ctx=context(hardware_sha256="e" * 64))
    with pytest.raises(timing.CpuTimingInfrastructureError, match="incomparable_reference"):
        timing.comparable_cpu_timings(candidate, different)


def test_runtime_limits_are_bound_to_authenticated_profile():
    timing.validate_runtime_resources(context(), cpus=2, memory_bytes=8 * 1024**3)
    with pytest.raises(timing.CpuTimingInfrastructureError, match="signed_runtime_mismatch"):
        timing.validate_runtime_resources(context(), cpus=6, memory_bytes=8 * 1024**3)
    with pytest.raises(ValidationError):
        context(cpu_quota_usec=600_000)
    with pytest.raises(ValidationError):
        context(memory_swap_max_bytes=1)


def test_slot_plan_reuses_exact_existing_names_and_is_disjoint():
    names = (
        "model-a.slot",
        "model-b.slot",
        "model-0003.slot",
        "model-0004.slot",
        "model-0005.slot",
    )
    plan = timing.plan_cpu_slots(names, tuple(range(32)), 6, background_cpus=(30, 31))
    assert tuple(p.slot_name for p in plan) == names
    assert tuple(cpu for p in plan for cpu in p.cpu_ids) == tuple(range(30))
    assert all(len(p.cpu_ids) == 6 for p in plan)


@pytest.mark.parametrize(
    "names,cpus,background",
    [
        (("a", "a"), tuple(range(12)), ()),
        (("a", "b"), tuple(range(11)), ()),
        (("a",), tuple(range(8)), (10,)),
    ],
)
def test_slot_plan_refuses_overcommit_or_ambiguous_names(names, cpus, background):
    with pytest.raises(timing.CpuTimingInfrastructureError):
        timing.plan_cpu_slots(names, cpus, 6, background_cpus=background)


def test_proc_stat_does_not_double_count_guest_or_count_other_cores():
    raw = "cpu0 100 20 30 200 10 5 6 7 80 10\ncpu1 5 5 5 5 5 5 5 5 5 5\n"
    (result,) = timing.parse_proc_stat(raw, (0,))
    assert result.total == 378
    assert result.busy == 161
    assert result.steal == 7
    with pytest.raises(timing.CpuTimingInfrastructureError, match="missing_cpu_counters"):
        timing.parse_proc_stat(raw, (0, 2))


@pytest.mark.parametrize("raw", ["", "0-1,1", "1-0", "0-8192", "-1", "0,a"])
def test_malformed_cpu_sets_refuse(raw):
    with pytest.raises(timing.CpuTimingInfrastructureError):
        timing.parse_cpu_set(raw)


def cpuinfo(*, model="Example CPU", mhz="3000"):
    return "\n\n".join(
        f"processor : {cpu}\nvendor_id : Example\nmodel name : {model}\n"
        f"flags : a b\ncpu MHz : {mhz}"
        for cpu in range(4)
    )


def test_hardware_fingerprint_ignores_frequency_but_not_cpu_class():
    first = timing.hardware_fingerprints(cpuinfo(), (0, 1))
    assert first == timing.hardware_fingerprints(cpuinfo(mhz="2999"), (2, 3))
    assert first != timing.hardware_fingerprints(cpuinfo(model="Other CPU"), (0, 1))
    mixed = cpuinfo().replace("model name : Example CPU", "model name : Other CPU", 1)
    with pytest.raises(timing.CpuTimingInfrastructureError, match="heterogeneous_cpu_set"):
        timing.hardware_fingerprints(mixed, (0, 1))


@pytest.fixture
def kernel(tmp_path):
    root = tmp_path / "cgroup"
    parent = root / "model-a"
    parent.mkdir(parents=True)
    files = {
        "cgroup.type": "domain",
        "cgroup.events": "populated 0\nfrozen 0\n",
        "cpu.max": "200000 100000",
        "cpuset.cpus.effective": "0-1",
        "memory.max": str(8 * 1024**3),
        "memory.swap.max": "0",
        "cpu.stat": "usage_usec 0\nnr_throttled 0\nthrottled_usec 0\n",
    }
    for name, raw in files.items():
        (parent / name).write_text(raw)
    proc = tmp_path / "proc"
    proc.mkdir()
    (proc / "stat").write_text("cpu0 50 0 0 50 0 0 0 0\ncpu1 50 0 0 50 0 0 0 0\n")
    (proc / "cpuinfo").write_text(cpuinfo())
    hardware, cpu_class = timing.hardware_fingerprints(cpuinfo(), (0, 1))
    info = parent.stat()
    ctx = context(
        hardware_sha256=hardware,
        cpu_class_sha256=cpu_class,
        cgroup_device=info.st_dev,
        cgroup_inode=info.st_ino,
    )
    return root, parent, proc, ctx


def sampler(kernel):
    root, parent, proc, ctx = kernel
    values = iter((1_000_000, 1_000_001, 11_000_000, 11_000_001))
    return timing.CpuTimingSampler(
        ctx,
        parent,
        cgroup_root=root,
        proc_stat_path=proc / "stat",
        cpuinfo_path=proc / "cpuinfo",
        clock=lambda: next(values),
    )


def test_owned_parent_preserves_accounting_after_short_container_exit(kernel):
    _, parent, proc, _ = kernel
    with sampler(kernel) as reader:
        before = reader.sample()
        # The temporary child can disappear; cumulative counters remain on the
        # existing parent that stays held by the caller's same model-slot lease.
        child = parent / "short-container"
        child.mkdir()
        child.rmdir()
        (parent / "cpu.stat").write_text(
            "usage_usec 10000000\nnr_throttled 4\nthrottled_usec 500000\n"
        )
        (proc / "stat").write_text("cpu0 550 0 0 550 0 0 0 0\ncpu1 550 0 0 550 0 0 0 0\n")
        after = reader.sample()
    assert before.cgroup_usage_usec == 0 and after.cgroup_usage_usec == 10_000_000
    assert reader.descriptor is None


@pytest.mark.parametrize(
    "name,value,reason",
    [
        ("cpu.max", "100000 100000", "cpu_quota_changed"),
        ("cpuset.cpus.effective", "0-2", "cpuset_changed"),
        ("memory.max", "1", "memory_profile_changed"),
        ("memory.swap.max", "1", "memory_profile_changed"),
        ("cgroup.type", "threaded", "cgroup_not_domain"),
    ],
)
def test_sampler_detects_changed_kernel_profile(kernel, name, value, reason):
    _, parent, _, _ = kernel
    with sampler(kernel) as reader:
        (parent / name).write_text(value)
        with pytest.raises(timing.CpuTimingInfrastructureError, match=reason):
            reader.sample()


def test_sampler_rejects_missing_counters_or_changed_cpu_identity(kernel):
    _, parent, proc, _ = kernel
    with sampler(kernel) as reader:
        (parent / "cpu.stat").unlink()
        with pytest.raises(timing.CpuTimingInfrastructureError, match="kernel_sample_unavailable"):
            reader.sample()
    with sampler(kernel) as reader:
        (proc / "cpuinfo").write_text(cpuinfo(model="Other CPU"))
        with pytest.raises(timing.CpuTimingInfrastructureError, match="hardware_identity_changed"):
            reader.sample()


def test_sampler_refuses_symlink_cgroup_and_files(kernel):
    root, parent, proc, ctx = kernel
    alias = root / "alias"
    alias.symlink_to(parent, target_is_directory=True)
    with pytest.raises(timing.CpuTimingInfrastructureError, match="kernel_context_unavailable"):
        timing.CpuTimingSampler(ctx, alias, cgroup_root=root)
    with sampler(kernel) as reader:
        (parent / "cpu.max").unlink()
        (parent / "cpu.max").symlink_to(proc / "stat")
        with pytest.raises(timing.CpuTimingInfrastructureError, match="kernel_sample_unavailable"):
            reader.sample()


@pytest.fixture
def ancestor_kernel(kernel):
    root, parent, proc, ctx = kernel
    shared = root / "shared.slice"
    slot = shared / "slot"
    slot.mkdir(parents=True)
    moved = slot / parent.name
    parent.rename(moved)
    for directory in (shared, slot):
        (directory / "cpu.max").write_text("max 100000")
        (directory / "cpu.stat").write_text("usage_usec 100\nnr_throttled 4\nthrottled_usec 500\n")
    return root, moved, proc, ctx


@pytest.mark.parametrize("ancestor", ["root", "shared", "slot"])
@pytest.mark.parametrize("quota", ["100000 100000", "10000000 100000"])
def test_finite_shared_ancestor_quota_refuses_even_when_large(ancestor_kernel, ancestor, quota):
    root, parent, _, _ = ancestor_kernel
    directory = {"root": root, "shared": parent.parent.parent, "slot": parent.parent}[ancestor]
    (directory / "cpu.max").write_text(quota)
    with (
        sampler(ancestor_kernel) as reader,
        pytest.raises(timing.CpuTimingInfrastructureError, match="ancestor_cpu_quota_limited"),
    ):
        reader.check_context()


@pytest.mark.parametrize("ancestor", ["shared", "slot"])
@pytest.mark.parametrize("counter", ["nr_throttled", "throttled_usec"])
def test_restored_ancestor_quota_cannot_hide_throttling(ancestor_kernel, ancestor, counter):
    _, parent, _, _ = ancestor_kernel
    directory = parent.parent.parent if ancestor == "shared" else parent.parent
    with sampler(ancestor_kernel) as reader:
        reader.sample()
        # A quota reduction is no longer visible by the second snapshot, but
        # the kernel's persistent local bandwidth counters retain its effect.
        (directory / "cpu.max").write_text("100000 100000")
        (directory / "cpu.max").write_text("max 100000")
        values = {"usage_usec": 100, "nr_throttled": 4, "throttled_usec": 500}
        values[counter] += 1
        (directory / "cpu.stat").write_text(
            "".join(f"{name} {value}\n" for name, value in values.items())
        )
        with pytest.raises(timing.CpuTimingInfrastructureError, match="ancestor_cpu_throttled"):
            reader.sample()


def test_ancestor_usage_and_old_throttling_do_not_reject_owned_model_cost(ancestor_kernel):
    _, parent, proc, _ = ancestor_kernel
    with sampler(ancestor_kernel) as reader:
        reader.sample()
        for directory in (parent.parent, parent.parent.parent):
            (directory / "cpu.stat").write_text(
                "usage_usec 10000100\nnr_throttled 4\nthrottled_usec 500\n"
            )
        (parent / "cpu.stat").write_text(
            "usage_usec 10000000\nnr_throttled 9\nthrottled_usec 900000\n"
        )
        (proc / "stat").write_text("cpu0 550 0 0 550 0 0 0 0\ncpu1 550 0 0 550 0 0 0 0\n")
        assert reader.sample().cgroup_throttled_periods == 9


@pytest.mark.parametrize(
    "change,reason",
    [
        ("reset", "ancestor_counter_reset"),
        ("replace", "ancestor_identity_changed"),
        ("missing_quota", "kernel_context_unavailable"),
        ("missing_counter", "kernel_context_unavailable"),
    ],
)
def test_ancestor_controls_cannot_disappear_or_reset(ancestor_kernel, change, reason):
    _, parent, _, _ = ancestor_kernel
    shared = parent.parent.parent
    with sampler(ancestor_kernel) as reader:
        reader.check_context()
        if change == "reset":
            (shared / "cpu.stat").write_text("nr_throttled 3\nthrottled_usec 500\n")
        elif change == "replace":
            shared.rename(shared.with_name("old-shared"))
            shared.mkdir()
        elif change == "missing_quota":
            (shared / "cpu.max").unlink()
        else:
            (shared / "cpu.stat").write_text("usage_usec 100\n")
        with pytest.raises(timing.CpuTimingInfrastructureError, match=reason):
            reader.check_context()


def test_ancestry_depth_is_bounded_before_opening_kernel_directories(kernel, monkeypatch):
    root, _, _, ctx = kernel

    def unexpected_open(*args, **kwargs):
        pytest.fail("unbounded ancestry must be rejected before opening directories")

    monkeypatch.setattr(timing.os, "open", unexpected_open)
    with pytest.raises(timing.CpuTimingInfrastructureError, match="invalid_cgroup_depth"):
        timing.CpuTimingSampler(ctx, root.joinpath(*("level" for _ in range(65))), cgroup_root=root)


def test_failed_ancestry_open_closes_all_pinned_descriptors(ancestor_kernel, monkeypatch):
    import os

    root, parent, _, ctx = ancestor_kernel
    original = timing.os.open
    opened = []

    def tracked_open(path, flags, *args, **kwargs):
        descriptor = original(path, flags, *args, **kwargs)
        if flags & os.O_DIRECTORY:
            opened.append(descriptor)
        return descriptor

    monkeypatch.setattr(timing.os, "open", tracked_open)
    with pytest.raises(timing.CpuTimingInfrastructureError, match="kernel_context_unavailable"):
        timing.CpuTimingSampler(ctx, parent / "absent", cgroup_root=root)
    assert len(opened) == 4
    for descriptor in opened:
        with pytest.raises(OSError):
            os.fstat(descriptor)


def test_clock_fields_remain_canonical_after_long_host_uptime():
    # 200 days exceeds canonical-safe nanoseconds; microseconds remain exact.
    offset = 200 * 86400 * 1_000_000
    value = evidence()
    body = value.model_dump(mode="json", by_alias=True)
    for name in ("started_monotonic_us", "model_started_monotonic_us", "finished_monotonic_us"):
        body[name] += offset
    for name in ("before", "after"):
        body[name]["started_us"] += offset
        body[name]["finished_us"] += offset
    shifted = timing.CpuTimingEvidence.model_validate_json(canonical_json_bytes(body))
    assert shifted.elapsed_ms == value.elapsed_ms
    assert timing.CpuTimingEvidence.model_validate_json(canonical_json_bytes(shifted)) == shifted
