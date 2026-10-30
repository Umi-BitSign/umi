"""Prospective CPU slot readiness over existing shared model-memory leases.

Installation controls provision persistent delegated cgroupfs parents and an
exclusive load-balanced cpuset partition. Loading this profile never changes a service or
kernel limit. C7 and older callers without a native efficiency capability never
activate this path. A qualification receipt is not a substitute for readback.
"""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .competition_cpu_conditions import PRESSURE_RULE, PROBE_RULE, CpuConditionLimits
from .competition_cpu_timing import (
    CpuTimingContext,
    CpuTimingInfrastructureError,
    CpuTimingSampler,
    cpu_timing_limits_v1,
    finish_cpu_timing,
    hardware_fingerprints,
    parse_cpu_set,
    validate_runtime_resources,
)
from .host_cpu_cgroupfs import podman_parent_argument, timed_podman_prefix
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


class CpuTimingHostSelection(StrictProtocolModel):
    profile_path: str
    profile_sha256: Hex32


class CpuTimingKernelDirectory(StrictProtocolModel):
    path: str


class CpuTimingParent(CpuTimingKernelDirectory):
    uid: Annotated[int, Field(ge=0, strict=True)]


class CpuTimingHostSlot(StrictProtocolModel):
    lock_name: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.-]{1,128}$")]
    lock_device: Annotated[int, Field(ge=0, strict=True)]
    lock_inode: Annotated[int, Field(gt=0, strict=True)]
    cpu_ids: Annotated[tuple[int, ...], Field(min_length=1, max_length=8)]
    parents: Annotated[tuple[CpuTimingParent, ...], Field(min_length=1, max_length=64)]


class CpuTimingHostProfile(StrictProtocolModel):
    schema_: Literal["umi-host-cpu-timing-profile/1"] = Field(alias="schema")
    host_identity_sha256: Hex32
    protocol_policy_sha256: Hex32
    runtime_sha256: Hex32
    hardware_sha256: Hex32
    cpu_class_sha256: Hex32
    qualification_sha256: Hex32
    topology_sha256: Hex32
    partition_mode: Literal["root"] = "root"
    partition: CpuTimingKernelDirectory
    reserved_cpu_ids: Annotated[tuple[int, ...], Field(min_length=1, max_length=256)]
    background_cpu_ids: Annotated[tuple[int, ...], Field(min_length=1, max_length=8192)]
    numa_node_ids: Annotated[tuple[int, ...], Field(min_length=1, max_length=64)]
    governor: Annotated[str, Field(min_length=1, max_length=128)] | None
    frequency_class: Literal["observable_governor", "virtual_frequency_unexposed"]
    slots: Annotated[tuple[CpuTimingHostSlot, ...], Field(min_length=1, max_length=32)]

    @model_validator(mode="after")
    def disjoint_resources(self):
        if (
            self.reserved_cpu_ids != tuple(sorted(set(self.reserved_cpu_ids)))
            or (self.background_cpu_ids != tuple(sorted(set(self.background_cpu_ids))))
            or set(self.reserved_cpu_ids) & set(self.background_cpu_ids)
        ):
            raise ValueError("CPU timing partition and background sets must be distinct")
        occupied = [cpu for slot in self.slots for cpu in slot.cpu_ids]
        if len(set(occupied)) != len(occupied) or set(occupied) != set(self.reserved_cpu_ids):
            raise ValueError("CPU timing slots must exactly partition the reserved cores")
        if len({slot.lock_name for slot in self.slots}) != len(self.slots):
            raise ValueError("CPU timing cannot repeat an existing slot lock")
        if (self.frequency_class == "observable_governor") != (self.governor is not None):
            raise ValueError("CPU timing frequency qualification must be explicit")
        for slot in self.slots:
            if slot.cpu_ids != tuple(sorted(set(slot.cpu_ids))) or len(
                {parent.uid for parent in slot.parents}
            ) != len(slot.parents):
                raise ValueError("CPU timing slot has ambiguous cores or service accounts")
            for parent in slot.parents:
                if not Path(parent.path).is_relative_to(self.partition.path):
                    raise ValueError("CPU timing parent is outside its exclusive partition")
        return self


def _error(reason):
    raise CpuTimingInfrastructureError(reason)


def _text(path, limit=4096):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        _error("cpu_timing_profile_metadata_too_large")
    return raw.decode("ascii", errors="strict").strip()


def _directory(binding, root, identities):
    path = Path(binding.path)
    if not path.is_absolute() or not path.is_relative_to(root) or path.resolve(strict=True) != path:
        _error("cpu_timing_profile_kernel_path_changed")
    observed = path.stat(follow_symlinks=False)
    identity = observed.st_dev, observed.st_ino
    if not stat.S_ISDIR(observed.st_mode) or identities.setdefault(str(path), identity) != identity:
        _error("cpu_timing_profile_kernel_identity_changed")
    return path


def measurement_profile_sha256(profile, runtime):
    """Stable measurement meaning, independent of a kernel object's lifetime.

    The installation file has a separate exact digest. Its selected paths and
    shared lease files do not change the meaning of a completed measurement.
    Kernel identities are captured afresh and held through each invocation.
    """
    return hashlib.sha256(
        canonical_json_bytes(
            {
                "schema": "umi-cpu-measurement-profile/2",
                "measurement_semantics": "umi-exclusive-cold-model-cpu-timing/1",
                "ancestor_quota_rule": "unlimited_shared_ancestors_no_throttle_delta/1",
                "timing_rule": "cold_model_exec_to_validated_result/1",
                "partition_mode": "root",
                "bundle_cache_rule": "verified_bundle_pagecache_eviction/1",
                "topology_sha256": profile.topology_sha256,
                "probe_rule": PROBE_RULE,
                "pressure_rule": PRESSURE_RULE,
                "condition_limits": CpuConditionLimits().model_dump(mode="json"),
                "host_identity_sha256": profile.host_identity_sha256,
                "runtime_sha256": profile.runtime_sha256,
                "hardware_sha256": profile.hardware_sha256,
                "cpu_class_sha256": profile.cpu_class_sha256,
                "cpu_count": runtime.cpus,
                "cpu_quota_usec": runtime.cpus * 100_000,
                "cpu_period_usec": 100_000,
                "memory_max_bytes": runtime.memory_bytes,
                "memory_swap_max_bytes": 0,
                "numa_node_ids": profile.numa_node_ids,
                "governor": profile.governor,
                "frequency_class": profile.frequency_class,
                "limits": cpu_timing_limits_v1().model_dump(mode="json", by_alias=True),
            }
        )
    ).hexdigest()


def load_cpu_timing_profile(selection, controller):
    """Read the selected small root-owned profile once at service construction."""
    if selection is None:
        return None
    path = Path(selection.profile_path)
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != 0
                or info.st_mode & 0o022
                or (info.st_nlink != 1 or info.st_size > 128 * 1024)
            ):
                _error("cpu_timing_profile_not_protected")
            raw = stream.read(128 * 1024 + 1)
        if hashlib.sha256(raw).hexdigest() != selection.profile_sha256:
            _error("cpu_timing_profile_identity_changed")
        profile = CpuTimingHostProfile.model_validate_json(raw)
        policy = controller.policy
        if (profile.host_identity_sha256, profile.protocol_policy_sha256) != (
            policy.host_identity_sha256,
            policy.protocol_policy_sha256,
        ):
            _error("cpu_timing_profile_host_or_policy_mismatch")
        expected = {(s.name, s.device, s.inode) for s in policy.slots if s.lane == "transient"}
        if not {(s.lock_name, s.lock_device, s.lock_inode) for s in profile.slots}.issubset(
            expected
        ):
            _error("cpu_timing_profile_existing_locks_mismatch")
        if set(policy.container_cgroupfs_roots) != {
            parent.path for slot in profile.slots for parent in slot.parents
        }:
            _error("cpu_timing_profile_container_roots_mismatch")
        return profile
    except CpuTimingInfrastructureError:
        raise
    except (OSError, ValueError, TypeError) as error:
        raise CpuTimingInfrastructureError("cpu_timing_profile_unavailable") from error


class CpuTimingSession:
    """One CPU measurement using a caller-owned existing memory slot lease."""

    def __init__(
        self,
        profile,
        profile_sha256,
        controller,
        lease,
        runtime,
        authorization,
        *,
        cgroup_root=Path("/sys/fs/cgroup"),
        cpu_root=Path("/sys/devices/system/cpu"),
        cpuinfo_path=Path("/proc/cpuinfo"),
        proc_stat_path=Path("/proc/stat"),
    ):
        self.profile, self.lease = profile, lease
        self.root, self.cpu_root = Path(cgroup_root), Path(cpu_root)
        self.controller = controller
        self.runtime = runtime
        self.installation_profile_sha256 = profile_sha256
        self.contract_sha256 = authorization.adoption_sha256
        self._sampler = None
        self._conditions = self._condition_evidence = None
        self._kernel_identities = {}
        if (
            profile is None
            or runtime is None
            or authorization.runtime_sha256 != profile.runtime_sha256
        ):
            _error("cpu_timing_profile_missing_or_runtime_mismatch")
        self.slot = next(
            (
                slot
                for slot in profile.slots
                if (slot.lock_name, slot.lock_device, slot.lock_inode)
                == (lease.slot.name, lease.slot.device, lease.slot.inode)
            ),
            None,
        )
        if self.slot is None:
            _error("cpu_timing_unselected_slot")
        self.parent = next(
            (parent for parent in self.slot.parents if parent.uid == os.geteuid()), None
        )
        if self.parent is None:
            _error("cpu_timing_service_account_unqualified")
        try:
            self.check_ready()
            from .host_cpu_conditions import slot_topology

            cpuinfo_raw = _text(cpuinfo_path, 2 * 1024**2)
            hardware, cpu_class = hardware_fingerprints(cpuinfo_raw, self.slot.cpu_ids)
            if (hardware, cpu_class) != (profile.hardware_sha256, profile.cpu_class_sha256):
                _error("cpu_timing_profile_hardware_changed")
            if (
                slot_topology(
                    self.cpu_root, self.slot.cpu_ids, profile.numa_node_ids, cpuinfo=cpuinfo_raw
                )
                != profile.topology_sha256
            ):
                _error("cpu_timing_visible_topology_changed")
            self.context = CpuTimingContext(
                profile_sha256=measurement_profile_sha256(profile, runtime),
                hardware_sha256=hardware,
                cpu_class_sha256=cpu_class,
                topology_sha256=profile.topology_sha256,
                cpu_ids=self.slot.cpu_ids,
                cpu_quota_usec=runtime.cpus * 100_000,
                cpu_period_usec=100_000,
                memory_max_bytes=runtime.memory_bytes,
                memory_swap_max_bytes=0,
                cgroup_device=self._kernel_identities[self.parent.path][0],
                cgroup_inode=self._kernel_identities[self.parent.path][1],
                clock_ticks_per_second=os.sysconf("SC_CLK_TCK"),
            )
            validate_runtime_resources(
                self.context, cpus=runtime.cpus, memory_bytes=runtime.memory_bytes
            )
            self._sampler = CpuTimingSampler(
                self.context,
                self.parent.path,
                cgroup_root=self.root,
                cpuinfo_path=cpuinfo_path,
                proc_stat_path=proc_stat_path,
            )
            self._sampler.check_context()
        except CpuTimingInfrastructureError:
            self.close()
            raise
        except (OSError, ValueError, TypeError, AttributeError) as error:
            self.close()
            raise CpuTimingInfrastructureError("cpu_timing_host_not_ready") from error

    @property
    def podman_parent(self):
        return podman_parent_argument(self.parent.path, cgroup_root=self.root)

    @property
    def podman_prefix(self):
        return timed_podman_prefix()

    @property
    def owned_parent(self):
        return self.parent.path

    @property
    def cpu_set_argument(self):
        return ",".join(str(cpu) for cpu in self.slot.cpu_ids)

    def check_ready(self):
        lease = self.lease
        if (
            lease.closed
            or lease._creator_pid != os.getpid()
            or lease not in self.controller._model_leases
        ):
            _error("cpu_timing_existing_slot_lease_released")
        lock = os.fstat(lease._descriptor)
        if (lock.st_dev, lock.st_ino) != (self.slot.lock_device, self.slot.lock_inode):
            _error("cpu_timing_existing_slot_lock_changed")
        partition = _directory(self.profile.partition, self.root, self._kernel_identities)
        parent = _directory(self.parent, self.root, self._kernel_identities)
        if (
            _text(partition / "cpuset.cpus.partition") != "root"
            or parse_cpu_set(_text(partition / "cpuset.cpus.exclusive.effective"))
            != self.profile.reserved_cpu_ids
            or parse_cpu_set(_text(partition / "cpuset.cpus.effective"))
            != self.profile.reserved_cpu_ids
        ):
            _error("cpu_timing_exclusive_partition_not_active")
        if parse_cpu_set(_text(parent / "cpuset.mems.effective")) != self.profile.numa_node_ids:
            _error("cpu_timing_numa_profile_changed")
        for cpu in self.slot.cpu_ids:
            location = self.cpu_root / f"cpu{cpu}"
            if parse_cpu_set(_text(location / "topology/thread_siblings_list")) != (cpu,):
                _error("cpu_timing_shared_smt_core_unqualified")
            governor = location / "cpufreq/scaling_governor"
            if self.profile.frequency_class == "observable_governor":
                if _text(governor) != self.profile.governor:
                    _error("cpu_timing_governor_changed")
            elif governor.exists():
                _error("cpu_timing_frequency_class_changed")
        if parse_cpu_set(_text(self.cpu_root / "online")) != tuple(
            sorted((*self.profile.reserved_cpu_ids, *self.profile.background_cpu_ids))
        ):
            _error("cpu_timing_online_cpu_partition_changed")

    def verify_container(self, path):
        """The host opens its launch gate only after actual kernel readback."""
        self.check_ready()
        path = Path(path)
        parent = Path(self.parent.path)
        import re

        if path.parent != parent or re.fullmatch(r"libpod-[0-9a-f]{64}", path.name) is None:
            _error("cpu_timing_container_outside_owned_parent")
        info = path.stat(follow_symlinks=False)
        context = self.context.model_copy(
            update={"cgroup_device": info.st_dev, "cgroup_inode": info.st_ino}
        )
        with CpuTimingSampler(context, path, cgroup_root=self.root, owned_parent=parent) as sampler:
            sampler.check_context()

    async def prepare_conditions(self, invocation_sha256):
        from .host_cpu_conditions import HostCpuConditions

        if self._conditions is not None:
            _error("cpu_condition_duplicate_preparation")
        try:
            self._conditions = HostCpuConditions(self, invocation_sha256)
            await self._conditions.before()
        except CpuTimingInfrastructureError:
            raise
        except (OSError, ValueError, KeyError) as error:
            raise CpuTimingInfrastructureError("cpu_condition_preparation_unavailable") from error

    async def finish_conditions(self):
        if self._conditions is None or self._condition_evidence is not None:
            _error("cpu_condition_invalid_finish")
        try:
            self._condition_evidence = await self._conditions.after()
        except CpuTimingInfrastructureError:
            raise
        except (OSError, ValueError, KeyError) as error:
            raise CpuTimingInfrastructureError("cpu_condition_completion_unavailable") from error

    def sample(self):
        self.check_ready()
        return self._sampler.sample()

    def finish(
        self,
        *,
        before,
        after,
        started_monotonic_us,
        finished_monotonic_us,
        launch_gate_elapsed_us,
        model_started_monotonic_us,
        bundle_cache=None,
    ):
        self.check_ready()
        if self._condition_evidence is None:
            _error("cpu_condition_missing_evidence")
        if not 0 < launch_gate_elapsed_us <= 5_000_000:
            _error("cpu_timing_launch_gate_delay")
        return finish_cpu_timing(
            contract_sha256=self.contract_sha256,
            context=self.context,
            before=before,
            after=after,
            started_monotonic_us=started_monotonic_us,
            finished_monotonic_us=finished_monotonic_us,
            model_started_monotonic_us=model_started_monotonic_us,
            launch_gate_elapsed_us=launch_gate_elapsed_us,
            limits=cpu_timing_limits_v1(),
            conditions=self._condition_evidence,
            bundle_cache=bundle_cache,
        )

    def close(self):
        if self._conditions is not None:
            self._conditions.close()
        if self._sampler is not None:
            self._sampler.close()
            self._sampler = None
