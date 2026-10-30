"""Host-owned condition collection for prospective CPU timing.

Small probes run in a provisioned leaf under the existing owned slot, outside
the scored interval. Pressure is read from disjoint external cgroup subtrees;
host PSI minus model PSI is never used to invent an external signal.
"""

import asyncio
import hashlib
import os
import stat
import sys
import time
from contextlib import suppress
from pathlib import Path

from .competition_cpu_conditions import (
    CpuConditionEvidence,
    FixedCpuProbe,
    ObserverLag,
    PressureSnapshot,
)
from .competition_cpu_timing import CpuTimingInfrastructureError, parse_cpu_set
from .competition_transport_verification import TransferProgress
from .concurrency import kill_and_reap
from .protocol import canonical_json_bytes


def _fail(reason):
    raise CpuTimingInfrastructureError(reason)


def _text(path, maximum=4096):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as stream:
        value = stream.read(maximum + 1)
    if len(value) > maximum:
        _fail("cpu_condition_metadata_too_large")
    return value.decode("ascii", errors="strict").strip()


def _optional_core_property(path, *, maximum, allow_zero=False):
    try:
        value = _text(path)
    except FileNotFoundError:
        return None
    if not value.isdecimal() or not (0 if allow_zero else 1) <= int(value) <= maximum:
        _fail("cpu_condition_invalid_core_class_metadata")
    return int(value)


def slot_core_class(cpu_root, cpu_ids, *, cpuinfo=None):
    """Bind visible core type/capacity without claiming physical VM placement.

    Intel's model name/family can be identical on performance and efficiency
    cores. It therefore requires an exposed, nonzero kernel core type. Uniform
    AMD identities and ARM implementer/part identities remain usable as visible
    classes when a kernel or hypervisor does not expose capacity. Their absence
    is retained explicitly; it is never evidence of physical isolation.
    """
    if cpuinfo is None:
        cpuinfo = _text(Path("/proc/cpuinfo"), 2 * 1024**2)
    if not isinstance(cpuinfo, str) or len(cpuinfo.encode()) > 2 * 1024**2:
        _fail("cpu_condition_invalid_core_class_metadata")
    selected = set(cpu_ids)
    identities = {}
    for block in cpuinfo.strip().split("\n\n"):
        fields = dict(
            (key.strip(), value.strip())
            for line in block.splitlines()
            if ":" in line
            for key, value in (line.split(":", 1),)
        )
        identifier = fields.get("processor", "")
        if not identifier.isdecimal() or int(identifier) not in selected:
            continue
        cpu = int(identifier)
        if cpu in identities:
            _fail("cpu_condition_ambiguous_core_identity")
        flags = set(fields.get("flags", "").split()) | set(fields.get("Features", "").split())
        identity = {
            key: fields[key]
            for key in (
                "vendor_id",
                "cpu family",
                "model",
                "model name",
                "stepping",
                "CPU implementer",
                "CPU architecture",
                "CPU variant",
                "CPU part",
                "CPU revision",
            )
            if key in fields
        }
        if not identity:
            _fail("cpu_condition_missing_core_identity")
        identities[cpu] = dict(
            identity=identity,
            hybrid_reported=bool(flags & {"hybrid", "hybrid_cpu"}),
            virtualization="visible_hypervisor" if "hypervisor" in flags else "not_reported",
        )
    if not selected or set(identities) != selected:
        _fail("cpu_condition_missing_core_identity")
    visible = identities[cpu_ids[0]]
    if any(value != visible for value in identities.values()):
        _fail("cpu_condition_heterogeneous_core_identity")
    exposed = []
    for cpu in cpu_ids:
        path = Path(cpu_root) / f"cpu{cpu}"
        exposed.append(
            (
                _optional_core_property(path / "topology/core_type", maximum=255, allow_zero=True),
                _optional_core_property(path / "cpu_capacity", maximum=2**31 - 1),
            )
        )
    if any(value != exposed[0] for value in exposed):
        _fail("cpu_condition_heterogeneous_core_class")
    core_type, capacity = exposed[0]
    identity = visible["identity"]
    requires_type = identity.get("vendor_id") == "GenuineIntel" or visible["hybrid_reported"]
    if requires_type and not core_type:
        _fail("cpu_condition_hybrid_core_class_unqualified")
    if core_type:
        basis = "exposed_kernel_core_type"
    elif capacity is not None:
        basis = "exposed_kernel_cpu_capacity"
    elif identity.get("vendor_id") == "AuthenticAMD" and all(
        identity.get(key) for key in ("cpu family", "model", "model name")
    ):
        basis = "uniform_visible_amd_identity"
    elif all(identity.get(key) for key in ("CPU implementer", "CPU architecture", "CPU part")):
        basis = "uniform_visible_arm_identity"
    else:
        _fail("cpu_condition_core_class_unqualified")
    return dict(
        schema="umi-visible-core-class/1",
        basis=basis,
        core_type=core_type,
        cpu_capacity=capacity,
        physical_placement="not_established",
        **visible,
    )


def slot_topology(cpu_root, cpu_ids, expected_numa, *, cpuinfo=None):
    """Visible topology only; a VM can hide its underlying physical placement."""
    cores, packages, nodes, caches = [], [], [], []
    for cpu in cpu_ids:
        path = Path(cpu_root) / f"cpu{cpu}"
        if parse_cpu_set(_text(path / "topology/thread_siblings_list")) != (cpu,):
            _fail("cpu_condition_shared_visible_core")
        package = int(_text(path / "topology/physical_package_id"))
        core = int(_text(path / "topology/core_id"))
        membership = tuple(
            sorted(
                int(item.name[4:])
                for item in path.iterdir()
                if item.name.startswith("node") and item.name[4:].isdecimal()
            )
        )
        if membership != expected_numa or len(membership) != 1:
            _fail("cpu_condition_cpu_memory_numa_mismatch")
        cores.append((package, core))
        packages.append(package)
        nodes.append(membership)
        per_core = []
        indices = tuple((path / "cache").iterdir())
        if len(indices) > 64:
            _fail("cpu_condition_cache_topology_too_large")
        for index in sorted(indices):
            if not index.name.startswith("index"):
                continue
            shared = parse_cpu_set(_text(index / "shared_cpu_list"))
            if cpu not in shared:
                _fail("cpu_condition_cache_topology_mismatch")
            per_core.append(
                dict(
                    level=int(_text(index / "level")),
                    type=_text(index / "type"),
                    size=_text(index / "size"),
                    slot_members=tuple(
                        i for i, selected in enumerate(cpu_ids) if selected in shared
                    ),
                    total_visible_members=len(shared),
                )
            )
        if not per_core:
            _fail("cpu_condition_cache_topology_missing")
        caches.append(per_core)
    if len(set(cores)) != len(cores) or len(set(packages)) != 1:
        _fail("cpu_condition_unequal_package_topology")
    body = dict(
        # This is a prospective host-profile identity. Retained timing evidence
        # still replays its original digest; old profiles cannot silently select
        # the stronger rule without a newly qualified topology digest.
        schema="umi-visible-slot-topology/2",
        core_class=slot_core_class(cpu_root, cpu_ids, cpuinfo=cpuinfo),
        numa=nodes,
        single_package=True,
        unique_physical_cores=len(cores),
        cache_shape=caches,
    )
    return hashlib.sha256(canonical_json_bytes(body)).hexdigest()


class ObserverLagMonitor:
    def __init__(self):
        self.started_us = time.monotonic_ns() // 1000
        self.due_us = self.started_us + 50_000
        self.maximum_us = self.ticks = 0
        self.task = asyncio.create_task(self._run())

    async def _run(self):
        while True:
            await asyncio.sleep(max(0, self.due_us - time.monotonic_ns() // 1000) / 1_000_000)
            now = time.monotonic_ns() // 1000
            self.maximum_us = max(self.maximum_us, now - self.due_us)
            self.ticks += 1
            self.due_us = now + 50_000

    async def finish(self):
        now = time.monotonic_ns() // 1000
        self.maximum_us = max(self.maximum_us, now - self.due_us, 0)
        self.close()
        with suppress(asyncio.CancelledError):
            await self.task
        return ObserverLag(
            started_us=self.started_us,
            finished_us=now,
            ticks=self.ticks,
            maximum_lateness_us=self.maximum_us,
        )

    def close(self):
        self.task.cancel()


def external_pressure_scopes(root, model_parent):
    """Partition the visible cgroup tree excluding the owned model subtree."""
    root, current = Path(root), Path(model_parent)
    if not current.is_relative_to(root) or current == root:
        _fail("cpu_condition_pressure_model_path")
    found = []
    for _ in range(32):
        parent = current.parent
        entries = tuple(parent.iterdir())
        if len(entries) > 4096:
            _fail("cpu_condition_pressure_inventory_too_large")
        for entry in entries:
            info = entry.stat(follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode) and entry != current:
                found.append((str(entry), info.st_dev, info.st_ino))
        if len(found) > 256:
            _fail("cpu_condition_pressure_scope_too_large")
        if parent == root:
            return tuple(sorted(found))
        current = parent
    _fail("cpu_condition_pressure_hierarchy_too_deep")


def _pressure(path):
    rows = {}
    for line in _text(path).splitlines():
        parts = line.split()
        if parts and parts[0] in {"some", "full"}:
            fields = dict(part.split("=", 1) for part in parts[1:])
            if not fields.get("total", "").isdecimal():
                _fail("cpu_condition_invalid_pressure_counter")
            rows[parts[0]] = int(fields["total"])
    if "full" not in rows:
        _fail("cpu_condition_full_pressure_unavailable")
    return rows["full"]


class PressureReader:
    def __init__(self, root, model_parent, *, proc_root=Path("/proc")):
        self.root, self.parent, self.proc = Path(root), Path(model_parent), Path(proc_root)
        self.scopes = external_pressure_scopes(self.root, self.parent)
        self.identity = hashlib.sha256(canonical_json_bytes(self.scopes)).hexdigest()

    def sample(self):
        started = time.monotonic_ns() // 1000
        if external_pressure_scopes(self.root, self.parent) != self.scopes:
            _fail("cpu_condition_pressure_scope_changed")
        memory = io = 0
        for value, device, inode in self.scopes:
            path = Path(value)
            info = path.stat(follow_symlinks=False)
            if (info.st_dev, info.st_ino) != (device, inode):
                _fail("cpu_condition_pressure_scope_changed")
            memory += _pressure(path / "memory.pressure")
            io += _pressure(path / "io.pressure")
        events = dict(line.split() for line in _text(self.parent / "memory.events").splitlines())
        counters = dict(
            line.split() for line in _text(self.parent / "memory.stat", 32768).splitlines()
        )
        vm = dict(line.split() for line in _text(self.proc / "vmstat", 32768).splitlines())
        read_bytes = 0
        for line in _text(self.parent / "io.stat", 32768).splitlines():
            fields = dict(part.split("=", 1) for part in line.split()[1:])
            read_bytes += int(fields["rbytes"])
        values = dict(
            external_memory_full_us=memory,
            external_io_full_us=io,
            host_memory_full_us=_pressure(self.proc / "pressure/memory"),
            host_io_full_us=_pressure(self.proc / "pressure/io"),
            model_memory_full_us=_pressure(self.parent / "memory.pressure"),
            model_io_full_us=_pressure(self.parent / "io.pressure"),
            model_memory_high=int(events["high"]),
            model_memory_max=int(events["max"]),
            model_oom=int(events["oom"]),
            model_oom_kill=int(events["oom_kill"]),
            model_major_faults=int(counters["pgmajfault"]),
            model_read_bytes=read_bytes,
            host_swap_in_pages=int(vm["pswpin"]),
            host_swap_out_pages=int(vm["pswpout"]),
        )
        return PressureSnapshot(
            started_us=started,
            finished_us=time.monotonic_ns() // 1000,
            scope_identity_sha256=self.identity,
            **values,
        )


def check_probe_leaf(path, cpu_ids):
    path = Path(path)
    if path.resolve(strict=True) != path:
        _fail("cpu_condition_probe_leaf_changed")
    if (
        _text(path / "memory.max") != str(128 * 1024**2)
        or _text(path / "memory.swap.max") != "0"
        or _text(path / "pids.max") != "16"
        or _text(path / "cpu.max") != f"{len(cpu_ids) * 100000} 100000"
        or parse_cpu_set(_text(path / "cpuset.cpus.effective")) != cpu_ids
        or "populated 1" in _text(path / "cgroup.events")
    ):
        _fail("cpu_condition_probe_leaf_not_ready")


async def run_probe(session, invocation, boundary):
    path = Path(session.parent.path) / "probe"
    check_probe_leaf(path, session.slot.cpu_ids)
    process = None
    try:
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-I",
            "-B",
            "-m",
            "umi.host_cpu_probe",
            "--cgroup",
            str(path),
            "--cpus",
            session.cpu_set_argument,
            "--profile",
            session.context.profile_sha256,
            "--invocation",
            invocation,
            "--boundary",
            boundary,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )

        async def collect():
            raw = bytearray()
            while chunk := await process.stdout.read(min(4096, 65537 - len(raw))):
                raw.extend(chunk)
                if len(raw) > 65536:
                    _fail("cpu_condition_probe_output_too_large")
            if await process.wait():
                _fail("cpu_condition_probe_failed")
            return FixedCpuProbe.model_validate_json(bytes(raw))

        result = await asyncio.wait_for(collect(), 5)
        check_probe_leaf(path, session.slot.cpu_ids)
        return result
    except (asyncio.TimeoutError, OSError, ValueError) as error:
        raise CpuTimingInfrastructureError("cpu_condition_probe_unavailable") from error
    finally:
        if process is not None and process.returncode is None:
            await kill_and_reap(process)


class HostCpuConditions:
    def __init__(self, session, invocation):
        self.session, self.invocation = session, invocation
        self.pressure = PressureReader(session.root, session.parent.path)
        self.observer = None

    async def before(self):
        with TransferProgress(
            "cpu_condition_before", 1, unit="probes", planning_unit_seconds=(0.1, 5.0)
        ) as progress:
            self.before_probe = await run_probe(self.session, self.invocation, "before")
            progress.advance(1)
        self.before_pressure = self.pressure.sample()
        self.observer = ObserverLagMonitor()

    async def after(self):
        observer = await self.observer.finish()
        self.observer = None
        pressure = self.pressure.sample()
        with TransferProgress(
            "cpu_condition_after", 1, unit="probes", planning_unit_seconds=(0.1, 5.0)
        ) as progress:
            probe = await run_probe(self.session, self.invocation, "after")
            progress.advance(1)
        return CpuConditionEvidence(
            schema="umi-cpu-condition-evidence/1",
            invocation_sha256=self.invocation,
            topology_sha256=self.session.context.topology_sha256,
            before_probe=self.before_probe,
            after_probe=probe,
            observer=observer,
            before_pressure=self.before_pressure,
            after_pressure=pressure,
        )

    def close(self):
        if self.observer is not None:
            self.observer.close()
            self.observer = None
