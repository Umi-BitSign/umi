"""Root-provisioned shared capacity slots, held for explicit object lifetimes.

This primitive does not select capacity or infer when a returned graph dies.
Every installed consumer must acquire the appropriate lane before allocation,
retain its lease through all owned work and objects, and use a qualified policy.
Owner exports have independent slots: reviewers may hold transient slots while
waiting for an export, so combining those two lanes would deadlock.
"""

from __future__ import annotations

import asyncio
import fcntl
import hashlib
import json
import os
import re
import stat
import weakref
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .protocol import StrictProtocolModel

Lane = Literal["owner_export", "transient", "settlement_retained"]
MINIMUM_AVAILABLE_BYTES = 24 * 1024**3
_MAX_POLICY_BYTES = 64 * 1024
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


class AdmissionBindingError(ValueError):
    """The selected immutable host capacity namespace no longer matches."""


class HostMemoryFile(StrictProtocolModel):
    name: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_-]{0,63}\.slot$")]
    device: Annotated[int, Field(ge=0, strict=True)]
    inode: Annotated[int, Field(gt=0, strict=True)]


class HostMemorySlot(HostMemoryFile):
    lane: Lane
    reservation_bytes: Annotated[int, Field(gt=0, strict=True)]
    settlement_role: Literal["coordinator", "reviewer"] | None = None


class HostSettlementSignal(HostMemoryFile):
    cohort_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class HostMemoryAdmissionPolicy(StrictProtocolModel):
    schema_: Literal["umi-host-memory-admission/2"] = Field(alias="schema")
    host_identity_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    directory: str
    directory_device: Annotated[int, Field(ge=0, strict=True)]
    directory_inode: Annotated[int, Field(gt=0, strict=True)]
    group_id: Annotated[int, Field(gt=0, strict=True)]
    minimum_available_bytes: Annotated[int, Field(ge=MINIMUM_AVAILABLE_BYTES, strict=True)]
    incremental_budget_bytes: Annotated[int, Field(gt=0, strict=True)]
    background_reservation_bytes: Annotated[int, Field(ge=0, strict=True)]
    maximum_aggregate_bytes: Annotated[int, Field(ge=1024, strict=True)]
    qualification_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    slots: Annotated[tuple[HostMemorySlot, ...], Field(min_length=4, max_length=64)]
    transaction_lock: HostMemoryFile
    settlement_gate: HostMemoryFile
    settlement_signals: Annotated[
        tuple[HostSettlementSignal, ...], Field(min_length=1, max_length=64)
    ]

    @model_validator(mode="after")
    def bindings(self):
        _absolute(self.directory)
        if {slot.lane for slot in self.slots} != {
            "owner_export",
            "transient",
            "settlement_retained",
        }:
            raise ValueError("host admission requires separately reserved lanes")
        files = (*self.slots, self.transaction_lock, self.settlement_gate, *self.settlement_signals)
        if len({slot.name for slot in files}) != len(files) or len(
            {(slot.device, slot.inode) for slot in files}
        ) != len(files):
            raise ValueError("host admission slots must have distinct names and inodes")
        retained = [slot for slot in self.slots if slot.lane == "settlement_retained"]
        if len(retained) != 2 or {s.settlement_role for s in retained} != {
            "coordinator",
            "reviewer",
        }:
            raise ValueError("settlement admission requires both independently reserved replicas")
        if any(
            s.settlement_role is not None for s in self.slots if s.lane != "settlement_retained"
        ):
            raise ValueError("only retained settlement slots select a replica")
        if len({s.cohort_sha256 for s in self.settlement_signals}) != len(self.settlement_signals):
            raise ValueError("settlement admission repeats a cohort signal")
        for lane in {slot.lane for slot in self.slots}:
            if len({slot.reservation_bytes for slot in self.slots if slot.lane == lane}) != 1:
                raise ValueError("each admission lane needs one measured per-slot reservation")
        if self.reserved_bytes > self.incremental_budget_bytes:
            raise ValueError("host admission reservations exceed qualified incremental budget")
        return self

    @property
    def reserved_bytes(self) -> int:
        return sum(slot.reservation_bytes for slot in self.slots)


def _root_uid() -> int:
    return 0


def _absolute(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute() or str(path) != value or ".." in path.parts or "\0" in value:
        raise AdmissionBindingError("host admission requires a canonical absolute path")
    return path


def _directory(descriptor: int) -> os.stat_result:
    details = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(details.st_mode)
        or details.st_uid not in {0, _root_uid()}
        or details.st_mode & 0o022
    ):
        raise AdmissionBindingError("host admission path must be root owned and immutable")
    return details


def _open_directory(path: Path) -> int:
    descriptor = os.open("/", _DIRECTORY_FLAGS)
    try:
        _directory(descriptor)
        for part in path.parts[1:]:
            child = os.open(part, _DIRECTORY_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            _directory(descriptor)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _regular(descriptor: int, group_id: int | None = None) -> os.stat_result:
    details = os.fstat(descriptor)
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_uid != _root_uid()
        or (group_id is not None and details.st_gid != group_id)
        or stat.S_IMODE(details.st_mode) not in {0o400, 0o440}
        or details.st_nlink != 1
    ):
        raise AdmissionBindingError("host admission file must be an immutable root-owned file")
    return details


def _host_identity(path: Path = Path("/etc/machine-id")) -> str:
    path = _absolute(str(path))
    parent = _open_directory(path.parent)
    descriptor = None
    try:
        descriptor = os.open(path.name, _FILE_FLAGS, dir_fd=parent)
        details = os.fstat(descriptor)
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_uid != 0
            or details.st_mode & 0o022
            or not 0 < details.st_size <= 128
        ):
            raise AdmissionBindingError("host identity must be a root-owned machine identity")
        value = os.read(descriptor, 129).strip()
        if len(value) != 32 or any(c not in b"0123456789abcdef" for c in value):
            raise AdmissionBindingError("host machine identity is invalid")
        return hashlib.sha256(value).hexdigest()
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)


def _available_memory() -> int:
    for line in Path("/proc/meminfo").read_text(encoding="ascii").splitlines():
        if line.startswith("MemAvailable:"):
            fields = line.split()
            if len(fields) == 3 and fields[2] == "kB":
                return int(fields[1]) * 1024
    raise AdmissionBindingError("host available memory could not be measured")


def _open_cgroup_directory(path: Path) -> int:
    """Open an actual directory through no-link components, including its roots."""
    descriptor = os.open("/", _DIRECTORY_FLAGS)
    try:
        for part in _absolute(str(path)).parts[1:]:
            child = os.open(part, _DIRECTORY_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _require_cgroup2(descriptor: int) -> None:
    # Kernel mount metadata supplies the filesystem type without an FFI ABI or
    # trusting similarly named files in an ordinary userspace directory.
    with Path("/proc/self/mountinfo").open("rb") as stream:
        raw = stream.read(1024**2 + 1)
    if len(raw) > 1024**2:
        raise AdmissionBindingError("kernel mount inventory exceeds its bound")
    device = os.fstat(descriptor).st_dev
    for line in raw.splitlines():
        sides = line.split(b" - ", 1)
        if len(sides) != 2:
            continue
        fields, filesystem = sides[0].split(), sides[1].split()
        if len(fields) < 5 or not filesystem:
            continue
        if fields[4] == b"/sys/fs/cgroup" and filesystem[0] == b"cgroup2":
            major, minor = (int(value) for value in fields[2].split(b":"))
            if device == os.makedev(major, minor):
                return
    raise AdmissionBindingError("model container must use the selected kernel cgroup2 filesystem")


def _cgroup_value(descriptor: int, name: str) -> str:
    child = os.open(name, _FILE_FLAGS, dir_fd=descriptor)
    try:
        raw = os.read(child, 4097)
        if not stat.S_ISREG(os.fstat(child).st_mode) or len(raw) > 4096:
            raise AdmissionBindingError("native cgroup metadata exceeds its bound")
        return raw.decode("ascii").strip()
    finally:
        os.close(child)


def _read_policy(path: Path) -> bytes:
    parent = _open_directory(path.parent)
    descriptor = None
    try:
        descriptor = os.open(path.name, _FILE_FLAGS, dir_fd=parent)
        before = _regular(descriptor)
        if not 0 < before.st_size <= _MAX_POLICY_BYTES:
            raise AdmissionBindingError("host admission policy exceeds its byte bound")
        data = os.read(descriptor, _MAX_POLICY_BYTES + 1)
        after = os.fstat(descriptor)

        def fingerprint(value):
            return (
                value.st_dev,
                value.st_ino,
                value.st_mode,
                value.st_uid,
                value.st_gid,
                value.st_nlink,
                value.st_size,
                value.st_mtime_ns,
                value.st_ctime_ns,
            )

        if len(data) != before.st_size or fingerprint(after) != fingerprint(before):
            raise AdmissionBindingError("host admission policy changed during read")
        return data
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)


class HostMemoryLease:
    """An explicit ownership token; close only after its protected objects die.

    Close the descriptor, never LOCK_UN: forked descendants sharing the open
    file description must keep capacity reserved until they also close it.
    O_CLOEXEC prevents accidental inheritance by unrelated executable children.
    """

    def __init__(self, descriptor: int, slot: HostMemorySlot, *, group=()):
        self._descriptor: int | None = descriptor
        self._group: tuple[int, ...] = tuple(group)
        self.slot = slot
        self._creator_pid = os.getpid()
        self._generation = object()
        self._model_container = None

    @property
    def closed(self) -> bool:
        return self._descriptor is None

    def close(self) -> None:
        self.clear_model_container()
        descriptor, self._descriptor = self._descriptor, None
        if descriptor is not None:
            os.close(descriptor)
        group, self._group = self._group, ()
        for descriptor in group:
            os.close(descriptor)

    def clear_model_container(self) -> None:
        binding, self._model_container = self._model_container, None
        if binding is not None:
            os.close(binding[2])

    def __del__(self):
        self.close()


class HostMemoryAdmission:
    """No files are created, no limits inferred, and no lease is reentrant.

    The root selection binds policy bytes and every slot inode. Installers must
    compare these bindings from each actual service namespace, including the
    sole writer; this class cannot prove another process sees the same files.
    """

    def __init__(
        self,
        policy_path: Path,
        *,
        expected_sha256: str,
        host_identity_path: Path = Path("/etc/machine-id"),
    ):
        raw = _read_policy(_absolute(str(policy_path)))
        if hashlib.sha256(raw).hexdigest() != expected_sha256:
            raise AdmissionBindingError("host admission policy differs from selection")
        schema = json.loads(raw).get("schema")
        if schema == "umi-c5-requests-memory-admission/1":
            from .host_memory_requests import RequestsStageMemoryPolicy

            self.policy = RequestsStageMemoryPolicy.model_validate_json(raw)
        elif schema == "umi-host-model-execution-admission/1":
            from .host_model_execution import ModelExecutionMemoryPolicy

            self.policy = ModelExecutionMemoryPolicy.model_validate_json(raw)
        else:
            self.policy = HostMemoryAdmissionPolicy.model_validate_json(raw)
        self.policy_sha256 = expected_sha256
        self._model_leases = weakref.WeakSet()
        self.last_model_admission = None
        if self.policy.host_identity_sha256 != _host_identity(host_identity_path):
            raise AdmissionBindingError("host admission policy belongs to another host")
        self._validate_all()
        # Startup and every later grant remeasure current memory. Idle Python
        # heaps remain in MemAvailable accounting after logical leases close.
        if not self.model_execution_stage and (
            _available_memory()
            < self.policy.minimum_available_bytes
            + self.policy.reserved_bytes
            + self.policy.background_reservation_bytes
        ):
            raise OSError("host memory admission startup awaits qualified headroom")

    @property
    def model_execution_stage(self) -> bool:
        return self.policy.schema_ == "umi-host-model-execution-admission/1"

    @property
    def requests_stage(self) -> bool:
        return self.policy.schema_ == "umi-c5-requests-memory-admission/1"

    def authorize(self, operation=None, cohort=None, phase=None, *, lane=None):
        if not self.requests_stage:
            return
        from .host_memory_requests import OPERATIONS

        if (
            operation not in self.policy.operations
            or cohort != self.policy.cohort_sha256
            or OPERATIONS.get(operation) != (lane, phase)
        ):
            raise AdmissionBindingError("operation is outside the qualified C5 requests stage")

    def bind_runtime(self, role, protocol_policy, series, authority):
        if self.requests_stage and (
            role not in {"intake", "phase_reviewer"}
            or protocol_policy != self.policy.protocol_policy_sha256
            or series != self.policy.series_sha256
            or authority != self.policy.authority_sha256
        ):
            raise AdmissionBindingError("runtime identity is outside the qualified requests stage")

    def _open_root(self) -> int:
        descriptor = _open_directory(_absolute(self.policy.directory))
        try:
            details = _directory(descriptor)
            if (
                (details.st_dev, details.st_ino)
                != (self.policy.directory_device, self.policy.directory_inode)
                or details.st_uid != _root_uid()
                or details.st_gid != self.policy.group_id
                or stat.S_IMODE(details.st_mode) != 0o750
            ):
                raise AdmissionBindingError("host admission directory differs from selection")
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def _open_slot(self, parent: int, slot: HostMemoryFile) -> int:
        descriptor = os.open(slot.name, _FILE_FLAGS, dir_fd=parent)
        try:
            details = _regular(descriptor, self.policy.group_id)
            if (details.st_dev, details.st_ino) != (slot.device, slot.inode) or details.st_size:
                raise AdmissionBindingError("host admission slot differs from selection")
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def _validate_all(self) -> None:
        parent = self._open_root()
        try:
            files = (*self.policy.slots, self.policy.transaction_lock)
            if not self.requests_stage and not self.model_execution_stage:
                files += (self.policy.settlement_gate, *self.policy.settlement_signals)
            for slot in files:
                os.close(self._open_slot(parent, slot))
        finally:
            os.close(parent)

    def _transaction(self, parent: int) -> int | None:
        descriptor = self._open_slot(parent, self.policy.transaction_lock)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return descriptor
        except BlockingIOError:
            os.close(descriptor)
            return None
        except BaseException:
            os.close(descriptor)
            raise

    def _reserve(self, parent: int, selected: HostMemorySlot) -> HostMemoryLease | None:
        descriptor = self._open_slot(parent, selected)
        try:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return None
            # Busy operations may not have allocated yet. Charge their full
            # reservation in addition to current RSS rather than racing grants
            # against a stale memory sample. Measurements must qualify this
            # conservative admission envelope, including downstream owner work.
            pending = selected.reservation_bytes
            busy = set()
            for slot in self.policy.slots:
                if slot.name == selected.name:
                    continue
                other = self._open_slot(parent, slot)
                try:
                    try:
                        fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError:
                        pending += slot.reservation_bytes
                        busy.add((slot.device, slot.inode))
                finally:
                    os.close(other)
            containers = self._model_container_reservations(busy)
            available = _available_memory()
            required = (
                self.policy.minimum_available_bytes
                + pending
                + self.policy.background_reservation_bytes
                + containers
            )
            if self.model_execution_stage:
                self.last_model_admission.update(
                    available_bytes=available,
                    required_available_bytes=required,
                    pending_reservation_bytes=pending,
                    minimum_available_bytes=self.policy.minimum_available_bytes,
                    background_reservation_bytes=self.policy.background_reservation_bytes,
                    shortfall_bytes=max(0, required - available),
                )
            if available < required:
                return None
            lease = HostMemoryLease(descriptor, selected)
            if self.model_execution_stage:
                self._model_leases.add(lease)
            descriptor = None
            return lease
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def bind_model_container(self, lease, container_id: str, path: Path) -> bool:
        """Bind only the trusted runner's exact CID to this live acquisition.

        The runner first authenticates its own full container ID and name.
        No ownership is inferred from a process ID, service account or RSS.
        """
        path = _absolute(str(path))
        if (
            not self.model_execution_stage
            or lease not in self._model_leases
            or lease.closed
            or lease._creator_pid != os.getpid()
            or lease.slot.lane != "transient"
            or type(container_id) is not str
            or re.fullmatch(r"[0-9a-f]{64}", container_id) is None
            or not (
                (
                    path.name == "container"
                    and path.parent.name == "libpod-" + container_id + ".scope"
                    and str(path.parent.parent) in self.policy.container_cgroup_roots
                )
                or (
                    path.name == "libpod-" + container_id
                    and str(path.parent) in self.policy.container_cgroupfs_roots
                )
            )
        ):
            raise AdmissionBindingError("container binding differs from its live model acquisition")
        descriptor = None
        try:
            descriptor = _open_cgroup_directory(path)
            _require_cgroup2(descriptor)
            events = dict(
                line.split() for line in _cgroup_value(descriptor, "cgroup.events").splitlines()
            )
            if events.get("populated") != "1":
                return False
            limit = _cgroup_value(descriptor, "memory.max")
            if not limit.isdecimal() or not 0 < int(limit) <= 1024**4:
                raise AdmissionBindingError("native container has no bounded memory ceiling")
            details = os.fstat(descriptor)
            identity = (details.st_dev, details.st_ino)
            existing = lease._model_container
            if existing is not None:
                if existing[:2] != (str(path), identity):
                    raise AdmissionBindingError(
                        "one model acquisition cannot cover another container"
                    )
                return True
            if any(
                other is not lease
                and not other.closed
                and other._creator_pid == os.getpid()
                and other._model_container is not None
                and other._model_container[1] == identity
                for other in tuple(self._model_leases)
            ):
                raise AdmissionBindingError(
                    "container already belongs to another model acquisition"
                )
            lease._model_container = (str(path), identity, descriptor, lease._generation)
            descriptor = None
            return True
        except FileNotFoundError:
            return False
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def _model_container_reservations(self, busy=()) -> int:
        """Charge every ceiling; credit only a live local lease already counted.

        Bindings disappear with their process and acquisition. Other processes,
        old acquisitions and orphaned containers therefore remain fully charged.
        A pending lease is never credited before its exact native binding exists.
        """
        if not self.model_execution_stage:
            return 0
        total = credit_total = count = 0
        credited = set()
        layouts = [(path, "systemd") for path in self.policy.container_cgroup_roots]
        layouts += [(path, "cgroupfs") for path in self.policy.container_cgroupfs_roots]
        for value, manager in layouts:
            root = Path(value)
            try:
                entries = tuple(root.iterdir())
            except FileNotFoundError:
                continue
            if len(entries) > 4096:
                raise AdmissionBindingError("native container inventory exceeds its bounded root")
            for entry in entries:
                pattern = (
                    r"libpod-[0-9a-f]{64}\.scope"
                    if manager == "systemd"
                    else r"libpod-[0-9a-f]{64}"
                )
                if re.fullmatch(pattern, entry.name) is None:
                    continue
                target = entry / "container" if manager == "systemd" else entry
                try:
                    descriptor = _open_cgroup_directory(target)
                    try:
                        _require_cgroup2(descriptor)
                        events = dict(
                            line.split()
                            for line in _cgroup_value(descriptor, "cgroup.events").splitlines()
                        )
                        if events.get("populated") != "1":
                            continue
                        limit = _cgroup_value(descriptor, "memory.max")
                        if not limit.isdecimal() or not 0 < int(limit) <= 1024**4:
                            raise AdmissionBindingError(
                                "native container has no bounded memory ceiling"
                            )
                        ceiling, credit = int(limit), 0
                        details = os.fstat(descriptor)
                        identity = (details.st_dev, details.st_ino)
                        for lease in tuple(self._model_leases):
                            binding = lease._model_container
                            if (
                                lease not in credited
                                and not lease.closed
                                and lease._creator_pid == os.getpid()
                                and (lease.slot.device, lease.slot.inode) in busy
                                and binding is not None
                                and binding[:2] == (str(target), identity)
                                and binding[3] is lease._generation
                            ):
                                lease_descriptor = lease._descriptor
                                try:
                                    held = os.fstat(binding[2])
                                    slot = os.fstat(lease_descriptor)
                                except (OSError, TypeError):
                                    # Cleanup may invalidate a copied witness.
                                    # Uncertain ownership receives no credit.
                                    continue
                                if (
                                    (held.st_dev, held.st_ino) == identity
                                    and (slot.st_dev, slot.st_ino)
                                    == (lease.slot.device, lease.slot.inode)
                                    and lease._descriptor == lease_descriptor
                                    and lease._model_container is binding
                                    and binding[3] is lease._generation
                                ):
                                    credit = min(ceiling, lease.slot.reservation_bytes)
                                    credited.add(lease)
                                    break
                        total += ceiling - credit
                        credit_total += credit
                        count += 1
                    finally:
                        os.close(descriptor)
                except FileNotFoundError:
                    # A deleted scope cannot allocate another native byte.
                    continue
        self.last_model_admission = dict(
            populated_containers=count,
            container_ceiling_bytes=total + credit_total,
            owned_container_credit_bytes=credit_total,
            unreserved_container_bytes=total,
        )
        return total

    def try_acquire(
        self, lane: Lane, *, operation=None, cohort=None, phase=None
    ) -> HostMemoryLease | None:
        self.authorize(operation, cohort, phase, lane=lane)
        if lane not in {"owner_export", "transient"}:
            raise ValueError("retained settlement requires role/cohort admission")
        parent = self._open_root()
        transaction = None
        try:
            transaction = self._transaction(parent)
            if transaction is None:
                return None
            for slot in self.policy.slots:
                if slot.lane == lane:
                    lease = self._reserve(parent, slot)
                    if lease is not None:
                        return lease
            return None
        finally:
            if transaction is not None:
                os.close(transaction)
            os.close(parent)

    def try_settlement(self, cohort: str, role: str) -> HostMemoryLease | None:
        if self.requests_stage or self.model_execution_stage:
            raise AdmissionBindingError("settlement is outside requests-stage qualification")
        if role not in {"coordinator", "reviewer"}:
            raise ValueError("settlement capacity requires a configured replica")
        signal = next(
            (s for s in self.policy.settlement_signals if s.cohort_sha256 == cohort), None
        )
        if signal is None:
            raise AdmissionBindingError("settlement cohort differs from selected host policy")
        parent = self._open_root()
        transaction = gate = marker = None
        lease = None
        try:
            transaction = self._transaction(parent)
            if transaction is None:
                return None
            # Each replica owns one retained slot and its signed-series
            # scheduler selects the earliest unfinished/recovery cohort. The
            # two replicas may be at different cohorts after restart; requiring
            # a shared current cohort would prevent either from catching up.
            gate = self._open_slot(parent, self.policy.settlement_gate)
            try:
                fcntl.flock(gate, fcntl.LOCK_SH | fcntl.LOCK_NB)
            except BlockingIOError:
                return None
            slot = next(s for s in self.policy.slots if s.settlement_role == role)
            lease = self._reserve(parent, slot)
            if lease is None:
                return None
            marker = self._open_slot(parent, signal)
            fcntl.flock(marker, fcntl.LOCK_SH | fcntl.LOCK_NB)
            lease._group = (marker, gate)
            marker = gate = None
            result, lease = lease, None
            return result
        finally:
            if lease is not None:
                lease.close()
            for descriptor in (marker, gate, transaction, parent):
                if descriptor is not None:
                    os.close(descriptor)

    def try_acquire_group(
        self, lane: Lane, count: int, *, slot_names=None
    ) -> HostMemoryLease | None:
        """Atomically reserve model slots; never retain a partial acquisition."""
        if not self.model_execution_stage or lane not in {"owner_export", "transient"}:
            raise AdmissionBindingError("group acquisition requires model execution capacity")
        slots = tuple(slot for slot in self.policy.slots if slot.lane == lane)
        if slot_names is not None:
            names = tuple(slot_names)
            if (
                lane != "transient"
                or not names
                or len(set(names)) != len(names)
                or not set(names).issubset(slot.name for slot in slots)
            ):
                raise AdmissionBindingError("CPU selection must use existing model slot files")
            slots = tuple(slot for slot in slots if slot.name in names)
        if type(count) is not int or not 1 <= count <= len(slots):
            raise ValueError("model execution slot count is outside its qualified capacity")
        self.last_model_admission = None
        parent, transaction, leases = self._open_root(), None, []
        try:
            transaction = self._transaction(parent)
            if transaction is None:
                return None
            for slot in slots:
                lease = self._reserve(parent, slot)
                if lease is not None:
                    leases.append(lease)
                if self.last_model_admission is not None:
                    self.last_model_admission["group_acquired_slots"] = len(leases)
                if len(leases) == count:
                    result = leases.pop(0)
                    result._group = tuple(lease._descriptor for lease in leases)
                    for lease in leases:
                        lease._descriptor = None
                    return result
            return None
        finally:
            for lease in leases:
                lease.close()
            if transaction is not None:
                os.close(transaction)
            os.close(parent)

    async def acquire(
        self, lane: Lane, *, operation=None, cohort=None, phase=None
    ) -> HostMemoryLease:
        # No blocking flock in a worker thread: cancellation cannot leave a
        # future acquisition running after the waiter has abandoned ownership.
        while True:
            lease = (
                self.try_acquire(lane, operation=operation, cohort=cohort, phase=phase)
                if self.requests_stage
                else self.try_acquire(lane)
            )
            if lease is not None:
                return lease
            await asyncio.sleep(0.1)

    @asynccontextmanager
    async def hold(self, lane: Lane):
        """Only for bounded compact-result operations which drain owned work.

        Returned models, raw bytes and retained replay state need explicit lease
        transfer instead. Do not acquire the same lane recursively or share a
        lease between concurrent tasks.
        """
        lease = await self.acquire(lane)
        try:
            yield lease
        finally:
            lease.close()
