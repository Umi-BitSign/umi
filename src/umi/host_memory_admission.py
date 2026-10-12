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
import stat
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

    @property
    def closed(self) -> bool:
        return self._descriptor is None

    def close(self) -> None:
        descriptor, self._descriptor = self._descriptor, None
        if descriptor is not None:
            os.close(descriptor)
        group, self._group = self._group, ()
        for descriptor in group:
            os.close(descriptor)

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
        else:
            self.policy = HostMemoryAdmissionPolicy.model_validate_json(raw)
        self.policy_sha256 = expected_sha256
        if self.policy.host_identity_sha256 != _host_identity(host_identity_path):
            raise AdmissionBindingError("host admission policy belongs to another host")
        self._validate_all()
        # Startup and every later grant remeasure current memory. Idle Python
        # heaps remain in MemAvailable accounting after logical leases close.
        if (
            _available_memory()
            < self.policy.minimum_available_bytes
            + self.policy.reserved_bytes
            + self.policy.background_reservation_bytes
        ):
            raise OSError("host memory admission startup awaits qualified headroom")

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
            if not self.requests_stage:
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
            for slot in self.policy.slots:
                if slot.name == selected.name:
                    continue
                other = self._open_slot(parent, slot)
                try:
                    try:
                        fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError:
                        pending += slot.reservation_bytes
                finally:
                    os.close(other)
            if (
                _available_memory()
                < self.policy.minimum_available_bytes
                + pending
                + self.policy.background_reservation_bytes
            ):
                return None
            lease = HostMemoryLease(descriptor, selected)
            descriptor = None
            return lease
        finally:
            if descriptor is not None:
                os.close(descriptor)

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
        if self.requests_stage:
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
