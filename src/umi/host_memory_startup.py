"""Reserve one bounded host startup using the existing native execution slots.

This explicit selection replaces the idle-all-slots startup sample. Construction
holds a normal transient lease, and the actual service cgroup must enforce the
selected budget without swap. Running graph/model grants remain unchanged.
"""

import asyncio
import fcntl
import os
import time
from contextlib import asynccontextmanager, contextmanager
from contextvars import ContextVar
from pathlib import Path

from . import host_memory_graph_peer
from .competition_transport_verification import TransferProgress
from .host_memory_admission import (
    CAPACITY_RETRY_SECONDS,
    AdmissionBindingError,
    _available_memory,
    _cgroup_value,
    _open_cgroup_directory,
    _require_cgroup2,
)
from .host_memory_residency import ResidentBudget

_active = ContextVar("host_startup_reservation", default=None)


class HostStartupStopped(Exception):
    """The operator stopped construction before it acquired host capacity."""


def check_startup_stop(stop):
    if stop is not None and stop.is_set():
        raise HostStartupStopped


def enforced_service_limit():
    membership = Path("/proc/self/cgroup").read_text().strip()
    if not membership.startswith("0::/") or "\n" in membership:
        raise AdmissionBindingError("startup reservation requires unified cgroup membership")
    relative = Path(membership[4:])
    if relative.is_absolute() or ".." in relative.parts:
        raise AdmissionBindingError("invalid startup cgroup membership")
    path = Path("/sys/fs/cgroup") / relative
    descriptor = _open_cgroup_directory(path)
    try:
        _require_cgroup2(descriptor)
        maximum = _cgroup_value(descriptor, "memory.max")
        swap = _cgroup_value(descriptor, "memory.swap.max")
        if not maximum.isdigit() or int(maximum) <= 0 or swap != "0":
            raise AdmissionBindingError("startup requires a finite service cap and zero swap")
        return int(maximum)
    finally:
        os.close(descriptor)


def current_startup_reservation():
    value = _active.get()
    return (
        value if value is not None and value.pid == os.getpid() and not value.lease.closed else None
    )


class StartupReservation:
    def __init__(self, controller, lease):
        self.controller, self.lease, self.pid = controller, lease, os.getpid()

    def compatible_model_controller(self, controller):
        a, b = self.controller.policy, controller.policy
        fields = (
            "directory",
            "directory_device",
            "directory_inode",
            "host_identity_sha256",
            "minimum_available_bytes",
            "background_reservation_bytes",
            "slots",
            "transaction_lock",
        )
        if any(getattr(a, name) != getattr(b, name) for name in fields):
            raise AdmissionBindingError("model constructor differs from reserved host capacity")

    def complete(self):
        self.lease.close()


def _selected(controller):
    budget = getattr(controller, "startup_reservation_bytes", None)
    if budget is None:
        return False
    if current_startup_reservation() is not None:
        raise AdmissionBindingError("nested host startup cannot borrow another construction lease")
    if enforced_service_limit() > budget:
        raise AdmissionBindingError("service memory cap exceeds its selected startup reservation")
    return True


@asynccontextmanager
async def memory_startup(controller, *, stop=None):
    check_startup_stop(stop)
    if not _selected(controller):
        yield None
        return
    with TransferProgress("host_startup_capacity", 1, unit="hosts") as progress:
        lease = (
            await controller.acquire("transient")
            if stop is None
            else await controller.acquire("transient", stop=stop)
        )
        if lease is None:
            raise HostStartupStopped
        progress.advance(1)
    reservation = StartupReservation(controller, lease)
    token = _active.set(reservation)
    try:
        yield reservation
    finally:
        reservation.complete()
        _active.reset(token)


@contextmanager
def synchronous_memory_startup(controller):
    # Intake's app factory runs before its event loop. Never block a running loop.
    if not _selected(controller):
        yield None
        return
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        pass
    else:
        raise AdmissionBindingError("synchronous startup cannot block an active event loop")
    with TransferProgress("host_startup_capacity", 1, unit="hosts") as progress:
        last_report = None
        while (lease := controller.try_acquire("transient")) is None:
            now = time.monotonic()
            if last_report is None or now - last_report >= 10:
                progress.emit("waiting", reason="host_startup_capacity")
                last_report = now
            time.sleep(CAPACITY_RETRY_SECONDS)
        progress.advance(1)
    reservation = StartupReservation(controller, lease)
    token = _active.set(reservation)
    try:
        yield reservation
    finally:
        reservation.complete()
        _active.reset(token)


def complete_memory_startup(reservation):
    if reservation is not None:
        reservation.complete()


def probe_startup_reservation(controller):
    """Sample the candidate and busy charges without owning a startup grant.

    Busy slots need not be idle before an existing service can drain. The new host
    must acquire its own lease before construction; this observation is not a grant.
    """
    root = controller._open_root()
    transaction = None
    busy = set()
    residency = ResidentBudget(controller.peer_execution_stage)
    pending = max(s.reservation_bytes for s in controller.policy.slots if s.lane == "transient")
    if controller.peer_execution_stage and controller.startup_reservation_bytes is not None:
        pending = min(pending, controller.startup_reservation_bytes)
    try:
        # A grant briefly locks otherwise free slots while measuring peers.
        # Without this transaction, a probe can mistake those locks for live
        # reservations and repeatedly refuse a replacement that actually fits.
        transaction = controller._transaction(root)
        if transaction is None:
            return dict(
                schema="umi-host-memory-startup/1",
                stage="host_startup_capacity",
                status="capacity_required",
                policy_sha256=controller.policy_sha256,
                startup_memory_bytes=controller.startup_reservation_bytes,
                capacity_reserved=False,
                eta_seconds=None,
                eta_basis="awaiting_native_capacity_transaction",
                stalled_or_retrying=True,
            )
        for slot in controller.policy.slots:
            descriptor = controller._open_slot(root, slot)
            try:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    pending += slot.reservation_bytes
                    busy.add((slot.device, slot.inode))
            finally:
                os.close(descriptor)
        graph_discount = host_memory_graph_peer.discount(
            controller, root, busy, residency=residency
        )
        pending -= graph_discount
        containers = controller._model_container_reservations(busy, residency=residency)
        available, resident_credit = residency.measure(_available_memory)
    finally:
        residency.close()
        if transaction is not None:
            os.close(transaction)
        os.close(root)
    required = (
        controller.policy.minimum_available_bytes
        + controller.policy.background_reservation_bytes
        + pending
        + containers
        - resident_credit
    )
    return dict(
        schema="umi-host-memory-startup/1",
        stage="host_startup_capacity",
        status="admitted" if available >= required else "capacity_required",
        policy_sha256=controller.policy_sha256,
        available_bytes=available,
        required_available_bytes=required,
        shortfall_bytes=max(0, required - available),
        startup_memory_bytes=controller.startup_reservation_bytes,
        pending_reservation_bytes=pending,
        shared_graph_ceiling_discount_bytes=graph_discount,
        **residency.observation,
        capacity_reserved=False,
        eta_seconds=0 if available >= required else None,
        eta_basis="startup_reservation_probe_actual_grant_required_before_construction",
        stalled_or_retrying=available < required,
    )
