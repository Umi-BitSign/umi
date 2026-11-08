"""Reclaim idle CPU-slot file cache under the existing native pool leases.

This root maintenance command allocates no model capacity and changes no limits.
It skips model grants, including surviving containers whose leases were lost.
The native transaction blocks new grants until bounded reclaim returns; existing
graph work may continue only with its exact kernel control-file witness.
"""

import argparse
import errno
import fcntl
import json
import os
import time
from pathlib import Path

from . import host_memory_graph_peer, host_memory_peer
from .host_cpu_timing import load_cpu_timing_profile
from .host_memory_admission import (
    AdmissionBindingError,
    HostMemoryAdmission,
    _cgroup_value,
    _open_cgroup_directory,
    _require_cgroup2,
)

MAXIMUM_RECLAIM_BYTES = 256 * 1024**2
MINIMUM_CACHE_BYTES = 64 * 1024**2


def _graph_owned(controller, slot, descriptor):
    """Prove an existing non-model grant while the native transaction is held.

    Reuse admission's owner, control-file and OFD witness checks. A graph grant
    cannot bind a model container; its replacement must acquire the transaction
    lock that the maintenance caller retains through reclaim.
    """
    binding = None
    try:
        if not controller.peer_execution_stage:
            return False
        marker = host_memory_graph_peer._marker(controller.policy, slot)
        owner = host_memory_graph_peer._lock_owners().get((slot.device, slot.inode))
        witness = host_memory_peer.observed_inode(descriptor)
        if marker is None or owner is None or witness is None:
            return False
        binding = host_memory_graph_peer._open_group(owner, marker, slot.reservation_bytes)
        return binding[2] == witness == host_memory_peer.observed_inode(descriptor)
    except (OSError, ValueError):
        return False
    finally:
        host_memory_graph_peer.close(binding)


def _sample(descriptor, ceiling):
    _require_cgroup2(descriptor)
    if _cgroup_value(descriptor, "memory.max") != str(ceiling):
        raise AdmissionBindingError("idle cache parent ceiling changed")
    if any(
        _cgroup_value(descriptor, name) != "0"
        for name in ("memory.swap.max", "memory.swap.current")
    ):
        raise AdmissionBindingError("idle cache parent requires zero swap")
    events = dict(line.split() for line in _cgroup_value(descriptor, "cgroup.events").splitlines())
    if events.get("populated") != "0":
        return None
    stats = dict(line.split() for line in _cgroup_value(descriptor, "memory.stat").splitlines())
    values = {
        key: int(stats[key]) for key in ("anon", "file", "shmem", "file_dirty", "file_writeback")
    }
    if min(values.values()) < 0:
        raise AdmissionBindingError("idle cache counters are invalid")
    return dict(current_bytes=int(_cgroup_value(descriptor, "memory.current")), **values)


def reclaim_once(controller, profile):
    """Return counted progress; a busy pool is a skipped pass, never a wait."""
    started = time.monotonic()
    result = dict(
        schema="umi-idle-cpu-cache-reclaim/1",
        policy_sha256=controller.policy_sha256,
        status="skipped",
        reason="pool_busy",
        completed=0,
        total=1,
        requested_bytes=0,
        reclaimed_bytes=0,
        eta_seconds=None,
        eta_basis="awaiting_idle_native_pool",
        certification_authority=False,
    )
    descriptors = []
    try:
        if profile is None:
            raise AdmissionBindingError("idle cache maintenance requires selected CPU slots")
        slots = {slot.name: slot for slot in controller.policy.slots if slot.lane == "transient"}
        if set(slots) != {slot.lock_name for slot in profile.slots}:
            raise AdmissionBindingError("idle cache maintenance requires the complete timed pool")
        root = controller._open_root()
        descriptors.append(root)
        transaction = controller._transaction(root)
        if transaction is None:
            result["reason"] = "admission_transaction_busy"
            return result
        descriptors.append(transaction)
        # Prevent every new grant, then own each free slot or prove it belongs
        # to an existing non-model graph grant. Existing models still block
        # maintenance, including the interval before their container exists.
        graph_slots = []
        for slot in sorted(slots.values(), key=lambda item: item.name):
            descriptor = controller._open_slot(root, slot)
            descriptors.append(descriptor)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                if not _graph_owned(controller, slot, descriptor):
                    return result
                graph_slots.append(slot.name)
        result["witnessed_graph_slots"] = graph_slots
        if controller._model_container_reservations():
            result["reason"] = "surviving_native_container"
            return result
        selected = []
        partition = Path(profile.partition.path)
        if {p.name for p in partition.iterdir() if p.is_dir()} != set(slots):
            raise AdmissionBindingError("idle cache pool layout changed; select its current policy")
        for slot in profile.slots:
            expected = {"uid" + str(parent.uid) for parent in slot.parents}
            if {p.name for p in (partition / slot.lock_name).iterdir() if p.is_dir()} != expected:
                raise AdmissionBindingError("idle cache account layout changed")
            for parent in slot.parents:
                path = Path(parent.path)
                if path != partition / slot.lock_name / ("uid" + str(parent.uid)):
                    raise AdmissionBindingError("idle cache parent is outside the selected slot")
                if path.resolve(strict=True) != path:
                    raise AdmissionBindingError("idle cache parent is aliased")
                descriptor = _open_cgroup_directory(path)
                descriptors.append(descriptor)
                if os.fstat(descriptor).st_uid != parent.uid:
                    raise AdmissionBindingError("idle cache parent owner changed")
                ceiling = slots[slot.lock_name].reservation_bytes
                sample = _sample(descriptor, ceiling)
                if sample is None:
                    result["reason"] = "populated_selected_parent"
                    return result
                # Empty groups can retain dirty/shmem or stale anon counters.
                # Wait for clean accounting instead of causing writeback/swap.
                if any(sample[key] for key in ("anon", "shmem", "file_dirty", "file_writeback")):
                    continue
                if sample["file"] >= MINIMUM_CACHE_BYTES:
                    selected.append((sample["file"], descriptor, ceiling, path))
        if not selected:
            result.update(
                status="completed",
                reason="no_eligible_cache",
                completed=1,
                eta_seconds=0,
                eta_basis="completed_pass",
            )
            return result
        _, descriptor, ceiling, path = max(selected, key=lambda item: item[0])
        before = _sample(descriptor, ceiling)
        if before is None or any(
            before[key] for key in ("anon", "shmem", "file_dirty", "file_writeback")
        ):
            result["reason"] = "selected_parent_changed"
            return result
        count = min(MAXIMUM_RECLAIM_BYTES, before["file"])
        result.update(parent=str(path), before=before, requested_bytes=count)
        control = os.open(
            "memory.reclaim", os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=descriptor
        )
        try:
            raw = (str(count) + "\n").encode("ascii")
            try:
                if os.write(control, raw) != len(raw):
                    raise OSError("incomplete idle cache reclaim write")
            except OSError as error:
                if error.errno != errno.EAGAIN:
                    raise
                # The kernel can reclaim less than requested. Record actual
                # counters; an EAGAIN is neither full completion nor corruption.
                result["partial_reclaim"] = True
        finally:
            os.close(control)
        after = _sample(descriptor, ceiling)
        if after is None:
            raise AdmissionBindingError("idle cache parent became populated under native locks")
        result.update(
            status="completed",
            reason="bounded_reclaim",
            after=after,
            reclaimed_bytes=max(0, before["file"] - after["file"]),
            completed=1,
            eta_seconds=0,
            eta_basis="completed_pass_remaining_cache_requires_future_idle_passes",
        )
        return result
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
        result["elapsed_seconds"] = time.monotonic() - started


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise PermissionError("idle CPU-cache maintenance requires root")
    # Inspection joins an already running pool. It does not perform startup
    # resource admission or acquire a model grant. The caller separately caps
    # this maintenance process, and reclaim_once takes only existing locks.
    controller = HostMemoryAdmission(
        args.policy, expected_sha256=args.sha256, _reattach_model_worker=True
    )
    profile = load_cpu_timing_profile(controller.policy.cpu_timing_profile, controller)
    print(json.dumps(reclaim_once(controller, profile), separators=(",", ":")), flush=True)


if __name__ == "__main__":
    main()
