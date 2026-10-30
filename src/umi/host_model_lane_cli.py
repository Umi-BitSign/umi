"""Prepare immutable CPU-derived capacity metadata; never select a live service.

The output contains the exact benchmark fields for the ordinary guarded
configuration handoff. Both shared-pool consumers must drain and remain held
until the same new policy is selected for both. Old readers cannot account for
new slots: preserving old lock identities does not permit mixed-policy execution.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
import time
from contextlib import suppress
from pathlib import Path

from . import host_memory_admission as admission
from .competition_delivery import _publish_noreplace
from .competition_runner import OfflineCpuRuntime
from .host_memory_runtime import HostMemoryAdmissionSelection
from .host_model_lane_policy import (
    expanded_lane_policy,
    model_lane_count,
    observe_cpu_capacity,
    validate_lane_runtime,
)
from .protocol import canonical_json_bytes


def _retain_policy(path, raw, group_id):
    """Publish under the shared transaction lock; recover this exact partial.

    Linux renameat2 exposes only fully initialized final files. A process death
    can leave one named partial for this exact target/content generation; the
    next serialized attempt validates and removes only that partial.
    """
    parent = admission._open_directory(path.parent)
    key = hashlib.sha256(path.name.encode() + b"\0" + raw).hexdigest()
    temporary = f".model-lane-{key}.partial"
    pending = False
    try:
        try:
            descriptor = os.open(path.name, admission._FILE_FLAGS, dir_fd=parent)
        except FileNotFoundError:
            pass
        else:
            try:
                admission._regular(descriptor, group_id)
                if os.read(descriptor, 65537) != raw:
                    raise ValueError("retained lane policy differs; use a new qualified generation")
            finally:
                os.close(descriptor)
            os.fsync(parent)
            return
        try:
            descriptor = os.open(temporary, admission._FILE_FLAGS, dir_fd=parent)
        except FileNotFoundError:
            pass
        else:
            try:
                details = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(details.st_mode)
                    or details.st_nlink != 1
                    or details.st_uid != admission._root_uid()
                    or stat.S_IMODE(details.st_mode) not in {0o400, 0o440, 0o600}
                    or not raw.startswith(os.read(descriptor, 65537))
                ):
                    raise ValueError("interrupted lane metadata differs from its exact generation")
            finally:
                os.close(descriptor)
            os.unlink(temporary, dir_fd=parent)
            os.fsync(parent)
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=parent,
        )
        pending = True
        with os.fdopen(descriptor, "wb") as stream:
            os.fchown(stream.fileno(), admission._root_uid(), group_id)
            os.fchmod(stream.fileno(), 0o440)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        _publish_noreplace(parent, temporary, path.name)
        pending = False
        os.fsync(parent)
    finally:
        if pending:
            with suppress(FileNotFoundError):
                os.unlink(temporary, dir_fd=parent)
        os.close(parent)


def prepare_lane_policy(
    selection,
    runtime,
    capacity,
    *,
    output_policy,
    qualification_sha256,
    maximum_lanes=None,
    progress=None,
    worker_pid=None,
):
    controller = admission.HostMemoryAdmission(
        Path(selection.policy_path),
        expected_sha256=selection.policy_sha256,
        host_identity_path=Path(selection.host_identity_path),
    )
    if not controller.model_execution_stage:
        raise ValueError("model execution capacity policy required")
    previous = controller.policy
    validate_lane_runtime(previous, runtime)
    # Refuse invalid qualification metadata before creating even an unused slot.
    expanded_lane_policy(previous, runtime, (), qualification_sha256=qualification_sha256)
    if capacity is None:
        capacity = observe_cpu_capacity(
            worker_pid,
            execution_cgroup_roots=previous.container_cgroup_roots,
        )
    desired = model_lane_count(capacity, runtime, maximum_lanes=maximum_lanes)
    output_policy = admission._absolute(str(output_policy))
    if output_policy.parent != Path(previous.directory):
        raise ValueError("new policy must use the existing shared capacity directory")
    if output_policy == Path(selection.policy_path):
        raise ValueError("never rewrite the selected admission policy")
    existing = [slot for slot in previous.slots if slot.lane == "transient"]
    # Keep old slots even when CPU availability or an explicit operator cap is
    # lower. The scheduler limit shrinks without replacing retained lock inodes.
    # Adoption still requires draining every old-policy consumer together.
    extra = max(0, desired - len(existing))
    if progress is not None:
        progress(0, extra + 1)
    parent = controller._open_root()
    transaction = None
    added = []
    try:
        transaction = controller._transaction(parent)
        if transaction is None:
            raise BlockingIOError("shared model capacity preparation busy; retry unchanged")
        for index in range(len(existing) + 1, len(existing) + extra + 1):
            name = f"model-{index:04d}.slot"
            if name in {slot.name for slot in previous.slots} | {previous.transaction_lock.name}:
                raise ValueError("new lane name overlaps a retained shared lock")
            # Fully initialize and sync the slot before exposing its final
            # name, just like the immutable policy. Interrupted preparation
            # cannot leave a partly chowned/chmodded final lock file.
            _retain_policy(Path(previous.directory) / name, b"", previous.group_id)
            descriptor = os.open(name, admission._FILE_FLAGS, dir_fd=parent)
            try:
                details = admission._regular(descriptor, previous.group_id)
                if details.st_size != 0:
                    raise ValueError("shared model slot must remain empty")
                added.append(
                    admission.HostMemorySlot(
                        name=name,
                        lane="transient",
                        device=details.st_dev,
                        inode=details.st_ino,
                        reservation_bytes=runtime.memory_bytes,
                    )
                )
            finally:
                os.close(descriptor)
            if progress is not None:
                progress(len(added), extra + 1)
        os.fsync(parent)
        proposed = expanded_lane_policy(
            previous,
            runtime,
            added,
            qualification_sha256=qualification_sha256,
        )
        raw = canonical_json_bytes(proposed)
        _retain_policy(output_policy, raw, previous.group_id)
    finally:
        if transaction is not None:
            os.close(transaction)
        os.close(parent)
    if progress is not None:
        progress(extra + 1, extra + 1)
    target = HostMemoryAdmissionSelection(
        policy_path=str(output_policy),
        policy_sha256=hashlib.sha256(raw).hexdigest(),
        host_identity_path=selection.host_identity_path,
    )
    return {
        "schema": "umi-model-lane-policy-preparation/1",
        "benchmark": {
            "concurrency": desired,
            "model_execution_admission": target.model_dump(mode="json"),
        },
        "effective_cpu_numerator": capacity.effective.numerator,
        "effective_cpu_denominator": capacity.effective.denominator,
        "signed_cpus_per_model": runtime.cpus,
        "operator_maximum_lanes": maximum_lanes,
        "model_slots": len(existing) + len(added),
        "previous_model_execution_admission": selection.model_dump(mode="json"),
        "qualification_sha256": qualification_sha256,
        "incremental_budget_bytes": proposed.incremental_budget_bytes,
        "coordinated_consumer_drain_required": True,
        "live_memory_admission_required": True,
        "production_selected": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selection", type=Path, required=True)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--worker-pid", type=int, required=True)
    parser.add_argument("--output-policy", type=Path, required=True)
    parser.add_argument("--qualification-sha256", required=True)
    parser.add_argument("--maximum-lanes", type=int)
    args = parser.parse_args()
    selection = HostMemoryAdmissionSelection.model_validate_json(args.selection.read_bytes())
    runtime = OfflineCpuRuntime.model_validate_json(args.runtime.read_bytes())
    started = time.monotonic()

    def progress(completed, total):
        elapsed = time.monotonic() - started
        print(
            json.dumps(
                {
                    "stage": "prepare_model_lane_policy",
                    "completed": completed,
                    "total": total,
                    "elapsed_seconds": elapsed,
                    "eta_seconds": 0 if completed == total else None,
                    "planning_eta_seconds": None if completed == total or elapsed > 5 else [0, 5],
                    "eta_basis": "completed"
                    if completed == total
                    else "planning_bounded_local_metadata",
                    "eta_scope": "policy_preparation_only_excludes_adoption_and_challenges",
                    "stalled_or_retrying": completed != total and elapsed > 5,
                }
            ),
            file=sys.stderr,
            flush=True,
        )

    result = prepare_lane_policy(
        selection,
        runtime,
        None,
        output_policy=args.output_policy,
        qualification_sha256=args.qualification_sha256,
        maximum_lanes=args.maximum_lanes,
        progress=progress,
        worker_pid=args.worker_pid,
    )
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
