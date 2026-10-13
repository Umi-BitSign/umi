"""Resumable migration of an offline original /1 archive to selected R2 storage.

Original frame bytes and object addresses are preserved. Completion and exact
local source identities live in the permanent remote index, never in the cache.
Callers must own the service's offline upgrade boundary before selecting eviction.
"""

from __future__ import annotations

import os
import re
from contextlib import contextmanager

from .competition_evidence_codec import MAX_EVIDENCE_BYTES
from .competition_reward_proof_archive import (
    MAX_FIELD_BYTES,
    MAX_FRAME_BYTES,
    RewardProofArchive,
    _publication_clock_ns,
)
from .competition_transport_verification import TransferProgress
from .open_competition import digest
from .private_files import ensure_private_directory, lock_private_file
from .protocol import canonical_json_bytes

_NAME = re.compile(r"^[0-9a-f]{64}\.json$")
_KINDS = ("objects", "history", "endpoint", "interval", "registration")


def _files(root, kind):
    directory = root / kind
    if not directory.exists():
        return
    ensure_private_directory(directory)
    with os.scandir(directory) as entries:
        for entry in entries:
            if entry.name == ".publish.lock":
                continue
            if _NAME.fullmatch(entry.name) is None:
                raise ValueError("legacy proof archive contains an unsupported file")
            yield directory / entry.name


@contextmanager
def _migration_owner(archive):
    archive._ensure_root()
    root = archive.root
    descriptor = lock_private_file(root / ".proof-migration.lock")
    try:
        yield
    finally:
        os.close(descriptor)


def migrate_proof_archive(
    original: RewardProofArchive,
    selected: RewardProofArchive,
    *,
    evict: bool = False,
    repair_source_identity: bool = False,
) -> dict:
    """Copy and optionally evict exact originals with durable per-file progress.

    This is a byte-format migration, not native proof acceptance. A new source
    identity after completion requires explicit repair and exact original bytes.
    Unknown files, missing dependencies and changed immutable names refuse first.
    """
    remote = selected.remote
    if original.remote is not None or remote is None or remote.config.read_only:
        raise ValueError("proof migration requires original local and writable remote stores")
    replicated = restored = removed = reclaimed = 0
    with _migration_owner(original):
        total = 0
        with TransferProgress(
            "proof_archive_inventory",
            len(_KINDS),
            unit="directories",
            planning_unit_seconds=(0.01, 60.0),
        ) as progress:
            for kind in _KINDS:
                total += sum(1 for _ in _files(original.root, kind))
                progress.advance(1)
        with TransferProgress("proof_archive_migration", total, unit="files") as progress:
            # Complete the object graph before exposing any portable frame.
            for kind in _KINDS:
                for path in _files(original.root, kind):
                    stamp = [str(v) for v in original._object_stamp(path)]
                    relative = path.relative_to(original.root).as_posix()
                    slot = digest({"root": str(original.root), "file": relative})
                    source_key = digest({"slot": slot, "stamp": stamp})
                    record = remote.journal.get("proof_migration_file", slot)
                    source = remote.journal.get("proof_migration_source", source_key)
                    if source is not None:
                        if record is None or source != {"record_sha256": digest(record)}:
                            raise ValueError("completed proof migration record is damaged")
                        remote.validate_reference(record["reference"])
                        restored += 1
                        progress.advance(1, restored=True)
                        continue
                    if record is not None and not repair_source_identity:
                        progress.emit("repair_required", reason="proof_migration_source_changed")
                        raise ValueError(
                            "completed proof migration source requires explicit repair"
                        )
                    tick = _publication_clock_ns()
                    if tick is None or int(stamp[-1]) >= tick:
                        # Do not certify a same-tick file identity as reusable.
                        progress.emit("retrying", reason="proof_migration_identity_tick")
                        raise OSError("proof migration requires a settled source timestamp")
                    key = path.stem
                    if kind == "objects":
                        raw = original._read_object(path, key, MAX_EVIDENCE_BYTES)
                        reference = remote.put_bytes(raw)
                    else:
                        frame = original._frame(kind, key)
                        if len(frame.fields) > 4:
                            raise ValueError("legacy proof frame exceeds field bound")
                        original.read(
                            kind, key, bounds={name: MAX_FIELD_BYTES for name in frame.fields}
                        )
                        raw = canonical_json_bytes(frame)
                        if len(raw) > MAX_FRAME_BYTES:
                            raise ValueError("legacy proof frame exceeds byte bound")
                        reference = remote.put_bytes(raw, path="frames/" + kind + "/" + key)
                    if [str(v) for v in original._object_stamp(path)] != stamp:
                        raise ValueError("legacy proof source changed during migration")
                    value = {"schema": "umi-proof-migration-file/1", "reference": reference}
                    if record is not None and record != value:
                        raise ValueError("proof migration repair changed the original bytes")
                    remote.journal.put_many(
                        (
                            ("proof_migration_file", slot, value),
                            (
                                "proof_migration_source",
                                source_key,
                                {"record_sha256": digest(value)},
                            ),
                        )
                    )
                    replicated += 1
                    progress.advance(1)
        if evict:
            with TransferProgress("proof_archive_local_eviction", total, unit="files") as progress:
                # Reverse dependency order. Never delete partial/unacknowledged
                # publication or the permanent .remote-state metadata directory.
                for kind in reversed(_KINDS):
                    for path in _files(original.root, kind):
                        stamp = [str(v) for v in original._object_stamp(path)]
                        relative = path.relative_to(original.root).as_posix()
                        slot = digest({"root": str(original.root), "file": relative})
                        record = remote.journal.get("proof_migration_file", slot)
                        source = remote.journal.get(
                            "proof_migration_source", digest({"slot": slot, "stamp": stamp})
                        )
                        if record is None or source != {"record_sha256": digest(record)}:
                            raise ValueError(
                                "proof eviction requires completed exact-source migration"
                            )
                        remote.validate_reference(record["reference"])
                        allocated = path.stat().st_blocks * 512
                        if [str(v) for v in original._object_stamp(path)] != stamp:
                            raise ValueError("proof source changed before eviction")
                        path.unlink()
                        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
                        try:
                            os.fsync(fd)
                        finally:
                            os.close(fd)
                        removed += 1
                        reclaimed += allocated
                        progress.advance(1)
    return {
        "replicated_files": replicated,
        "restored_files": restored,
        "removed_files": removed,
        "reclaimed_allocated_bytes": reclaimed,
    }
