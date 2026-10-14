"""Preserve stopped native preparation while increasing its operational allowance.

No journal payload is opened. The immutable intent precedes the only mutation:
rewriting the existing preparation mutex's scope in place. It is not evidence
of native restore, permission to select history, or authority to submit weights.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import logging
import os
import re
import stat
import time
from pathlib import Path

from . import competition_reward_history_preparation as preparation
from .competition_reward_history_preparation_runtime import HistoryPreparationLaunch
from .competition_reward_history_preparation_service import stopped_preparation_service
from .competition_reward_writer_review import select_stopped_writer_boot
from .competition_reward_writer_selection import _content_stamps, _history, _sync
from .open_competition import digest
from .protocol import canonical_json_bytes

_LOG = logging.getLogger("umi.competition.progress")
_MAX = preparation.MAX_PREPARATION_CONTROL_BYTES


def _report(started, completed, state):
    elapsed = time.monotonic() - started
    _LOG.info(
        json.dumps(
            {
                "stage": "history_preparation_capacity_migration",
                "state": state,
                "completed": completed,
                "total": 4,
                "percent": completed * 25,
                "elapsed_seconds": elapsed,
                "eta_seconds": 0 if state == "completed" else None,
                "planning_eta_seconds": [0.05, max(0.05, 10 - elapsed)]
                if state in {"planning", "running", "repairing"} and elapsed < 10
                else None,
                "eta_basis": "completed"
                if state == "completed"
                else "bounded_local_controls_and_fsync"
                if elapsed < 10
                else "withdrawn",
                "eta_scope": "capacity_migration_only_excludes_native_restore_and_rewards",
                "stalled": state == "blocked",
                "retrying": state == "repairing",
                "weight_authority": False,
            },
            separators=(",", ":"),
        )
    )


def _read_record(path):
    preparation._root_ancestors(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != preparation._root_owner_uid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or not 0 <= before.st_size <= _MAX
        ):
            raise ValueError("capacity migration record is unsafe")
        raw = os.read(descriptor, _MAX + 1)
        after = os.fstat(descriptor)
        if before != after or len(raw) != before.st_size:
            # Reading can change access time, which does not identify contents.
            def stamp(info):
                return (
                    *preparation._file_identity(info),
                    info.st_size,
                    info.st_mtime_ns,
                    info.st_ctime_ns,
                )

            if stamp(before) != stamp(after) or len(raw) != before.st_size:
                raise ValueError("capacity migration record changed during read")
        return raw
    finally:
        os.close(descriptor)


def _publish_exact(path, raw, *, repair):
    """Recover only the deterministic prefix of this exact bounded publication."""
    if len(raw) > _MAX:
        raise ValueError("capacity migration record exceeds its bound")
    pending = path.with_suffix(".pending")
    if path.exists() or path.is_symlink():
        if _read_record(path) != raw:
            raise ValueError("retained capacity migration record differs")
        if pending.exists() or pending.is_symlink():
            if not raw.startswith(_read_record(pending)):
                raise ValueError("capacity migration pending record differs")
            repair()
            pending.unlink()
            _sync(path.parent)
        return
    if pending.exists() or pending.is_symlink():
        if not raw.startswith(_read_record(pending)):
            raise ValueError("capacity migration pending record differs")
        repair()
        pending.unlink()
        _sync(path.parent)
    descriptor = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        _write_all(descriptor, raw)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(pending, path)
    _sync(path.parent)


def _write_all(descriptor, raw):
    remaining = memoryview(raw)
    while remaining:
        written = os.write(descriptor, remaining)
        if not written:
            raise OSError("capacity migration write made no progress")
        remaining = remaining[written:]


def _rewrite_scope(descriptor, raw):
    # After intent publication, an interrupted truncate or prefix write can be
    # repaired on this same inode. Never replace, unlink or recreate the mutex.
    os.ftruncate(descriptor, 0)
    os.lseek(descriptor, 0, os.SEEK_SET)
    _write_all(descriptor, raw)
    os.fsync(descriptor)


def _launch_pair(old_path, new_path, old_approval, new_approval):
    old_raw, old_identity = preparation._control(old_path, _MAX)
    new_raw, new_identity = preparation._control(new_path, _MAX)
    old = HistoryPreparationLaunch.model_validate_json(old_raw)
    new = HistoryPreparationLaunch.model_validate_json(new_raw)
    if (
        canonical_json_bytes(old) != old_raw
        or canonical_json_bytes(new) != new_raw
        or old.preparation_approval_sha256 != digest(old_approval)
        or new.preparation_approval_sha256 != digest(new_approval)
        or new != old.model_copy(update={"preparation_approval_sha256": digest(new_approval)})
    ):
        raise ValueError("capacity migration may only rebind unchanged launch controls")
    return old, new, (old_identity, new_identity)


def _writer_can_read_boot(path, uid, gid):
    for parent in path.parents:
        info = parent.stat()
        execute = 0o100 if info.st_uid == uid else 0o010 if info.st_gid == gid else 0o001
        if not info.st_mode & execute:
            raise ValueError("final writer cannot traverse selected capacity boot")


def _migration_paths(root, boot_sha256):
    intent = root / ("capacity-migration-" + boot_sha256 + ".json")
    return intent, intent.with_suffix(".completed.json")


def _prior_migrations(root, selected):
    """Retain completed upgrades; another interrupted transition must recover first."""
    entries = tuple(root.iterdir())
    if len(entries) > 1024:
        raise ValueError("preparation control inventory exceeds its bound")
    selected_paths = {*selected, *(p.with_suffix(".pending") for p in selected)}
    others = {p for p in entries if p.name.startswith("capacity-migration-")} - selected_paths
    for path in others:
        match = re.fullmatch(r"capacity-migration-([0-9a-f]{64})(?:\.completed)?\.json", path.name)
        if match is None:
            raise ValueError("another capacity migration needs explicit recovery")
        intent_path, receipt_path = _migration_paths(root, match[1])
        if intent_path not in others or receipt_path not in others:
            raise ValueError("another capacity migration lacks durable completion")
        raw, receipt_raw = _read_record(intent_path), _read_record(receipt_path)
        value, receipt = json.loads(raw), json.loads(receipt_raw)
        if (
            canonical_json_bytes(value) != raw
            or canonical_json_bytes(receipt) != receipt_raw
            or value.get("schema") != "umi-history-preparation-capacity-migration/1"
            or receipt.get("schema") != "umi-history-preparation-capacity-completed/1"
            or receipt.get("intent_sha256") != hashlib.sha256(raw).hexdigest()
            or receipt.get("maximum_history_bytes") != value.get("new_capacity")
            or value.get("new_scope", {}).get("boot") != match[1]
        ):
            raise ValueError("retained completed capacity migration requires explicit repair")


def migrate_preparation_capacity(
    anchor,
    *,
    old_boot: Path,
    new_boot: Path,
    old_approval: Path,
    new_approval: Path,
    preparation_launch: tuple[Path, Path],
    writer_launch: tuple[Path, Path],
    preparation_unit: str,
    installed_unit: str,
    config_path: Path,
    held_approval: Path | None = None,
):
    """Authenticate both consumers, retain intent, and preserve the native checkpoint.

    All four new immutable controls must already exist. The caller stops only
    the isolated preparation service before invoking this operation. No service
    is changed here, and the installed coordinator/writer need not be stopped.
    """
    started = time.monotonic()
    progress = [0]
    _report(started, 0, "planning")
    try:
        return _migrate(
            anchor,
            old_boot=old_boot,
            new_boot=new_boot,
            old_approval=old_approval,
            new_approval=new_approval,
            preparation_launch=preparation_launch,
            writer_launch=writer_launch,
            preparation_unit=preparation_unit,
            installed_unit=installed_unit,
            config_path=config_path,
            held_approval=held_approval,
            started=started,
            progress=progress,
        )
    except BaseException:
        _report(started, progress[0], "blocked")
        raise


def _migrate(
    anchor,
    *,
    old_boot,
    new_boot,
    old_approval,
    new_approval,
    preparation_launch,
    writer_launch,
    preparation_unit,
    installed_unit,
    config_path,
    held_approval,
    started,
    progress,
):
    old = preparation._authenticated_scope(
        anchor, standing_boot=old_boot, approval_path=old_approval
    )
    new = preparation._authenticated_scope(
        anchor, standing_boot=new_boot, approval_path=new_approval
    )
    old_policy, old_config = old[:2]
    new_policy, new_config = new[:2]
    if (
        new_config.maximum_history_bytes <= old_config.maximum_history_bytes
        or new_config
        != old_config.model_copy(
            update={
                "maximum_history_bytes": new_config.maximum_history_bytes,
            }
        )
        or new_policy
        != old_policy.model_copy(
            update={
                "standing_boot_raw_sha256": new_policy.standing_boot_raw_sha256,
            }
        )
        or old[2:8] != new[2:8]
    ):
        raise ValueError("capacity migration requires only a strictly increased history allowance")
    # The ordinary approval and signed scope must remain valid for the final
    # native consumer. It does not pin operational history capacity.
    original_writer = select_stopped_writer_boot(anchor, old_boot, held_approval=held_approval)
    selected_writer = select_stopped_writer_boot(anchor, new_boot, held_approval=held_approval)
    _writer_can_read_boot(new_boot, anchor.service_uid, new_policy.service_gid)
    prep_pair = _launch_pair(*preparation_launch, old_policy, new_policy)
    final_pair = _launch_pair(*writer_launch, old_policy, new_policy)
    root, history = old[4:6]
    path, receipt = _migration_paths(root, new_policy.standing_boot_raw_sha256)
    lock = preparation._lock_file(root / "preparation.lock")
    native = None
    completed = progress[0] = 1
    _report(started, completed, "running")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        expected_lock = preparation._file_identity(os.fstat(lock))
        native_identity = _history(history, anchor.service_uid, old_policy.service_gid)
        content = _content_stamps(history)
        native = os.open(history / "rounds.lock", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        fcntl.flock(native, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if list(preparation._file_identity(os.fstat(native))) != native_identity["rounds.lock"]:
            raise ValueError("capacity migration native mutex changed")
        service_args = dict(
            installed_unit=installed_unit,
            config_path=config_path,
            python_path=Path(prep_pair[0].python_root) / ".venv/bin/python",
            choices=(
                (old_boot, old_approval, preparation_launch[0]),
                (new_boot, new_approval, preparation_launch[1]),
            ),
        )
        service = stopped_preparation_service(preparation_unit, **service_args)
        controls = (*old[9], *new[9], *prep_pair[2], *final_pair[2])

        def recheck():
            _prior_migrations(root, (path, receipt))
            if any(p.name.startswith("history-selection-") for p in root.iterdir()):
                raise ValueError("capacity migration refuses an existing history selection")
            if (
                preparation._authenticated_scope(
                    anchor, standing_boot=old_boot, approval_path=old_approval
                )
                != old
                or preparation._authenticated_scope(
                    anchor, standing_boot=new_boot, approval_path=new_approval
                )
                != new
            ):
                raise ValueError("capacity migration authenticated scope changed")
            original_writer.recheck()
            selected_writer.recheck()
            for p, maximum, stamp, checksum in controls:
                if preparation._control(p, maximum)[1] != (p, maximum, stamp, checksum):
                    raise ValueError("capacity migration controls changed")
            if (
                preparation._file_identity((root / "preparation.lock").lstat()) != expected_lock
                or preparation._file_identity(os.fstat(lock)) != expected_lock
                or _history(history, anchor.service_uid, old_policy.service_gid) != native_identity
                or _content_stamps(history) != content
                or stopped_preparation_service(preparation_unit, **service_args) != service
            ):
                raise ValueError("capacity migration stopped ownership or native history changed")

        recheck()
        intent = {
            "schema": "umi-history-preparation-capacity-migration/1",
            "old_scope": json.loads(old[8]),
            "new_scope": json.loads(new[8]),
            "old_capacity": old_config.maximum_history_bytes,
            "new_capacity": new_config.maximum_history_bytes,
            "lock_identity": list(expected_lock),
            "native_identity": native_identity,
            "native_content_stamps": content,
            "controls": [
                [str(p), maximum, [str(value) for value in stamp], sha]
                for p, maximum, stamp, sha in controls
            ],
            "preparation_unit": preparation_unit,
            "installed_unit": installed_unit,
            "config_path": str(config_path),
            "final_boot": str(new_boot),
            "final_launch": str(writer_launch[1]),
        }
        raw = canonical_json_bytes(intent)
        scope = os.pread(lock, _MAX + 1, 0)
        retained = path.exists() or path.is_symlink()
        if retained:
            if _read_record(path) != raw:
                raise ValueError("retained capacity migration intent differs")
            if scope not in (old[8], new[8]) and not new[8].startswith(scope):
                raise ValueError("capacity migration lock has unrelated bytes")
        elif scope != old[8]:
            raise ValueError("capacity migration needs its original scope or durable intent")
        if (receipt.exists() or receipt.is_symlink()) and (not retained or scope != new[8]):
            raise ValueError("completed capacity migration scope changed")

        def repairing():
            _report(started, 2, "repairing")

        _publish_exact(path, raw, repair=repairing)
        completed = progress[0] = 2
        _report(started, completed, "running")
        recheck()
        if scope != new[8]:
            if retained:
                repairing()
            _rewrite_scope(lock, new[8])
        _sync(root)
        if os.pread(lock, _MAX + 1, 0) != new[8]:
            raise ValueError("capacity migration scope did not persist")
        recheck()
        completed = progress[0] = 3
        _report(started, completed, "running")
        result = {
            "schema": "umi-history-preparation-capacity-completed/1",
            "intent_sha256": hashlib.sha256(raw).hexdigest(),
            "maximum_history_bytes": new_config.maximum_history_bytes,
            "standing_boot": str(new_boot),
            "preparation_approval": str(new_approval),
            "preparation_launch": str(preparation_launch[1]),
            "writer_launch": str(writer_launch[1]),
            "native_history_reverified": False,
            "native_restore_qualified": False,
            "weight_authority": False,
        }
        _publish_exact(receipt, canonical_json_bytes(result), repair=repairing)
        recheck()
        _report(started, 4, "completed")
        return result
    finally:
        if native is not None:
            os.close(native)
        os.close(lock)
