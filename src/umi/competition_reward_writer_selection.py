"""Durable root directory exchange; native reconciliation remains the caller's job.

This preserves both history directories and their database inodes. It never
manufactures a preparation/startup lease or treats its journal as verification.
The broker must retain genuine native lock ownership through commit or rollback.
Ordinary cutover keeps one stopped-writer child alive. After unexpected child
exit, workers must drain while root retains duplicate original open file
descriptions; serialized metadata cannot replace those actual held locks.
"""

from __future__ import annotations

import ctypes
import fcntl
import hashlib
import json
import logging
import os
import re
import stat
import time
from contextlib import contextmanager
from pathlib import Path

from . import competition_reward_history_preparation as preparation
from .competition_host_anchor import MaterializedSuccessorAnchor
from .competition_reward_boot import MAX_BOOT_BYTES, StandingRewardBootConfig
from .open_competition import digest
from .private_files import private_path
from .protocol import canonical_json_bytes

MAX_SELECTION_BYTES = 64 * 1024
_SCHEMA = "umi-writer-history-selection/1"
_PHASES = {
    "prepared",
    "exchange_pending",
    "exchanged",
    "committed",
    "rollback_pending",
    "rolled_back",
}
_LOG = logging.getLogger(__name__)


def _root():
    uid = preparation._root_owner_uid()
    if (os.getuid(), os.geteuid()) != (uid, uid):
        raise ValueError("history directory selection requires the root broker")
    return uid


def _journal_path(root, operation):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", operation):
        raise ValueError("history selection requires a stable bounded operation")
    return root / ("history-selection-" + operation + ".json")


def _directory(path, uid, gid=None):
    return list(preparation._private_directory(path, uid, gid))


def _history(path, uid, gid, *, quiescent=True):
    result = {"directory": _directory(path, uid, gid)}
    for name in ("rounds.sqlite3", "rounds.lock"):
        info = (path / name).lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != uid
            or info.st_gid != gid
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
        ):
            raise ValueError("history selection requires original private database and lock")
        # Metadata only: never open/close an SQLite inode to inspect identity.
        result[name] = list(preparation._file_identity(info))
    for suffix in ("-journal", "-wal", "-shm"):
        try:
            info = (path / ("rounds.sqlite3" + suffix)).lstat()
        except FileNotFoundError:
            continue
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != uid
            or info.st_gid != gid
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
        ):
            raise ValueError("history selection has an unsafe SQLite sidecar")
        if quiescent:
            raise ValueError("history selection requires quiescent native databases")
    return result


def _content_stamps(path):
    result = {}
    for name in ("rounds.sqlite3", "rounds.lock"):
        info = (path / name).lstat()
        result[name] = [info.st_size, str(info.st_mtime_ns), str(info.st_ctime_ns)]
    return result


def _read(path):
    raw = preparation._read_root_control_path(path, MAX_SELECTION_BYTES, modes={0o600})
    value = json.loads(raw)
    if (
        canonical_json_bytes(value) != raw
        or value.get("schema") != _SCHEMA
        or value.get("phase") not in _PHASES
    ):
        raise ValueError("history selection journal requires explicit repair")
    return value


def _sync(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write(path, value):
    raw = canonical_json_bytes(value)
    if len(raw) > MAX_SELECTION_BYTES:
        raise ValueError("history selection journal exceeds its bound")
    pending = path.with_suffix(".pending")
    # The root-private parent and held native preparation lock serialize writes.
    # A previous pending file is retained for explicit repair, never overwritten.
    descriptor = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        remaining = memoryview(raw)
        while remaining:
            written = os.write(descriptor, remaining)
            if not written:
                raise OSError("history selection journal write made no progress")
            remaining = remaining[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(pending, path)
    _sync(path.parent)


def _repair_pending(path, value, *, initial=False):
    """A torn unpublished state changes no directory; validate before dropping it."""
    pending = path.with_suffix(".pending")
    if not pending.exists() and not pending.is_symlink():
        return
    descriptor = os.open(pending, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != _root()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or not 0 <= before.st_size <= MAX_SELECTION_BYTES
        ):
            raise ValueError("pending history selection file is unsafe")
        raw = os.read(descriptor, MAX_SELECTION_BYTES + 1)
        after = os.fstat(descriptor)
        if (
            preparation._file_identity(before),
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            preparation._file_identity(after),
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) or len(raw) != before.st_size:
            raise ValueError("pending history selection changed while reading")
    finally:
        os.close(descriptor)
    # A crash before replace leaves an unpublished phase. Native commit requires
    # successful publication; recovery conservatively follows the older phase.
    phases = {"prepared"} if initial else _PHASES
    if not any(canonical_json_bytes({**value, "phase": phase}).startswith(raw) for phase in phases):
        raise ValueError("pending history selection differs; explicit repair required")
    pending.unlink()
    _sync(path.parent)


def _report(started, phase, *, completed=0, state="running"):
    elapsed = time.monotonic() - started
    finished = state == "completed"
    _LOG.info(
        "writer_history_selection_progress %s",
        {
            "stage": "writer_history_directory_selection",
            "phase": phase,
            "state": state,
            "completed_items": completed,
            "total_items": 3,
            "percent": 100.0 * completed / 3,
            "elapsed_seconds": elapsed,
            "eta_seconds": 0.0 if finished else None,
            "planning_eta_seconds": [0, max(0, 5 - elapsed)]
            if state == "running" and elapsed <= 5
            else None,
            "eta_basis": "completed"
            if finished
            else "local_atomic_directory_operations"
            if state == "running" and elapsed <= 5
            else "withdrawn",
            "eta_scope": "directory_selection_only_excludes_native_reconciliation_and_rewards",
            "chain_submission_authorized": False,
        },
    )


def _exchange(original, staged):
    function = getattr(ctypes.CDLL(None, use_errno=True), "renameat2", None)
    if function is None:
        raise ValueError("atomic history selection requires Linux renameat2")
    function.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    function.restype = ctypes.c_int
    left = os.open(original.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        right = os.open(staged.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            if function(left, os.fsencode(original.name), right, os.fsencode(staged.name), 2):
                raise OSError(ctypes.get_errno(), "atomic history directory exchange failed")
            os.fsync(left)
            os.fsync(right)
        finally:
            os.close(right)
    finally:
        os.close(left)


def _placement(value, *, allow_busy=False):
    uid, gid = value["service_uid"], value["service_gid"]
    original, staged = Path(value["original"]), Path(value["staged"])
    current = (
        _history(original, uid, gid, quiescent=not allow_busy),
        _history(staged, uid, gid),
    )
    before = (value["original_identity"], value["staged_identity"])
    if current == before:
        if allow_busy:
            _history(original, uid, gid)
        return "original"
    if current == before[::-1]:
        return "selected"
    raise ValueError("history selection directory or database identity changed; repair required")


class WriterHistorySelection:
    """Root mechanical selection under a genuine already-held staging lease."""

    def __init__(self, lease, *, operation):
        self.started = time.monotonic()
        _report(self.started, "authenticating")
        _root()
        preparation.validate_history_preparation_lease(lease)
        self.lease, self.active = lease, True
        self.original, self.staged = lease.logical_history, lease.staged_history
        root = Path(lease.approval.preparation_directory)
        self.path = _journal_path(root, operation)
        uid, gid = lease._anchor.service_uid, lease.approval.service_gid
        original, staged = _history(self.original, uid, gid), _history(self.staged, uid, gid)
        if original["directory"][0] != staged["directory"][0]:
            raise ValueError("history selection requires the same filesystem")
        if original["directory"][:2] == staged["directory"][:2]:
            raise ValueError("history selection requires disjoint original and staged directories")
        self.value = {
            "schema": _SCHEMA,
            "operation": operation,
            "phase": "prepared",
            "preparation_approval": digest(lease.approval),
            "boot": digest(lease.config),
            "anchor": lease._anchor.receipt_sha256,
            "preparation_scope": lease._lock_bytes.decode(),
            "preparation_lock": list(lease._lock_identity),
            "root": _directory(root, _root()),
            "original_parent": _directory(self.original.parent, uid, gid),
            "original": str(self.original),
            "staged": str(self.staged),
            "original_identity": original,
            "staged_identity": staged,
            "original_content": _content_stamps(self.original),
            "staged_content": _content_stamps(self.staged),
            "service_uid": uid,
            "service_gid": gid,
        }
        if self.path.exists() or self.path.is_symlink():
            existing = _read(self.path)
            comparable = {**existing, "phase": "prepared"}
            if comparable != self.value or existing["phase"] not in {"prepared", "rolled_back"}:
                raise ValueError("history selection requires recovery or a new operation")
            self.value = existing
            _repair_pending(self.path, self.value)
        else:
            _repair_pending(self.path, self.value, initial=True)
            _write(self.path, self.value)
        self.recheck()
        _report(self.started, "prepared", completed=1)

    def recheck(self, *, allow_busy=False):
        _root()
        if not self.active:
            raise ValueError("history selection lifetime is closed")
        lease = self.lease
        # Do not mutate or rebind the preparation lease when its history moves.
        # Its genuine issuer, original scope, controls and descriptor stay held.
        if (
            type(lease) is not preparation.StandingHistoryPreparationLease
            or lease._issuer is not preparation._ISSUER
            or not lease._state.held
            or lease._binding != preparation._binding(lease)
        ):
            raise ValueError("history selection lost its genuine preparation lease")
        _validate_scope(
            self.value,
            lease._anchor,
            lease.approval,
            lease.config,
            lease._lock_bytes,
            lease._descriptor,
        )
        for path, maximum, stamp, checksum in lease._controls:
            if preparation._control(path, maximum)[1] != (path, maximum, stamp, checksum):
                raise ValueError("history selection sealed controls changed")
        if _read(self.path) != self.value:
            raise ValueError("history selection journal changed during ownership")
        return _placement(
            self.value,
            allow_busy=allow_busy and self.value["phase"] in {"exchanged", "committed"},
        )

    def _phase(self, phase):
        updated = {**self.value, "phase": phase}
        _write(self.path, updated)
        self.value = updated

    def exchange(self):
        placement = self.recheck()
        if self.value["phase"] == "committed":
            if placement != "selected":
                raise ValueError("committed history selection lost its selected directory")
            return
        if placement == "original":
            self._check_frozen_inputs()
            self._phase("exchange_pending")
            self.recheck()
            self._check_frozen_inputs()
            _exchange(self.original, self.staged)
        self.recheck()
        self._phase("exchanged")
        _report(self.started, "exchanged", completed=2)

    def _check_frozen_inputs(self):
        # The same-live native child has drained its original writes before the
        # caller enters this scope. Candidate native replay after exchange may
        # persist legitimate metadata; its result is separately reconciled by
        # that child's original owner, never inferred from these stamps.
        if (
            _content_stamps(self.original) != self.value["original_content"]
            or _content_stamps(self.staged) != self.value["staged_content"]
        ):
            raise ValueError("history database bytes changed before directory exchange")

    def commit(self):
        if self.recheck() != "selected" or self.value["phase"] not in {"exchanged", "committed"}:
            raise ValueError("history selection must be exchanged and natively reconciled")
        if self.value["phase"] != "committed":
            self._phase("committed")
        _report(self.started, "committed", completed=3, state="completed")

    def rollback(self):
        placement = self.recheck()
        if self.value["phase"] == "committed":
            raise ValueError("committed history selection needs a separately qualified rollback")
        self._phase("rollback_pending")
        if placement == "selected":
            self.recheck()
            _exchange(self.original, self.staged)
        if self.recheck() != "original":
            raise ValueError("history rollback did not restore its original directory")
        self._phase("rolled_back")
        self.lease.recheck()
        _report(self.started, "rolled_back", completed=3, state="completed")


def _validate_scope(value, anchor, approval, config, scope_bytes, descriptor):
    if type(anchor) is not MaterializedSuccessorAnchor:
        raise ValueError("history selection requires its genuine installed anchor")
    anchor.recheck_for_parent_repair()
    root = Path(approval.preparation_directory)
    selected = config.series if approval.history == "current" else config.predecessor_series
    logical = Path(anchor.config.state_root) / "standing-rewards" / digest(selected) / "history"
    preparation._root_ancestors(root)
    preparation._no_preparation_mounts(root)
    preparation._disjoint_preparation(root, preparation._protected_roots(anchor, config))
    scope = json.loads(scope_bytes)
    expected_scope = {
        "approval": digest(approval),
        "boot": hashlib.sha256(canonical_json_bytes(config)).hexdigest(),
        "root": value["root"],
        "history": value["staged_identity"]["directory"],
        "logical_history": str(logical),
    }
    if (
        scope != expected_scope
        or canonical_json_bytes(scope) != scope_bytes
        or value["preparation_scope"].encode() != scope_bytes
        or value["preparation_approval"] != digest(approval)
        or value["boot"] != digest(config)
        or value["anchor"] != anchor.receipt_sha256
        or approval.source_config_sha256 != digest(anchor.config)
        or approval.installation_receipt_sha256 != anchor.receipt_sha256
        or approval.standing_boot_raw_sha256 != expected_scope["boot"]
        or approval.series_sha256 != digest(selected)
        or approval.chain_config_sha256 != digest(config.chain)
        or approval.verifier_semantics != preparation.runtime_identity()
        or value["service_uid"] != anchor.service_uid
        or value["service_gid"] != approval.service_gid
        or preparation._service_gid(anchor.service_uid) != approval.service_gid
        or value["original"] != str(logical)
        or value["staged"] != str(root / "history")
        or _directory(root, _root()) != value["root"]
        or _directory(logical.parent, anchor.service_uid, approval.service_gid)
        != value["original_parent"]
    ):
        raise ValueError("history selection changed its sealed installed scope")
    named = preparation._lock_file(root / "preparation.lock")
    try:
        if (
            list(preparation._file_identity(os.fstat(named))) != value["preparation_lock"]
            or list(preparation._file_identity(os.fstat(descriptor))) != value["preparation_lock"]
            or os.pread(descriptor, MAX_SELECTION_BYTES + 1, 0) != scope_bytes
        ):
            raise ValueError("history selection changed its original preparation lock")
        try:
            fcntl.flock(named, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            pass
        else:
            fcntl.flock(named, fcntl.LOCK_UN)
            raise ValueError("history selection lost its exclusive staging ownership")
    finally:
        os.close(named)
    private_path(str(logical))


@contextmanager
def hold_writer_history_selection(lease, *, operation):
    """Caller keeps native ownership alive; uncommitted exit restores both paths."""
    selection = WriterHistorySelection(lease, operation=operation)
    try:
        yield selection
    finally:
        try:
            if selection.value["phase"] != "committed":
                selection.rollback()
        finally:
            selection.active = False


def recover_writer_history_selection(anchor, *, standing_boot, approval_path, operation):
    """Restore an interrupted root exchange; never authorize or commit a candidate.

    Call only under the broker's authenticated stopped native owner. This acquires
    the real original staging lock directly because a moved directory cannot
    satisfy an ordinary preparation lease. It restores the sealed old mapping,
    after which the caller can reacquire the genuine lease normally.
    """
    started = time.monotonic()
    _report(started, "recovery_authentication")
    _root()
    approval_raw, approval_control = preparation._control(
        Path(approval_path), preparation.MAX_PREPARATION_CONTROL_BYTES
    )
    boot_raw, boot_control = preparation._control(Path(standing_boot), MAX_BOOT_BYTES)
    approval = preparation.StandingHistoryPreparationApproval.model_validate_json(approval_raw)
    config = StandingRewardBootConfig.model_validate_json(boot_raw)
    if canonical_json_bytes(approval) != approval_raw or canonical_json_bytes(config) != boot_raw:
        raise ValueError("history recovery requires original canonical controls")
    root = Path(approval.preparation_directory)
    path = _journal_path(root, operation)
    value = _read(path)
    if value["operation"] != operation:
        raise ValueError("history recovery operation differs")
    descriptor = preparation._lock_file(root / "preparation.lock")
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)

        def recheck():
            for selected in (approval_control, boot_control):
                if preparation._control(selected[0], selected[1])[1] != selected:
                    raise ValueError("history recovery sealed controls changed")
            _validate_scope(
                value,
                anchor,
                approval,
                config,
                os.pread(descriptor, MAX_SELECTION_BYTES + 1, 0),
                descriptor,
            )
            if _read(path) != value:
                raise ValueError("history recovery journal changed")
            return _placement(value)

        placement = recheck()
        _repair_pending(path, value)
        _report(started, "recovery_owned", completed=1)
        if value["phase"] == "committed":
            if placement != "selected":
                raise ValueError("committed history selection lost its selected directory")
            _report(started, "committed", completed=3, state="completed")
            return "committed"
        value = {**value, "phase": "rollback_pending"}
        _write(path, value)
        recheck()
        if placement == "selected":
            _exchange(Path(value["original"]), Path(value["staged"]))
        _report(started, "recovery_restored", completed=2)
        if recheck() != "original":
            raise ValueError("history recovery did not restore original directory")
        value = {**value, "phase": "rolled_back"}
        _write(path, value)
        _report(started, "rolled_back", completed=3, state="completed")
        return "rolled_back"
    finally:
        os.close(descriptor)
