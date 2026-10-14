"""Root broker ownership for isolated, non-authorizing history preparation.

This lease owns only a separately approved staging directory. It never acquires
the installed supervisor lock, restores weight approval, opens a history journal,
or starts a process. The actual stopped-owner cutover still requires the native
SuccessorStartupLease and independently qualified history reconciliation.
"""

from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import logging
import os
import pwd
import re
import stat
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field

from .competition_host_activation import _read_root_control_path, _root_owner_uid
from .competition_host_anchor import MaterializedSuccessorAnchor
from .competition_reward_boot import MAX_BOOT_BYTES, StandingRewardBootConfig
from .competition_verification_rules import runtime_identity
from .competition_work_progress import WorkProgress
from .open_competition import digest, identity
from .private_files import Directory, private_path
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

MAX_PREPARATION_CONTROL_BYTES = 64 * 1024
_ISSUER = object()
_LOG = logging.getLogger("umi.competition.progress")


class HistoryPreparationError(ValueError):
    pass


class StandingHistoryPreparationApproval(StrictProtocolModel):
    """Explicit root approval to prepare one immutable, bounded history scope."""

    schema_: Literal["umi-standing-history-preparation/1"] = Field(alias="schema")
    source_config_sha256: Hex32
    installation_receipt_sha256: Hex32
    standing_boot_raw_sha256: Hex32
    series_sha256: Hex32
    chain_config_sha256: Hex32
    verifier_semantics: Hex32
    history: Literal["current", "predecessor"]
    through_block: Annotated[int, Field(ge=0, lt=2**53)]
    preparation_directory: Directory
    service_gid: Annotated[int, Field(ge=1, lt=2**32)]
    reason: Annotated[str, Field(min_length=1, max_length=4096)]


@dataclass
class _LeaseState:
    held: bool = True


@dataclass(frozen=True, slots=True)
class StandingHistoryPreparationLease:
    """Process-local staging ownership; unusable as startup or history authority."""

    approval: StandingHistoryPreparationApproval
    config: StandingRewardBootConfig
    logical_history: Path
    staged_history: Path
    first_block: int
    _anchor: MaterializedSuccessorAnchor = field(repr=False)
    _controls: tuple = field(repr=False)
    _directories: tuple = field(repr=False)
    _descriptor: int = field(repr=False)
    _lock_identity: tuple = field(repr=False)
    _lock_bytes: bytes = field(repr=False)
    _state: _LeaseState = field(repr=False, compare=False)
    _issuer: object = field(default=None, repr=False, compare=False)
    _binding: str = field(default="", repr=False, compare=False)

    def recheck(self):
        validate_history_preparation_lease(self)


def _file_identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode, info.st_nlink)


def _private_directory(path, uid, gid=None):
    private_path(str(path))
    info = path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != uid
        or (gid is not None and info.st_gid != gid)
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise HistoryPreparationError("preparation directory owner or mode changed")
    return _file_identity(info)


def _root_ancestors(path):
    private_path(str(path))
    for parent in path.parents:
        info = parent.stat()
        # Root-owned sticky ancestors support isolated maintenance roots.
        if (info.st_uid not in {0, _root_owner_uid()} or info.st_mode & 0o022) and not (
            info.st_uid == 0 and info.st_mode & stat.S_ISVTX
        ):
            raise HistoryPreparationError("preparation has an untrusted ancestor")


def _service_gid(uid):
    return pwd.getpwuid(uid).pw_gid


def _no_preparation_mounts(root):
    # A mount on or below staging can alias a live journal despite different
    # lexical paths. Decode the kernel's escaped path representation first.
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        mount = Path(re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), line.split()[4]))
        if mount == root or root in mount.parents:
            raise HistoryPreparationError("preparation subtree contains a mount")


def _protected_roots(anchor, config):
    from .competition_coordinator_namespace import active_coordinator_view

    paths = (
        *config.mutable_stores(),
        Path(anchor.config.state_root),
        Path(anchor.config.worker_state_root),
        Path(anchor.config.wallet.path),
    )
    view = active_coordinator_view()
    if view is not None:
        view.recheck()
        paths += (view.layout.root_directory, *(view.layout.bind_source(p) for p in paths))
    return paths


def _backing_path(path, mounts):
    candidates = [entry for entry in mounts if path == entry[2] or entry[2] in path.parents]
    depth = max(len(entry[2].parts) for entry in candidates)
    deepest = {entry for entry in candidates if len(entry[2].parts) == depth}
    if len(deepest) != 1:
        raise HistoryPreparationError("preparation backing mount is ambiguous")
    selected = deepest.pop()
    device, root, mount = selected
    return device, root / path.relative_to(mount)


def _disjoint_preparation(root, protected):
    def decoded(field):
        return Path(re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), field))

    mounts = []
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        fields = line.split()
        mounts.append((fields[2], decoded(fields[3]), decoded(fields[4])))
    device, backing = _backing_path(root, mounts)
    for path in protected:
        other_device, other_backing = _backing_path(path, mounts)
        if (root.is_relative_to(path) or path.is_relative_to(root)) or (
            device == other_device
            and (backing.is_relative_to(other_backing) or other_backing.is_relative_to(backing))
        ):
            raise HistoryPreparationError("preparation overlaps installed mutable state")


def _control(path, maximum):
    _root_ancestors(path)
    before = path.lstat()
    raw = _read_root_control_path(path, maximum, modes={0o444})
    after = path.lstat()
    stamp = (*_file_identity(before), before.st_size, before.st_mtime_ns, before.st_ctime_ns)
    if stamp != (*_file_identity(after), after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise HistoryPreparationError("preparation control changed during read")
    return raw, (path, maximum, stamp, hashlib.sha256(raw).hexdigest())


def _binding(lease):
    return hashlib.sha256(
        canonical_json_bytes(
            {
                "approval": digest(lease.approval),
                "boot": digest(lease.config),
                "logical": str(lease.logical_history),
                "staged": str(lease.staged_history),
                "first": lease.first_block,
                "anchor": lease._anchor.receipt_sha256,
                "controls": [
                    [str(p), maximum, [str(v) for v in stamp], sha]
                    for p, maximum, stamp, sha in lease._controls
                ],
                "directories": [
                    [str(p), uid, gid, list(stamp)] for p, uid, gid, stamp in lease._directories
                ],
                "descriptor": lease._descriptor,
                "lock_identity": list(lease._lock_identity),
                "lock_sha256": hashlib.sha256(lease._lock_bytes).hexdigest(),
                "state_identity": id(lease._state),
            }
        )
    ).hexdigest()


def _lock_file(path, *, create=False):
    descriptor = os.open(path, (os.O_CREAT if create else 0) | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != _root_owner_uid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size > MAX_PREPARATION_CONTROL_BYTES
        ):
            raise HistoryPreparationError("preparation lock identity is unsafe")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def validate_history_preparation_lease(lease):
    if (
        type(lease) is not StandingHistoryPreparationLease
        or lease._issuer is not _ISSUER
        or not lease._state.held
        or lease._binding != _binding(lease)
    ):
        raise HistoryPreparationError("preparation lease is absent, altered or closed")
    lease._anchor.recheck_for_parent_repair()
    if runtime_identity() != lease.approval.verifier_semantics:
        raise HistoryPreparationError("preparation verifier semantics changed")
    if _service_gid(lease._anchor.service_uid) != lease.approval.service_gid:
        raise HistoryPreparationError("preparation service account group changed")
    _no_preparation_mounts(Path(lease.approval.preparation_directory))
    _disjoint_preparation(
        Path(lease.approval.preparation_directory), _protected_roots(lease._anchor, lease.config)
    )
    for path, maximum, stamp, checksum in lease._controls:
        _, current = _control(path, maximum)
        if current != (path, maximum, stamp, checksum):
            raise HistoryPreparationError("sealed preparation selection changed")
    for path, uid, gid, stamp in lease._directories:
        if _private_directory(path, uid, gid) != stamp:
            raise HistoryPreparationError("preparation directory identity changed")
    named = _lock_file(Path(lease.approval.preparation_directory) / "preparation.lock")
    try:
        if (
            _file_identity(os.fstat(named)) != lease._lock_identity
            or _file_identity(os.fstat(lease._descriptor)) != lease._lock_identity
            or os.pread(lease._descriptor, MAX_PREPARATION_CONTROL_BYTES + 1, 0)
            != lease._lock_bytes
        ):
            raise HistoryPreparationError("preparation lock identity or bytes changed")
        try:
            fcntl.flock(named, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            pass
        else:
            fcntl.flock(named, fcntl.LOCK_UN)
            raise HistoryPreparationError("preparation lease lost exclusive ownership")
    finally:
        os.close(named)


@contextmanager
def hold_history_preparation_lease(anchor, *, standing_boot: Path, approval_path: Path):
    """Authenticate explicit staging ownership while the installed writer runs.

    The caller creates the root-private broker directory and a private empty
    history child under the service UID/GID. This operation creates only its
    root-owned lock; no native journal, provider, process or service is opened.
    An existing staging scope cannot silently be retargeted on resume.
    """
    _LOG.info(
        json.dumps(
            {
                "stage": "history_preparation_broker",
                "state": "planning",
                "planning_eta_seconds": [0.05, 5.0],
                "eta_basis": "local_anchor_controls_and_nonblocking_staging_lock",
                "eta_scope": "broker_admission_only_excluding_native_replay",
            },
            separators=(",", ":"),
        )
    )
    with (
        WorkProgress("history_preparation_broker", 3, unit="checks") as progress,
        _hold_history_preparation_lease(
            anchor, standing_boot=standing_boot, approval_path=approval_path, progress=progress
        ) as lease,
    ):
        progress.finish()
        yield lease


def _authenticated_scope(anchor, *, standing_boot, approval_path):
    """Authenticate immutable controls and directories without taking ownership."""
    if (os.getuid(), os.geteuid()) != (_root_owner_uid(), _root_owner_uid()):
        raise HistoryPreparationError("history preparation requires the root broker")
    if type(anchor) is not MaterializedSuccessorAnchor:
        raise HistoryPreparationError("preparation requires a genuine installed anchor")
    anchor.recheck_for_parent_repair()
    approval_raw, approval_control = _control(approval_path, MAX_PREPARATION_CONTROL_BYTES)
    approval = StandingHistoryPreparationApproval.model_validate_json(approval_raw)
    boot_raw, boot_control = _control(standing_boot, MAX_BOOT_BYTES)
    config = StandingRewardBootConfig.model_validate_json(boot_raw)
    selected = config.series if approval.history == "current" else config.predecessor_series
    if (
        canonical_json_bytes(approval) != approval_raw
        or canonical_json_bytes(config) != boot_raw
        or not approval.reason.strip()
        or approval.source_config_sha256 != digest(anchor.config)
        or approval.installation_receipt_sha256 != anchor.receipt_sha256
        or approval.standing_boot_raw_sha256 != hashlib.sha256(boot_raw).hexdigest()
        or selected is None
        or approval.series_sha256 != digest(selected)
        or approval.chain_config_sha256 != digest(config.chain)
        or approval.verifier_semantics != runtime_identity()
        or identity(anchor.config.validator_hotkey)
        not in {identity(k) for k in selected.validators}
        or approval.through_block < selected.recovery.authority.issued_at_block
    ):
        raise HistoryPreparationError("preparation differs from its installed native scope")
    root = Path(approval.preparation_directory)
    history = root / "history"
    if _service_gid(anchor.service_uid) != approval.service_gid:
        raise HistoryPreparationError("preparation service account group differs")
    _no_preparation_mounts(root)
    _root_ancestors(root)
    root_stamp = _private_directory(root, _root_owner_uid())
    history_stamp = _private_directory(history, anchor.service_uid, approval.service_gid)
    _disjoint_preparation(root, _protected_roots(anchor, config))
    logical = Path(anchor.config.state_root) / "standing-rewards" / digest(selected) / "history"
    payload = canonical_json_bytes(
        {
            "approval": digest(approval),
            "boot": hashlib.sha256(boot_raw).hexdigest(),
            "root": list(root_stamp),
            "history": list(history_stamp),
            "logical_history": str(logical),
        }
    )
    return (
        approval,
        config,
        logical,
        selected,
        root,
        history,
        root_stamp,
        history_stamp,
        payload,
        (approval_control, boot_control),
    )


@contextmanager
def _hold_history_preparation_lease(anchor, *, standing_boot, approval_path, progress):
    (
        approval,
        config,
        logical,
        selected,
        root,
        history,
        root_stamp,
        history_stamp,
        payload,
        controls,
    ) = _authenticated_scope(anchor, standing_boot=standing_boot, approval_path=approval_path)
    progress.advance()
    progress.advance()
    descriptor = _lock_file(root / "preparation.lock", create=True)
    lease = None
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        old = os.pread(descriptor, MAX_PREPARATION_CONTROL_BYTES + 1, 0)
        if not old or (len(old) < len(payload) and payload.startswith(old)):
            # No worker can launch before this durable record is complete. A
            # torn first write is repairable only while native staging is empty;
            # never reconstruct a lost binding over existing journal contents.
            if any(history.iterdir()):
                raise HistoryPreparationError("preparation scope repair requires empty staging")
            os.lseek(descriptor, 0, os.SEEK_SET)
            pending = memoryview(payload)
            while pending:
                pending = pending[os.write(descriptor, pending) :]
            os.fsync(descriptor)
            directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        elif old != payload:
            raise HistoryPreparationError("retained preparation cannot change scope or identity")
        lease = StandingHistoryPreparationLease(
            approval,
            config,
            logical,
            history,
            selected.recovery.authority.issued_at_block,
            anchor,
            controls,
            (
                (root, _root_owner_uid(), None, root_stamp),
                (history, anchor.service_uid, approval.service_gid, history_stamp),
            ),
            descriptor,
            _file_identity(os.fstat(descriptor)),
            payload,
            _LeaseState(),
            _ISSUER,
        )
        object.__setattr__(lease, "_binding", _binding(lease))
        lease.recheck()
        progress.advance()
        yield lease
    finally:
        if lease is not None:
            lease._state.held = False
        try:
            current = os.fstat(descriptor)
        except OSError as error:
            if error.errno != errno.EBADF:
                raise
        else:
            if lease is not None and _file_identity(current) != lease._lock_identity:
                raise HistoryPreparationError("preparation descriptor was replaced before close")
            os.close(descriptor)
