"""Offline preparation only: keep the original, create a separate bounded candidate.

This is not a stopped-host authorization or a storage selector. The caller must
establish process absence and coordinate host-wide disk reservations. A private
lock prevents cooperative writers, not an independently restarted service. On
failure the original remains selected; the partial candidate is left for review.
Resuming explicitly requires the same persisted plan. No source or candidate
history is discarded on resume; only an uncommitted SQLite copy is retried.
"""

from __future__ import annotations

import fcntl
import hashlib
import os
import sqlite3
import stat
from contextlib import ExitStack
from dataclasses import asdict
from pathlib import Path

from .competition_evidence_codec import checked_digest, checked_size
from .competition_evidence_copy import (
    copy_legacy_weight_journal,
    verify_copied_legacy_weight_journal,
)
from .competition_evidence_store import EvidenceStore
from .competition_evidence_worker import EvidenceWorkerProfile, bind_worker_profile
from .competition_package import _file_identity
from .competition_weights import _recovery_journal_snapshot
from .competition_worker import (
    CompetitionReplayWorker,
    _canonical_absolute_path,
    _open_directory_without_links,
    _open_private_regular_file,
)
from .protocol import canonical_json_bytes

_DATABASE = "competition-weights.sqlite3"
_LOCK = "competition-weights.lock"
_RECEIPT = "evidence-preparation.json"
_PLAN = "evidence-preparation-plan.json"
_MAX_DATABASE_BYTES = 32 * 1024**3


def _hash_file(descriptor: int, maximum: int) -> str:
    before = os.fstat(descriptor)
    if before.st_size > maximum:
        raise ValueError("preparation file exceeds physical bound")
    os.lseek(descriptor, 0, os.SEEK_SET)
    result = hashlib.sha256()
    total = 0
    while chunk := os.read(descriptor, 1024**2):
        total += len(chunk)
        if total > maximum:
            raise ValueError("preparation file grew beyond bound")
        result.update(chunk)
    if total != before.st_size or _file_identity(os.fstat(descriptor)) != _file_identity(before):
        raise ValueError("preparation file changed while hashing")
    return result.hexdigest()


def _write_control(root: int, name: str, raw: bytes):
    if len(raw) > 16 * 1024:
        raise ValueError("preparation control exceeds bound")

    def read_private(name):
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=root)
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid != os.geteuid()
                or info.st_mode & 0o777 != 0o600
                or info.st_size > 16 * 1024
            ):
                raise ValueError("unsafe preparation control")
            return os.read(descriptor, 16 * 1024 + 1)
        finally:
            os.close(descriptor)

    try:
        existing = read_private(name)
    except FileNotFoundError:
        pass
    else:
        if existing != raw:
            raise ValueError("preparation control changed")
        return
    pending = "." + name + ".pending"
    try:
        descriptor = os.open(
            pending, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=root
        )
    except FileExistsError:
        # Only our exact bounded interrupted control write is disposable.
        if not raw.startswith(read_private(pending)):
            raise ValueError("interrupted preparation control differs from plan") from None
        descriptor = os.open(pending, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=root)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o777 != 0o600
            or info.st_size > len(raw)
            or not raw.startswith(os.read(descriptor, len(raw) + 1))
        ):
            raise ValueError("interrupted control ownership or content changed")
        os.ftruncate(descriptor, 0)
        os.lseek(descriptor, 0, os.SEEK_SET)
        with os.fdopen(descriptor, "wb", closefd=False) as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
    finally:
        os.close(descriptor)
    # rename is atomic. The source lock excludes another cooperative preparer;
    # an existing complete control is never overwritten on the resume path.
    os.rename(pending, name, src_dir_fd=root, dst_dir_fd=root)
    os.fsync(root)


def _write_receipt(root: int, raw: bytes):
    _write_control(root, _RECEIPT, raw)


def prepare_legacy_candidate(
    source_root: Path,
    candidate_root: Path,
    *,
    expected_source_sha256: str,
    expected_binding_sha256: str,
    profile: EvidenceWorkerProfile,
    maximum_database_bytes: int,
    minimum_free_bytes: int,
    resume: bool = False,
) -> dict:
    """Prepare/resume exact-byte history under both locks, without selecting it.

    Source must be a clean private legacy database with no SQLite sidecars.
    max_page_count limits candidate pages. Free space is checked conservatively
    for two candidate-sized files plus the host's explicit reserve; that check
    is not a persistent allocation against other host consumers.
    """
    source_root = _canonical_absolute_path(source_root, "source weight root")
    candidate_root = _canonical_absolute_path(candidate_root, "candidate weight root")
    if source_root.is_relative_to(candidate_root) or candidate_root.is_relative_to(source_root):
        raise ValueError("preparation needs disjoint source and candidate directories")
    checked_digest(expected_source_sha256)
    checked_digest(expected_binding_sha256)
    checked_size(maximum_database_bytes, _MAX_DATABASE_BYTES, minimum=4096)
    checked_size(minimum_free_bytes, 1024**4, minimum=1)
    source_path, candidate_path = source_root / _DATABASE, candidate_root / _DATABASE
    with ExitStack() as stack:
        source_lock = _open_private_regular_file(source_root / _LOCK, "source weight lock")
        stack.callback(os.close, source_lock)
        fcntl.flock(source_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        lock_identity = _file_identity(os.fstat(source_lock))
        before = _recovery_journal_snapshot(source_path)
        if any(identity is not None for _suffix, identity in before[1][1:]):
            raise ValueError("source has SQLite sidecars; native stopped recovery is required")
        source_file = _open_private_regular_file(source_path, "source weight database")
        stack.callback(os.close, source_file)
        if _hash_file(source_file, _MAX_DATABASE_BYTES) != expected_source_sha256:
            raise ValueError("source database does not match the expected frozen bytes")
        source = sqlite3.connect(source_path.as_uri() + "?mode=ro", uri=True, isolation_level=None)
        stack.callback(source.close)
        source.execute("PRAGMA query_only=ON")
        source.execute("BEGIN")
        if source.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
            raise ValueError("source SQLite integrity check failed")
        parent = _open_directory_without_links(candidate_root.parent)
        stack.callback(os.close, parent)
        disk = os.fstatvfs(parent)
        required = 2 * maximum_database_bytes + minimum_free_bytes + 1024**2
        if disk.f_bavail * disk.f_frsize < required:
            raise ValueError("insufficient disk for candidate, rollback allowance and host reserve")
        plan = canonical_json_bytes(
            {
                "schema": "umi-weight-evidence-preparation-plan/1",
                "source_root": str(source_root),
                "candidate_root": str(candidate_root),
                "expected_source_sha256": expected_source_sha256,
                "expected_binding_sha256": expected_binding_sha256,
                "profile": asdict(profile),
                "maximum_database_bytes": maximum_database_bytes,
                "minimum_free_bytes": minimum_free_bytes,
            }
        )
        try:
            os.mkdir(candidate_root.name, mode=0o700, dir_fd=parent)
            os.fsync(parent)
        except FileExistsError:
            if not resume:
                raise
        root = _open_directory_without_links(candidate_root)
        stack.callback(os.close, root)
        info = os.fstat(root)
        if info.st_uid != os.geteuid() or info.st_mode & 0o777 != 0o700:
            raise ValueError("candidate root must be private")
        if not (candidate_root / _PLAN).exists() and set(os.listdir(root)) - {
            "." + _PLAN + ".pending"
        }:
            raise ValueError("cannot resume an unrecorded candidate")
        _write_control(root, _PLAN, plan)
        allowed = {
            _PLAN,
            _RECEIPT,
            "." + _RECEIPT + ".pending",
            _DATABASE,
            _LOCK,
            _DATABASE + "-journal",
        }
        if set(os.listdir(root)) - allowed:
            raise ValueError("candidate has unexpected files")
        for name in (_DATABASE, _LOCK):
            CompetitionReplayWorker._prepare_state_file(root, name)
        candidate_lock = _open_private_regular_file(candidate_root / _LOCK, "candidate weight lock")
        stack.callback(os.close, candidate_lock)
        fcntl.flock(candidate_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for name in os.listdir(root):
            descriptor = _open_private_regular_file(candidate_root / name, "candidate file")
            try:
                if os.fstat(descriptor).st_size > maximum_database_bytes:
                    raise ValueError("candidate file exceeds physical bound")
            finally:
                os.close(descriptor)
        destination = sqlite3.connect(candidate_path, timeout=10, isolation_level=None)
        try:
            destination.execute("PRAGMA journal_mode=DELETE")
            destination.execute("PRAGMA synchronous=FULL")
            destination.execute("PRAGMA cache_size=-8192")
            page_size = destination.execute("PRAGMA page_size").fetchone()[0]
            pages = maximum_database_bytes // page_size
            actual = destination.execute(f"PRAGMA max_page_count={pages}").fetchone()[0]
            if actual != pages:
                raise ValueError("candidate physical page bound could not be installed")
            destination.execute("BEGIN IMMEDIATE")
            copier = (
                verify_copied_legacy_weight_journal
                if resume and destination.execute("SELECT 1 FROM sqlite_master LIMIT 1").fetchone()
                else copy_legacy_weight_journal
            )
            copied = copier(
                source,
                destination,
                expected_binding_sha256=expected_binding_sha256,
                limits=profile.limits,
            )
            bind_worker_profile(destination, profile, create=copier is copy_legacy_weight_journal)
            destination.commit()
            candidate_snapshot = _recovery_journal_snapshot(candidate_path)
            destination.execute("BEGIN")
            bind_worker_profile(destination, profile)
            usage = EvidenceStore(
                destination,
                owner_binding_sha256=expected_binding_sha256,
                limits=profile.limits,
            ).audit()
            if asdict(usage) != copied["stored_usage"]:
                raise ValueError("candidate changed after copy commit")
            if destination.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
                raise ValueError("candidate SQLite integrity check failed")
        finally:
            destination.close()
        if _recovery_journal_snapshot(candidate_path) != candidate_snapshot:
            raise ValueError("candidate changed during post-commit verification")
        current_lock = _open_private_regular_file(source_root / _LOCK, "source weight lock")
        stack.callback(os.close, current_lock)
        if (
            _recovery_journal_snapshot(source_path) != before
            or _file_identity(os.fstat(source_lock)) != lock_identity
            or _file_identity(os.fstat(current_lock)) != lock_identity
            or _hash_file(source_file, _MAX_DATABASE_BYTES) != expected_source_sha256
        ):
            raise ValueError("source history or ownership changed during preparation")
        descriptor = _open_private_regular_file(candidate_path, "candidate weight database")
        stack.callback(os.close, descriptor)
        os.fsync(descriptor)
        os.fsync(root)
        candidate_digest = _hash_file(descriptor, maximum_database_bytes)
        if _recovery_journal_snapshot(candidate_path) != candidate_snapshot:
            raise ValueError("candidate changed after verification")
        receipt = {
            "schema": "umi-weight-evidence-preparation/1",
            "source_root": str(source_root),
            "candidate_root": str(candidate_root),
            "source_database_sha256": expected_source_sha256,
            "candidate_database_sha256": candidate_digest,
            "candidate_database_bytes": os.fstat(descriptor).st_size,
            "maximum_database_bytes": maximum_database_bytes,
            "minimum_free_bytes": minimum_free_bytes,
            "worker_profile_sha256": hashlib.sha256(profile.encoded()).hexdigest(),
            "copy": copied,
            "source_selection_changed": False,
            "activation_authorized": False,
            "root_sealed": False,
            "signature_required": True,
        }
        _write_receipt(root, canonical_json_bytes(receipt))
        return receipt
