"""Read-only stopped-owner snapshots and private preflight checkpoints.

No inspected SQLite connection can migrate, repair, checkpoint or write. Derived
receipts live outside inspected state; they never authorize a runtime switch.
The selected service account and its filesystem namespace remain trusted.
"""

from __future__ import annotations

import fcntl
import hashlib
import os
import sqlite3
import stat
import tempfile
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import Literal

from pydantic import Field, JsonValue

from .competition_package import _canonical_absolute_path, _open_directory_without_links
from .competition_verification_reuse import metadata_completion, remember_metadata_completion
from .private_files import ensure_private_directory, lock_private_file, publish_private_model
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

MAX_CHECKPOINT_BYTES = 64 * 1024**2


class TransitionPreflightRefused(ValueError):
    """An inspection prerequisite needs recovery or a different selected layout."""


def _identity(info: os.stat_result) -> tuple[str, ...]:
    return tuple(
        str(getattr(info, name))
        for name in (
            "st_dev",
            "st_ino",
            "st_size",
            "st_mode",
            "st_uid",
            "st_gid",
            "st_mtime_ns",
            "st_ctime_ns",
            "st_nlink",
        )
    )


@contextmanager
def opened_input(path: Path, *, private: bool = True):
    path = _canonical_absolute_path(path, "transition input")
    parent = _open_directory_without_links(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_nlink != 1
                or (private and info.st_mode & 0o077)
            ):
                raise TransitionPreflightRefused(
                    "input_not_owned_regular_private_file: " + str(path)
                )
            before = _identity(info)
            yield fd, before
            if (
                _identity(os.fstat(fd)) != before
                or _identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)) != before
                or _identity(os.stat(path.parent, follow_symlinks=False))[:2]
                != _identity(os.fstat(parent))[:2]
            ):
                raise TransitionPreflightRefused("input_changed_during_inspection: " + str(path))
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def file_identity(path: Path, *, private: bool = True) -> tuple[str, ...]:
    with opened_input(path, private=private) as (_, facts):
        return facts


def bounded_read(path: Path, maximum: int, *, private: bool = True) -> bytes:
    with opened_input(path, private=private) as (fd, before):
        if not 0 < int(before[2]) <= maximum:
            raise TransitionPreflightRefused("input_exceeds_selected_bound: " + str(path))
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(maximum + 1)
        if len(raw) != int(before[2]):
            raise TransitionPreflightRefused("input_changed_during_inspection: " + str(path))
        return raw


def directory_inventory(
    path: Path, *, maximum_entries: int
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Capture exact children and directory identity without following links."""
    path = _canonical_absolute_path(path, "enrollment directory")
    fd = _open_directory_without_links(path)
    try:
        info = os.fstat(fd)
        if info.st_uid != os.getuid():
            raise TransitionPreflightRefused("enrollment_directory_owner_changed")
        names = []
        with os.scandir(fd) as entries:
            for entry in entries:
                if not entry.is_file(follow_symlinks=False):
                    raise TransitionPreflightRefused("unsupported_enrollment_tree")
                names.append(entry.name)
                if len(names) > maximum_entries:
                    raise TransitionPreflightRefused(
                        "enrollment_inventory_exceeds_selected_grant_capacity"
                    )
        if _identity(os.fstat(fd)) != _identity(info):
            raise TransitionPreflightRefused("enrollment_directory_changed")
        return _identity(info), tuple(sorted(names))
    finally:
        os.close(fd)


def _bound_sqlite_values(db: sqlite3.Connection, maximum: int) -> None:
    """Apply the selected value bound on supported CPython SQLite versions.

    Python 3.10 does not expose sqlite3_limit. Its row factory still rejects
    every returned value before the transition can use it; the larger native
    bodies are also checked with SQL LENGTH before they are selected.
    """
    if type(maximum) is not int or maximum <= 0:
        raise TransitionPreflightRefused("invalid_selected_sqlite_value_bound")
    db.row_factory = sqlite3.Row
    setlimit = getattr(db, "setlimit", None)
    if setlimit is not None:
        setlimit(sqlite3.SQLITE_LIMIT_LENGTH, maximum)
        return

    def bounded_row(cursor, values):
        if any(
            isinstance(value, (str, bytes, bytearray, memoryview)) and len(value) > maximum
            for value in values
        ):
            raise TransitionPreflightRefused("retained_sqlite_value_exceeds_selected_bound")
        return sqlite3.Row(cursor, values)

    db.row_factory = bounded_row


@contextmanager
def stopped_snapshots(
    databases: tuple[tuple[Path, Path], ...], *, maximum_value_bytes: int
) -> Iterator[tuple[sqlite3.Connection, ...]]:
    if not Path("/proc/self/fd").is_dir():
        raise TransitionPreflightRefused("descriptor_snapshot_requires_qualified_linux_runtime")
    with ExitStack() as stack:
        handles = []
        for path, lock in databases:
            lock_fd, _ = stack.enter_context(opened_input(lock))
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise TransitionPreflightRefused("owner_active: " + str(path)) from error
            fd, facts = stack.enter_context(opened_input(path))
            for suffix in ("-journal", "-wal", "-shm"):
                sidecar = Path(str(path) + suffix)
                if sidecar.exists() or sidecar.is_symlink():
                    raise TransitionPreflightRefused("database_recovery_required: " + str(sidecar))
            header = os.pread(fd, 100, 0)
            if header[:16] != b"SQLite format 3\0" or header[18:20] not in (
                b"\x01\x01",
                b"\x02\x02",
            ):
                raise TransitionPreflightRefused("database_requires_supported_sqlite_format")
            handles.append((path, fd, facts))
        connections = []
        for path, fd, facts in handles:
            db = sqlite3.connect(
                f"file:/proc/self/fd/{fd}?mode=ro&immutable=1", uri=True, timeout=0
            )
            stack.callback(db.close)
            # SQLite may canonicalize the descriptor path. Prove that its selected
            # filename still identifies our held original inode before reading.
            selected = Path(db.execute("PRAGMA database_list").fetchone()[2])
            if selected != path or file_identity(selected) != facts:
                raise TransitionPreflightRefused("database_descriptor_selection_changed")
            _bound_sqlite_values(db, maximum_value_bytes)
            db.execute("PRAGMA query_only=ON")
            db.execute("PRAGMA temp_store=MEMORY")
            db.execute("BEGIN")
            connections.append(db)
        yield tuple(connections)
        for path, _, facts in handles:
            if file_identity(path) != facts:
                raise TransitionPreflightRefused("state_changed_during_inspection")
            if any(os.path.lexists(str(path) + suffix) for suffix in ("-journal", "-wal", "-shm")):
                raise TransitionPreflightRefused("database_sidecar_created_during_inspection")


class PreflightReceipt(StrictProtocolModel):
    schema_: Literal["umi-miner-transition-verification/1"] = Field(alias="schema")
    key: Hex32
    result: JsonValue
    checksum: Hex32


class PreflightCheckpoints:
    def __init__(self, directory: Path, *, repair_reason: str | None = None):
        self.directory = directory
        if repair_reason is not None and not repair_reason.strip():
            raise TransitionPreflightRefused("verification_repair_requires_reason")
        self.repair_reason = repair_reason
        ensure_private_directory(directory)

    def get(self, key: str):
        path = self.directory / (key + ".json")
        try:
            raw = bounded_read(path, MAX_CHECKPOINT_BYTES)
            value = PreflightReceipt.model_validate_json(raw)
            if (
                canonical_json_bytes(value) != raw
                or value.key != key
                or value.checksum
                != hashlib.sha256(canonical_json_bytes([key, value.result])).hexdigest()
            ):
                raise ValueError("checkpoint identity or checksum differs")
        except (OSError, ValueError) as error:
            if isinstance(error, FileNotFoundError) and not os.path.lexists(
                metadata_completion(path)
            ):
                return None
            if self.repair_reason:
                return None
            raise TransitionPreflightRefused(
                "verification_metadata_repair_required: " + key
            ) from error
        remember_metadata_completion(path)
        return value.result

    def put(self, key: str, result: JsonValue) -> None:
        value = PreflightReceipt(
            schema="umi-miner-transition-verification/1",
            key=key,
            result=result,
            checksum=hashlib.sha256(canonical_json_bytes([key, result])).hexdigest(),
        )
        raw = canonical_json_bytes(value)
        if len(raw) > MAX_CHECKPOINT_BYTES:
            raise TransitionPreflightRefused("verification_checkpoint_exceeds_bound")
        path = self.directory / (key + ".json")
        if self.repair_reason:
            lock = lock_private_file(self.directory / ".publish.lock")
            temporary = None
            try:
                fd, temporary = tempfile.mkstemp(prefix=".repair-", dir=self.directory)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, path)
                fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
            finally:
                if temporary is not None:
                    Path(temporary).unlink(missing_ok=True)
                os.close(lock)
        else:
            publish_private_model(path, value, maximum_bytes=len(raw))
        remember_metadata_completion(path)
