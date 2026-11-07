"""Private file-bound completion for the native finality mutation owner.

The completion is outside the mutable SQLite database. Its file identities cover
both the database and its WAL, and the native owner holds one lock from the
identity check through SQLite close and publication. Unmanaged mutation cannot
extend this completion. A missing or changed completion requires a stated repair
audit; this module never decides that an unaudited database is valid.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import stat
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

from .protocol import canonical_json_bytes

AUDIT_SEMANTICS = "umi-grandpa-native-audit/1"
_SCHEMA = "umi-grandpa-file-bound-frontier/1"
_MAXIMUM_RECORD_BYTES = 64 * 1024


class FinalityFrontierError(ValueError):
    """The native mutation owner cannot establish its retained completion."""


def _identity(path: Path, *, directory: bool = False):
    info = path.lstat()
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if (
        not kind(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_mode & 0o077
        or (not directory and info.st_nlink != 1)
    ):
        raise FinalityFrontierError("unsafe_frontier_path")
    fields = (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode)
    if not directory:
        fields += (info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    return [str(value) for value in fields]


class FinalityAuditFrontier:
    """Serialize native mutations and bind their successful semantic conclusion."""

    def __init__(self, database: Path, *, busy_timeout_ms: int):
        self.database = database
        self.root = database.with_name(database.name + ".audit-frontier")
        self.record = self.root / "completed.json"
        self.busy_timeout_ms = busy_timeout_ms
        self._owned = False

    @contextmanager
    def owner(self):
        self.root.mkdir(mode=0o700, exist_ok=True)
        root_identity = _identity(self.root, directory=True)
        lock = self.root / "owner.lock"
        fd = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            before = _identity(lock)
            opened = os.fstat(fd)
            if (opened.st_dev, opened.st_ino) != tuple(map(int, before[:2])):
                raise FinalityFrontierError("frontier_lock_replaced")
            deadline = time.monotonic() + self.busy_timeout_ms / 1000
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise FinalityFrontierError("frontier_owner_busy") from None
                    time.sleep(min(0.01, max(0, deadline - time.monotonic())))
            if _identity(self.root, directory=True) != root_identity or _identity(lock) != before:
                raise FinalityFrontierError("frontier_owner_replaced")
            self._owned = True
            try:
                yield
            finally:
                self._owned = False
        finally:
            os.close(fd)

    def snapshot(self):
        if not self._owned:
            raise FinalityFrontierError("frontier_owner_required")
        files = {}
        for suffix in ("", "-wal"):
            path = Path(str(self.database) + suffix)
            try:
                files[suffix] = _identity(path)
            except FileNotFoundError:
                if not suffix:
                    raise FinalityFrontierError("frontier_database_missing") from None
                files[suffix] = None
        # SHM is a disposable SQLite coordination index, not accepted evidence.
        return {"directory": _identity(self.root, directory=True), "files": files}

    @staticmethod
    def binding(config: bytes):
        return {
            "semantics": AUDIT_SEMANTICS,
            "config_sha256": hashlib.sha256(config).hexdigest(),
        }

    def inspect(self, config: bytes):
        """Return a reason, never silently repair or open the SQLite payload."""
        snapshot = self.snapshot()
        try:
            before = _identity(self.record)
            if int(before[5]) > _MAXIMUM_RECORD_BYTES:
                return "completion_record_oversized"
            fd = os.open(self.record, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, "rb") as stream:
                opened = os.fstat(stream.fileno())
                if (opened.st_dev, opened.st_ino) != tuple(map(int, before[:2])):
                    return "completion_record_replaced"
                raw = stream.read(_MAXIMUM_RECORD_BYTES + 1)
            if _identity(self.record) != before:
                return "completion_record_changed"
            value = json.loads(raw)
            if (
                not isinstance(value, dict)
                or set(value) != {"schema", "binding", "snapshot"}
                or value["schema"] != _SCHEMA
                or canonical_json_bytes(value) != raw
            ):
                return "completion_record_damaged"
        except FileNotFoundError:
            return "completion_record_missing"
        except (ValueError, UnicodeError):
            return "completion_record_damaged"
        if value["binding"] != self.binding(config):
            return "completion_binding_changed"
        if value["snapshot"] != snapshot or self.snapshot() != snapshot:
            return "database_or_wal_changed"
        return None

    def require_snapshot(self, expected, *, opened_wal: bool = False):
        current = self.snapshot()
        # Opening an existing WAL database can provision an empty WAL. It has
        # no committed frames and grants no permission to change the database.
        if opened_wal and expected["files"]["-wal"] is None:
            wal = current["files"]["-wal"]
            if wal is not None and wal[5] == "0":
                current["files"]["-wal"] = None
        if current != expected:
            raise FinalityFrontierError("database_changed_outside_native_owner")

    def publish(self, config: bytes, *, expected_snapshot):
        """Call only after the native audit or verified append has finished."""
        self.require_snapshot(expected_snapshot)
        snapshot = expected_snapshot
        raw = canonical_json_bytes(
            {"schema": _SCHEMA, "binding": self.binding(config), "snapshot": snapshot}
        )
        if self.record.exists() or self.record.is_symlink():
            _identity(self.record)
        fd, name = tempfile.mkstemp(prefix=".completion-", dir=self.root)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            if self.snapshot() != snapshot:
                raise FinalityFrontierError("database_changed_during_publication")
            os.replace(name, self.record)
            directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            Path(name).unlink(missing_ok=True)
