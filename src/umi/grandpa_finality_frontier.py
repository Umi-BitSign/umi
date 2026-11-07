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
import logging
import os
import stat
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

from .protocol import canonical_json_bytes

AUDIT_SEMANTICS = "umi-grandpa-native-audit/1"
_SCHEMA = "umi-grandpa-file-bound-frontier/1"
_CHECKPOINT_SCHEMA = "umi-grandpa-audit-checkpoint/1"
_MAXIMUM_RECORD_BYTES = 64 * 1024
_LOGGER = logging.getLogger(__name__)


def audit_frontier_disk_usage(parent: int, name: str) -> int:
    """Account private audit metadata without opening SQLite or evidence files."""
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    try:
        root = os.fstat(fd)
        if root.st_uid != os.getuid() or stat.S_IMODE(root.st_mode) != 0o700:
            raise FinalityFrontierError("unsafe_frontier_path")
        total = 0
        with os.scandir(fd) as entries:
            for index, entry in enumerate(entries):
                # Normally three records plus one publication in flight. Bound
                # inspection even if interrupted older owners left temp files.
                if index >= 67:
                    raise FinalityFrontierError("frontier_publication_cleanup_required")
                temporary = entry.name.startswith(".completion-")
                if (
                    entry.name not in {"owner.lock", "completed.json", "audit-progress.json"}
                    and not temporary
                ):
                    raise FinalityFrontierError("unknown_frontier_entry")
                try:
                    info = os.stat(entry.name, dir_fd=fd, follow_symlinks=False)
                except FileNotFoundError:
                    if temporary:
                        continue
                    raise
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_nlink != 1
                    or info.st_size > (0 if entry.name == "owner.lock" else _MAXIMUM_RECORD_BYTES)
                ):
                    raise FinalityFrontierError("unsafe_frontier_path")
                total += info.st_size
        return total
    finally:
        os.close(fd)


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
            # An abrupt process death can leave an unpublished atomic-write
            # temporary. Only the selected records grant reuse; the next owner
            # releases these incomplete files under the same exclusive lock.
            for index, path in enumerate(self.root.iterdir()):
                if index >= 67:
                    raise FinalityFrontierError("frontier_publication_cleanup_required")
                if path.name.startswith(".completion-"):
                    if int(_identity(path)[5]) > _MAXIMUM_RECORD_BYTES:
                        raise FinalityFrontierError("frontier_record_oversized")
                    path.unlink()
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
        self._publish_record(
            self.record,
            {"schema": _SCHEMA, "binding": self.binding(config), "snapshot": expected_snapshot},
            expected_snapshot,
        )

    def audit_checkpoint(self, config: bytes, *, legacy_accounting: bool):
        return FinalityAuditCheckpoint(self, config, legacy_accounting=legacy_accounting)

    def _publish_record(self, path, value, snapshot):
        self.require_snapshot(snapshot)
        raw = canonical_json_bytes(value)
        if len(raw) > _MAXIMUM_RECORD_BYTES:
            raise FinalityFrontierError("frontier_record_oversized")
        if path.exists() or path.is_symlink():
            _identity(path)
        fd, name = tempfile.mkstemp(prefix=".completion-", dir=self.root)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            if self.snapshot() != snapshot:
                raise FinalityFrontierError("database_changed_during_publication")
            os.replace(name, path)
            directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            Path(name).unlink(missing_ok=True)


def _audit_snapshot_identity(snapshot):
    # An empty WAL contains no committed frames. SQLite may create or discard
    # it when an interrupted read-only audit is opened again.
    files = dict(snapshot["files"])
    if files["-wal"] is not None and files["-wal"][5] == "0":
        files["-wal"] = None
    return {"directory": snapshot["directory"], "files": files}


class FinalityAuditCheckpoint:
    """One bounded continuation, committed after every accepted audit row.

    No evidence payload is copied. The consumer supplies only the validated
    predecessor metadata needed to continue its original ordered audit.
    """

    def __init__(self, owner, config, *, legacy_accounting):
        self.owner = owner
        self.path = owner.root / "audit-progress.json"
        self.binding = {**owner.binding(config), "legacy_accounting": legacy_accounting}
        self.snapshot = owner.snapshot()
        self.reason = None
        self._repair = False

    def repair(self, reason):
        self.reason, self._repair = reason, True
        _LOGGER.warning(
            "finality_startup_audit state=repair_required reason=%s completed=0 "
            "total=unknown elapsed_seconds=0 eta_seconds=unknown "
            "eta_basis=integrity_and_count_required stalled=false retrying=false",
            reason,
        )

    def load(self):
        if self._repair:
            return None
        try:
            before = _identity(self.path)
            if int(before[5]) > _MAXIMUM_RECORD_BYTES:
                raise FinalityFrontierError("audit_checkpoint_oversized")
            fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if (info.st_dev, info.st_ino) != tuple(map(int, before[:2])):
                    raise FinalityFrontierError("audit_checkpoint_replaced")
                raw = stream.read(_MAXIMUM_RECORD_BYTES + 1)
            if _identity(self.path) != before:
                raise FinalityFrontierError("audit_checkpoint_changed")
            value = json.loads(raw)
            if (
                not isinstance(value, dict)
                or set(value) != {"schema", "binding", "snapshot", "state", "state_sha256"}
                or value["schema"] != _CHECKPOINT_SCHEMA
                or canonical_json_bytes(value) != raw
                or hashlib.sha256(canonical_json_bytes(value["state"])).hexdigest()
                != value["state_sha256"]
            ):
                raise FinalityFrontierError("audit_checkpoint_damaged")
        except FileNotFoundError:
            self.reason = "audit_checkpoint_missing"
            return None
        except (ValueError, UnicodeError) as error:
            if isinstance(error, FinalityFrontierError) and str(error) == "unsafe_frontier_path":
                raise
            self.repair("audit_checkpoint_requires_repair")
            return None
        self.owner.require_snapshot(self.snapshot)
        if value["binding"] != self.binding:
            self.repair("audit_checkpoint_binding_changed")
            return None
        if value["snapshot"] != _audit_snapshot_identity(self.snapshot):
            self.repair("audit_checkpoint_database_changed")
            return None
        return value["state"]

    def save(self, state):
        self.owner._publish_record(
            self.path,
            {
                "schema": _CHECKPOINT_SCHEMA,
                "binding": self.binding,
                "snapshot": _audit_snapshot_identity(self.snapshot),
                "state": state,
                "state_sha256": hashlib.sha256(canonical_json_bytes(state)).hexdigest(),
            },
            self.snapshot,
        )
