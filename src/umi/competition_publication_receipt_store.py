"""Indexed, bounded publication verdicts with legacy receipts retained in place.

Only local successful native verification supplies these bytes. Transactions
checkpoint one verdict at a time; the completion index distinguishes lost rows
from first work. No directory inventory or source payload read is needed.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import stat
import tempfile
from contextlib import contextmanager

from .competition_transport_verification import TransferProgress
from .private_files import ensure_private_directory, lock_private_file

MAX_RECEIPT_BYTES = 16 * 1024**2
MAX_STORE_BYTES = 64 * 1024**2
_FORMAT = b"umi-publication-receipt-store/1\n"


class PublicationReceiptUnavailable(RuntimeError):
    def __init__(self, reason):
        self.reason_code = reason
        super().__init__(reason)


def _owned(path):
    value = path.lstat()
    if (
        not stat.S_ISREG(value.st_mode)
        or value.st_nlink != 1
        or value.st_uid != os.getuid()
        or value.st_mode & 0o077
    ):
        raise PublicationReceiptUnavailable("publication_receipt_store_unsafe")


class PublicationReceiptStore:
    def __init__(self, directory):
        self.directory = directory
        self.path = directory / "receipts.sqlite3"
        # Outside the directory so losing the entire store is also visible.
        self.marker = directory.parent / ".publication-verification.initialized"

    @staticmethod
    def failure(reason):
        with TransferProgress("publication_receipt_retention", 1, unit="receipts") as progress:
            progress.emit("repair_required", reason=reason)
        return PublicationReceiptUnavailable(reason)

    @contextmanager
    def connection(self, *, create=False):
        db = lock = None
        try:
            initialized = os.path.lexists(self.marker)
            if initialized:
                _owned(self.marker)
                if (
                    self.marker.stat().st_size != len(_FORMAT)
                    or self.marker.read_bytes() != _FORMAT
                ):
                    raise PublicationReceiptUnavailable("publication_receipt_marker_changed")
                if not os.path.lexists(self.path):
                    raise PublicationReceiptUnavailable("completed_publication_store_missing")
            if not create and not os.path.lexists(self.path):
                yield None
                return
            ensure_private_directory(self.directory)
            lock = lock_private_file(self.directory / ".cache.lock")
            if not os.path.lexists(self.path):
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
                os.close(fd)
            _owned(self.path)
            for suffix in ("-journal", "-wal", "-shm"):
                sidecar = self.path.with_name(self.path.name + suffix)
                if os.path.lexists(sidecar):
                    _owned(sidecar)
            db = sqlite3.connect(str(self.path), timeout=0)
            db.execute("PRAGMA synchronous=FULL")
            db.execute("PRAGMA temp_store=MEMORY")
            db.execute("PRAGMA cache_size=-2048")
            # Bound indexes and free pages as well as payloads. The rollback
            # journal is bounded by this same database size; no WAL accumulates.
            page_size = db.execute("PRAGMA page_size").fetchone()[0]
            db.execute(f"PRAGMA max_page_count={2 * MAX_STORE_BYTES // page_size}")
            if not initialized:
                with db:
                    db.execute(
                        "CREATE TABLE IF NOT EXISTS receipts "
                        "(key TEXT PRIMARY KEY, body BLOB NOT NULL)"
                    )
                    db.execute(
                        "CREATE TABLE IF NOT EXISTS completed "
                        "(key TEXT PRIMARY KEY, checksum TEXT NOT NULL)"
                    )
                    db.execute(
                        "CREATE TABLE IF NOT EXISTS metadata "
                        "(id INTEGER PRIMARY KEY CHECK(id=1), "
                        "format BLOB NOT NULL, bytes INTEGER NOT NULL)"
                    )
                    db.execute("INSERT OR IGNORE INTO metadata VALUES (1,?,0)", (_FORMAT,))
            metadata = db.execute("SELECT format,bytes FROM metadata WHERE id=1").fetchone()
            if (
                metadata is None
                or metadata[0] != _FORMAT
                or not 0 <= metadata[1] <= MAX_STORE_BYTES
            ):
                raise PublicationReceiptUnavailable("publication_receipt_metadata_changed")
            if not initialized:
                fd, temporary = tempfile.mkstemp(
                    prefix=".publication-verification.", dir=self.directory.parent
                )
                try:
                    os.write(fd, _FORMAT)
                    os.fsync(fd)
                    os.replace(temporary, self.marker)
                finally:
                    os.close(fd)
                    if os.path.lexists(temporary):
                        os.unlink(temporary)
                for path in (self.directory, self.directory.parent):
                    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                    try:
                        os.fsync(fd)
                    finally:
                        os.close(fd)
            yield db
        except PublicationReceiptUnavailable as error:
            raise self.failure(error.reason_code) from error
        except sqlite3.Error as error:
            raise self.failure("publication_receipt_database_repair_required") from error
        except OSError as error:
            raise self.failure("publication_receipt_storage_unavailable") from error
        finally:
            if db is not None:
                db.close()
            if lock is not None:
                os.close(lock)

    def load(self, key):
        with self.connection() as db:
            if db is None:
                return None
            row = db.execute("SELECT body FROM receipts WHERE key=?", (key,)).fetchone()
            completion = db.execute("SELECT checksum FROM completed WHERE key=?", (key,)).fetchone()
            if row is None and completion is None:
                return None
            if row is None or completion is None:
                raise PublicationReceiptUnavailable("completed_publication_receipt_missing")
            raw = row[0]
            if (
                type(raw) is not bytes
                or not 0 < len(raw) <= MAX_RECEIPT_BYTES
                or hashlib.sha256(raw).hexdigest() != completion[0]
            ):
                raise PublicationReceiptUnavailable("completed_publication_receipt_changed")
            return raw

    def remember(self, key, raw):
        if not 0 < len(raw) <= MAX_RECEIPT_BYTES:
            raise self.failure("publication_receipt_byte_capacity")
        with self.connection(create=True) as db, db:
            db.execute("BEGIN IMMEDIATE")
            old = db.execute("SELECT length(body) FROM receipts WHERE key=?", (key,)).fetchone()
            used = db.execute("SELECT bytes FROM metadata WHERE id=1").fetchone()[0]
            selected = used - (0 if old is None else old[0]) + len(raw)
            if selected > MAX_STORE_BYTES:
                raise self.failure("publication_receipt_store_capacity")
            db.execute("INSERT OR REPLACE INTO receipts VALUES (?,?)", (key, raw))
            db.execute(
                "INSERT OR REPLACE INTO completed VALUES (?,?)",
                (key, hashlib.sha256(raw).hexdigest()),
            )
            db.execute("UPDATE metadata SET bytes=? WHERE id=1", (selected,))
