"""Add untrusted header hints online; never issue or copy finality authority.

The existing provider owns its ancestry cursor. This importer only inserts
missing exact bytes under the same SQLite write serialization as native _save.
Each bounded batch and its append-only transfer checkpoint commit atomically.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import stat
import time
from contextlib import closing, suppress
from pathlib import Path

from .competition_worker import (
    _canonical_absolute_path,
    _open_directory_without_links,
    _verify_private_directory,
)
from .finalized_ancestry import MAXIMUM_HEADER_BYTES
from .grandpa_finality import _decode_header

MAXIMUM_BATCH_BYTES = 8 * 1024**2
SCHEMA = "umi-untrusted-header-hint-import/1"


def _identity(path, *, source=False):
    # Never independently open/close a SQLite main file or sidecar. POSIX locks
    # are process scoped: closing any descriptor for the main inode silently
    # drops SQLite's read/write locks even while its connection remains open.
    # Directory descriptors do not alias those inodes and are safe to close.
    parent = _open_directory_without_links(path.parent)
    try:
        info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
    finally:
        os.close(parent)
    owners = {0, os.getuid()} if source else {os.getuid()}
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid not in owners
        or (info.st_mode & 0o022 if source else stat.S_IMODE(info.st_mode) != 0o600)
    ):
        raise ValueError("header hint input ownership or file type differs")
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid)


def _table(db):
    columns = db.execute("PRAGMA table_info(historical_header_hints)").fetchall()
    if [(r[1], r[2], r[3], r[5]) for r in columns] != [
        ("hash", "TEXT", 0, 1),
        ("encoded", "TEXT", 1, 0),
    ]:
        raise ValueError("unsupported historical header hint schema")


class HeaderHintImport:
    """A resumable transfer into an existing isolated/private provider cache.

    Run as the existing cache owner. Online insertion does not acquire or
    replace owner.lock, touch provider memory, or open its finality database.
    Limits must come from that cache's selected runtime configuration.
    """

    def __init__(
        self,
        source: Path,
        target_directory: Path,
        *,
        operation: str,
        maximum_bytes: int,
        maximum_database_bytes: int,
        batch_size: int = 256,
        busy_timeout_seconds: float = 0.25,
    ):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", operation):
            raise ValueError("header import needs a stable operation name")
        if any(type(x) is not int or x < 1 for x in (maximum_bytes, maximum_database_bytes)):
            raise ValueError("header import needs the selected positive capacities")
        if type(batch_size) is not int or not 1 <= batch_size <= 4096:
            raise ValueError("header import batch must be bounded")
        if type(busy_timeout_seconds) not in (int, float) or not 0 < busy_timeout_seconds <= 2:
            raise ValueError("header import database wait must be bounded")
        self.source = _canonical_absolute_path(source, "source hint database")
        self.root = _canonical_absolute_path(target_directory, "target hint directory")
        self.target = self.root / "historical-headers.sqlite3"
        self.operation = operation
        self.maximum_bytes, self.maximum_database_bytes = maximum_bytes, maximum_database_bytes
        self.batch_size, self.timeout = batch_size, busy_timeout_seconds
        self.started = time.monotonic()
        self.copied_this_run = 0
        self.source_identity = _identity(self.source, source=True)
        self.target_identity = _identity(self.target)
        if self.source_identity[:2] == self.target_identity[:2]:
            raise ValueError("header hint import source and target must be disjoint")
        self._recheck()

    def _recheck(self):
        _verify_private_directory(self.root, "target header directory")
        _identity(self.root / "owner.lock")
        for suffix in ("-journal", "-wal", "-shm"):
            # The active native owner may remove a DELETE journal between
            # stat/open. Ignore only disappearance of this exact sidecar.
            with suppress(FileNotFoundError):
                _identity(Path(str(self.target) + suffix))
        if (
            _identity(self.source, source=True) != self.source_identity
            or _identity(self.target) != self.target_identity
        ):
            raise ValueError("header import source or target identity changed")
        if self.source.stat().st_size > self.maximum_database_bytes:
            raise ValueError("source hint database exceeds selected physical capacity")

    def _source(self):
        db = sqlite3.connect(
            self.source.as_uri() + "?mode=ro", uri=True, timeout=self.timeout, isolation_level=None
        )
        try:
            db.execute("PRAGMA query_only=ON")
            if db.execute("PRAGMA journal_mode").fetchone()[0] != "delete":
                raise ValueError("source hints require supported DELETE journal mode")
            _table(db)
            return db
        except BaseException:
            db.close()
            raise

    def _target(self):
        db = sqlite3.connect(
            self.target.as_uri() + "?mode=rw", uri=True, timeout=self.timeout, isolation_level=None
        )
        try:
            page_size = db.execute("PRAGMA page_size").fetchone()[0]
            page_count = db.execute("PRAGMA page_count").fetchone()[0]
            pages = self.maximum_database_bytes // page_size
            if pages < 1 or page_count * page_size > self.maximum_database_bytes:
                raise ValueError("target hints exceed selected database capacity")
            if db.execute(f"PRAGMA max_page_count={pages}").fetchone()[0] != pages:
                raise ValueError("header hint database capacity was not installed")
            if db.execute("PRAGMA journal_mode").fetchone()[0] != "delete":
                raise ValueError("target hints require supported DELETE journal mode")
            db.execute("PRAGMA synchronous=FULL")
            _table(db)
            return db
        except BaseException:
            db.close()
            raise

    def _progress(self, processed, total, inserted, reused, *, state="running", reason=None):
        elapsed = time.monotonic() - self.started
        rate = self.copied_this_run / elapsed if elapsed > 0 and self.copied_this_run else None
        remaining = None if total is None else total - processed
        return {
            "schema": SCHEMA,
            "stage": "untrusted_header_hint_import",
            "state": state,
            "operation": self.operation,
            "processed_headers": processed,
            "total_headers": total,
            "inserted_headers": inserted,
            "reused_headers": reused,
            "percent": None if total is None else 100.0 * processed / total if total else 100.0,
            "elapsed_seconds": elapsed,
            "headers_per_second": rate,
            "eta_seconds": 0.0
            if state == "completed"
            else remaining / rate
            if rate and state == "running" and remaining is not None
            else None,
            "planning_eta_seconds": [remaining / 10000, remaining / 100]
            if not rate and state == "running" and remaining is not None
            else None,
            "eta_basis": "completed"
            if state == "completed"
            else "withdrawn_retry_or_capacity"
            if state != "running"
            else "measured_import_rate"
            if rate
            else "waiting_for_transfer_inventory"
            if total is None
            else "planning_100_to_10000_local_headers_per_second",
            "eta_scope": "untrusted_hint_transfer_only_excludes_ancestry_verification",
            "retrying": state == "retrying",
            "stalled": state == "capacity_required",
            "reason": reason,
            "finality_authority": False,
            "native_verification_completed": False,
        }

    def step(self):
        """Commit at most one bounded batch; unchanged completed rows are skipped."""
        self._recheck()
        with closing(self._source()) as source, closing(self._target()) as target:
            # Source reads hold only a short read transaction per batch. The
            # initial high-water rowid makes concurrent native appends a future
            # operation without resetting this transfer's bounded progress.
            source.execute("BEGIN")
            target.execute("BEGIN IMMEDIATE")
            try:
                target.execute(
                    "CREATE TABLE IF NOT EXISTS historical_header_hint_import_runs "
                    "(operation TEXT PRIMARY KEY, selection TEXT NOT NULL)"
                )
                target.execute(
                    "CREATE TABLE IF NOT EXISTS historical_header_hint_import_batches "
                    "(operation TEXT NOT NULL, cursor INTEGER NOT NULL, "
                    "processed INTEGER NOT NULL, "
                    "inserted INTEGER NOT NULL, reused INTEGER NOT NULL, "
                    "PRIMARY KEY(operation,cursor))"
                )
                existing = target.execute(
                    "SELECT selection FROM historical_header_hint_import_runs WHERE operation=?",
                    (self.operation,),
                ).fetchone()
                selection = {
                    "source": str(self.source),
                    "source_identity": list(self.source_identity),
                    "target": str(self.target),
                    "target_identity": list(self.target_identity),
                }
                if existing is None:
                    high, low, count = source.execute(
                        "SELECT COALESCE(MAX(rowid),0),COALESCE(MIN(rowid),1),COUNT(*) "
                        "FROM historical_header_hints"
                    ).fetchone()
                    if low < 1:
                        raise ValueError("unsupported source hint row identity")
                    selection.update(high=high, total=count)
                    target.execute(
                        "INSERT INTO historical_header_hint_import_runs VALUES (?,?)",
                        (self.operation, json.dumps(selection, sort_keys=True)),
                    )
                else:
                    saved = json.loads(existing[0])
                    if any(saved.get(key) != value for key, value in selection.items()):
                        raise ValueError("header import operation changes source or target")
                    selection = saved
                prior = target.execute(
                    "SELECT cursor,processed,inserted,reused FROM "
                    "historical_header_hint_import_batches WHERE operation=? "
                    "ORDER BY cursor DESC LIMIT 1",
                    (self.operation,),
                ).fetchone()
                cursor, processed, inserted, reused = prior or (0, 0, 0, 0)
                if processed == selection["total"]:
                    target.commit()
                    return self._progress(
                        processed, selection["total"], inserted, reused, state="completed"
                    )
                rows, chars = [], 0
                query = source.execute(
                    "SELECT rowid,hash,substr(encoded,1,?) FROM historical_header_hints "
                    "WHERE rowid>? AND rowid<=? ORDER BY rowid LIMIT ?",
                    (2 * MAXIMUM_HEADER_BYTES + 3, cursor, selection["high"], self.batch_size),
                )
                for row in query:
                    number, block_hash, encoded = row
                    decoded = _decode_header(encoded, maximum_bytes=MAXIMUM_HEADER_BYTES)
                    if decoded["hash"] != block_hash:
                        raise ValueError("untrusted hint hash does not match its encoded header")
                    if rows and chars + len(encoded) > MAXIMUM_BATCH_BYTES:
                        break
                    rows.append((number, block_hash, encoded))
                    chars += len(encoded)
                if not rows or processed + len(rows) > selection["total"]:
                    raise ValueError("source hint transfer scope changed or contains a gap")
                # SQLite pages are a conservative upper bound for ASCII hint
                # payload. Avoid rescanning the growing cache on every import
                # batch when even this bound is comfortably below capacity.
                used = (
                    target.execute("PRAGMA page_count").fetchone()[0]
                    * target.execute("PRAGMA page_size").fetchone()[0]
                )
                if used + chars > self.maximum_bytes:
                    used = target.execute(
                        "SELECT COALESCE(SUM(length(encoded)),0) FROM historical_header_hints"
                    ).fetchone()[0]
                for _rowid, block_hash, encoded in rows:
                    old = target.execute(
                        "SELECT substr(encoded,1,?) FROM historical_header_hints WHERE hash=?",
                        (2 * MAXIMUM_HEADER_BYTES + 3, block_hash),
                    ).fetchone()
                    if old is not None:
                        if old[0] != encoded:
                            raise ValueError(
                                "existing target header hint conflicts; repair required"
                            )
                        reused += 1
                    else:
                        if used + len(encoded) > self.maximum_bytes:
                            raise sqlite3.OperationalError("header hint payload capacity required")
                        target.execute(
                            "INSERT INTO historical_header_hints VALUES (?,?)",
                            (block_hash, encoded),
                        )
                        used += len(encoded)
                        inserted += 1
                processed += len(rows)
                cursor = rows[-1][0]
                if (cursor == selection["high"]) != (processed == selection["total"]):
                    raise ValueError("source hint transfer count changed")
                self._recheck()
                target.execute(
                    "INSERT INTO historical_header_hint_import_batches VALUES (?,?,?,?,?)",
                    (self.operation, cursor, processed, inserted, reused),
                )
                target.commit()
                self.copied_this_run += len(rows)
                return self._progress(
                    processed,
                    selection["total"],
                    inserted,
                    reused,
                    state="completed" if processed == selection["total"] else "running",
                )
            except BaseException:
                target.rollback()
                raise
            finally:
                source.rollback()
