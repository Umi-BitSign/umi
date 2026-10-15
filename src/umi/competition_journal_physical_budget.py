"""Explicit physical ceilings for selected stopped-owner journal work.

These controls never replace logical capacity or proof authority. They bound
SQLite file growth and refuse before a transaction can consume its selected
reserve. A caller must separately qualify the filesystem and its restart floor.
"""

from __future__ import annotations

import os
import sqlite3
import struct
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class JournalPhysicalBudget:
    maximum_database_bytes: int
    minimum_free_bytes: int
    allocation_overhead_bytes: int

    def __post_init__(self):
        if (
            any(
                type(v) is not int or v < 0
                for v in (
                    self.maximum_database_bytes,
                    self.minimum_free_bytes,
                    self.allocation_overhead_bytes,
                )
            )
            or not self.maximum_database_bytes
            or not self.allocation_overhead_bytes
        ):
            raise ValueError("explicit nonnegative physical journal budget required")

    def configure(self, db: sqlite3.Connection, path: Path):
        if db.execute("PRAGMA journal_mode").fetchone() != ("delete",):
            raise ValueError("physical journal budget requires DELETE rollback mode")
        if db.execute("PRAGMA locking_mode").fetchone() != ("normal",):
            raise ValueError("physical journal budget requires normal locking")
        size = db.execute("PRAGMA page_size").fetchone()[0]
        pages = db.execute("PRAGMA page_count").fetchone()[0]
        maximum = self.maximum_database_bytes // size
        if maximum < pages:
            raise ValueError("physical journal budget is below retained database size")
        # No spill means each original page occurs in one rollback segment at
        # most once. No savepoints or attached databases are allowed below.
        db.execute("PRAGMA cache_spill=OFF")
        db.execute("PRAGMA temp_store=MEMORY")
        if db.execute("PRAGMA cache_spill").fetchone() != (0,):
            raise ValueError("physical journal spill fence failed")
        if db.execute("PRAGMA max_page_count=" + str(maximum)).fetchone() != (maximum,):
            raise ValueError("physical journal page ceiling could not be installed")
        # Each rollback entry contains an original page, page number and check
        # sum. Reserve the largest supported SQLite sector header separately.
        journal_bytes = pages * (size + 8) + 65536
        retained_allocation_gap = max(0, pages * size - path.stat().st_blocks * 512)
        growth_bytes = (maximum - pages) * size + retained_allocation_gap
        needed = (
            self.minimum_free_bytes + journal_bytes + growth_bytes + self.allocation_overhead_bytes
        )
        available = os.statvfs(path.parent)
        if available.f_bavail * available.f_frsize < needed:
            raise ValueError("physical journal rollback, growth and restart reserve unavailable")
        db.set_authorizer(self._authorize)
        return {
            "page_size": size,
            "initial_pages": pages,
            "maximum_pages": maximum,
            "rollback_bytes": journal_bytes,
            "growth_bytes": growth_bytes,
            "minimum_free_bytes": self.minimum_free_bytes,
            "required_free_bytes": needed,
        }

    def recover(self, path: Path):
        """Let SQLite roll back only the original target's interrupted transaction.

        No journal is removed by this helper. Unknown WAL/multi-database recovery
        refuses. Reserve a whole database for worst-case sparse-page allocation.
        """
        journal = Path(str(path) + "-journal")
        size = path.stat().st_size
        if (
            size > self.maximum_database_bytes
            or journal.stat().st_size > self.maximum_database_bytes * 65 // 64 + 65536
        ):
            raise ValueError("interrupted journal exceeds selected physical envelope")
        self._check_recovery_geometry(path, journal)
        available = os.statvfs(path.parent)
        needed = (
            self.minimum_free_bytes + self.maximum_database_bytes + self.allocation_overhead_bytes
        )
        if available.f_bavail * available.f_frsize < needed:
            raise ValueError("interrupted journal recovery and restart reserve unavailable")
        from .competition_transport_verification import TransferProgress

        with TransferProgress(
            "history_transfer_interrupted_transaction_recovery",
            1,
            unit="transactions",
            planning_unit_seconds=(0.01, 300.0),
        ) as report:
            db = sqlite3.connect(
                path.resolve().as_uri() + "?mode=rw", uri=True, isolation_level=None, timeout=0
            )
            try:
                db.execute("PRAGMA query_only=ON")
                db.execute("PRAGMA temp_store=MEMORY")
                db.execute("BEGIN")
                db.execute("SELECT name FROM sqlite_master LIMIT 1").fetchone()
            finally:
                db.close()
            if journal.exists() and journal.stat().st_size:
                with journal.open("rb") as stream:
                    prefix = stream.read(8)
                # With spill disabled, interruption before COMMIT leaves an
                # unsynced all-zero journal header and unchanged database. SQLite
                # may retain that cold sidecar until its next native write.
                if prefix != bytes(len(prefix)):
                    raise ValueError(
                        "SQLite retained a hot or damaged journal; explicit recovery required"
                    )
            report.advance(1)

    def _check_recovery_geometry(self, path: Path, journal: Path):
        """Bound every address SQLite could restore before opening a writer.

        Only the one segment emitted with spilling disabled is supported. This
        does not establish proof validity; it constrains native rollback writes.
        """
        from .competition_transport_verification import TransferProgress

        before = journal.stat()
        with path.open("rb") as source:
            database_header = source.read(100)
        if database_header[:16] != b"SQLite format 3\0":
            raise ValueError("interrupted recovery database header is unsupported")
        page_size = int.from_bytes(database_header[16:18], "big")
        if page_size == 1:
            page_size = 65536
        with journal.open("rb") as stream:
            header = stream.read(28)
            if not header or header[:8] == bytes(len(header[:8])):
                return  # SQLite ignores the unsynced cold journal header.
            if len(header) != 28 or header[:8] != bytes.fromhex("d9d505f920a163d7"):
                raise ValueError("interrupted recovery journal header is damaged")
            count, nonce, original_pages, sector, recorded_page_size = struct.unpack(
                ">IIIII", header[8:]
            )
            if (
                recorded_page_size != page_size
                or not 512 <= page_size <= 65536
                or page_size & (page_size - 1)
                or not 512 <= sector <= 65536
                or sector & (sector - 1)
                or not 0 < original_pages <= self.maximum_database_bytes // page_size
                or not 0 <= count <= original_pages
                or before.st_size != sector + count * (page_size + 8)
            ):
                raise ValueError("interrupted recovery journal geometry exceeds selected envelope")
            with TransferProgress(
                "history_transfer_rollback_geometry",
                count,
                unit="pages",
                planning_unit_seconds=(0.00001, 0.01),
            ) as report:
                stream.seek(sector)
                for index in range(count):
                    record = stream.read(page_size + 8)
                    page = int.from_bytes(record[:4], "big")
                    if len(record) != page_size + 8 or not 1 <= page <= original_pages:
                        raise ValueError(
                            "interrupted recovery page address exceeds selected envelope"
                        )
                    body = record[4:-4]
                    checksum = (
                        nonce + sum(body[offset] for offset in range(page_size - 200, 0, -200))
                    ) & 0xFFFFFFFF
                    if checksum != int.from_bytes(record[-4:], "big"):
                        raise ValueError("interrupted recovery journal page checksum changed")
                    if index % 256 == 255 or index + 1 == count:
                        report.advance(256 if index % 256 == 255 else count % 256)
        after = journal.stat()
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError("interrupted recovery journal changed during geometry qualification")

    @staticmethod
    def _authorize(action, first, second, database, trigger):
        if action in (sqlite3.SQLITE_ATTACH, sqlite3.SQLITE_DETACH, sqlite3.SQLITE_SAVEPOINT):
            return sqlite3.SQLITE_DENY
        if (
            action == sqlite3.SQLITE_PRAGMA
            and second is not None
            and first.lower()
            in {
                "cache_spill",
                "temp_store",
                "journal_mode",
                "max_page_count",
                "page_size",
                "locking_mode",
                "synchronous",
                "auto_vacuum",
                "wal_checkpoint",
            }
        ):
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK


@dataclass(frozen=True)
class ArchivePhysicalBudget:
    maximum_file_bytes: int
    minimum_free_bytes: int
    allocation_overhead_bytes: int

    def __post_init__(self):
        if (
            any(
                type(v) is not int or v < 0
                for v in (
                    self.maximum_file_bytes,
                    self.minimum_free_bytes,
                    self.allocation_overhead_bytes,
                )
            )
            or not self.maximum_file_bytes
            or not self.allocation_overhead_bytes
        ):
            raise ValueError("explicit nonnegative physical archive budget required")

    def check(self, root: Path, size: int):
        if type(size) is not int or not 0 < size <= self.maximum_file_bytes:
            raise ValueError("selected physical archive file ceiling exceeded")
        # Include the full temporary file even for an exact existing retry.
        # No sample multiplier or presumed deduplication supplies capacity.
        parent = root
        while not parent.exists():
            parent = parent.parent
        space = os.statvfs(parent)
        rounded = ((size + space.f_frsize - 1) // space.f_frsize) * space.f_frsize
        if (
            space.f_bavail * space.f_frsize
            < self.minimum_free_bytes + rounded + self.allocation_overhead_bytes
        ):
            raise ValueError("physical archive publication and restart reserve unavailable")


@dataclass(frozen=True)
class HistoryTransferPhysicalBudget:
    journal: JournalPhysicalBudget
    archive: ArchivePhysicalBudget

    def __post_init__(self):
        if (
            type(self.journal) is not JournalPhysicalBudget
            or type(self.archive) is not ArchivePhysicalBudget
        ):
            raise ValueError("typed journal and archive physical budgets required")
        if self.journal.minimum_free_bytes != self.archive.minimum_free_bytes:
            raise ValueError("history transfer requires one selected restart floor")
