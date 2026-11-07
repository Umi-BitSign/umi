"""Return archived forecast free pages through their existing SQLite owner."""

import fcntl
import os
import stat
import time
from typing import Annotated

from pydantic import Field

from .competition_transport_verification import TransferProgress
from .private_files import Directory
from .protocol import StrictProtocolModel


class ForecastCompactionConfig(StrictProtocolModel):
    reserve_bytes: Annotated[int, Field(ge=0)]
    lock_file: Directory


class ForecastCompaction:
    minimum_reclaim_bytes = 16 * 1024**2
    maximum_live_bytes = 16 * 1024**2

    def __init__(self, ledger):
        self.ledger = ledger
        self.started = time.monotonic()
        self.status = dict(
            stage="forecast_physical_reclamation",
            status="unselected" if ledger.compaction is None else "pending",
            completed=0,
            total=1,
            elapsed_seconds=0.0,
            eta_seconds=None,
            eta_basis="awaiting_owned_storage_observation",
            stalled_or_retrying=False,
        )

    def advance(self):
        ledger = self.ledger
        if ledger.compaction is None:
            return False
        # Provision one shared file for all selected owners on this filesystem.
        # Never create/replace a missing admission identity during maintenance.
        fd = os.open(ledger.compaction.lock_file, os.O_RDWR | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o002:
                raise ValueError("forecast compaction admission file is unsafe")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                self.status.update(
                    status="waiting_for_compaction_owner",
                    elapsed_seconds=time.monotonic() - self.started,
                    eta_seconds=None,
                    eta_basis="shared_compaction_admission_busy",
                    stalled_or_retrying=True,
                )
                return False
            selected = os.stat(ledger.compaction.lock_file, follow_symlinks=False)
            if (selected.st_dev, selected.st_ino) != (info.st_dev, info.st_ino):
                raise ValueError("forecast compaction admission identity changed")
            return self._owned_advance()
        finally:
            os.close(fd)

    def _owned_advance(self):
        ledger = self.ledger
        # The same connection and lock serialize every append, snapshot and
        # close. An independent connection can exceed the writer's 50ms timeout.
        with ledger.lock:
            page = ledger.db.execute("PRAGMA page_size").fetchone()[0]
            pages = ledger.db.execute("PRAGMA page_count").fetchone()[0]
            free = ledger.db.execute("PRAGMA freelist_count").fetchone()[0]
            before = pages * page
            live = (pages - free) * page
            if free * page < self.minimum_reclaim_bytes:
                if self.status["status"] != "completed":
                    self.status.update(
                        status="below_threshold",
                        total=0,
                        eta_seconds=0,
                        planning_eta_seconds=None,
                        stalled_or_retrying=False,
                    )
                return False
            # Bound the live rewrite, including historical non-auto-vacuum
            # layouts. Keep all rows and the original hash-chain head unchanged.
            required = ledger.compaction.reserve_bytes + 2 * before
            stats = os.statvfs(ledger.directory)
            available = stats.f_bavail * stats.f_frsize
            self.status.update(
                before_bytes=before,
                reclaimable_bytes=free * page,
                live_bytes=live,
                required_available_bytes=required,
                available_bytes=available,
                completed=0,
                total=1,
                eta_seconds=None,
            )
            if live > self.maximum_live_bytes or available < required:
                self.status.update(
                    status="waiting_for_archive"
                    if live > self.maximum_live_bytes
                    else "capacity_required",
                    elapsed_seconds=time.monotonic() - self.started,
                    eta_basis="awaiting_bounded_live_set_or_selected_reserve_plus_two_database_sizes",
                    stalled_or_retrying=True,
                )
                return False
            started = time.monotonic()
            self.status.update(
                status="running",
                elapsed_seconds=0.0,
                planning_eta_seconds=[1, 300],
                eta_basis="planning_seconds_for_one_bounded_SQLite_compaction_excludes_owner_wait",
                stalled_or_retrying=False,
            )
            try:
                # SQLite owns atomic rollback and its temporary files. No
                # database replacement, new schema, remote read or row replay.
                with TransferProgress("forecast_physical_reclamation", 1, unit="databases") as work:
                    ledger.db.execute("VACUUM")
                    work.advance(1)
            except BaseException:
                self.status.update(
                    status="retrying",
                    elapsed_seconds=time.monotonic() - started,
                    planning_eta_seconds=None,
                    eta_basis="withdrawn_compaction_interrupted_or_failed",
                    stalled_or_retrying=True,
                )
                raise
            after = ledger.db.execute("PRAGMA page_count").fetchone()[0] * page
            self.status.update(
                status="completed",
                completed=1,
                after_bytes=after,
                released_file_bytes=max(0, before - after),
                elapsed_seconds=time.monotonic() - started,
                eta_seconds=0,
                planning_eta_seconds=None,
                eta_basis="completed_owned_SQLite_compaction",
                stalled_or_retrying=False,
            )
            return True
