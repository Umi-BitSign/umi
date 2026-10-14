"""Fence original standing writer journals before any native mutable opener."""

from __future__ import annotations

import fcntl
import hashlib
import os
import stat
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path

from .competition_reward_cutover_ownership import _existing
from .competition_reward_decisions import StandingRewardSeries
from .competition_reward_writer_reconciliation import StoppedStandingWriter
from .competition_supervisor_runtime import _validate_startup_lease
from .open_competition import digest

_ISSUER = object()


def _absent(path):
    try:
        path.lstat()
    except FileNotFoundError:
        return True
    return False


@dataclass(frozen=True, slots=True)
class StoppedWriterJournals:
    root: Path
    _owner: StoppedStandingWriter = field(repr=False)
    _identities: tuple = field(repr=False)
    _absent_paths: tuple[Path, ...] = field(repr=False)
    _locks: tuple = field(repr=False)
    _active: list = field(repr=False)
    _history_selection: list = field(repr=False)
    _original_history_fd: int = field(repr=False)
    _issuer: object = field(default=None, repr=False)
    _binding: str = field(default="", repr=False)

    def _seal(self):
        return digest(
            {
                "root": str(self.root),
                "owner": self._owner._binding,
                "identities": [
                    (str(p), directory, stamp) for p, directory, stamp in self._identities
                ],
                "absent": [str(p) for p in self._absent_paths],
                "locks": [(str(p), fd, sha) for p, fd, sha in self._locks],
                "lifetime": id(self._active),
                "selection_lifetime": id(self._history_selection),
                "original_history_fd": self._original_history_fd,
            }
        )

    def recheck(self, journal=None):
        if (
            type(self) is not StoppedWriterJournals
            or self._issuer is not _ISSUER
            or self._active != [True]
            or self._binding != self._seal()
        ):
            raise ValueError("writer journals lack their original live ownership")
        _validate_startup_lease(self._owner.startup)
        if self._owner._active != [True]:
            raise ValueError("writer journal owner is closed")
        for path, directory, expected in self._identities:
            if path == self.root / "history" or self.root / "history" in path.parents:
                relative = str(path.relative_to(self.root / "history"))
                details = (
                    os.fstat(self._original_history_fd)
                    if relative == "."
                    else os.stat(relative, dir_fd=self._original_history_fd, follow_symlinks=False)
                )
                actual = (
                    details.st_dev,
                    details.st_ino,
                    details.st_uid,
                    details.st_gid,
                    stat.S_IMODE(details.st_mode),
                )
                if (
                    (not directory and details.st_nlink != 1)
                    or actual != expected
                    or not (
                        stat.S_ISDIR(details.st_mode)
                        if directory
                        else stat.S_ISREG(details.st_mode)
                    )
                ):
                    raise ValueError("retained original writer history identity changed")
                continue
            if _existing(path, directory=directory) != expected:
                raise ValueError("original writer journal identity changed")
        accepted = self._history_selection[1]
        if accepted is not None:
            accepted.validate(accepted.action)
            if accepted.payload["history_identities"] != {
                str(path.relative_to(self.root / "history")): list(stamp)
                for path, _, stamp in self._history_selection[0]
            }:
                raise ValueError("writer history selection differs from its authenticated packet")
        for path, directory, expected in self._history_selection[0]:
            if _existing(path, directory=directory) != expected:
                raise ValueError("selected writer history identity changed")
        if any(not _absent(path) for path in self._absent_paths):
            raise ValueError("original absent writer state appeared during review")
        for path, fd, checksum in self._locks:
            held, named = os.fstat(fd), path.stat()
            if (held.st_dev, held.st_ino) != (named.st_dev, named.st_ino) or hashlib.sha256(
                os.pread(fd, 65537, 0)
            ).hexdigest() != checksum:
                raise ValueError("original writer lock changed")
            probe = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                try:
                    fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    pass
                else:
                    raise ValueError("writer journal lock is no longer held")
            finally:
                os.close(probe)
        if journal is not None and journal.journal.root != self.root / "weights":
            raise ValueError("writer attempt uses another original journal")

    def accept_history_exchange(self, message):
        """Consume an authenticated root exchange while retaining every other fence."""
        from .competition_reward_writer_broker_channel import WriterBrokerMessage

        if type(message) is not WriterBrokerMessage:
            raise TypeError("history exchange requires the live root broker")
        if message.action not in {"selected", "rolled_back"}:
            raise ValueError("unsupported history exchange transition")
        message.validate(message.action)
        original = tuple(
            item
            for item in self._identities
            if item[0] == self.root / "history" or self.root / "history" in item[0].parents
        )
        actual = tuple(
            (path, directory, _existing(path, directory=directory))
            for path, directory, _ in original
        )
        expected = {
            str(path.relative_to(self.root / "history")): list(stamp) for path, _, stamp in actual
        }
        if message.payload.get("history_identities") != expected:
            raise ValueError("root and child history selections differ")
        if message.action == "rolled_back" and actual != original:
            raise ValueError("rollback did not restore original writer history")
        if message.action == "selected" and actual == original:
            raise ValueError("candidate history was not selected")
        self._history_selection[:] = [actual, message]
        self.recheck()


@asynccontextmanager
async def hold_stopped_writer_journals(owner: StoppedStandingWriter, series: StandingRewardSeries):
    """Hold applicable existing locks; never initialize a missing weight journal.

    Before the first native handoff the weight journal and its process locks may
    be absent. Their absence remains pinned under the genuine startup owner;
    this does not establish that any legacy pending attempt has been resolved.
    """
    if type(owner) is not StoppedStandingWriter or type(series) is not StandingRewardSeries:
        raise TypeError("writer journals require a native stopped owner and series")
    await owner.recheck()
    root = Path(owner.startup.config.state_root) / "standing-rewards" / digest(series)
    identities, missing, locks, opened = [], [], [], []
    lease = None

    def retain(path, *, directory=False):
        identities.append((path, directory, _existing(path, directory=directory)))

    try:
        for path in (root.parent, root):
            retain(path, directory=True)
        weights = root / "weights"
        absent_weights = _absent(weights)
        lock_paths = [root.parent / "standing-writer.lock"]
        if absent_weights:
            missing.append(weights)
        else:
            lock_paths.append(weights / "standing-writer.lock")
        # These process locks precede journal construction and format migration.
        for path in lock_paths:
            if _absent(path) and absent_weights:
                missing.append(path)
                continue
            retain(path)
            fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
            opened.append(fd)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if os.fstat(fd).st_size > 65536:
                raise ValueError("writer lock bytes exceed supported metadata size")
            locks.append((path, fd, hashlib.sha256(os.pread(fd, 65537, 0)).hexdigest()))
        for name in ("history", "control", *(("weights",) if not absent_weights else ())):
            retain(root / name, directory=True)
            for child in ("rounds.sqlite3", "rounds.lock"):
                retain(root / name / child)
        history_fd = os.open(root / "history", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        opened.append(history_fd)
        lease = StoppedWriterJournals(
            root,
            owner,
            tuple(identities),
            tuple(missing),
            tuple(locks),
            [True],
            [
                tuple(
                    item
                    for item in identities
                    if item[0] == root / "history" or root / "history" in item[0].parents
                ),
                None,
            ],
            history_fd,
            _ISSUER,
        )
        object.__setattr__(lease, "_binding", lease._seal())
        lease.recheck()
        await owner.recheck()
        yield lease
        lease.recheck()
        await owner.recheck()
    finally:
        if lease is not None:
            lease._active[0] = False
        for fd in reversed(opened):
            os.close(fd)
