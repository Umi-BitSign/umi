"""Exclusive existing coordinator state for a no-launch cutover review."""

from __future__ import annotations

import fcntl
import os
import stat
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from .competition_reward_admission_provenance import load_provenance, validate_provenance
from .competition_reward_history_checkpoint import HistoryCheckpointRepairRequired
from .open_competition import digest

_ISSUER = object()

if TYPE_CHECKING:
    from .competition_reward_coordinator_boot import RewardCoordinatorConfig


def _existing(path, *, directory=False):
    path = Path(path)
    for item in (path, *path.parents):
        if item.is_symlink():
            raise HistoryCheckpointRepairRequired("cutover owner path contains a symlink")
    value = path.stat()
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if (
        not kind(value.st_mode)
        or value.st_uid != os.getuid()
        or value.st_mode & 0o077
        or (not directory and value.st_nlink != 1)
    ):
        raise HistoryCheckpointRepairRequired("cutover needs private existing owner state")
    return (value.st_dev, value.st_ino, value.st_uid, value.st_gid, stat.S_IMODE(value.st_mode))


@dataclass(slots=True)
class RewardCutoverLease:
    """A live local lock owner; serialized results cannot recreate this lease."""

    root: Path
    config_sha256: str
    identities: dict
    descriptors: tuple[int, ...]
    provenance: dict | None
    _issuer: object = field(default=None, repr=False)
    _closed: bool = field(default=False, repr=False)

    def recheck(self, config: RewardCoordinatorConfig) -> None:
        if (
            self._issuer is not _ISSUER
            or self._closed
            or self.config_sha256 != digest(config)
            or self.root != Path(config.state_directory) / digest(config.series)
        ):
            raise ValueError("cutover lacks its original live coordinator ownership")
        for path, (directory, expected) in self.identities.items():
            if _existing(path, directory=directory) != expected:
                raise HistoryCheckpointRepairRequired("cutover original owner identity changed")
        for fd, path in zip(self.descriptors, self.lock_paths, strict=True):
            current, held = Path(path).stat(), os.fstat(fd)
            if (current.st_dev, current.st_ino) != (held.st_dev, held.st_ino):
                raise HistoryCheckpointRepairRequired("cutover owner lock was replaced")
        if self.provenance is not None:
            validate_provenance(self.provenance, require_stopped=True)

    @property
    def lock_paths(self):
        return (
            self.root / "service.lock",
            self.root.parent / "control-writer.lock",
            self.root / "transactions/control-writer.lock",
        )


@contextmanager
def hold_reward_cutover_owner(
    config: RewardCoordinatorConfig, *, original_owner_selection: Path | None = None
):
    """Fence real owners before any journal/provider constructor; never reset.

    The installed coordinator holds the first two process locks and its publisher
    holds the third. Journal compound-operation locks remain available to their
    genuine native consumers; they are not reentrant and must not be held here.
    The optional installed342 seal additionally proves the exact stopped C5
    owner. Other supported coordinators use the same existing process locks.
    """
    if config.role != "coordinator" or config.predecessor_series is not None:
        raise ValueError("cutover review requires the original coordinator series owner")
    root = Path(config.state_directory) / digest(config.series)
    provenance = None
    if original_owner_selection is not None:
        provenance = load_provenance(original_owner_selection)
        validate_provenance(provenance, require_stopped=True)
        if (
            provenance["owner_uid"] != os.getuid()
            or provenance["owner_uid"] != os.geteuid()
            or provenance["paths"]["service_root"] != str(root)
            or provenance["series_sha256"] != digest(config.series)
            or provenance["policy_sha256"] != digest(config.policy)
            or provenance["chain_config_sha256"] != digest(config.chain)
            or provenance["configuration"]["sha256"] != digest(config)
        ):
            raise HistoryCheckpointRepairRequired("cutover changes the selected original owner")
    identities = {}
    for path in (root, root.parent):
        identities[path] = (True, _existing(path, directory=True))
    for name in ("decisions", "history", "control", "transactions"):
        path = root / name
        identities[path] = (True, _existing(path, directory=True))
        for child in ("rounds.sqlite3", "rounds.lock"):
            selected = path / child
            identities[selected] = (False, _existing(selected))
    paths = (
        root / "service.lock",
        root.parent / "control-writer.lock",
        root / "transactions/control-writer.lock",
    )
    descriptors = []
    lease = None
    try:
        for path in paths:
            identities[path] = (False, _existing(path))
            fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
            descriptors.append(fd)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        lease = RewardCutoverLease(
            root, digest(config), identities, tuple(descriptors), provenance, _issuer=_ISSUER
        )
        lease.recheck(config)
        yield lease
    finally:
        if lease is not None:
            lease._closed = True
        for fd in reversed(descriptors):
            os.close(fd)
