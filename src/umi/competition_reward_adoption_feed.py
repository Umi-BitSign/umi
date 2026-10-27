"""Append-only signed reward selection shared by already installed consumers.

The source is transport, not authority. Each consumer retains its own accepted
frontier and refuses removal, replacement or rollback across process restarts.
Refreshing this compact selection never opens a model or replays a package.
"""

from __future__ import annotations

import logging
import os
import stat
import threading
import time
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field

from .competition_reward_adoption import (
    RewardAdoptionSelection,
    SignedRewardModelAdoption,
    verify_adoption_selection,
)
from .competition_round_journal import RoundJournal
from .open_competition import digest
from .private_files import Directory
from .protocol import StrictProtocolModel, canonical_json_bytes

logger = logging.getLogger(__name__)


class RewardAdoptionFeedConfig(StrictProtocolModel):
    path: Directory
    maximum_bytes: Annotated[int, Field(ge=1024, le=16 * 1024**2)] = 4 * 1024**2


class RewardAdoptionFeedCheckpoint(StrictProtocolModel):
    schema_: Literal["umi-reward-adoption-feed-checkpoint/1"] = Field(alias="schema")
    added: Annotated[tuple[SignedRewardModelAdoption, ...], Field(max_length=4096)]
    maximum_decisions: int


def _contains(previous, selected):
    if previous is None:
        return True
    if selected is None or selected.maximum_decisions < previous.maximum_decisions:
        return False
    available = {canonical_json_bytes(item) for item in selected.adoptions}
    return all(canonical_json_bytes(item) in available for item in previous.adoptions)


def extend_adoption_selection(previous, selected, *, series, policy):
    """Authenticate a complete frontier, preserving every original signed byte."""
    selected = verify_adoption_selection(selected, series, policy)
    if selected is None:
        if previous is not None:
            raise ValueError("reward adoption feed removed its retained selection")
        return None
    if not _contains(previous, selected):
        raise ValueError("reward adoption feed rolled back or replaced retained signed bytes")
    return selected


class RewardAdoptionFeed:
    def __init__(self, root, *, source, series, policy, initial, deferred=False):
        self.source, self.series, self.policy = source, series, policy
        self._serial = threading.RLock()
        self.root = Path(root)
        self.selected = verify_adoption_selection(initial, series, policy)
        self.journal = None
        self._initialized = False
        self._source_identity = None
        if not deferred:
            self._initialize()

    def _initialize(self):
        if self._initialized:
            return
        self.journal = RoundJournal(
            self.root,
            {
                "schema": "umi-reward-adoption-feed-owner/1",
                "series_sha256": digest(self.series),
                "policy_sha256": digest(self.policy),
                "source": self.source.path,
            },
            maximum_rounds=1024,
            maximum_bytes=64 * 1024**2,
            maximum_record_bytes=self.source.maximum_bytes,
        )
        keys = self.journal.keys("feed_selection")
        self._generation = len(keys)
        if keys != [f"{n:06d}" for n in range(self._generation)]:
            raise ValueError("reward adoption feed frontier needs retained metadata repair")
        retained = self._restore(keys)
        if retained is not None:
            retained = verify_adoption_selection(retained, self.series, self.policy)
            # A supported config update may already include a newer signed
            # frontier. Reconcile it monotonically, rather than requiring the
            # operator to erase this consumer's independent recovery journal.
            if _contains(retained, self.selected):
                if retained != self.selected:
                    self._checkpoint(self.selected, retained)
            elif _contains(self.selected, retained):
                self.selected = retained
            else:
                raise ValueError("reward adoption feed conflicts with its configured frontier")
        self._raw = None if self.selected is None else canonical_json_bytes(self.selected)
        self._initialized = True

    def _restore(self, keys):
        retained = None
        for key in keys:
            raw = self.journal.get("feed_selection", key)
            if raw is None:
                raise ValueError("reward adoption feed frontier needs retained metadata repair")
            if raw.get("schema") == "umi-standing-reward-adoption-selection/1":
                # Preserve the earlier draft's cumulative checkpoint format.
                selected = RewardAdoptionSelection.model_validate_json(canonical_json_bytes(raw))
                if not _contains(retained, selected):
                    raise ValueError("reward adoption feed checkpoint replaced signed bytes")
            else:
                saved = RewardAdoptionFeedCheckpoint.model_validate_json(canonical_json_bytes(raw))
                items = () if retained is None else retained.adoptions
                selected = RewardAdoptionSelection(
                    schema="umi-standing-reward-adoption-selection/1",
                    adoptions=tuple(
                        sorted(
                            (*items, *saved.added),
                            key=lambda item: (item.adoption.cohort_sha256, item.adoption.revision),
                        )
                    ),
                    maximum_decisions=saved.maximum_decisions,
                )
                if retained is not None and selected.maximum_decisions < retained.maximum_decisions:
                    raise ValueError("reward adoption feed checkpoint rolled back its capacity")
            retained = selected
        return retained

    def _checkpoint(self, selected, previous):
        # Retain each signed revision once, instead of N cumulative snapshots.
        known = (
            set()
            if previous is None
            else {canonical_json_bytes(item) for item in previous.adoptions}
        )
        checkpoint = RewardAdoptionFeedCheckpoint(
            schema="umi-reward-adoption-feed-checkpoint/1",
            added=tuple(
                item for item in selected.adoptions if canonical_json_bytes(item) not in known
            ),
            maximum_decisions=selected.maximum_decisions,
        )
        self.journal.put("feed_selection", f"{self._generation:06d}", checkpoint)
        self._generation += 1

    def _read(self):
        try:
            # Refuse nonregular transport files without blocking on a FIFO.
            fd = os.open(self.source.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            if self._generation:
                raise ValueError("reward adoption feed lost its retained frontier") from None
            return None
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= self.source.maximum_bytes:
                raise ValueError("reward adoption feed exceeds its configured bound")
            identity = (
                info.st_dev,
                info.st_ino,
                info.st_size,
                info.st_mtime_ns,
                info.st_ctime_ns,
            )
            if identity == self._source_identity:
                return self._raw, identity
            with os.fdopen(fd, "rb", closefd=False) as stream:
                raw = stream.read(self.source.maximum_bytes + 1)
            if len(raw) > self.source.maximum_bytes:
                raise ValueError("reward adoption feed exceeds its configured bound")
            # Publish uses atomic replacement. A different inode is observed
            # on the next refresh; an in-place write during this read is not a
            # reusable immutable source identity.
            after = os.fstat(fd)
            if identity != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ):
                raise ValueError("reward adoption feed changed during its bounded read")
            return raw, identity
        finally:
            os.close(fd)

    def refresh(self):
        with self._serial:
            return self._refresh()

    def _refresh(self):
        self._initialize()
        started = time.monotonic()
        value = self._read()
        if value is None:
            return self.selected
        raw, identity = value
        if raw == self._raw:
            self._source_identity = identity
            return self.selected
        selected = RewardAdoptionSelection.model_validate_json(raw)
        if canonical_json_bytes(selected) != raw:
            raise ValueError("reward adoption feed requires canonical signed bytes")
        selected = extend_adoption_selection(
            self.selected, selected, series=self.series, policy=self.policy
        )
        self._checkpoint(selected, self.selected if self._generation else None)
        self.selected, self._raw = selected, raw
        self._source_identity = identity
        logger.info(
            "reward_adoption_feed_progress generation=%d completed=%d total=%d "
            "elapsed_seconds=%.3f eta_seconds=0 eta_basis=committed_signed_selection "
            "stalled_or_retrying=false",
            self._generation,
            len(selected.adoptions),
            len(selected.adoptions),
            time.monotonic() - started,
        )
        return selected

    def publish(self, signed):
        """Publish one already quorum-signed revision, with repeat-safe recovery."""
        with self._serial:
            return self._publish(signed)

    def _publish(self, signed):
        self._initialize()
        with self.journal.locked():
            previous = self.refresh()
            if previous is not None and any(item == signed for item in previous.adoptions):
                if self._source_identity is not None:
                    return previous
                # A fresh producer can seed transport from its already signed
                # boot selection without creating another signature/revision.
                selected = previous
            else:
                items = () if previous is None else previous.adoptions
                selected = RewardAdoptionSelection(
                    schema="umi-standing-reward-adoption-selection/1",
                    adoptions=tuple(
                        sorted(
                            (*items, signed),
                            key=lambda item: (item.adoption.cohort_sha256, item.adoption.revision),
                        )
                    ),
                    maximum_decisions=(1024 if previous is None else previous.maximum_decisions),
                )
                selected = extend_adoption_selection(
                    previous, selected, series=self.series, policy=self.policy
                )
            raw = canonical_json_bytes(selected)
            if len(raw) > self.source.maximum_bytes:
                raise ValueError("reward adoption feed exceeds its configured bound")
            path = Path(self.source.path)
            # One configured producer owns this directory; consumers verify the
            # signatures and their own retained frontier, independent of its uid.
            temporary = path.with_name(path.name + ".publishing")
            fd = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                0o644,
            )
            try:
                info = os.fstat(fd)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.getuid()
                    or info.st_nlink != 1
                ):
                    raise ValueError("reward adoption publication requires its owned regular file")
                os.ftruncate(fd, 0)
                os.fchmod(fd, 0o644)
                with os.fdopen(fd, "wb", closefd=False) as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(fd)
            finally:
                os.close(fd)
            os.replace(temporary, path)
            parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
            return self.refresh()
