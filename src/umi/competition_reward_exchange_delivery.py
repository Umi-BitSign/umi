"""Exact current request/vote discovery; transport metadata grants no authority.

Publishers advance separate cursors only after immutable native requests exist.
The consumer keeps a bounded durable frontier and never walks request trees or
reads original proofs. Native recipients still authenticate and review messages.
"""

from __future__ import annotations

import fcntl
import logging
import os
import stat
import time
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field

from .competition_cohort_recovery import verify_recovery_authority
from .competition_public_results_directory import atomic_write, read_owned_file
from .competition_reward_adoption import MAX_REWARD_DECISIONS
from .competition_reward_adoption_consumer import RewardAdoptionConsumer, open_reward_adoption_feed
from .competition_reward_decisions import reward_decision_capacity
from .open_competition import Hex32, digest, identity
from .private_files import ensure_private_directory, lock_private_file, private_path
from .private_files import read_private_model as read
from .protocol import StrictProtocolModel, canonical_json_bytes

MAX_CURSOR_BYTES = 2048
MAX_CHECKPOINT_BYTES = 1024 * 1024
logger = logging.getLogger(__name__)


class RewardExchangeCursor(StrictProtocolModel):
    schema_: Literal["umi-reward-exchange-cursor/1"] = Field(alias="schema")
    series_sha256: Hex32
    proposer: Hex32
    cohort_sha256: Hex32 | None = None
    position: Annotated[int, Field(ge=0, lt=MAX_REWARD_DECISIONS + 1)]

    @property
    def name(self):
        return "decision" if self.cohort_sha256 is None else "adoption-" + self.cohort_sha256

    @property
    def slot(self):
        if self.cohort_sha256 is None:
            if self.position >= MAX_REWARD_DECISIONS:
                raise ValueError("ordinary reward cursor exceeds decision capacity")
            return f"{self.position:04d}"
        if self.position == 0:
            raise ValueError("adoption cursor requires a positive revision")
        return f"adoption-{self.cohort_sha256}-{self.position:06d}"


def cursor_path(outbox, cursor):
    return Path(outbox) / "transport" / cursor.series_sha256 / (cursor.name + ".json")


def publish_exchange_cursor(outbox, *, series, proposer, position, cohort=None):
    """Caller holds its signing journal lease; retries repair a missing export."""
    value = RewardExchangeCursor(
        schema="umi-reward-exchange-cursor/1",
        series_sha256=series,
        proposer=proposer,
        cohort_sha256=cohort,
        position=position,
    )
    # Force slot validation even before the transport consumes this cursor.
    _ = value.slot
    path = cursor_path(outbox, value)
    ensure_private_directory(path.parent)
    lease = lock_private_file(path.parent / (value.name + ".lock"))
    try:
        try:
            old = read(path, RewardExchangeCursor, maximum_bytes=MAX_CURSOR_BYTES)
        except FileNotFoundError:
            old = None
        if old is not None:
            if (old.series_sha256, old.proposer, old.cohort_sha256) != (
                value.series_sha256,
                value.proposer,
                value.cohort_sha256,
            ):
                raise ValueError("reward transport cursor changed its selected publisher")
            if old.position >= value.position:
                # A retry for an older immutable request must not roll discovery back.
                return
        atomic_write(path, canonical_json_bytes(value), immutable=False)
    finally:
        fcntl.flock(lease, fcntl.LOCK_UN)
        os.close(lease)


def _stamp(path, owner, maximum):
    private_path(str(path))
    parent, info = path.parent.lstat(), path.lstat()
    if (
        not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != owner
        or parent.st_mode & 0o077
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != owner
        or info.st_mode & 0o077
        or info.st_nlink != 1
        or not 0 < info.st_size <= maximum
    ):
        raise ValueError("reward exchange cursor has unsafe owner, layout or size")
    return [
        str(value)
        for value in (
            parent.st_dev,
            parent.st_ino,
            parent.st_mode,
            parent.st_uid,
            parent.st_gid,
            info.st_dev,
            info.st_ino,
            info.st_mode,
            info.st_uid,
            info.st_gid,
            info.st_nlink,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
        )
    ]


class RewardExchangeCheckpoint(StrictProtocolModel):
    schema_: Literal["umi-reward-exchange-delivery-checkpoint/1"] = Field(alias="schema")
    binding_sha256: Hex32
    cursors: dict[str, RewardExchangeCursor]
    stamps: dict[str, list[str]]


class RewardExchangeSelection(RewardAdoptionConsumer):
    """One copier-owned selection state, distinct from all live signing journals."""

    def __init__(
        self,
        root,
        *,
        outbox,
        source_owner,
        series,
        policy,
        proposer,
        peer,
        initial=None,
        source=None,
    ):
        if series.policy_sha256 != digest(policy):
            raise ValueError("reward exchange transport selects another policy")
        if type(source_owner) is not int or source_owner < 0:
            raise ValueError("reward exchange transport requires an explicit source owner")
        verify_recovery_authority(series.recovery, policy)
        self.proposer, self.peer = identity(proposer), identity(peer)
        admitted = {identity(item.hotkey) for item in policy.evaluators}
        if self.proposer == self.peer or not {self.proposer, self.peer} <= admitted:
            raise ValueError("reward exchange transport selects invalid independent roles")
        self.root, self.outbox = Path(root), Path(private_path(str(outbox)))
        self.owner, self.series = source_owner, series
        self.series_id = digest(series)
        self.cohorts = tuple(digest(plan) for plan in series.cohorts if plan.sequence >= 6)
        self.binding = digest(
            [
                "umi-reward-exchange-delivery/1",
                self.series_id,
                digest(policy),
                str(self.outbox),
                source_owner,
                self.proposer,
                self.peer,
            ]
        )
        self._configure_reward_adoptions(
            initial,
            series=series,
            policy=policy,
            feed=open_reward_adoption_feed(
                self.root / "adoption-feed",
                source=source,
                series=series,
                policy=policy,
                initial=initial,
                deferred=True,
            ),
        )
        self._saved = None

    def _initialize(self):
        if self._saved is not None:
            return
        ensure_private_directory(self.root)
        marker, checkpoint = self.root / "format.json", self.root / "checkpoint.json"
        expected = b'{"schema":"umi-reward-exchange-delivery-state/1"}'
        if marker.exists():
            if read_owned_file(marker, MAX_CURSOR_BYTES) != expected:
                raise ValueError("reward exchange delivery format requires repair")
            try:
                saved = read(
                    checkpoint, RewardExchangeCheckpoint, maximum_bytes=MAX_CHECKPOINT_BYTES
                )
            except FileNotFoundError:
                raise ValueError("reward exchange delivery lost its completed frontier") from None
        else:
            if checkpoint.exists():
                raise ValueError("reward exchange delivery requires explicit metadata repair")
            saved = RewardExchangeCheckpoint(
                schema="umi-reward-exchange-delivery-checkpoint/1",
                binding_sha256=self.binding,
                cursors={},
                stamps={},
            )
            atomic_write(checkpoint, canonical_json_bytes(saved), immutable=False)
            atomic_write(marker, expected)
        allowed = {"decision", *("adoption-" + cohort for cohort in self.cohorts)}
        if (
            saved.binding_sha256 != self.binding
            or set(saved.cursors) != set(saved.stamps)
            or not set(saved.cursors) <= allowed
        ):
            raise ValueError("reward exchange delivery changed its retained binding")
        for name, cursor in saved.cursors.items():
            self._check(cursor, name)
        self._saved = saved

    def _check(self, cursor, name):
        if (
            cursor.series_sha256 != self.series_id
            or cursor.proposer != self.proposer
            or cursor.name != name
            or (cursor.cohort_sha256 is not None and cursor.cohort_sha256 not in self.cohorts)
        ):
            raise ValueError("reward exchange cursor changes its signed series or proposer")
        _ = cursor.slot

    def __call__(self):
        started = time.monotonic()
        ensure_private_directory(self.root)
        lease = lock_private_file(self.root / "selection.lock")
        try:
            self._initialize()
            selected = self._select()
            logger.info(
                "reward_exchange_discovery completed=%d total=%d requests=%d votes=%d "
                "elapsed_seconds=%.3f eta_seconds=0 eta_basis=bounded_cursor_selection "
                "stalled_or_retrying=false",
                len(self.cohorts) + 1,
                len(self.cohorts) + 1,
                len(selected[0]),
                len(selected[1]),
                time.monotonic() - started,
            )
            return selected
        except Exception as error:
            logger.warning(
                "reward_exchange_discovery elapsed_seconds=%.3f eta_seconds=null "
                "eta_basis=withdrawn_repair_required stalled_or_retrying=true reason=%s",
                time.monotonic() - started,
                str(error),
            )
            raise
        finally:
            fcntl.flock(lease, fcntl.LOCK_UN)
            os.close(lease)

    def _select(self):
        selected = self.refresh_reward_adoptions()
        saved = self._saved
        cursors, stamps = dict(saved.cursors), dict(saved.stamps)
        requests, votes = [], []
        for cohort in (None, *self.cohorts):
            name = "decision" if cohort is None else "adoption-" + cohort
            path = self.outbox / "transport" / self.series_id / (name + ".json")
            try:
                stamp = _stamp(path, self.owner, MAX_CURSOR_BYTES)
            except FileNotFoundError:
                if name in cursors:
                    raise ValueError(
                        "reward exchange cursor lost its completed publication"
                    ) from None
                continue
            if stamps.get(name) == stamp:
                cursor = cursors[name]
            else:
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(fd, "rb") as stream:
                    raw = stream.read(MAX_CURSOR_BYTES + 1)
                if _stamp(path, self.owner, MAX_CURSOR_BYTES) != stamp:
                    raise ValueError("reward exchange cursor changed during read")
                cursor = RewardExchangeCursor.model_validate_json(raw)
                if canonical_json_bytes(cursor) != raw:
                    raise ValueError("reward exchange cursor requires canonical bytes")
                self._check(cursor, name)
                if name in cursors and cursor.position < cursors[name].position:
                    raise ValueError("reward exchange cursor rolled back its retained position")
                cursors[name], stamps[name] = cursor, stamp
            if cohort is None:
                if cursor.position >= reward_decision_capacity(self.series, selected):
                    raise ValueError("reward request exceeds authenticated decision capacity")
            else:
                latest = None if selected is None else selected.latest(cohort)
                revision = 0 if latest is None else latest.adoption.revision
                if cursor.position <= revision:
                    continue
                if cursor.position != revision + 1:
                    raise ValueError("reward adoption request skips its authenticated revision")
            requests.append(Path("requests") / self.series_id / (cursor.slot + ".json"))
            votes.append(Path("votes") / self.series_id / cursor.slot / (self.peer + ".json"))
        if cursors != saved.cursors or stamps != saved.stamps:
            updated = RewardExchangeCheckpoint(
                schema="umi-reward-exchange-delivery-checkpoint/1",
                binding_sha256=self.binding,
                cursors=cursors,
                stamps=stamps,
            )
            raw = canonical_json_bytes(updated)
            if len(raw) > MAX_CHECKPOINT_BYTES:
                raise ValueError("reward exchange delivery frontier exceeds its bound")
            atomic_write(self.root / "checkpoint.json", raw, immutable=False)
            self._saved = updated
        return tuple(requests), tuple(votes)
