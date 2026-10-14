"""Original retained native prefix selection, including an explicit empty original."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from .competition_reward_history import RewardControlHistoryReader
from .competition_reward_history_checkpoint import HistoryCheckpointRepairRequired
from .competition_reward_writer_journals import StoppedWriterJournals
from .historical_header_recovery import HistoricalHeaderRecoveryProgress
from .open_competition import digest

_ISSUER = object()


def retained_completed_tip(reader):
    """Read completed metadata only; missing or damaged successes require repair."""
    if type(reader) is not RewardControlHistoryReader:
        raise TypeError("original prefix requires a native history reader")
    completed = reader.completed_admission.load()
    with reader.journal.read_transaction() as db:
        reader.checkpoints.check_schema(db)
        highest = db.execute("SELECT highest FROM history_checkpoint_state").fetchone()[0]
        maximum = db.execute("SELECT MAX(height) FROM history_checkpoint_index").fetchone()[0]
        if (
            type(highest) is not int
            or highest < reader.first_block - 1
            or (maximum is not None and highest != maximum)
            or (maximum is None and highest != reader.first_block - 1)
        ):
            raise HistoryCheckpointRepairRequired("original completed history tip is damaged")
    return max(
        highest,
        reader.first_block - 1 if completed is None else completed["snapshot"]["block_number"],
    )


@dataclass(frozen=True, slots=True)
class EmptyOriginalWriterHistory:
    first_block: int
    control_hotkey: str
    chain_config_sha256: str
    original_owner: str
    _journal_owner: StoppedWriterJournals = field(repr=False)
    _issuer: object = field(default=None, repr=False)
    _binding: str = field(default="", repr=False)

    def seal(self):
        return digest(
            [
                self.first_block,
                self.control_hotkey,
                self.chain_config_sha256,
                self.original_owner,
                self._journal_owner._binding,
            ]
        )

    def validate(self):
        if (
            type(self) is not EmptyOriginalWriterHistory
            or self._issuer is not _ISSUER
            or self._binding != self.seal()
        ):
            raise ValueError("empty original history lacks its native retained owner")
        self._journal_owner.recheck()


def review_empty_original(reader, journal_owner):
    if (
        type(reader) is not RewardControlHistoryReader
        or type(journal_owner) is not StoppedWriterJournals
    ):
        raise TypeError("empty original requires genuine stopped journal ownership")
    journal_owner.recheck()
    if reader.journal.root != journal_owner.root / "history":
        raise ValueError("empty original differs from original logical history")
    with reader.journal.read_transaction() as db:
        reader.checkpoints.check_schema(db)
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        empty_tables = {
            "holds",
            "highwater",
            "round_index",
            "plan_index",
            "round_settlement_index",
            "history_source_identity",
            "history_checkpoint_index",
        }
        allowed = empty_tables | {
            "binding",
            "records",
            "history_checkpoint_state",
            "round_record_capacity",
            "round_record_capacity_kinds",
        }
        if tables - allowed or db.execute("PRAGMA user_version").fetchone()[0] != 0:
            raise HistoryCheckpointRepairRequired("empty original has unsupported auxiliary state")
        if reader.completed_admission._index(db) is not None:
            raise HistoryCheckpointRepairRequired("original has completed admission state")
        if db.execute("SELECT highest FROM history_checkpoint_state").fetchall() != [
            (reader.first_block - 1,)
        ]:
            raise HistoryCheckpointRepairRequired("original history is not empty")
        for table in empty_tables:
            if db.execute("SELECT 1 FROM " + table + " LIMIT 1").fetchone():
                raise HistoryCheckpointRepairRequired(
                    "original history retains work or source metadata"
                )
        if db.execute("SELECT kind,id FROM records").fetchall() != [
            ("control_history_checkpoint_owner", "owner")
        ]:
            raise HistoryCheckpointRepairRequired(
                "original history retains source or result records"
            )
    value = EmptyOriginalWriterHistory(
        reader.first_block,
        reader.hotkey,
        reader.config_sha256,
        reader.checkpoints.owner,
        journal_owner,
        _ISSUER,
    )
    object.__setattr__(value, "_binding", value.seal())
    value.validate()
    return value


async def restore_completed_prefix(reader, provider, *, through_block, maximum_blocks, owner):
    """Restore only retained successful results; never start new block verification."""
    if type(reader) is not RewardControlHistoryReader or maximum_blocks < 1:
        raise TypeError("completed prefix requires native bounded reader")
    reader._validate_advance(provider, through_block, maximum_blocks)
    reader.progress.start(through_block, reader._next, repair=False)
    try:
        async with reader._advance_lock, reader._lock:
            with reader.journal.locked():
                while True:
                    try:
                        await reader._restore_completed_admission(provider, through_block)
                        break
                    except HistoricalHeaderRecoveryProgress:
                        await owner.recheck()
                        await asyncio.sleep(0)
                while reader._next <= through_block:
                    await owner.recheck()
                    last = min(through_block, reader._next + maximum_blocks - 1)
                    try:
                        await reader._restore_prefix(provider, last)
                    except HistoricalHeaderRecoveryProgress:
                        await owner.recheck()
                        await asyncio.sleep(0)
                        continue
                    if reader._next <= last:
                        raise HistoryCheckpointRepairRequired(
                            "selected completed prefix has a gap; finish preparation before cutover"
                        )
                return reader._prefix(through_block)
    finally:
        reader.progress.finish()
