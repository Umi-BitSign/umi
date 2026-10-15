"""Preserve legacy unverified writer sources during an explicitly selected upgrade.

Raw sources never establish accepted history. The candidate must independently
restore its native completed prefix and cover the same retained block records.
The original directory, including every source payload, remains frozen and owned
through the exchange. Completed, missing-result or unfamiliar state is refused.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field

from .competition_reward_history import (
    OwnedRewardControlHistory,
    RewardControlHistoryReader,
    validate_control_history,
)
from .competition_reward_history_checkpoint import SOURCE_KINDS, HistoryCheckpointRepairRequired
from .competition_reward_writer_journals import StoppedWriterJournals
from .competition_work_progress import WorkProgress
from .open_competition import digest

_ISSUER = object()


def _stamp(journals):
    info = os.stat("rounds.sqlite3", dir_fd=journals._original_history_fd, follow_symlinks=False)
    return info.st_dev, info.st_ino, info.st_size, str(info.st_mtime_ns), str(info.st_ctime_ns)


@dataclass(frozen=True, slots=True)
class SourceOnlyOriginalWriterHistory:
    first_block: int
    source_tip: int
    control_hotkey: str
    chain_config_sha256: str
    original_owner: str
    source_counts: tuple
    block_records: tuple
    _journal_owner: StoppedWriterJournals = field(repr=False)
    _stamp: tuple = field(repr=False)
    _issuer: object = field(default=None, repr=False)
    _binding: str = field(default="", repr=False)

    def seal(self):
        return digest(
            [
                self.first_block,
                self.source_tip,
                self.control_hotkey,
                self.chain_config_sha256,
                self.original_owner,
                self.source_counts,
                self.block_records,
                self._journal_owner._binding,
                self._stamp,
            ]
        )

    def validate(self):
        if (
            type(self) is not SourceOnlyOriginalWriterHistory
            or self._issuer is not _ISSUER
            or self._binding != self.seal()
        ):
            raise ValueError("unverified original sources lack native retained ownership")
        self._journal_owner.recheck()
        if _stamp(self._journal_owner) != self._stamp:
            raise HistoryCheckpointRepairRequired("retained original source database changed")


@dataclass(frozen=True, slots=True)
class CoveredOriginalWriterSources:
    original: SourceOnlyOriginalWriterHistory
    candidate_binding: str
    _issuer: object = field(default=None, repr=False)
    _binding: str = field(default="", repr=False)

    def seal(self):
        return digest([self.original._binding, self.candidate_binding])

    def validate(self, original, candidate):
        if (
            type(self) is not CoveredOriginalWriterSources
            or self._issuer is not _ISSUER
            or self._binding != self.seal()
            or self.original is not original
            or type(candidate) is not OwnedRewardControlHistory
            or candidate._binding != self.candidate_binding
        ):
            raise ValueError("original source coverage lacks its native candidate")
        original.validate()


def review_source_only_original(reader, journals, *, through_block):
    if (
        type(reader) is not RewardControlHistoryReader
        or type(journals) is not StoppedWriterJournals
    ):
        raise TypeError("source preservation requires native readers and stopped ownership")
    journals.recheck()
    if reader.journal.root != journals.root / "history":
        raise ValueError("source preservation differs from original history")
    before = _stamp(journals)
    with reader.journal.read_transaction() as db:
        reader.checkpoints.check_schema(db)
        empty_tables = {
            "holds",
            "highwater",
            "round_index",
            "plan_index",
            "round_settlement_index",
            "history_checkpoint_index",
        }
        allowed = empty_tables | {
            "binding",
            "records",
            "history_checkpoint_state",
            "history_source_identity",
            "round_record_capacity",
            "round_record_capacity_kinds",
        }
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if tables != allowed or db.execute("PRAGMA user_version").fetchone()[0] != 0:
            raise HistoryCheckpointRepairRequired(
                "source-only original has unsupported auxiliary state"
            )
        if db.execute("SELECT highest FROM history_checkpoint_state").fetchall() != [
            (reader.first_block - 1,)
        ]:
            raise HistoryCheckpointRepairRequired(
                "source-only original has retained completed work"
            )
        for table in empty_tables:
            if db.execute("SELECT 1 FROM " + table + " LIMIT 1").fetchone():
                raise HistoryCheckpointRepairRequired("source-only original has retained outcomes")
        counts = tuple(db.execute("SELECT kind,COUNT(*) FROM records GROUP BY kind"))
        if set(k for k, _ in counts) - {*SOURCE_KINDS, "control_history_checkpoint_owner"}:
            raise HistoryCheckpointRepairRequired(
                "source-only original has results or unknown records"
            )
        if db.execute(
            "SELECT id FROM records WHERE kind='control_history_checkpoint_owner'"
        ).fetchall() != [("owner",)]:
            raise HistoryCheckpointRepairRequired("source-only original owner record differs")
        # Tombstones or missing mutation identities are repairs, never ordinary legacy input.
        if db.execute(
            "SELECT 1 FROM history_source_identity WHERE present!=1 OR revision<0 LIMIT 1"
        ).fetchone():
            raise HistoryCheckpointRepairRequired(
                "source-only original has damaged source identities"
            )
        source_count = sum(n for kind, n in counts if kind in SOURCE_KINDS)
        if db.execute("SELECT COUNT(*) FROM history_source_identity").fetchone()[0] != source_count:
            raise HistoryCheckpointRepairRequired(
                "source-only original source identities are incomplete"
            )
        blocks = []
        total = dict(counts).get("control_history_block", 0)
        if total < 1 or total > through_block - reader.first_block + 1:
            raise ValueError("source-only original exceeds selected candidate interval")
        with WorkProgress("writer_original_source_inventory", total, unit="blocks") as progress:
            for key, body in db.execute(
                "SELECT id,body FROM records WHERE kind='control_history_block' "
                "ORDER BY length(id),id"
            ):
                height = reader.first_block + len(blocks)
                if key != str(height) or height > through_block:
                    raise HistoryCheckpointRepairRequired(
                        "original source interval is incomplete or unsupported"
                    )
                blocks.append((height, hashlib.sha256(body).hexdigest()))
                progress.advance()
    if _stamp(journals) != before:
        raise HistoryCheckpointRepairRequired("original sources changed during inventory")
    value = SourceOnlyOriginalWriterHistory(
        reader.first_block,
        blocks[-1][0],
        reader.hotkey,
        reader.config_sha256,
        reader.checkpoints.owner,
        counts,
        tuple(blocks),
        journals,
        before,
        _ISSUER,
    )
    object.__setattr__(value, "_binding", value.seal())
    value.validate()
    return value


def cover_source_only_original(original, reader, candidate):
    """Compare bounded block envelopes only after actual native candidate restoration."""
    if (
        type(original) is not SourceOnlyOriginalWriterHistory
        or type(reader) is not RewardControlHistoryReader
    ):
        raise TypeError("source coverage requires original ownership and a native candidate reader")
    original.validate()
    validate_control_history(
        candidate,
        first_block=original.first_block,
        tip=candidate.tip,
        control_hotkey=original.control_hotkey,
        chain_config_sha256=original.chain_config_sha256,
    )
    if (
        candidate.unresolved_blocks
        or candidate.tip.block_number < original.source_tip
        or reader.journal.root != original._journal_owner.root / "history"
        or reader.checkpoints.owner == original.original_owner
        or candidate != reader._prefix(candidate.tip.block_number)
    ):
        raise ValueError("source coverage requires the actual restored candidate interval")
    with reader.journal.read_transaction() as db:
        reader.checkpoints.check_schema(db)
        with WorkProgress(
            "writer_original_source_coverage", len(original.block_records), unit="blocks"
        ) as progress:
            for height, checksum in original.block_records:
                row = db.execute(
                    "SELECT body FROM records WHERE kind='control_history_block' AND id=?",
                    (str(height),),
                ).fetchone()
                if row is None or hashlib.sha256(row[0]).hexdigest() != checksum:
                    raise HistoryCheckpointRepairRequired(
                        "candidate does not cover retained original block sources"
                    )
                progress.advance()
    original.validate()
    value = CoveredOriginalWriterSources(original, candidate._binding, _ISSUER)
    object.__setattr__(value, "_binding", value.seal())
    value.validate(original, candidate)
    return value
