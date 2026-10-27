"""Deliver an owned folded history to a newly selected local proof archive.

The native fold stays intact. Each bounded pass copies completed checkpoint
transport and advances a separate durable destination cursor. The checkpoint's
export receipt handles a lost acknowledgement between copy and cursor commit.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

from .competition_reward_history_checkpoint import HistoryCheckpointRepairRequired
from .open_competition import digest

_TABLE = "history_local_archive_delivery_heads"
_SQL = f"CREATE TABLE {_TABLE}(scope TEXT PRIMARY KEY,head TEXT NOT NULL)"
_OWNER = "history_local_archive_delivery_owner"
_STEP = "history_local_archive_delivery_step"


class HistoryLocalArchiveDelivery:
    def __init__(self, reader):
        self.reader = reader
        self.journal = reader.journal
        self.identity = reader._export_identity()
        if self.identity is None:
            raise HistoryCheckpointRepairRequired("local archive destination identity is missing")
        self.context = dict(
            schema="umi-history-local-archive-delivery/1",
            owner=reader.checkpoints.owner,
            destination=self.identity,
            first_block=reader.first_block,
        )
        self.scope = digest(self.context)
        self.started = time.monotonic()
        self.completed_attempt = 0
        prior = self.journal.get(_OWNER, self.scope)
        if prior is not None and prior != self.context:
            raise HistoryCheckpointRepairRequired("local archive delivery owner changed")
        start = dict(
            scope=self.scope,
            next_block=reader.first_block,
            started_utc=datetime.now(timezone.utc).isoformat(),
            prior=None,
        )
        start_key = digest(start)

        def initialize(db):
            table = db.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (_TABLE,)
            ).fetchone()
            if table is None:
                if prior is not None:
                    raise HistoryCheckpointRepairRequired(
                        "local archive delivery cursor is missing"
                    )
                db.execute(_SQL)
            elif table != (_SQL,):
                raise HistoryCheckpointRepairRequired("local archive delivery schema changed")
            head = db.execute(f"SELECT head FROM {_TABLE} WHERE scope=?", (self.scope,)).fetchone()
            if head is None:
                if prior is not None:
                    raise HistoryCheckpointRepairRequired("local archive delivery head is missing")
                db.execute(f"INSERT INTO {_TABLE} VALUES (?,?)", (self.scope, start_key))

        records = [(_OWNER, self.scope, self.context)]
        if prior is None:
            records.append((_STEP, start_key, start))
        self.journal.put_many(records, index=initialize)
        self._state()

    def _state(self):
        with self.journal.read_transaction() as db:
            table = db.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (_TABLE,)
            ).fetchone()
            owner = self.journal.get(_OWNER, self.scope, db=db)
            row = db.execute(f"SELECT head FROM {_TABLE} WHERE scope=?", (self.scope,)).fetchone()
            value = None if row is None else self.journal.get(_STEP, row[0], db=db)
            if (
                table != (_SQL,)
                or owner != self.context
                or value is None
                or digest(value) != row[0]
                or value.get("scope") != self.scope
                or type(value.get("next_block")) is not int
                or value["next_block"] < self.reader.first_block
                or value["next_block"] > self.reader._next
            ):
                raise HistoryCheckpointRepairRequired("local archive delivery cursor damaged")
            return row[0], value

    def _commit(self, head, value):
        key = digest(value)

        def select(db):
            current = db.execute(
                f"SELECT head FROM {_TABLE} WHERE scope=?", (self.scope,)
            ).fetchone()
            if current != (head,):
                raise HistoryCheckpointRepairRequired("local archive delivery owner advanced")
            db.execute(f"UPDATE {_TABLE} SET head=? WHERE scope=?", (key, self.scope))

        self.journal.put_many(((_STEP, key, value),), index=select)

    async def run(self, maximum_frames):
        if type(maximum_frames) is not int or not 1 <= maximum_frames <= 4096:
            raise ValueError("local archive delivery requires a bounded frame count")
        head, state = self._state()
        through = self.reader._next - 1
        stop = min(through + 1, state["next_block"] + maximum_frames)
        for height in range(state["next_block"], stop):
            if self.reader._shutdown_requested():
                break
            checkpoint = self.reader.checkpoints.load(height)
            if checkpoint is None:
                raise HistoryCheckpointRepairRequired(
                    "completed archive delivery checkpoint is missing"
                )
            await self.reader._ensure_checkpoint_export(checkpoint)
            updated = dict(state, prior=head, next_block=height + 1)
            self._commit(head, updated)
            head, state = digest(updated), updated
            self.completed_attempt += 1
        total = max(0, through - self.reader.first_block + 1)
        completed = min(total, state["next_block"] - self.reader.first_block)
        remaining = total - completed
        elapsed = time.monotonic() - self.started
        rate = self.completed_attempt / elapsed if self.completed_attempt and elapsed >= 1 else None
        return dict(
            stage="history_archive_delivery_migration",
            state="completed" if not remaining else "pending",
            first_block=self.reader.first_block,
            through_block=through,
            next_block=state["next_block"],
            completed_blocks=completed,
            total_blocks=total,
            percent=100 * completed / total if total else 100,
            elapsed_seconds=(
                datetime.now(timezone.utc) - datetime.fromisoformat(state["started_utc"])
            ).total_seconds(),
            attempt_elapsed_seconds=elapsed,
            attempt_completed_blocks=self.completed_attempt,
            blocks_per_second=rate,
            eta_seconds=remaining / rate if rate else 0 if not remaining else None,
            planning_eta_seconds=[remaining / 100, remaining]
            if remaining and rate is None
            else None,
            eta_basis="measured_current_process_archive_frames_per_second"
            if rate
            else "complete_archive_delivery"
            if not remaining
            else "planning_unmeasured_1_to_100_frames_per_second",
            eta_scope="archive_delivery_only_not_native_history_or_rewards",
            stalled=False,
            retrying=False,
            native_fold_reused=self.reader._folded_tip is not None,
        )
