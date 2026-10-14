"""One local completed initial-admission interval, with no per-block receipts.

Only the stopped-owner migrator can create this result. Its original native
intent remains a required dependency. Raw-source updates invalidate the interval;
ordinary appended block frames do not. Missing completion state requires repair.
"""

from __future__ import annotations

import sqlite3

from .chain_evidence import FinalizedSnapshotRef
from .competition_evidence_codec import checked_digest
from .competition_reward_admission_source import check_retained_admission_source
from .competition_reward_history_checkpoint import (
    SOURCE_KINDS,
    HistoryCheckpointRepairRequired,
)
from .open_competition import digest

ABI = "umi-native-completed-admission-interval/1"
_KIND = "control_history_completed_admission"
_DONE = "control_history_completed_admission_done"
_TABLE = "history_completed_admission"


def _triggers():
    kinds = ",".join("'" + kind + "'" for kind in SOURCE_KINDS)
    return {
        "history_completed_admission_" + action.lower(): (
            "CREATE TRIGGER history_completed_admission_"
            + action.lower()
            + " AFTER "
            + action
            + " ON records WHEN OLD.kind IN ("
            + kinds
            + ") "
            "BEGIN UPDATE history_completed_admission SET revision=revision+1; END"
        )
        for action in ("UPDATE", "DELETE")
    }


class CompletedAdmissionCheckpoint:
    def __init__(self, checkpoints):
        self.blocks = checkpoints
        self.journal = checkpoints.journal

    def _index(self, db):
        installed = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (_TABLE,)
        ).fetchone()
        done = self.journal.get(_DONE, "original", db=db)
        if not installed:
            if (
                done is not None
                or db.execute("SELECT 1 FROM records WHERE kind=? LIMIT 1", (_KIND,)).fetchone()
                or db.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='trigger' "
                    "AND name LIKE 'history_completed_admission_%' LIMIT 1"
                ).fetchone()
            ):
                raise HistoryCheckpointRepairRequired("completed admission index is missing")
            return None
        rows = db.execute("SELECT owner,key,revision FROM " + _TABLE + " LIMIT 2").fetchall()
        if len(rows) != 1 or rows[0][0] != self.blocks.owner:
            raise HistoryCheckpointRepairRequired("completed admission original owner changed")
        owner, key, revision = rows[0]
        if done != {"owner": owner, "key": key} or revision != 0:
            raise HistoryCheckpointRepairRequired("completed admission source or marker changed")
        triggers = dict(db.execute("SELECT name,sql FROM sqlite_master WHERE type='trigger'"))
        if any(triggers.get(name) != sql for name, sql in _triggers().items()):
            raise HistoryCheckpointRepairRequired("completed admission source fence changed")
        return key

    def load(self):
        try:
            with self.journal.read_transaction() as db:
                self.blocks.check_schema(db)
                key = self._index(db)
                if key is None:
                    return None
                value = self.journal.get(_KIND, key, db=db)
                if not isinstance(value, dict) or digest(value) != key:
                    raise HistoryCheckpointRepairRequired("completed admission result is missing")
                self.validate(value)
                self.blocks.check_sources(value["boundary_sources"], db)
            check_retained_admission_source(value)
            return value
        except HistoryCheckpointRepairRequired:
            raise
        except (
            OSError,
            KeyError,
            TypeError,
            ValueError,
            RecursionError,
            sqlite3.DatabaseError,
        ) as error:
            raise HistoryCheckpointRepairRequired(
                "completed admission requires explicit provenance repair"
            ) from error

    def validate(self, value):
        fields = {
            "schema",
            "owner",
            "semantics",
            "first_block",
            "control_hotkey",
            "chain_config_sha256",
            "snapshot",
            "header",
            "control_sha256",
            "committed_at_block",
            "history_sha256",
            "provenance_path",
            "provenance_sha256",
            "source_sha256",
            "boundary_sources",
        }
        if (
            set(value) != fields
            or value["schema"] != ABI
            or value["owner"] != self.blocks.owner
            or value["semantics"] != self.blocks.semantics
            or value["control_sha256"] is not None
            or value["committed_at_block"] is not None
        ):
            raise HistoryCheckpointRepairRequired("completed admission semantics or owner changed")
        snapshot = FinalizedSnapshotRef(**value["snapshot"])
        if (
            type(value["first_block"]) is not int
            or not 0 < value["first_block"] <= snapshot.block_number
        ):
            raise HistoryCheckpointRepairRequired("completed admission interval changed")
        for field in (
            "chain_config_sha256",
            "history_sha256",
            "provenance_sha256",
            "source_sha256",
        ):
            checked_digest(value[field])
        if (
            not isinstance(value["header"], str)
            or not value["header"].startswith("0x")
            or bytes.fromhex(value["header"][2:]).hex() != value["header"][2:]
            or not value["boundary_sources"]
        ):
            raise HistoryCheckpointRepairRequired("completed admission boundary changed")

    def remember(self, value):
        """Atomic completed result/index; an interrupted acknowledgement is reusable."""
        self.validate(value)
        key = digest(value)
        old = self.load()
        if old is not None:
            if old != value:
                raise HistoryCheckpointRepairRequired(
                    "completed admission differs from retained result"
                )
            return

        def index(db):
            if db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (_TABLE,)
            ).fetchone():
                raise HistoryCheckpointRepairRequired("admission migration ownership changed")
            self.blocks.check_sources(value["boundary_sources"], db)
            if db.execute(
                "SELECT 1 FROM history_checkpoint_index WHERE height<=? LIMIT 1",
                (value["snapshot"]["block_number"],),
            ).fetchone():
                raise HistoryCheckpointRepairRequired(
                    "admission migration overlaps existing block results"
                )
            db.execute(
                "CREATE TABLE "
                + _TABLE
                + "(owner TEXT NOT NULL,key TEXT NOT NULL,revision INTEGER NOT NULL)"
            )
            db.execute("INSERT INTO " + _TABLE + " VALUES (?,?,0)", (self.blocks.owner, key))
            for sql in _triggers().values():
                db.execute(sql)

        # Original owner locks cover the preflight and atomic result/index write.
        self.journal.put_many(
            ((_KIND, key, value), (_DONE, "original", {"owner": self.blocks.owner, "key": key})),
            index=index,
        )
