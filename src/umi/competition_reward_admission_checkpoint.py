"""One local completed initial-admission interval, with no per-block receipts.

Only the stopped-owner migrator can create this result. Its original native
intent remains a required dependency. Raw-source updates invalidate the interval;
ordinary appended block frames do not. Missing completion state requires repair.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager

from .chain_evidence import FinalizedSnapshotRef
from .competition_evidence_codec import checked_digest
from .competition_reward_admission_source import check_retained_admission_source
from .competition_reward_checkpoint_tip import OwnedCheckpointTip, _issue_checkpoint_tip
from .competition_reward_history_checkpoint import (
    SOURCE_KINDS,
    HistoryCheckpointRepairRequired,
)
from .open_competition import digest
from .protocol import canonical_json_bytes

ABI = "umi-native-completed-admission-interval/1"
_KIND = "control_history_completed_admission"
_DONE = "control_history_completed_admission_done"
_TABLE = "history_completed_admission"
_RELEASE = "control_history_completed_admission_release"
_RELEASE_TRIGGER = "history_completed_admission_reinsert"


def _release_trigger():
    kinds = ",".join("'" + kind + "'" for kind in SOURCE_KINDS)
    return (
        "CREATE TRIGGER " + _RELEASE_TRIGGER + " BEFORE INSERT ON records "
        "WHEN NEW.kind IN (" + kinds + ") AND EXISTS ("
        "SELECT 1 FROM history_source_identity WHERE kind=NEW.kind AND id=NEW.id AND present=0) "
        "BEGIN UPDATE history_completed_admission SET revision=revision+1; END"
    )


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
                or self.journal.get(_RELEASE, "original", db=db) is not None
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
        release = self.journal.get(_RELEASE, "original", db=db)
        reinsert = triggers.get(_RELEASE_TRIGGER)
        if release is None:
            if reinsert is not None:
                raise HistoryCheckpointRepairRequired("completed admission release marker missing")
        elif release != self._release_marker(key) or reinsert != _release_trigger():
            raise HistoryCheckpointRepairRequired("completed admission release fence changed")
        return key

    def _release_marker(self, key):
        return {"schema": "umi-admission-source-release/1", "owner": self.blocks.owner, "key": key}

    @contextmanager
    def preserve_source_release(self, db):
        """Keep the admitted interval across one exact native alias replacement.

        The externalizer owns the immediate transaction and checks the original
        source token, immutable R2 receipt and replacement alias. Its one DELETE
        must be the only raw-source mutation; an existing invalidation or any
        additional mutation refuses and rolls the entire replacement back.
        No completion, provenance, source token or trigger is rewritten.
        """
        if not db.in_transaction or db.execute("PRAGMA query_only").fetchone() != (0,):
            raise ValueError("source release requires its native writer transaction")
        key = self._index(db)
        charged = 0
        if key is not None and self.journal.get(_RELEASE, "original", db=db) is None:
            # Original admissions did not need an INSERT fence: every prefix
            # source already occupied its key. Aliasing makes that key absent.
            # Install its shadow/reinsertion fence atomically before deletion,
            # while retaining the old verdict and both original triggers.
            db.execute(_release_trigger())
            raw = canonical_json_bytes(self._release_marker(key))
            db.execute(
                "INSERT INTO records VALUES (?,?,?)",
                (_RELEASE, "original", raw),
            )
            charged = len(raw)
        yield charged
        if key is not None:
            changed = db.execute(
                "UPDATE history_completed_admission SET revision=0 "
                "WHERE owner=? AND key=? AND revision=1",
                (self.blocks.owner, key),
            ).rowcount
            if changed != 1:
                raise HistoryCheckpointRepairRequired(
                    "completed admission changed during exact source release"
                )

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

    def load_for_restore(self) -> tuple[dict | None, OwnedCheckpointTip | None]:
        value = self.load()
        tip = None if value is None else _issue_checkpoint_tip(self.blocks, value)
        return value, tip

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
