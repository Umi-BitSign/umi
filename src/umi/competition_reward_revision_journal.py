"""Permanent revision inventory; retained metadata never substitutes for native proofs.

The independent immutable ledger detects lost target, endpoint and live-lock
records. A fresh installation creates its marker, table and fences atomically.
An existing incomplete inventory requires explicit repair, never silent reset.
"""

import json

from .competition_transport_verification import TransferProgress
from .open_competition import digest
from .protocol import canonical_json_bytes

_TABLE = (
    "CREATE TABLE reward_revision_completion(kind TEXT,id TEXT,sha256 TEXT NOT NULL,"
    "body BLOB NOT NULL,"
    "PRIMARY KEY(kind,id))"
)
_OWNER = {"schema": "umi-reward-revision-completion/1"}
_KINDS = {
    "reward_revision_target",
    "reward_revision_endpoint",
    "reward_revision_endpoint_done",
    "reward_economics_live_lock",
}


def _triggers():
    values = {}
    for action in ("UPDATE", "DELETE"):
        name = "reward_revision_completion_" + action.lower()
        values[name] = (
            f"CREATE TRIGGER {name} BEFORE {action} ON reward_revision_completion "
            "BEGIN SELECT RAISE(ABORT,'reward revision completion is permanent'); END"
        )
        name = "reward_revision_completion_owner_" + action.lower()
        values[name] = (
            f"CREATE TRIGGER {name} BEFORE {action} ON records "
            "WHEN OLD.kind='reward_revision_owner' BEGIN SELECT "
            "RAISE(ABORT,'reward revision owner is immutable'); END"
        )
    return values


class RevisionProgressJournal:
    def __init__(self, journal):
        self.journal = journal
        self.triggers = _triggers()
        with journal.read_transaction() as db:
            existing = db.execute(
                "SELECT 1 FROM sqlite_master WHERE name GLOB 'reward_revision_completion*' "
                "UNION ALL SELECT 1 FROM records WHERE kind LIKE 'reward_revision_%' "
                "OR kind='reward_economics_live_lock' LIMIT 1"
            ).fetchone()
            if existing:
                self._schema(db)
                return

        def initialize(db):
            if db.execute(
                "SELECT 1 FROM sqlite_master WHERE name='reward_revision_completion'"
            ).fetchone():
                self._schema(db)
                return
            db.execute(_TABLE)
            for sql in self.triggers.values():
                db.execute(sql)

        journal.put_many((("reward_revision_owner", "owner", _OWNER),), index=initialize)

    def _schema(self, db):
        table = db.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='reward_revision_completion'"
        ).fetchone()
        fences = dict(
            db.execute(
                "SELECT name,sql FROM sqlite_master WHERE type='trigger' "
                "AND name GLOB 'reward_revision_completion_*'"
            )
        )
        if (
            table != (_TABLE,)
            or fences != self.triggers
            or self.journal.get("reward_revision_owner", "owner", db=db) != _OWNER
        ):
            raise ValueError("reward revision completion ledger needs original metadata repair")

    def get(self, kind, key):
        if kind not in _KINDS:
            raise ValueError("unsupported reward revision record")
        with self.journal.read_transaction() as db:
            self._schema(db)
            value = self.journal.get(kind, key, db=db)
            completed = db.execute(
                "SELECT sha256,body FROM reward_revision_completion WHERE kind=? AND id=?",
                (kind, key),
            ).fetchone()
            original = None if completed is None else json.loads(completed[1])
            if (completed is not None and completed[0] != digest(original)) or (
                value is not None and (completed is None or value != original)
            ):
                raise ValueError("reward revision completed record needs original metadata repair")
        if value is None and completed is not None:
            # The permanent inventory retains the exact original small record.
            # Restore it visibly, then the consumer still reopens its native
            # proof owner. This grants no authority to these metadata bytes.
            with TransferProgress(
                "reward_revision_metadata_repair",
                1,
                unit="records",
                planning_unit_seconds=(0.001, 1),
            ) as progress:
                progress.emit("running", reason="restore_exact_retained_revision_metadata")
                self.put_many(((kind, key, original),))
                progress.advance(1)
            return original
        return value

    def put_many(self, records):
        records = tuple(records)
        if any(kind not in _KINDS for kind, _, _ in records):
            raise ValueError("unsupported reward revision record")

        def complete(db):
            self._schema(db)
            for kind, key, value in records:
                old = db.execute(
                    "SELECT sha256 FROM reward_revision_completion WHERE kind=? AND id=?",
                    (kind, key),
                ).fetchone()
                if old is not None and old != (digest(value),):
                    raise ValueError("reward revision completion changes immutable identity")
                db.execute(
                    "INSERT OR IGNORE INTO reward_revision_completion VALUES (?,?,?,?)",
                    (kind, key, digest(value), canonical_json_bytes(value)),
                )

        self.journal.put_many(records, index=complete)

    def retain_first(self, kind, key, value):
        """Equivalent native live proofs keep the first winner under one owner."""
        with self.journal.locked():
            prior = self.get(kind, key)
            if prior is None:
                self.put_many(((kind, key, value),))
                return value
            return prior
