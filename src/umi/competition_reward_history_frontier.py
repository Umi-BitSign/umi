"""Owner-produced folded history prefixes, independent of proof payload caches.

Native block checkpoints remain authoritative. This stores their already applied
ordered fold and sparse prefix anchors. UPDATE/DELETE, conflicts and receipt
damage invalidate reuse; ordinary appended work and exact source externalization
do not. A frontier never supplies current finality or a new native block verdict.
"""

import secrets
import sqlite3
from bisect import bisect_left
from contextlib import contextmanager
from dataclasses import asdict
from functools import wraps

from . import competition_reward_admission_provenance as provenance
from .chain_evidence import FinalizedSnapshotRef
from .competition_reward_checkpoint_tip import _issue_checkpoint_tip
from .competition_reward_history_checkpoint import HistoryCheckpointRepairRequired
from .open_competition import digest

SCHEMA = "umi-native-history-folded-frontier/1"
_STATE = "history_folded_state"
_ANCHORS = "history_folded_anchors"
_KIND = "control_history_folded_frontier"
_ANCHOR = "control_history_folded_anchor"
_MARKER = "control_history_folded_owner"
_GENERATION = "control_history_folded_generation"
_POPULATED = "control_history_folded_populated"
ANCHOR_INTERVAL = 64
_STATE_SQL = (
    f"CREATE TABLE {_STATE}(owner TEXT NOT NULL,revision INTEGER NOT NULL,"
    "highest INTEGER NOT NULL,key TEXT,generation TEXT NOT NULL)"
)
_ANCHOR_SQL = f"CREATE TABLE {_ANCHORS}(height INTEGER PRIMARY KEY,key TEXT NOT NULL)"


def _repair_metadata(function):
    @wraps(function)
    def checked(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except HistoryCheckpointRepairRequired:
            raise
        except (OSError, KeyError, TypeError, ValueError, sqlite3.DatabaseError) as error:
            raise HistoryCheckpointRepairRequired(
                "folded history metadata or dependency damaged; explicit scoped repair required"
            ) from error

    return checked


def _triggers():
    change = "UPDATE history_folded_state SET revision=revision+1;"
    triggers = {
        "history_folded_source": "CREATE TRIGGER history_folded_source AFTER UPDATE ON "
        "history_source_identity BEGIN " + change + " END",
        "history_folded_source_delete": "CREATE TRIGGER history_folded_source_delete AFTER DELETE "
        "ON history_source_identity BEGIN " + change + " END",
        "history_folded_index_delete": "CREATE TRIGGER history_folded_index_delete AFTER DELETE "
        "ON history_checkpoint_index WHEN OLD.height<=(SELECT highest FROM history_folded_state) "
        "BEGIN " + change + " END",
        "history_folded_index_insert": "CREATE TRIGGER history_folded_index_insert AFTER INSERT "
        "ON history_checkpoint_index WHEN NEW.height<=(SELECT highest FROM history_folded_state) "
        "BEGIN " + change + " END",
        "history_folded_index_update": "CREATE TRIGGER history_folded_index_update AFTER UPDATE "
        "ON history_checkpoint_index WHEN OLD.height<=(SELECT highest FROM history_folded_state) "
        "AND (OLD.height!=NEW.height OR json_remove((SELECT body FROM records WHERE "
        "kind='control_history_verified' AND id=OLD.key),'$.exports','$.repair') IS NOT "
        "json_remove((SELECT body FROM records WHERE kind='control_history_verified' "
        "AND id=NEW.key),'$.exports','$.repair')) BEGIN " + change + " END",
    }
    for action in ("UPDATE", "DELETE"):
        name = "history_folded_record_" + action.lower()
        triggers[name] = (
            f"CREATE TRIGGER {name} AFTER {action} ON records WHEN OLD.kind IN "
            "('control_history_verified','control_history_checkpoint_done',"
            "'control_history_completed_admission','control_history_completed_admission_done',"
            "'control_history_folded_anchor','control_history_folded_generation',"
            "'control_history_folded_populated',"
            "'control_history_original_export_origin') BEGIN " + change + " END"
        )
        name = "history_folded_selected_" + action.lower()
        triggers[name] = (
            f"CREATE TRIGGER {name} AFTER {action} ON records WHEN OLD.kind="
            "'control_history_folded_frontier' AND OLD.id=(SELECT key FROM "
            "history_folded_state) BEGIN " + change + " END"
        )
        name = "history_folded_anchor_" + action.lower()
        triggers[name] = f"CREATE TRIGGER {name} AFTER {action} ON {_ANCHORS} BEGIN {change} END"
    for action in ("INSERT", "UPDATE", "DELETE"):
        name = "history_folded_hold_" + action.lower()
        triggers[name] = f"CREATE TRIGGER {name} AFTER {action} ON holds BEGIN {change} END"
    return triggers


def remember_export_range(ranges, low, high):
    """Maintain compact delivery intervals without scanning the old prefix."""
    if high < low:
        return
    position = bisect_left(ranges, [low, -1])
    if position and ranges[position - 1][1] >= low - 1:
        position -= 1
        low = min(low, ranges[position][0])
        high = max(high, ranges[position][1])
    end = position
    while end < len(ranges) and ranges[end][0] <= high + 1:
        high = max(high, ranges[end][1])
        end += 1
    ranges[position:end] = [[low, high]]


def folded_checkpoint(previous, value):
    """Fold only already validated native metadata; issue no proof authority."""
    snapshot = FinalizedSnapshotRef(**value["snapshot"])
    prior = None if previous is None else FinalizedSnapshotRef(**previous["snapshot"])
    if prior is not None and (
        snapshot.block_number != prior.block_number + 1 or snapshot.parent_hash != prior.block_hash
    ):
        raise ValueError("control history has a gap or a different parent")
    unresolved = bool(value["unresolved_extrinsics"])
    if (
        previous is not None
        and not value["writes"]
        and (value["control_sha256"], value["committed_at_block"])
        != (previous["control_sha256"], previous["committed_at_block"])
    ):
        unresolved = True
    evidence = digest(
        dict(
            prior=previous["evidence"] if previous else value["initial_evidence"],
            block=snapshot.block_number,
            slot=value["slot_evidence_sha256"],
            writes=value["write_evidence_sha256"],
        )
    )
    return dict(
        snapshot=asdict(snapshot),
        header=value["header"],
        control_sha256=value["control_sha256"],
        committed_at_block=value["committed_at_block"],
        evidence=evidence,
        writes=(previous["writes"] if previous else 0) + len(value["writes"]),
        unresolved=(previous["unresolved"] if previous else 0) + int(unresolved),
    )


class FoldedHistoryFrontier:
    def __init__(self, checkpoints):
        self.blocks, self.journal = checkpoints, checkpoints.journal
        self.marker = dict(schema=SCHEMA, owner=checkpoints.owner, semantics=checkpoints.semantics)
        self.triggers = _triggers()
        if self.journal.read_only or self.journal.existing_only:
            return
        marker_before = self.journal.get(_MARKER, "owner")
        if marker_before is not None and marker_before != self.marker:
            raise HistoryCheckpointRepairRequired(
                "folded history frontier owner or semantics changed"
            )

        def initialize(db):
            present = db.execute("SELECT 1 FROM sqlite_master WHERE name=?", (_STATE,)).fetchone()
            marker = self.journal.get(_MARKER, "owner", db=db)
            if not present:
                if (
                    marker_before is not None
                    or db.execute(
                        "SELECT 1 FROM records WHERE kind IN (?,?) LIMIT 1", (_KIND, _ANCHOR)
                    ).fetchone()
                ):
                    raise HistoryCheckpointRepairRequired(
                        "folded history frontier index is missing"
                    )
                db.execute(_STATE_SQL)
                db.execute(
                    f"INSERT INTO {_STATE} VALUES (?,0,?,NULL,'initial')",
                    (checkpoints.owner, checkpoints.binding["first_block"] - 1),
                )
                db.execute(_ANCHOR_SQL)
                for sql in self.triggers.values():
                    db.execute(sql)
            elif marker != self.marker:
                raise HistoryCheckpointRepairRequired(
                    "folded history frontier owner is missing or changed"
                )

        self.journal.put_many(
            ((_MARKER, "owner", self.marker), (_GENERATION, "initial", self.generation("initial"))),
            index=initialize,
        )

    def generation(self, key):
        return dict(
            context=self.marker, generation=key, first_block=self.blocks.binding["first_block"]
        )

    def populated(self, key):
        return dict(owner=self.blocks.owner, generation=key)

    @_repair_metadata
    def state(self, db, *, pending_population=None):
        self.blocks.check_schema(db)
        exists = db.execute("SELECT 1 FROM sqlite_master WHERE name=?", (_STATE,)).fetchone()
        marker = self.journal.get(_MARKER, "owner", db=db)
        if exists is None and marker is None:
            return None
        if marker != self.marker:
            raise HistoryCheckpointRepairRequired("folded history frontier owner changed")
        tables = dict(
            db.execute(
                "SELECT name,sql FROM sqlite_master WHERE type='table' AND name IN (?,?)",
                (_STATE, _ANCHORS),
            )
        )
        if tables != {_STATE: _STATE_SQL, _ANCHORS: _ANCHOR_SQL}:
            raise HistoryCheckpointRepairRequired("folded history frontier schema changed")
        actual = dict(
            db.execute(
                "SELECT name,sql FROM sqlite_master WHERE type='trigger' "
                "AND name LIKE 'history_folded_%'"
            )
        )
        if actual != self.triggers:
            raise HistoryCheckpointRepairRequired("folded history frontier mutation fence changed")
        rows = db.execute(
            f"SELECT owner,revision,highest,key,generation FROM {_STATE} LIMIT 2"
        ).fetchall()
        if len(rows) != 1 or rows[0][0] != self.blocks.owner:
            raise HistoryCheckpointRepairRequired("folded history frontier state changed")
        state = rows[0]
        generation = state[4]
        if self.journal.get(_GENERATION, generation, db=db) != self.generation(generation):
            raise HistoryCheckpointRepairRequired("folded history generation witness changed")
        populated = self.journal.get(_POPULATED, generation, db=db)
        if state[3] is None:
            if generation != pending_population and (
                populated is not None
                or state[2] != self.blocks.binding["first_block"] - 1
                or db.execute(
                    "SELECT 1 FROM records WHERE kind IN (?,?) LIMIT 1", (_KIND, _ANCHOR)
                ).fetchone()
            ):
                raise HistoryCheckpointRepairRequired(
                    "completed folded history frontier index lost its selection"
                )
        elif populated != self.populated(generation):
            raise HistoryCheckpointRepairRequired("folded history completion witness changed")
        return state

    @_repair_metadata
    def remote_identity(self):
        source = self.blocks.remote_sources
        remote = None if source is None else source.remote
        if remote is None:
            return None
        indexes = []
        paths = set()
        for owner in (remote.journal, remote.receipt_source):
            if owner is None or owner.path in paths:
                continue
            paths.add(owner.path)
            info = owner.path.stat()
            with owner.read_transaction() as db:
                owner._version(db)
                count = db.execute(
                    "SELECT number FROM round_record_capacity_kinds "
                    "WHERE kind='remote_proof_damage'"
                ).fetchone()
                holds = db.execute("SELECT COUNT(*) FROM holds").fetchone()[0]
            indexes.append(
                dict(
                    database=[info.st_dev, info.st_ino, info.st_uid],
                    damaged=0 if count is None else count[0],
                    holds=holds,
                )
            )
        return dict(namespace=remote.namespace_sha256, indexes=indexes)

    def origin_seals(self, reader):
        seals = dict(reader._folded_origin_seals)
        for origin, owner_seal in self.blocks._original_export_origins.values():
            for seal in (origin["_seal"], owner_seal):
                seals[seal["path"]] = {
                    k: str(v) if type(v) is int else v for k, v in seal.items() if k != "sha256"
                }
        return seals

    @staticmethod
    @_repair_metadata
    def check_origin_seals(seals):
        for path, expected in seals.items():
            actual = provenance._metadata(path, owner=provenance._ROOT_UID, immutable=True)
            if {k: str(v) if type(v) is int else v for k, v in actual.items()} != expected:
                raise HistoryCheckpointRepairRequired("folded history original root seal changed")

    @_repair_metadata
    def load(self, target):
        with self.journal.read_transaction() as db:
            state = self.state(db)
            if state is None or state[3] is None:
                return None
            value = self.journal.get(_KIND, state[3], db=db)
            if (
                not isinstance(value, dict)
                or digest(value) != state[3]
                or value.get("context") != self.marker
            ):
                raise HistoryCheckpointRepairRequired("folded history frontier record is damaged")
            if (
                value["revision"] != state[1]
                or value["generation"] != state[4]
                or value["tip"]["snapshot"]["block_number"] != state[2]
            ):
                raise HistoryCheckpointRepairRequired(
                    "folded history frontier source mutation requires scoped repair"
                )
            row = db.execute(
                f"SELECT height,key FROM {_ANCHORS} WHERE height<=? ORDER BY height DESC LIMIT 1",
                (min(target, state[2]),),
            ).fetchone()
            if target >= state[2]:
                prefix = value["tip"]
            elif row is None:
                prefix = None
            else:
                anchor = self.journal.get(_ANCHOR, row[1], db=db)
                if (
                    not isinstance(anchor, dict)
                    or digest(anchor) != row[1]
                    or anchor.get("context") != self.marker
                    or anchor["prefix"]["snapshot"]["block_number"] != row[0]
                ):
                    raise HistoryCheckpointRepairRequired("folded history prefix anchor is damaged")
                prefix = anchor["prefix"]
        remote = self.remote_identity()
        saved = value["remote"]
        if saved is not None and saved != remote:
            # A supported read-only consumer adds its empty local receipt index
            # while preserving the producer as receipt_source. Retain every
            # original dependency and require new indexes to have no damage.
            if remote is None or saved["namespace"] != remote["namespace"]:
                raise HistoryCheckpointRepairRequired("folded history remote namespace changed")
            previous = {tuple(i["database"]): i for i in saved["indexes"]}
            current = {tuple(i["database"]): i for i in remote["indexes"]}
            if any(current.get(key) != item for key, item in previous.items()) or any(
                item["damaged"] or item["holds"]
                for key, item in current.items()
                if key not in previous
            ):
                raise HistoryCheckpointRepairRequired(
                    "folded history remote source owner or damage changed"
                )
        # Local-only folds have no prior remote dependency. New read-only
        # indexes add no authority over already retained immutable receipts.
        value = dict(value, remote=remote)
        self.check_origin_seals(value["origin_seals"])
        return (
            value,
            prefix,
            state,
            None if prefix is None else _issue_checkpoint_tip(self.blocks, prefix),
        )

    @_repair_metadata
    def recheck(self, state, remote, origin_seals):
        with self.journal.read_transaction() as db:
            if self.state(db) != state:
                raise HistoryCheckpointRepairRequired(
                    "folded history frontier changed during finality"
                )
        if self.remote_identity() != remote:
            raise HistoryCheckpointRepairRequired(
                "folded history remote source changed during finality"
            )

        self.check_origin_seals(origin_seals)

    @contextmanager
    def preserve_source_release(self, db):
        state = self.state(db)
        yield 0
        if state is not None:
            changed = db.execute(
                f"UPDATE {_STATE} SET revision=? WHERE owner=? AND revision=?",
                (state[1], state[0], state[1] + 1),
            ).rowcount
            if changed != 1:
                raise HistoryCheckpointRepairRequired(
                    "folded history changed during exact source externalization"
                )

    def reset_for_repair(self):
        generation = secrets.token_hex(16)

        def reset(db):
            state = self.state(db)
            if state is not None:
                db.execute(f"DELETE FROM {_ANCHORS}")
                db.execute("DELETE FROM records WHERE kind=?", (_ANCHOR,))
                db.execute(
                    f"UPDATE {_STATE} SET highest=?,key=NULL,generation=?",
                    (self.blocks.binding["first_block"] - 1, generation),
                )
                db.execute("DELETE FROM records WHERE kind=?", (_KIND,))

        self.journal.put_many(
            ((_GENERATION, generation, self.generation(generation)),), index=reset
        )

    def remember(self, reader):
        if reader._tip is None or self.journal.read_only or self.journal.existing_only:
            return
        tip = reader._folded_tip
        if tip is None:
            return
        remote = self.remote_identity()
        with self.journal.read_transaction() as db:
            state = self.state(db)
            if state is None:
                return
            old = None if state[3] is None else self.journal.get(_KIND, state[3], db=db)
            if old is not None and old["revision"] != state[1]:
                raise HistoryCheckpointRepairRequired(
                    "folded history frontier mutation requires explicit repair"
                )
            if state[2] > tip["snapshot"]["block_number"]:
                return
        anchors = [
            dict(context=self.marker, prefix=prefix)
            for prefix in reader._pending_folded_anchors.values()
        ]
        value = dict(
            context=self.marker,
            revision=state[1],
            generation=state[4],
            remote=remote,
            origin_seals=self.origin_seals(reader),
            export_ranges=reader._folded_export_ranges,
            export_identity=reader._folded_export_identity
            if reader.progress.archive_delivery is not None
            else None
            if reader.export_archive is None
            else reader._export_identity(),
            tip=tip,
            writes=[[w.block_number, w.extrinsic_index, w.decision_sha256] for w in reader._writes],
            unresolved=list(reader._unresolved),
        )
        key = digest(value)
        if key == state[3] and not anchors:
            return
        records = [(_KIND, key, value), (_POPULATED, state[4], self.populated(state[4]))]
        records += [(_ANCHOR, digest(a), a) for a in anchors]

        def commit(db):
            if self.state(db, pending_population=state[4]) != state:
                raise HistoryCheckpointRepairRequired("folded history changed before checkpoint")
            for a in anchors:
                height = a["prefix"]["snapshot"]["block_number"]
                old = db.execute(f"SELECT key FROM {_ANCHORS} WHERE height=?", (height,)).fetchone()
                if old is None:
                    db.execute(f"INSERT INTO {_ANCHORS} VALUES (?,?)", (height, digest(a)))
                elif old != (digest(a),):
                    raise HistoryCheckpointRepairRequired("folded history anchor changed")
            db.execute(
                f"UPDATE {_STATE} SET highest=?,key=? WHERE owner=?",
                (tip["snapshot"]["block_number"], key, self.blocks.owner),
            )
            if state[3] is not None and state[3] != key:
                db.execute("DELETE FROM records WHERE kind=? AND id=?", (_KIND, state[3]))

        self.journal.put_many(records, index=commit)
        reader._pending_folded_anchors.clear()
