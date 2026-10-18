"""Private successful block facts; raw /1 history records remain unchanged.

SQLite mutation identities bind a verdict to each original immutable record.
Triggers invalidate affected dependencies even for same-length direct updates.
These local receipts never make a portable proof or issue an owned history.
The history owner still checks ordered continuity and fresh owned tip finality.
"""

import hashlib
import json
import logging
import sqlite3
import time
from dataclasses import asdict

from .chain_evidence import FinalizedSnapshotRef
from .competition_evidence_codec import checked_digest
from .competition_reward_history_origin import check_checkpoint_origin
from .competition_verification_rules import runtime_identity
from .open_competition import digest

SOURCE_KINDS = ("control_history_block", "control_history_chunk", "control_history_object")
ABI = "umi-native-control-history-block/1"
logger = logging.getLogger(__name__)


def _migration_progress(state, total, completed, started):
    try:
        elapsed = time.monotonic() - started
        rate = completed / elapsed if elapsed > 0 and completed else None
        logger.info(
            "reward_history_progress %s",
            {
                "stage": "checkpoint_source_identity_migration",
                "state": state,
                "completed_records": completed,
                "total_records": None if state == "repair_required" else total,
                "percent": None
                if state == "repair_required"
                else 100.0 * completed / total
                if total
                else 100.0,
                "elapsed_seconds": elapsed,
                "eta_seconds": None
                if state in {"retrying", "repair_required"}
                else (total - completed) / rate
                if rate
                else 0.0
                if not total
                else None,
                "planning_eta_seconds": [total / 100000, total / 1000]
                if not completed and state not in {"retrying", "repair_required"}
                else None,
                "eta_basis": "withdrawn_stalled_or_retrying"
                if state in {"retrying", "repair_required"}
                else "measured_metadata_records_per_second"
                if rate
                else "planning_assumption_1000_to_100000_metadata_records_per_second",
            },
        )
    except Exception:
        pass


class HistoryCheckpointRepairRequired(ValueError):
    """A previously successful result changed; explicit scoped repair is required."""

    height: int | None = None


def source_triggers():
    kinds = ",".join("'" + k + "'" for k in SOURCE_KINDS)
    result = {}
    for action in ("INSERT", "UPDATE", "DELETE"):
        row = "OLD" if action == "DELETE" else "NEW"
        name = "history_source_" + action.lower()
        result[name] = (
            f"CREATE TRIGGER {name} AFTER {action} ON records "
            f"WHEN {row}.kind IN ({kinds}) BEGIN "
            "INSERT INTO history_source_identity(kind,id,revision,present) "
            f"VALUES({row}.kind,{row}.id,1,{int(action != 'DELETE')}) "
            "ON CONFLICT(kind,id) DO UPDATE SET revision=revision+1,"
            f"present={int(action != 'DELETE')}; END"
        )
    # A changed primary key must also invalidate the old identity.
    result["history_source_rekey"] = (
        "CREATE TRIGGER history_source_rekey AFTER UPDATE ON records "
        f"WHEN OLD.kind IN ({kinds}) AND (OLD.kind!=NEW.kind OR OLD.id!=NEW.id) "
        "BEGIN UPDATE history_source_identity SET revision=revision+1,present=0 "
        "WHERE kind=OLD.kind AND id=OLD.id; END"
    )
    return result


class HistoryCheckpoints:
    def __init__(self, journal, binding):
        try:
            self._initialize(journal, binding)
        except HistoryCheckpointRepairRequired:
            # Constructor failures occur before the reader can start its normal
            # progress monitor. Make the explicit repair state visible here too.
            _migration_progress("repair_required", 0, 0, time.monotonic())
            raise

    def _initialize(self, journal, binding):
        self.journal = journal
        self._original_export_origins = {}
        self.remote_sources = None
        directory = journal.root.stat()
        database = journal.path.stat()
        self.directory_identity = (directory.st_dev, directory.st_ino, directory.st_uid)
        self.database_identity = (database.st_dev, database.st_ino, database.st_uid)
        self.owner = digest(
            {
                "binding": binding,
                "directory": str(journal.root.resolve()),
                "directory_identity": [directory.st_dev, directory.st_ino, directory.st_uid],
                "database_identity": [database.st_dev, database.st_ino, database.st_uid],
            }
        )
        self.semantics = digest([ABI, runtime_identity()])
        self.triggers = source_triggers()
        marker = {"schema": ABI, "owner": self.owner}
        self.marker = marker
        with journal.read_transaction() as db:
            try:
                marker_value = journal.get("control_history_checkpoint_owner", "owner", db=db)
            except (ValueError, sqlite3.DatabaseError) as error:
                raise HistoryCheckpointRepairRequired(
                    "history checkpoint owner marker is damaged"
                ) from error
        if marker_value is not None and marker_value != marker:
            raise HistoryCheckpointRepairRequired("history checkpoint original owner changed")
        if journal.existing_only:
            with journal.read_transaction() as db:
                self.check_schema(db)
            return
        migration = None

        def initialize(db):
            nonlocal migration
            installed = db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='history_checkpoint_state'"
            ).fetchone()
            if not installed:
                remnants = db.execute(
                    "SELECT 1 FROM sqlite_master WHERE name IN "
                    "('history_source_identity','history_checkpoint_index') "
                    "OR name LIKE 'history_source_%'"
                ).fetchone()
                prior = db.execute(
                    "SELECT 1 FROM records WHERE kind IN "
                    "('control_history_verified','control_history_checkpoint_done') LIMIT 1"
                ).fetchone()
                if remnants or prior or marker_value is not None:
                    raise HistoryCheckpointRepairRequired(
                        "history checkpoint metadata lost; recover original metadata before reuse"
                    )
                # Raw records have no success claim. This only establishes their
                # mutation identities for a visible legacy first-checkpoint pass.
                started = time.monotonic()
                total = sum(
                    db.execute("SELECT COUNT(*) FROM records WHERE kind=?", (kind,)).fetchone()[0]
                    for kind in SOURCE_KINDS
                )
                _migration_progress("running", total, 0, started)
                migration = [total, 0, started]
                db.execute(
                    "CREATE TABLE history_checkpoint_state(owner TEXT NOT NULL, highest "
                    "INTEGER NOT NULL)"
                )
                db.execute(
                    "INSERT INTO history_checkpoint_state VALUES (?,?)",
                    (self.owner, binding["first_block"] - 1),
                )
                db.execute(
                    "CREATE TABLE history_source_identity(kind TEXT,id TEXT,revision INTEGER "
                    "NOT NULL,present INTEGER NOT NULL,PRIMARY KEY(kind,id))"
                )
                db.execute(
                    "CREATE TABLE history_checkpoint_index(height INTEGER PRIMARY KEY,key TEXT "
                    "NOT NULL)"
                )
                completed = 0
                for kind in SOURCE_KINDS:
                    added = db.execute(
                        "INSERT INTO history_source_identity SELECT kind,id,0,1 FROM records "
                        "WHERE kind=?",
                        (kind,),
                    ).rowcount
                    completed += added
                    migration[1] = completed
                    _migration_progress("running", total, completed, started)
                for sql in self.triggers.values():
                    db.execute(sql)
            elif marker_value is None:
                raise HistoryCheckpointRepairRequired("history checkpoint owner marker is missing")
            self.check_schema(db)

        # The marker survives loss of auxiliary tables. Its immutable original
        # owner prevents recreating an apparently empty success index on restart.
        try:
            journal.put_many(
                (("control_history_checkpoint_owner", "owner", marker),), index=initialize
            )
        except Exception:
            if migration is not None:
                _migration_progress("retrying", *migration)
            raise
        if migration is not None:
            _migration_progress("completed", *migration)

    def check_schema(self, db):
        directory = self.journal.root.stat()
        database = self.journal.path.stat()
        if (directory.st_dev, directory.st_ino, directory.st_uid) != self.directory_identity or (
            database.st_dev,
            database.st_ino,
            database.st_uid,
        ) != self.database_identity:
            raise HistoryCheckpointRepairRequired(
                "history checkpoint original directory or database changed"
            )
        if self.journal.get("control_history_checkpoint_owner", "owner", db=db) != self.marker:
            raise HistoryCheckpointRepairRequired(
                "history checkpoint owner marker is missing or changed"
            )
        try:
            states = db.execute(
                "SELECT owner,highest FROM history_checkpoint_state LIMIT 2"
            ).fetchall()
            db.execute("SELECT height,key FROM history_checkpoint_index LIMIT 0")
            db.execute("SELECT kind,id,revision,present FROM history_source_identity LIMIT 0")
        except sqlite3.DatabaseError as error:
            raise HistoryCheckpointRepairRequired(
                "history checkpoint metadata missing or damaged"
            ) from error
        if len(states) != 1 or states[0][0] != self.owner:
            raise HistoryCheckpointRepairRequired("history checkpoint original owner changed")
        actual = dict(
            db.execute(
                "SELECT name,sql FROM sqlite_master WHERE type='trigger' AND name LIKE "
                "'history_source_%'"
            )
        )
        if actual != self.triggers:
            raise HistoryCheckpointRepairRequired(
                "history checkpoint source identity triggers changed"
            )

    def sources(self, keys, db):
        self.check_schema(db)
        out = []
        for kind, key in sorted(set(keys)):
            if self.remote_sources is not None:
                out.append(self.remote_sources.source_token(kind, key, db))
                continue
            row = db.execute(
                "SELECT revision,present FROM history_source_identity WHERE kind=? AND id=?",
                (kind, key),
            ).fetchone()
            held = db.execute("SELECT 1 FROM holds WHERE id=?", (key,)).fetchone()
            if row is None or row[1] != 1 or held:
                raise HistoryCheckpointRepairRequired(
                    "history checkpoint source missing or conflict held"
                )
            out.append([kind, key, row[0]])
        return out

    def check_sources(self, sources, db):
        if self.sources(((v[0], v[1]) for v in sources), db) != sources:
            raise HistoryCheckpointRepairRequired(
                "history checkpoint source changed; scoped native repair required"
            )

    def load(self, height):
        try:
            return self._load(height)
        except HistoryCheckpointRepairRequired:
            raise
        except (
            ValueError,
            TypeError,
            KeyError,
            IndexError,
            AttributeError,
            sqlite3.DatabaseError,
        ) as error:
            raise HistoryCheckpointRepairRequired(
                "history checkpoint result is damaged; scoped native repair required"
            ) from error

    def load_many(self, first: int, last: int) -> list[dict]:
        """Read a bounded contiguous prefix under one fresh read-only snapshot.

        Every result keeps the single-item owner, schema, source-generation and
        origin checks. A missing new item ends the prefix; damaged completed work
        still raises and identifies its height. No snapshot survives this call.
        """
        self._batch_bounds(first, last)
        height = first
        try:
            with self.journal.read_transaction() as db:
                values = []
                for height in range(first, last + 1):
                    value = self._load_snapshot(height, db)
                    if value is None:
                        break
                    values.append(value)
                return values
        except HistoryCheckpointRepairRequired as error:
            error.height = height
            raise
        except (
            ValueError,
            TypeError,
            KeyError,
            IndexError,
            AttributeError,
            sqlite3.DatabaseError,
        ) as error:
            failure = HistoryCheckpointRepairRequired(
                "history checkpoint result is damaged; scoped native repair required"
            )
            failure.height = height
            raise failure from error

    @staticmethod
    def _batch_bounds(first, last):
        if (
            type(first) is not int
            or type(last) is not int
            or not 1 <= first <= last <= 2**53 - 1
            or last - first + 1 > 4096
        ):
            raise ValueError("history checkpoint batch must contain 1 to 4096 blocks")

    def recheck_many(self, values: list[dict]) -> None:
        """Recheck a retained batch after finality without a second batch copy."""
        if not 1 <= len(values) <= 4096:
            raise ValueError("history checkpoint recheck must contain 1 to 4096 blocks")
        first = values[0]["snapshot"]["block_number"]
        last = values[-1]["snapshot"]["block_number"]
        self._batch_bounds(first, last)
        if last - first + 1 != len(values):
            raise ValueError("history checkpoint recheck must be contiguous")
        height = first
        try:
            with self.journal.read_transaction() as db:
                for height, saved in zip(range(first, last + 1), values, strict=True):
                    if (
                        saved["snapshot"]["block_number"] != height
                        or self._load_snapshot(height, db) != saved
                    ):
                        raise HistoryCheckpointRepairRequired(
                            "checkpoint changed during owned restore"
                        )
        except HistoryCheckpointRepairRequired as error:
            error.height = height
            raise
        except (
            ValueError,
            TypeError,
            KeyError,
            IndexError,
            AttributeError,
            sqlite3.DatabaseError,
        ) as error:
            failure = HistoryCheckpointRepairRequired(
                "history checkpoint recheck needs scoped native repair"
            )
            failure.height = height
            raise failure from error

    def _load(self, height):
        with self.journal.read_transaction() as db:
            return self._load_snapshot(height, db)

    def _load_snapshot(self, height, db):
        self.check_schema(db)
        row = db.execute(
            "SELECT key FROM history_checkpoint_index WHERE height=?", (height,)
        ).fetchone()
        done = self.journal.get("control_history_checkpoint_done", str(height), db=db)
        if row is None:
            if done is not None:
                raise HistoryCheckpointRepairRequired("completed history checkpoint is missing")
            return None
        if done != {"height": height, "owner": self.owner}:
            raise HistoryCheckpointRepairRequired("history checkpoint completion marker is missing")
        value = self.journal.get("control_history_verified", row[0], db=db)
        if (
            not isinstance(value, dict)
            or digest(value) != row[0]
            or value.get("schema") != ABI
            or value.get("owner") != self.owner
            or value.get("semantics") != self.semantics
            or value.get("snapshot", {}).get("block_number") != height
        ):
            raise HistoryCheckpointRepairRequired(
                "history checkpoint result or verifier semantics changed"
            )
        self.validate(value)
        self.check_sources(value["sources"], db)
        check_checkpoint_origin(self.journal, value, db, self._original_export_origins)
        return value

    def validate(self, value):
        fields = {
            "schema",
            "owner",
            "semantics",
            "snapshot",
            "header",
            "control_sha256",
            "committed_at_block",
            "slot_evidence_sha256",
            "slot_metadata_sha256",
            "write_evidence_sha256",
            "writes",
            "unresolved_extrinsics",
            "sources",
            "exports",
            "repair",
        }
        if set(value) != fields:
            raise ValueError("history checkpoint fields differ")
        snapshot = FinalizedSnapshotRef(**value["snapshot"])
        for key in ("slot_evidence_sha256", "slot_metadata_sha256", "write_evidence_sha256"):
            checked_digest(value[key])
        if value["control_sha256"] is not None:
            checked_digest(value["control_sha256"])
        committed = value["committed_at_block"]
        if committed is not None and (
            type(committed) is not int or not 0 <= committed <= snapshot.block_number
        ):
            raise ValueError("history checkpoint commitment differs")
        header = value["header"]
        if (
            type(header) is not str
            or not header.startswith("0x")
            or bytes.fromhex(header[2:]).hex() != header[2:]
        ):
            raise ValueError("history checkpoint header differs")
        for key in ("writes", "unresolved_extrinsics", "sources"):
            if type(value[key]) is not list:
                raise ValueError("history checkpoint list differs")
        if type(value["exports"]) is not list or len(set(value["exports"])) != len(
            value["exports"]
        ):
            raise ValueError("history checkpoint export identities differ")
        for export in value["exports"]:
            checked_digest(export)
        repair = value["repair"]
        if repair is not None and (
            type(repair) is not dict
            or set(repair) != {"reason", "operation"}
            or any(type(v) is not str or not v for v in repair.values())
        ):
            raise ValueError("history checkpoint repair binding differs")
        for index, key in value["writes"]:
            if type(index) is not int or index < 0:
                raise ValueError("history checkpoint extrinsic differs")
            checked_digest(key)
        if any(type(index) is not int or index < 0 for index in value["unresolved_extrinsics"]):
            raise ValueError("history checkpoint unresolved extrinsic differs")
        if (
            not value["sources"]
            or sorted(value["sources"]) != value["sources"]
            or len({(v[0], v[1]) for v in value["sources"]}) != len(value["sources"])
        ):
            raise ValueError("history checkpoint source identities differ")
        for kind, key, revision in value["sources"]:
            if (
                kind not in SOURCE_KINDS
                or type(key) is not str
                or type(revision) is not int
                or revision < 0
            ):
                raise ValueError("history checkpoint source identity differs")
        if ["control_history_block", str(snapshot.block_number)] not in [
            v[:2] for v in value["sources"]
        ]:
            raise ValueError("history checkpoint frame identity missing")

    def progress_rows(self, first, last, export_identity):
        """Bounded compact inventory; no retained proof payloads are loaded.

        Diagnostic counts describe durable facts, not an authority decision.
        Normal load()/repair still validates every selected source revision.
        """
        if not 0 <= last - first < 512:
            raise ValueError("history progress inventory exceeds its work window")
        heights = tuple(str(height) for height in range(first, last + 1))
        with self.journal.read_transaction() as db:
            captured = {
                int(row[0])
                for row in db.execute(
                    "SELECT id FROM records WHERE kind='control_history_block' AND id IN ("
                    + ",".join("?" for _ in heights)
                    + ")",
                    heights,
                )
            }
            if self.remote_sources is not None:
                for height in range(first, last + 1):
                    if height in captured:
                        continue
                    alias = self.remote_sources._alias("control_history_block", str(height), db)
                    if alias is not None:
                        self.remote_sources.source_token("control_history_block", str(height), db)
                        captured.add(height)
            verified, exported = set(), set()
            for height, body in db.execute(
                "SELECT i.height,r.body FROM history_checkpoint_index i LEFT JOIN records r "
                "ON r.kind='control_history_verified' AND r.id=i.key "
                "WHERE i.height>=? AND i.height<=?",
                (first, last),
            ):
                try:
                    value = json.loads(body)
                    if (
                        value["schema"] != ABI
                        or value["owner"] != self.owner
                        or value["semantics"] != self.semantics
                        or value["snapshot"]["block_number"] != height
                    ):
                        continue
                    verified.add(height)
                    if export_identity is not None and export_identity in value["exports"]:
                        exported.add(height)
                except (KeyError, TypeError, ValueError):
                    # A damaged receipt is never counted as successful. Its
                    # authoritative load exposes the scoped repair requirement.
                    continue
        return captured, verified, exported

    def capture(self, observation, sources):
        slot = observation.slot
        return {
            "schema": ABI,
            "owner": self.owner,
            "semantics": self.semantics,
            "snapshot": asdict(slot.snapshot),
            "header": json.loads(slot.evidence)["finality"]["block"]["scale_header"],
            "control_sha256": slot.control_sha256,
            "committed_at_block": slot.committed_at_block,
            "slot_evidence_sha256": slot.evidence_sha256,
            "slot_metadata_sha256": slot.metadata_sha256,
            "write_evidence_sha256": hashlib.sha256(observation.evidence).hexdigest(),
            "writes": [[w.extrinsic_index, w.decision_sha256] for w in observation.writes],
            "unresolved_extrinsics": list(observation.unresolved_extrinsics),
            "sources": sources,
            "exports": [],
            "repair": None,
        }

    def remember(self, value, *, repair_reason=None):
        self.validate(value)
        height, key = value["snapshot"]["block_number"], digest(value)

        def index(db):
            self.check_sources(value["sources"], db)
            old = db.execute(
                "SELECT key FROM history_checkpoint_index WHERE height=?", (height,)
            ).fetchone()
            if old is not None and old[0] != key and not repair_reason:
                raise HistoryCheckpointRepairRequired(
                    "completed checkpoint differs; explicit repair required"
                )
            db.execute(
                "INSERT INTO history_checkpoint_index VALUES (?,?) ON CONFLICT(height) DO "
                "UPDATE SET key=excluded.key",
                (height, key),
            )
            db.execute("UPDATE history_checkpoint_state SET highest=MAX(highest,?)", (height,))

        # Result and completion index commit atomically. A lost acknowledgement
        # is discovered by load() without repeating the successful native check.
        records = [
            ("control_history_verified", key, value),
            (
                "control_history_checkpoint_done",
                str(height),
                {"height": height, "owner": self.owner},
            ),
        ]
        if repair_reason:
            repair = {"height": height, "result": key, "owner": self.owner, "reason": repair_reason}
            records.append(("control_history_checkpoint_repair", digest(repair), repair))
        self.journal.put_many(records, index=index)
