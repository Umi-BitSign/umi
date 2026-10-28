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
from collections import OrderedDict
from dataclasses import asdict

from .chain_evidence import FinalizedSnapshotRef
from .competition_evidence_codec import checked_digest
from .competition_reward_checkpoint_progress import CheckpointMetadataProgress
from .competition_reward_checkpoint_tip import OwnedCheckpointTip, _issue_checkpoint_tip
from .competition_reward_history_origin import check_checkpoint_origin
from .competition_verification_rules import runtime_identity
from .open_competition import digest, digest_canonical_bytes

SOURCE_KINDS = ("control_history_block", "control_history_chunk", "control_history_object")
ABI = "umi-native-control-history-block/1"
logger = logging.getLogger(__name__)
_MAX_SNAPSHOT_TOKENS = 8192


def _remember_source_token(cache, identity, fact):
    if cache is None:
        return
    if isinstance(cache, OrderedDict):
        cache[identity] = fact
        cache.move_to_end(identity)
        if len(cache) > _MAX_SNAPSHOT_TOKENS:
            cache.popitem(last=False)
    elif len(cache) < _MAX_SNAPSHOT_TOKENS:
        cache[identity] = fact


class _CheckpointSourceSnapshot:
    """Reuse source identities only inside one fresh read-only SQL snapshot."""

    def __init__(self, checkpoints, db):
        if not db.in_transaction or db.execute("PRAGMA query_only").fetchone() != (1,):
            raise ValueError("checkpoint source reuse requires a read-only snapshot")
        checkpoints.check_schema(db)
        self.checkpoints, self.db, self.tokens = checkpoints, db, OrderedDict()
        self.remote_sources = checkpoints.remote_sources

    def sources(self, keys):
        if self.remote_sources is not self.checkpoints.remote_sources:
            raise HistoryCheckpointRepairRequired("checkpoint remote source owner changed")
        return self.checkpoints._sources(keys, self.db, self.tokens)


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
        self.binding = dict(binding)
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
        self._check_storage_identity()
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

    def _check_storage_identity(self):
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

    def sources(self, keys, db):
        self.check_schema(db)
        return self._sources(keys, db)

    def _sources(self, keys, db, snapshot_tokens=None):
        if self.remote_sources is not None:
            return self._remote_snapshot_sources(keys, db, snapshot_tokens)
        out = []
        for kind, key in sorted(set(keys)):
            identity = (kind, key)
            if snapshot_tokens is not None and identity in snapshot_tokens:
                cached = snapshot_tokens[identity]
                out.append(list(cached))
                _remember_source_token(snapshot_tokens, identity, cached)
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
            token = [kind, key, row[0]]
            fact = tuple(token)
            # Cache saturation changes only performance, never supported work.
            # Neither this dictionary nor its read-only connection survives a batch.
            _remember_source_token(snapshot_tokens, identity, fact)
            out.append(token)
        return out

    def _remote_snapshot_sources(self, keys, db, snapshot_tokens):
        ordered = sorted(set(keys))
        out = []
        for start in range(0, len(ordered), 256):
            group = ordered[start : start + 256]
            reused = {
                key: snapshot_tokens[key]
                for key in group
                if snapshot_tokens is not None and key in snapshot_tokens
            }
            missing = [key for key in group if key not in reused]
            fresh = (
                dict(zip(missing, self.remote_sources.snapshot_tokens(missing, db), strict=True))
                if missing
                else {}
            )
            rechecked = (
                dict(
                    zip(
                        reused,
                        self.remote_sources.recheck_snapshot_tokens(list(reused.values())),
                        strict=True,
                    )
                )
                if reused
                else {}
            )
            for identity in group:
                if identity in fresh:
                    fact = fresh[identity]
                    token = list(fact.token)
                else:
                    # Remote indexes can change independently of this SQL
                    # snapshot; every reused receipt still receives its check.
                    fact = reused[identity]
                    token = rechecked[identity]
                _remember_source_token(snapshot_tokens, identity, fact)
                out.append(token)
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
            with (
                CheckpointMetadataProgress("checkpoint_metadata_loading", first, last) as progress,
                self.journal.read_transaction() as db,
            ):
                sources = _CheckpointSourceSnapshot(self, db)
                values = []
                for height in range(first, last + 1):
                    value = self._load_snapshot(height, db, sources)
                    progress.checked(retained=value is not None)
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

    def load_restore_batch(
        self, first: int, last: int
    ) -> tuple[list[dict], OwnedCheckpointTip | None]:
        """Carry the checked native tip across the owner's async finality read.

        These original-owner receipts already establish historical finality.
        The ordinary fresh source recheck still fences every item before apply;
        neither serialization nor an imported archive can issue this capability.
        """
        values = self.load_many(first, last)
        tip = _issue_checkpoint_tip(self, values[-1]) if values else None
        return values, tip

    def header_hints(self, first: int, last: int) -> tuple[str, ...]:
        """Reuse completed local headers without opening their proof payloads.

        These remain untrusted ancestry inputs. Missing future work ends the
        contiguous batch; damaged completed results keep their explicit repair.
        """
        return tuple(value["header"] for value in self.load_many(first, last))

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
            with (
                CheckpointMetadataProgress("checkpoint_metadata_recheck", first, last) as progress,
                self.journal.read_transaction() as db,
            ):
                sources = _CheckpointSourceSnapshot(self, db)
                for height, saved in zip(range(first, last + 1), values, strict=True):
                    if (
                        saved["snapshot"]["block_number"] != height
                        or self._load_snapshot(height, db, sources) != saved
                    ):
                        raise HistoryCheckpointRepairRequired(
                            "checkpoint changed during owned restore"
                        )
                    progress.checked()
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

    def _load_snapshot(self, height, db, source_snapshot=None):
        if source_snapshot is None:
            self.check_schema(db)
        elif source_snapshot.db is not db or source_snapshot.checkpoints is not self:
            raise ValueError("checkpoint source snapshot belongs to another reader")
        else:
            self._check_storage_identity()
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
        # get_raw retains the ordinary size, canonicality and conflict checks.
        # Its exact canonical bytes already define digest(value), so avoid a
        # second full serialization of every completed checkpoint.
        raw = self.journal.get_raw("control_history_verified", row[0], db=db)
        value = None if raw is None else json.loads(raw)
        if (
            raw is None
            or not isinstance(value, dict)
            or digest_canonical_bytes(raw) != row[0]
            or value.get("schema") != ABI
            or value.get("owner") != self.owner
            or value.get("semantics") != self.semantics
            or value.get("snapshot", {}).get("block_number") != height
        ):
            raise HistoryCheckpointRepairRequired(
                "history checkpoint result or verifier semantics changed"
            )
        self.validate(value)
        if source_snapshot is None:
            self.check_sources(value["sources"], db)
        elif source_snapshot.sources((v[0], v[1]) for v in value["sources"]) != value["sources"]:
            raise HistoryCheckpointRepairRequired(
                "history checkpoint source changed; scoped native repair required"
            )
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
                pending = [
                    (str(height), digest(["control_history_block", str(height)]))
                    for height in range(first, last + 1)
                    if height not in captured
                ]
                for start in range(0, len(pending), 256):
                    group = pending[start : start + 256]
                    arguments = [alias for _, alias in group]
                    markers = ",".join("?" for _ in arguments)
                    aliases = {
                        row[0]
                        for row in db.execute(
                            "SELECT id FROM records WHERE kind=? AND id IN (" + markers + ")",
                            [self.remote_sources.alias_kind, *arguments],
                        )
                    }
                    aliases.update(
                        row[0]
                        for row in db.execute(
                            "SELECT id FROM holds WHERE id IN (" + markers + ")",
                            arguments,
                        )
                    )
                    keys = [
                        ("control_history_block", height)
                        for height, alias in group
                        if alias in aliases
                    ]
                    if keys:
                        self.remote_sources.snapshot_tokens(keys, db)
                        captured.update(int(key) for _, key in keys)
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
