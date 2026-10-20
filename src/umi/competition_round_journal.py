"""Private round storage, immutable records, capacity reservations and conflict holds."""

from __future__ import annotations

import json
import logging
import os
import secrets
import sqlite3
import stat
import threading
import time
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path

from pydantic import JsonValue

from .competition_journal_physical_budget import JournalPhysicalBudget
from .competition_round_plan import RoundPlan, RoundProposal
from .competition_round_rpc_migration import has_transport_history, validate_rpc_binding
from .host_memory_request_bounds import charge_stage_declaration, check_stage_json, stage_limit
from .open_competition import digest
from .private_files import MAX_CONFIGURED_PRIVATE_BYTES, acquire_private_mutex
from .private_files import MAX_PRIVATE_BYTES as MAX_BYTES
from .private_files import ensure_private_directory as _private
from .protocol import canonical_json_bytes, is_canonical_json, sha256_hex

# Bound reservation bodies and allowances before transferring them to Python.
# Accounting validates key types and byte lengths separately. A rejected body
# or allowance remains an error, never an absent reservation.
_OBLIGATION_COLUMNS = (
    "kind,id,CASE WHEN TYPEOF(document)='blob' AND LENGTH(document) BETWEEN 1 AND 8192 "
    "THEN document END,CASE WHEN TYPEOF(maximum_bytes)='integer' THEN maximum_bytes END,"
    "CASE WHEN TYPEOF(value_sha256)='text' AND LENGTH(CAST(value_sha256 AS BLOB))=64 "
    "THEN value_sha256 END,"
    "(TYPEOF(maximum_bytes)='integer' AND (TYPEOF(value_sha256)='null' OR "
    "(TYPEOF(value_sha256)='text' AND LENGTH(CAST(value_sha256 AS BLOB))=64)))"
)

_CAPACITY_APPLICATION_ID = 0x554D5243  # UMRC; user_version still fences reservations.
_CAPACITY_TABLES = frozenset({"round_record_capacity", "round_record_capacity_kinds"})
_CAPACITY_SCHEMA = {
    "round_record_capacity": (
        "CREATE TABLE round_record_capacity (id INTEGER PRIMARY KEY CHECK(id=1), "
        "number INTEGER NOT NULL CHECK(TYPEOF(number)='integer' AND number>=0), "
        "nbytes INTEGER NOT NULL CHECK(TYPEOF(nbytes)='integer' AND nbytes>=0))"
    ),
    "round_record_capacity_kinds": (
        "CREATE TABLE round_record_capacity_kinds (kind TEXT PRIMARY KEY NOT NULL, "
        "number INTEGER NOT NULL CHECK(TYPEOF(number)='integer' AND number>=0), "
        "nbytes INTEGER NOT NULL CHECK(TYPEOF(nbytes)='integer' AND nbytes>=0))"
    ),
}
logger = logging.getLogger(__name__)


class RoundCapacityRepairRequired(ValueError):
    """Derived accounting is damaged; the owner must explicitly rebuild metadata."""


def _capacity_triggers():
    insert = (
        "INSERT INTO round_record_capacity_kinds VALUES (NEW.kind,1,LENGTH(NEW.body)) "
        "ON CONFLICT(kind) DO UPDATE SET number=number+1,nbytes=nbytes+LENGTH(NEW.body); "
        "UPDATE round_record_capacity SET number=number+1,nbytes=nbytes+LENGTH(NEW.body) "
        "WHERE id=1; "
        "SELECT CASE WHEN changes()!=1 THEN "
        "RAISE(ABORT,'round record capacity repair required') END; "
    )
    delete = (
        "UPDATE round_record_capacity_kinds SET number=number-1,nbytes=nbytes-LENGTH(OLD.body) "
        "WHERE kind=OLD.kind; "
        "SELECT CASE WHEN changes()!=1 THEN "
        "RAISE(ABORT,'round record capacity repair required') END; "
        "DELETE FROM round_record_capacity_kinds WHERE kind=OLD.kind AND number=0; "
        "UPDATE round_record_capacity SET number=number-1,nbytes=nbytes-LENGTH(OLD.body) "
        "WHERE id=1; "
        "SELECT CASE WHEN changes()!=1 THEN "
        "RAISE(ABORT,'round record capacity repair required') END; "
    )
    result = {}
    for action, body in (("INSERT", insert), ("DELETE", delete), ("UPDATE", delete + insert)):
        name = "round_record_capacity_" + action.lower()
        result[name] = f"CREATE TRIGGER {name} AFTER {action} ON records BEGIN {body}END"
    # SQLite omits the implicit DELETE trigger of REPLACE unless recursive
    # triggers are enabled. Older native writers only insert absent immutable
    # records, so they remain supported. A conflicting SQL write from an older
    # connection must fail before changing either records or their accounting.
    for action in ("INSERT", "UPDATE"):
        name = "round_record_capacity_replace_" + action.lower()
        different = " AND rowid!=OLD.rowid" if action == "UPDATE" else ""
        result[name] = (
            f"CREATE TRIGGER {name} BEFORE {action} ON records "
            "WHEN NOT (SELECT recursive_triggers FROM pragma_recursive_triggers) "
            "AND EXISTS(SELECT 1 FROM records WHERE kind=NEW.kind AND id=NEW.id"
            f"{different}) BEGIN SELECT "
            "RAISE(ABORT,'round record replacement requires recursive triggers'); END"
        )
    return result


def _capacity_progress(state, completed, total, started, operation):
    elapsed = max(0.0, time.monotonic() - started)
    rate = completed / elapsed if completed and elapsed else None
    unavailable = state in {"repair_required", "retrying", "stalled"}
    # Telemetry cannot turn a committed migration into a failed operation.
    with suppress(Exception):
        logger.info(
            "round_journal_progress %s",
            {
                "stage": "record_capacity_" + operation,
                "state": state,
                "completed_records": completed,
                "total_records": total,
                "percent": 100.0 * completed / total if total else 100.0 if total == 0 else None,
                "elapsed_seconds": elapsed,
                "eta_seconds": None
                if unavailable or total is None
                else ((total - completed) / rate if rate else 0.0 if total == 0 else None),
                "planning_eta_seconds": [total / 100000, total / 1000]
                if total is not None and not completed and not unavailable
                else None,
                "eta_basis": "withdrawn_stalled_or_retrying"
                if unavailable
                else (
                    "measured_metadata_records_per_second"
                    if rate
                    else "planning_assumption_1000_to_100000_metadata_records_per_second"
                ),
            },
        )


@dataclass(frozen=True, slots=True)
class RecordReservation:
    """Private allowance for one canonical journal value, before it exists."""

    kind: str
    key: str
    maximum_bytes: int
    value_sha256: str | None = None


class FinalizedHeadRegression(ValueError):
    """A valid observation is older than this journal's retained high water."""

    def __init__(self, message, *, capture_block=None, retained_block=None):
        super().__init__(message)
        self.capture_block = capture_block
        self.retained_block = retained_block


class RoundJournal:
    """Bounded immutable records and durable conflict holds, shared by both roles."""

    MAXIMUM_BYTES = 16 * 1024**3

    @property
    def maximum_records(self) -> int:
        """Total retained records; per-call batches keep their separate bound."""
        return self.maximum_rounds * 80

    def __init__(
        self,
        root: Path,
        binding: object,
        *,
        maximum_rounds: int = 1024,
        maximum_bytes: int = 1024**3,
        maximum_record_bytes: int = MAX_BYTES,
        compatible_bindings: Iterable[object] = (),
        repair_record_capacity: bool = False,
        existing_only: bool = False,
        read_only: bool = False,
        physical_budget: JournalPhysicalBudget | None = None,
    ) -> None:
        if (
            type(maximum_rounds) is not int
            or not 1 <= maximum_rounds <= 65536
            or (type(maximum_bytes) is not int or not 1024 <= maximum_bytes <= self.MAXIMUM_BYTES)
            or type(maximum_record_bytes) is not int
            or not 1 <= maximum_record_bytes <= MAX_CONFIGURED_PRIVATE_BYTES
            or type(repair_record_capacity) is not bool
            or type(existing_only) is not bool
            or type(read_only) is not bool
            or (read_only and not existing_only)
            or (existing_only and repair_record_capacity)
            or (physical_budget is not None and type(physical_budget) is not JournalPhysicalBudget)
        ):
            raise ValueError("round journal requires bounded capacity")
        self.root, self.maximum_rounds, self.maximum_bytes = root, maximum_rounds, maximum_bytes
        # Read/write envelope only. Existing reservation allowances, manifests,
        # bindings and total journal capacity are never enlarged by this value.
        self.maximum_record_bytes = maximum_record_bytes
        # Serialize this instance's writers. Read-only snapshots own separate
        # connections and must not queue behind unrelated writer work.
        self._transaction_lock = threading.RLock()
        self._capacity_migration = None
        self.existing_only, self.read_only = existing_only, read_only
        self.physical_budget = physical_budget
        if existing_only and (
            not root.is_dir()
            or not (root / "rounds.sqlite3").is_file()
            or not (root / "rounds.lock").is_file()
        ):
            raise ValueError("existing journal requires original directory, database and lock")
        _private(root)
        self.path = root / "rounds.sqlite3"
        self.lock_path = root / "rounds.lock"
        self._check_files()
        if existing_only:
            self._validate_existing(binding)
            return
        for path in (self.path, self.lock_path):
            os.close(os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600))
        self._check_files()
        with self.transaction(_repair_record_capacity=repair_record_capacity) as db:
            db.execute("CREATE TABLE IF NOT EXISTS binding (body BLOB NOT NULL)")
            raw = canonical_json_bytes(binding)
            if len(raw) > MAX_BYTES:
                raise ValueError("round journal binding exceeds its byte bound")
            compatible = {canonical_json_bytes(value) for value in compatible_bindings}
            if raw in compatible or any(len(value) > MAX_BYTES for value in compatible):
                raise ValueError("round journal compatible binding is invalid")
            sizes = db.execute("SELECT LENGTH(body) FROM binding LIMIT 2").fetchall()
            if len(sizes) > 1:
                raise ValueError("round journal configuration changed")
            old = db.execute("SELECT body FROM binding LIMIT 1").fetchall()
            transport_history = has_transport_history(db)
            if transport_history and not old:
                raise ValueError("round RPC migration lacks original binding")
            if old and (transport_history or bytes(old[0][0]) != raw):
                prior = bytes(old[0][0])
                if not transport_history and prior in compatible:
                    db.execute("UPDATE binding SET body = ?", (raw,))
                elif transport_history or (
                    isinstance(binding, dict)
                    and binding.get("schema") == "umi-round-coordinator-config/2"
                    and prior not in _predecessor_bindings(binding)
                ):
                    validate_rpc_binding(db, prior, raw)
                elif prior not in _predecessor_bindings(binding):
                    raise ValueError("round journal configuration changed")
                # Bound under a deal-preserving predecessor policy (same binding body with the
                # predecessor's digest wherever policy_sha256 appears): move it to the live policy.
                else:
                    db.execute("UPDATE binding SET body = ?", (raw,))
            if not old:
                db.execute("INSERT INTO binding VALUES (?)", (raw,))
            db.execute(
                "CREATE TABLE IF NOT EXISTS records (kind TEXT, id TEXT, body BLOB NOT NULL, "
                "PRIMARY KEY(kind,id))"
            )
            # Capacity checks need counts and byte lengths, not proof bodies.
            # SQLite maintains this covering index in the same transaction as
            # every record write. Existing records, bindings and limits remain
            # unchanged; older readers can continue using the journal.
            db.execute(
                "CREATE INDEX IF NOT EXISTS records_capacity_lengths ON records(kind,LENGTH(body))"
            )
            self._initialize_record_capacity(db, repair=repair_record_capacity)
            db.execute("CREATE TABLE IF NOT EXISTS holds (id TEXT PRIMARY KEY)")
            db.execute("CREATE TABLE IF NOT EXISTS highwater (block INTEGER NOT NULL)")
            db.execute(
                "CREATE TABLE IF NOT EXISTS round_index "
                "(sequence INTEGER PRIMARY KEY, suite TEXT UNIQUE, proposal TEXT UNIQUE, "
                "snapshot_block INTEGER NOT NULL, signing_close INTEGER NOT NULL)"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS plan_index "
                "(suite TEXT PRIMARY KEY, opens INTEGER NOT NULL, closes INTEGER NOT NULL)"
            )
            if "execution_close" not in {
                r[1] for r in db.execute("PRAGMA table_info(round_index)")
            }:
                db.execute(
                    "ALTER TABLE round_index ADD COLUMN execution_close INTEGER NOT NULL DEFAULT 0"
                )
                rows = db.execute(
                    "SELECT sequence,suite FROM round_index LIMIT ?", (maximum_rounds + 1,)
                ).fetchall()
                if len(rows) > maximum_rounds:
                    raise ValueError("round journal index capacity exhausted")
                for sequence, suite in rows:
                    raw = self._record(db, "prepared", suite)
                    if raw is None:
                        raise ValueError("round index is missing its prepared record")
                    proposal = RoundProposal.model_validate_json(raw)
                    if (
                        proposal.cutoff.round.sequence != sequence
                        or proposal.cutoff.round.suite_sha256 != suite
                    ):
                        raise ValueError("round index migration binding mismatch")
                    db.execute(
                        "UPDATE round_index SET execution_close=? WHERE sequence=?",
                        (proposal.cutoff.round.evaluation_close_block, sequence),
                    )
            db.execute(
                "CREATE TABLE IF NOT EXISTS round_settlement_index "
                "(sequence INTEGER PRIMARY KEY, cutoff INTEGER NOT NULL, "
                "valid_through INTEGER NOT NULL)"
            )
            rows = db.execute(
                "SELECT sequence,suite FROM round_index LIMIT ?", (maximum_rounds + 1,)
            ).fetchall()
            if len(rows) > maximum_rounds:
                raise ValueError("round settlement index capacity exhausted")
            for sequence, suite in rows:
                proposal = RoundProposal.model_validate_json(self._record(db, "prepared", suite))
                if proposal.cutoff.round.sequence != sequence or (
                    proposal.cutoff.round.suite_sha256 != suite
                ):
                    raise ValueError("round settlement index binding mismatch")
                expected = (
                    proposal.cutoff.cutoff_schedule.evidence_cutoff_block,
                    proposal.cutoff.round.valid_through_block,
                )
                prior = db.execute(
                    "SELECT cutoff,valid_through FROM round_settlement_index WHERE sequence=?",
                    (sequence,),
                ).fetchone()
                if prior is not None and prior != expected:
                    raise ValueError("round settlement index windows changed")
                db.execute(
                    "INSERT OR IGNORE INTO round_settlement_index VALUES (?,?,?)",
                    (sequence, *expected),
                )

    def _validate_existing(self, binding, *, require_clean_rollback=True):
        if type(require_clean_rollback) is not bool or (
            not require_clean_rollback and not self.read_only
        ):
            raise ValueError("live existing journal inspection requires a read-only connection")
        # Never run a schema/binding migration while merely opening the source
        # of a stopped-owner transfer. Old layouts require their explicit repair.
        for suffix in ("-wal", "-shm"):
            sidecar = Path(str(self.path) + suffix)
            if sidecar.exists() or sidecar.is_symlink():
                raise ValueError("existing journal has an unrecovered SQLite sidecar")
        with self.path.open("rb") as stream:
            header = stream.read(100)
        if header[:16] != b"SQLite format 3\0" or header[18:20] != b"\x01\x01":
            raise ValueError("existing journal requires clean rollback format")
        rollback = Path(str(self.path) + "-journal")
        if require_clean_rollback and (rollback.exists() or rollback.is_symlink()):
            if self.read_only or self.physical_budget is None:
                raise ValueError(
                    "existing source journal requires explicit interrupted transaction recovery"
                )
            self.physical_budget.recover(self.path)
        with self.read_transaction() as db:
            raw = canonical_json_bytes(binding)
            sizes = db.execute("SELECT LENGTH(body) FROM binding LIMIT 2").fetchall()
            if sizes != [(len(raw),)]:
                raise ValueError("existing journal binding requires explicit migration")
            rows = db.execute("SELECT body FROM binding LIMIT 1").fetchall()
            if rows != [(raw,)]:
                raise ValueError("existing journal binding requires explicit migration")
            for table, columns in {
                "records": "kind,id,body",
                "holds": "id",
                "highwater": "block",
                "round_index": (
                    "sequence,suite,proposal,snapshot_block,signing_close,execution_close"
                ),
                "plan_index": "suite,opens,closes",
                "round_settlement_index": "sequence,cutoff,valid_through",
            }.items():
                db.execute("SELECT " + columns + " FROM " + table + " LIMIT 0")
            index = db.execute(
                "SELECT sql FROM sqlite_master WHERE type='index' "
                "AND name='records_capacity_lengths'"
            ).fetchone()
            if index != ("CREATE INDEX records_capacity_lengths ON records(kind,LENGTH(body))",):
                raise ValueError("existing journal capacity index requires explicit migration")
            self._record_capacity(db)

    def _check_files(self):
        _private(self.root)
        sidecars = tuple(Path(str(self.path) + suffix) for suffix in ("-journal", "-wal", "-shm"))
        paths = (self.path, *sidecars, self.lock_path)
        for p in paths:
            try:
                s = p.lstat()
            except FileNotFoundError:
                # SQLite can remove a rollback sidecar as another connection
                # commits. Inspect present paths with one non-following stat,
                # rather than racing exists/is_symlink against a later stat.
                continue
            if stat.S_ISLNK(s.st_mode):
                raise ValueError("round journal symlink")
            # SQLite may unlink a private sidecar between path resolution and
            # lstat's inode read. A zero-link sidecar has already disappeared,
            # just like FileNotFoundError above; it is not an extra hard link.
            # The database/lock must remain linked, and every observed inode
            # still has to be regular, private and owned by this process user.
            permitted_links = (0, 1) if p in sidecars else (1,)
            if (
                not stat.S_ISREG(s.st_mode)
                or s.st_nlink not in permitted_links
                or (s.st_uid != os.getuid() or s.st_mode & 0o077)
            ):
                raise ValueError("round journal must be private and owned")

    @contextmanager
    def locked(self) -> Iterator[None]:
        """Serialize compound operations without locking the SQLite file.

        BSD ``flock`` interacts with SQLite's byte-range locks on macOS. The
        private sibling file keeps the process mutex independent of SQLite's
        transaction locks on every supported platform.
        Acquisition fails immediately on contention. This lock is not reentrant;
        ordinary journal operations do not acquire it.
        """
        self._check_files()
        descriptor = os.open(
            self.lock_path,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
        )
        try:
            acquire_private_mutex(descriptor, self.lock_path, operation="round_journal_lock")
            self._check_files()
            opened = os.fstat(descriptor)
            current = self.lock_path.stat()
            if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
                raise ValueError("round journal lock identity changed")
            yield
        finally:
            os.close(descriptor)

    @contextmanager
    def transaction(self, *, _repair_record_capacity=False) -> Iterator[sqlite3.Connection]:
        """Own one immediate writer transaction through commit, rollback and close.

        Callers must not commit, close or retain the supplied connection.
        """
        if self.read_only:
            raise ValueError("existing source journal is read-only")
        with self._transaction_lock:
            self._check_files()
            db = sqlite3.connect(self.path, isolation_level=None, timeout=5)
            try:
                db.create_function("umi_round_writer_generation", 0, lambda: 2)
                db.execute("PRAGMA synchronous=FULL")
                db.execute("PRAGMA recursive_triggers=ON")
                # maximum_bytes admits logical records and reservations, not
                # physical SQLite pages. Indexes, keys and page fragmentation
                # need separate disk headroom; deriving another ceiling here
                # can reject valid work before its logical allowance is used.
                if self.physical_budget is not None:
                    self.physical_budget.configure(db, self.path)
                db.execute("BEGIN IMMEDIATE")
                version = self._version(db)
                initial_tables = self._table_names(db)
                if version == 2:
                    self._fence_tables(db)
                if not _repair_record_capacity:
                    self._check_record_capacity_schema(db)
                yield db
                self._check_record_capacity_schema(db)
                if db.execute("PRAGMA user_version").fetchone()[0] == 2:
                    self._fence_tables(db, new_tables=self._table_names(db) - initial_tables)
                db.commit()
                migration, self._capacity_migration = self._capacity_migration, None
                if migration is not None:
                    _capacity_progress("completed", *migration)
            except BaseException:
                db.rollback()
                migration, self._capacity_migration = self._capacity_migration, None
                if migration is not None:
                    _capacity_progress("retrying", *migration)
                raise
            finally:
                db.close()

    @staticmethod
    def _version(db):
        version = db.execute("PRAGMA user_version").fetchone()[0]
        if version not in (0, 2):
            raise ValueError("unsupported round journal capability")
        if (
            version == 0
            and db.execute(
                "SELECT 1 FROM sqlite_master WHERE name GLOB 'record_reservation*' "
                "OR name GLOB 'round_generation_*' LIMIT 1"
            ).fetchone()
        ):
            raise ValueError("round reservation generation marker was downgraded")
        return version

    @contextmanager
    def read_transaction(self, *, wait: bool = True) -> Iterator[sqlite3.Connection]:
        """Read one current snapshot without reserving SQLite's writer slot.

        Authorization that reads and then mutates state must keep using
        ``transaction``. This connection cannot write or repair schema fences.
        Conflict holds and generation markers are read afresh on every call.
        Advisory probes can set ``wait=False`` to refuse SQLite contention promptly.
        """
        self._check_files()
        db = sqlite3.connect(
            self.path.resolve().as_uri() + "?mode=ro",
            uri=True,
            isolation_level=None,
            timeout=5 if wait else 0,
        )
        try:
            db.execute("PRAGMA query_only=ON")
            if self.existing_only or self.physical_budget is not None:
                db.execute("PRAGMA temp_store=MEMORY")
            db.execute("BEGIN")
            if self._version(db) == 2:
                self._fence_tables(db)
            self._check_record_capacity_schema(db)
            yield db
        finally:
            db.close()

    @staticmethod
    def _identifier(name):
        return '"' + name.replace('"', '""') + '"'

    @classmethod
    def _table_names(cls, db):
        return {
            row[0]
            for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }

    @classmethod
    def _trigger(cls, name, action, *, immutable=False):
        if immutable:
            trigger = f"{name}_immutable_{action.lower()}"
            body = "SELECT RAISE(ABORT,'round reservations are append-only');"
        else:
            trigger = f"round_generation_{name}_{action.lower()}"
            body = (
                "SELECT CASE WHEN umi_round_writer_generation() IS NOT 2 THEN "
                "RAISE(ABORT,'round journal writer capability required') END;"
            )
        return trigger, (
            f"CREATE TRIGGER {cls._identifier(trigger)} BEFORE {action} "
            f"ON {cls._identifier(name)} BEGIN {body} END"
        )

    @classmethod
    def _fence_tables(cls, db, *, new_tables=frozenset()):
        """Verify existing fences; install only for explicitly new tables."""
        tables = cls._table_names(db)
        required = {
            "binding",
            "records",
            "holds",
            "highwater",
            "round_index",
            "plan_index",
            "round_settlement_index",
            "record_reservations",
            "record_reservation_batches",
            "record_reservation_identity",
        }
        if not required <= tables:
            raise ValueError("round journal capability table missing")
        existing = dict(db.execute("SELECT name,sql FROM sqlite_master WHERE type='trigger'"))
        for name in tables:
            for action in ("INSERT", "UPDATE", "DELETE"):
                definitions = [cls._trigger(name, action)]
                if name.startswith("record_reservation") and action != "INSERT":
                    definitions.append(cls._trigger(name, action, immutable=True))
                for trigger_name, sql in definitions:
                    retained = existing.get(trigger_name)
                    if retained is None and name in new_tables:
                        db.execute(sql)
                    elif retained is None or " ".join(retained.split()) != " ".join(sql.split()):
                        raise ValueError("round journal capability fence missing or changed")

    def _enable_reservations(self, db):
        if db.execute("PRAGMA user_version").fetchone()[0] == 2:
            return
        # Older reservation-capable owners charge every auxiliary table as
        # retained data. Preserve their already signed capacity accounting:
        # the reservation transition removes only these derived counters, in
        # the same commit as its capability fence. History journals never
        # enable reservations; they retain the constant-work write path.
        if db.execute("PRAGMA application_id").fetchone()[0] == _CAPACITY_APPLICATION_ID:
            self._check_record_capacity_schema(db)
            self._record_capacity(db)
            for name in _capacity_triggers():
                db.execute(f"DROP TRIGGER {self._identifier(name)}")
            for name in _CAPACITY_TABLES:
                db.execute(f"DROP TABLE {self._identifier(name)}")
            db.execute("PRAGMA application_id=0")
        db.execute(
            "CREATE TABLE record_reservation_batches (id TEXT PRIMARY KEY, body BLOB NOT NULL)"
        )
        db.execute("CREATE TABLE record_reservation_identity (body BLOB NOT NULL)")
        db.execute(
            "INSERT INTO record_reservation_identity VALUES (?)",
            (
                canonical_json_bytes(
                    {
                        "journal_identity": secrets.token_hex(32),
                        **self._binding(db),
                        "maximum_rounds": self.maximum_rounds,
                        "maximum_bytes": self.maximum_bytes,
                    }
                ),
            ),
        )
        db.execute(
            "CREATE TABLE record_reservations (kind TEXT NOT NULL, id TEXT NOT NULL, "
            "maximum_bytes INTEGER NOT NULL, value_sha256 TEXT, document BLOB NOT NULL, "
            "PRIMARY KEY(kind,id))"
        )
        self._fence_tables(db, new_tables=self._table_names(db))
        db.execute("PRAGMA user_version=2")

    def _binding(self, db):
        body = self._bounded_blob(db, "binding", "body")
        if body is None:
            raise ValueError("round journal binding missing")
        return {
            "journal_path": str(self.path.resolve()),
            "binding_sha256": sha256_hex(body),
        }

    @classmethod
    def _bounded_blob(cls, db, table, column, *, where="", arguments=(), maximum=MAX_BYTES):
        source = f"{cls._identifier(table)} {where}"
        field = cls._identifier(column)
        sizes = db.execute(
            f"SELECT LENGTH({field}),TYPEOF({field}) FROM {source} LIMIT 2", arguments
        ).fetchall()
        if not sizes:
            return None
        if (
            len(sizes) != 1
            or sizes[0][1] != "blob"
            or (type(sizes[0][0]) is not int or not 1 <= sizes[0][0] <= maximum)
        ):
            raise ValueError("round reservation retained blob exceeds bound")
        return bytes(db.execute(f"SELECT {field} FROM {source} LIMIT 1", arguments).fetchone()[0])

    @staticmethod
    def _canonical_document(raw):
        try:
            value = json.loads(raw)
            if type(value) is not dict or canonical_json_bytes(value) != raw:
                raise ValueError("round reservation document is not canonical")
            return value
        except (TypeError, UnicodeError, json.JSONDecodeError) as error:
            raise ValueError("round reservation document is invalid") from error

    @staticmethod
    def _spec_document(value):
        if type(value) is not dict or set(value) != {
            "kind",
            "key",
            "maximum_bytes",
            "value_sha256",
        }:
            raise ValueError("invalid round record reservation fields")
        kind, key, maximum, sha = (
            value[k] for k in ("kind", "key", "maximum_bytes", "value_sha256")
        )
        if (
            type(kind) is not str
            or not 1 <= len(kind.encode()) <= 128
            or type(key) is not str
            or not 1 <= len(key.encode()) <= 1024
            or type(maximum) is not int
            or not 1 <= maximum <= MAX_BYTES
            or (
                sha is not None
                and (
                    type(sha) is not str
                    or len(sha) != 64
                    or any(c not in "0123456789abcdef" for c in sha)
                )
            )
        ):
            raise ValueError("invalid round record reservation")
        return value

    @classmethod
    def _decode_obligation(cls, row):
        kind, key, raw, maximum, sha, valid_columns = row
        if raw is None:
            raise ValueError("round reservation retained blob exceeds bound")
        doc = cls._spec_document(cls._canonical_document(raw))
        if not valid_columns:
            raise ValueError("round reservation allowance columns changed")
        if (doc["kind"], doc["key"], doc["maximum_bytes"], doc["value_sha256"]) != (
            kind,
            key,
            maximum,
            sha,
        ):
            raise ValueError("round reservation allowance columns changed")
        return doc

    @classmethod
    def _obligation(cls, db, kind, key):
        row = db.execute(
            f"SELECT {_OBLIGATION_COLUMNS} FROM record_reservations WHERE kind=? AND id=?",
            (kind, key),
        ).fetchone()
        return None if row is None else cls._decode_obligation(row)

    @staticmethod
    def _capacity_damage(message):
        _capacity_progress("repair_required", 0, None, time.monotonic(), "repair")
        raise RoundCapacityRepairRequired(message)

    @classmethod
    def _check_record_capacity_schema(cls, db):
        marker = db.execute("PRAGMA application_id").fetchone()[0]
        retained = dict(
            db.execute(
                "SELECT name,sql FROM sqlite_master WHERE name GLOB 'round_record_capacity*'"
            )
        )
        if marker == 0 and not retained:
            return  # A genuine legacy journal; only the constructor migrates it.
        expected = {**_CAPACITY_SCHEMA, **_capacity_triggers()}
        if (
            marker != _CAPACITY_APPLICATION_ID
            or set(retained) != set(expected)
            or any(
                " ".join(retained[name].split()) != " ".join(sql.split())
                for name, sql in expected.items()
            )
        ):
            cls._capacity_damage(
                "round record capacity metadata missing or changed; repair required"
            )

    def _initialize_record_capacity(self, db, *, repair):
        """Migrate v0 in place, or explicitly rebuild only derived accounting.

        The application marker survives loss of the auxiliary tables. Missing
        counters or triggers are never treated as an empty/legacy journal. The
        explicit repair reads record lengths, not their signed payloads; it does
        not bless evidence, rewrite binding bytes, or change reservation fences.
        Migration and repair are atomic, with counted progress and retry status.
        """
        marker = db.execute("PRAGMA application_id").fetchone()[0]
        if marker not in (0, _CAPACITY_APPLICATION_ID):
            self._capacity_damage("unsupported round record capacity marker")
        if self._version(db) == 2:
            # Existing v2 owners count all metadata tables in their allowance.
            # Do not introduce an accounting change for those mixed-runtime
            # consumers. Their bounded reservation validation still scans all
            # obligations and retains its existing record-accounting path.
            if (
                marker
                or db.execute(
                    "SELECT 1 FROM sqlite_master WHERE name GLOB 'round_record_capacity*' LIMIT 1"
                ).fetchone()
            ):
                self._capacity_damage("reserved journal has unsupported capacity counters")
            return
        try:
            self._check_record_capacity_schema(db)
            if marker == _CAPACITY_APPLICATION_ID:
                self._record_capacity(db)
                return
        except RoundCapacityRepairRequired:
            if not repair:
                raise
        started = time.monotonic()
        operation = "repair" if repair else "migration"
        self._capacity_migration = (0, None, started, operation)
        _capacity_progress("running", *self._capacity_migration)
        for name in _capacity_triggers():
            db.execute(f"DROP TRIGGER IF EXISTS {self._identifier(name)}")
        for name in _CAPACITY_TABLES:
            db.execute(f"DROP TABLE IF EXISTS {self._identifier(name)}")
            db.execute(_CAPACITY_SCHEMA[name])
        db.execute("INSERT INTO round_record_capacity VALUES (1,0,0)")
        # Only kind and the indexed byte length cross into Python. An explicit
        # repair derives lengths from original record metadata, so a damaged
        # auxiliary covering index cannot become the source of new counters.
        source = "records NOT INDEXED" if repair else "records INDEXED BY records_capacity_lengths"
        total = db.execute(f"SELECT COUNT(*) FROM {source}").fetchone()[0]
        self._capacity_migration = (0, total, started, operation)
        _capacity_progress("running", *self._capacity_migration)
        completed = used = 0
        cursor = db.execute(f"SELECT kind,LENGTH(body) FROM {source}")
        try:
            while rows := cursor.fetchmany(4096):
                batch = {}
                for kind, size in rows:
                    if type(kind) is not str or type(size) is not int or size < 0:
                        raise ValueError("round record capacity source metadata is invalid")
                    number, nbytes = batch.get(kind, (0, 0))
                    batch[kind] = (number + 1, nbytes + size)
                    used += size
                db.executemany(
                    "INSERT INTO round_record_capacity_kinds VALUES (?,?,?) "
                    "ON CONFLICT(kind) DO UPDATE SET number=number+excluded.number,"
                    "nbytes=nbytes+excluded.nbytes",
                    ((kind, *values) for kind, values in batch.items()),
                )
                completed += len(rows)
                self._capacity_migration = (completed, total, started, operation)
                _capacity_progress("running", *self._capacity_migration)
        finally:
            cursor.close()
        db.execute(
            "UPDATE round_record_capacity SET number=?,nbytes=? WHERE id=1", (completed, used)
        )
        for definition in _capacity_triggers().values():
            db.execute(definition)
        db.execute(f"PRAGMA application_id={_CAPACITY_APPLICATION_ID}")
        self._record_capacity(db)

    @classmethod
    def _record_capacity(cls, db):
        """Read O(number of record kinds) metadata, independent of history size.

        SQLite changes counters in the same transaction as every native or
        compatible older writer. No process-local cache can hide another writer,
        rollback, same-length mutation, deletion or identity-changing update.
        Reserved journals retain the prior complete accounting path for older
        owners whose durable allowances include every auxiliary table.
        """
        if db.execute("PRAGMA application_id").fetchone()[0] == 0:
            count, used = db.execute(
                "SELECT COUNT(*),COALESCE(SUM(LENGTH(body)),0) FROM records"
            ).fetchone()
            return count, used, dict(db.execute("SELECT kind,COUNT(*) FROM records GROUP BY kind"))
        totals = db.execute("SELECT id,number,nbytes FROM round_record_capacity LIMIT 2").fetchall()
        kinds = {}
        count = used = 0
        for kind, number, nbytes in db.execute(
            "SELECT kind,number,nbytes FROM round_record_capacity_kinds"
        ):
            if (
                type(kind) is not str
                or type(number) is not int
                or number <= 0
                or type(nbytes) is not int
                or nbytes < 0
                or kind in kinds
            ):
                cls._capacity_damage("round record capacity counters damaged; repair required")
            kinds[kind] = number
            count += number
            used += nbytes
        if totals != [(1, count, used)] or any(
            type(value) is not int for row in totals for value in row
        ):
            cls._capacity_damage("round record capacity counters disagree; repair required")
        return count, used, kinds

    def _capacity(self, db):
        """Logical retained bytes plus outstanding record allowances.

        Reservation manifests and table metadata remain charged after use.
        The matching immutable record consumes its allowance without deleting
        the obligation. SQLite pages and filesystem overhead are separate.
        """
        invalid = db.execute(
            "SELECT 1 FROM record_reservations WHERE TYPEOF(kind)!='text' OR TYPEOF(id)!='text' "
            "OR LENGTH(CAST(kind AS BLOB)) NOT BETWEEN 1 AND 128 "
            "OR LENGTH(CAST(id AS BLOB)) NOT BETWEEN 1 AND 1024 LIMIT 1"
        ).fetchone()
        if invalid:
            raise ValueError("invalid round reservation identity columns")
        cursor = db.execute(f"SELECT {_OBLIGATION_COLUMNS} FROM record_reservations")
        try:
            for offset, row in enumerate(cursor):
                if offset >= self.maximum_records:
                    raise ValueError("round reservation batch capacity exhausted")
                self._decode_obligation(row)
        finally:
            cursor.close()
        count, used, kinds = self._record_capacity(db)
        pending = (
            " FROM record_reservations o WHERE NOT EXISTS "
            "(SELECT 1 FROM records r WHERE r.kind=o.kind AND r.id=o.id)"
        )
        pending_count, pending_bytes = db.execute(
            "SELECT COUNT(*),COALESCE(SUM(maximum_bytes),0)" + pending
        ).fetchone()
        count += pending_count
        used += pending_bytes
        for kind, number in db.execute("SELECT kind,COUNT(*)" + pending + " GROUP BY kind"):
            kinds[kind] = kinds.get(kind, 0) + number
        # Built-in index rows are created by the same write as these records.
        # Their strings are fixed by the key/digest; block fields have <=16 digits.
        for kind, key in db.execute(
            "SELECT kind,id" + pending + " AND kind IN ('plan','prepared')"
        ):
            count += 1 if kind == "plan" else 2
            used += len(key.encode()) + (32 if kind == "plan" else 176)
        for (name,) in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%' AND name!='records'"
        ).fetchall():
            table = self._identifier(name)
            columns = [
                self._identifier(row[1]) for row in db.execute(f"PRAGMA table_info({table})")
            ]
            sizes = "+".join(f"COALESCE(LENGTH(CAST({col} AS BLOB)),0)" for col in columns)
            rows, size = db.execute(
                f"SELECT COUNT(*),COALESCE(SUM({sizes}),0) FROM {table}"
            ).fetchone()
            if name == "highwater":
                # A later head observation must not consume record credit.
                rows, size = max(1, rows), max(16, size)
            count += rows
            used += size
        return count, used, kinds

    def _check_capacity(self, db):
        count, used, kinds = self._capacity(db)
        if any(
            kinds.get(kind, 0) > self.maximum_rounds
            for kind in ("plan", "prepared", "intent", "suite", "certificate")
        ):
            raise ValueError("round journal record capacity exhausted")
        if count > self.maximum_records or used > self.maximum_bytes:
            raise ValueError("round journal capacity exhausted")

    def reserve_records(
        self,
        batch_id: str,
        specs: Iterable[RecordReservation],
        *,
        db: sqlite3.Connection | None = None,
    ) -> dict[str, str | int] | None:
        """Atomically enable reservations and retain a complete private batch.

        Callers bind semantic identities in their admission manifest. A future
        value may omit its hash; its first immutable write still has to fit the
        reserved bound. No records are published and no signing occurs here.
        This reserves logical journal capacity, not disk space or other stores.
        With ``db``, borrow this journal's active transaction. This allows a
        ``put_many`` index callback to reserve future signature capacity in the
        same commit as the original intent; the caller owns commit/rollback.
        """
        if type(batch_id) is not str or not 1 <= len(batch_id.encode()) <= 128:
            raise ValueError("invalid round reservation batch identity")
        documents = {}
        staged_bytes = 0
        for offset, spec in enumerate(specs):
            if offset >= self.maximum_rounds * 80:
                raise ValueError("round reservation batch capacity exhausted")
            if not isinstance(spec, RecordReservation):
                raise ValueError("invalid round record reservation")
            document = self._spec_document(
                {
                    "kind": spec.kind,
                    "key": spec.key,
                    "maximum_bytes": spec.maximum_bytes,
                    "value_sha256": spec.value_sha256,
                }
            )
            record_key = (spec.kind, spec.key)
            if record_key in documents:
                if documents[record_key] != document:
                    raise ValueError("round reservation identity conflict")
                continue
            staged_bytes += len(canonical_json_bytes(document))
            if staged_bytes > min(MAX_BYTES, self.maximum_bytes):
                raise ValueError("round reservation manifest capacity exhausted")
            documents[record_key] = document
        manifest = canonical_json_bytes(
            {
                "batch_id": batch_id,
                "records": [documents[key] for key in sorted(documents)],
            }
        )
        if len(manifest) > min(MAX_BYTES, self.maximum_bytes):
            raise ValueError("round reservation manifest capacity exhausted")
        if db is not None:
            return self._reserve_records(db, batch_id, documents, manifest)
        with self.transaction() as owned:
            return self._reserve_records(owned, batch_id, documents, manifest)

    def _reserve_records(self, db, batch_id, documents, manifest):
        self._enable_reservations(db)
        old = self._bounded_blob(
            db, "record_reservation_batches", "body", where="WHERE id=?", arguments=(batch_id,)
        )
        if old is not None:
            if old != manifest:
                raise ValueError("round reservation batch changed")
            return self._reservation(db, batch_id)
        for (kind, key), doc in documents.items():
            if db.execute("SELECT 1 FROM holds WHERE id=?", (key,)).fetchone():
                raise ValueError("round journal conflict held")
            body = canonical_json_bytes(doc)
            prior = self._obligation(db, kind, key)
            if prior is not None and prior != doc:
                raise ValueError("round reservation identity conflict")
            retained = self._record(db, kind, key)
            if retained is not None and (
                len(retained) > doc["maximum_bytes"]
                or (doc["value_sha256"] is not None and sha256_hex(retained) != doc["value_sha256"])
            ):
                raise ValueError("retained round record differs from reservation")
            if prior is None:
                db.execute(
                    "INSERT INTO record_reservations VALUES (?,?,?,?,?)",
                    (kind, key, doc["maximum_bytes"], doc["value_sha256"], body),
                )
        db.execute("INSERT INTO record_reservation_batches VALUES (?,?)", (batch_id, manifest))
        return self._reservation(db, batch_id)

    def _reservation(self, db, batch_id):
        identity_raw = self._bounded_blob(db, "record_reservation_identity", "body", maximum=65536)
        if identity_raw is None:
            raise ValueError("round reservation journal identity invalid")
        identity_ = self._canonical_document(identity_raw)
        expected = self._binding(db)
        if (
            set(identity_) != {*expected, "journal_identity", "maximum_rounds", "maximum_bytes"}
            or any(
                type(identity_[key]) is not type(value) or identity_[key] != value
                for key, value in expected.items()
            )
            or (
                type(identity_.get("journal_identity")) is not str
                or len(identity_["journal_identity"]) != 64
                or any(c not in "0123456789abcdef" for c in identity_["journal_identity"])
                or type(identity_["maximum_rounds"]) is not int
                or not 1 <= identity_["maximum_rounds"] <= 65536
                or type(identity_["maximum_bytes"]) is not int
                or not 1024 <= identity_["maximum_bytes"] <= self.MAXIMUM_BYTES
            )
        ):
            raise ValueError("round reservation journal binding changed")
        raw = self._bounded_blob(
            db, "record_reservation_batches", "body", where="WHERE id=?", arguments=(batch_id,)
        )
        if raw is None:
            return None
        manifest = self._canonical_document(raw)
        if (
            set(manifest) != {"batch_id", "records"}
            or type(manifest["batch_id"]) is not str
            or manifest["batch_id"] != batch_id
            or type(manifest["records"]) is not list
            or len(manifest["records"]) > self.maximum_rounds * 80
        ):
            raise ValueError("round reservation manifest changed")
        previous = None
        for doc in manifest["records"]:
            doc = self._spec_document(doc)
            kind, key = doc["kind"], doc["key"]
            if previous is not None and (kind, key) <= previous:
                raise ValueError("round reservation identities are not unique and sorted")
            previous = (kind, key)
            if self._obligation(db, kind, key) != doc:
                raise ValueError("round reservation obligation missing or changed")
            if db.execute("SELECT 1 FROM holds WHERE id=?", (key,)).fetchone():
                raise ValueError("round journal conflict held")
            retained = self._record(db, kind, key)
            if retained is not None and (
                len(retained) > doc["maximum_bytes"]
                or (doc["value_sha256"] is not None and sha256_hex(retained) != doc["value_sha256"])
            ):
                raise ValueError("retained round record differs from reservation")
        self._check_capacity(db)
        return {
            "batch_id": batch_id,
            "manifest_sha256": sha256_hex(raw),
            "generation": 2,
            "journal_identity": identity_["journal_identity"],
            "maximum_rounds": identity_["maximum_rounds"],
            "maximum_bytes": identity_["maximum_bytes"],
            **expected,
        }

    def reservation(self, batch_id: str) -> dict[str, str | int] | None:
        """Recheck durable obligations and return their bound native receipt."""
        if type(batch_id) is not str or not 1 <= len(batch_id.encode()) <= 128:
            raise ValueError("invalid round reservation batch identity")
        with self.read_transaction() as db:
            if db.execute("PRAGMA user_version").fetchone()[0] != 2:
                return None
            return self._reservation(db, batch_id)

    def put(self, kind: str, key: str, value: object) -> None:
        # Exact immutable retries need only the current committed snapshot.
        # Retaking the writer slot for every retained archive object can hold
        # up unrelated signing and retirement. Missing or different bytes still
        # use the native writer, which retains conflicts atomically.
        with self.read_transaction() as db:
            prior = self.get_raw(kind, key, db=db)
            if prior is not None:
                raw = canonical_json_bytes(value)
                if len(raw) > self.maximum_record_bytes:
                    raise ValueError("round journal object exceeds its byte bound")
                if prior == raw:
                    doc = self._obligation(db, kind, key) if self._version(db) == 2 else None
                    if doc is not None and (
                        len(raw) > doc["maximum_bytes"]
                        or (
                            doc["value_sha256"] is not None
                            and sha256_hex(raw) != doc["value_sha256"]
                        )
                    ):
                        raise ValueError("retained round record differs from reservation")
                    return
        self.put_many(((kind, key, value),))

    def put_many(
        self,
        records: Iterable[tuple[str, str, object]],
        *,
        index: Callable[[sqlite3.Connection], None] | None = None,
    ) -> None:
        """Commit immutable records and their indexes together, or retain holds.

        ``index(db)`` may update caller-owned indexes in this same transaction.
        It also runs for exact retries, but never for held or conflicting keys.
        A conflict commits only holds; other errors roll back the entire batch.
        The iterable is consumed inside the transaction. Only new records are
        staged, within the journal capacity; retries retain only digest metadata.
        The callback is synchronous and also runs for an empty batch. Use its
        connection for index work; do not open a nested journal transaction.
        """
        if index is not None and not callable(index):
            raise ValueError("round journal index must be callable")
        conflicts = set()
        held = False
        with self.transaction() as db:
            reserved = db.execute("PRAGMA user_version").fetchone()[0] == 2
            seen = {}
            pending = []
            capacity_error = None
            count = used = 0
            kinds = None
            for offset, (kind, key, value) in enumerate(records):
                if offset >= self.maximum_rounds * 80:
                    raise ValueError("round journal batch capacity exhausted")
                raw = canonical_json_bytes(value)
                if len(raw) > self.maximum_record_bytes:
                    raise ValueError("round journal object exceeds its byte bound")
                record_key = (kind, key)
                fingerprint = (len(raw), sha256_hex(raw))
                if record_key in seen:
                    if seen[record_key] != fingerprint:
                        conflicts.add(key)
                    continue
                seen[record_key] = fingerprint
                if db.execute("SELECT 1 FROM holds WHERE id=?", (key,)).fetchone():
                    held = True
                    continue
                doc = self._obligation(db, kind, key) if reserved else None
                obligation = None if doc is None else (doc["maximum_bytes"], doc["value_sha256"])
                prior = self._record(db, kind, key)
                if prior is not None:
                    if prior != raw:
                        conflicts.add(key)
                    elif obligation is not None and (
                        len(prior) > obligation[0]
                        or (obligation[1] is not None and fingerprint[1] != obligation[1])
                    ):
                        raise ValueError("retained round record differs from reservation")
                    continue
                if reserved:
                    if (
                        obligation is not None
                        and obligation[1] is not None
                        and (obligation[1] != fingerprint[1])
                    ):
                        conflicts.add(key)
                        continue
                    if obligation is not None and len(raw) > obligation[0]:
                        capacity_error = "round record exceeds reserved allowance"
                if held or conflicts or capacity_error is not None:
                    continue
                if kinds is None:
                    if reserved:
                        count, used, kinds = self._capacity(db)
                    else:
                        count, used, kinds = self._record_capacity(db)
                extra_count = 0 if obligation is not None else 1
                extra_bytes = len(raw) - (obligation[0] if obligation is not None else 0)
                if kind in {"plan", "prepared", "intent", "suite", "certificate"} and (
                    kinds.get(kind, 0) + extra_count > self.maximum_rounds
                ):
                    capacity_error = "round journal record capacity exhausted"
                elif (
                    used + extra_bytes > self.maximum_bytes
                    or count + extra_count > self.maximum_records
                ):
                    capacity_error = "round journal capacity exhausted"
                else:
                    pending.append((kind, key, raw))
                    count += extra_count
                    used += extra_bytes
                    kinds[kind] = kinds.get(kind, 0) + extra_count
            if conflicts:
                db.executemany(
                    "INSERT OR IGNORE INTO holds VALUES (?)", ((key,) for key in conflicts)
                )
            elif not held:
                if capacity_error is not None:
                    raise ValueError(capacity_error)
                for kind, key, raw in pending:
                    db.execute("INSERT INTO records VALUES (?,?,?)", (kind, key, raw))
                    if kind == "prepared":
                        proposal = RoundProposal.model_validate_json(raw)
                        if key != proposal.cutoff.round.suite_sha256:
                            raise ValueError("round index suite binding mismatch")
                        db.execute(
                            "INSERT INTO round_index VALUES (?,?,?,?,?,?)",
                            (
                                proposal.cutoff.round.sequence,
                                key,
                                digest(proposal),
                                proposal.cutoff.registration_snapshot.block,
                                proposal.signing_close_block,
                                proposal.cutoff.round.evaluation_close_block,
                            ),
                        )
                        db.execute(
                            "INSERT INTO round_settlement_index VALUES (?,?,?)",
                            (
                                proposal.cutoff.round.sequence,
                                proposal.cutoff.cutoff_schedule.evidence_cutoff_block,
                                proposal.cutoff.round.valid_through_block,
                            ),
                        )
                    elif kind == "plan":
                        plan = RoundPlan.model_validate_json(raw)
                        if key != digest(plan.suite):
                            raise ValueError("round plan suite binding mismatch")
                        db.execute(
                            "INSERT INTO plan_index VALUES (?,?,?)",
                            (key, plan.not_before_block, plan.admission_close_by_block),
                        )
                if index is not None:
                    index(db)
                if reserved and (pending or index is not None):
                    self._check_capacity(db)
        if held:
            raise ValueError("round journal conflict held")
        if conflicts:
            raise ValueError("round journal conflict retained")

    def _record(self, db, kind, key):
        size = db.execute(
            "SELECT length(body) FROM records WHERE kind=? AND id=?", (kind, key)
        ).fetchone()
        if size is None:
            return None
        bound_kind = "declaration" if kind in {"service_catalog", "service_round"} else "object"
        maximum = stage_limit("maximum_" + bound_kind + "_bytes", self.maximum_record_bytes)
        if type(size[0]) is not int or not 1 <= size[0] <= maximum:
            raise ValueError("retained round object exceeds its byte bound")
        row = db.execute("SELECT body FROM records WHERE kind=? AND id=?", (kind, key)).fetchone()
        raw = bytes(row[0])
        if bound_kind == "declaration":
            charge_stage_declaration(len(raw))
        check_stage_json(raw, kind=bound_kind)
        if not is_canonical_json(raw):
            raise ValueError("retained round object is not canonical")
        return raw

    def get(self, kind: str, key: str, *, db: sqlite3.Connection | None = None) -> JsonValue:
        """Read canonical JSON, borrowing this journal's transaction when supplied.

        A borrowed connection remains owned by the caller. None represents
        either an absent record or a retained JSON null.
        """
        raw = self.get_raw(kind, key, db=db)
        if raw is not None:
            return json.loads(raw)
        return None

    def get_raw(self, kind: str, key: str, *, db: sqlite3.Connection | None = None) -> bytes | None:
        """Read bounded canonical bytes with the same fresh conflict fence."""
        if db is None:
            with self.read_transaction() as db:
                return self.get_raw(kind, key, db=db)
        if db.execute("SELECT 1 FROM holds WHERE id=?", (key,)).fetchone():
            raise ValueError("round journal conflict held")
        return self._record(db, kind, key)

    def keys(self, kind: str) -> list[str]:
        with self.read_transaction() as db:
            rows = db.execute(
                "SELECT id FROM records WHERE kind=? ORDER BY id LIMIT ?",
                (kind, self.maximum_rounds + 1),
            ).fetchall()
        if len(rows) > self.maximum_rounds:
            raise ValueError("round journal record limit")
        return [row[0] for row in rows]

    @staticmethod
    def _observed_head(db, block):
        old = db.execute("SELECT block FROM highwater LIMIT 2").fetchall()
        if len(old) > 1 or (
            old and (type(old[0][0]) is not int or not 0 <= old[0][0] <= 2**53 - 1)
        ):
            raise ValueError("round finalized head is invalid")
        if old and old[0][0] > block:
            raise FinalizedHeadRegression(
                "round finalized head regressed", capture_block=block, retained_block=old[0][0]
            )
        return None if not old else old[0][0]

    def observe(self, block: int) -> None:
        if type(block) is not int or not 0 <= block <= 2**53 - 1:
            raise ValueError("round finalized head regressed")
        # An already retained head is a read. Repeating it must not queue behind
        # unrelated record writers or scan every reservation and payload table.
        with self.read_transaction() as db:
            if self._observed_head(db, block) == block:
                return
        with self.transaction() as db:
            # Another observer can advance while this caller waits for ownership.
            if self._observed_head(db, block) == block:
                return
            db.execute("DELETE FROM highwater")
            db.execute("INSERT INTO highwater VALUES (?)", (block,))
            # _capacity always reserves one 16-byte highwater row, including when
            # empty. This bounded update cannot consume record or byte credit.
            # Growth checks remain on record/reservation/index mutations.

    def due_plans(self, block: int) -> list[str]:
        """Return at most four unprepared suite identities due at this block."""
        with self.read_transaction() as db:
            rows = db.execute(
                "SELECT suite FROM plan_index WHERE opens<=? AND closes>=? "
                "AND suite NOT IN (SELECT suite FROM round_index) "
                "AND suite NOT IN (SELECT id FROM holds) ORDER BY closes,suite LIMIT 4",
                (block, block),
            ).fetchall()
        return [r[0] for r in rows]

    def prepared_entries(
        self,
        after_sequence: int = 0,
        proposal_id: str | None = None,
        *,
        block: int | None = None,
        maximum_age: int = 360,
        for_work: bool = False,
    ) -> list[tuple[int, str, str, int, int]]:
        """Return sequence, suite, proposal, snapshot block and signing-close block.

        Cursor queries return at most four entries; an exact proposal is unique.
        """
        with self.read_transaction() as db:
            if proposal_id is not None:
                rows = db.execute(
                    "SELECT sequence,suite,proposal,snapshot_block,signing_close "
                    "FROM round_index WHERE proposal=?",
                    (proposal_id,),
                ).fetchall()
            elif for_work and block is not None:
                rows = db.execute(
                    "SELECT sequence,suite,proposal,snapshot_block,signing_close FROM round_index "
                    "WHERE sequence>? AND snapshot_block<=? AND execution_close>? "
                    "AND suite NOT IN (SELECT id FROM holds) ORDER BY sequence LIMIT 4",
                    (after_sequence, block, block),
                ).fetchall()
            else:
                rows = db.execute(
                    "SELECT sequence,suite,proposal,snapshot_block,signing_close "
                    "FROM round_index WHERE sequence>? "
                    "AND (? IS NULL OR suite NOT IN (SELECT id FROM holds)) "
                    "AND (? IS NULL OR (snapshot_block<=? AND signing_close>=? "
                    "AND snapshot_block+?>=?)) ORDER BY sequence LIMIT 4",
                    (after_sequence, block, block, block, block, maximum_age, block),
                ).fetchall()
        return rows

    def settlement_entries(self, block: int, after_sequence: int = 0) -> list[RoundProposal]:
        """Return at most four verified proposals inside their settlement window."""
        with self.read_transaction() as db:
            rows = db.execute(
                "SELECT r.sequence,r.suite,s.cutoff,s.valid_through FROM round_index r "
                "JOIN round_settlement_index s ON s.sequence=r.sequence "
                "WHERE r.sequence>? AND s.cutoff<=? AND s.valid_through>=? "
                "AND r.suite NOT IN (SELECT id FROM holds) ORDER BY r.sequence LIMIT 4",
                (after_sequence, block, block),
            ).fetchall()
            result = []
            for sequence, suite, cutoff, valid_through in rows:
                proposal = RoundProposal.model_validate_json(self._record(db, "prepared", suite))
                if (
                    proposal.cutoff.round.sequence != sequence
                    or proposal.cutoff.round.suite_sha256 != suite
                    or proposal.cutoff.cutoff_schedule.evidence_cutoff_block != cutoff
                    or proposal.cutoff.round.valid_through_block != valid_through
                ):
                    raise ValueError("round settlement index differs from its retained proposal")
                result.append(proposal)
        return result


def _predecessor_bindings(binding: object) -> set[bytes]:
    """Binding bodies this journal would carry under an honored predecessor policy."""
    from .competition_policy_lineage import registered_admitted_sha256s

    if not isinstance(binding, dict):
        return set()
    live = binding.get("policy_sha256") or binding.get("policy")
    if not isinstance(live, str):
        return set()
    out = set()
    for predecessor in registered_admitted_sha256s(live)[1:]:

        def swap(o, predecessor=predecessor):
            if isinstance(o, dict):
                return {
                    k: (predecessor if k in ("policy_sha256", "policy") and v == live else swap(v))
                    for k, v in o.items()
                }
            if isinstance(o, list):
                return [swap(v) for v in o]
            return o

        out.add(canonical_json_bytes(swap(binding)))
    return out
