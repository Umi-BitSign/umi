"""Private round storage, immutable records, capacity reservations and conflict holds."""

from __future__ import annotations

import fcntl
import json
import os
import secrets
import sqlite3
import stat
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from pydantic import JsonValue

from .competition_round_plan import RoundPlan, RoundProposal
from .open_competition import digest
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


@dataclass(frozen=True, slots=True)
class RecordReservation:
    """Private allowance for one canonical journal value, before it exists."""

    kind: str
    key: str
    maximum_bytes: int
    value_sha256: str | None = None


class RoundJournal:
    """Bounded immutable records and durable conflict holds, shared by both roles."""

    def __init__(
        self,
        root: Path,
        binding: object,
        *,
        maximum_rounds: int = 1024,
        maximum_bytes: int = 1024**3,
    ) -> None:
        if (
            type(maximum_rounds) is not int
            or not 1 <= maximum_rounds <= 65536
            or (type(maximum_bytes) is not int or not 1024 <= maximum_bytes <= 16 * 1024**3)
        ):
            raise ValueError("round journal requires bounded capacity")
        self.root, self.maximum_rounds, self.maximum_bytes = root, maximum_rounds, maximum_bytes
        _private(root)
        self.path = root / "rounds.sqlite3"
        self.lock_path = root / "rounds.lock"
        self._check_files()
        for path in (self.path, self.lock_path):
            os.close(os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600))
        self._check_files()
        with self.transaction() as db:
            db.execute("CREATE TABLE IF NOT EXISTS binding (body BLOB NOT NULL)")
            raw = canonical_json_bytes(binding)
            if len(raw) > MAX_BYTES:
                raise ValueError("round journal binding exceeds its byte bound")
            sizes = db.execute("SELECT LENGTH(body) FROM binding LIMIT 2").fetchall()
            if len(sizes) > 1:
                raise ValueError("round journal configuration changed")
            old = db.execute("SELECT body FROM binding LIMIT 1").fetchall()
            if old and (len(old) != 1 or bytes(old[0][0]) != raw):
                if len(old) != 1 or bytes(old[0][0]) not in _predecessor_bindings(binding):
                    raise ValueError("round journal configuration changed")
                # Bound under a deal-preserving predecessor policy (same binding body with the
                # predecessor's digest wherever policy_sha256 appears): move it to the live policy.
                db.execute("UPDATE binding SET body = ?", (raw,))
            if not old:
                db.execute("INSERT INTO binding VALUES (?)", (raw,))
            db.execute(
                "CREATE TABLE IF NOT EXISTS records (kind TEXT, id TEXT, body BLOB NOT NULL, "
                "PRIMARY KEY(kind,id))"
            )
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

    def _check_files(self):
        _private(self.root)
        paths = [Path(str(self.path) + suffix) for suffix in ("", "-journal", "-wal", "-shm")]
        paths.append(self.lock_path)
        for p in paths:
            if p.is_symlink():
                raise ValueError("round journal symlink")
            if p.exists():
                s = p.stat()
                if (
                    not stat.S_ISREG(s.st_mode)
                    or s.st_nlink != 1
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
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._check_files()
            opened = os.fstat(descriptor)
            current = self.lock_path.stat()
            if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
                raise ValueError("round journal lock identity changed")
            yield
        finally:
            os.close(descriptor)

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Own one immediate writer transaction through commit, rollback and close.

        Callers must not commit, close or retain the supplied connection.
        """
        self._check_files()
        db = sqlite3.connect(self.path, isolation_level=None, timeout=5)
        try:
            db.create_function("umi_round_writer_generation", 0, lambda: 2)
            db.execute("PRAGMA synchronous=FULL")
            db.execute(f"PRAGMA max_page_count={(self.maximum_bytes + 16 * 1024**2) // 4096}")
            db.execute("BEGIN IMMEDIATE")
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
            initial_tables = self._table_names(db)
            if version == 2:
                self._fence_tables(db)
            yield db
            if db.execute("PRAGMA user_version").fetchone()[0] == 2:
                self._fence_tables(db, new_tables=self._table_names(db) - initial_tables)
            db.commit()
        except BaseException:
            db.rollback()
            raise
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
                if offset >= self.maximum_rounds * 80:
                    raise ValueError("round reservation batch capacity exhausted")
                self._decode_obligation(row)
        finally:
            cursor.close()
        count, used = db.execute(
            "SELECT COUNT(*),COALESCE(SUM(LENGTH(body)),0) FROM records"
        ).fetchone()
        kinds = dict(db.execute("SELECT kind,COUNT(*) FROM records GROUP BY kind"))
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
        if count > self.maximum_rounds * 80 or used > self.maximum_bytes:
            raise ValueError("round journal capacity exhausted")

    def reserve_records(
        self, batch_id: str, specs: Iterable[RecordReservation]
    ) -> dict[str, str | int] | None:
        """Atomically enable reservations and retain a complete private batch.

        Callers bind semantic identities in their admission manifest. A future
        value may omit its hash; its first immutable write still has to fit the
        reserved bound. No records are published and no signing occurs here.
        This reserves logical journal capacity, not disk space or other stores.
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
        with self.transaction() as db:
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
                    or (
                        doc["value_sha256"] is not None
                        and sha256_hex(retained) != doc["value_sha256"]
                    )
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
                or not 1024 <= identity_["maximum_bytes"] <= 16 * 1024**3
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
        with self.transaction() as db:
            if db.execute("PRAGMA user_version").fetchone()[0] != 2:
                return None
            return self._reservation(db, batch_id)

    def put(self, kind: str, key: str, value: object) -> None:
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
                if len(raw) > MAX_BYTES:
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
                        count, used = db.execute(
                            "SELECT COUNT(*),COALESCE(SUM(LENGTH(body)),0) FROM records"
                        ).fetchone()
                        kinds = dict(db.execute("SELECT kind,COUNT(*) FROM records GROUP BY kind"))
                extra_count = 0 if obligation is not None else 1
                extra_bytes = len(raw) - (obligation[0] if obligation is not None else 0)
                if kind in {"plan", "prepared", "intent", "suite", "certificate"} and (
                    kinds.get(kind, 0) + extra_count > self.maximum_rounds
                ):
                    capacity_error = "round journal record capacity exhausted"
                elif (
                    used + extra_bytes > self.maximum_bytes
                    or count + extra_count > self.maximum_rounds * 80
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

    @staticmethod
    def _record(db, kind, key):
        size = db.execute(
            "SELECT length(body) FROM records WHERE kind=? AND id=?", (kind, key)
        ).fetchone()
        if size is None:
            return None
        if type(size[0]) is not int or not 1 <= size[0] <= MAX_BYTES:
            raise ValueError("retained round object exceeds its byte bound")
        row = db.execute("SELECT body FROM records WHERE kind=? AND id=?", (kind, key)).fetchone()
        raw = bytes(row[0])
        if not is_canonical_json(raw):
            raise ValueError("retained round object is not canonical")
        return raw

    def get(self, kind: str, key: str, *, db: sqlite3.Connection | None = None) -> JsonValue:
        """Read canonical JSON, borrowing this journal's transaction when supplied.

        A borrowed connection remains owned by the caller. None represents
        either an absent record or a retained JSON null.
        """
        if db is None:
            with self.transaction() as db:
                return self.get(kind, key, db=db)
        if db.execute("SELECT 1 FROM holds WHERE id=?", (key,)).fetchone():
            raise ValueError("round journal conflict held")
        raw = self._record(db, kind, key)
        return json.loads(raw) if raw is not None else None

    def keys(self, kind: str) -> list[str]:
        with self.transaction() as db:
            rows = db.execute(
                "SELECT id FROM records WHERE kind=? ORDER BY id LIMIT ?",
                (kind, self.maximum_rounds + 1),
            ).fetchall()
        if len(rows) > self.maximum_rounds:
            raise ValueError("round journal record limit")
        return [row[0] for row in rows]

    def observe(self, block: int) -> None:
        with self.transaction() as db:
            old = db.execute("SELECT block FROM highwater LIMIT 2").fetchall()
            if (
                type(block) is not int
                or not 0 <= block <= 2**53 - 1
                or (old and (len(old) != 1 or old[0][0] > block))
            ):
                raise ValueError("round finalized head regressed")
            db.execute("DELETE FROM highwater")
            db.execute("INSERT INTO highwater VALUES (?)", (block,))
            if db.execute("PRAGMA user_version").fetchone()[0] == 2:
                self._check_capacity(db)

    def due_plans(self, block: int) -> list[str]:
        """Return at most four unprepared suite identities due at this block."""
        with self.transaction() as db:
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
        with self.transaction() as db:
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
        with self.transaction() as db:
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
