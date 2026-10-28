"""Durable local retention projections, never registration or payout authority.

Original record mutations advance SQL identities in the same commit. Completed
per-record projections survive restart; an unchanged lookup reads small metadata
and current conflict holds, never the original model or admission body.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from contextlib import contextmanager

from .competition_transport_verification import TransferProgress
from .competition_verification_rules import runtime_identity
from .open_competition import digest
from .private_files import PrivateStateBusyError
from .protocol import canonical_json_bytes

ABI = "umi-service-registration-pin-projection/1"
KINDS = ("service_catalog", "service_catalog_round", "service_round", "service_admission")

TABLES = {
    "registration_pin_sources": "CREATE TABLE registration_pin_sources(kind TEXT,id TEXT,"
    "revision INTEGER NOT NULL,present INTEGER NOT NULL,PRIMARY KEY(kind,id))",
    "registration_pin_index": "CREATE TABLE registration_pin_index("
    "id TEXT PRIMARY KEY,result TEXT NOT NULL)",
    "registration_pin_state": "CREATE TABLE registration_pin_state(owner TEXT NOT NULL)",
}


class RegistrationPinProjectionPending(OSError):
    """A bounded first/changed projection pass retained its completed items."""

    def __init__(self, completed, total, reason="bounded_projection"):
        self.completed, self.total, self.reason = completed, total, reason
        super().__init__("registration pin projection continues from retained items: " + reason)


class RegistrationPinRepairRequired(ValueError):
    """Retained pin metadata is damaged, rather than an ordinary cache miss."""


def _triggers():
    kinds = ",".join("'" + kind + "'" for kind in KINDS)
    values = {}
    for action in ("INSERT", "UPDATE", "DELETE"):
        row = "OLD" if action == "DELETE" else "NEW"
        name = "registration_pin_source_" + action.lower()
        values[name] = (
            f"CREATE TRIGGER {name} AFTER {action} ON records WHEN {row}.kind IN ({kinds}) "
            "BEGIN INSERT INTO registration_pin_sources(kind,id,revision,present) "
            f"VALUES({row}.kind,{row}.id,1,{int(action != 'DELETE')}) "
            "ON CONFLICT(kind,id) DO UPDATE SET revision=revision+1,"
            f"present={int(action != 'DELETE')}; END"
        )
    values["registration_pin_source_rekey"] = (
        "CREATE TRIGGER registration_pin_source_rekey AFTER UPDATE ON records "
        f"WHEN OLD.kind IN ({kinds}) AND (OLD.kind!=NEW.kind OR OLD.id!=NEW.id) "
        "BEGIN UPDATE registration_pin_sources SET revision=revision+1,present=0 "
        "WHERE kind=OLD.kind AND id=OLD.id; END"
    )
    return values


class RegistrationPins:
    def __init__(self, journal, binding, *, repair_reason=None):
        self.journal = journal
        self.binding = dict(binding)
        self.identity = self._identity()
        self.owner = digest(
            {"binding": binding, "path": str(journal.root), "identity": self.identity}
        )
        self.storage_owner = self.owner
        self.semantics = digest([ABI, runtime_identity()])
        self.marker = {"schema": ABI, "owner": self.owner, "storage_owner": self.storage_owner}
        self.installed = {"schema": ABI, "binding": digest(binding)}
        self.triggers = _triggers()
        if repair_reason is not None:
            self._repair(repair_reason)
            return
        with journal.read_transaction() as db:
            marker = self._get("registration_pin_installed", "installed", db)
            remnants = db.execute(
                "SELECT 1 FROM sqlite_master WHERE name GLOB 'registration_pin_*' LIMIT 1"
            ).fetchone()
            if marker is not None or remnants:
                try:
                    state = db.execute(
                        "SELECT owner FROM registration_pin_state LIMIT 2"
                    ).fetchall()
                    if len(state) != 1:
                        raise RegistrationPinRepairRequired("registration pin owner state changed")
                    self.owner = state[0][0]
                    self.marker = {
                        "schema": ABI,
                        "owner": self.owner,
                        "storage_owner": self.storage_owner,
                    }
                except sqlite3.DatabaseError as error:
                    raise RegistrationPinRepairRequired(
                        "registration pin metadata requires repair"
                    ) from error
                self.check_schema(db)
                return

        def initialize(db):
            if db.execute(
                "SELECT 1 FROM sqlite_master WHERE name GLOB 'registration_pin_*' LIMIT 1"
            ).fetchone():
                self.check_schema(db)
                return
            total = sum(
                db.execute("SELECT COUNT(*) FROM records WHERE kind=?", (kind,)).fetchone()[0]
                for kind in KINDS
            )
            with TransferProgress(
                "registration_pin_source_migration",
                total,
                unit="records",
                planning_unit_seconds=(0.00001, 0.01),
            ) as progress:
                for sql in TABLES.values():
                    db.execute(sql)
                db.execute("INSERT INTO registration_pin_state VALUES (?)", (self.owner,))
                for kind in KINDS:
                    added = db.execute(
                        "INSERT INTO registration_pin_sources SELECT kind,id,0,1 FROM records "
                        "WHERE kind=?",
                        (kind,),
                    ).rowcount
                    progress.advance(added)
                for sql in self.triggers.values():
                    db.execute(sql)

            self._capacity(db)

        journal.put_many(
            (
                ("registration_pin_installed", "installed", self.installed),
                ("registration_pin_owner", self.owner, self.marker),
            ),
            index=initialize,
        )
        with journal.read_transaction() as db:
            self.check_schema(db)

    @contextmanager
    def snapshot(self):
        try:
            with self.journal.read_transaction(wait=False) as db:
                yield db
        except sqlite3.OperationalError as error:
            if getattr(error, "sqlite_errorcode", None) in (
                sqlite3.SQLITE_BUSY,
                sqlite3.SQLITE_LOCKED,
            ):
                raise PrivateStateBusyError(
                    "registration_pin_snapshot",
                    digest(str(self.journal.path)),
                    error.sqlite_errorcode,
                ) from error
            raise

    def _identity(self):
        return [
            [s.st_dev, s.st_ino, s.st_uid]
            for s in (self.journal.root.stat(), self.journal.path.stat())
        ]

    def _get(self, kind, key, db):
        try:
            return self.journal.get(kind, key, db=db)
        except ValueError as error:
            raise RegistrationPinRepairRequired(
                "registration pin metadata invalid or conflict held"
            ) from error

    def check_schema(self, db, *, capacity=True):
        try:
            if (
                self._identity() != self.identity
                or self._get("registration_pin_owner", self.owner, db) != self.marker
                or self._get("registration_pin_installed", "installed", db) != self.installed
                or db.execute("SELECT owner FROM registration_pin_state LIMIT 2").fetchall()
                != [(self.owner,)]
            ):
                raise RegistrationPinRepairRequired("registration pin original owner changed")
            actual = dict(
                db.execute(
                    "SELECT name,sql FROM sqlite_master WHERE type='trigger' "
                    "AND name GLOB 'registration_pin_source_*'"
                )
            )
            if actual != self.triggers:
                raise RegistrationPinRepairRequired("registration pin mutation fences changed")
            actual_tables = dict(
                db.execute(
                    "SELECT name,sql FROM sqlite_master WHERE type='table' "
                    "AND name GLOB 'registration_pin_*'"
                )
            )
            if actual_tables != TABLES:
                raise RegistrationPinRepairRequired("registration pin metadata schema changed")
            if capacity:
                self._capacity(db)
        except sqlite3.DatabaseError as error:
            raise RegistrationPinRepairRequired(
                "registration pin metadata requires repair"
            ) from error

    def _capacity(self, db):
        # v2 journals include every auxiliary table in their native allowance.
        if self.journal._version(db) == 2:
            # The ordinary writer checks the complete reservation budget after
            # its index callback. Reading it again here would rescan obligations.
            return
        count, size, _ = self.journal._record_capacity(db)
        for name in (
            "registration_pin_sources",
            "registration_pin_index",
            "registration_pin_state",
        ):
            columns = [row[1] for row in db.execute(f"PRAGMA table_info({name})")]
            if not columns:
                raise RegistrationPinRepairRequired("registration pin metadata missing")
            lengths = "+".join(self.journal._stored_byte_length(c) for c in columns)
            rows, used = db.execute(
                f"SELECT COUNT(*),COALESCE(SUM({lengths}),0) FROM {name}"
            ).fetchone()
            count += rows
            size += used
        if count > self.journal.maximum_records or size > self.journal.maximum_bytes:
            raise RegistrationPinRepairRequired("registration pin metadata capacity exhausted")

    def _repair(self, reason):
        if not isinstance(reason, str) or not 1 <= len(reason) <= 1024:
            raise ValueError("registration pin repair requires an explicit bounded reason")
        with self.journal.locked(), self.journal.transaction() as db:
            installed = self._get("registration_pin_installed", "installed", db)
            if installed is not None and installed != self.installed:
                raise RegistrationPinRepairRequired("registration pin repair has another binding")
            tables = self.journal._table_names(db)
            prior = {}
            for table in (
                "registration_pin_sources",
                "registration_pin_index",
                "registration_pin_state",
            ):
                if table in tables:
                    prior[table] = [list(row) for row in db.execute(f"SELECT * FROM {table}")]
            states = prior.get("registration_pin_state", [])
            old_owner = states[0][0] if len(states) == 1 and len(states[0]) == 1 else None
            old_marker = (
                None if old_owner is None else self._get("registration_pin_owner", old_owner, db)
            )
            original_sources = dict(
                db.execute(
                    "SELECT name,sql FROM sqlite_master WHERE type='trigger' "
                    "AND name GLOB 'registration_pin_source_*'"
                )
            )
            sources_trusted = (
                dict(db.execute("SELECT name,sql FROM sqlite_master WHERE type='table'")).get(
                    "registration_pin_sources"
                )
                == TABLES["registration_pin_sources"]
                and original_sources == self.triggers
                and old_marker
                == {"schema": ABI, "owner": old_owner, "storage_owner": self.storage_owner}
            )
            damaged_sources = []
            if sources_trusted:
                try:
                    live = {
                        (kind, key)
                        for kind, key in db.execute(
                            "SELECT kind,id FROM records WHERE kind IN (?,?,?,?)", KINDS
                        )
                    }
                    known = {}
                    for kind, key, revision, present in db.execute(
                        "SELECT kind,id,revision,present FROM registration_pin_sources"
                    ):
                        known[kind, key] = (revision, present)
                    damaged_sources = sorted(
                        key
                        for key in live | set(known)
                        if key not in known
                        or type(known[key][0]) is not int
                        or known[key][0] < 0
                        or known[key][1] != int(key in live)
                    )
                except sqlite3.DatabaseError:
                    sources_trusted = False
            if sources_trusted and not damaged_sources:
                self.owner, self.marker = old_owner, old_marker
                try:
                    self.check_schema(db)
                    catalog = self.load(db, "catalog", {"catalog": self.binding["catalog"]})
                    for row in db.execute("SELECT ordinal,claim_key,admission FROM service_claims"):
                        self.load(db, str(row[0]), {"row": list(row), "catalog": digest(catalog)})
                except (ValueError, sqlite3.DatabaseError):
                    pass
                else:
                    return
            audit = {
                "schema": "umi-registration-pin-repair/1",
                "reason": reason,
                "prior": prior,
                "storage_owner": self.storage_owner,
                "source_identity_preserved": sources_trusted,
                "damaged_sources": damaged_sources,
                "installed_reconstructed": installed is None,
            }
            if len(canonical_json_bytes(audit)) > self.journal.maximum_record_bytes:
                raise RegistrationPinRepairRequired(
                    "registration pin repair evidence exceeds capacity"
                )
            # Recover intact immutable results from their current native source
            # generations. Lost indices do not force original payload rereads.
            recovered = {}
            if sources_trusted:
                for (key,) in db.execute(
                    "SELECT id FROM records WHERE kind='registration_pin_result'"
                ):
                    try:
                        value = self._get("registration_pin_result", key, db)
                        if (
                            digest(value) != key
                            or value["owner"] != old_owner
                            or value["schema"] != ABI
                            or value["semantics"] != self.semantics
                            or set(value)
                            != {"schema", "owner", "semantics", "sources", "context", "result"}
                        ):
                            continue
                        keys = [(kind, source) for kind, source, _ in value["sources"]]
                        if self.sources(db, keys) != value["sources"]:
                            continue
                        context = value["context"]
                        if set(context) == {"catalog"}:
                            if context["catalog"] != self.binding["catalog"]:
                                continue
                            slot = "catalog"
                        elif set(context) == {"row", "catalog"}:
                            row = db.execute(
                                "SELECT ordinal,claim_key,admission FROM service_claims "
                                "WHERE ordinal=?",
                                (context["row"][0],),
                            ).fetchone()
                            if row is None or list(row) != context["row"]:
                                continue
                            slot = str(row[0])
                        else:
                            continue
                        if (
                            self.journal.get(
                                "registration_pin_completed", digest([old_owner, slot]), db=db
                            )
                            != old_marker
                        ):
                            continue
                        recovered[slot] = value
                    except (KeyError, TypeError, ValueError):
                        continue
            # The new namespace retains all original success/audit records. If
            # mutation metadata or the storage owner changed, only this explicit
            # repair permits a bounded first pass over affected originals.
            self.owner = digest([self.storage_owner, audit])
            self.marker = {"schema": ABI, "owner": self.owner, "storage_owner": self.storage_owner}
            for table in ("registration_pin_index", "registration_pin_state"):
                db.execute("DROP TABLE IF EXISTS " + table)
            for table in ("registration_pin_index", "registration_pin_state"):
                db.execute(TABLES[table])
            db.execute("INSERT INTO registration_pin_state VALUES (?)", (self.owner,))
            new_tables = {"registration_pin_index", "registration_pin_state"}
            if not sources_trusted:
                for name in self.triggers:
                    db.execute("DROP TRIGGER IF EXISTS " + name)
                db.execute("DROP TABLE IF EXISTS registration_pin_sources")
                db.execute(TABLES["registration_pin_sources"])
                new_tables.add("registration_pin_sources")
                total = sum(
                    db.execute("SELECT COUNT(*) FROM records WHERE kind=?", (k,)).fetchone()[0]
                    for k in KINDS
                )
                with TransferProgress(
                    "registration_pin_repair_sources",
                    total,
                    unit="records",
                    planning_unit_seconds=(0.00001, 0.01),
                ) as progress:
                    for kind in KINDS:
                        added = db.execute(
                            "INSERT INTO registration_pin_sources SELECT kind,id,0,1 "
                            "FROM records WHERE kind=?",
                            (kind,),
                        ).rowcount
                        progress.advance(added)
                    for sql in self.triggers.values():
                        db.execute(sql)
            elif damaged_sources:
                with TransferProgress(
                    "registration_pin_repair_sources",
                    len(damaged_sources),
                    unit="records",
                    planning_unit_seconds=(0.00001, 0.01),
                ) as progress:
                    for kind, key in damaged_sources:
                        present = (
                            db.execute(
                                "SELECT 1 FROM records WHERE kind=? AND id=?", (kind, key)
                            ).fetchone()
                            is not None
                        )
                        db.execute(
                            "INSERT INTO registration_pin_sources VALUES (?,?,0,?) "
                            "ON CONFLICT(kind,id) DO UPDATE SET "
                            "revision=0,present=excluded.present",
                            (kind, key, int(present)),
                        )
                        progress.advance(1)
            old_catalog = recovered.get("catalog")
            new_catalog = None if old_catalog is None else {**old_catalog, "owner": self.owner}
            with TransferProgress(
                "registration_pin_repair_results",
                len(recovered),
                unit="results",
                planning_unit_seconds=(0.001, 0.1),
            ) as progress:
                for slot, value in recovered.items():
                    if slot != "catalog" and (
                        old_catalog is None or value["context"]["catalog"] != digest(old_catalog)
                    ):
                        progress.advance(1)
                        continue
                    context = (
                        value["context"]
                        if slot == "catalog"
                        else {**value["context"], "catalog": digest(new_catalog)}
                    )
                    value = {**value, "owner": self.owner, "context": context}
                    key, identity = digest(value), digest([self.owner, slot])
                    for kind, record_key, body in (
                        ("registration_pin_result", key, value),
                        ("registration_pin_completed", identity, self.marker),
                    ):
                        db.execute(
                            "INSERT OR IGNORE INTO records VALUES (?,?,?)",
                            (kind, record_key, canonical_json_bytes(body)),
                        )
                    db.execute("INSERT INTO registration_pin_index VALUES (?,?)", (identity, key))
                    progress.advance(1, restored=True)
            for kind, key, body in (
                ("registration_pin_installed", "installed", self.installed),
                ("registration_pin_repair", digest(audit), audit),
                ("registration_pin_owner", self.owner, self.marker),
            ):
                db.execute(
                    "INSERT OR IGNORE INTO records VALUES (?,?,?)",
                    (kind, key, canonical_json_bytes(body)),
                )
            self._capacity(db)
            if self.journal._version(db) == 2:
                self.journal._fence_tables(db, new_tables=new_tables)
                self.journal._check_capacity(db)

    def sources(self, db, keys):
        result = []
        for kind, key in sorted(set(keys)):
            if kind not in KINDS:
                raise ValueError("unsupported registration pin source")
            row = db.execute(
                "SELECT revision,present FROM registration_pin_sources WHERE kind=? AND id=?",
                (kind, key),
            ).fetchone()
            present = db.execute(
                "SELECT 1 FROM records WHERE kind=? AND id=?", (kind, key)
            ).fetchone()
            held = db.execute("SELECT 1 FROM holds WHERE id=?", (key,)).fetchone()
            if row is None or row[1] != 1 or present is None or held:
                raise RegistrationPinRepairRequired(
                    "registration pin source missing or conflict held"
                )
            if type(row[0]) is not int or row[0] < 0:
                raise RegistrationPinRepairRequired("registration pin source revision changed")
            result.append([kind, key, row[0]])
        return result

    def load(self, db, slot, context):
        slot = digest([self.owner, slot])
        row = db.execute("SELECT result FROM registration_pin_index WHERE id=?", (slot,)).fetchone()
        seen = self._get("registration_pin_completed", slot, db)
        if row is None:
            if seen is not None:
                raise RegistrationPinRepairRequired("completed registration pin index is missing")
            return None
        if seen != self.marker:
            raise RegistrationPinRepairRequired("registration pin completion marker changed")
        value = self._get("registration_pin_result", row[0], db)
        if (
            not isinstance(value, dict)
            or digest(value) != row[0]
            or value.get("owner") != self.owner
        ):
            raise RegistrationPinRepairRequired("completed registration pin result is damaged")
        if set(value) != {"schema", "owner", "semantics", "sources", "context", "result"}:
            raise RegistrationPinRepairRequired("registration pin result fields changed")
        try:
            keys = [(kind, key) for kind, key, _ in value["sources"]]
            current = self.sources(db, keys)
        except (TypeError, KeyError) as error:
            raise RegistrationPinRepairRequired("registration pin dependencies changed") from error
        if value["schema"] != ABI:
            raise RegistrationPinRepairRequired("registration pin result schema changed")
        if (
            value["semantics"] != self.semantics
            or value["context"] != context
            or value["sources"] != current
        ):
            return None
        return value

    def require_complete_metadata(self, db, slots):
        """Refuse cold pruning without reading completed result bodies.

        This is only a negative readiness check. Presence never authorizes a
        retained block: a complete inventory still goes through load(), with
        its canonical bytes, current sources, semantics and context checks.
        The independent projection owner keeps its full validation/repair path.
        """
        expected = [(digest([self.owner, slot]), source) for slot, source in slots]
        marker = canonical_json_bytes(self.marker)
        present = 0
        # Two bindings per admission plus the small canonical marker; remain
        # below older supported SQLite's 999-variable limit as well.
        for offset in range(0, len(expected), 256):
            batch = expected[offset : offset + 256]
            rows = db.execute(
                "WITH expected(slot,source) AS (VALUES "
                + ",".join("(?,?)" for _ in batch)
                + ") SELECT i.id,c.id,"
                "CASE WHEN length(c.body)=? THEN c.body=? ELSE 0 END,"
                "r.id,length(r.body),hc.id,hr.id,s.revision,s.present,a.id,ha.id "
                "FROM expected e "
                "LEFT JOIN registration_pin_index i ON i.id=e.slot "
                "LEFT JOIN records c ON c.kind='registration_pin_completed' AND c.id=e.slot "
                "LEFT JOIN records r ON r.kind='registration_pin_result' AND r.id=i.result "
                "LEFT JOIN holds hc ON hc.id=e.slot "
                "LEFT JOIN holds hr ON hr.id=i.result "
                "LEFT JOIN registration_pin_sources s "
                "ON s.kind='service_admission' AND s.id=e.source "
                "LEFT JOIN records a ON a.kind='service_admission' AND a.id=e.source "
                "LEFT JOIN holds ha ON ha.id=e.source",
                (*[value for pair in batch for value in pair], len(marker), marker),
            ).fetchall()
            for (
                index,
                completed,
                marker_matches,
                body,
                size,
                held,
                result_held,
                revision,
                source_present,
                original,
                source_held,
            ) in rows:
                if held or result_held:
                    raise RegistrationPinRepairRequired(
                        "registration pin metadata invalid or conflict held"
                    )
                if index is None:
                    if completed is not None:
                        raise RegistrationPinRepairRequired(
                            "completed registration pin index is missing"
                        )
                    continue
                if completed is None or marker_matches != 1:
                    raise RegistrationPinRepairRequired(
                        "registration pin completion marker changed"
                    )
                if body is None or type(size) is not int or size <= 0:
                    raise RegistrationPinRepairRequired(
                        "completed registration pin result is damaged"
                    )
                if original is None or source_present != 1 or source_held:
                    raise RegistrationPinRepairRequired(
                        "registration pin source missing or conflict held"
                    )
                if type(revision) is not int or revision < 0:
                    raise RegistrationPinRepairRequired("registration pin source revision changed")
                present += 1
        if present != len(expected):
            # These are retained metadata entries, not freshly validated pins.
            # The reason distinguishes this count from the full projection pass.
            raise RegistrationPinProjectionPending(
                present,
                len(expected),
                "projection_metadata_incomplete" if present else "bounded_projection",
            )

    def make(self, db, keys, context, result):
        return dict(
            schema=ABI,
            owner=self.owner,
            semantics=self.semantics,
            sources=self.sources(db, keys),
            context=context,
            result=result,
        )

    def remember(self, slot, value, check: Callable):
        slot = digest([self.owner, slot])
        key = digest(value)

        def publish(db):
            self.check_schema(db)
            keys = [(kind, source) for kind, source, _ in value["sources"]]
            if self.sources(db, keys) != value["sources"]:
                raise RegistrationPinProjectionPending(0, 1, "source_changed_before_checkpoint")
            check(db)
            db.execute(
                "INSERT INTO registration_pin_index VALUES (?,?) "
                "ON CONFLICT(id) DO UPDATE SET result=excluded.result",
                (slot, key),
            )
            self._capacity(db)

        if not self.journal._transaction_lock.acquire(blocking=False):
            raise PrivateStateBusyError(
                "registration_pin_writer", digest(str(self.journal.path)), None
            )
        try:
            self.journal.put_many(
                (
                    ("registration_pin_result", key, value),
                    ("registration_pin_completed", slot, self.marker),
                ),
                index=publish,
            )
        except sqlite3.OperationalError as error:
            if getattr(error, "sqlite_errorcode", None) in (
                sqlite3.SQLITE_BUSY,
                sqlite3.SQLITE_LOCKED,
            ):
                raise PrivateStateBusyError(
                    "registration_pin_writer",
                    digest(str(self.journal.path)),
                    error.sqlite_errorcode,
                ) from error
            raise RegistrationPinRepairRequired(
                "registration pin checkpoint storage unavailable"
            ) from error
        except (OSError, ValueError) as error:
            if isinstance(error, (RegistrationPinProjectionPending, RegistrationPinRepairRequired)):
                raise
            raise RegistrationPinRepairRequired(
                "registration pin checkpoint write failed: " + str(error)
            ) from error
        finally:
            self.journal._transaction_lock.release()
