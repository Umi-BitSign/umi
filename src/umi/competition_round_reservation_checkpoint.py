"""Durable native validation of append-only v2 reservation metadata.

This is not capacity accounting: callers still execute the original SQL sums.
Only successful canonical-body/typed-column validation is reused. The initial
rowid scan has a retained ceiling; an insert trigger tracks additions anywhere
in the signed 64-bit rowid range, including behind the retained cursor.
"""

from __future__ import annotations

import logging
import sqlite3
import time

from .competition_verification_rules import runtime_identity
from .protocol import canonical_json_bytes, sha256_hex

logger = logging.getLogger(__name__)
ABI = "umi-native-reservation-validation/1"
CHUNK_SIZE = 4096
PREFIX = "round_reservation_validation"
STATE = PREFIX + "_state"
PENDING = PREFIX + "_pending"
MARKER_KIND, MARKER_ID = "reservation-validation", "native-v1"
MARKER = canonical_json_bytes({"schema": ABI})
SCHEMA = {
    STATE: f"CREATE TABLE {STATE} (id INTEGER PRIMARY KEY CHECK(id=1), "
    "dependency TEXT NOT NULL, schema_epoch BLOB NOT NULL, ceiling INTEGER, cursor INTEGER, "
    "observed INTEGER NOT NULL, validated INTEGER NOT NULL, complete INTEGER NOT NULL, "
    "started INTEGER NOT NULL)",
    PENDING: f"CREATE TABLE {PENDING} (kind TEXT NOT NULL, id TEXT NOT NULL, "
    "source_rowid INTEGER NOT NULL, PRIMARY KEY(kind,id))",
    PREFIX + "_insert": f"CREATE TRIGGER {PREFIX}_insert AFTER INSERT ON record_reservations "
    f"BEGIN INSERT INTO {PENDING} VALUES (NEW.kind,NEW.id,NEW.rowid); "
    f"UPDATE {STATE} SET observed=observed+1 WHERE id=1; "
    "SELECT CASE WHEN changes()!=1 THEN RAISE(ABORT,'reservation validation repair required') "
    "END; END",
    PREFIX + "_replace": f"CREATE TRIGGER {PREFIX}_replace BEFORE INSERT ON record_reservations "
    "WHEN NOT (SELECT recursive_triggers FROM pragma_recursive_triggers) "
    "AND EXISTS(SELECT 1 FROM record_reservations "
    "WHERE (kind=NEW.kind AND id=NEW.id) OR rowid=NEW.rowid) "
    "BEGIN SELECT RAISE(ABORT,'round reservation replacement requires recursive triggers'); END",
}


class ReservationValidationRepairRequired(ValueError):
    """Retained successful validation cannot safely be reused."""


def progress(state, completed=0, total=None, started=None):
    elapsed = max(0.0, time.time() - started) if started else 0.0
    rate = completed / elapsed if completed and elapsed else None
    logger.info(
        "round_journal_progress %s",
        dict(
            stage="reservation_validation",
            state=state,
            completed_records=completed,
            total_records=total,
            elapsed_seconds=elapsed,
            percent=100.0 * completed / total if total else 100.0 if total == 0 else None,
            eta_seconds=(total - completed) / rate
            if rate and total is not None and state != "repair_required"
            else None,
            planning_eta_seconds=[total / 10000, total / 100]
            if total and not rate and state != "repair_required"
            else None,
            eta_basis="measured_metadata_records_per_second"
            if rate
            else "planning_assumption_100_to_10000_metadata_records_per_second",
            stalled_or_retrying=state in {"repair_required", "retrying"},
        ),
    )


def damage(reason):
    progress("repair_required")
    raise ReservationValidationRepairRequired("reservation validation repair required: " + reason)


def dependency(journal, db):
    identity = journal._bounded_blob(db, "record_reservation_identity", "body", maximum=65536)
    return sha256_hex(
        canonical_json_bytes(
            {
                "abi": ABI,
                "runtime": runtime_identity(),
                **journal._binding(db),
                "identity": sha256_hex(identity or b""),
            }
        )
    )


def installed(db):
    if db.execute("PRAGMA user_version").fetchone()[0] != 2:
        return False
    marker = db.execute(
        "SELECT CASE WHEN TYPEOF(body)='blob' AND LENGTH(body)=? THEN body END "
        "FROM records WHERE kind=? AND id=?",
        (len(MARKER), MARKER_KIND, MARKER_ID),
    ).fetchone()
    retained = dict(
        db.execute("SELECT name,sql FROM sqlite_master WHERE name GLOB ?", (PREFIX + "*",))
    )
    if not marker and not retained:
        return False
    if (
        marker != (MARKER,)
        or set(retained) != set(SCHEMA)
        or any(
            " ".join(retained[name].split()) != " ".join(sql.split())
            for name, sql in SCHEMA.items()
        )
    ):
        damage("installation marker or schema missing or changed")
    return True


def check(journal, db, *, trusted_epoch=False):
    if not installed(db):
        return None
    rows = db.execute(f"SELECT * FROM {STATE} LIMIT 2").fetchall()
    if len(rows) != 1:
        damage("checkpoint missing")
    ident, binding, epoch, ceiling, cursor, observed, validated, complete, started = rows[0]
    if (
        ident != 1
        or binding != dependency(journal, db)
        or any(type(v) is not int for v in (ident, observed, validated, complete, started))
        or any(v is not None and type(v) is not int for v in (ceiling, cursor))
        # Count integrity follows SQLite's integer range. Native journal
        # subclasses enforce their own capacity after validation; service
        # reviewers can retain more obligations than the ordinary round cap.
        or not 0 <= validated <= observed <= 2**63 - 1
        or complete not in (0, 1)
        or type(epoch) is not bytes
        or len(epoch) != 8
        or started <= 0
        or (cursor is not None and (ceiling is None or cursor > ceiling))
    ):
        damage("checkpoint or validation dependency changed")
    if not trusted_epoch and epoch != schema_epoch(db):
        damage("schema epoch changed; source fences require native revalidation")
    source_count = db.execute("SELECT COUNT(*) FROM record_reservations").fetchone()[0]
    pending = db.execute(f"SELECT COUNT(*) FROM {PENDING}").fetchone()[0]
    absent = db.execute(
        f"SELECT 1 FROM {PENDING} p LEFT JOIN record_reservations r "
        "ON r.kind=p.kind AND r.id=p.id AND r.rowid=p.source_rowid "
        "WHERE r.rowid IS NULL LIMIT 1"
    ).fetchone()
    remaining = 0
    if not complete and ceiling is not None:
        remaining = db.execute(
            "SELECT COUNT(*) FROM record_reservations r WHERE r.rowid<=? "
            "AND (? IS NULL OR r.rowid>?) AND NOT EXISTS "
            f"(SELECT 1 FROM {PENDING} p WHERE p.kind=r.kind AND p.id=r.id)",
            (ceiling, cursor, cursor),
        ).fetchone()[0]
    if source_count != observed or absent or observed - validated != pending + remaining:
        damage("source, pending keys and completed count disagree")
    return rows[0]


def initialize(journal, db):
    if installed(db):
        return
    for sql in SCHEMA.values():
        db.execute(sql)
    count, ceiling = db.execute("SELECT COUNT(*),MAX(rowid) FROM record_reservations").fetchone()
    db.execute(
        f"INSERT INTO {STATE} VALUES (1,?,?,?,NULL,?,0,?,?)",
        (
            dependency(journal, db),
            schema_epoch(db),
            ceiling,
            count,
            int(count == 0),
            int(time.time()),
        ),
    )
    db.execute("INSERT INTO records VALUES (?,?,?)", (MARKER_KIND, MARKER_ID, MARKER))
    journal._fence_tables(db, new_tables={STATE, PENDING})
    bind_epoch(db)
    db.set_authorizer(authorizer(journal))
    journal._check_capacity_totals(db)
    progress("running", 0, count, time.time())


def bind_epoch(db):
    # Fixed-width metadata preserves the caller's final capacity check when
    # unrelated native DDL advances the schema epoch before commit.
    epoch = schema_epoch(db)
    db.execute(
        f"UPDATE {STATE} SET schema_epoch=? WHERE id=1 AND schema_epoch!=?",
        (epoch, epoch),
    )


def schema_epoch(db):
    return db.execute("PRAGMA schema_version").fetchone()[0].to_bytes(8, "big", signed=True)


def authorizer(journal):
    protected = {"record_reservations", "record_reservation_identity", STATE, PENDING}

    def authorize(action, first, second, database, trigger):
        if journal.physical_budget is not None:
            result = journal.physical_budget._authorize(action, first, second, database, trigger)
            if result != sqlite3.SQLITE_OK:
                return result
        if (
            (action == sqlite3.SQLITE_DROP_TABLE and first in protected)
            or (action == sqlite3.SQLITE_ALTER_TABLE and second in protected)
            or (
                action == sqlite3.SQLITE_DROP_TRIGGER
                and (second in protected or first.startswith(PREFIX))
            )
            or (
                action == sqlite3.SQLITE_PRAGMA
                and second is not None
                and first.lower()
                in {
                    "writable_schema",
                    "schema_version",
                    "recursive_triggers",
                    "user_version",
                    "application_id",
                }
            )
        ):
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    return authorize


def advance(journal, db, columns, *, initial=False, readonly=False):
    pass_started = time.time()
    state = check(journal, db, trusted_epoch=not readonly)
    if state is None:
        return False
    _, _, _, ceiling, cursor, observed, validated, complete, started = state
    if complete and observed == validated:
        return True
    if not complete:
        if not initial:
            damage("initial native validation incomplete; resume with a mutable owner")
        rows = db.execute(
            f"SELECT rowid,{columns} FROM record_reservations WHERE rowid<=? "
            "AND (? IS NULL OR rowid>?) ORDER BY rowid LIMIT ?",
            (ceiling, cursor, cursor, CHUNK_SIZE),
        )
    else:
        # The key/rowid index includes old-writer inserts below the scan ceiling.
        # Readonly receipts validate only these additions, without claiming a
        # reusable completion or acquiring the writer held by another process.
        rows = db.execute(
            f"SELECT rowid,{columns} FROM record_reservations WHERE rowid IN "
            f"(SELECT source_rowid FROM {PENDING}) ORDER BY rowid"
            + (" LIMIT ?" if initial else ""),
            (CHUNK_SIZE,) if initial else (),
        )
    consumed = 0
    last = cursor
    try:
        while batch := rows.fetchmany(CHUNK_SIZE):
            for rowid, *row in batch:
                journal._decode_obligation(row)
                if not readonly:
                    db.execute(f"DELETE FROM {PENDING} WHERE kind=? AND id=?", (row[0], row[1]))
                consumed += 1
                last = rowid
    finally:
        rows.close()
    if readonly:
        progress("readonly_pending_not_retained", consumed, observed - validated, pass_started)
        return True
    if not complete:
        cursor = last
        complete = int(consumed < CHUNK_SIZE or cursor == ceiling)
    db.execute(
        f"UPDATE {STATE} SET cursor=?,validated=validated+?,complete=? WHERE id=1",
        (
            cursor,
            consumed,
            complete,
        ),
    )
    progress(
        "completed" if complete and validated + consumed == observed else "running",
        validated + consumed,
        observed,
        started,
    )
    return True
