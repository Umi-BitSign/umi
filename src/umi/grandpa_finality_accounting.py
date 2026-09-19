"""Transactional evidence accounting for the private finality store.

Database triggers keep older, already-open writers accounted for. Startup still
replays the authoritative history and compares the derived usage to this index.
Installing the index requires an audited snapshot inside the same write
transaction; missing or altered installed objects must never be rebuilt silently.
"""

from __future__ import annotations

import sqlite3

_KEY = "evidence_accounting_v1"
_MARKER = b"umi-grandpa-evidence-accounting/1"
_TABLE = "finality_evidence_accounting"
_TABLE_SQL = f"""CREATE TABLE {_TABLE} (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    header_count INTEGER NOT NULL
        CHECK(typeof(header_count) = 'integer' AND header_count >= 0),
    evidence_bytes INTEGER NOT NULL
        CHECK(typeof(evidence_bytes) = 'integer' AND evidence_bytes >= 0)
)"""


def _trigger(name: str, event: str, count: str, size: str) -> str:
    return f"""CREATE TRIGGER {name} AFTER {event} ON finalized_headers
BEGIN
    UPDATE {_TABLE} SET header_count = header_count {count},
        evidence_bytes = evidence_bytes {size} WHERE singleton = 1;
    SELECT CASE WHEN changes() != 1
        THEN RAISE(ABORT, 'finality evidence accounting row missing') END;
END"""


_OBJECTS = {
    _TABLE: ("table", _TABLE_SQL),
    "finality_evidence_insert": (
        "trigger",
        _trigger("finality_evidence_insert", "INSERT", "+ 1", "+ length(NEW.canonical_evidence)"),
    ),
    "finality_evidence_delete": (
        "trigger",
        _trigger("finality_evidence_delete", "DELETE", "- 1", "- length(OLD.canonical_evidence)"),
    ),
    "finality_evidence_update": (
        "trigger",
        _trigger(
            "finality_evidence_update",
            "UPDATE OF canonical_evidence",
            "+ 0",
            "+ length(NEW.canonical_evidence) - length(OLD.canonical_evidence)",
        ),
    ),
}


class AccountingError(ValueError):
    """The installed private accounting index is missing or inconsistent."""


def read_usage(
    connection: sqlite3.Connection, *, allow_missing: bool = False
) -> tuple[int, int] | None:
    """Read bounded scalar usage after checking the installed schema and marker.

    ``allow_missing`` is only for a legacy schema during migration. The caller
    owns a consistent transaction for this check and its subsequent operation.
    No evidence rows are visited here.
    """
    marker = connection.execute("SELECT value FROM store_meta WHERE key = ?", (_KEY,)).fetchone()
    placeholders = ",".join("?" for _ in _OBJECTS)
    objects = {
        row[0]: (row[1], row[2])
        for row in connection.execute(
            f"SELECT name,type,sql FROM sqlite_master WHERE name IN ({placeholders})",
            tuple(_OBJECTS),
        )
    }
    if not objects and marker is None and allow_missing:
        return None
    if marker is None or marker[0] != _MARKER or objects != _OBJECTS:
        raise AccountingError("evidence accounting schema differs")
    row = connection.execute(
        f"SELECT header_count,evidence_bytes FROM {_TABLE} WHERE singleton = 1"
    ).fetchone()
    if row is None or any(type(value) is not int or value < 0 for value in row):
        raise AccountingError("evidence accounting row differs")
    return row[0], row[1]


def install_accounting(connection: sqlite3.Connection, usage: tuple[int, int]) -> None:
    """Install counters from the caller's audited, write-locked legacy snapshot."""
    if not connection.in_transaction:
        raise ValueError("evidence accounting installation requires a transaction")
    if len(usage) != 2 or any(type(value) is not int or value < 0 for value in usage):
        raise ValueError("evidence accounting requires nonnegative integer usage")
    if read_usage(connection, allow_missing=True) is not None:
        raise AccountingError("evidence accounting already installed")
    connection.execute(_TABLE_SQL)
    connection.execute(f"INSERT INTO {_TABLE} VALUES (1,?,?)", usage)
    for kind, statement in _OBJECTS.values():
        if kind == "trigger":
            connection.execute(statement)
    connection.execute("INSERT INTO store_meta(key,value) VALUES (?,?)", (_KEY, _MARKER))
