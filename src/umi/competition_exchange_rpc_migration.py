"""Monotonic exchange proof-transport additions; no delivery-history reset.

The selected native config authorizes one absent -> exactly two backup addition.
Retain its exact old/new bindings, protect old writers with SQLite fences, and
allow subsequent independently authorized policy/launch changes to coexist.
"""

from __future__ import annotations

import json

from .competition_chain import CompetitionChainConfig
from .private_files import MAX_PRIVATE_BYTES
from .protocol import canonical_json_bytes

TABLE = "exchange_rpc_transport_changes"
TABLE_SQL = (
    f"CREATE TABLE {TABLE} (sequence INTEGER PRIMARY KEY, "
    "previous BLOB NOT NULL, current BLOB NOT NULL)"
)
_WRITER_TABLES = ("binding", "events", "audience", "collected", "highwater", TABLE)


def validate_rpc_addition(previous: bytes, current: bytes) -> None:
    old, new = json.loads(previous), json.loads(current)
    if canonical_json_bytes(old) != previous or canonical_json_bytes(new) != current:
        raise ValueError("exchange RPC binding is not canonical")
    before, after = old.get("chain"), new.get("chain")
    if not isinstance(before, dict) or not isinstance(after, dict):
        raise ValueError("exchange RPC migration requires a bound chain")
    backups = after.get("proof_rpc_fallback_urls")
    if (
        "proof_rpc_fallback_urls" in before
        or not isinstance(backups, list)
        or len(backups) != 2
        or any(type(value) is not str for value in backups)
        or len(set(backups)) != 2
        or {**before, "proof_rpc_fallback_urls": backups} != after
        or {**old, "chain": after} != new
    ):
        raise ValueError("exchange configuration changed beyond two backup RPC additions")
    CompetitionChainConfig.model_validate_json(canonical_json_bytes(after))


def rpc_fences() -> dict[str, str]:
    fences = {}
    for table in _WRITER_TABLES:
        for operation in ("INSERT", "UPDATE", "DELETE"):
            name = f"exchange_rpc_writer_{table}_{operation.lower()}"
            fences[name] = (
                f"CREATE TRIGGER {name} BEFORE {operation} ON {table} "
                "BEGIN SELECT CASE WHEN umi_exchange_rpc_writer("
                "(SELECT body FROM binding)) IS NOT 1 "
                "THEN RAISE(ABORT,'stale exchange RPC writer') END; END"
            )
    for operation in ("UPDATE", "DELETE"):
        name = f"exchange_rpc_immutable_{operation.lower()}"
        fences[name] = (
            f"CREATE TRIGGER {name} BEFORE {operation} ON {TABLE} "
            "BEGIN SELECT RAISE(ABORT,'immutable exchange RPC migration'); END"
        )
    fences["exchange_rpc_single_addition"] = (
        f"CREATE TRIGGER exchange_rpc_single_addition BEFORE INSERT ON {TABLE} "
        f"WHEN EXISTS(SELECT 1 FROM {TABLE}) OR NEW.sequence != 1 "
        "BEGIN SELECT RAISE(ABORT,'exchange RPC addition already retained'); END"
    )
    return fences


def check_rpc_history(db) -> bool:
    objects = dict(
        db.execute("SELECT name,sql FROM sqlite_master WHERE type IN ('table','trigger')")
    )
    if TABLE not in objects:
        if any(name.startswith("exchange_rpc_") for name in objects):
            raise ValueError("exchange RPC history marker missing")
        return False
    if objects[TABLE] != TABLE_SQL or any(
        objects.get(name) != sql for name, sql in rpc_fences().items()
    ):
        raise ValueError("exchange RPC history or writer fences changed")
    rows = db.execute(
        f"SELECT sequence,substr(previous,1,?),length(previous),"
        f"substr(current,1,?),length(current) FROM {TABLE} ORDER BY sequence LIMIT 2",
        (MAX_PRIVATE_BYTES + 1, MAX_PRIVATE_BYTES + 1),
    ).fetchall()
    if (
        len(rows) != 1
        or rows[0][0] != 1
        or any(
            type(size) is not int or not 0 < size <= MAX_PRIVATE_BYTES
            for size in (rows[0][2], rows[0][4])
        )
    ):
        raise ValueError("exchange RPC history exceeds its single addition")
    _, previous, _, current, _ = rows[0]
    validate_rpc_addition(previous, current)
    binding = db.execute("SELECT body FROM binding").fetchall()
    if len(binding) != 1:
        raise ValueError("exchange RPC current binding missing")
    # Signed policy lineage may change its digest; signed launch migration may
    # change public_launch. Neither authorizes undoing or replacing transports.
    bound_chain = json.loads(binding[0][0]).get("chain")
    reviewed_chain = json.loads(current)["chain"]
    if not isinstance(bound_chain, dict) or (
        {k: v for k, v in bound_chain.items() if k != "policy_sha256"}
        != {k: v for k, v in reviewed_chain.items() if k != "policy_sha256"}
    ):
        raise ValueError("exchange RPC transport history differs from current binding")
    return True


def migrate_rpc_binding(db, previous: bytes, current: bytes) -> None:
    validate_rpc_addition(previous, current)
    if max(len(previous), len(current)) > MAX_PRIVATE_BYTES:
        raise ValueError("exchange RPC migration binding exceeds native byte bound")
    if check_rpc_history(db):
        raise ValueError("exchange RPC addition already retained")
    if db.execute("SELECT body FROM binding").fetchall() != [(previous,)]:
        raise ValueError("exchange configuration changed before RPC addition")
    db.execute(TABLE_SQL)
    db.execute(f"INSERT INTO {TABLE} VALUES (1,?,?)", (previous, current))
    db.execute("UPDATE binding SET body=?", (current,))
    for sql in rpc_fences().values():
        db.execute(sql)
    check_rpc_history(db)
