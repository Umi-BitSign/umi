"""Add backup round proof transports without rebinding capacity receipts."""

from __future__ import annotations

import json

from .competition_chain import CompetitionChainConfig
from .protocol import canonical_json_bytes

TABLE = "round_rpc_transport_changes"


def has_transport_history(db) -> bool:
    return (
        db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (TABLE,)).fetchone()
        is not None
    )


def _validate_addition(previous: bytes, current: bytes) -> None:
    old, new = json.loads(previous), json.loads(current)
    if (
        not isinstance(old, dict)
        or not isinstance(new, dict)
        or old.get("schema") != "umi-round-coordinator-config/2"
        or new.get("schema") != old["schema"]
        or canonical_json_bytes(old) != previous
        or canonical_json_bytes(new) != current
    ):
        raise ValueError("round RPC migration requires canonical coordinator bindings")
    changed = False
    for path in (("chain",), ("work", "transport_chain")):
        before_parent, after_parent = old, new
        for key in path[:-1]:
            before_parent = before_parent.get(key)
            after_parent = after_parent.get(key)
            if before_parent is None and after_parent is None:
                break
            if not isinstance(before_parent, dict) or not isinstance(after_parent, dict):
                raise ValueError("round journal configuration changed")
        if before_parent is None and after_parent is None:
            continue
        before, after = before_parent.get(path[-1]), after_parent.get(path[-1])
        if before == after:
            continue
        if not isinstance(before, dict) or not isinstance(after, dict):
            raise ValueError("round journal configuration changed")
        backups = after.get("proof_rpc_fallback_urls")
        if (
            "proof_rpc_fallback_urls" in before
            or not isinstance(backups, list)
            or len(backups) != 2
            or any(not isinstance(url, str) for url in backups)
            or len(set(backups)) != 2
            or {**before, "proof_rpc_fallback_urls": backups} != after
        ):
            raise ValueError("round journal configuration changed")
        CompetitionChainConfig.model_validate_json(canonical_json_bytes(after))
        before_parent[path[-1]] = after
        changed = True
    if not changed or old != new:
        raise ValueError("round journal configuration changed")


def validate_rpc_binding(db, original: bytes, current: bytes) -> None:
    """Record at most one addition per transport; keep original binding intact."""
    rows = (
        db.execute(
            "SELECT sequence,previous,current FROM round_rpc_transport_changes "
            "ORDER BY sequence LIMIT 3"
        ).fetchall()
        if has_transport_history(db)
        else []
    )
    if len(rows) > 2:
        raise ValueError("round RPC migration history exceeds scope")
    effective = original
    for expected, (sequence, previous, selected) in enumerate(rows, 1):
        if sequence != expected or previous != effective:
            raise ValueError("round RPC migration history changed")
        _validate_addition(previous, selected)
        effective = selected
    if effective == current:
        return
    _validate_addition(effective, current)
    if len(rows) == 2:
        raise ValueError("round RPC migration history exceeds scope")
    db.execute(
        "CREATE TABLE IF NOT EXISTS round_rpc_transport_changes "
        "(sequence INTEGER PRIMARY KEY, previous BLOB NOT NULL, current BLOB NOT NULL)"
    )
    db.execute(
        "INSERT INTO round_rpc_transport_changes VALUES (?,?,?)",
        (len(rows) + 1, effective, current),
    )
