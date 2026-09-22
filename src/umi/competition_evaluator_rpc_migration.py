"""Preserve evaluator history when explicitly adding backup proof transports."""

from __future__ import annotations

import json

from .competition_chain import CompetitionChainConfig
from .protocol import canonical_json_bytes


def _validate_addition(previous: bytes, current: bytes) -> None:
    """Allow only absent -> two-backup additions, with the primary and pins fixed.

    Current config model validation remains the caller's responsibility.
    """
    old, new = json.loads(previous), json.loads(current)
    if canonical_json_bytes(old) != previous or canonical_json_bytes(new) != current:
        raise ValueError("evaluator journal configuration changed")
    changed = []
    for field in ("chain", "work_signing_chain"):
        before, after = old.get(field), new.get(field)
        if before == after:
            continue
        if not isinstance(before, dict) or not isinstance(after, dict):
            raise ValueError("evaluator journal configuration changed")
        backups = after.get("proof_rpc_fallback_urls")
        if (
            "proof_rpc_fallback_urls" in before
            or not isinstance(backups, list)
            or len(backups) != 2
            or len(set(backups)) != 2
            or {**before, "proof_rpc_fallback_urls": backups} != after
        ):
            raise ValueError("evaluator journal configuration changed")
        CompetitionChainConfig.model_validate_json(canonical_json_bytes(after))
        old[field] = after
        changed.append(field)
    if not changed or old != new:
        raise ValueError("evaluator journal configuration changed")


def validate_rpc_binding(db, original: bytes, current: bytes) -> None:
    """Retain at most two monotonic additions under the caller's transaction.

    The original binding stays byte-identical: existing capacity reservations
    reference its digest. A chained transport history records the effective
    configuration and prevents a new reader from removing the added backups.
    """
    table = "evaluator_rpc_transport_changes"
    exists = db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone()
    rows = (
        []
        if exists is None
        else db.execute(
            "SELECT sequence,previous,current FROM evaluator_rpc_transport_changes "
            "ORDER BY sequence LIMIT 3"
        ).fetchall()
    )
    if len(rows) > 2:
        raise ValueError("evaluator RPC migration history exceeds scope")
    effective = original
    for number, (sequence, previous, selected) in enumerate(rows, 1):
        if sequence != number or previous != effective:
            raise ValueError("evaluator RPC migration history changed")
        _validate_addition(previous, selected)
        effective = selected
    if effective == current:
        return
    _validate_addition(effective, current)
    if len(rows) == 2:
        raise ValueError("evaluator RPC migration history exceeds scope")
    db.execute(
        "CREATE TABLE IF NOT EXISTS evaluator_rpc_transport_changes "
        "(sequence INTEGER PRIMARY KEY, previous BLOB NOT NULL, current BLOB NOT NULL)"
    )
    db.execute(
        "INSERT INTO evaluator_rpc_transport_changes VALUES (?,?,?)",
        (len(rows) + 1, effective, current),
    )
