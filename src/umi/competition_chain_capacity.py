"""Audited increases to registration storage without discarding prior evidence."""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing

from .competition_work_progress import WorkProgress
from .protocol import canonical_json_bytes


def capacity_increase(previous, current):
    """Require the same chain configuration with strictly more cache space."""
    from .competition_chain import CompetitionChainConfig

    before = CompetitionChainConfig.model_validate_json(canonical_json_bytes(previous))
    after = CompetitionChainConfig.model_validate_json(canonical_json_bytes(current))
    if (
        after.maximum_cache_bytes <= before.maximum_cache_bytes
        or before.model_copy(update={"maximum_cache_bytes": after.maximum_cache_bytes}) != after
    ):
        raise ValueError("registration capacity change must only increase maximum_cache_bytes")
    return before, after


def _binding(config, transport_policy_sha256):
    from .competition_chain import FinalizedRegistrationProvider
    from .open_competition import digest

    chain = FinalizedRegistrationProvider._config_binding_hash(config)
    return (
        chain
        if transport_policy_sha256 is None
        else digest(
            {
                "chain": chain,
                "transport_policy": transport_policy_sha256,
            }
        )
    )


def _cache_history(db):
    """Stream retained transitions; only the count and final tuple stay in memory."""
    total = db.execute("SELECT COUNT(*) FROM cache_capacity_changes").fetchone()[0]
    tail = None
    count = 0
    with (
        closing(
            db.execute(
                "SELECT sequence,previous,current,transport_policy_sha256 "
                "FROM cache_capacity_changes ORDER BY sequence"
            )
        ) as rows,
        WorkProgress("registration_capacity_history", total, unit="changes") as progress,
    ):
        for count, row in enumerate(rows, 1):
            sequence, prior, selected, context = row
            before, after = capacity_increase(json.loads(prior), json.loads(selected))
            if (
                sequence != count
                or (tail is not None and (prior != tail[2] or context != tail[3]))
                or canonical_json_bytes(before) != prior
                or canonical_json_bytes(after) != selected
            ):
                raise ValueError("registration capacity history changed")
            tail = row
            progress.advance()
    return count, tail


def verify_cache_capacity_history(db, config, *, expected_binding):
    exists = db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='cache_capacity_changes'"
    ).fetchone()
    if exists is None:
        return
    _, tail = _cache_history(db)
    if tail is None:
        raise ValueError("registration capacity history is empty")
    context = tail[3]
    _, after = capacity_increase(json.loads(tail[1]), json.loads(tail[2]))
    expected = _binding(config, context)
    if _binding(after, context) != expected or expected != expected_binding:
        raise ValueError("registration capacity history differs from selected configuration")
    if db.execute("SELECT digest FROM binding").fetchall() != [(expected,)]:
        raise ValueError("registration capacity history differs from retained binding")


def grow_registration_cache(path, previous, current, *, transport_policy_sha256=None):
    """Migrate a quiescent provider's binding and retain every stored proof.

    The caller must own the service's stop/drain boundary. A retry after commit
    verifies the original receipt instead of rewriting or erasing history.
    """
    before, after = capacity_increase(previous, current)
    if path.is_symlink() or not path.is_file():
        raise ValueError("registration capacity migration needs an existing regular database")
    old = _binding(before, transport_policy_sha256)
    new = _binding(after, transport_policy_sha256)
    raw_before, raw_after = canonical_json_bytes(before), canonical_json_bytes(after)
    db = sqlite3.connect(path, timeout=30, isolation_level=None)
    try:
        db.execute("PRAGMA synchronous=FULL")
        db.execute("BEGIN IMMEDIATE")
        bound = db.execute("SELECT digest FROM binding").fetchall()
        exists = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='cache_capacity_changes'"
        ).fetchone()
        count, tail = (0, None) if exists is None else _cache_history(db)
        if tail is not None and tail[3] != transport_policy_sha256:
            raise ValueError("registration capacity history changed")
        if bound == [(new,)] and tail is None:
            # A fresh successor namespace may have been created with this
            # configuration, with no predecessor database to migrate.
            db.commit()
            return
        if (
            bound == [(new,)]
            and tail is not None
            and tail[1:] == (raw_before, raw_after, transport_policy_sha256)
        ):
            verify_cache_capacity_history(db, after, expected_binding=new)
            db.commit()
            return
        if bound != [(old,)] or (tail is not None and tail[2] != raw_before):
            raise ValueError("registration capacity source binding changed")
        db.execute(
            "CREATE TABLE IF NOT EXISTS cache_capacity_changes "
            "(sequence INTEGER PRIMARY KEY, previous BLOB NOT NULL, current BLOB NOT NULL, "
            "transport_policy_sha256 TEXT)"
        )
        db.execute(
            "INSERT INTO cache_capacity_changes VALUES (?,?,?,?)",
            (
                count + 1,
                raw_before,
                raw_after,
                transport_policy_sha256,
            ),
        )
        db.execute("UPDATE binding SET digest=?", (new,))
        verify_cache_capacity_history(db, after, expected_binding=new)
        db.commit()
    finally:
        db.close()


def _evaluator_increase(previous, current):
    old, new = json.loads(previous), json.loads(current)
    if canonical_json_bytes(old) != previous or canonical_json_bytes(new) != current:
        raise ValueError("evaluator capacity history is not canonical")
    changes = 0
    for field in ("chain", "work_signing_chain"):
        if old.get(field) != new.get(field):
            capacity_increase(old.get(field), new.get(field))
            old[field] = new[field]
            changes += 1
    if not changes or old != new:
        raise ValueError("evaluator configuration change is outside cache capacity")


def validate_evaluator_binding(db, original, current):
    """Preserve reservations bound to original bytes through explicit growth."""
    from .competition_evaluator_rpc_migration import validate_rpc_binding

    exists = db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='evaluator_chain_capacity_changes'"
    ).fetchone()
    count = 0
    if exists is not None:
        total = db.execute("SELECT COUNT(*) FROM evaluator_chain_capacity_changes").fetchone()[0]
        with (
            closing(
                db.execute(
                    "SELECT sequence,previous,current FROM evaluator_chain_capacity_changes "
                    "ORDER BY sequence"
                )
            ) as rows,
            WorkProgress("evaluator_capacity_history", total, unit="changes") as progress,
        ):
            for count, (sequence, prior, selected) in enumerate(rows, 1):
                if count == 1:
                    effective = prior
                    validate_rpc_binding(db, original, effective)
                if sequence != count or prior != effective:
                    raise ValueError("evaluator capacity history changed")
                _evaluator_increase(prior, selected)
                effective = selected
                progress.advance()
    if not count:
        rpc = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' "
            "AND name='evaluator_rpc_transport_changes'"
        ).fetchone()
        tail = (
            None
            if rpc is None
            else db.execute(
                "SELECT current FROM evaluator_rpc_transport_changes ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
        )
        effective = original if tail is None else tail[0]
        try:
            _evaluator_increase(effective, current)
        except ValueError:
            validate_rpc_binding(db, original, current)
            return
        validate_rpc_binding(db, original, effective)
    if current == effective:
        return
    _evaluator_increase(effective, current)
    db.execute(
        "CREATE TABLE IF NOT EXISTS evaluator_chain_capacity_changes "
        "(sequence INTEGER PRIMARY KEY, previous BLOB NOT NULL, current BLOB NOT NULL)"
    )
    db.execute(
        "INSERT INTO evaluator_chain_capacity_changes VALUES (?,?,?)",
        (
            count + 1,
            effective,
            current,
        ),
    )
