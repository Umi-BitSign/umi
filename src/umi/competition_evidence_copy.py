"""Build an offline storage candidate from a read-only frozen weight snapshot.

This copies every legacy row except the evidence representation. It does not
select the candidate, seal a migration receipt, authorize a new worker, or prove
that the source process has stopped. Those are mandatory host transition tasks.
The caller must hold source ownership and keep the original database unchanged.
"""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import asdict

from .competition_evidence_codec import MAX_EVIDENCE_BYTES, checked_digest
from .competition_evidence_store import EvidenceBudget, EvidenceStore
from .competition_weights import _WeightAttempt
from .protocol import canonical_json_bytes

_LEGACY = {
    "binding": "(hotkey TEXT PRIMARY KEY, maximum_attempts INTEGER NOT NULL, "
    "maximum_evidence_bytes INTEGER NOT NULL)",
    "attempts": "(id TEXT PRIMARY KEY, body BLOB NOT NULL, sha256 TEXT NOT NULL)",
    "evidence": "(sha256 TEXT PRIMARY KEY, body BLOB NOT NULL)",
    "highwater": "(id INTEGER PRIMARY KEY CHECK(id=1), block INTEGER NOT NULL, hash TEXT NOT NULL)",
    "held_policies": "(policy TEXT PRIMARY KEY)",
    "continuity_highwater": "(policy TEXT PRIMARY KEY, authority TEXT NOT NULL, "
    "round_sequence INTEGER NOT NULL, package TEXT NOT NULL, admission TEXT NOT NULL)",
}


def _state_digest(db):
    digest = hashlib.sha256(b"umi-weight-evidence-preserved-state/1\x00")
    for table in _LEGACY:
        if table != "evidence":
            digest.update(table.encode("ascii") + b"\x00")
            for row in db.execute(f"SELECT * FROM {table} ORDER BY 1"):
                raw = canonical_json_bytes(
                    [
                        ["bytes", value.hex()] if isinstance(value, bytes) else ["scalar", value]
                        for value in row
                    ]
                )
                digest.update(len(raw).to_bytes(8, "big"))
                digest.update(raw)
            digest.update(b"\x00" * 8)
    return digest.hexdigest()


def copy_legacy_weight_journal(
    source: sqlite3.Connection,
    destination: sqlite3.Connection,
    *,
    expected_binding_sha256: str,
    limits: EvidenceBudget,
) -> dict:
    """One transactional, lossless candidate copy; no live journal mutation."""
    if not source.in_transaction or source.execute("PRAGMA query_only").fetchone() != (1,):
        raise ValueError("legacy copy requires an owned read-only source snapshot")
    if not destination.in_transaction or source is destination:
        raise ValueError("candidate copy requires a separate destination transaction")
    if destination.execute("SELECT 1 FROM sqlite_master LIMIT 1").fetchone():
        raise ValueError("candidate destination must be empty")
    schema = dict(source.execute("SELECT name,sql FROM sqlite_master WHERE type='table'"))
    expected = {name: f"CREATE TABLE {name} {sql}" for name, sql in _LEGACY.items()}
    if (
        schema != expected
        or source.execute(
            "SELECT 1 FROM sqlite_master WHERE type IN ('trigger','view') LIMIT 1"
        ).fetchone()
    ):
        raise ValueError("legacy weight journal schema changed")
    count, size = source.execute(
        "SELECT COUNT(*),COALESCE(MAX(length(hotkey)),0) FROM binding"
    ).fetchone()
    if count != 1 or not 1 <= size <= 128:
        raise ValueError("legacy copy needs exactly one existing owner binding")
    binding = source.execute("SELECT * FROM binding").fetchall()
    hotkey, maximum_attempts, maximum_evidence_bytes = binding[0]
    if hashlib.sha256(canonical_json_bytes(binding)).hexdigest() != checked_digest(
        expected_binding_sha256
    ):
        raise ValueError("legacy owner binding does not match expected digest")
    if (
        not isinstance(hotkey, str)
        or type(maximum_attempts) is not int
        or not 1 <= maximum_attempts <= 65536
        or type(maximum_evidence_bytes) is not int
        or not 1024 <= maximum_evidence_bytes <= 16 * 1024**3
    ):
        raise ValueError("legacy owner binding is invalid")
    for table in _LEGACY:
        if table != "evidence":
            count = source.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            if count > (1 if table in {"binding", "highwater"} else maximum_attempts):
                raise ValueError("legacy state count exceeds candidate copy bounds")
    count, total, minimum, maximum = source.execute(
        "SELECT COUNT(*),COALESCE(SUM(length(body)),0),COALESCE(MIN(length(body)),1),"
        "COALESCE(MAX(length(body)),0) FROM evidence"
    ).fetchone()
    if count > limits.records or total > maximum_evidence_bytes or minimum <= 0:
        raise ValueError("legacy evidence exceeds capacity")
    if maximum > MAX_EVIDENCE_BYTES:
        raise ValueError("legacy evidence contains oversized object")
    if (
        source.execute(
            "SELECT 1 FROM attempts WHERE length(id)!=64 OR length(sha256)!=64 LIMIT 1"
        ).fetchone()
        or source.execute("SELECT 1 FROM evidence WHERE length(sha256)!=64 LIMIT 1").fetchone()
    ):
        raise ValueError("legacy digest field exceeds copy bound")
    for identity, size in source.execute("SELECT id,length(body) FROM attempts"):
        if not 0 < size <= 256 * 1024:
            raise ValueError("legacy attempt exceeds size bound")
        raw, checksum = source.execute(
            "SELECT body,sha256 FROM attempts WHERE id=?", (identity,)
        ).fetchone()
        if not isinstance(raw, bytes) or hashlib.sha256(raw).hexdigest() != checksum:
            raise ValueError("legacy attempt checksum changed")
        attempt = _WeightAttempt.model_validate_json(raw)
        if (
            canonical_json_bytes(attempt) != raw
            or attempt.authorization_id != identity
            or attempt.validator_hotkey != hotkey
            or not source.execute(
                "SELECT 1 FROM evidence WHERE sha256=?", (attempt.chain_evidence_sha256,)
            ).fetchone()
        ):
            raise ValueError("legacy attempt identity or retained evidence changed")
    # Bound the remaining small tables before their rows are materialized.
    for table in ("binding", "highwater", "held_policies", "continuity_highwater"):
        for row in source.execute(f"SELECT * FROM {table}"):
            if any(isinstance(value, (str, bytes)) and len(value) > 1024 for value in row):
                raise ValueError("legacy state field exceeds copy bound")
    before = _state_digest(source)
    destination.execute("SAVEPOINT weight_evidence_candidate")
    try:
        for table, definition in _LEGACY.items():
            if table == "evidence":
                continue
            destination.execute(f"CREATE TABLE {table} {definition}")
            columns = len(source.execute(f"PRAGMA table_info({table})").fetchall())
            destination.executemany(
                f"INSERT INTO {table} VALUES ({','.join('?' for _ in range(columns))})",
                source.execute(f"SELECT * FROM {table}"),
            )
        store = EvidenceStore(
            destination, owner_binding_sha256=expected_binding_sha256, limits=limits, create=True
        )
        evidence_index = hashlib.sha256()
        for identity, raw in source.execute("SELECT sha256,body FROM evidence ORDER BY sha256"):
            if not isinstance(raw, bytes) or hashlib.sha256(raw).hexdigest() != identity:
                raise ValueError("legacy evidence digest changed")
            # v1 does not persist a kind tag. Preserve its 32MiB accepted bound
            # for every imported body; never infer semantics from JSON contents.
            if store.put(raw, kind="proof") != identity or store.get(identity) != raw:
                raise ValueError("legacy evidence reconstruction changed")
            evidence_index.update(bytes.fromhex(identity))
            evidence_index.update(len(raw).to_bytes(8, "big"))
        usage = store.audit()
        if _state_digest(source) != before or _state_digest(destination) != before:
            raise ValueError("legacy journal state changed during copy")
        result = {
            "schema": "umi-weight-evidence-candidate-copy/1",
            "owner_binding_sha256": expected_binding_sha256,
            "preserved_state_sha256": before,
            "evidence_index_sha256": evidence_index.hexdigest(),
            "original_evidence_bytes": total,
            "evidence_records": count,
            "stored_usage": asdict(usage),
            "activation_authorized": False,
        }
        destination.execute("RELEASE weight_evidence_candidate")
        return result
    except BaseException:
        destination.execute("ROLLBACK TO weight_evidence_candidate")
        destination.execute("RELEASE weight_evidence_candidate")
        raise
