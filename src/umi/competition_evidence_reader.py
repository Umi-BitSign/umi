"""Read and audit the selected retained evidence format under a host-owned lock."""

from __future__ import annotations

import hashlib

from .competition_evidence_continuity import audit_continuity_transitions
from .competition_evidence_store import EvidenceStore
from .competition_evidence_worker import bind_worker_profile
from .encoding import account_id32
from .protocol import canonical_json_bytes


def evidence_reader(db, *, storage, validator_hotkey, maximum_attempts, maximum_evidence_bytes):
    if not db.in_transaction:
        raise ValueError("retained evidence requires a host-owned snapshot")
    count, size = db.execute(
        "SELECT COUNT(*),COALESCE(MAX(length(hotkey)),0) FROM binding"
    ).fetchone()
    if count > 1 or size > 128:
        raise ValueError("retained evidence owner binding exceeds bounds")
    binding = db.execute("SELECT * FROM binding").fetchall()
    cas = db.execute("SELECT 1 FROM sqlite_master WHERE name='weight_proof_binding'").fetchone()
    if (
        storage is not None
        and db.execute("SELECT 1 FROM sqlite_master WHERE name='evidence'").fetchone()
    ):
        raise ValueError("legacy journal needs explicit stopped migration")
    if (
        storage is None
        and db.execute("SELECT 1 FROM sqlite_master WHERE name LIKE 'weight_proof_%'").fetchone()
    ):
        raise ValueError("legacy host cannot interpret content-addressed evidence")
    if not binding:
        if cas or db.execute("SELECT 1 FROM attempts").fetchone():
            raise ValueError("retained evidence has no original owner binding")
        if storage is None and db.execute("SELECT 1 FROM evidence").fetchone():
            raise ValueError("unbound legacy journal contains evidence")
        if (
            storage is not None
            and db.execute("SELECT 1 FROM sqlite_master WHERE name='evidence'").fetchone()
        ):
            raise ValueError("legacy journal needs explicit stopped migration")
        return lambda identity: _missing()
    if len(binding) != 1:
        raise ValueError("retained evidence has multiple owner bindings")
    hotkey, attempts, evidence = binding[0]
    if (
        account_id32(hotkey) != account_id32(validator_hotkey)
        or type(attempts) is not int
        or not 1 <= attempts <= maximum_attempts
        or type(evidence) is not int
        or not 1024 <= evidence <= maximum_evidence_bytes
    ):
        raise ValueError("retained evidence owner or legacy capacity changed")
    if storage is not None:
        audit_continuity_transitions(db)
        bind_worker_profile(db, storage.profile())
        store = EvidenceStore(
            db,
            owner_binding_sha256=hashlib.sha256(canonical_json_bytes(binding)).hexdigest(),
            limits=storage.profile().limits,
        )
        store.audit()
        return store.get
    if cas:
        raise ValueError("legacy host cannot interpret content-addressed evidence")
    total, maximum = db.execute(
        "SELECT COALESCE(SUM(length(body)),0),COALESCE(MAX(length(body)),0) FROM evidence"
    ).fetchone()
    if total > evidence or maximum > 32 * 1024**2:
        raise ValueError("legacy retained evidence exceeds its bound")

    def read(identity):
        found = db.execute(
            "SELECT length(body) FROM evidence WHERE sha256=?", (identity,)
        ).fetchone()
        if found is None or not 0 < found[0] <= 32 * 1024**2:
            raise ValueError("retained evidence absent or oversized")
        raw = db.execute("SELECT body FROM evidence WHERE sha256=?", (identity,)).fetchone()[0]
        if not isinstance(raw, bytes) or hashlib.sha256(raw).hexdigest() != identity:
            raise ValueError("retained evidence is corrupt")
        return raw

    for (identity,) in db.execute("SELECT sha256 FROM evidence"):
        read(identity)
    return read


def _missing():
    raise ValueError("unbound empty journal cannot supply evidence")
