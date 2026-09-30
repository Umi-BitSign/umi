"""One explicit continuity-authority handoff, preserving the previous ledger row."""

from __future__ import annotations

import hashlib
import json

from .competition_history_compatibility import (
    SignedHistoryCompatibility,
    verify_history_compatibility,
)
from .protocol import canonical_json_bytes

_TABLE = "weight_proof_continuity_transitions"
_SQL = f"CREATE TABLE {_TABLE} (id TEXT PRIMARY KEY, body BLOB NOT NULL, sha256 TEXT NOT NULL)"
_MAX_RECORD = 256 * 1024
_MAX_RECORDS = 32


def audit_continuity_transitions(db):
    schema = db.execute("SELECT sql FROM sqlite_master WHERE name=?", (_TABLE,)).fetchone()
    if schema is None:
        return
    if schema != (_SQL,):
        raise ValueError("continuity transition history schema differs")
    count, maximum = db.execute(
        f"SELECT count(*),coalesce(max(length(body)),0) FROM {_TABLE}"
    ).fetchone()
    if count > _MAX_RECORDS or maximum > _MAX_RECORD:
        raise ValueError("continuity transition history exceeds its bound")
    for identity, raw, checksum in db.execute(f"SELECT id,body,sha256 FROM {_TABLE}"):
        if not isinstance(raw, bytes) or hashlib.sha256(raw).hexdigest() != checksum:
            raise ValueError("continuity transition history checksum differs")
        value = json.loads(raw)
        if (
            canonical_json_bytes(value) != raw
            or set(value)
            != {
                "schema",
                "policy",
                "before",
                "after",
                "compatibility_sha256",
                "signed_compatibility",
                "installation_receipt_sha256",
                "directive_sha256",
            }
            or value["schema"] != "umi-evidence-continuity-transition/1"
        ):
            raise ValueError("continuity transition history is not canonical")
        expected = hashlib.sha256(
            canonical_json_bytes([value["policy"], value["compatibility_sha256"]])
        ).hexdigest()
        if identity != expected:
            raise ValueError("continuity transition history identity differs")
        grant = SignedHistoryCompatibility.model_validate(value["signed_compatibility"])
        if grant.body_sha256 != value["compatibility_sha256"]:
            raise ValueError("continuity transition embedded authority differs")


def record_continuity_transition(db, *, activation, policy, before, after):
    if not db.in_transaction:
        raise ValueError("continuity handoff must share the native adoption transaction")
    # Import is required by the existing host/weight capability dependency. This
    # function is reachable only at the native post-preflight adoption boundary.
    from .competition_host_activation import AuthenticatedSuccessorActivation

    if type(activation) is not AuthenticatedSuccessorActivation:
        raise ValueError("continuity handoff needs genuine active host authority")
    activation.recheck()
    inputs = activation._inputs
    consent = inputs.operator_consent
    if consent.history_compatibility is None or inputs._receipt.evidence_migration is None:
        raise ValueError("continuity handoff lacks signed migration authority")
    grant = verify_history_compatibility(consent.history_compatibility, config=inputs.config)
    if (
        before[0] != consent.historical_consent.reward_continuity_sha256
        or after[0] != consent.reward_continuity_sha256
        or before[0] == after[0]
        or policy not in grant.forward_policy_sha256s
        or not grant.first_round_sequence <= after[1] <= grant.last_round_sequence
        or after[1] <= before[1]
        or activation.signed_directive.directive.sequence <= grant.predecessor_sequence
        or activation.signed_directive.directive.replay_package.release_identity_sha256
        != grant.target_release_identity_sha256
        or activation.package_sha256 != after[2]
    ):
        raise ValueError("continuity ledger handoff differs from signed forward scope")
    audit_continuity_transitions(db)
    if db.execute("SELECT 1 FROM sqlite_master WHERE name=?", (_TABLE,)).fetchone() is None:
        db.execute(_SQL)
    identity = hashlib.sha256(
        canonical_json_bytes([policy, consent.history_compatibility.body_sha256])
    ).hexdigest()
    raw = canonical_json_bytes(
        {
            "schema": "umi-evidence-continuity-transition/1",
            "policy": policy,
            "before": list(before),
            "after": list(after),
            "compatibility_sha256": consent.history_compatibility.body_sha256,
            "signed_compatibility": consent.history_compatibility.model_dump(
                mode="json", by_alias=True
            ),
            "installation_receipt_sha256": inputs.receipt_sha256,
            "directive_sha256": activation.directive_sha256,
        }
    )
    if (
        len(raw) > _MAX_RECORD
        or db.execute(f"SELECT count(*) FROM {_TABLE}").fetchone()[0] >= _MAX_RECORDS
    ):
        raise ValueError("continuity transition capacity exhausted")
    # A repeated different handoff cannot overwrite its retained predecessor.
    db.execute(
        f"INSERT INTO {_TABLE} VALUES (?,?,?)", (identity, raw, hashlib.sha256(raw).hexdigest())
    )
    activation.recheck()
