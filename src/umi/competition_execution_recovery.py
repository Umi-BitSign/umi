"""Explicit local audit records for legacy failures before model invocation.

These records are operator attestations, not portable execution proofs. They
never authorize weights or relax signed evaluation boundaries. Original failed
jobs remain unchanged; an authorized attempt is separately retained and cannot
be retried after it is claimed, including when its result is ambiguous.
"""

import hashlib
from typing import Annotated, Literal

from pydantic import Field

from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


class LegacyPreflightRecovery(StrictProtocolModel):
    schema_: Literal["umi-legacy-preflight-recovery/1"] = Field(alias="schema")
    source_execution_key: Hex32
    source_job_sha256: Hex32
    scope_sha256: Hex32
    policy_sha256: Hex32
    round_sha256: Hex32
    journal_state_sha256: Hex32
    preserved_snapshot_sha256: Hex32
    operator_audit_sha256: Hex32
    observed_block: Annotated[int, Field(ge=1)]
    basis: Literal["operator_audited_no_prior_model_invocation"]
    chain_submission_authorized: Literal[False] = False


TABLES = {
    "recovery_authorizations": (
        "CREATE TABLE recovery_authorizations (scope TEXT PRIMARY KEY NOT NULL, "
        "source_job TEXT UNIQUE NOT NULL, document BLOB NOT NULL)"
    ),
    "recovery_attempts": (
        "CREATE TABLE recovery_attempts (job_id TEXT PRIMARY KEY NOT NULL, "
        "source_job TEXT NOT NULL, status TEXT NOT NULL, reason TEXT)"
    ),
}


def fences(tables):
    result = {
        f"recovery_writer_{table}_{op.lower()}": (
            f"CREATE TRIGGER recovery_writer_{table}_{op.lower()} BEFORE {op} ON {table} "
            "BEGIN SELECT CASE WHEN umi_execution_recovery_writer() IS NOT 1 "
            "THEN RAISE(ABORT,'execution recovery writer required') END; END"
        )
        for table in (*tables, *TABLES)
        for op in ("INSERT", "UPDATE", "DELETE")
    }
    for op in ("UPDATE", "DELETE"):
        name = f"recovery_authorization_immutable_{op.lower()}"
        result[name] = (
            f"CREATE TRIGGER {name} BEFORE {op} ON recovery_authorizations "
            "BEGIN SELECT RAISE(ABORT,'immutable execution recovery authorization'); END"
        )
        name = f"recovery_original_immutable_{op.lower()}"
        result[name] = (
            f"CREATE TRIGGER {name} BEFORE {op} ON jobs "
            "WHEN EXISTS (SELECT 1 FROM recovery_attempts WHERE job_id=OLD.id) "
            "BEGIN SELECT RAISE(ABORT,'immutable original execution failure'); END"
        )
    return result


def state_digest(db, tables):
    """Bind complete logical state, including reservations, without SQLite layout."""
    state = {}
    for table in tables:
        if not db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
        ).fetchone():
            continue
        rows = [
            [dict(blob=value.hex()) if isinstance(value, bytes) else value for value in row]
            for row in db.execute(f"SELECT * FROM {table}")
        ]
        state[table] = sorted(rows, key=canonical_json_bytes)
    return hashlib.sha256(canonical_json_bytes(state)).hexdigest()
