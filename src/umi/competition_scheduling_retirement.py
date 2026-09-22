"""Release future scheduling obligations using an authenticated repair void.

The original dispatch remains uncertain and cannot be retried. This disposition
only releases its pending timing/proof allowance. It does not establish timely
settlement receipt, a score, or permission to submit weights.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from pydantic import Field

from .competition_authorization import (
    SignedEndpointAuthorization,
    scheduled_assignment_key,
    validate_publication,
)
from .competition_dispatch_repair import EndpointUnavailableEvidence
from .competition_void import (
    MAX_VOID_BYTES,
    VoidEvaluationEvidence,
    authenticate_void_evidence,
    void_decision_digest,
)
from .open_competition import EvaluationSuite, digest, identity
from .protocol import StrictProtocolModel, canonical_json_bytes

if TYPE_CHECKING:
    import sqlite3

    from .competition_scheduling import AssignmentPublicationJournal

_TABLE = "scheduling_retirements"
_MAX_DOCUMENT_BYTES = 2 * MAX_VOID_BYTES


class ClaimRetirement(StrictProtocolModel):
    schema_: Literal["umi-scheduling-claim-retirement/1"] = Field(alias="schema")
    evidence: VoidEvaluationEvidence
    suite: EvaluationSuite


@dataclass(frozen=True)
class _Claim:
    key: str
    evaluator: str
    publication: str
    publication_bytes: str
    body_bytes: str
    deadline: int
    claim: tuple[str, int, int, str]


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _facts(journal, raw):
    """Cache only immutable derivations; durable claims are checked every time."""
    if not isinstance(raw, bytes) or not 0 < len(raw) <= _MAX_DOCUMENT_BYTES:
        raise ValueError("scheduling retirement document exceeds its bound")
    key = ("retirement", _sha(raw))
    cached = journal._retirement_validation.get(key)
    if cached is not None:
        return cached
    document = ClaimRetirement.model_validate_json(raw)
    if canonical_json_bytes(document) != raw:
        raise ValueError("scheduling retirement document is not canonical")
    evidence = document.evidence
    if evidence.legacy_policy != journal.legacy_policy or (
        evidence.certificate.void.reason != "coordinator_outcome_unavailable"
    ):
        raise ValueError("scheduling retirement requires the bound repair void")
    authenticate_void_evidence(evidence, suite=document.suite, policy=journal.policy)
    order = evidence.order.order
    publication = order.publication
    assignments = {
        scheduled_assignment_key(publication.publication, a): a
        for a in publication.publication.assignments
    }
    claims = {}
    for signed in evidence.certificate.void.observations:
        observation = signed.announcement.evidence
        if not isinstance(observation, EndpointUnavailableEvidence):
            continue
        for claim in observation.repair.amendment.unavailable:
            assignment = assignments[claim.assignment_key]
            claims[claim.assignment_key] = _Claim(
                key=claim.assignment_key,
                evaluator=identity(claim.evaluator_hotkey),
                publication=digest(publication.publication),
                publication_bytes=_sha(canonical_json_bytes(publication.publication)),
                body_bytes=_sha(canonical_json_bytes(assignment)),
                deadline=claim.deadline_block,
                claim=(
                    claim.claim_sha256,
                    claim.claim_block,
                    claim.claim_unix_ms,
                    claim.request_sha256,
                ),
            )
    facts = (digest(order), void_decision_digest(evidence.certificate.void), tuple(claims.values()))
    _cache(journal, key, facts)
    return facts


def _cache(journal, key, value):
    if len(journal._retirement_validation) >= 64:
        journal._retirement_validation.pop(next(iter(journal._retirement_validation)), None)
    journal._retirement_validation[key] = value


def _publication(journal, raw):
    key = ("publication", _sha(raw))
    cached = journal._retirement_validation.get(key)
    if cached is not None:
        return cached
    signed = validate_publication(
        SignedEndpointAuthorization.model_validate_json(raw), journal.policy, journal.legacy_policy
    )
    if canonical_json_bytes(signed) != raw:
        raise ValueError("retirement retained publication is not canonical")
    facts = (digest(signed.publication), _sha(canonical_json_bytes(signed.publication)))
    _cache(journal, key, facts)
    return facts


def _local_claims(journal, db, claims):
    local = set()
    for claim in claims:
        assignment = db.execute(
            "SELECT a.publication_id,a.evaluator,a.body,a.deadline_block,p.signed "
            "FROM assignments a JOIN publications p ON p.id=a.publication_id WHERE a.id=?",
            (claim.key,),
        ).fetchone()
        if assignment is None:
            continue  # Another evaluator may have its own scheduling journal.
        if tuple(assignment[:2]) != (claim.publication, claim.evaluator) or (
            _sha(bytes(assignment[2])) != claim.body_bytes
            or assignment[3] != claim.deadline
            or _publication(journal, bytes(assignment[4]))
            != (claim.publication, claim.publication_bytes)
        ):
            raise ValueError("retirement changes the original local assignment")
        events = db.execute(
            "SELECT kind,observed_height,observed_ms,body,length(evidence) FROM events "
            "WHERE assignment_id=? ORDER BY ordinal",
            (claim.key,),
        ).fetchall()
        if [r[0] for r in events] != ["published", "dispatched"] or events[-1][4] != 0:
            raise ValueError("retirement requires an original uncertain local claim")
        _, block, ms, raw, _ = events[-1]
        body = json.loads(raw)
        if (
            canonical_json_bytes(body) != raw
            or set(body) != {"claim_id", "issuance_height", "request_sha256"}
            or (_sha(raw), block, ms, body["request_sha256"]) != claim.claim
        ):
            raise ValueError("retirement changes the original local claim")
        local.add(claim.key)
    return local


def _exists(db):
    return (
        db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (_TABLE,)
        ).fetchone()
        is not None
    )


def retired_claims(journal: AssignmentPublicationJournal, db: sqlite3.Connection) -> frozenset[str]:
    """Authenticate every retained disposition against this transaction's claims."""
    if not _exists(db):
        return frozenset()
    retired = set()
    count = db.execute(f"SELECT COUNT(*) FROM {_TABLE}").fetchone()[0]
    if count > journal.maximum_assignments:
        raise ValueError("scheduling retirement count exceeds assignment capacity")
    for order, decision, length in db.execute(
        f"SELECT order_sha256,decision_sha256,length(document) FROM {_TABLE}"
    ):
        if not 0 < length <= _MAX_DOCUMENT_BYTES:
            raise ValueError("scheduling retirement document exceeds its bound")
        raw = bytes(
            db.execute(f"SELECT document FROM {_TABLE} WHERE order_sha256=?", (order,)).fetchone()[
                0
            ]
        )
        actual_order, actual_decision, claims = _facts(journal, raw)
        if (order, decision) != (actual_order, actual_decision):
            raise ValueError("scheduling retirement identity differs")
        local = _local_claims(journal, db, claims)
        if not local or retired.intersection(local):
            raise ValueError("scheduling retirement has absent or duplicate local claims")
        retired.update(local)
    return frozenset(retired)


def retained_bytes(db: sqlite3.Connection) -> int:
    if not _exists(db):
        return 0
    return db.execute(f"SELECT COALESCE(SUM(length(document)+128),0) FROM {_TABLE}").fetchone()[0]


def retire_void(
    journal: AssignmentPublicationJournal,
    *,
    evidence: VoidEvaluationEvidence,
    suite: EvaluationSuite,
) -> frozenset[str]:
    """Append an authenticated disposition, atomically with its capacity check.

    Historical authentication is deliberate: an already certified void remains
    useful after a restart, even if settlement failed or its payment window ended.
    No historical receipt time is supplied or changed here.
    """
    raw = canonical_json_bytes(
        ClaimRetirement(schema="umi-scheduling-claim-retirement/1", evidence=evidence, suite=suite)
    )
    order, decision, claims = _facts(journal, raw)
    with journal._transaction() as db:
        local = _local_claims(journal, db, claims)
        if not local:
            return frozenset()
        if not _exists(db):
            db.execute(
                f"CREATE TABLE {_TABLE} (order_sha256 TEXT PRIMARY KEY, "
                "decision_sha256 TEXT NOT NULL, document BLOB NOT NULL, "
                "retained_unix_ms INTEGER NOT NULL)"
            )
            for operation in ("UPDATE", "DELETE"):
                db.execute(
                    f"CREATE TRIGGER immutable_{_TABLE}_{operation.lower()} BEFORE {operation} "
                    f"ON {_TABLE} BEGIN SELECT RAISE(ABORT,"
                    "'append-only scheduling retirement'); END"
                )
        old = db.execute(
            f"SELECT decision_sha256 FROM {_TABLE} WHERE order_sha256=?", (order,)
        ).fetchone()
        if old is not None and old[0] != decision:
            raise ValueError("retirement conflicts with the retained void decision")
        if old is None:
            db.execute(
                f"INSERT INTO {_TABLE} VALUES (?,?,?,?)",
                (order, decision, raw, time.time_ns() // 1_000_000),
            )
        journal._capacity(db)
        return frozenset(local)
