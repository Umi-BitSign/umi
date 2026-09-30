"""Durable void receipts with actual arrival blocks and shared conflict holds."""

from __future__ import annotations

from .competition_void import (
    MAX_VOID_BYTES,
    authenticate_void_evidence,
    validate_void_receipt,
    void_decision_digest,
    void_evidence_digest,
)
from .open_competition import digest
from .protocol import canonical_json_bytes


def hold_outcome_conflict(connection, round_id, observed_block):
    connection.execute(
        "INSERT OR IGNORE INTO round_conflicts VALUES (?, ?)", (round_id, observed_block)
    )
    if connection.execute(
        "SELECT 1 FROM competition_settlements WHERE round=?", (round_id,)
    ).fetchone():
        connection.execute(
            "INSERT OR IGNORE INTO settlement_disputes VALUES (?, ?)", (round_id, observed_block)
        )
    source = connection.execute(
        "SELECT MIN(sequence) FROM promotion_sources WHERE round=?", (round_id,)
    ).fetchone()[0]
    if source is not None:
        connection.execute(
            "INSERT OR IGNORE INTO settlement_disputes "
            "SELECT round, ? FROM settlement_heads WHERE promotion_sequence>=?",
            (observed_block, source),
        )


class VoidEvidenceRetention:
    def record_void_evaluation(self, *, evidence, suite, observed_block):
        from .competition_store import AdmissionCapacityError, _advance_block

        evidence = authenticate_void_evidence(evidence, suite=suite, policy=self.policy)
        order = evidence.order.order
        round_id, submission_id = digest(order.round), digest(order.submission.submission)
        if type(observed_block) is not int or not (
            order.round.reveal_block <= observed_block <= 2**53 - 1
        ):
            raise ValueError("void observation must be at or after reveal in a valid block")
        validate_void_receipt(evidence, observed_block)
        body = canonical_json_bytes(evidence)
        if len(body) > MAX_VOID_BYTES:
            raise ValueError("void evidence exceeds its byte bound")
        evidence_id = void_evidence_digest(evidence)
        decision_id = void_decision_digest(evidence.certificate.void)
        exhausted = False
        with self._transaction() as connection:
            closed = connection.execute(
                "SELECT body FROM rounds WHERE digest=?", (round_id,)
            ).fetchone()
            signed = connection.execute(
                "SELECT body FROM submissions WHERE digest=?", (submission_id,)
            ).fetchone()
            if (
                closed is None
                or closed[0] != canonical_json_bytes(order.round)
                or (signed is None or signed[0] != canonical_json_bytes(order.submission))
            ):
                raise ValueError("void evidence differs from the retained round or submission")
            self._fixed_cutoff(connection, round_id)
            _advance_block(connection, observed_block)
            # A full body store must not suppress a newly authenticated conflict.
            # Keep the compact hold in this transaction even if retention fails.
            if (
                connection.execute(
                    "SELECT 1 FROM void_evaluation_evidence "
                    "WHERE round=? AND submission=? AND decision<>? LIMIT 1",
                    (round_id, submission_id, decision_id),
                ).fetchone()
                or connection.execute(
                    "SELECT 1 FROM evaluation_results WHERE round=? AND submission=? LIMIT 1",
                    (round_id, submission_id),
                ).fetchone()
            ):
                hold_outcome_conflict(connection, round_id, observed_block)
            prior = connection.execute(
                "SELECT round,submission,decision,body,first_observed_block "
                "FROM void_evaluation_evidence WHERE digest=?",
                (evidence_id,),
            ).fetchone()
            if prior is not None:
                if prior[:4] != (round_id, submission_id, decision_id, body):
                    raise ValueError("retained void evidence digest conflicts with stored bytes")
                first_observed = prior[4]
            else:
                count, size = connection.execute(
                    "SELECT COUNT(*),COALESCE(SUM(length(body)),0) FROM void_evaluation_evidence"
                ).fetchone()
                if count + 1 > self.admission_capacity.maximum_records or (
                    size + len(body) > self.admission_capacity.maximum_bytes
                ):
                    exhausted = True
                else:
                    connection.execute(
                        "INSERT INTO void_evaluation_evidence VALUES (?,?,?,?,?,?)",
                        (evidence_id, round_id, submission_id, decision_id, body, observed_block),
                    )
                first_observed = observed_block
            conflicted = (
                connection.execute(
                    "SELECT 1 FROM round_conflicts WHERE round=?", (round_id,)
                ).fetchone()
                is not None
            )
        if exhausted:
            raise AdmissionCapacityError("void evidence capacity exhausted; preserve history")
        return {
            "schema": "umi-competition-void-evidence-receipt/1",
            "policy_sha256": digest(self.policy),
            "round_sha256": round_id,
            "submission_sha256": submission_id,
            "void_decision_sha256": decision_id,
            "void_evidence_sha256": evidence_id,
            "first_observed_block": first_observed,
            "conflicted": conflicted,
            "chain_submission_authorized": False,
        }
