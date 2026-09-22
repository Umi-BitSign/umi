"""Bounded public metadata from the configured intake ledger, without replay."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path

from .open_competition import EvaluationRound, digest

# A round has at most 512 roster digests. Never load preparation/evidence bodies.
MAXIMUM_ROUND_BYTES = 64 * 1024
MAXIMUM_ROUND_SEQUENCE = 2**32 - 1


def round_index(
    path: Path,
    *,
    policy_sha256: str,
    before_sequence: int | None = None,
    limit: int = 20,
) -> dict:
    """Read one consistent page; the exclusive sequence cursor survives appends."""
    if not 1 <= limit <= 100 or (
        before_sequence is not None and not 1 <= before_sequence <= MAXIMUM_ROUND_SEQUENCE
    ):
        raise ValueError("invalid round index page")
    ceiling = MAXIMUM_ROUND_SEQUENCE + 1 if before_sequence is None else before_sequence
    with closing(
        sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, isolation_level=None)
    ) as connection:
        connection.execute("PRAGMA query_only=ON")
        connection.execute("BEGIN")
        rows = connection.execute(
            "SELECT digest, sequence, CASE WHEN length(body)<=? THEN body END "
            "FROM rounds WHERE sequence<? ORDER BY sequence DESC LIMIT ?",
            (MAXIMUM_ROUND_BYTES, ceiling, limit + 1),
        ).fetchall()
        items = []
        for round_id, sequence, body in rows[:limit]:
            if body is None:
                raise ValueError("retained round exceeds public metadata bound")
            round_ = EvaluationRound.model_validate_json(body)
            if digest(round_) != round_id or round_.sequence != sequence:
                raise ValueError("retained round identity differs")
            result_count = connection.execute(
                "SELECT COUNT(DISTINCT submission) FROM independent_evaluation_evidence "
                "WHERE round=?",
                (round_id,),
            ).fetchone()[0]
            void_count = connection.execute(
                "SELECT COUNT(DISTINCT submission) FROM void_evaluation_evidence WHERE round=?",
                (round_id,),
            ).fetchone()[0]
            outcome_count = connection.execute(
                "SELECT COUNT(*) FROM ("
                "SELECT submission FROM independent_evaluation_evidence WHERE round=? UNION "
                "SELECT submission FROM void_evaluation_evidence WHERE round=?)",
                (round_id, round_id),
            ).fetchone()[0]
            has_results = (
                connection.execute(
                    "SELECT 1 FROM evaluation_results WHERE round=? LIMIT 1",
                    (round_id,),
                ).fetchone()
                is not None
            )
            settlement = connection.execute(
                "SELECT digest FROM competition_settlements WHERE round=?",
                (round_id,),
            ).fetchone()
            conflicted = (
                connection.execute(
                    "SELECT 1 FROM round_conflicts WHERE round=?",
                    (round_id,),
                ).fetchone()
                is not None
            )
            disputed = (
                conflicted
                or connection.execute(
                    "SELECT 1 FROM settlement_disputes WHERE round=?",
                    (round_id,),
                ).fetchone()
                is not None
            )
            state = "prepared"
            if outcome_count or has_results:
                state = "evaluating"
            if settlement is not None:
                state = "closed_computed_uncertified"
            items.append(
                {
                    "round_sha256": round_id,
                    "sequence": sequence,
                    "policy_sha256": round_.policy_sha256,
                    "state": state,
                    "public_schedule": round_.public_schedule.model_dump(
                        mode="json", by_alias=True
                    ),
                    "submission_close_block": round_.submission_close_block,
                    "eligible_tracks": list(round_.eligible_tracks),
                    "roster_count": len(round_.roster),
                    "independent_result_count": result_count,
                    "void_count": void_count,
                    "outcome_count": outcome_count,
                    "conflicted": conflicted,
                    "disputed": disputed,
                    "settlement_sha256": None if settlement is None else settlement[0],
                    "certification": "not_checked",
                    "round_url": f"/v1/competition/rounds/{round_id}",
                    "settlement_url": (
                        None if settlement is None else f"/v1/competition/settlements/{round_id}"
                    ),
                    "chain_submission_authorized": False,
                }
            )
    return {
        "schema": "umi-competition-round-index/1",
        "source": "configured_intake_store",
        "policy_sha256": policy_sha256,
        "items": items,
        "limit": limit,
        "before_sequence": before_sequence,
        "next_before_sequence": items[-1]["sequence"] if len(rows) > limit else None,
        "chain_submission_authorized": False,
    }
