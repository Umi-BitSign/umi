"""Offline native score replay, streaming one retained outcome at a time.

Reads only a consistent query-only intake snapshot. No journal constructors,
inference, signing, finality collection, projected weights or payment authority.
"""

from __future__ import annotations

import sqlite3
from contextlib import closing, contextmanager
from fractions import Fraction
from pathlib import Path
from typing import Annotated

from pydantic import Field

from .competition_evidence import IndependentEvaluationEvidence
from .competition_outcomes import binding_ids, outcome_binding, outcome_storage, replay_outcome
from .competition_policy_lineage import replay_lineage
from .competition_public_results import PublicQuality, PublicSettlementScores
from .competition_round_discovery import MAXIMUM_ROUND_BYTES
from .competition_settlement import (
    CompetitionSettlement,
    EvidenceCutoffSchedule,
    competition_settlement_digest,
)
from .competition_void import VoidEvaluationEvidence
from .open_competition import (
    CompetitionPolicy,
    EvaluationRound,
    SignedSubmission,
    StrictProtocolModel,
    aggregate_quality,
    digest,
    identity,
)
from .policy import ScoringPolicy, scoring_policy_hash, validate_scoring_runtime


class PublicResultsExportLimits(StrictProtocolModel):
    maximum_record_bytes: Annotated[int, Field(ge=1024, le=512 * 1024**2)] = 64 * 1024**2
    maximum_evidence_bytes: Annotated[int, Field(ge=1024, le=16 * 1024**3)] = 512 * 1024**2
    maximum_roster_bytes: Annotated[int, Field(ge=1024, le=512 * 1024**2)] = 16 * 1024**2


@contextmanager
def readonly_snapshot(database: Path):
    if (
        not database.is_absolute()
        or database.resolve() != database
        or database.is_symlink()
        or not database.is_file()
    ):
        raise ValueError("export needs an existing absolute database without symlinks")
    with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True, timeout=5)) as db:
        db.execute("PRAGMA query_only=ON")
        db.execute("BEGIN")
        yield db


def _body(db, table, column, key, maximum):
    # Identifiers are private constants chosen below, never supplied by a request.
    row = db.execute(
        f"SELECT CASE WHEN length(body)<=? THEN body END FROM {table} WHERE {column}=?",
        (maximum, key),
    ).fetchone()
    if row is None or row[0] is None:
        raise ValueError("required retained export input is missing or exceeds its byte bound")
    return row[0]


def _fraction(value: Fraction):
    return dict(
        numerator=str(value.numerator), denominator=str(value.denominator), decimal=float(value)
    )


def _metrics(strata, policy):
    return dict(
        aggregate=_fraction(aggregate_quality(strata, policy)),
        by_stratum={name: _fraction(value) for name, value in strata.items()},
    )


def export_round(
    database: Path,
    round_id: str,
    *,
    policy: CompetitionPolicy,
    scoring_policy: ScoringPolicy,
    predecessors: tuple[CompetitionPolicy, ...] = (),
    limits: PublicResultsExportLimits | None = None,
) -> PublicSettlementScores:
    """Validate every scored/void binding; export only public aggregate fields.

    This verifies score evidence, not the settlement projection or certificate.
    Retained first-observation blocks are checked, never rewritten as fresh ones.
    """
    limits = limits or PublicResultsExportLimits()
    validate_scoring_runtime(scoring_policy)
    checked_scoring = {scoring_policy_hash(scoring_policy)}
    with readonly_snapshot(database) as db, replay_lineage(policy, predecessors):
        round_ = EvaluationRound.model_validate_json(
            _body(db, "rounds", "digest", round_id, MAXIMUM_ROUND_BYTES)
        )
        settlement = CompetitionSettlement.model_validate_json(
            _body(db, "competition_settlements", "round", round_id, limits.maximum_record_bytes)
        )
        settlement_id = db.execute(
            "SELECT digest FROM competition_settlements WHERE round=?", (round_id,)
        ).fetchone()[0]
        cutoff = EvidenceCutoffSchedule.model_validate_json(
            _body(db, "evidence_cutoff_schedules", "round", round_id, MAXIMUM_ROUND_BYTES)
        )
        if (
            digest(round_) != round_id
            or round_.policy_sha256 != digest(policy)
            or settlement.policy_sha256 != digest(policy)
            or settlement.round_sha256 != round_id
            or competition_settlement_digest(settlement) != settlement_id
            or settlement.roster != round_.roster
            or digest(settlement.suite) != round_.suite_sha256
            or settlement.cutoff_schedule != cutoff
            or not round_.reveal_block
            <= cutoff.evidence_cutoff_block
            <= settlement.observed_block
            <= round_.valid_through_block
        ):
            raise ValueError("retained public score settlement binding mismatch")
        registrations = {
            identity(row.hotkey): row.uid for row in settlement.registration_snapshot.registrations
        }
        rows, roster_bytes, evidence_bytes = [], 0, 0
        for binding in settlement.results:
            sid = binding.submission_sha256
            raw = _body(
                db, "submissions", "digest", sid, limits.maximum_roster_bytes - roster_bytes
            )
            roster_bytes += len(raw)
            signed = SignedSubmission.model_validate_json(raw)
            if digest(signed.submission) != sid:
                raise ValueError("retained score submission binding mismatch")
            table, decision = outcome_storage(binding)
            decision_id, evidence_id = binding_ids(binding)
            raw = _body(
                db,
                table,
                "digest",
                evidence_id,
                min(limits.maximum_record_bytes, limits.maximum_evidence_bytes - evidence_bytes),
            )
            evidence_bytes += len(raw)
            model = (
                VoidEvaluationEvidence
                if table == "void_evaluation_evidence"
                else IndependentEvaluationEvidence
            )
            evidence = model.model_validate_json(raw)
            retained = db.execute(
                f"SELECT round,submission,{decision},first_observed_block "
                f"FROM {table} WHERE digest=?",
                (evidence_id,),
            ).fetchone()
            if (
                retained != (round_id, sid, decision_id, binding.first_observed_block)
                or outcome_binding(sid, evidence, binding.first_observed_block) != binding
                or not round_.reveal_block
                <= binding.first_observed_block
                <= cutoff.evidence_cutoff_block
            ):
                raise ValueError("retained score evidence/observation binding mismatch")
            if isinstance(evidence, VoidEvaluationEvidence) and evidence.legacy_policy is not None:
                legacy_id = scoring_policy_hash(evidence.legacy_policy)
                if legacy_id not in checked_scoring:
                    validate_scoring_runtime(evidence.legacy_policy)
                    checked_scoring.add(legacy_id)
            quality = replay_outcome(
                evidence,
                signed,
                round_,
                settlement.suite,
                policy,
                current_block=settlement.observed_block,
            )
            scored = isinstance(evidence, IndependentEvaluationEvidence)
            rows.append(
                dict(
                    submission_sha256=sid,
                    hotkey=signed.submission.hotkey,
                    uid=registrations.get(identity(signed.submission.hotkey)),
                    track=signed.submission.track,
                    status="scored" if scored else "void",
                    result_sha256=decision_id if scored else None,
                    independent_evidence_sha256=evidence_id if scored else None,
                    void_decision_sha256=None if scored else decision_id,
                    void_evidence_sha256=None if scored else evidence_id,
                    first_observed_block=binding.first_observed_block,
                    candidate=_metrics(quality[0], policy) if scored else None,
                    incumbent=_metrics(quality[1], policy) if scored else None,
                    score_rank=None,
                )
            )
            # Do not retain previous private evidence while parsing the next record.
            del evidence, raw, quality, signed
        scores = {
            row["submission_sha256"]: PublicQuality(**row["candidate"]["aggregate"]).fraction()
            for row in rows
            if row["candidate"] is not None
        }
        for row in rows:
            if row["candidate"] is not None:
                row["score_rank"] = 1 + sum(
                    other["track"] == row["track"]
                    and other["candidate"] is not None
                    and scores[other["submission_sha256"]] > scores[row["submission_sha256"]]
                    for other in rows
                )
        return PublicSettlementScores(
            schema="umi-competition-public-results/2",
            round_sha256=round_id,
            policy_sha256=digest(policy),
            settlement_sha256=settlement_id,
            observed_block=settlement.observed_block,
            scoring_method="native_replay_evaluation_at_settlement_observed_block",
            chain_submission_authorized=False,
            items=tuple(rows),
        )
