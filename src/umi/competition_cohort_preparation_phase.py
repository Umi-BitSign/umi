"""Retained preparation observations through the native intake owner.

The prepared round remains fixed. Each new progress observation uses the owner's
finalized capture; the recovery controller reserves it before quorum signing.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from pydantic import Field

from .competition_chain import RegistrationCapture
from .competition_cohort_coordinator import (
    CohortDecisionInput,
    CohortPhaseProgress,
    _choice,
    replay_cohort_decisions,
)
from .competition_cohort_history import CohortRecoveryHistory
from .competition_cohort_intake import history_tip
from .competition_cohort_preparation import PreparedCohortRound
from .competition_cohort_preparation_owner import CohortPreparation
from .competition_cohort_recovery import CohortRecoveryState, CohortRecoveryTransition
from .competition_execution import ExecutionBoundary, execution_boundary
from .concurrency import run_owned_thread
from .open_competition import digest
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


class PreparationProgressEvidence(StrictProtocolModel):
    schema_: Literal["umi-preparation-progress-evidence/1"] = Field(alias="schema")
    prepared_sha256: Hex32
    observation: ExecutionBoundary


class PreparationProgressReviewRecord(StrictProtocolModel):
    schema_: Literal["umi-preparation-progress-review/1"] = Field(alias="schema")
    progress: CohortPhaseProgress
    history_sha256: Hex32
    evidence: PreparationProgressEvidence


@dataclass(frozen=True)
class NativePreparationReview:
    record: PreparationProgressReviewRecord
    history: CohortRecoveryHistory
    prepared: PreparedCohortRound
    consents: tuple[str, ...]
    decisions: tuple[CohortDecisionInput, ...]


def _progress(history, state, prior, restored, evidence, prepared):
    if (
        state.phase != "preparation"
        or state.tip_sha256 != history_tip(history)
        or evidence.prepared_sha256 != digest(prepared)
        or evidence.observation.block < max(state.observed_at_block, prepared.observation.block)
    ):
        raise ValueError("preparation progress differs from its round or owned history")
    return CohortPhaseProgress(
        schema="umi-cohort-phase-progress/1",
        cohort_sha256=digest(history.plan),
        recovery_tip_sha256=state.tip_sha256,
        phase="preparation",
        observed_at_block=evidence.observation.block,
        unavailable_blocks=max(prior, restored),
        completion="complete",
        phase_result_sha256=digest(prepared.roster.round),
        evidence_sha256=digest(evidence),
    )


class NativePreparationProgressSource:
    """Runs inside the configured intake owner; remote peers need owner exports."""

    def __init__(self, owner: CohortPreparation):
        self.owner, self.intake = owner, owner.queue.intake

    async def sample(
        self, state: CohortRecoveryState, capture: RegistrationCapture
    ) -> CohortPhaseProgress:
        return await run_owned_thread(self.observe, state, capture)

    def observe(
        self, state: CohortRecoveryState, capture: RegistrationCapture
    ) -> CohortPhaseProgress:
        cohort = state.cohort_sha256
        prepared = self.owner.prepare(cohort, capture, expected_tip_sha256=state.tip_sha256)
        evidence = PreparationProgressEvidence(
            schema="umi-preparation-progress-evidence/1",
            prepared_sha256=digest(prepared),
            observation=execution_boundary(capture),
        )
        with self.owner.queue._connection() as (db, store):
            history = store.published_history(cohort)
            current, restored, prior = replay_cohort_decisions(
                history,
                self.intake.policy,
                lambda key: store.source(cohort, key, CohortDecisionInput),
            )
            if current != state:
                raise OSError("preparation history changed before observation")
            progress = _progress(history, state, prior, restored, evidence, prepared)
            db.execute(
                "CREATE TABLE IF NOT EXISTS cohort_preparation_progress "
                "(cohort TEXT NOT NULL, digest TEXT NOT NULL, observed INTEGER NOT NULL, "
                "body BLOB NOT NULL, PRIMARY KEY(cohort,digest))"
            )
            raw = canonical_json_bytes(evidence)
            with self.owner.queue._transaction(db):
                old = db.execute(
                    "SELECT observed,substr(body,1,16385) FROM cohort_preparation_progress "
                    "WHERE cohort=? AND digest=?",
                    (cohort, digest(evidence)),
                ).fetchone()
                if old is not None and old != (evidence.observation.block, raw):
                    raise ValueError("retained preparation observation changed")
                db.execute(
                    "INSERT OR IGNORE INTO cohort_preparation_progress VALUES (?,?,?,?)",
                    (cohort, digest(evidence), evidence.observation.block, raw),
                )
            return progress

    def read(self, progress: CohortPhaseProgress) -> NativePreparationReview:
        progress = CohortPhaseProgress.model_validate_json(canonical_json_bytes(progress))
        cohort = progress.cohort_sha256
        self.intake._allowed(cohort)
        with self.owner.queue._connection() as (db, store):
            history = store.published_history(cohort)
            decisions = tuple(
                store.source(cohort, s.transition.evidence_sha256, CohortDecisionInput)
                for s in history.transitions
                if s.transition.operation != "revoke"
            )
            sources = {digest(d): d for d in decisions}
            state, restored, prior = replay_cohort_decisions(
                history, self.intake.policy, sources.__getitem__
            )
            if state.phase != "preparation" or progress.recovery_tip_sha256 != state.tip_sha256:
                raise ValueError("preparation review requires its active owned history")
            if not db.execute(
                "SELECT 1 FROM sqlite_master "
                "WHERE type='table' AND name='cohort_preparation_progress'"
            ).fetchone():
                raise FileNotFoundError("preparation observation has not been retained")
            row = db.execute(
                "SELECT observed,substr(body,1,16385) FROM cohort_preparation_progress "
                "WHERE cohort=? AND digest=?",
                (cohort, progress.evidence_sha256),
            ).fetchone()
            if row is None:
                raise FileNotFoundError("preparation observation has not been retained")
            evidence = PreparationProgressEvidence.model_validate_json(row[1])
            if (
                len(row[1]) > 16384
                or canonical_json_bytes(evidence) != row[1]
                or digest(evidence) != progress.evidence_sha256
                or row[0] != evidence.observation.block
            ):
                raise ValueError("preparation observation differs from its retained identity")
            consents = tuple(key for key, _ in self.intake._records(db, history))
        prepared = self.owner.retained(
            cohort,
            expected_tip_sha256=progress.recovery_tip_sha256,
            current_block=evidence.observation.block,
        )
        if _progress(history, state, prior, restored, evidence, prepared) != progress:
            raise ValueError("preparation progress differs from its native evidence")
        return NativePreparationReview(
            PreparationProgressReviewRecord(
                schema="umi-preparation-progress-review/1",
                progress=progress,
                history_sha256=digest(history),
                evidence=evidence,
            ),
            history,
            prepared,
            consents,
            decisions,
        )

    def decision(self, transition: CohortRecoveryTransition, evidence: CohortDecisionInput) -> str:
        reviewed = self.read(evidence.progress.progress)
        if evidence.observation != reviewed.record.evidence.observation:
            raise ValueError("preparation decision changed its original finalized observation")
        sources = {digest(d): d for d in reviewed.decisions}
        state, restored, prior = replay_cohort_decisions(
            reviewed.history, self.intake.policy, sources.__getitem__
        )
        expected, _ = _choice(
            state,
            reviewed.history.authority.authority,
            self.intake.policy,
            evidence,
            restored,
            prior,
        )
        if transition != expected:
            raise ValueError("preparation decision differs from native progress")
        return digest(reviewed.history)
