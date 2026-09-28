"""Review native intake progress using owned records and historical proofs.

The configured intake is the source of service observations, not a peer's status
JSON. Its hash chain accounts for unknown intervals; it does not prove network
availability independently. Each reviewer owns its finality provider and checks
the original consent and seal registration proofs before approving closure.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from pydantic import Field

from .competition_cohort_admission_queue import CohortAdmissionQueue
from .competition_cohort_admission_review import review_cohort_participation
from .competition_cohort_availability import (
    CohortAvailabilityObservation,
    CohortServiceAvailability,
    pending_availability_progress,
)
from .competition_cohort_coordinator import (
    CohortDecisionInput,
    CohortPhaseProgress,
    _choice,
    replay_cohort_decisions,
)
from .competition_cohort_history import CohortRecoveryHistory
from .competition_cohort_intake import CohortIntake, history_tip
from .competition_cohort_intake_seal import CohortIntakeSeal
from .competition_cohort_recovery import CohortRecoveryTransition
from .competition_execution import ExecutionBoundary, execution_boundary
from .competition_historical_registration import HistoricalRegistrationProvider
from .competition_progress import log_phase
from .concurrency import run_owned_thread
from .open_competition import digest
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


class IntakeProgressReviewRecord(StrictProtocolModel):
    schema_: Literal["umi-intake-progress-review/1"] = Field(alias="schema")
    progress: CohortPhaseProgress
    history_sha256: Hex32
    service: CohortAvailabilityObservation
    seal_sha256: Hex32 | None


@dataclass(frozen=True)
class NativeIntakeReview:
    record: IntakeProgressReviewRecord
    history: CohortRecoveryHistory
    seal: CohortIntakeSeal | None
    consents: tuple[str, ...]


class NativeIntakeProgressSource:
    """Read through the intake owner's lock; never inspect another live journal.

    This adapter runs inside the configured intake owner. A remote reviewer
    needs an authenticated owner export of the same evidence, not filesystem
    access to the running coordinator's SQLite database.
    """

    def __init__(self, intake: CohortIntake, *, maximum_sample_gap_blocks: int = 10):
        self.intake, self.gap = intake, maximum_sample_gap_blocks

    def read(self, progress: CohortPhaseProgress) -> NativeIntakeReview:
        progress = CohortPhaseProgress.model_validate_json(canonical_json_bytes(progress))
        cohort = progress.cohort_sha256
        self.intake._allowed(cohort)
        with self.intake._connection() as (db, store):
            history = store.published_history(cohort)
            state, restored, prior = replay_cohort_decisions(
                history,
                self.intake.policy,
                lambda key: store.source(cohort, key, CohortDecisionInput),
            )
            if (
                state.phase != "intake"
                or progress.phase != "intake"
                or progress.recovery_tip_sha256 != history_tip(history)
                or progress.observed_at_block < state.observed_at_block
            ):
                raise ValueError("intake progress differs from the owned current history")
            availability = CohortServiceAvailability(
                store, self.intake.policy, maximum_sample_gap_blocks=self.gap
            )
            # Replay the entire retained chain, including sequence and cumulative
            # outage accounting. A later sample may coexist with an older vote.
            availability._last(cohort, "intake")
            seal = None
            if progress.completion == "complete":
                seal = self.intake._seal(db, history, state.tip_sha256)
                if seal is None or (
                    progress.phase_result_sha256 != digest(seal)
                    or progress.evidence_sha256 != digest(seal)
                ):
                    raise ValueError("intake progress lacks its exact native seal")
                row = db.execute(
                    "SELECT substr(body,1,16385) FROM cohort_intake_service_seals "
                    "WHERE cohort=? AND tip=?",
                    (cohort, state.tip_sha256),
                ).fetchone()
                if row is None:
                    raise ValueError("intake seal lacks its retained service observation")
                raw = row[0]
            else:
                raw = next(
                    (
                        row[0]
                        for row in db.execute(
                            "SELECT substr(body,1,16385) FROM cohort_service_observations "
                            "WHERE cohort=? AND phase='intake' ORDER BY sequence DESC",
                            (cohort,),
                        )
                        if digest(CohortAvailabilityObservation.model_validate_json(row[0]))
                        == progress.evidence_sha256
                    ),
                    None,
                )
                if raw is None:
                    raise ValueError("intake progress has no retained service observation")
            service = CohortAvailabilityObservation.model_validate_json(raw)
            retained = db.execute(
                "SELECT substr(body,1,16385) FROM cohort_service_observations "
                "WHERE cohort=? AND phase='intake' AND sequence=?",
                (cohort, service.sequence),
            ).fetchone()
            if (
                len(raw) > 16384
                or canonical_json_bytes(service) != raw
                or retained != (raw,)
                or service.cohort_sha256 != cohort
                or service.recovery_tip_sha256 != state.tip_sha256
                or service.phase != "intake"
                or service.unavailable_blocks != progress.unavailable_blocks
                or service.unavailable_blocks < max(restored, prior)
            ):
                raise ValueError("intake progress differs from its original service evidence")
            if seal is None:
                if pending_availability_progress(state, service) != progress:
                    raise ValueError("pending intake progress changed its original observation")
            elif (
                not service.serving
                or service.observation != seal.observation
                or seal.observation.block > progress.observed_at_block
                or seal.observation.block
                < state.targets[0].target_block + service.unavailable_blocks - restored
            ):
                raise ValueError("intake closed before restoring unavailable service")
            # _seal already reconstructs membership from every original record.
            # Review registration proofs for all records, including superseded
            # submissions and currently unregistered participants.
            consents = (
                tuple(key for key, _ in self.intake._records(db, history))
                if seal is not None
                else ()
            )
            return NativeIntakeReview(
                IntakeProgressReviewRecord(
                    schema="umi-intake-progress-review/1",
                    progress=progress,
                    history_sha256=digest(history),
                    service=service,
                    seal_sha256=None if seal is None else digest(seal),
                ),
                history,
                seal,
                consents,
            )

    def decision(self, transition: CohortRecoveryTransition, evidence: CohortDecisionInput):
        """Recompute the exact proposed transition from the owned decision history."""
        cohort = transition.cohort_sha256
        self.intake._allowed(cohort)
        with self.intake._connection() as (_, store):
            history = store.published_history(cohort)
            state, restored, prior = replay_cohort_decisions(
                history,
                self.intake.policy,
                lambda key: store.source(cohort, key, CohortDecisionInput),
            )
            expected, _ = _choice(
                state,
                history.authority.authority,
                self.intake.policy,
                evidence,
                restored,
                prior,
            )
            if state.phase != "intake" or transition != expected:
                raise ValueError("intake decision differs from its owned history and progress")
            return digest(history)


class IntakeProgressReviewer:
    def __init__(
        self,
        source: NativeIntakeProgressSource,
        provider: HistoricalRegistrationProvider,
        archive,
    ):
        if provider.policy != source.intake.policy:
            raise ValueError("intake reviewer finality belongs to another policy")
        self.source, self.provider, self.archive = source, provider, archive
        self.queue = CohortAdmissionQueue(source.intake)

    @log_phase("cohort_intake_review")
    async def review(self, progress: CohortPhaseProgress) -> IntakeProgressReviewRecord:
        """Recheck owned history after proof I/O, before reserving a signature.

        archive is the owner's retained-registration export. Proof bytes from
        that port gain no authority until this reviewer's provider checks them.
        The owner must retain consent/seal archives across process restarts.
        """
        original = await run_owned_thread(self.source.read, progress)
        if original.seal is not None:
            evidence, metadata = await self.archive(original.seal.observation)
            registration = await self.provider.review_archive(
                original.seal.observation, evidence, metadata
            )
            if registration.snapshot != original.seal.snapshot:
                raise ValueError("intake seal differs from independently reviewed registration")
            for consent in original.consents:
                raw, evidence, metadata = await run_owned_thread(
                    self.queue.evidence, progress.cohort_sha256, consent
                )
                await review_cohort_participation(
                    raw,
                    original.history,
                    self.source.intake.policy,
                    self.provider,
                    expected_tip_sha256=progress.recovery_tip_sha256,
                    registration_archive=(evidence, metadata),
                )
        current: ExecutionBoundary = execution_boundary(await self.provider.collect())
        if current.block < progress.observed_at_block:
            raise ValueError("intake progress is ahead of owned finality")
        checked = await run_owned_thread(self.source.read, progress)
        if checked != original:
            raise OSError("intake history changed during review; retry current progress")
        return original.record
