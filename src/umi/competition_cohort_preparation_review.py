"""Independent original-proof review before certifying a prepared round."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from .competition_cohort_admission_review import review_cohort_participation
from .competition_cohort_coordinator import CohortPhaseProgress
from .competition_cohort_preparation_phase import (
    NativePreparationProgressSource,
    PreparationProgressReviewRecord,
)
from .competition_execution import ExecutionBoundary, execution_boundary
from .competition_historical_registration import HistoricalRegistrationProvider
from .competition_progress import log_phase
from .concurrency import run_owned_thread
from .open_competition import digest


class PreparationProgressReviewer:
    def __init__(
        self,
        source: NativePreparationProgressSource,
        provider: HistoricalRegistrationProvider,
        archive: Callable[[ExecutionBoundary], Awaitable[tuple[bytes, bytes]]],
    ):
        if provider.policy != source.intake.policy:
            raise ValueError("preparation reviewer finality belongs to another policy")
        self.source, self.provider, self.archive = source, provider, archive
        self.queue = source.owner.queue

    @log_phase("cohort_preparation_review")
    async def review(self, progress: CohortPhaseProgress) -> PreparationProgressReviewRecord:
        original = await run_owned_thread(self.source.read, progress)
        prepared = original.prepared
        seal = prepared.roster.intake_seal
        observations = (
            seal.observation,
            prepared.observation,
            original.record.evidence.observation,
            *(d.observation for d in original.decisions),
        )
        checked = {}
        for observation in observations:
            key = digest(observation)
            if key not in checked:
                raw, metadata = await self.archive(observation)
                checked[key] = await self.provider.review_archive(observation, raw, metadata)
        if checked[digest(seal.observation)].snapshot != seal.snapshot:
            raise ValueError("prepared intake differs from independently verified registration")
        # All original consents, including superseded and unregistered records,
        # participate in the seal. A selected-only proof export is incomplete.
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
        current = execution_boundary(await self.provider.collect())
        if current.block < progress.observed_at_block:
            raise ValueError("preparation progress is ahead of owned finality")
        replay = await run_owned_thread(self.source.read, progress)
        if replay != original:
            raise OSError("preparation history changed during independent review")
        return original.record
