"""Review original request completion before native phase certification."""

from .competition_cohort_admission_queue import CohortAdmissionQueue
from .competition_cohort_admission_review import review_cohort_participation
from .competition_cohort_request_phase import (
    NativeRequestProgressSource,
    RequestProgressReviewRecord,
)
from .competition_cohort_request_tail import verify_request_tail_clock
from .competition_execution import execution_boundary
from .competition_progress import log_phase
from .concurrency import run_owned_thread
from .open_competition import digest


class RequestProgressReviewer:
    """Runs beside the configured native owner with this reviewer's proof port.

    The observer's local readiness history is an explicit operational trust
    boundary. Hashes do not make a remote status flag proof of service. Terminal
    execution is replayed through its original signed evidence and certificates.
    """

    def __init__(self, source: NativeRequestProgressSource, provider, archive):
        if provider.policy != source.intake.policy:
            raise ValueError("request reviewer finality belongs to another policy")
        self.source, self.provider, self.archive = source, provider, archive
        self.policy, self.cohorts = source.intake.policy, source.intake.config.cohorts
        self.queue = CohortAdmissionQueue(source.intake)

    async def decision(self, transition, evidence):
        return await run_owned_thread(self.source.decision, transition, evidence)

    @log_phase("cohort_request_completion_review")
    async def review(self, progress) -> RequestProgressReviewRecord:
        original = await run_owned_thread(self.source.read, progress)
        observations = [original.record.service.observation]
        if original.record.fence is not None:
            observations.append(original.record.fence.observation)
        if original.record.tail_fence is not None:
            observations.append(original.record.tail_fence.observation)
        if original.tail is not None and original.tail.selected_observation is not None:
            observations.append(original.tail.selected_observation)
        observations.extend(d.observation for d in original.decisions)
        observations.extend(original.inventory_observations)
        seal = self.source.roster.intake_seal
        if progress.completion == "complete":
            observations.append(seal.observation)
        checked = {}
        for observation in observations:
            key = digest(observation)
            if key in checked:
                continue
            raw, metadata = await self.archive(observation)
            checked[key] = await self.provider.review_archive(observation, raw, metadata)
            if (
                checked[key].original != observation
                or checked[key].replayed_at.block_number < observation.block
            ):
                raise ValueError("request proof differs from its original observation")
        for tail in (original.tail, original.record.tail_fence):
            if tail is None:
                continue
            verify_request_tail_clock(
                tail,
                checked[digest(tail.opened_observation)],
                checked[digest(tail.observation)],
                None
                if tail.selected_observation is None
                else checked[digest(tail.selected_observation)],
            )
        if progress.completion == "complete":
            if checked[digest(seal.observation)].snapshot != seal.snapshot:
                raise ValueError("request roster seal changed its original registration")
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
            raise ValueError("request completion is ahead of owned finality")
        replay = await run_owned_thread(self.source.read, progress)
        if replay != original:
            raise OSError("request history changed during independent review")
        return original.record
