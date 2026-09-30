"""Independent original-proof review before native request-phase voting."""

from __future__ import annotations

import secrets
from collections.abc import Awaitable, Callable
from functools import partial

from .competition_cohort_admission_review import review_cohort_participation
from .competition_cohort_coordinator import (
    CohortDecisionInput,
    CohortPhaseProgress,
    _choice,
    replay_cohort_decisions,
)
from .competition_cohort_intake import CohortIntakeBinding
from .competition_cohort_recovery import CohortRecoveryTransition
from .competition_cohort_request_export import (
    RequestReviewExport,
    RequestReviewRequest,
    SignedRequestReviewResponse,
    replay_request_export,
)
from .competition_cohort_request_phase import NativeRequestReview, RequestProgressReviewRecord
from .competition_cohort_review_export import (
    MAX_EXPORT_BYTES,
    review_export_limits,
    review_selection,
)
from .competition_cohort_roster import RecoverableRosterEvidence
from .competition_cohort_service_work import SignedServiceWorkCatalog
from .competition_execution import ExecutionBoundary, execution_boundary
from .competition_historical_registration import HistoricalRegistrationProvider
from .concurrency import run_owned_thread, wait_for_owned
from .open_competition import digest, identity, verify_signature
from .policy import ScoringPolicy
from .protocol import canonical_json_bytes


class RemoteRequestProgressReviewer:
    """One configured owner of the original service observations and queue seals.

    The host selects certified preparation and catalog inputs independently;
    the owner response may not replace those selections. Archive delivery is
    separate from the owner's completion claim and uses this reviewer's proof
    verifier. No journal or local path is accepted from the remote owner.
    """

    def __init__(
        self,
        provider: HistoricalRegistrationProvider,
        cohorts: tuple[CohortIntakeBinding, ...],
        owner: str,
        fetch: Callable[[RequestReviewRequest], Awaitable[bytes]],
        archive: Callable[[ExecutionBoundary], Awaitable[tuple[bytes, bytes]]],
        *,
        roster: RecoverableRosterEvidence,
        catalogs: tuple[SignedServiceWorkCatalog, ...],
        transport: ScoringPolicy,
        maximum_sample_gap_blocks: int = 10,
        maximum_bytes: int = MAX_EXPORT_BYTES,
        timeout_seconds: int = 30,
    ):
        review_export_limits(maximum_bytes, timeout_seconds)
        if type(maximum_sample_gap_blocks) is not int or not 1 <= maximum_sample_gap_blocks <= 300:
            raise ValueError("request export sampling gap is outside bounds")
        self.policy, self.cohorts, self.owner = review_selection(provider.policy, cohorts, owner)
        self.roster = RecoverableRosterEvidence.model_validate_json(canonical_json_bytes(roster))
        self.catalogs = tuple(
            SignedServiceWorkCatalog.model_validate_json(canonical_json_bytes(c)) for c in catalogs
        )
        self.transport = ScoringPolicy.model_validate_json(canonical_json_bytes(transport))
        keys = tuple(digest(c.catalog) for c in self.catalogs)
        if not 1 <= len(keys) <= 64 or keys != tuple(sorted(set(keys))):
            raise ValueError("request review requires every selected catalog once")
        if self.roster.round.cohort_sha256 not in {c.cohort_sha256 for c in self.cohorts}:
            raise ValueError("request roster is outside configured cohorts")
        self.provider, self.fetch, self.archive = provider, fetch, archive
        self.gap, self.maximum_bytes, self.timeout_seconds = (
            maximum_sample_gap_blocks,
            maximum_bytes,
            timeout_seconds,
        )

    async def _read(
        self, progress: CohortPhaseProgress
    ) -> tuple[RequestReviewExport, NativeRequestReview]:
        progress = CohortPhaseProgress.model_validate_json(canonical_json_bytes(progress))
        bindings = {c.cohort_sha256: c.authority_sha256 for c in self.cohorts}
        if (
            progress.phase != "requests"
            or progress.cohort_sha256 != self.roster.round.cohort_sha256
        ):
            raise ValueError("request review is outside configured cohort or phase")
        request = RequestReviewRequest(
            schema="umi-request-review-request/1",
            challenge=secrets.token_hex(32),
            progress=progress,
        )
        raw = await wait_for_owned(self.fetch(request), timeout=self.timeout_seconds)
        if type(raw) is not bytes or not 0 < len(raw) <= self.maximum_bytes:
            raise ValueError("request response exceeds its byte bound")
        signed = SignedRequestReviewResponse.model_validate_json(raw)
        response, signature = signed.response, signed.signature
        if canonical_json_bytes(signed) != raw or identity(signature.hotkey) != self.owner:
            raise ValueError("request response is not canonical or changes its selected owner")
        verify_signature(response, signature)
        exported = response.evidence
        if (
            response.challenge != request.challenge
            or exported.record.progress != progress
            or digest(exported.history.authority.authority) != bindings[progress.cohort_sha256]
        ):
            raise ValueError(
                "request response changes its challenge, progress or approved authority"
            )
        replay = await run_owned_thread(
            partial(
                replay_request_export,
                exported,
                self.policy,
                roster=self.roster,
                catalogs=self.catalogs,
                transport=self.transport,
                maximum_sample_gap_blocks=self.gap,
                maximum_bytes=self.maximum_bytes,
            )
        )
        return exported, replay

    async def review(self, progress: CohortPhaseProgress) -> RequestProgressReviewRecord:
        exported, original = await self._read(progress)
        observations = [
            original.record.service.observation,
            *(d.observation for d in original.decisions),
        ]
        if original.record.fence is not None:
            observations.append(original.record.fence.observation)
        seal = self.roster.intake_seal
        if progress.completion == "complete":
            observations.extend([seal.observation, *(s.observation for s in exported.seals)])
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
        if progress.completion == "complete":
            if checked[digest(seal.observation)].snapshot != seal.snapshot:
                raise ValueError("request roster seal changed its original registration")
            for record in exported.records:
                proof = await self.archive(record.observation)
                await review_cohort_participation(
                    canonical_json_bytes(record),
                    original.history,
                    self.policy,
                    self.provider,
                    expected_tip_sha256=progress.recovery_tip_sha256,
                    registration_archive=proof,
                )
        if execution_boundary(await self.provider.collect()).block < progress.observed_at_block:
            raise ValueError("request completion is ahead of owned finality")
        repeated, replay = await self._read(progress)
        if repeated != exported or replay != original:
            raise OSError("request history changed during independent review")
        return original.record

    async def decision(
        self, transition: CohortRecoveryTransition, evidence: CohortDecisionInput
    ) -> str:
        exported, original = await self._read(evidence.progress.progress)
        if evidence.observation != original.record.service.observation:
            raise ValueError("request decision changed its original finalized observation")
        sources = {digest(d): d for d in exported.decisions}
        state, restored, prior = replay_cohort_decisions(
            exported.history, self.policy, sources.__getitem__
        )
        expected, _ = _choice(
            state, exported.history.authority.authority, self.policy, evidence, restored, prior
        )
        if transition != expected:
            raise ValueError("request decision differs from native completion")
        return original.record.history_sha256
