"""Independent preparation review from the native owner's bounded export.

The reviewer reconstructs the original round using its own reviewed promotion
history and original registration archives. The owner supplies neither executable
code nor access to its live stores. Fresh signed challenges recheck owner history
after proof replay; missing evidence or delivery never expires a cohort.
"""

from __future__ import annotations

import secrets
from collections.abc import Awaitable, Callable
from typing import Annotated, Literal

from pydantic import Field

from .competition_cohort_admission_review import review_cohort_participation
from .competition_cohort_coordinator import (
    CohortDecisionInput,
    CohortPhaseProgress,
    _choice,
    replay_cohort_decisions,
)
from .competition_cohort_history import CohortRecoveryHistory
from .competition_cohort_intake import CohortIntakeBinding
from .competition_cohort_intake_records import RetainedCohortParticipation, read_participation
from .competition_cohort_preparation import PreparedCohortRound, prepare_cohort_round
from .competition_cohort_preparation_phase import (
    NativePreparationProgressSource,
    NativePreparationReview,
    PreparationProgressEvidence,
    PreparationProgressReviewRecord,
    _progress,
)
from .competition_cohort_recovery import CohortRecoveryTransition, cohort_tracks
from .competition_cohort_review_export import (
    MAX_EXPORT_BYTES,
    review_export_limits,
    review_selection,
)
from .competition_execution import ExecutionBoundary, execution_boundary
from .competition_historical_registration import HistoricalRegistrationProvider
from .competition_settlement import PromotionHeadBinding
from .competition_store import CompetitionStore
from .concurrency import run_owned_thread, wait_for_owned
from .open_competition import (
    CompetitionPolicy,
    Signature,
    Track,
    digest,
    identity,
    verify_signature,
)
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


class PreparationReviewRequest(StrictProtocolModel):
    schema_: Literal["umi-preparation-review-request/1"] = Field(alias="schema")
    challenge: Hex32
    progress: CohortPhaseProgress


class PreparationReviewExport(StrictProtocolModel):
    schema_: Literal["umi-preparation-review-export/1"] = Field(alias="schema")
    progress: CohortPhaseProgress
    history: CohortRecoveryHistory
    decisions: Annotated[tuple[CohortDecisionInput, ...], Field(max_length=128)]
    prepared: PreparedCohortRound
    evidence: PreparationProgressEvidence
    records: Annotated[tuple[RetainedCohortParticipation, ...], Field(max_length=65536)]


class PreparationReviewResponse(StrictProtocolModel):
    schema_: Literal["umi-preparation-review-response/1"] = Field(alias="schema")
    challenge: Hex32
    evidence: PreparationReviewExport


class SignedPreparationReviewResponse(StrictProtocolModel):
    response: PreparationReviewResponse
    signature: Signature


class PreparationReviewExporter:
    def __init__(
        self,
        source: NativePreparationProgressSource,
        owner: str,
        sign: Callable[[PreparationReviewResponse], Awaitable[Signature]],
        *,
        maximum_bytes: int = MAX_EXPORT_BYTES,
        timeout_seconds: int = 2400,
    ):
        review_export_limits(maximum_bytes, timeout_seconds)
        self.source, self.owner, self.sign = source, identity(owner), sign
        if self.owner not in {identity(e.hotkey) for e in source.intake.policy.evaluators}:
            raise ValueError("preparation export owner is outside the configured evaluator set")
        self.maximum_bytes, self.timeout_seconds = maximum_bytes, timeout_seconds

    def export(self, progress: CohortPhaseProgress) -> PreparationReviewExport:
        progress = CohortPhaseProgress.model_validate_json(canonical_json_bytes(progress))
        # read() checks the original observation and replays retained preparation
        # through its owner. It never creates a replacement round.
        original = self.source.read(progress)
        intake, cohort = self.source.intake, progress.cohort_sha256
        with self.source.owner.queue._connection() as (db, store):
            if store.published_history(cohort) != original.history:
                raise OSError("preparation history changed during owner export")
            records, keys, size = [], [], 0
            for key, raw in intake._records(db, original.history):
                size += len(raw)
                if size > self.maximum_bytes:
                    raise OSError(
                        "complete preparation export exceeds capacity; preserve and retry"
                    )
                keys.append(key)
                records.append(read_participation(raw))
            if tuple(keys) != original.consents:
                raise OSError("preparation inventory changed during owner export")
        result = PreparationReviewExport(
            schema="umi-preparation-review-export/1",
            progress=progress,
            history=original.history,
            decisions=original.decisions,
            prepared=original.prepared,
            evidence=original.record.evidence,
            records=tuple(records),
        )
        if len(canonical_json_bytes(result)) > self.maximum_bytes:
            raise OSError("complete preparation export exceeds capacity; preserve and retry")
        return result

    async def respond(self, request: PreparationReviewRequest) -> bytes:
        request = PreparationReviewRequest.model_validate_json(canonical_json_bytes(request))
        exported = await run_owned_thread(self.export, request.progress)
        response = PreparationReviewResponse(
            schema="umi-preparation-review-response/1",
            challenge=request.challenge,
            evidence=exported,
        )
        signature = await wait_for_owned(self.sign(response), timeout=self.timeout_seconds)
        if identity(signature.hotkey) != self.owner:
            raise ValueError("preparation export was signed by another owner")
        verify_signature(response, signature)
        raw = canonical_json_bytes(
            SignedPreparationReviewResponse(response=response, signature=signature)
        )
        if len(raw) > self.maximum_bytes:
            raise OSError("signed preparation export exceeds capacity; preserve and retry")
        return raw


def replay_preparation_export(
    exported: PreparationReviewExport,
    policy: CompetitionPolicy,
    promotion: PromotionHeadBinding,
    *,
    eligible_tracks: tuple[Track, ...],
) -> NativePreparationReview:
    decisions = {digest(d): d for d in exported.decisions}
    expected = {
        t.transition.evidence_sha256
        for t in exported.history.transitions
        if t.transition.operation != "revoke"
    }
    if len(decisions) != len(exported.decisions) or set(decisions) != expected:
        raise ValueError("preparation export needs every original decision exactly once")
    state, restored, prior = replay_cohort_decisions(
        exported.history, policy, decisions.__getitem__
    )
    progress, original = exported.progress, exported.prepared
    if (
        state.phase != "preparation"
        or progress.phase != "preparation"
        or progress.recovery_tip_sha256 != state.tip_sha256
        or progress.cohort_sha256 != digest(exported.history.plan)
    ):
        raise ValueError("preparation export differs from its current history")
    records = tuple(
        (digest(r.request.consent.consent), canonical_json_bytes(r)) for r in exported.records
    )
    if tuple(k for k, _ in records) != tuple(sorted({k for k, _ in records})):
        raise ValueError("preparation export inventory must be unique and ordered")
    # Promotion comes from the reviewer's own preserved evidence, never from an
    # unverified binding in the owner's export. Rebuild every participant too.
    selected_tracks = cohort_tracks(exported.history.plan, eligible_tracks)
    rebuilt = prepare_cohort_round(
        exported.history,
        policy,
        original.roster.intake_seal,
        original.roster.participants,
        promotion,
        original.observation,
        eligible_tracks=selected_tracks,
        decision_source=decisions.__getitem__,
        intake_records=records,
        expected_tip_sha256=progress.recovery_tip_sha256,
        current_block=progress.observed_at_block,
    )
    if rebuilt != original:
        raise ValueError("preparation export changes its original round, tracks or promotion")
    if _progress(exported.history, state, prior, restored, exported.evidence, rebuilt) != progress:
        raise ValueError("preparation progress differs from its original native evidence")
    return NativePreparationReview(
        PreparationProgressReviewRecord(
            schema="umi-preparation-progress-review/1",
            progress=progress,
            history_sha256=digest(exported.history),
            evidence=exported.evidence,
        ),
        exported.history,
        rebuilt,
        tuple(k for k, _ in records),
        exported.decisions,
    )


class RemotePreparationProgressReviewer:
    def __init__(
        self,
        provider: HistoricalRegistrationProvider,
        cohorts: tuple[CohortIntakeBinding, ...],
        owner: str,
        fetch: Callable[[PreparationReviewRequest], Awaitable[bytes]],
        archive: Callable[[ExecutionBoundary], Awaitable[tuple[bytes, bytes]]],
        promotion_store: CompetitionStore,
        *,
        eligible_tracks: tuple[Track, ...] = ("endpoint",),
        maximum_bytes: int = MAX_EXPORT_BYTES,
        maximum_promotion_bytes: int = 16 * 1024**2,
        timeout_seconds: int = 2400,
    ):
        review_export_limits(maximum_bytes, timeout_seconds)
        self.policy, self.cohorts, self.owner = review_selection(provider.policy, cohorts, owner)
        if (
            not isinstance(promotion_store, CompetitionStore)
            or promotion_store.policy != self.policy
        ):
            raise ValueError("preparation reviewer requires its own native promotion store")
        if (
            not eligible_tracks
            or tuple(eligible_tracks) != tuple(sorted(set(eligible_tracks)))
            or any(t not in ("endpoint", "model") for t in eligible_tracks)
        ):
            raise ValueError("preparation reviewer tracks must be unique and ordered")
        if (
            type(maximum_promotion_bytes) is not int
            or not 1 <= maximum_promotion_bytes <= 16 * 1024**2
        ):
            raise ValueError("preparation promotion evidence bound is invalid")
        self.provider, self.fetch, self.archive = provider, fetch, archive
        self.promotion, self.tracks = promotion_store, tuple(eligible_tracks)
        self.maximum_bytes, self.maximum_promotion_bytes, self.timeout_seconds = (
            maximum_bytes,
            maximum_promotion_bytes,
            timeout_seconds,
        )

    def _replay(self, exported: PreparationReviewExport) -> NativePreparationReview:
        original = exported.prepared.promotion_head
        selected = self.promotion.reviewed_promotion_at(
            exported.progress.cohort_sha256,
            original.promotion_sha256,
            maximum_bytes=self.maximum_promotion_bytes,
        )
        return replay_preparation_export(
            exported, self.policy, selected, eligible_tracks=self.tracks
        )

    async def _read(
        self, progress: CohortPhaseProgress
    ) -> tuple[PreparationReviewExport, NativePreparationReview]:
        progress = CohortPhaseProgress.model_validate_json(canonical_json_bytes(progress))
        bindings = {c.cohort_sha256: c.authority_sha256 for c in self.cohorts}
        if progress.cohort_sha256 not in bindings or progress.phase != "preparation":
            raise ValueError("preparation review is outside configured cohorts or phase")
        request = PreparationReviewRequest(
            schema="umi-preparation-review-request/1",
            challenge=secrets.token_hex(32),
            progress=progress,
        )
        raw = await wait_for_owned(self.fetch(request), timeout=self.timeout_seconds)
        if type(raw) is not bytes or not 0 < len(raw) <= self.maximum_bytes:
            raise ValueError("preparation response exceeds its byte bound")
        signed = SignedPreparationReviewResponse.model_validate_json(raw)
        response, signature = signed.response, signed.signature
        if canonical_json_bytes(signed) != raw or identity(signature.hotkey) != self.owner:
            raise ValueError("preparation response is not canonical or changes its selected owner")
        verify_signature(response, signature)
        exported = response.evidence
        if (
            response.challenge != request.challenge
            or exported.progress != progress
            or digest(exported.history.authority.authority) != bindings[progress.cohort_sha256]
        ):
            raise ValueError(
                "preparation response changes its challenge, progress or approved authority"
            )
        return exported, await run_owned_thread(self._replay, exported)

    async def review(self, progress: CohortPhaseProgress) -> PreparationProgressReviewRecord:
        exported, original = await self._read(progress)
        seal = original.prepared.roster.intake_seal
        observations = (
            seal.observation,
            original.prepared.observation,
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
            raise ValueError("preparation progress is ahead of owned finality")
        repeated, _ = await self._read(progress)
        if repeated != exported:
            raise OSError("preparation owner evidence changed during independent review")
        return original.record

    async def decision(
        self, transition: CohortRecoveryTransition, evidence: CohortDecisionInput
    ) -> str:
        exported, original = await self._read(evidence.progress.progress)
        if evidence.observation != original.record.evidence.observation:
            raise ValueError("preparation decision changed its original finalized observation")
        decisions = {digest(d): d for d in exported.decisions}
        state, restored, prior = replay_cohort_decisions(
            exported.history, self.policy, decisions.__getitem__
        )
        expected, _ = _choice(
            state, exported.history.authority.authority, self.policy, evidence, restored, prior
        )
        if transition != expected:
            raise ValueError("preparation decision differs from authenticated original evidence")
        return original.record.history_sha256
