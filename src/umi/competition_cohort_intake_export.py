"""Owner-authenticated intake exports for independent phase reviewers.

Only the intake process reads its live database. Reviewers replay bounded exports
and original registration archives with their own finality provider. Each read
answers a fresh challenge: an old export cannot conceal a changed owner history.
Service readiness remains an explicit trust in the configured intake owner;
its signature authenticates the source, not public network availability.
"""

from __future__ import annotations

import secrets
from collections.abc import Awaitable, Callable
from functools import partial
from typing import Annotated, Literal

from pydantic import Field, model_serializer, model_validator

from .competition_cohort_admission_review import review_cohort_participation
from .competition_cohort_availability import (
    CohortAvailabilityObservation,
    pending_availability_progress,
    unavailable_service_blocks,
)
from .competition_cohort_coordinator import (
    CohortDecisionInput,
    CohortPhaseProgress,
    _choice,
    replay_cohort_decisions,
)
from .competition_cohort_history import CohortRecoveryHistory
from .competition_cohort_intake import CohortIntakeBinding, history_tip
from .competition_cohort_intake_records import RetainedCohortParticipation, read_participation
from .competition_cohort_intake_review import (
    IntakeProgressReviewRecord,
    NativeIntakeProgressSource,
    NativeIntakeReview,
)
from .competition_cohort_intake_seal import CohortIntakeSeal, build_intake_seal
from .competition_cohort_model_acceptance import CertifiedModelArtifactAcceptance
from .competition_cohort_model_acceptance_store import (
    model_acceptances_for_seal,
    verify_sealed_model_acceptances,
)
from .competition_cohort_recovery import CohortRecoveryTransition, ModelRewardCohortAuthority
from .competition_cohort_review_export import review_export_limits as _bounds
from .competition_cohort_review_export import review_selection
from .competition_execution import ExecutionBoundary, execution_boundary
from .competition_historical_registration import HistoricalRegistrationProvider
from .concurrency import run_owned_thread, wait_for_owned
from .open_competition import CompetitionPolicy, Signature, digest, identity, verify_signature
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

MAX_EXPORT_BYTES = 64 * 1024**2


class IntakeReviewRequest(StrictProtocolModel):
    schema_: Literal["umi-intake-review-request/1"] = Field(alias="schema")
    challenge: Hex32
    progress: CohortPhaseProgress


class IntakeReviewExport(StrictProtocolModel):
    schema_: Literal["umi-intake-review-export/1", "umi-intake-review-export/2"] = Field(
        alias="schema"
    )
    progress: CohortPhaseProgress
    history: CohortRecoveryHistory
    decisions: Annotated[tuple[CohortDecisionInput, ...], Field(max_length=128)]
    services: Annotated[
        tuple[CohortAvailabilityObservation, ...], Field(min_length=1, max_length=262144)
    ]
    seal: CohortIntakeSeal | None
    records: Annotated[tuple[RetainedCohortParticipation, ...], Field(max_length=65536)]
    model_acceptances: (
        Annotated[tuple[CertifiedModelArtifactAcceptance, ...], Field(max_length=512)] | None
    ) = None

    @model_serializer(mode="wrap")
    def preserve_versions(self, handler):
        value = handler(self)
        if self.model_acceptances is None:
            value.pop("model_acceptances", None)
        return value

    @model_validator(mode="after")
    def model_binding(self):
        selected = isinstance(self.history.authority.authority, ModelRewardCohortAuthority)
        if selected != (self.schema_ == "umi-intake-review-export/2") or selected != (
            self.model_acceptances is not None
        ):
            raise ValueError("model award authority requires its complete acceptance export")
        return self


class IntakeReviewResponse(StrictProtocolModel):
    schema_: Literal["umi-intake-review-response/1"] = Field(alias="schema")
    challenge: Hex32
    evidence: IntakeReviewExport


class SignedIntakeReviewResponse(StrictProtocolModel):
    response: IntakeReviewResponse
    signature: Signature


class IntakeReviewExporter:
    """Host port; serialize and sign outside the native intake lock.

    The host supplies an approved signer and a bounded, authenticated transport.
    This read never closes intake, changes a decision, or signs a phase vote.
    Registration archive delivery remains a separate content-addressed port.
    """

    def __init__(
        self,
        source: NativeIntakeProgressSource,
        owner: str,
        sign: Callable[[IntakeReviewResponse], Awaitable[Signature]],
        *,
        maximum_bytes: int = MAX_EXPORT_BYTES,
        timeout_seconds: int = 30,
    ):
        _bounds(maximum_bytes, timeout_seconds)
        self.source, self.owner, self.sign = source, identity(owner), sign
        if self.owner not in {identity(e.hotkey) for e in source.intake.policy.evaluators}:
            raise ValueError("intake export owner is outside the configured evaluator set")
        self.maximum_bytes, self.timeout_seconds = maximum_bytes, timeout_seconds

    def export(self, progress: CohortPhaseProgress) -> IntakeReviewExport:
        progress = CohortPhaseProgress.model_validate_json(canonical_json_bytes(progress))
        intake, cohort = self.source.intake, progress.cohort_sha256
        intake._allowed(cohort)
        with intake._connection() as (db, store):
            native = self.source._read(db, store, progress)
            services, size = [], 0
            for (raw,) in db.execute(
                "SELECT substr(body,1,16385) FROM cohort_service_observations "
                "WHERE cohort=? AND phase='intake' AND sequence<=? ORDER BY sequence",
                (cohort, native.record.service.sequence),
            ):
                size += len(raw)
                if size > self.maximum_bytes:
                    raise OSError("complete intake export exceeds capacity; preserve and retry")
                services.append(CohortAvailabilityObservation.model_validate_json(raw))
            records = []
            if native.seal is not None:
                for _, raw in intake._records(db, native.history):
                    size += len(raw)
                    if size > self.maximum_bytes:
                        raise OSError("complete intake export exceeds capacity; preserve and retry")
                    records.append(read_participation(raw))
            models = isinstance(native.history.authority.authority, ModelRewardCohortAuthority)
            result = IntakeReviewExport(
                schema="umi-intake-review-export/2" if models else "umi-intake-review-export/1",
                progress=progress,
                history=native.history,
                decisions=tuple(
                    store.source(cohort, t.transition.evidence_sha256, CohortDecisionInput)
                    for t in native.history.transitions
                    if t.transition.operation != "revoke"
                ),
                services=tuple(services),
                seal=native.seal,
                records=tuple(records),
                model_acceptances=(
                    model_acceptances_for_seal(
                        db,
                        native.seal,
                        native.history,
                        intake.policy,
                        intake._records(db, native.history),
                    )
                    if native.seal is not None
                    else ()
                )
                if models
                else None,
            )
        if len(canonical_json_bytes(result)) > self.maximum_bytes:
            raise OSError("complete intake export exceeds capacity; preserve and retry")
        return result

    async def respond(self, request: IntakeReviewRequest) -> bytes:
        request = IntakeReviewRequest.model_validate_json(canonical_json_bytes(request))
        evidence = await run_owned_thread(self.export, request.progress)
        response = IntakeReviewResponse(
            schema="umi-intake-review-response/1", challenge=request.challenge, evidence=evidence
        )
        signature = await wait_for_owned(self.sign(response), timeout=self.timeout_seconds)
        if identity(signature.hotkey) != self.owner:
            raise ValueError("intake export was signed by another owner")
        verify_signature(response, signature)
        raw = canonical_json_bytes(
            SignedIntakeReviewResponse(response=response, signature=signature)
        )
        if len(raw) > self.maximum_bytes:
            raise OSError("signed intake export exceeds capacity; preserve and retry")
        return raw


def replay_intake_export(
    exported: IntakeReviewExport,
    policy: CompetitionPolicy,
    *,
    maximum_sample_gap_blocks: int,
) -> NativeIntakeReview:
    """Replay the same original inventory, progress and outage arithmetic as the owner."""
    exported = IntakeReviewExport.model_validate_json(canonical_json_bytes(exported))
    progress, history = exported.progress, exported.history
    cohort, tip = progress.cohort_sha256, history_tip(history)
    decisions = {digest(d): d for d in exported.decisions}
    expected = {
        t.transition.evidence_sha256
        for t in history.transitions
        if t.transition.operation != "revoke"
    }
    if len(decisions) != len(exported.decisions) or set(decisions) != expected:
        raise ValueError("intake export needs every original decision exactly once")
    state, restored, prior = replay_cohort_decisions(history, policy, decisions.__getitem__)
    if (
        cohort != digest(history.plan)
        or state.phase != "intake"
        or progress.phase != "intake"
        or progress.recovery_tip_sha256 != tip
        or progress.observed_at_block < state.observed_at_block
    ):
        raise ValueError("intake export differs from its current history")
    previous = None
    tips = {digest(history.genesis), *(digest(t.transition) for t in history.transitions)}
    for service in exported.services:
        if (
            service.cohort_sha256 != cohort
            or service.phase != "intake"
            or service.phase_started_block != history.plan.not_before_block
            or service.recovery_tip_sha256 not in tips
            or service.sequence != (1 if previous is None else previous.sequence + 1)
            or service.predecessor_sha256 != (None if previous is None else digest(previous))
            or service.unavailable_blocks
            != unavailable_service_blocks(previous, service, maximum_sample_gap_blocks)
        ):
            raise ValueError("intake export service history is incomplete or inconsistent")
        previous = service
    service = exported.services[-1]
    if (
        service.recovery_tip_sha256 != tip
        or service.unavailable_blocks != progress.unavailable_blocks
        or service.unavailable_blocks < max(restored, prior)
    ):
        raise ValueError("intake export changes its original service evidence")
    seal = exported.seal
    records = tuple(
        (digest(r.request.consent.consent), canonical_json_bytes(r)) for r in exported.records
    )
    if tuple(k for k, _ in records) != tuple(sorted({k for k, _ in records})):
        raise ValueError("intake export consent inventory must be complete, unique and ordered")
    if progress.completion == "complete":
        if (
            seal is None
            or progress.phase_result_sha256 != digest(seal)
            or progress.evidence_sha256 != digest(seal)
        ):
            raise ValueError("intake export lacks its exact native seal")
        rebuilt = build_intake_seal(
            history, policy, seal.observation, seal.snapshot, records, expected_tip_sha256=tip
        )
        if rebuilt != seal:
            raise ValueError("intake export changes its sealed original inventory")
        if exported.model_acceptances is not None:
            verify_sealed_model_acceptances(
                exported.model_acceptances, seal, history, policy, records
            )
        if (
            not service.serving
            or service.observation != seal.observation
            or seal.observation.block > progress.observed_at_block
            or seal.observation.block
            < state.targets[0].target_block + service.unavailable_blocks - restored
        ):
            raise ValueError("intake export closes before restoring unavailable service")
    elif (
        seal is not None
        or records
        or exported.model_acceptances
        or pending_availability_progress(state, service) != progress
    ):
        raise ValueError("pending intake export changes its original observation")
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
        tuple(k for k, _ in records),
    )


class RemoteIntakeProgressReviewer:
    """Independent verifier; no coordinator path or database access is accepted.

    fetch must bound response bytes while receiving them. This layer also checks
    the configured capacity before decoding. Archive bytes gain authority only
    through the reviewer's own historical header and registration proof replay.
    """

    def __init__(
        self,
        provider: HistoricalRegistrationProvider,
        cohorts: tuple[CohortIntakeBinding, ...],
        owner: str,
        fetch: Callable[[IntakeReviewRequest], Awaitable[bytes]],
        archive: Callable[[ExecutionBoundary], Awaitable[tuple[bytes, bytes]]],
        *,
        maximum_sample_gap_blocks: int = 10,
        maximum_bytes: int = MAX_EXPORT_BYTES,
        timeout_seconds: int = 30,
    ):
        _bounds(maximum_bytes, timeout_seconds)
        if type(maximum_sample_gap_blocks) is not int or not 1 <= maximum_sample_gap_blocks <= 300:
            raise ValueError("intake export sampling gap is outside bounds")
        self.policy, self.cohorts, self.owner = review_selection(provider.policy, cohorts, owner)
        self.provider, self.fetch, self.archive = provider, fetch, archive
        self.gap, self.maximum_bytes, self.timeout_seconds = (
            maximum_sample_gap_blocks,
            maximum_bytes,
            timeout_seconds,
        )

    async def _read(
        self, progress: CohortPhaseProgress
    ) -> tuple[IntakeReviewExport, NativeIntakeReview]:
        progress = CohortPhaseProgress.model_validate_json(canonical_json_bytes(progress))
        bindings = {c.cohort_sha256: c.authority_sha256 for c in self.cohorts}
        if progress.cohort_sha256 not in bindings or progress.phase != "intake":
            raise ValueError("intake review is outside configured cohorts or phase")
        request = IntakeReviewRequest(
            schema="umi-intake-review-request/1", challenge=secrets.token_hex(32), progress=progress
        )
        raw = await wait_for_owned(self.fetch(request), timeout=self.timeout_seconds)
        if type(raw) is not bytes or not 0 < len(raw) <= self.maximum_bytes:
            raise ValueError("intake response exceeds its byte bound")
        signed = SignedIntakeReviewResponse.model_validate_json(raw)
        response, signature = signed.response, signed.signature
        if canonical_json_bytes(signed) != raw or identity(signature.hotkey) != self.owner:
            raise ValueError("intake response is not canonical or changes its selected owner")
        verify_signature(response, signature)
        evidence = response.evidence
        if (
            response.challenge != request.challenge
            or evidence.progress != progress
            or digest(evidence.history.authority.authority) != bindings[progress.cohort_sha256]
        ):
            raise ValueError(
                "intake response changes its challenge, progress or approved authority"
            )
        reviewed = await run_owned_thread(
            partial(replay_intake_export, evidence, self.policy, maximum_sample_gap_blocks=self.gap)
        )
        return evidence, reviewed

    async def review(self, progress: CohortPhaseProgress) -> IntakeProgressReviewRecord:
        exported, original = await self._read(progress)
        observations = [d.observation for d in exported.decisions]
        observations.append(original.record.service.observation)
        if original.seal is not None:
            observations.append(original.seal.observation)
        checked = {}
        for observation in observations:
            key = digest(observation)
            if key in checked:
                continue
            raw, metadata = await self.archive(observation)
            checked[key] = await self.provider.review_archive(observation, raw, metadata)
        if original.seal is not None:
            if checked[digest(original.seal.observation)].snapshot != original.seal.snapshot:
                raise ValueError("intake seal differs from independently reviewed registration")
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
        current = execution_boundary(await self.provider.collect())
        if current.block < progress.observed_at_block:
            raise ValueError("intake progress is ahead of owned finality")
        # Fresh challenge after proof I/O. A disconnected owner delays the vote;
        # it never turns an old export into evidence that the history is current.
        repeated, _ = await self._read(progress)
        if repeated != exported:
            raise OSError("intake owner evidence changed during independent review")
        return original.record

    async def decision(
        self, transition: CohortRecoveryTransition, evidence: CohortDecisionInput
    ) -> str:
        exported, reviewed = await self._read(evidence.progress.progress)
        decisions = {digest(d): d for d in exported.decisions}
        state, restored, prior = replay_cohort_decisions(
            exported.history, self.policy, decisions.__getitem__
        )
        expected, _ = _choice(
            state, exported.history.authority.authority, self.policy, evidence, restored, prior
        )
        if transition != expected:
            raise ValueError("intake decision differs from authenticated original evidence")
        return reviewed.record.history_sha256
