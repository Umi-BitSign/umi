"""Independent, restartable votes for service requests and retired retries.

The host owns current history, historical registration proofs and verified block
ports. A completed vote is recovered before network reads. An unfinished vote
keeps its original evidence and still checks current cohort authority.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Sequence
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field

from .competition_cohort_admission_journal import CohortAdmissionSignerConfig
from .competition_cohort_endpoint_decision_contracts import (
    CohortEndpointCaseDecision,
    SignedCohortEndpointCaseDecision,
)
from .competition_cohort_order_signer import CohortOrderHistory, remember_order_history
from .competition_cohort_recovery import verify_recovery_quorum
from .competition_cohort_request_window import (
    CohortAttemptRequestWindow,
    capture_cohort_attempt_window,
    capture_request_window,
)
from .competition_cohort_service_export import ServiceWorkReader, SignedServiceWorkResponse
from .competition_cohort_service_grant import (
    MAX_SERVICE_GRANT_BYTES,
    ServiceMinerGrant,
    ServiceRequestBody,
    review_service_request_current,
    service_grant_slot,
    service_obligation,
    validate_service_body,
    verify_service_grant,
    verify_service_parent_body,
)
from .competition_execution import ExecutionBoundary, execution_boundary
from .competition_historical_registration import HistoricalRegistrationProvider
from .competition_registration_archive import (
    MAX_ARCHIVE_BYTES,
    MAX_METADATA_BYTES,
    RegistrationArchive,
)
from .competition_round_journal import RecordReservation, RoundJournal
from .concurrency import run_owned_thread, wait_for_owned
from .endpoint_retirement import (
    SignedEndpointRetirementReceipt,
    retirement_absence_elapsed,
    verify_retirement_receipt,
)
from .open_competition import (
    CompetitionPolicy,
    Hotkey,
    Signature,
    digest,
    identity,
    verify_signature,
)
from .policy import ScoringPolicy
from .protocol import StrictProtocolModel, canonical_json_bytes, request_digest
from .validator_plans import VerifiedFinalizedAnnouncementPort


class ServiceRequestReview(StrictProtocolModel):
    body: ServiceRequestBody
    parent: ServiceMinerGrant | None = None


class ServiceRetryReview(StrictProtocolModel):
    grant: ServiceMinerGrant
    retirement: SignedEndpointRetirementReceipt


class ServiceReviewConfig(CohortAdmissionSignerConfig):
    schema_: Literal["umi-service-review-config/1"] = Field(alias="schema")
    owner: Hotkey
    read_timeout_seconds: Annotated[int, Field(ge=1, le=3600)] = 2400


class ServiceReviewIntent(StrictProtocolModel):
    schema_: Literal["umi-service-review-intent/1"] = Field(alias="schema")
    review: ServiceRequestReview | ServiceRetryReview
    owner: SignedServiceWorkResponse
    source: CohortOrderHistory
    observation: ExecutionBoundary
    observed_round: Annotated[int, Field(ge=0)] | None = None
    registration_hex: Annotated[str, Field(max_length=2 * MAX_ARCHIVE_BYTES)]
    metadata_hex: Annotated[str, Field(max_length=2 * MAX_METADATA_BYTES)]


def service_retry_decision(review: ServiceRetryReview) -> CohortEndpointCaseDecision:
    body, fence = review.grant.body, review.retirement
    assignment = body.assignment
    return CohortEndpointCaseDecision(
        schema="umi-cohort-endpoint-case-decision/1",
        policy_sha256=assignment.catalog.catalog.policy_sha256,
        cohort_sha256=assignment.round.cohort_sha256,
        obligation_sha256=service_obligation(assignment, body.evaluator_hotkey),
        case_id=assignment.catalog.catalog.work[assignment.admission.ordinal - 1].case_id,
        attempt_number=body.attempt_number,
        review_sha256=digest(fence),
        request_sha256=request_digest(body.request),
        disposition="retry_required",
        response_sha256=None,
    )


def certify_service_retry(
    review: ServiceRetryReview,
    policy: CompetitionPolicy,
    transport: ScoringPolicy,
    votes: Sequence[Signature],
) -> SignedCohortEndpointCaseDecision:
    """Assemble independently retained votes for this exact fenced request."""
    review = ServiceRetryReview.model_validate_json(canonical_json_bytes(review))
    grant = verify_service_grant(review.grant, policy, transport)
    body = grant.body
    miner = body.assignment.admission.claim.claim.hotkey
    verify_retirement_receipt(
        review.retirement,
        request=body.request,
        grant_sha256=digest(grant),
        miner_hotkey=miner,
        evaluator_hotkey=body.evaluator_hotkey,
    )
    if (
        review.retirement.receipt.result
        not in {"no_response_retained", "expired_response_opportunity"}
        or not 1 <= len(votes) <= 64
    ):
        raise ValueError("service retry requires a no-response fence and bounded votes")
    signatures = tuple(
        sorted(
            (Signature.model_validate_json(canonical_json_bytes(v)) for v in votes),
            key=lambda v: identity(v.hotkey),
        )
    )
    if any(identity(v.hotkey) == identity(miner) for v in signatures):
        raise ValueError("miner cannot authorize its own retry")
    decision = service_retry_decision(review)
    verify_recovery_quorum(decision, signatures, policy)
    return SignedCohortEndpointCaseDecision(decision=decision, signatures=signatures)


class ServiceWorkReviewer:
    def __init__(
        self,
        config: ServiceReviewConfig,
        policy: CompetitionPolicy,
        transport: ScoringPolicy,
        provider: HistoricalRegistrationProvider,
        blocks: VerifiedFinalizedAnnouncementPort,
        history: Callable[[str], Awaitable[CohortOrderHistory]],
        owner: ServiceWorkReader,
        archive: Callable[[ExecutionBoundary], Awaitable[tuple[bytes, bytes]]],
        current_round: Callable[[], Awaitable[int]],
        sign: Callable[[ServiceRequestBody | CohortEndpointCaseDecision], Awaitable[Signature]],
    ):
        self.config = ServiceReviewConfig.model_validate_json(canonical_json_bytes(config))
        self.policy, self.transport = (
            policy,
            ScoringPolicy.model_validate_json(canonical_json_bytes(transport)),
        )
        if (
            config.policy_sha256 != digest(policy)
            or provider.policy != policy
            or owner.policy != policy
            or owner.owner != identity(config.owner)
            or identity(config.signer) not in {identity(e.hotkey) for e in policy.evaluators}
        ):
            raise ValueError("service reviewer differs from configured policy or owner")
        self.provider, self.blocks, self.history = provider, blocks, history
        self.owner, self.archive, self.current_round, self.sign = (
            owner,
            archive,
            current_round,
            sign,
        )
        self.cohorts = {c.cohort_sha256: c.authority_sha256 for c in config.cohorts}
        self.serial = asyncio.Lock()
        self.journal = RoundJournal(
            Path(config.directory),
            {
                "config": config.model_dump(
                    mode="json",
                    by_alias=True,
                    exclude={
                        "maximum_votes",
                        "maximum_bytes",
                        "signing_timeout_seconds",
                        "read_timeout_seconds",
                    },
                ),
                "transport": digest(self.transport),
            },
            maximum_rounds=config.maximum_votes,
            maximum_bytes=config.maximum_bytes,
            maximum_record_bytes=3 * MAX_SERVICE_GRANT_BYTES
            + 2 * (MAX_ARCHIVE_BYTES + MAX_METADATA_BYTES),
        )
        with self.journal.transaction() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS order_heads "
                "(cohort TEXT PRIMARY KEY, history TEXT NOT NULL)"
            )

    def _validate(self, review):
        cls = ServiceRetryReview if isinstance(review, ServiceRetryReview) else ServiceRequestReview
        raw = canonical_json_bytes(review)
        if len(raw) > 2 * MAX_SERVICE_GRANT_BYTES:
            raise ValueError("service review exceeds its byte bound")
        review = cls.model_validate_json(raw)
        body = review.grant.body if isinstance(review, ServiceRetryReview) else review.body
        validate_service_body(body, self.policy, self.transport)
        catalog = body.assignment.catalog.catalog
        if self.cohorts.get(catalog.cohort_sha256) != catalog.authority_sha256 or identity(
            self.config.signer
        ) == identity(body.assignment.admission.claim.claim.hotkey):
            raise ValueError("service review is outside independent configured authority")
        if isinstance(review, ServiceRetryReview):
            verify_service_grant(review.grant, self.policy, self.transport)
            verify_retirement_receipt(
                review.retirement,
                request=body.request,
                grant_sha256=digest(review.grant),
                miner_hotkey=body.assignment.admission.claim.claim.hotkey,
                evaluator_hotkey=body.evaluator_hotkey,
            )
            if review.retirement.receipt.result not in {
                "no_response_retained",
                "expired_response_opportunity",
            }:
                raise ValueError("service retry needs a signed no-response fence")
            kind, value = "service_retry", service_retry_decision(review)
        else:
            if (review.parent is not None) != (body.attempt_number > 1):
                raise ValueError("service review lacks its exact parent grant")
            if review.parent is not None:
                verify_service_grant(review.parent, self.policy, self.transport)
                verify_service_parent_body(body, review.parent)
            kind, value = "service_request", body
        return review, body, kind, value

    def _check_intent(self, intent: ServiceReviewIntent):
        review, body, _, _ = self._validate(intent.review)
        assignment = body.assignment
        if (
            identity(intent.owner.signature.hotkey) != identity(self.config.owner)
            or intent.owner.response.assignment != assignment
        ):
            raise ValueError("retained service owner differs from accepted assignment")
        verify_signature(intent.owner.response, intent.owner.signature)
        archive = RegistrationArchive(
            bytes.fromhex(intent.registration_hex), bytes.fromhex(intent.metadata_hex)
        )
        if (
            archive.evidence_sha256 != assignment.admission.observation.evidence_sha256
            or archive.snapshot != assignment.admission.registration
        ):
            raise ValueError("retained service registration differs from original admission")
        self._check_current(
            review, body, intent.source, intent.observation.block, intent.observed_round
        )
        return intent

    def _check_current(self, review, body, source, block, observed_round):
        review_service_request_current(body, self.policy, source, block)
        if isinstance(review, ServiceRetryReview) and not retirement_absence_elapsed(
            review.retirement.receipt,
            body.request,
            observed_block=block,
            observed_round=observed_round,
        ):
            raise ValueError("service retry precedes request expiry")

    async def _call(self, awaitable):
        return await wait_for_owned(awaitable, timeout=self.config.read_timeout_seconds)

    async def _current(self, review, body):
        source = await self._call(self.history(body.assignment.round.cohort_sha256))
        observation = execution_boundary(await self._call(self.provider.collect()))
        await run_owned_thread(
            remember_order_history,
            self.journal,
            self.cohorts,
            self.policy,
            source,
            observation.block,
        )
        observed_round = (
            await self._call(self.current_round())
            if isinstance(review, ServiceRetryReview)
            else None
        )
        self._check_current(review, body, source, observation.block, observed_round)
        return source, observation, observed_round

    async def attest(self, review: ServiceRequestReview | ServiceRetryReview) -> Signature:
        review, body, kind, value = await run_owned_thread(self._validate, review)
        slot, work = service_grant_slot(body), body.assignment.admission.work_sha256
        binding = {
            "assignment": digest(body.assignment),
            "evaluator": identity(body.evaluator_hotkey),
        }
        async with self.serial:
            with self.journal.locked():
                old = await run_owned_thread(self.journal.get, kind + "_intent", slot)
                if old is not None:
                    intent = await run_owned_thread(
                        self._check_intent,
                        ServiceReviewIntent.model_validate_json(canonical_json_bytes(old)),
                    )
                    if (
                        intent.review != review
                        or self.journal.get("service_review_work", work) != binding
                    ):
                        raise ValueError("service review changed its original intent")
                    vote = await run_owned_thread(self.journal.get, kind + "_vote", slot)
                    if vote is not None:
                        return self._vote(value, vote)
                source, observation, observed_round = await self._current(review, body)
                if old is None:
                    accepted = await self._call(self.owner(body.assignment))
                    expected = body.assignment.admission.observation
                    raw, metadata = await self._call(self.archive(expected))
                    replay = await self._call(self.provider.review_archive(expected, raw, metadata))
                    if (
                        replay.original != expected
                        or replay.snapshot != body.assignment.admission.registration
                        or replay.replayed_at.block_number < expected.block
                    ):
                        raise ValueError(
                            "service registration proof changed its original admission"
                        )
                    if isinstance(body.window, CohortAttemptRequestWindow):
                        window = await self._call(
                            capture_cohort_attempt_window(
                                self.transport,
                                self.blocks,
                                body.request.issued_block,
                                body.assignment,
                                body.attempt_number,
                            )
                        )
                    else:
                        window = await self._call(
                            capture_request_window(
                                self.transport, self.blocks, body.request.issued_block
                            )
                        )
                    if window != body.window:
                        raise ValueError("service request window differs from independent finality")
                    intent = ServiceReviewIntent(
                        schema="umi-service-review-intent/1",
                        review=review,
                        owner=accepted,
                        source=source,
                        observation=observation,
                        observed_round=observed_round,
                        registration_hex=raw.hex(),
                        metadata_hex=metadata.hex(),
                    )
                    await run_owned_thread(self._check_intent, intent)
                    await run_owned_thread(self._reserve, kind, slot, work, binding, intent)
                # Detect owner equivocation or phase closure during slow proof replay.
                await self._call(self.owner(body.assignment))
                current, _, _ = await self._current(review, body)
                if current != source:
                    raise OSError("service authority changed during review; retry unchanged")

                async def commit():
                    signature = self._vote(value, await self.sign(value))
                    await run_owned_thread(self.journal.put, kind + "_vote", slot, signature)
                    return signature

                return await wait_for_owned(commit(), timeout=self.config.signing_timeout_seconds)

    def _reserve(self, kind, slot, work, binding, intent):
        self.journal.reserve_records(
            digest([kind, slot]), (RecordReservation(kind + "_vote", slot, 2048),)
        )

        def bounded(db):
            count = db.execute(
                "SELECT COUNT(*) FROM records "
                "WHERE kind IN ('service_request_intent', 'service_retry_intent')"
            ).fetchone()[0]
            if count > self.config.maximum_votes:
                raise ValueError("service review capacity exhausted; preserve and retry")

        self.journal.put_many(
            (
                ("service_review_work", work, binding),
                (kind + "_intent", slot, intent),
            ),
            index=bounded,
        )

    def _vote(self, value, signature):
        signature = Signature.model_validate(signature)
        if identity(signature.hotkey) != identity(self.config.signer):
            raise ValueError("service vote was signed by another reviewer")
        verify_signature(value, signature)
        return signature
