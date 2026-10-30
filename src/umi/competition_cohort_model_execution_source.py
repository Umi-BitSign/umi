"""Restore certified execution metadata without inventing a local review vote."""

from __future__ import annotations

import asyncio
import hashlib

from .competition_assignment_reuse import AssignmentVerificationReuse
from .competition_cohort_coordinator import replay_cohort_decisions
from .competition_cohort_history import verify_cohort_history
from .competition_cohort_intake import history_tip
from .competition_cohort_intake_records import replay_participation
from .competition_cohort_model_acceptance import (
    CertifiedModelArtifactAcceptance,
    ModelReviewRequest,
    verify_model_acceptance,
)
from .competition_cohort_order_signer import CohortOrderHistory
from .competition_cohort_recovery import verify_recovery_quorum
from .competition_cohort_review_http import PhaseReviewHTTPClient, phase_review_routes
from .competition_transport_verification import TransferProgress
from .competition_work_progress import await_progress
from .concurrency import run_owned_thread
from .open_competition import digest, identity
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

PATH = "/internal/cohorts/model-artifacts/execution-source"
MAX_BYTES = 32 * 1024**2
ABI = "umi-certified-model-execution-source/1"
REFERENCE_ABI = "umi-certified-reference-execution-source/1"


class ModelExecutionSourceQuery(StrictProtocolModel):
    cohort_sha256: Hex32
    submission_sha256: Hex32


class CertifiedModelExecutionSource(StrictProtocolModel):
    request: ModelReviewRequest
    certificate: CertifiedModelArtifactAcceptance
    history: CohortOrderHistory


class _Exporter:
    maximum_bytes = MAX_BYTES

    def __init__(self, owner, history, timeout_seconds):
        self.owner, self.history, self.timeout_seconds = owner, history, timeout_seconds

    def read(self, query):
        publication = self.owner.retained(query.cohort_sha256, query.submission_sha256)
        request = self.owner.review_request(query.cohort_sha256, query.submission_sha256)
        if request.acceptance != publication.certificate.acceptance:
            raise ValueError("execution metadata differs from certified original")
        return CertifiedModelExecutionSource(
            request=request,
            certificate=publication.certificate,
            history=self.history(query.cohort_sha256),
        )

    async def respond(self, query):
        return canonical_json_bytes(await run_owned_thread(self.read, query))


def model_execution_source_routes(owner, history, *, token, timeout_seconds=2400):
    return phase_review_routes(
        _Exporter(owner, history, timeout_seconds),
        token=token,
        path=PATH,
        request_model=ModelExecutionSourceQuery,
        maximum_request_bytes=1024,
    )


def verify_execution_model_source(value, job, policy, cohorts):
    request, source = value.request, value.history
    cohort = job.round.cohort_sha256
    if (
        request.acceptance != value.certificate.acceptance
        or request.record.request.signed_submission != job.submission
        or request.acceptance.cohort_sha256 != cohort
        or cohorts.get(cohort) != request.acceptance.authority_sha256
        or digest(source.history.plan) != cohort
        or digest(source.history.authority.authority) != cohorts.get(cohort)
        or job.round.policy_sha256 != digest(policy)
    ):
        raise ValueError("certified execution source changes its selected job or authority")
    block = max(
        job.round.prepared_at_block,
        *(t.transition.observed_at_block for t in source.history.transitions),
    )
    view = verify_cohort_history(
        source.history, policy, expected_tip_sha256=history_tip(source.history), current_block=block
    )
    replay_cohort_decisions(source.history, policy, source.inputs().__getitem__)
    if (
        digest(view.closure("preparation")) != job.preparation_closure_sha256
        or request.acceptance.accepted_at_block > view.closure("intake").observed_at_block
        or not any(
            p.submission_sha256 == digest(job.submission.submission)
            and p.admission_sha256 == digest(request.admission.admission)
            for p in job.round.participants
        )
        or replay_participation(request.record, source.history, policy)
        != request.admission.admission
        or request.record.proposed_admission != request.admission.admission
    ):
        raise ValueError("certified execution source changes its prepared admission or clocks")
    verify_recovery_quorum(request.admission.admission, request.admission.signatures, policy)
    verify_model_acceptance(
        value.certificate,
        request.record,
        source.history,
        policy,
        maximum_block=view.closure("intake").observed_at_block,
    )
    return request


def reference_execution_binding(job, review, policy):
    """The caller's applied baseline, never source metadata, grants reference authority."""
    if (
        review.model != job.incumbent
        or review.target_cohort_sha256 != job.round.cohort_sha256
        or review.target_sequence != job.round.sequence
        or review.policy_sha256 != job.round.policy_sha256
        or review.policy_sha256 != digest(policy)
        or review.candidate.model_sha256 != job.round.incumbent_model_sha256
        or digest(review.model) != job.round.incumbent_model_sha256
    ):
        raise ValueError("certified reference source differs from its frozen execution")


def verify_reference_model_source(value, review, policy, cohorts):
    """Verify the winner's original certificate without inventing a target-roster job."""
    request, source, candidate = value.request, value.history, review.candidate
    acceptance = request.acceptance
    submission = request.record.request.signed_submission.submission
    cohort = review.source_cohort_sha256
    if (
        acceptance != value.certificate.acceptance
        or digest(value.certificate) != candidate.acceptance_sha256
        or acceptance.cohort_sha256 != cohort
        or acceptance.authority_sha256 != candidate.authority_sha256
        or cohorts.get(cohort) != candidate.authority_sha256
        or digest(source.history.plan) != cohort
        or source.history.plan.sequence != review.source_sequence
        or digest(source.history.authority.authority) != candidate.authority_sha256
        or acceptance.policy_sha256 != review.policy_sha256
        or review.policy_sha256 != digest(policy)
        or candidate.policy_sha256 != review.policy_sha256
        or acceptance.submission_sha256 != candidate.submission_sha256
        or digest(submission) != candidate.submission_sha256
        or submission.model_bundle != review.model
        or acceptance.model_sha256 != candidate.model_sha256
        or acceptance.content_sha256 != candidate.content_sha256
        or identity(submission.hotkey) != identity(candidate.contributor_hotkey)
        or identity(acceptance.recipient_hotkey) != identity(candidate.contributor_hotkey)
        or acceptance.accepted_ordinal != candidate.accepted_ordinal
        or acceptance.rights_evidence_sha256 != candidate.rights_evidence_sha256
        or acceptance.reconstruction_evidence_sha256 != candidate.reconstruction_evidence_sha256
    ):
        raise ValueError("certified reference metadata changes its original baseline source")
    block = max(
        source.history.genesis.admitted_at_block,
        *(t.transition.observed_at_block for t in source.history.transitions),
    )
    view = verify_cohort_history(
        source.history, policy, expected_tip_sha256=history_tip(source.history), current_block=block
    )
    replay_cohort_decisions(source.history, policy, source.inputs().__getitem__)
    if (
        replay_participation(request.record, source.history, policy) != request.admission.admission
        or request.record.proposed_admission != request.admission.admission
    ):
        raise ValueError("certified reference metadata changes its original admission")
    verify_recovery_quorum(request.admission.admission, request.admission.signatures, policy)
    verify_model_acceptance(
        value.certificate,
        request.record,
        source.history,
        policy,
        maximum_block=view.closure("intake").observed_at_block,
    )
    return request


class CertifiedModelExecutionSources:
    """One atomic durable verification result per immutable certified source.

    This separate namespace never records that this evaluator reviewed or signed
    the artifact. Current order authority and finality remain the executor's job.
    """

    def __init__(self, client, origin, *, token, policy, cohorts, journal, timeout_seconds):
        self.policy, self.cohorts, self.journal = policy, cohorts, journal
        self.transport = PhaseReviewHTTPClient(
            client,
            origin,
            token=token,
            path=PATH,
            maximum_bytes=MAX_BYTES,
            maximum_request_bytes=1024,
            timeout_seconds=timeout_seconds,
        )
        self.serial = asyncio.Lock()
        self.memory = AssignmentVerificationReuse()

    def _context(self, job):
        return digest(
            [
                ABI,
                digest(self.policy),
                self.cohorts.get(job.round.cohort_sha256),
                digest(job.round),
                job.preparation_closure_sha256,
                digest(job.submission.submission),
            ]
        )

    def _load_record(self, slot, context, kind="model_execution_source"):
        with self.journal.read_transaction() as db:
            raw = self.journal.get_raw(kind, slot, db=db)
            receipt = self.journal.get(kind + "_verified", slot, db=db)
        if raw is None and receipt is None:
            return None
        if (
            raw is None
            or receipt is None
            or receipt
            != {
                "context_sha256": context,
                "source_raw_sha256": hashlib.sha256(raw).hexdigest(),
            }
        ):
            reason = (
                "completed_execution_metadata_source_missing"
                if raw is None
                else "completed_execution_metadata_receipt_missing"
                if receipt is None
                else "completed_execution_metadata_context_changed"
                if isinstance(receipt, dict) and receipt.get("context_sha256") != context
                else "completed_execution_metadata_changed"
            )
            with TransferProgress("execution_model_metadata_repair", 1, unit="sources") as progress:
                progress.emit("repair_required", reason=reason)
                raise ValueError("completed execution model metadata changed; repair required")
        key = (kind, slot)
        cached = self.memory.lookup(key, receipt)
        if cached is not None:
            return cached
        value = CertifiedModelExecutionSource.model_validate_json(raw)
        request = value.request
        # Native semantic verification completed before the same atomic commit.
        # Reopen checks exact immutable input/context, without repeating replay.
        self.memory.remember(key, receipt, request)
        return request

    def _load(self, job):
        slot = job.round.cohort_sha256 + ":" + digest(job.submission.submission)
        request = self._load_record(slot, self._context(job))
        if request is not None and request.record.request.signed_submission != job.submission:
            raise ValueError("retained execution metadata changes its selected submission")
        return request

    def _reference_context(self, review):
        # Neither target candidate nor target round belongs to the immutable
        # source verdict. Each invocation separately checks its applied baseline.
        return digest(
            [
                REFERENCE_ABI,
                digest(self.policy),
                self.cohorts.get(review.source_cohort_sha256),
                review.source_cohort_sha256,
                review.source_sequence,
                digest(review.candidate),
                digest(review.model),
            ]
        )

    async def reference(self, job, review):
        reference_execution_binding(job, review, self.policy)
        slot = review.source_cohort_sha256 + ":" + review.candidate.submission_sha256
        context = self._reference_context(review)
        kind = "reference_execution_source"
        async with self.serial:
            retained = await run_owned_thread(self._load_record, slot, context, kind)
            if retained is not None:
                return retained
            query = ModelExecutionSourceQuery(
                cohort_sha256=review.source_cohort_sha256,
                submission_sha256=review.candidate.submission_sha256,
            )
            raw = await await_progress(
                self.transport(query),
                stage="reference_model_metadata",
                cohort=job.round.cohort_sha256,
                planning_range_seconds=(0, 30),
                planning_basis="planning_bounded_owner_metadata_response_excludes_retries",
            )
            value = CertifiedModelExecutionSource.model_validate_json(raw)
            if canonical_json_bytes(value) != raw:
                raise ValueError("reference model source is not canonical")
            with TransferProgress(
                "reference_model_metadata_verification",
                1,
                unit="sources",
                planning_unit_seconds=(0.01, 30),
            ) as progress:
                await run_owned_thread(
                    verify_reference_model_source, value, review, self.policy, self.cohorts
                )
                await run_owned_thread(
                    self.journal.put_many,
                    (
                        (kind, slot, value),
                        (
                            kind + "_verified",
                            slot,
                            {
                                "context_sha256": context,
                                "source_raw_sha256": hashlib.sha256(raw).hexdigest(),
                            },
                        ),
                    ),
                )
                progress.advance(1)
            return await run_owned_thread(self._load_record, slot, context, kind)

    async def request(self, job):
        async with self.serial:
            retained = await run_owned_thread(self._load, job)
            if retained is not None:
                return retained
            cohort = job.round.cohort_sha256
            query = ModelExecutionSourceQuery(
                cohort_sha256=cohort, submission_sha256=digest(job.submission.submission)
            )
            raw = await await_progress(
                self.transport(query), stage="execution_model_metadata", cohort=cohort
            )
            value = CertifiedModelExecutionSource.model_validate_json(raw)
            if canonical_json_bytes(value) != raw:
                raise ValueError("execution model source is not canonical")
            await run_owned_thread(
                verify_execution_model_source, value, job, self.policy, self.cohorts
            )
            slot = cohort + ":" + query.submission_sha256
            await run_owned_thread(
                self.journal.put_many,
                (
                    ("model_execution_source", slot, value),
                    (
                        "model_execution_source_verified",
                        slot,
                        {
                            "context_sha256": self._context(job),
                            "source_raw_sha256": hashlib.sha256(raw).hexdigest(),
                        },
                    ),
                ),
            )
            return await run_owned_thread(self._load, job)
