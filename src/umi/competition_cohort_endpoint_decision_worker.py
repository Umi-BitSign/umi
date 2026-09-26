"""Recover, retire and certify one retained endpoint case without re-inference."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from .competition_cohort_endpoint_decision import (
    CohortEndpointCaseReview,
    CohortEndpointReplacementCaseReview,
    CohortEndpointReplacementSelection,
    EndpointCaseReview,
    SignedCohortEndpointCaseDecision,
    case_decision_slot,
    validate_case_review,
    verify_case_decision,
)
from .competition_cohort_endpoint_decision_signer import CohortEndpointDecisionSigner
from .competition_cohort_endpoint_recovery import recovery_slot
from .competition_cohort_endpoint_retirement import CohortEndpointRetirement
from .competition_round_journal import RecordReservation
from .concurrency import run_owned_thread, wait_for_owned
from .open_competition import Signature, digest, identity
from .protocol import canonical_json_bytes


@dataclass(frozen=True)
class EndpointCaseDecisionOutcome:
    status: str
    reason: str
    certificate: SignedCohortEndpointCaseDecision | None = None


class CohortEndpointCaseCoordinator:
    def __init__(
        self,
        retirement: CohortEndpointRetirement,
        signer: CohortEndpointDecisionSigner,
        request_vote: Callable[[str, EndpointCaseReview], Awaitable[Signature]],
    ):
        journal = retirement.recovery.journal
        if (
            signer.journal.policy != journal.policy
            or signer.journal.cohorts != journal.cohorts
            or identity(signer.journal.config.signer) != identity(journal.config.signer)
        ):
            raise ValueError("case coordinator reviewer differs from its evaluator")
        self.retirement, self.signer, self.request_vote = retirement, signer, request_vote
        self.recovery = retirement.recovery

    def _review(self, slot, case_id):
        selected, assignment, job = self.recovery.selection(slot)
        retired = self.retirement.retained(slot, case_id)
        if retired is None:
            return None
        if isinstance(selected, CohortEndpointReplacementSelection):
            return CohortEndpointReplacementCaseReview(
                schema="umi-cohort-endpoint-case-review/2",
                selection=selected,
                retirement=retired,
                recovered=self.recovery._retained(selected, job, case_id),
            )
        return CohortEndpointCaseReview(
            schema="umi-cohort-endpoint-case-review/1",
            assignment=assignment,
            selection=selected,
            retirement=retired,
            recovered=self.recovery._retained(selected, job, case_id),
        )

    @staticmethod
    def _key(review):
        # Every original attempt keeps its own evidence. The obligation key
        # alone must never become an overwriteable archive location.
        return digest(
            [
                "umi-cohort-endpoint-case-review-record/1",
                digest(review.selection),
                review.retirement.case_id,
            ]
        )

    def retained(self, slot, case_id) -> SignedCohortEndpointCaseDecision | None:
        review = self._review(slot, case_id)
        if review is None:
            return None
        journal = self.recovery.journal.journal
        key = self._key(review)
        raw = journal.get("endpoint_case_decision", key)
        if raw is None:
            return None
        stored = journal.get("endpoint_case_review", key)
        if canonical_json_bytes(stored) != canonical_json_bytes(review):
            raise ValueError("case decision differs from original retained evidence")
        return verify_case_decision(
            SignedCohortEndpointCaseDecision.model_validate_json(canonical_json_bytes(raw)),
            review,
            self.recovery.journal.policy,
        )

    async def _certificate(self, slot):
        try:
            return await self.signer.certify(slot)
        except ValueError as error:
            if str(error) not in {
                "cohort recovery lacks the policy evaluator quorum",
                "endpoint decision signature count is outside bounds",
            }:
                raise
            return None

    async def advance(self, slot: str, case_id: str) -> EndpointCaseDecisionOutcome:
        journal = self.recovery.journal
        # Retirement owns the execution fence and preserves any original reply.
        # A missing miner or active request remains pending without a zero/void.
        retired = await self.retirement.retire(slot, case_id)
        if retired.value is None:
            return EndpointCaseDecisionOutcome("pending", retired.reason)
        with journal.locked(recovery_slot(slot)):
            existing = await run_owned_thread(self.retained, slot, case_id)
            if existing is not None:
                return EndpointCaseDecisionOutcome("certified", "retained_case_decision", existing)
            review = await run_owned_thread(self._review, slot, case_id)
            _, decision = await run_owned_thread(validate_case_review, review, journal.policy)
            key = self._key(review)
            await run_owned_thread(
                journal.journal.reserve_records,
                digest(["umi-cohort-endpoint-case-decision-reservation/1", key]),
                (RecordReservation("endpoint_case_decision", key, 32 * 1024),),
            )
            await run_owned_thread(journal.journal.put, "endpoint_case_review", key, review)
        # No network call holds the evaluator recovery lock. Reviewer journals
        # keep one immutable selection; cancellation retains partial quorum.
        await self.signer.attest(review)
        decision_slot = case_decision_slot(decision)
        certificate = await self._certificate(decision_slot)
        for reviewer in self.signer.journal.policy.evaluators:
            if certificate is not None:
                break
            if await run_owned_thread(self.signer.journal.vote, decision_slot, reviewer.hotkey):
                continue
            try:
                vote = await wait_for_owned(
                    self.request_vote(reviewer.hotkey, review),
                    timeout=self.signer.journal.config.read_timeout_seconds,
                )
                if identity(vote.hotkey) != identity(reviewer.hotkey):
                    raise ValueError("case reviewer returned another identity")
                await self.signer.collect(decision_slot, vote)
                certificate = await self._certificate(decision_slot)
            except (ValueError, OSError):
                # A faulty/unavailable reviewer cannot erase already retained
                # votes or prevent another independent group being tried.
                continue
        if certificate is None:
            return EndpointCaseDecisionOutcome("pending", "case_decision_quorum_pending")
        with journal.locked(recovery_slot(slot)):
            current = await run_owned_thread(self._review, slot, case_id)
            if current != review:
                raise ValueError("case evidence changed during decision review")
            await run_owned_thread(journal.journal.put, "endpoint_case_decision", key, certificate)
        return EndpointCaseDecisionOutcome("certified", "case_decision_retained", certificate)
