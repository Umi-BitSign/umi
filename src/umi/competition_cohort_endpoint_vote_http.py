"""Authenticated request and retirement votes backed by native reviewer journals."""

from fastapi import APIRouter

from .competition_cohort_endpoint_decision import (
    MAX_CASE_REVIEW_BYTES,
    EndpointCaseReview,
    validate_case_review,
)
from .competition_cohort_request_signer import EndpointRequestPlan
from .competition_cohort_review_export import review_export_limits, review_selection
from .competition_cohort_review_http import PhaseReviewHTTPClient, phase_review_routes
from .concurrency import run_owned_thread
from .open_competition import Signature, digest, identity, verify_signature
from .protocol import StrictProtocolModel, canonical_json_bytes

MAX_REVIEW_BYTES = 32 * 1024**2
MAX_VOTE_BYTES = 2048
PREFIX = "/internal/cohorts/endpoint/votes"


def _limit(kind):
    # Decision evidence has a larger native bound; allow its typed wrapper too.
    return MAX_CASE_REVIEW_BYTES + 1024 if kind == "decision" else MAX_REVIEW_BYTES


class EndpointDecisionReview(StrictProtocolModel):
    review: EndpointCaseReview


class _Responder:
    maximum_bytes = MAX_VOTE_BYTES

    def __init__(self, action, timeout_seconds):
        review_export_limits(self.maximum_bytes, timeout_seconds)
        self.action, self.timeout_seconds = action, timeout_seconds

    async def respond(self, request):
        return canonical_json_bytes(await self.action(request))


def endpoint_vote_routes(reviewer, *, token: str, timeout_seconds=1200):
    router = APIRouter()

    async def decision(request):
        return await reviewer.decision_vote(request.review)

    for kind, model, action in (
        ("request", EndpointRequestPlan, reviewer.request_vote),
        ("decision", EndpointDecisionReview, decision),
    ):
        router.include_router(
            phase_review_routes(
                _Responder(action, timeout_seconds),
                token=token,
                path=f"{PREFIX}/{kind}",
                request_model=model,
                maximum_request_bytes=_limit(kind),
            )
        )
    return router


class EndpointVotePeer:
    def __init__(self, client, origin, *, policy, cohorts, signer, token, timeout_seconds=1200):
        self.policy, self.cohorts, _ = review_selection(policy, cohorts, signer)
        self.signer = identity(signer)
        self.clients = {
            kind: PhaseReviewHTTPClient(
                client,
                origin,
                token=token,
                path=f"{PREFIX}/{kind}",
                maximum_bytes=MAX_VOTE_BYTES,
                maximum_request_bytes=_limit(kind),
                timeout_seconds=timeout_seconds,
            )
            for kind in ("request", "decision")
        }

    def check_assignment(self, assignment):
        round_ = assignment.certificate.order.round
        if round_.policy_sha256 != digest(self.policy) or round_.cohort_sha256 not in {
            c.cohort_sha256 for c in self.cohorts
        }:
            raise ValueError("endpoint vote is outside configured cohorts")

    async def _vote(self, kind, request, body):
        raw = await self.clients[kind](request)
        vote = Signature.model_validate_json(raw)
        if canonical_json_bytes(vote) != raw or identity(vote.hotkey) != self.signer:
            raise ValueError("endpoint vote changed its bytes or reviewer")
        verify_signature(body, vote)
        return vote

    async def request_vote(self, plan):
        self.check_assignment(plan.assignment)
        return await self._vote("request", plan, plan.body)

    async def decision_vote(self, review):
        self.check_assignment(review.assignment)
        review, decision = await run_owned_thread(validate_case_review, review, self.policy)
        return await self._vote("decision", EndpointDecisionReview(review=review), decision)
