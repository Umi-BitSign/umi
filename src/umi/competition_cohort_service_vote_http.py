"""Private service votes using the native reviewer's retained signing journal."""

from __future__ import annotations

from typing import Protocol

from fastapi import APIRouter

from .competition_cohort_review_export import review_export_limits, review_selection
from .competition_cohort_review_http import PhaseReviewHTTPClient, phase_review_routes
from .competition_cohort_service_review import (
    ServiceRequestReview,
    ServiceRetryReview,
    service_retry_decision,
)
from .open_competition import Signature, identity, verify_signature
from .protocol import canonical_json_bytes

MAX_VOTE_BYTES = 2048
MAX_REVIEW_BYTES = 32 * 1024**2
Request = ServiceRequestReview | ServiceRetryReview


class ServiceReviewer(Protocol):
    async def attest(self, request: Request) -> Signature: ...


def _path(kind):
    if kind not in ("request", "retry"):
        raise ValueError("unknown service vote kind")
    return f"/internal/cohorts/service/votes/{kind}"


class _Responder:
    def __init__(self, reviewer: ServiceReviewer, timeout_seconds):
        review_export_limits(MAX_VOTE_BYTES, timeout_seconds)
        self.reviewer, self.timeout_seconds = reviewer, timeout_seconds
        self.maximum_bytes = MAX_VOTE_BYTES

    async def respond(self, request: Request) -> bytes:
        return canonical_json_bytes(await self.reviewer.attest(request))


def service_vote_routes(reviewer: ServiceReviewer, *, token: str, timeout_seconds=1200):
    router = APIRouter()
    responder = _Responder(reviewer, timeout_seconds)
    for kind, model in (("request", ServiceRequestReview), ("retry", ServiceRetryReview)):
        router.include_router(
            phase_review_routes(
                responder,
                token=token,
                path=_path(kind),
                request_model=model,
                maximum_request_bytes=MAX_REVIEW_BYTES,
            )
        )
    return router


class ServiceVotePeer:
    def __init__(
        self, client, origin, *, policy, cohorts, signer: str, token, timeout_seconds=1200
    ):
        self.policy, self.cohorts, _ = review_selection(policy, cohorts, signer)
        self.signer = signer
        self.requests = PhaseReviewHTTPClient[ServiceRequestReview](
            client,
            origin,
            token=token,
            path=_path("request"),
            maximum_bytes=MAX_VOTE_BYTES,
            maximum_request_bytes=MAX_REVIEW_BYTES,
            timeout_seconds=timeout_seconds,
        )
        self.retries = PhaseReviewHTTPClient[ServiceRetryReview](
            client,
            origin,
            token=token,
            path=_path("retry"),
            maximum_bytes=MAX_VOTE_BYTES,
            maximum_request_bytes=MAX_REVIEW_BYTES,
            timeout_seconds=timeout_seconds,
        )

    async def attest(self, review: Request) -> Signature:
        retry = isinstance(review, ServiceRetryReview)
        model = ServiceRetryReview if retry else ServiceRequestReview
        raw = canonical_json_bytes(review)
        if len(raw) > MAX_REVIEW_BYTES:
            raise ValueError("service vote request exceeds delivery capacity")
        review = model.model_validate_json(raw)
        body = review.grant.body if retry else review.body
        catalog = body.assignment.catalog.catalog
        if {c.cohort_sha256: c.authority_sha256 for c in self.cohorts}.get(
            catalog.cohort_sha256
        ) != catalog.authority_sha256:
            raise ValueError("service vote request is outside configured cohorts")
        value = service_retry_decision(review) if retry else body
        raw = await (self.retries if retry else self.requests)(review)
        vote = Signature.model_validate_json(raw)
        if canonical_json_bytes(vote) != raw or identity(vote.hotkey) != identity(self.signer):
            raise ValueError("remote service vote changed its bytes or reviewer")
        verify_signature(value, vote)
        return vote
