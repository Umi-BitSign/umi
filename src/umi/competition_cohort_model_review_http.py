"""Private model artifact votes; payload files and approval documents stay local."""

from .competition_cohort_model_acceptance import (
    ModelArtifactVote,
    ModelReviewRequest,
    check_model_vote,
)
from .competition_cohort_model_batch_adoption import (
    ModelBatchAdoptionReviewRequest,
    ModelBatchAdoptionVote,
    check_model_batch_adoption_vote,
)
from .competition_cohort_model_batch_review import (
    ModelBatchArtifactVote,
    ModelBatchReviewRequest,
    check_model_batch_vote,
)
from .competition_cohort_review_export import review_export_limits, review_selection
from .competition_cohort_review_http import (
    CohortReviewPeerConfig,
    PhaseReviewHTTPClient,
    phase_review_routes,
)
from .concurrency import wait_for_owned
from .protocol import canonical_json_bytes

VOTE_PATH = "/internal/cohorts/model-artifacts/votes"
BATCH_VOTE_PATH = "/internal/cohorts/model-artifacts/batch-votes"
BATCH_ADOPTION_VOTE_PATH = "/internal/cohorts/model-artifacts/batch-adoption-votes"
MAX_BATCH_REQUEST_BYTES = 64 * 1024**2
MAX_REQUEST_BYTES = 5 * 1024**2
MAX_VOTE_BYTES = 16 * 1024
ModelReviewPeerConfig = CohortReviewPeerConfig


class _VoteResponder:
    def __init__(self, reviewer, timeout_seconds):
        review_export_limits(MAX_VOTE_BYTES, timeout_seconds)
        self.reviewer = reviewer
        self.maximum_bytes, self.timeout_seconds = MAX_VOTE_BYTES, timeout_seconds

    async def respond(self, request):
        return canonical_json_bytes(await self.reviewer.attest(request))


class _BatchVoteResponder(_VoteResponder):
    async def respond(self, request):
        return canonical_json_bytes(await self.reviewer.attest_batch(request))


class _BatchAdoptionVoteResponder(_VoteResponder):
    async def respond(self, request):
        return canonical_json_bytes(await self.reviewer.attest_batch_adoption(request))


def model_review_routes(reviewer, *, token, timeout_seconds=2400):
    router = phase_review_routes(
        _VoteResponder(reviewer, timeout_seconds),
        token=token,
        path=VOTE_PATH,
        request_model=ModelReviewRequest,
        maximum_request_bytes=MAX_REQUEST_BYTES,
    )
    router.include_router(
        phase_review_routes(
            _BatchVoteResponder(reviewer, timeout_seconds),
            token=token,
            path=BATCH_VOTE_PATH,
            request_model=ModelBatchReviewRequest,
            maximum_request_bytes=MAX_BATCH_REQUEST_BYTES,
        )
    )
    router.include_router(
        phase_review_routes(
            _BatchAdoptionVoteResponder(reviewer, timeout_seconds),
            token=token,
            path=BATCH_ADOPTION_VOTE_PATH,
            request_model=ModelBatchAdoptionReviewRequest,
            maximum_request_bytes=16 * 1024,
        )
    )
    return router


class ModelReviewPeer:
    def __init__(self, client, origin, *, policy, cohorts, signer, token, timeout_seconds=2400):
        self.policy, self.cohorts, self.account = review_selection(policy, cohorts, signer)
        self.signer, self.timeout = signer, timeout_seconds
        self.transport = PhaseReviewHTTPClient[ModelReviewRequest](
            client,
            origin,
            token=token,
            path=VOTE_PATH,
            maximum_bytes=MAX_VOTE_BYTES,
            maximum_request_bytes=MAX_REQUEST_BYTES,
            timeout_seconds=timeout_seconds,
        )
        self.batch_transport = PhaseReviewHTTPClient[ModelBatchReviewRequest](
            client,
            origin,
            token=token,
            path=BATCH_VOTE_PATH,
            maximum_bytes=MAX_VOTE_BYTES,
            maximum_request_bytes=MAX_BATCH_REQUEST_BYTES,
            timeout_seconds=timeout_seconds,
        )
        self.batch_adoption_transport = PhaseReviewHTTPClient[ModelBatchAdoptionReviewRequest](
            client,
            origin,
            token=token,
            path=BATCH_ADOPTION_VOTE_PATH,
            maximum_bytes=MAX_VOTE_BYTES,
            maximum_request_bytes=16 * 1024,
            timeout_seconds=timeout_seconds,
        )

    async def attest(self, request):
        a = request.acceptance
        if not any(
            b.cohort_sha256 == a.cohort_sha256 and b.authority_sha256 == a.authority_sha256
            for b in self.cohorts
        ):
            raise ValueError("model vote is outside configured cohort authority")
        response = await wait_for_owned(self.transport(request), timeout=self.timeout)
        vote = ModelArtifactVote.model_validate_json(response)
        if canonical_json_bytes(vote) != response:
            raise ValueError("model vote is not canonical")
        check_model_vote(vote, a, self.policy, signer=self.signer)
        return vote

    async def attest_batch(self, request):
        batch = request.batch
        if not any(
            b.cohort_sha256 == batch.cohort_sha256 and b.authority_sha256 == batch.authority_sha256
            for b in self.cohorts
        ):
            raise ValueError("model batch is outside configured cohort authority")
        response = await wait_for_owned(self.batch_transport(request), timeout=self.timeout)
        vote = ModelBatchArtifactVote.model_validate_json(response)
        if canonical_json_bytes(vote) != response:
            raise ValueError("model batch vote is not canonical")
        check_model_batch_vote(vote, request, self.policy, signer=self.signer)
        return vote

    async def attest_batch_adoption(self, request):
        adoption = request.adoption
        if not any(
            b.cohort_sha256 == adoption.cohort_sha256
            and b.authority_sha256 == adoption.authority_sha256
            for b in self.cohorts
        ):
            raise ValueError("model batch adoption is outside configured cohort authority")
        response = await wait_for_owned(
            self.batch_adoption_transport(request), timeout=self.timeout
        )
        vote = ModelBatchAdoptionVote.model_validate_json(response)
        if canonical_json_bytes(vote) != response:
            raise ValueError("model batch adoption vote is not canonical")
        check_model_batch_adoption_vote(vote, request, self.policy, signer=self.signer)
        return vote
