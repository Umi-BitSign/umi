"""Private model artifact votes; payload files and approval documents stay local."""

from .competition_cohort_model_acceptance import (
    ModelArtifactVote,
    ModelReviewRequest,
    check_model_vote,
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


def model_review_routes(reviewer, *, token, timeout_seconds=2400):
    return phase_review_routes(
        _VoteResponder(reviewer, timeout_seconds),
        token=token,
        path=VOTE_PATH,
        request_model=ModelReviewRequest,
        maximum_request_bytes=MAX_REQUEST_BYTES,
    )


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
