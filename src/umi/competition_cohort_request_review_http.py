"""Private HTTP delivery for original request-completion evidence."""

from .competition_cohort_request_export import RequestReviewExporter, RequestReviewRequest
from .competition_cohort_review_http import PhaseReviewHTTPClient, phase_review_routes

PATH = "/internal/cohorts/request-review"


def request_review_routes(exporter: RequestReviewExporter, *, token: str):
    return phase_review_routes(exporter, token=token, path=PATH, request_model=RequestReviewRequest)


class RequestReviewHTTPClient(PhaseReviewHTTPClient[RequestReviewRequest]):
    def __init__(self, client, origin, *, token, maximum_bytes=64 * 1024**2, timeout_seconds=30):
        super().__init__(
            client,
            origin,
            token=token,
            path=PATH,
            maximum_bytes=maximum_bytes,
            timeout_seconds=timeout_seconds,
        )
