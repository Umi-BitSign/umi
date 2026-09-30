"""Private HTTP route for authenticated intake review exports."""

from .competition_cohort_intake_export import IntakeReviewExporter, IntakeReviewRequest
from .competition_cohort_review_http import PhaseReviewHTTPClient, phase_review_routes

PATH = "/internal/cohorts/intake-review"


def intake_review_routes(exporter: IntakeReviewExporter, *, token: str):
    return phase_review_routes(exporter, token=token, path=PATH, request_model=IntakeReviewRequest)


class IntakeReviewHTTPClient(PhaseReviewHTTPClient[IntakeReviewRequest]):
    def __init__(self, client, origin, *, token, maximum_bytes=64 * 1024**2, timeout_seconds=30):
        super().__init__(
            client,
            origin,
            token=token,
            path=PATH,
            maximum_bytes=maximum_bytes,
            timeout_seconds=timeout_seconds,
        )
