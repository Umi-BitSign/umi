"""Private HTTP route for authenticated preparation review exports."""

from .competition_cohort_preparation_export import (
    PreparationReviewExporter,
    PreparationReviewRequest,
)
from .competition_cohort_review_http import PhaseReviewHTTPClient, phase_review_routes

PATH = "/internal/cohorts/preparation-review"


def preparation_review_routes(exporter: PreparationReviewExporter, *, token: str):
    return phase_review_routes(
        exporter, token=token, path=PATH, request_model=PreparationReviewRequest
    )


class PreparationReviewHTTPClient(PhaseReviewHTTPClient[PreparationReviewRequest]):
    def __init__(
        self,
        client,
        origin,
        *,
        token,
        maximum_bytes=64 * 1024**2,
        timeout_seconds=2400,
    ):
        super().__init__(
            client,
            origin,
            token=token,
            path=PATH,
            maximum_bytes=maximum_bytes,
            timeout_seconds=timeout_seconds,
        )
