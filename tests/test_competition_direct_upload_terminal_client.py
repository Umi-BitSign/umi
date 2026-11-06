"""An unfinished upload can terminate without changing signed status schemas."""

import httpx
import pytest

from umi.competition_client import CompetitionSubmissionError, intake_rejection
from umi.competition_cohort_direct_model_client import _json_exchange
from umi.competition_cohort_model_client import _retry


@pytest.mark.parametrize("method, suffix", [("GET", ""), ("POST", "/complete"), ("POST", "/parts")])
async def test_terminal_completion_response_does_not_retry_or_read_server_body(method, suffix):
    calls = []
    reports = []

    class UnreadBody(httpx.AsyncByteStream):
        async def __aiter__(self):
            raise AssertionError("terminal server body must remain unread")
            yield b""  # pragma: no cover

    def respond(request):
        calls.append(request)
        return httpx.Response(
            410,
            headers={"X-UMI-Reason-Code": "model_upload_completion_closed"},
            stream=UnreadBody(),
        )

    async with httpx.AsyncClient(
        base_url="https://intake.example", transport=httpx.MockTransport(respond)
    ) as client:
        with pytest.raises(CompetitionSubmissionError) as error:
            await _retry(
                lambda: _json_exchange(
                    client, method, "/direct-model-uploads/reservation" + suffix
                ),
                0,
                reports.append,
            )
    assert error.value.reason_code == "model_upload_completion_closed"
    assert error.value.status_code == 410
    assert len(calls) == 1
    assert reports == []


@pytest.mark.parametrize(
    "status, header, expected",
    [
        (410, "model_upload_completion_closed", "model_upload_completion_closed"),
        (503, "model_upload_completion_closed", "model_upload_rejected"),
        (409, "cohort_intake_closed", "cohort_intake_closed"),
        (410, "cohort_intake_closed", "model_upload_rejected"),
        (410, "untrusted_server_detail", "model_upload_rejected"),
        (410, "", "model_upload_rejected"),
    ],
)
def test_only_exact_status_and_reason_pairs_are_exposed(status, header, expected):
    error = intake_rejection(
        httpx.Response(status, headers={"X-UMI-Reason-Code": header}),
        "model_upload_rejected",
    )
    assert error.reason_code == expected
    assert error.status_code == status
