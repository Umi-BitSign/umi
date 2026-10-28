"""All supported model submission transports expose the same terminal cutoff."""

import asyncio

import httpx
import pytest

from umi.competition_client import CompetitionSubmissionError, post_intake_document
from umi.competition_cohort_direct_model_client import _json_exchange
from umi.competition_cohort_model_client import _exchange, _retry


@pytest.mark.parametrize("transport_kind", ["direct", "legacy", "participation"])
def test_closed_admission_is_terminal_without_repeated_requests(transport_kind):
    calls = []

    def respond(request):
        calls.append(request)
        return httpx.Response(409, headers={"X-UMI-Reason-Code": "cohort_intake_closed"})

    async def run():
        transport = httpx.MockTransport(respond)
        async with httpx.AsyncClient(
            base_url="https://intake.example", transport=transport
        ) as client:

            async def once():
                if transport_kind == "participation":
                    return await post_intake_document(
                        origin="https://intake.example",
                        path="/v1/competition/participation",
                        body=b"{}",
                        transport=transport,
                    )
                method = _json_exchange if transport_kind == "direct" else _exchange
                return await method(client, "POST", "/v1/competition/models", body=b"{}")

            with pytest.raises(CompetitionSubmissionError) as caught:
                await _retry(once, 1, lambda value: None)
            assert caught.value.reason_code == "cohort_intake_closed"
            assert caught.value.status_code == 409

    asyncio.run(run())
    assert len(calls) == 1
