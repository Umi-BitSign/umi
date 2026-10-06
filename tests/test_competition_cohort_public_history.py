"""Public history uses native phase decisions and owner signatures, synthetic chain."""

import asyncio
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI

from umi.competition_cohort_history_http import (
    CohortHistoryExporter,
    CohortHistoryReader,
    CohortHistoryRequest,
)
from umi.competition_cohort_public_history import PublicCohortHistoryClient, public_history_routes
from umi.open_competition import sign_object

from .test_competition_cohort_lifecycle import intake as intake
from .test_competition_cohort_lifecycle import legacy_scenario as legacy_scenario
from .test_competition_cohort_lifecycle import lifecycle as lifecycle
from .test_competition_cohort_lifecycle import lifecycle_before_intake as lifecycle_before_intake
from .test_competition_cohort_lifecycle import policy as policy
from .test_competition_cohort_lifecycle import recovery as recovery
from .test_competition_cohort_lifecycle import scenario as scenario
from .test_open_competition import wallet


def public(h):
    async def sign(body):
        return sign_object(body, wallet("Charlie"))

    owner = CohortHistoryExporter(h.intake, wallet("Charlie").hotkey.ss58_address, sign)
    state = SimpleNamespace(owner=owner)
    app = FastAPI()
    app.include_router(public_history_routes(lambda: state.owner))
    return state, app


async def test_public_reader_tracks_native_phase_history_without_private_inputs(lifecycle):
    h = lifecycle
    state, app = public(h)
    raw = []
    native = httpx.ASGITransport(app)

    async def wire(request):
        assert "authorization" not in request.headers
        response = await native.handle_async_request(request)
        assert response.headers["cache-control"] == "no-store"
        raw.append(await response.aread())
        return response

    reader = CohortHistoryReader(
        wallet("Charlie").hotkey.ss58_address,
        PublicCohortHistoryClient(
            "https://intake.example", timeout_seconds=10, transport=httpx.MockTransport(wire)
        ),
    )
    initial = await reader(h.cohort)
    assert initial.history == h.intake.history(h.cohort)
    assert initial.decisions == ()
    for worker in h.admissions:
        await worker.poll_once()
    node = h.reopen()
    for _ in range(100):
        h.block += 5
        await node.tick()
        if h.intake.history(h.cohort).transitions:
            break
    current = await reader(h.cohort)
    assert current.history.transitions and current.decisions
    assert current == state.owner.read(h.cohort)
    for content in raw:
        assert all(
            word not in content
            for word in (b'"references"', b'"hypothesis"', b'"video"', b'"request_body"')
        )


@pytest.mark.parametrize(
    "fault", ["offline", "challenge", "signer", "cohort", "redirect", "encoded", "oversize"]
)
async def test_public_history_rejects_unavailable_or_changed_response(
    lifecycle, fault, monkeypatch
):
    h = lifecycle
    state, app = public(h)
    calls = []
    if fault == "offline":
        state.owner = None
    if fault == "oversize":
        monkeypatch.setattr("umi.competition_cohort_public_history.MAX_EXPORT_BYTES", 100)

    async def wire(request):
        calls.append(request)
        if fault == "redirect":
            return httpx.Response(307, headers={"Location": "https://other.example"})
        response = await httpx.ASGITransport(app).handle_async_request(request)
        await response.aread()
        if fault in {"challenge", "signer", "cohort"}:
            body = response.json()
            if fault == "challenge":
                body["response"]["challenge"] = "01" * 32
            elif fault == "signer":
                body["signature"]["hotkey"] = wallet("Dave").hotkey.ss58_address
            else:
                body["response"]["source"]["history"]["plan"]["sequence"] += 1
            from umi.protocol import canonical_json_bytes

            return httpx.Response(
                200,
                content=canonical_json_bytes(body),
                headers={"Content-Type": "application/json"},
            )
        if fault == "encoded":
            response.headers["Content-Encoding"] = "identity,identity"
        return response

    reader = CohortHistoryReader(
        wallet("Charlie").hotkey.ss58_address,
        PublicCohortHistoryClient(
            "https://intake.example", timeout_seconds=5, transport=httpx.MockTransport(wire)
        ),
    )
    with pytest.raises((OSError, ValueError)):
        await reader(h.cohort)
    assert len(calls) == 1


@pytest.mark.parametrize("owner_change", ["unchanged", "offline", "replaced"])
async def test_public_signing_queues_with_bound_and_rechecks_owner(lifecycle, owner_change):
    h = lifecycle
    state, app = public(h)
    entered, release = asyncio.Event(), asyncio.Event()
    original = state.owner.sign
    active = maximum_active = 0

    async def held(body):
        nonlocal active, maximum_active
        active += 1
        maximum_active = max(maximum_active, active)
        if active == 2:
            entered.set()
        try:
            await release.wait()
            return await original(body)
        finally:
            active -= 1

    state.owner.sign = held
    path = f"/v1/competition/cohorts/{h.cohort}/authority?challenge={'01' * 32}"
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app), base_url="https://intake.example"
    ) as caller:
        tasks = [asyncio.create_task(caller.get(path)) for _ in range(2)]
        queued = None
        try:
            await asyncio.wait_for(entered.wait(), 5)
            queued = asyncio.create_task(caller.get(path))
            await asyncio.sleep(0.15)  # The released 100 ms capacity wait rejects this reader.
            assert not queued.done() and maximum_active == 2
            owner = state.owner
            if owner_change == "offline":
                state.owner = None
            elif owner_change == "replaced":
                state.owner = CohortHistoryExporter(
                    h.intake, wallet("Charlie").hotkey.ss58_address, original
                )
            release.set()
            response = await asyncio.wait_for(queued, 5)
            assert response.status_code == (200 if owner_change == "unchanged" else 503)
            if owner_change == "unchanged":
                request = CohortHistoryRequest(
                    schema="umi-cohort-history-request/1",
                    cohort_sha256=h.cohort,
                    challenge="01" * 32,
                )
                reader = CohortHistoryReader(wallet("Charlie").hotkey.ss58_address, lambda _: None)
                assert reader._verify(response.content, request) == owner.read(h.cohort)
            assert maximum_active == 2
        finally:
            release.set()
            assert all(response.status_code == 200 for response in await asyncio.gather(*tasks))
            if queued is not None:
                await asyncio.gather(queued, return_exceptions=True)
