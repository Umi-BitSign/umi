from __future__ import annotations

import asyncio
import json

import httpx
import pytest
from fastapi import FastAPI

from umi.competition_api import CompetitionApiLimits, create_app
from umi.competition_cohort_api import cohort_routes
from umi.competition_cohort_coordinator import replay_cohort_decisions
from umi.competition_cohort_readiness import LiveIntakePhaseObserver, intake_readiness
from umi.competition_store import AdmissionCapacity, CompetitionStore
from umi.open_competition import digest

from .test_competition_cohort_consumers import scenario as scenario
from .test_competition_cohort_intake import capture_at
from .test_competition_cohort_intake import intake as intake
from .test_competition_cohort_intake_phase import healthy
from .test_competition_cohort_intake_phase import phase as phase
from .test_competition_cohort_recovery import recovery as recovery
from .test_open_competition import policy as policy


def state_for(scenario):
    return replay_cohort_decisions(scenario["intake_history"], scenario["policy"], lambda _: None)[
        0
    ]


def reply_for(phase, scenario, request, block=210):
    return intake_readiness(
        phase.intake,
        digest(scenario["intake_history"].plan),
        capture_at(block),
        nonce=request.url.params["nonce"],
        archive_available=True,
    ).model_dump(mode="json", by_alias=True)


def router(intake, block, *, archive=True):
    async def current():
        return capture_at(block[0])

    async def retain(_):
        raise AssertionError("readiness must not archive participant evidence")

    app = FastAPI()
    app.include_router(
        cohort_routes(
            intake,
            current,
            maximum_body_bytes=4 * 1024**2,
            archive=retain if archive else None,
        )
    )
    return app


async def test_native_api_probe_records_actual_serving_state(phase, scenario):
    block = [200]
    sampler = LiveIntakePhaseObserver(
        phase,
        "https://intake.example",
        transport=httpx.ASGITransport(router(phase.intake, block)),
    )
    state = state_for(scenario)
    for b in range(200, 301, 5):
        block[0] = b
        result = await sampler(state, capture_at(b))
        assert result.service.serving
        assert result.service.unavailable_blocks == 0
    assert result.seal is not None and result.progress.completion == "complete"
    # The API now reports its native fence, while retries preserve the original
    # completed result instead of counting recovery time as another outage.
    block[0] = 1000
    again = await sampler(state, capture_at(1000))
    assert again.seal == result.seal
    assert again.progress.unavailable_blocks == 0


async def test_api_failure_restores_participant_time(phase, scenario):
    block = [200]
    ready = [True]
    app_transport = httpx.ASGITransport(router(phase.intake, block))

    async def serve(request):
        if not ready[0]:
            return httpx.Response(503)
        return await app_transport.handle_async_request(request)

    sampler = LiveIntakePhaseObserver(
        phase, "https://intake.example", transport=httpx.MockTransport(serve)
    )
    state = state_for(scenario)
    assert (await sampler(state, capture_at(200))).service.unavailable_blocks == 0
    ready[0] = False
    failed = await sampler(state, capture_at(205))
    assert not failed.service.serving and failed.service.unavailable_blocks == 5
    ready[0], block[0] = True, 210
    recovered = await sampler(state, capture_at(210))
    assert recovered.service.serving and recovered.service.unavailable_blocks == 10
    for b in range(215, 311, 5):
        block[0] = b
        current = await sampler(state, capture_at(b))
        if b < 310:
            assert current.seal is None
    assert current.seal.observation.block == 310


@pytest.mark.parametrize(
    "field,value",
    [
        ("nonce", "ff" * 16),
        ("policy_sha256", "ff" * 32),
        ("cohort_sha256", "ff" * 32),
        ("authority_sha256", "ff" * 32),
        ("recovery_tip_sha256", "ff" * 32),
        ("ready", "true"),
        ("chain_submission_authorized", True),
        ("reason_code", "capacity_exhausted"),
    ],
)
async def test_unbound_or_inconsistent_status_never_credits_service(phase, scenario, field, value):
    def serve(request):
        data = reply_for(phase, scenario, request)
        data[field] = value
        return httpx.Response(200, json=data)

    sampler = LiveIntakePhaseObserver(
        phase, "https://intake.example", transport=httpx.MockTransport(serve)
    )
    result = await sampler(state_for(scenario), capture_at(210))
    assert not result.service.serving and result.service.unavailable_blocks == 10
    assert result.seal is None


@pytest.mark.parametrize("block", [199, 221])
async def test_stale_or_far_future_server_capture_is_unavailable(phase, scenario, block):
    def serve(request):
        data = reply_for(phase, scenario, request)
        data["observation"]["block"] = block
        return httpx.Response(200, json=data)

    sampler = LiveIntakePhaseObserver(
        phase, "https://intake.example", transport=httpx.MockTransport(serve)
    )
    assert not (await sampler(state_for(scenario), capture_at(210))).service.serving


@pytest.mark.parametrize("field", ["block_hash", "state_root"])
async def test_same_height_conflicting_finality_is_unavailable(phase, scenario, field):
    def serve(request):
        data = reply_for(phase, scenario, request)
        data["observation"][field] = "0x" + "ff" * 32
        return httpx.Response(200, json=data)

    sampler = LiveIntakePhaseObserver(
        phase, "https://intake.example", transport=httpx.MockTransport(serve)
    )
    assert not (await sampler(state_for(scenario), capture_at(210))).service.serving


@pytest.mark.parametrize("failure", ["redirect", "encoding", "type", "bytes", "json", "io"])
async def test_bad_transport_is_unavailable_without_followup(phase, scenario, failure):
    calls = []

    def serve(request):
        calls.append(request)
        if failure == "io":
            raise httpx.ReadError("private transport details")
        data = reply_for(phase, scenario, request)
        if failure == "redirect":
            return httpx.Response(302, headers={"location": "https://other.example"})
        headers = {"content-type": "application/json"}
        if failure == "encoding":
            headers["content-encoding"] = "br"
        if failure == "type":
            headers["content-type"] = "text/plain"
        raw = json.dumps(data).encode()
        if failure == "bytes":
            raw = b" " * (16 * 1024 + 1)
        if failure == "json":
            raw = b"not json"
        return httpx.Response(200, content=raw, headers=headers)

    sampler = LiveIntakePhaseObserver(
        phase, "https://intake.example", transport=httpx.MockTransport(serve)
    )
    assert not (await sampler(state_for(scenario), capture_at(210))).service.serving
    assert len(calls) == 1


async def test_cached_success_is_rejected_on_next_nonce(phase, scenario):
    cache = []

    def serve(request):
        if not cache:
            cache.append(reply_for(phase, scenario, request))
        return httpx.Response(200, json=cache[0])

    sampler = LiveIntakePhaseObserver(
        phase, "https://intake.example", transport=httpx.MockTransport(serve)
    )
    state = state_for(scenario)
    assert (await sampler(state, capture_at(210))).service.serving
    assert not (await sampler(state, capture_at(215))).service.serving


async def test_timeout_counts_unavailable_but_cancellation_does_not_write(phase, scenario):
    entered = asyncio.Event()

    async def wait(_):
        entered.set()
        await asyncio.Event().wait()

    sampler = LiveIntakePhaseObserver(
        phase,
        "https://intake.example",
        transport=httpx.MockTransport(wait),
        timeout_seconds=0.05,
    )
    state = state_for(scenario)
    timed_out = await sampler(state, capture_at(210))
    assert not timed_out.service.serving
    entered.clear()
    task = asyncio.create_task(sampler(state, capture_at(215)))
    await entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    with phase.intake._connection() as (db, _):
        assert db.execute("SELECT COUNT(*) FROM cohort_service_observations").fetchone() == (1,)


@pytest.mark.parametrize("condition", ["archive", "capacity", "fence"])
async def test_native_readiness_reflects_intake_constraints(phase, scenario, condition):
    if condition == "capacity":
        phase.intake.capacity = AdmissionCapacity(maximum_records=1)
    if condition == "fence":
        healthy(phase, scenario)
    block = [300 if condition == "fence" else 210]
    app = router(phase.intake, block, archive=condition != "archive")
    cohort = digest(scenario["intake_history"].plan)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app), base_url="https://intake.example"
    ) as client:
        response = await client.get(
            f"/v1/competition/cohorts/{cohort}/readiness", params={"nonce": "ab" * 16}
        )
    assert response.status_code == 200
    assert response.json()["ready"] is False
    assert (
        response.json()["reason_code"]
        == {"archive": "archive_unavailable", "capacity": "capacity_exhausted", "fence": "fenced"}[
            condition
        ]
    )


async def test_missing_decision_source_is_retryable_api_failure(phase, scenario):
    from .test_competition_cohort_intake_phase import extension_input

    history, evidence = extension_input(phase, scenario)
    phase.intake.publish(history, capture_at(305), decision_inputs=(evidence,))
    with phase.intake._connection() as (db, _):
        db.execute("DELETE FROM cohort_recovery_sources")
    app = router(phase.intake, [305])
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app), base_url="https://intake.example"
    ) as client:
        response = await client.get(
            f"/v1/competition/cohorts/{digest(history.plan)}/readiness",
            params={"nonce": "ab" * 16},
        )
    assert response.status_code == 503


async def test_owned_finality_failure_is_safe_retryable_api_failure(phase, scenario):
    async def unavailable():
        raise RuntimeError("private RPC details")

    app = FastAPI()
    app.include_router(cohort_routes(phase.intake, unavailable, maximum_body_bytes=1024))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app), base_url="https://intake.example"
    ) as client:
        response = await client.get(
            f"/v1/competition/cohorts/{digest(scenario['intake_history'].plan)}/readiness",
            params={"nonce": "ab" * 16},
        )
    assert response.status_code == 503
    assert "private RPC" not in response.text


async def test_late_recovered_api_keeps_intake_open_and_restores_outage(phase, scenario):
    sampler = LiveIntakePhaseObserver(
        phase,
        "https://intake.example",
        transport=httpx.ASGITransport(router(phase.intake, [1400])),
    )
    result = await sampler(state_for(scenario), capture_at(1400))
    assert result.service.serving
    assert result.service.unavailable_blocks == 1200
    assert result.progress.completion == "pending" and result.seal is None


@pytest.mark.parametrize("nonce", [None, "x", "ab" * 17])
async def test_api_requires_bounded_nonce(phase, scenario, nonce):
    app = router(phase.intake, [210])
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app), base_url="https://intake.example"
    ) as client:
        response = await client.get(
            f"/v1/competition/cohorts/{digest(scenario['intake_history'].plan)}/readiness",
            params={} if nonce is None else {"nonce": nonce},
        )
    assert response.status_code == 422


async def test_probe_uses_readiness_capacity_and_preserves_no_store(phase, scenario, tmp_path):
    entered, release = asyncio.Event(), asyncio.Event()

    async def current():
        return capture_at(210).snapshot

    async def capture():
        entered.set()
        await release.wait()
        return capture_at(210)

    async def archive(_):
        raise AssertionError("readiness should not archive a consent")

    app = create_app(
        CompetitionStore(tmp_path / "base", scenario["policy"]),
        current,
        registration_source="verifier_attested_finality",
        cohort_intake=phase.intake,
        cohort_capture_provider=capture,
        cohort_archive_provider=archive,
        limits=CompetitionApiLimits(maximum_concurrent_readiness=1, capacity_wait_seconds=0.05),
    )
    path = f"/v1/competition/cohorts/{digest(scenario['intake_history'].plan)}/readiness"
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app), base_url="https://intake.example"
    ) as client:
        first = asyncio.create_task(client.get(path, params={"nonce": "ab" * 16}))
        try:
            await asyncio.wait_for(entered.wait(), timeout=1)
            second = await client.get(path, params={"nonce": "cd" * 16})
            assert second.status_code == 503
            assert second.headers["cache-control"] == "no-store"
            history = await client.get(path.replace("/readiness", "/history"))
            assert history.status_code == 200
        finally:
            release.set()
            response = await first
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.json()["ready"] is True
