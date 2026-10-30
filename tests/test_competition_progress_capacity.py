"""Cached diagnostics survive slow native reads without enlarging those lanes."""

import asyncio
from types import SimpleNamespace

import httpx
import pytest

from umi import competition_api as public
from umi import competition_cohort_api as cohort
from umi.competition_cohort_public_progress import (
    CohortProgressSnapshots,
    is_cached_cohort_progress_request,
)
from umi.competition_store import CompetitionStore

from .test_open_competition import policy as policy

C = "c" * 64
PATH = f"/v1/competition/cohorts/{C}/progress"


async def forbidden(*args, **kwargs):
    raise AssertionError("cached progress performed native I/O or RPC")


async def test_cached_native_progress_survives_general_read_saturation(
    policy, tmp_path, monkeypatch
):
    store = CompetitionStore(tmp_path / "state", policy)
    app = public.create_app(
        store,
        forbidden,
        limits=public.CompetitionApiLimits(maximum_concurrent_reads=1, capacity_wait_seconds=0.05),
    )
    snapshots = CohortProgressSnapshots()
    snapshots.record("lifecycle", dict(cohort_sha256=C, phase="requests"))
    snapshots.record(
        "execution",
        dict(cohort_sha256=C, stage="model_evaluation", completed=97, total=103, percent=94.175),
    )
    monkeypatch.setattr(cohort, "PUBLIC_COHORT_PROGRESS", snapshots)
    monkeypatch.setattr(cohort, "CohortAdmissionQueue", lambda _: object())
    app.include_router(
        cohort.cohort_routes(
            SimpleNamespace(bindings={C: "authority"}),
            forbidden,
            maximum_body_bytes=1024,
        )
    )
    entered, release = asyncio.Event(), asyncio.Event()

    @app.get("/slow-native-read")
    async def slow():
        entered.set()
        await release.wait()
        return {"done": True}

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app),
        base_url="http://test",
    ) as client:
        slow_read = asyncio.create_task(client.get("/slow-native-read"))
        try:
            await asyncio.wait_for(entered.wait(), 2)
            # Reproduce the predecessor's shared-lane failure in this same app.
            with monkeypatch.context() as old:
                old.setattr(public, "is_cached_cohort_progress_request", lambda *_: False)
                assert (await client.get(PATH)).status_code == 503
            response = await client.get(PATH)
            assert response.status_code == 200
            assert response.json()["completed"] == 97
            assert response.headers["cache-control"] == "no-store"
            assert not slow_read.done()
            # Other native reads retain their original admission bound.
            assert (await client.get(f"/v1/competition/cohorts/{C}/history")).status_code == 503
            unknown = "/v1/competition/cohorts/" + "d" * 64 + "/progress"
            assert (await client.get(unknown)).status_code == 404
        finally:
            release.set()
            assert (await slow_read).status_code == 200


async def test_diagnostic_lane_is_bounded_and_queued_cancellation_does_not_leak(
    policy,
    tmp_path,
):
    app = public.create_app(
        CompetitionStore(tmp_path / "state", policy),
        forbidden,
        limits=public.CompetitionApiLimits(maximum_concurrent_reads=1, capacity_wait_seconds=0.05),
    )
    entered, release = asyncio.Event(), asyncio.Event()

    @app.get(PATH)
    async def snapshot():
        entered.set()
        await release.wait()
        return {"cached": True}

    @app.get("/ordinary-read")
    async def ordinary():
        return {"ok": True}

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app),
        base_url="http://test",
    ) as client:
        first = asyncio.create_task(client.get(PATH))
        try:
            await asyncio.wait_for(entered.wait(), 2)
            queued = asyncio.create_task(client.get(PATH))
            await asyncio.sleep(0)
            queued.cancel()
            with pytest.raises(asyncio.CancelledError):
                await queued
            assert (await client.get(PATH)).status_code == 503
            assert (await client.get("/ordinary-read")).status_code == 200
        finally:
            release.set()
            assert (await first).status_code == 200
        assert (await client.get(PATH)).status_code == 200


@pytest.mark.parametrize(
    "method,path",
    [
        ("POST", PATH),
        ("HEAD", PATH),
        ("GET", PATH + "/"),
        ("GET", PATH.replace(C, "c" * 63)),
        ("GET", PATH.replace(C, "C" * 64)),
        ("GET", PATH + "/extra"),
        ("GET", PATH.replace("/progress", "/history")),
    ],
)
def test_only_exact_cache_only_gets_use_diagnostic_admission(method, path):
    assert not is_cached_cohort_progress_request(method, path)


def test_valid_cached_routes_cover_every_cohort_without_a_sequence_allowlist():
    for value in ("0", "a", "f"):
        assert is_cached_cohort_progress_request(
            "GET",
            f"/v1/competition/cohorts/{value * 64}/progress",
        )
