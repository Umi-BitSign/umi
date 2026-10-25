"""Live cached stages, old-peer compatibility, restart isolation and bounded views."""

import asyncio
import json
import sqlite3
from collections import OrderedDict
from pathlib import Path
from types import SimpleNamespace as NS

import httpx
import pytest
from fastapi import FastAPI

from umi import competition_cohort_execution_work as module
from umi import competition_cohort_public_progress as public
from umi.competition_cohort_producer_epoch import ExecutionProducerEpochs, producer_epoch_routes
from umi.host_memory_runtime import RequestsStageASGIBinding

from .test_competition_cohort_producer_epoch import EVALUATOR, EVALUATOR_ID, TOKEN

C = "c" * 64
EPOCH = "11" * 32


def stage(**changes):
    return dict(
        stage="model_materialization",
        state="running",
        work_id=-1,
        completed=50,
        total=100,
        percent=50,
        elapsed_seconds=10,
        eta_seconds=20,
        age_seconds=0,
        eta_basis="native_work_units_per_elapsed_second",
        unit="bytes",
        **changes,
    )


def envelope(stages=None):
    return dict(
        schema="umi-execution-work/1",
        evaluator=EVALUATOR_ID,
        epoch_sha256=EPOCH,
        cohort_sha256=C,
        execution_enabled=True,
        stages=[stage()] if stages is None else stages,
    )


def observer(client):
    return ExecutionProducerEpochs(
        client, [NS(signer=EVALUATOR, origin="http://127.0.0.1:19579")], [TOKEN]
    )


async def test_cached_native_stages_reach_public_component_without_changing_export_counts(
    monkeypatch,
):
    monkeypatch.setattr(public.PUBLIC_COHORT_PROGRESS, "entries", OrderedDict())
    private = public.PUBLIC_COHORT_PROGRESS
    private.record(
        "work",
        dict(
            cohort_sha256=C,
            **stage(),
            job_sha256="private-job",
            model_path="/private/model",
            exception="private input",
        ),
    )
    app = FastAPI()
    app.include_router(producer_epoch_routes(EVALUATOR, token=TOKEN, enabled=True, cohorts=(C,)))
    with monkeypatch.context() as guard:

        def forbidden(*args, **kwargs):
            raise AssertionError("cached diagnostic request performed native I/O")

        guard.setattr(sqlite3, "connect", forbidden)
        guard.setattr(Path, "read_bytes", forbidden)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:19579"
        ) as client:
            endpoint = module.WORK_PATH + C
            assert (await client.get(endpoint)).status_code == 401
            headers = {"authorization": "Bearer " + TOKEN}
            assert (
                await client.get(module.WORK_PATH + "d" * 64, headers=headers)
            ).status_code == 404
            peer = observer(client)
            epochs = await peer.sample([EVALUATOR_ID])
            workers = await peer.work.sample(C, [EVALUATOR_ID], epochs)
    assert workers[0]["stages"][0]["percent"] == 50
    assert "private" not in json.dumps(workers)
    intake = public.CohortProgressSnapshots()
    intake.record("lifecycle", dict(cohort_sha256=C, phase="requests"))
    intake.record(
        "execution",
        dict(
            cohort_sha256=C,
            stage="model_evaluation",
            completed=91,
            total=103,
            percent=88.35,
            stalled_or_retrying=True,
        ),
    )
    intake.record("execution_workers", dict(cohort_sha256=C, workers=workers))
    value = intake.snapshot(C)
    assert (value["stage"], value["completed"], value["percent"]) == ("model_evaluation", 91, 88.35)
    assert value["stalled_or_retrying"]  # Export stall remains distinct from worker activity.
    assert value["components"]["execution_workers"]["workers"][0]["stages"][0]["percent"] == 50
    value["components"]["execution_workers"]["workers"][0]["stages"].clear()
    assert intake.snapshot(C)["components"]["execution_workers"]["workers"][0]["stages"]


async def test_work_cache_ages_eta_and_discards_previous_stages_on_restart_or_failed_refresh(
    monkeypatch,
):
    clock, calls, mode = [0], [], ["current"]
    monkeypatch.setattr(module.time, "monotonic", lambda: clock[0])

    def reply(request):
        calls.append(request)
        assert request.headers["authorization"] == "Bearer " + TOKEN
        if mode[0] == "old":
            return httpx.Response(404)
        return httpx.Response(200, json=envelope())

    async with httpx.AsyncClient(transport=httpx.MockTransport(reply)) as client:
        peer = observer(client)
        first = await peer.work.sample(C, [EVALUATOR_ID], {EVALUATOR_ID: EPOCH})
        clock[0] = 15
        cached = await peer.work.sample(C, [EVALUATOR_ID], {EVALUATOR_ID: EPOCH})
        assert len(calls) == 1
        assert first[0]["stages"][0]["eta_seconds"] == 20
        assert cached[0]["stages"][0]["eta_seconds"] == 5
        assert cached[0]["stages"][0]["age_seconds"] == 15
        clock[0] = 21
        overdue = await peer.work.sample(C, [EVALUATOR_ID], {EVALUATOR_ID: EPOCH})
        assert overdue[0]["stages"][0]["eta_seconds"] is None
        # A restarted producer bypasses the old cache; an old process response
        # cannot attach its prior work to the new confirmed rate epoch.
        restarted = await peer.work.sample(C, [EVALUATOR_ID], {EVALUATOR_ID: "22" * 32})
        assert restarted[0] == dict(
            evaluator=EVALUATOR_ID, status="invalid_or_unavailable", stages=[]
        )
        clock[0], mode[0] = 52, "old"
        old = await peer.work.sample(C, [EVALUATOR_ID], {EVALUATOR_ID: EPOCH})
        assert old[0] == dict(evaluator=EVALUATOR_ID, status="unavailable", stages=[])
        unknown = await peer.work.sample(C, [EVALUATOR_ID], {})
        assert unknown[0]["status"] == "epoch_unavailable" and not unknown[0]["stages"]


@pytest.mark.parametrize(
    "fault",
    [
        "oversized",
        "malformed",
        "wrong_cohort",
        "wrong_signer",
        "disabled",
        "too_many",
        "duplicate",
        "nan",
        "bool",
        "timeout",
    ],
)
async def test_invalid_or_unavailable_peer_cannot_supply_live_work(fault):
    def reply(request):
        if fault == "timeout":
            raise httpx.ReadTimeout("private endpoint timeout", request=request)
        if fault == "oversized":
            return httpx.Response(200, content=b" " * (module.MAX_BYTES + 1))
        if fault == "malformed":
            return httpx.Response(200, json=[])
        body = envelope()
        if fault == "wrong_cohort":
            body["cohort_sha256"] = "d" * 64
        elif fault == "wrong_signer":
            body["evaluator"] = "00" * 32
        elif fault == "disabled":
            body["execution_enabled"] = False
        elif fault == "too_many":
            body["stages"] *= 33
        elif fault == "duplicate":
            body["stages"] *= 2
        elif fault == "nan":
            return httpx.Response(
                200, content=json.dumps({**body, "stages": [{**stage(), "percent": float("nan")}]})
            )
        elif fault == "bool":
            body["stages"][0]["completed"] = True
        return httpx.Response(200, json=body)

    async with httpx.AsyncClient(transport=httpx.MockTransport(reply)) as client:
        rows = await observer(client).work.sample(C, [EVALUATOR_ID], {EVALUATOR_ID: EPOCH})
        assert rows == [dict(evaluator=EVALUATOR_ID, status="invalid_or_unavailable", stages=[])]


def test_public_inventory_is_bounded_redacted_and_stale_estimates_are_withdrawn(monkeypatch):
    clock = [0]
    monkeypatch.setattr(public.time, "monotonic", lambda: clock[0])
    state = public.CohortProgressSnapshots()
    workers = [
        dict(
            evaluator=f"{i:064x}",
            status="current",
            credential="secret",
            stages=[{**stage(), "work_id": j, "input": "secret"} for j in range(32)],
        )
        for i in range(64)
    ]
    state.record("execution_workers", dict(cohort_sha256=C, workers=workers))
    current = state.snapshot(C)["components"]["execution_workers"]["workers"]
    assert sum(len(row["stages"]) for row in current) == 32
    assert sum(row["omitted_stages"] for row in current) == 2016
    assert "secret" not in json.dumps(current)
    clock[0] = 121
    stale = state.snapshot(C)["components"]["execution_workers"]["workers"][0]["stages"][0]
    assert stale["stale"] and stale["eta_seconds"] is None


def test_request_stage_binding_only_allows_exact_cached_read_paths():
    wrapper = RequestsStageASGIBinding(
        None, controller=NS(policy=NS(operations=())), private_role="phase_reviewer"
    )
    assert wrapper._permitted(dict(method="GET", path=module.WORK_PATH + C))
    for path in (module.WORK_PATH, module.WORK_PATH + "../private", module.WORK_PATH + C + "/"):
        assert not wrapper._permitted(dict(method="GET", path=path))
    assert not wrapper._permitted(dict(method="POST", path=module.WORK_PATH + C))


async def test_work_sampling_cancellation_is_not_swallowed():
    async def reply(request):
        raise asyncio.CancelledError

    async with httpx.AsyncClient(transport=httpx.MockTransport(reply)) as client:
        with pytest.raises(asyncio.CancelledError):
            await observer(client).work.sample(C, [EVALUATOR_ID], {EVALUATOR_ID: EPOCH})


async def test_diagnostic_failure_does_not_stop_confirmed_export_sampling(monkeypatch):
    from umi.competition_cohort_lifecycle_host import LifecycleHost

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    samples = []

    class Meter:
        selected = True
        required_producers = (EVALUATOR_ID,)

        def sample(self, **kwargs):
            samples.append(kwargs)
            if len(samples) == 2:
                loop.call_soon_threadsafe(stop.set)
            return dict(cohort_sha256=C, stage="model_evaluation", completed=91, total=103)

    class Peer:
        async def sample(self, *args):
            return {EVALUATOR_ID: EPOCH}

        def diagnostics(self, *args):
            return {}

    class BrokenWork:
        async def sample(self, *args):
            raise ValueError("private malformed diagnostic")

    peer = Peer()
    peer.work = BrokenWork()
    host = NS(
        config=NS(poll_seconds=1),
        requests={C: NS()},
        execution_progress={C: Meter()},
        producer_epochs=peer,
        forecast_ledger=None,
        service=NS(config=NS(series=NS(cohorts=()))),
    )
    monkeypatch.setattr(public.PUBLIC_COHORT_PROGRESS, "entries", OrderedDict())
    await asyncio.wait_for(LifecycleHost.run(host, stop), timeout=3)
    assert len(samples) == 2
    result = public.PUBLIC_COHORT_PROGRESS.snapshot(C)
    assert result["components"]["execution"]["completed"] == 91
