"""Native benchmark host through authenticated history; only inference/finality are fixtures."""

import asyncio
from types import SimpleNamespace

import httpx
import pytest

from umi import competition_cohort_benchmark_host as host_module
from umi.competition_cohort_benchmark_host import BenchmarkHost, BenchmarkHostConfig
from umi.competition_cohort_execution_journal import step_count
from umi.competition_cohort_history_http import (
    CohortHistoryRequest,
    CohortHistoryResponse,
    SignedCohortHistoryResponse,
)
from umi.open_competition import digest, identity, sign_object
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_executor import base_policy as base_policy
from .test_competition_cohort_executor import execution as execution
from .test_competition_cohort_executor import harness as harness
from .test_competition_cohort_executor import legacy_scenario as legacy_scenario
from .test_competition_cohort_executor import policy as policy
from .test_competition_cohort_executor import receipt_scenario as receipt_scenario
from .test_competition_cohort_executor import recovery as recovery
from .test_competition_cohort_executor import relay as relay
from .test_competition_cohort_executor import runtime as runtime
from .test_competition_cohort_executor import scenario as scenario
from .test_open_competition import wallet


@pytest.fixture
async def native(execution, tmp_path, monkeypatch):
    e = execution
    n = SimpleNamespace(e=e, unavailable=False, history_reads=0, signs=[])
    name = e.r.names[identity(e.box.config.signer)]
    config = BenchmarkHostConfig(
        schema="umi-cohort-benchmark-host/1",
        directory=str(tmp_path / "benchmark-host"),
        orders=e.r.h.worker(name).journal.config,
        inbox=e.box.config,
        execution=e.cfg,
        archive_directory=str(tmp_path / "models"),
        videos_directory=str(tmp_path / "videos"),
        workspace_directory=str(tmp_path / "scratch"),
        request_export_directory=str(tmp_path / "exports"),
        poll_seconds=1,
    )
    outer = SimpleNamespace(
        benchmark=config,
        policy=e.r.h.batch["policy"],
        series={"fixture_cohort": e.r.cohort},
        owner_hotkey=wallet("Charlie").hotkey.ss58_address,
        owner_origin="https://owner.example",
        review_timeout_seconds=30,
    )

    def history(request):
        n.history_reads += 1
        assert request.headers["authorization"] == "Bearer " + "owner-token" * 4
        if n.unavailable:
            return httpx.Response(503)
        selected = CohortHistoryRequest.model_validate_json(request.content)
        assert selected.cohort_sha256 == e.r.cohort
        body = CohortHistoryResponse(
            schema="umi-cohort-history-response/1",
            source=e.r.h.source,
            challenge=selected.challenge,
        )
        return httpx.Response(
            200,
            content=canonical_json_bytes(
                SignedCohortHistoryResponse(
                    response=body, signature=sign_object(body, wallet("Charlie"))
                )
            ),
            headers={"content-type": "application/json"},
        )

    async def sign(body):
        n.signs.append(digest(body))
        return sign_object(body, wallet(name))

    monkeypatch.setattr(host_module, "CohortCpuSandbox", lambda *args, **kwargs: e.port)
    async with httpx.AsyncClient(transport=httpx.MockTransport(history)) as client:
        n.host = lambda: BenchmarkHost(
            outer, e.box.provider, client, "owner-token" * 4, "vote-token" * 4, sign
        )
        yield n


async def test_completed_steps_survive_offline_restart_and_export_originals(native):
    n, e = native, native.e
    first = n.host()
    await first.worker.poll_once()
    original = canonical_json_bytes(first.execution.step(e.job, 0))
    n.unavailable = True
    e.r.h.block += 3000
    interrupted = n.host()
    assert (await interrupted.worker.poll_once())["retry_count"] == 1
    assert canonical_json_bytes(interrupted.execution.step(e.job, 0)) == original
    assert len(e.calls) == 1
    n.unavailable = False
    for _ in range(step_count(e.job) - 1):
        assert (await interrupted.worker.poll_once())["retry_count"] == 0
    assert interrupted.execution.evidence(e.r.slot) is not None
    report = await interrupted.exporter.poll_once()
    if e.job.mode == "paired_model":
        assert report["assignments_exported"] == 1
        assert len(n.signs) == 1
        assert interrupted.files.terminal(e.assignment.certificate, e.box.config.signer) is not None
    else:
        # An endpoint benchmark still needs its actual signed miner responses.
        assert report["assignments_pending"] == 1
        assert not n.signs
    n.unavailable = True
    e.r.h.fail_collect = True
    count = len(e.calls), len(n.signs), n.history_reads
    assert (await n.host().worker.poll_once())["jobs_complete"] == 1
    assert (len(e.calls), len(n.signs), n.history_reads) == count


async def test_host_runs_workers_and_drains_cancelled_inference(native):
    n, e = native, native.e
    entered, finished = asyncio.Event(), asyncio.Event()

    async def hanging(job, attempt):
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            await asyncio.sleep(0)
            finished.set()

    e.port.invoke = hanging
    host = n.host()
    stop = asyncio.Event()
    task = asyncio.create_task(host.run(stop))
    try:
        await asyncio.wait_for(entered.wait(), 20)
        assert not task.done()
        assert set(host.tasks) == {"execution", "exports"}
    finally:
        stop.set()
        await asyncio.wait_for(task, 20)
    assert finished.is_set() and not host.tasks
    assert host.execution.evidence(e.r.slot) is None
    # The retained interrupted attempt is still available for native reconciliation.
    assert host.execution.head(e.job, 0) is not None


async def test_host_reports_failed_worker_without_private_exception_text(native):
    class FailedWorker:
        async def run(self, stop, *, poll_seconds, report):
            raise ValueError("PRIVATE_WORKER_EXCEPTION_TEXT")

    host = native.host()
    host.workers = {"execution": FailedWorker()}
    with pytest.raises(
        host_module.BenchmarkWorkerFailure,
        match=r"^benchmark_execution_worker_stopped$",
    ) as caught:
        await host.run(asyncio.Event())
    assert caught.value.reason_code == "benchmark_execution_worker_stopped"
    assert "PRIVATE_WORKER_EXCEPTION_TEXT" not in str(caught.value)
    assert not host.tasks


async def test_repeated_cancellation_waits_for_inference_cleanup(native):
    n, e = native, native.e
    entered, cleaning, release = asyncio.Event(), asyncio.Event(), asyncio.Event()

    async def invocation(job, attempt):
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            cleaning.set()
            await release.wait()

    e.port.invoke = invocation
    host = n.host()
    task = asyncio.create_task(host.run(asyncio.Event()))
    try:
        await asyncio.wait_for(entered.wait(), 20)
        task.cancel()
        await asyncio.wait_for(cleaning.wait(), 20)
        task.cancel()
        await asyncio.sleep(0.01)
        assert not task.done() and host.tasks
    finally:
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 20)
    assert not host.tasks
