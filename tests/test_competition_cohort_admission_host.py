"""Configured owner startup with native votes; synthetic finality and HTTPS routing."""

import asyncio
import socket
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from fastapi import FastAPI

import umi.competition_cohort_admission_host as boot
from umi.competition_cohort_admission_http import (
    AdmissionHistoryHTTPClient,
    AdmissionHistoryReader,
    admission_vote_routes,
)
from umi.competition_cohort_preparation_owner import CohortPreparation
from umi.competition_cohort_review_http import CohortReviewPeerConfig
from umi.competition_store import CompetitionStore
from umi.open_competition import identity
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_admission_http import (  # noqa: F401
    OWNER,
    OWNER_TOKEN,
    VOTE_TOKEN,
    accepted,
    archive,
    chain,
    chain_config,
    harness,
    legacy_scenario,
    policy,
    recovery,
    scenario,
    status,
    submit,
    wallet,
)
from .test_competition_cohort_admission_http import relay as relay


@pytest.fixture
async def owned(relay, tmp_path, monkeypatch):
    h = relay
    await submit(h)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    c = boot.AdmissionOwnerConfig(
        schema="umi-cohort-admission-owner/1",
        directory=str(tmp_path / "owner-state"),
        owner_hotkey=OWNER,
        owner_key_file=str(tmp_path / "owner-key"),
        export_token_file=str(tmp_path / "owner-token"),
        reviewers=tuple(
            CohortReviewPeerConfig(
                signer=wallet(name).hotkey.ss58_address,
                origin=f"https://{name.lower()}.example",
                token_file=str(tmp_path / f"{name}-token"),
                timeout_seconds=2,
            )
            for name in ("Charlie", "Dave")
        ),
        listen_port=port,
        poll_seconds=1,
    )
    preparation = CohortPreparation(
        h.queue, CompetitionStore(tmp_path / "promotion", h.queue.policy)
    )
    apps, unavailable = {}, set()

    class Routing(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            if request.url.host in unavailable:
                raise httpx.ConnectError("synthetic reviewer outage")
            return await httpx.ASGITransport(app=apps[request.url.host]).handle_async_request(
                request
            )

    client_type, server_type = httpx.AsyncClient, boot._Server
    client = client_type(transport=Routing(), trust_env=False)
    history = AdmissionHistoryReader(
        OWNER,
        AdmissionHistoryHTTPClient(client, "https://owner.example", token=OWNER_TOKEN),
    )
    for name in ("Charlie", "Dave"):
        reviewer = h.worker(name)
        reviewer.history = history
        reviewer.archive = AsyncMock(return_value=(h.archive.raw, h.archive.metadata))
        app = FastAPI()
        app.include_router(admission_vote_routes(reviewer, token=VOTE_TOKEN))
        apps[name.lower() + ".example"] = app

    def server(cfg):
        apps["owner.example"] = cfg.app
        return server_type(cfg)

    monkeypatch.setattr(boot, "_Server", server)
    monkeypatch.setattr(boot, "load_named_hotkey", lambda *_: wallet("Charlie"))
    monkeypatch.setattr(
        boot, "_token", lambda p: OWNER_TOKEN if p == c.export_token_file else VOTE_TOKEN
    )
    monkeypatch.setattr(h.archive.reviewer, "ensure_observer_running", lambda: None)
    monkeypatch.setattr(
        boot.httpx,
        "AsyncClient",
        lambda **kw: client_type(**({"transport": Routing()} | kw)),
    )
    tasks = []

    def start():
        stop = asyncio.Event()
        task = asyncio.create_task(
            boot.run_admission_owner(c, preparation, h.archive.reviewer, stop)
        )
        tasks.append((stop, task))
        return stop, task

    try:
        yield SimpleNamespace(
            h=h,
            config=c,
            preparation=preparation,
            apps=apps,
            unavailable=unavailable,
            start=start,
            client_type=client_type,
        )
    finally:
        for stop, task in tasks:
            stop.set()
            if not task.done():
                await asyncio.wait_for(task, timeout=10)
            elif not task.cancelled():
                task.exception()
        await client.aclose()


async def until(check, *, timeout=10):
    async def poll():
        while not await check():
            await asyncio.sleep(0.02)

    await asyncio.wait_for(poll(), timeout=timeout)


async def test_recurring_owner_recovers_partial_quorum_after_restart(owned):
    o, h = owned, owned.h
    o.unavailable.add("dave.example")
    stop, task = o.start()

    async def one_vote():
        return len(h.calls) == 1

    await until(one_vote)
    assert (await status(h)).status == "pending_attestation"
    async with o.client_type(transport=httpx.AsyncHTTPTransport(), trust_env=False) as client:
        response = await client.post(
            f"http://127.0.0.1:{o.config.listen_port}/internal/cohorts/admission-history",
            json={},
        )
        assert response.status_code == 401
    with pytest.raises(BlockingIOError):
        async with boot.admission_owner_app(o.config, o.preparation, h.archive.reviewer):
            pytest.fail("second owner acquired live process lease")
    stop.set()
    await asyncio.wait_for(task, timeout=10)
    o.unavailable.clear()
    stop, task = o.start()

    async def certified():
        return (await status(h)).status == "admission_certified"

    await until(certified)
    original = canonical_json_bytes((await status(h)).certificate)
    assert len(h.calls) == 2
    stop.set()
    await asyncio.wait_for(task, timeout=10)
    stop, task = o.start()
    await until(certified)
    assert canonical_json_bytes((await status(h)).certificate) == original
    assert len(h.calls) == 2
    stop.set()
    await asyncio.wait_for(task, timeout=10)


async def test_slow_first_reviewer_does_not_starve_second(owned):
    o, h = owned, owned.h
    o.unavailable.add("charlie.example")
    stop, task = o.start()

    async def dave_finished():
        app = o.apps.get("owner.example")
        return (
            app is not None
            and app.state.admission_reports.get(
                identity(wallet("Dave").hotkey.ss58_address), {}
            ).get("votes_published")
            == 1
        )

    await until(dave_finished)
    assert (await status(h)).status == "pending_attestation"
    o.unavailable.clear()

    async def certified():
        return (await status(h)).status == "admission_certified"

    await until(certified)
    stop.set()
    await asyncio.wait_for(task, timeout=10)


async def test_service_owner_shares_its_capture_with_every_reviewer(owned):
    o = owned

    async def shared_capture():
        return await o.h.archive.reviewer.collect()

    service = SimpleNamespace(
        preparation=o.preparation,
        provider=o.h.archive.reviewer,
        capture=shared_capture,
        config=SimpleNamespace(lifecycle=None),
    )
    async with boot.admission_owner_app(
        o.config,
        o.preparation,
        o.h.archive.reviewer,
        service_host=service,
    ) as app:
        assert app.state.admission_workers
        assert all(worker.capture is shared_capture for worker in app.state.admission_workers)
        assert app.state.intake_review_exporter.timeout_seconds == 2


async def test_unexpected_worker_failure_drains_other_workers_before_releasing_owner(
    owned, monkeypatch
):
    o = owned
    entered, drained = asyncio.Event(), asyncio.Event()

    async def fail_or_wait(worker):
        if identity(worker.votes.signer) == identity(o.config.reviewers[0].signer):
            await entered.wait()
            raise RuntimeError("synthetic unexpected worker failure")
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            drained.set()

    monkeypatch.setattr(boot.CohortAdmissionWorker, "poll_once", fail_or_wait)
    _, task = o.start()
    with pytest.raises(RuntimeError, match="unexpected worker failure"):
        await asyncio.wait_for(task, timeout=10)
    assert drained.is_set()
    async with boot.admission_owner_app(o.config, o.preparation, o.h.archive.reviewer):
        pass


@pytest.mark.parametrize("fault", ["credentials", "key", "quorum", "public-listener", "overlap"])
async def test_owner_rejects_invalid_configuration_before_serving(owned, monkeypatch, fault):
    o, c = owned, owned.config
    if fault == "credentials":
        monkeypatch.setattr(boot, "_token", lambda _: OWNER_TOKEN)
    elif fault == "key":
        monkeypatch.setattr(
            boot, "load_named_hotkey", lambda *_: (_ for _ in ()).throw(ValueError("key"))
        )
    elif fault == "quorum":
        c = c.model_copy(update={"reviewers": c.reviewers[:1]})
    elif fault == "public-listener":
        c = c.model_copy(update={"listen_host": "0.0.0.0"})
    else:
        c = c.model_copy(update={"owner_key_file": str(Path(c.directory) / "key")})
    with pytest.raises(ValueError):
        async with boot.admission_owner_app(c, o.preparation, o.h.archive.reviewer):
            pytest.fail("invalid admission host started")
    monkeypatch.setattr(boot, "load_named_hotkey", lambda *_: wallet("Charlie"))
    monkeypatch.setattr(
        boot, "_token", lambda p: OWNER_TOKEN if p == o.config.export_token_file else VOTE_TOKEN
    )
    async with boot.admission_owner_app(o.config, o.preparation, o.h.archive.reviewer):
        pass  # A failed start released its process lease.


@pytest.mark.parametrize("durable", [False, True])
async def test_shutdown_bounds_control_drain_and_retains_owned_writes(owned, monkeypatch, durable):
    import threading

    from umi.concurrency import run_owned_thread

    o = owned
    entered, cancelled = asyncio.Event(), asyncio.Event()
    release, written = threading.Event(), threading.Event()
    server_factory = boot._Server
    assert boot.OWNER_REQUEST_DRAIN_SECONDS == 120
    monkeypatch.setattr(boot, "OWNER_REQUEST_DRAIN_SECONDS", 0.1)

    def server(config):
        assert config.timeout_graceful_shutdown == 0.1

        async def delayed():
            if durable:
                loop = asyncio.get_running_loop()

                def native_write():
                    loop.call_soon_threadsafe(entered.set)
                    assert release.wait(10)
                    (Path(o.config.directory) / "retained-shutdown-marker").write_bytes(b"exact")
                    written.set()

                await run_owned_thread(native_write, on_cancel=cancelled.set)
                return {"written": True}
            entered.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                cancelled.set()
                raise

        config.app.add_api_route("/shutdown-diagnostic", delayed)
        return server_factory(config)

    monkeypatch.setattr(boot, "_Server", server)
    stop, task = o.start()

    async def ready():
        return "owner.example" in o.apps

    await until(ready)
    await asyncio.sleep(0.05)
    async with o.client_type(trust_env=False, timeout=10) as client:
        request = asyncio.create_task(
            client.get(f"http://127.0.0.1:{o.config.listen_port}/shutdown-diagnostic")
        )
        try:
            await asyncio.wait_for(entered.wait(), timeout=10)
            stop.set()
            await asyncio.wait_for(cancelled.wait(), timeout=10)
            if durable:
                # Give uvicorn time to finish lifespan shutdown while the owned
                # write is still held; checking on the cancellation tick misses
                # an early lease release in the following scheduler turns.
                await asyncio.sleep(0.2)
                assert not task.done() and not written.is_set()
                from umi.private_files import PrivateStateBusyError

                with pytest.raises(PrivateStateBusyError):
                    async with boot.admission_owner_app(
                        o.config, o.preparation, o.h.archive.reviewer
                    ):
                        pytest.fail("owner lease released while an HTTP write remained active")
                release.set()
            await asyncio.wait_for(task, timeout=10)
            response = await request
            assert response.status_code == 500
            if durable:
                assert written.is_set()
                assert (
                    Path(o.config.directory) / "retained-shutdown-marker"
                ).read_bytes() == b"exact"
        finally:
            release.set()
            await asyncio.gather(request, return_exceptions=True)
    async with boot.admission_owner_app(o.config, o.preparation, o.h.archive.reviewer):
        pass
