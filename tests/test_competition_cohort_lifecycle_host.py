"""Configured owner factories and native HTTP votes; synthetic finality/readiness."""

import asyncio
import socket
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI

import umi.competition_cohort_admission_host as boot
from umi.competition_cohort_clip_delivery import ClipDeliveryConfig
from umi.competition_cohort_dispatch_host import ServiceDispatchConfig, ServiceDispatchHost
from umi.competition_cohort_lifecycle_host import LifecycleHostConfig
from umi.competition_cohort_phase_vote_http import phase_vote_routes
from umi.competition_cohort_readiness import intake_readiness
from umi.competition_cohort_request_readiness import LiveRequestPhaseObserver, RequestReadiness
from umi.competition_cohort_request_start import RequestStartConfig
from umi.competition_cohort_review_http import CohortReviewPeerConfig
from umi.competition_cohort_service_host import ServiceAdmissionHost, ServiceAdmissionHostConfig
from umi.competition_cohort_settlement_config import SettlementOriginalSources
from umi.competition_execution import execution_boundary
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_lifecycle import intake as intake
from .test_competition_cohort_lifecycle import legacy_scenario as legacy_scenario
from .test_competition_cohort_lifecycle import lifecycle as lifecycle
from .test_competition_cohort_lifecycle import lifecycle_before_intake as lifecycle_before_intake
from .test_competition_cohort_lifecycle import policy as policy
from .test_competition_cohort_lifecycle import precommit_service_inventory
from .test_competition_cohort_lifecycle import recovery as recovery
from .test_competition_cohort_lifecycle import scenario as scenario
from .test_competition_service import chain_config as chain_config
from .test_open_competition import wallet

pytestmark = pytest.mark.parametrize(
    "lifecycle_before_intake", [precommit_service_inventory], indirect=True
)


def configured(h, root):
    _, manifest, series = h.precommitted
    owner = boot.AdmissionOwnerConfig(
        schema="umi-cohort-admission-owner/1",
        directory=str(root / "admission"),
        owner_hotkey=wallet("Charlie").hotkey.ss58_address,
        owner_key_file=str(root / "owner-key"),
        export_token_file=str(root / "export-token"),
        reviewers=tuple(
            CohortReviewPeerConfig(
                signer=wallet(n).hotkey.ss58_address,
                origin=f"https://{n.lower()}.example",
                token_file=str(root / (n + "-token")),
                timeout_seconds=10,
            )
            for n in ("Charlie", "Dave")
        ),
        listen_port=18090,
    )
    source = SettlementOriginalSources(
        intake=h.intake.config,
        eligible_tracks=h.intake.tracks,
        round_directory=str(root / "rounds"),
        objects_directory=str(root / "objects"),
        catalogs_directory=str(root / "inputs/catalogs"),
        transport_directory=str(root / "transport"),
        pulses_directory=str(root / "pulses"),
    )
    return ServiceAdmissionHostConfig(
        schema="umi-cohort-service-admission-host/5",
        series=series,
        manifest=manifest,
        queue_directory=str(root / "queues"),
        inputs_directory=str(root / "inputs"),
        admission_owner=owner,
        lifecycle=LifecycleHostConfig(
            schema="umi-cohort-lifecycle-host/1",
            directory=str(root / "lifecycle"),
            request_start=RequestStartConfig(
                schema="umi-cohort-request-start-config/1",
                directory=str(root / "rest"),
                first_cohort_not_before_unix_ms=2_000_000,
            ),
            request_completion_directory=str(root / "completion"),
            settlement_history_directory=str(root / "closed"),
            proof_export_directory=str(root / "proofs"),
            sources=source,
            public_origin="https://public.example",
            poll_seconds=1,
            sample_seconds=1,
        ),
    )


@pytest.fixture
async def host(lifecycle, tmp_path, monkeypatch):
    h = lifecycle
    c = configured(h, tmp_path / "host")
    h.timestamp = 1_000_000
    h.provider.config = SimpleNamespace(maximum_head_age_ms=120_000, maximum_future_skew_ms=30_000)
    collect = h.provider.collect

    async def fresh():
        value = await collect()
        return value.__class__(value.snapshot, dict(value.provenance, timestamp_ms=h.timestamp))

    h.provider.collect = fresh
    service = ServiceAdmissionHost(
        c, h.intake, h.owner.promotion, fresh, h.provider.retained_archive, provider=h.provider
    )
    apps, outages = {}, set()
    for name in ("Charlie", "Dave"):
        apps[name.lower() + ".example"] = FastAPI()
    for phase in ("intake", "preparation"):
        driver = await h.reopen().factories[phase]()
        for name, signer in zip(("Charlie", "Dave"), driver.observer.signers, strict=True):
            apps[name.lower() + ".example"].include_router(
                phase_vote_routes(signer, phase=phase, token="v" * 32)
            )

    class Routing(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            if request.url.host in outages:
                raise httpx.ConnectError("reviewer temporarily unavailable")
            if request.url.host == "public.example":
                if request.url.path.endswith("/requests/readiness"):
                    return httpx.Response(404)  # Dispatch is deliberately not installed.
                return httpx.Response(
                    200,
                    json=intake_readiness(
                        h.intake,
                        h.cohort,
                        h.capture(h.block),
                        nonce=request.url.params["nonce"],
                        archive_available=h.ready,
                    ).model_dump(mode="json", by_alias=True),
                )
            return await httpx.ASGITransport(app=apps[request.url.host]).handle_async_request(
                request
            )

    real_client = httpx.AsyncClient

    def routed_client(**kw):
        kw["transport"] = kw.get("transport") or Routing()
        return real_client(**kw)

    monkeypatch.setattr(boot.httpx, "AsyncClient", routed_client)
    monkeypatch.setattr(boot, "load_named_hotkey", lambda *_: wallet("Charlie"))
    monkeypatch.setattr(
        boot, "_token", lambda p: "e" * 32 if p == c.admission_owner.export_token_file else "v" * 32
    )

    def open_host():
        return boot.admission_owner_app(
            c.admission_owner, service.preparation, h.provider, service_host=service
        )

    yield SimpleNamespace(h=h, service=service, config=c, open=open_host, outages=outages)


async def test_configured_phase_owner_recovers_quorum_and_holds_request_start(host):
    o, h = host, host.h
    for worker in h.admissions:
        await worker.poll_once()
    async with o.open() as app:
        control = app.state.lifecycle
        node = await control.node(h.cohort)
        driver = await node._driver("intake")
        assert await driver.observer.observe._ready(
            node.controller.store.status(h.cohort)[0], await h.provider.collect()
        )
        for _ in range(100):
            if node.controller.store.status(h.cohort)[0].phase == "preparation":
                break
            h.block += 5
            await node.tick()
        assert node.controller.store.status(h.cohort)[0].phase == "preparation", node.last_report
        assert (await node.tick())["status"] == "waiting_request_rest"
        original_votes = dict(h.calls)
    # Restart reopens the actual control journal and does not repeat intake votes.
    async with o.open() as app:
        node = await app.state.lifecycle.node(h.cohort)
        assert (await node.tick())["status"] == "waiting_request_rest"
        assert dict(h.calls) == original_votes
        h.timestamp = 2_030_000
        o.outages.add("dave.example")
        with pytest.raises(ValueError):
            await node.tick()
        assert node.controller.store.status(h.cohort)[0].phase == "preparation"
    o.outages.clear()
    async with o.open() as app:
        node = await app.state.lifecycle.node(h.cohort)
        await node.tick()
        assert node.controller.store.status(h.cohort)[0].phase == "requests"
        assert Path(o.config.lifecycle.sources.round_directory, h.cohort + ".json").is_file()
        # Source readiness cannot be inferred from successful preparation.
        with pytest.raises(FileNotFoundError):
            await node.tick()
        assert not app.state.lifecycle.requests
        assert max(h.calls.values()) == 1


@pytest.mark.parametrize("dispatch_enabled", [False, True])
async def test_owner_service_starts_and_drains_configured_lifecycle(
    host, monkeypatch, tmp_path, chain_config, dispatch_enabled
):
    o, h = host, host.h
    for worker in h.admissions:
        await worker.poll_once()
    with socket.socket() as socket_:
        socket_.bind(("127.0.0.1", 0))
        port = socket_.getsockname()[1]
    owner = o.config.admission_owner.model_copy(update={"listen_port": port, "poll_seconds": 1})
    o.service.config = o.config.model_copy(update={"admission_owner": owner})
    if dispatch_enabled:
        dispatch = ServiceDispatchConfig(
            schema="umi-cohort-service-dispatch-config/1",
            origins=chain_config,
            clips=ClipDeliveryConfig(
                schema="umi-cohort-clip-delivery-config/1",
                directory=str(tmp_path / "clips"),
                videos_directory=str(tmp_path / "videos"),
                origin="https://clips.example",
                upload_token_file=str(tmp_path / "clip-token"),
            ),
            poll_seconds=1,
        )
        o.service.config = ServiceAdmissionHostConfig.model_validate(
            {
                **o.service.config.model_dump(by_alias=True),
                "schema": "umi-cohort-service-admission-host/6",
                "dispatch": dispatch,
            }
        )
        old_token = boot._token
        monkeypatch.setattr(
            boot,
            "_token",
            lambda p: "a" * 64 if p == dispatch.clips.upload_token_file else old_token(p),
        )

        async def start(service, lifecycle, resources, client, credentials, key, sign, token):
            assert token == "a" * 64
            # Network finality and media are explicit fixtures. Native dispatch
            # still waits for this cohort's original prepared inputs and drains.
            return ServiceDispatchHost(
                service,
                lifecycle,
                SimpleNamespace(policy=h.intake.policy),
                client,
                credentials,
                key,
                sign,
                None,
            )

        monkeypatch.setattr(boot, "start_service_dispatch", start)
    server_type, apps = boot._Server, []

    def server(config):
        apps.append(config.app)
        return server_type(config)

    monkeypatch.setattr(boot, "_Server", server)
    stop = asyncio.Event()
    task = asyncio.create_task(
        boot.run_admission_owner(
            owner, o.service.preparation, h.provider, stop, service_host=o.service
        )
    )

    async def reaches_preparation():
        while True:
            if task.done():
                task.result()
                pytest.fail("configured owner stopped early")
            if apps:
                control = apps[0].state.lifecycle
                node = control.nodes.get(h.cohort)
                if node and node.controller.store.status(h.cohort)[0].phase == "preparation":
                    return control
            await asyncio.sleep(0.25)
            h.block += 1

    try:
        control = await asyncio.wait_for(reaches_preparation(), timeout=30)
        assert control.nodes[h.cohort].request_start is control.gate
        if dispatch_enabled:
            worker_host = apps[0].state.dispatch
            assert worker_host.tasks
            assert all(not t.done() for t in worker_host.tasks.values())
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=apps[0]), base_url="https://owner.example"
            ) as client:
                for path in ("/internal/cohorts/history", "/internal/cohorts/service-work"):
                    response = await client.post(path, content=b"{}")
                    assert response.status_code == 401
    finally:
        stop.set()
        await asyncio.wait_for(task, timeout=10)
    if dispatch_enabled:
        assert all(t.done() for t in worker_host.tasks.values())
    # Service shutdown releases the control database lease, not only HTTP.
    async with o.open() as app:
        node = await app.state.lifecycle.node(h.cohort)
        assert node.controller.store.status(h.cohort)[0].phase == "preparation"


@pytest.mark.parametrize("fault", ["version", "missing", "intake", "catalogs"])
async def test_phase_host_rejects_mismatched_selection(host, fault):
    c, service = host.config, host.service
    if fault in {"version", "missing"}:
        bad = (
            c.model_copy(update={"schema_": "umi-cohort-service-admission-host/4"})
            if fault == "version"
            else c.model_copy(update={"lifecycle": None})
        )
        with pytest.raises(ValueError):
            ServiceAdmissionHostConfig.model_validate_json(canonical_json_bytes(bad))
        return
    sources = c.lifecycle.sources.model_copy(
        update={
            "eligible_tracks": ("model",),
        }
        if fault == "intake"
        else {"catalogs_directory": str(Path(c.inputs_directory) / "different")}
    )
    service.config = c.model_copy(
        update={"lifecycle": c.lifecycle.model_copy(update={"sources": sources})}
    )
    with pytest.raises(ValueError):
        async with host.open():
            pytest.fail("mismatched native source was accepted")


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "offline",
        "nonce",
        "cohort",
        "tip",
        "catalog",
        "head",
        "fork",
        "redirect",
        "oversize",
        "unready",
    ],
)
async def test_request_readiness_requires_exact_fresh_dispatch_observation(lifecycle, fault):
    h = lifecycle
    catalog = h.precommitted[0]
    state = SimpleNamespace(cohort_sha256=h.cohort, tip_sha256="a1" * 32)
    capture = h.capture(h.block)
    source = SimpleNamespace(intake=h.intake, catalogs=(catalog,), gap=10)

    async def response(request):
        if fault == "offline":
            raise httpx.ConnectError("offline")
        if fault == "redirect":
            return httpx.Response(302, headers={"location": "https://other.example"})
        if fault == "oversize":
            return httpx.Response(
                200, content=b" " * 20000, headers={"content-type": "application/json"}
            )
        result = RequestReadiness(
            schema="umi-cohort-request-readiness/1",
            nonce=request.url.params["nonce"],
            policy_sha256=digest(h.intake.policy),
            cohort_sha256=h.cohort,
            recovery_tip_sha256=state.tip_sha256,
            catalog_sha256s=(digest(catalog.catalog),),
            observation=execution_boundary(capture),
            ready=fault != "unready",
        ).model_dump(mode="json", by_alias=True)
        fields = {"nonce": "nonce", "cohort": "cohort_sha256", "tip": "recovery_tip_sha256"}
        if fault in fields:
            result[fields[fault]] = "0" * (32 if fault == "nonce" else 64)
        if fault == "catalog":
            result["catalog_sha256s"] = ["0" * 64]
        if fault == "head":
            result["observation"]["block"] -= 11
        if fault == "fork":
            result["observation"]["block_hash"] = "0x" + "0" * 64
        return httpx.Response(200, json=result)

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(response), trust_env=False
    ) as client:
        live = LiveRequestPhaseObserver(source, "https://public.example", client=client)
        assert await live._ready(state, capture) is (fault is None)
