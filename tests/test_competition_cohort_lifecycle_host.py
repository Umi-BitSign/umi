"""Configured owner factories and native HTTP votes; synthetic finality/readiness."""

import asyncio
import hashlib
import json
import os
import socket
import threading
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI

import umi.competition_cohort_admission_host as boot
from umi.competition_cohort_clip_delivery import ClipDeliveryConfig
from umi.competition_cohort_dispatch_host import ServiceDispatchConfig, ServiceDispatchHost
from umi.competition_cohort_lifecycle_host import LifecycleHostConfig
from umi.competition_cohort_order_host import OrderHostConfig
from umi.competition_cohort_order_queue import CohortOrderQueueConfig
from umi.competition_cohort_phase_vote_http import phase_vote_routes
from umi.competition_cohort_readiness import intake_readiness
from umi.competition_cohort_reference_preflight import preflight_service_references
from umi.competition_cohort_request_readiness import LiveRequestPhaseObserver, RequestReadiness
from umi.competition_cohort_request_start import RequestStartConfig
from umi.competition_cohort_review_http import CohortReviewPeerConfig
from umi.competition_cohort_service_host import ServiceAdmissionHost, ServiceAdmissionHostConfig
from umi.competition_cohort_service_quality import ServiceReference, ServiceTerms
from umi.competition_cohort_settlement_config import SettlementOriginalSources
from umi.competition_cohort_settlement_delivery import SettlementEvidenceFiles
from umi.competition_execution import execution_boundary
from umi.open_competition import digest
from umi.private_files import publish_private_model
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


def precommit_complete_service_inventory(h):
    h.service_reference = ServiceReference(
        schema="umi-cohort-service-reference/1",
        case_id="91" * 32,
        video_sha256="92" * 32,
        stratum="fingerspelling",
        salt="94" * 32,
        reference="caf\u00e9",
    )
    h.service_reference_raw = json.dumps(
        h.service_reference.model_dump(mode="json", by_alias=True),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()
    h.service_terms = ServiceTerms(
        schema="umi-cohort-service-terms/1",
        policy_sha256=digest(h.intake.policy),
        transport_policy_sha256="95" * 32,
        service_pool_bps=7000,
        stratum_weights={"fingerspelling": 3, "continuous": 10},
    )
    precommit_service_inventory(
        h,
        service_terms_sha256=digest(h.service_terms),
        service_reference_sha256=hashlib.sha256(h.service_reference_raw).hexdigest(),
    )


pytestmark = pytest.mark.parametrize(
    "lifecycle_before_intake", [precommit_complete_service_inventory], indirect=True
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
                timeout_seconds=45,
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
                first_cohort_not_before_unix_ms=getattr(
                    h, "first_request_not_before_unix_ms", 2_000_000
                ),
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


def test_peer_origin_migration_preserves_shared_token_bindings(lifecycle, tmp_path):
    config = configured(lifecycle, tmp_path / "host")
    peers = config.admission_owner.reviewers
    config = ServiceAdmissionHostConfig.model_validate_json(
        canonical_json_bytes(config.model_copy(update={"model_review_peers": peers}))
    )
    original_paths = config.stores()
    local = tuple(
        peer.model_copy(update={"origin": f"http://127.0.0.1:{19578 + index}"})
        for index, peer in enumerate(peers)
    )
    owner = config.admission_owner.model_copy(update={"reviewers": local})
    inconsistent = config.model_copy(update={"admission_owner": owner})
    with pytest.raises(ValueError, match="conflicting identities or origins"):
        inconsistent.stores()
    migrated = ServiceAdmissionHostConfig.model_validate_json(
        canonical_json_bytes(inconsistent.model_copy(update={"model_review_peers": local}))
    )
    assert migrated.stores() == original_paths
    assert canonical_json_bytes(migrated.series) == canonical_json_bytes(config.series)
    assert migrated.lifecycle == config.lifecycle


@pytest.fixture
async def host(lifecycle, tmp_path, monkeypatch):
    h = lifecycle
    c = configured(h, tmp_path / "host")
    if hasattr(h, "service_reference_raw"):
        # This module's complete inventory owns these originals. Connected
        # pipeline fixtures install their own explicitly selected inputs later;
        # never replace or rekey their committed references here.
        objects = SettlementEvidenceFiles(Path(c.lifecycle.sources.objects_directory))
        originals = {
            digest(h.service_terms): canonical_json_bytes(h.service_terms),
            hashlib.sha256(h.service_reference_raw).hexdigest(): h.service_reference_raw,
        }
        for key in originals:
            objects.publish(key, originals.__getitem__)
        for catalog in h.catalogs:
            publish_private_model(
                Path(c.lifecycle.sources.catalogs_directory) / (digest(catalog.catalog) + ".json"),
                catalog,
            )
    h.timestamp = getattr(h, "timestamp", 1_000_000)
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

    yield SimpleNamespace(
        h=h, service=service, config=c, open=open_host, outages=outages, apps=apps
    )


@pytest.mark.parametrize("damage", ["missing", "tampered", "public", "unreadable", "binding"])
async def test_reference_preflight_checks_actual_private_originals_on_every_read(host, damage):
    h, sources = host.h, host.config.lifecycle.sources
    requirement = host.config.manifest.requirement(h.cohort)

    def check():
        return preflight_service_references(
            sources, h.history, requirement, h.intake.policy, phase="preparation"
        )

    assert check() == 1
    key = hashlib.sha256(h.service_reference_raw).hexdigest()
    path = Path(sources.objects_directory) / (key + ".json")
    if damage == "missing":
        path.unlink()
    elif damage == "tampered":
        path.write_bytes(path.read_bytes().replace(b"caf", b"bad"))
    elif damage == "public":
        path.chmod(0o644)
    elif damage == "unreadable":
        if os.geteuid() == 0:
            pytest.skip("root overrides the service account's discretionary read permission")
        path.chmod(0)
    else:
        # Keep a correctly committed reference; change the selected signed
        # catalog's video binding and require the native signature quorum.
        from .test_competition_cohort_lifecycle import signatures

        catalog = h.catalogs[0]
        item = catalog.catalog.work[0].model_copy(update={"video_sha256": "96" * 32})
        body = catalog.catalog.model_copy(update={"work": (item,)})
        catalog = catalog.model_copy(update={"catalog": body, "signatures": signatures(body)})
        publish_private_model(Path(sources.catalogs_directory) / (digest(body) + ".json"), catalog)
        requirement = requirement.model_copy(update={"catalog_sha256s": (digest(body),)})
    with pytest.raises((OSError, ValueError)):
        check()


async def test_reference_preflight_does_not_gate_model_only_or_existing_recovery(host):
    h = host.h
    sources = host.config.lifecycle.sources.model_copy(
        update={
            "objects_directory": "/unavailable/private-references",
            "eligible_tracks": ("endpoint", "model"),
        }
    )
    requirement = host.config.manifest.requirement(h.cohort)
    for phase in ("requests", "reference_reveal", "evidence", "certification", "complete"):
        assert (
            preflight_service_references(
                sources, h.history, requirement, h.intake.policy, phase=phase
            )
            == 0
        )
    plan = h.history.plan.model_copy(
        update={
            "schema_": "umi-recoverable-cohort-plan/2",
            "sequence": 6,
            "eligible_tracks": ("model",),
            "service_pool_bps": 0,
        }
    )
    history = h.history.model_copy(update={"plan": plan})
    for phase in ("intake", "preparation"):
        assert (
            preflight_service_references(
                sources, history, requirement, h.intake.policy, phase=phase
            )
            == 0
        )


async def test_lifecycle_rechecks_references_before_new_phase_work(host, monkeypatch):
    o, h = host, host.h
    async with o.open() as app:
        node = await app.state.lifecycle.node(h.cohort)
        original_history, owner_thread = node.controller._history, threading.get_ident()
        history_reads = []

        def owned_history():
            assert threading.get_ident() == owner_thread
            history_reads.append(threading.get_ident())
            return original_history()

        monkeypatch.setattr(node.controller, "_history", owned_history)
        await node.before_tick()
        assert history_reads
        before = node.controller.store.status(h.cohort)[0]
        key = hashlib.sha256(h.service_reference_raw).hexdigest()
        (Path(o.config.lifecycle.sources.objects_directory) / (key + ".json")).unlink()
        with pytest.raises(FileNotFoundError):
            await node.tick()
        assert node.controller.store.status(h.cohort)[0] == before
        assert not node.drivers


async def test_c5_publication_keeps_capture_with_selected_review_profile(host, monkeypatch):
    from .test_competition_cohort_review_budget import profile

    h = host.h
    assert h.history.plan.sequence == 5
    budget = profile(h.intake.policy)
    c = host.config
    owner = c.admission_owner.model_copy(
        update={
            "phase_review_budget": budget,
            "reviewers": tuple(
                peer.model_copy(update={"phase_review_budget": budget})
                for peer in c.admission_owner.reviewers
            ),
        }
    )
    host.service.config = c.model_copy(update={"admission_owner": owner})

    async def forbidden():
        pytest.fail("C5 publication retains its original capture path")

    monkeypatch.setattr(h.provider, "current_finalized_block", forbidden)
    async with boot.admission_owner_app(
        owner, host.service.preparation, h.provider, service_host=host.service
    ) as app:
        node = await app.state.lifecycle.node(h.cohort)
        assert node.publish_history.current_block is None
        await node._publish(h.history)


async def test_configured_phase_owner_recovers_quorum_and_holds_request_start(host):
    o, h = host, host.h
    for worker in h.admissions:
        await worker.poll_once()
    async with o.open() as app:
        control = app.state.lifecycle
        assert control.timeout_seconds == 45
        assert app.state.intake_review_exporter.publish_archive == control.proofs.publish
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
        before = node.controller.store.status(h.cohort)[0]
        assert before.phase == "preparation"
        # The request-rest gate is now ready. A lost reference must still stop
        # opening requests, then exact restoration resumes the signed clock.
        key = hashlib.sha256(h.service_reference_raw).hexdigest()
        objects = SettlementEvidenceFiles(Path(o.config.lifecycle.sources.objects_directory))
        original = objects(key)
        (Path(o.config.lifecycle.sources.objects_directory) / (key + ".json")).unlink()
        with pytest.raises(FileNotFoundError):
            await node.tick()
        assert node.controller.store.status(h.cohort)[0] == before
        objects.publish(key, lambda _: original)
        await node.tick()
        assert node.controller.store.status(h.cohort)[0].phase == "requests"
        assert Path(o.config.lifecycle.sources.round_directory, h.cohort + ".json").is_file()
        # Source readiness cannot be inferred from successful preparation.
        with pytest.raises(FileNotFoundError):
            await node.tick()
        assert not app.state.lifecycle.requests
        assert max(h.calls.values()) == 1


@pytest.mark.parametrize(
    "dispatch_enabled, orders_enabled", [(False, False), (True, False), (True, True)]
)
async def test_owner_service_starts_and_drains_configured_lifecycle(
    host, monkeypatch, tmp_path, chain_config, dispatch_enabled, orders_enabled
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

        async def start(
            service, lifecycle, resources, client, credentials, key, sign, token, *, windows=None
        ):
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
                windows=windows,
            )

        monkeypatch.setattr(boot, "start_service_dispatch", start)
    if orders_enabled:
        from umi.open_competition import identity

        orders = OrderHostConfig(
            schema="umi-cohort-order-host/1",
            queue=CohortOrderQueueConfig(
                schema="umi-cohort-order-queue-config/1",
                directory=str(tmp_path / "orders"),
                policy_sha256=digest(h.intake.policy),
                cohorts=h.intake.config.cohorts,
                reviewers=tuple(sorted((p.signer for p in owner.reviewers), key=identity)),
            ),
            poll_seconds=1,
        )
        o.service.config = ServiceAdmissionHostConfig.model_validate_json(
            canonical_json_bytes(
                o.service.config.model_copy(
                    update={"schema_": "umi-cohort-service-admission-host/7", "orders": orders}
                )
            )
        )
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
        assert o.service.history_exporter is apps[0].state.history_exporter
        assert control.nodes[h.cohort].request_start is control.gate
        if orders_enabled:
            assert apps[0].state.orders is not None
            assert apps[0].state.orders.last_reports
            assert o.service.request_readiness is apps[0].state.request_readiness
            assert o.service.request_readiness.running()
        if dispatch_enabled:
            worker_host = apps[0].state.dispatch
            assert worker_host.windows is apps[0].state.windows
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
    assert o.service.request_readiness is None
    assert o.service.history_exporter is None
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


@pytest.mark.parametrize("legacy_read_through", [False, True])
async def test_r2_lifecycle_publishes_original_registration_proofs_across_restart(
    host, tmp_path, monkeypatch, legacy_read_through
):
    from .test_competition_remote_proof_store import select_remote_proofs

    selected, opened, server = select_remote_proofs(
        host.config.lifecycle, tmp_path, monkeypatch, legacy_read_through=legacy_read_through
    )
    host.service.config = ServiceAdmissionHostConfig.model_validate_json(
        canonical_json_bytes(host.config.model_copy(update={"lifecycle": selected}))
    )
    await test_configured_phase_owner_recovers_quorum_and_holds_request_start(host)
    async with host.open() as app:
        observation = execution_boundary(await host.h.provider.collect())
        await app.state.lifecycle.proofs.publish(observation)
        expected = await host.h.provider.retained_archive(observation)
    async with host.open() as app:
        assert await app.state.lifecycle.proofs.read(observation) == expected
        await app.state.lifecycle.proofs.publish(observation)
    assert opened and len(opened) % 2 == 0
    assert [store.config.read_only for store in opened] == [True, False] * (len(opened) // 2)
    assert any("/frames/registration/" in key for key in server.objects)
    assert not list(Path(selected.proof_export_directory).glob("registration/*.json"))


def test_progression_hold_configuration_preserves_legacy_bytes(lifecycle, tmp_path):
    config = configured(lifecycle, tmp_path / "host").lifecycle
    old = canonical_json_bytes(config)
    assert b"automatic_progression_hold_cohorts" not in old
    assert b"forecast_accounting_bytes" not in old
    assert canonical_json_bytes(LifecycleHostConfig.model_validate_json(old)) == old
    expanded = LifecycleHostConfig.model_validate_json(
        canonical_json_bytes(config.model_copy(update={"forecast_accounting_bytes": 64 * 1024**2}))
    )
    assert expanded.forecast_accounting_bytes == 64 * 1024**2
    cohort = config.sources.intake.cohorts[0].cohort_sha256
    value = config.model_dump(by_alias=True)
    value["automatic_progression_hold_cohorts"] = (cohort,)
    held = LifecycleHostConfig.model_validate(value)
    assert held.automatic_progression_hold_cohorts == (cohort,)
    assert LifecycleHostConfig.model_validate_json(canonical_json_bytes(held)) == held
    for bad in ((cohort, cohort), ("ff" * 32,)):
        value["automatic_progression_hold_cohorts"] = bad
        with pytest.raises(ValueError, match="distinct configured cohorts"):
            LifecycleHostConfig.model_validate(value)


@pytest.mark.asyncio
async def test_held_cohort_never_constructs_controller_and_other_cohort_runs(
    monkeypatch, lifecycle_before_intake
):
    import umi.competition_cohort_lifecycle_host as module

    monkeypatch.setattr(module, "digest", lambda value: value)
    monkeypatch.setattr(module, "requests_stage_policy", lambda: None)
    held, active = "11" * 32, "22" * 32
    stop = asyncio.Event()
    node_started = asyncio.Event()
    node_stopped = asyncio.Event()
    calls = []

    class Node:
        async def run(self, event, **kwargs):
            node_started.set()
            try:
                await event.wait()
                return {"status": "stopped"}
            finally:
                node_stopped.set()

    async def node(cohort):
        calls.append(cohort)
        assert cohort == active, "held cohort constructed a native controller"
        return Node()

    host = SimpleNamespace(
        config=SimpleNamespace(
            automatic_progression_hold_cohorts=(held,), poll_seconds=1, sample_seconds=1
        ),
        service=SimpleNamespace(
            config=SimpleNamespace(series=SimpleNamespace(cohorts=(held, active)))
        ),
        last_reports={},
        requests={},
        execution_progress={},
        node=node,
    )
    task = asyncio.create_task(module.LifecycleHost.run(host, stop))
    await asyncio.wait_for(node_started.wait(), timeout=1)
    assert calls == [active]
    report = host.last_reports[held]
    assert report["status"] == "automatic_progression_held"
    assert report["percent"] == 0 and report["eta_seconds"] is None
    assert report["signed_state_changed"] is False
    stop.set()
    await asyncio.wait_for(task, timeout=1)
    assert node_stopped.is_set()
    assert host.last_reports[active] == {"status": "stopped"}


async def test_older_lifecycle_boot_owns_separate_epoch_client_until_shutdown(host):
    o = host
    async with o.open() as app:
        lifecycle = app.state.lifecycle
        advisory = lifecycle.producer_epochs.client
        assert advisory is not lifecycle.client and not advisory.is_closed
    assert advisory.is_closed
