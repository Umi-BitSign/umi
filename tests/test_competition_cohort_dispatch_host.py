"""Configured native service dispatch; synthetic chain, HTTPS and inference boundaries."""

import asyncio
import json
import os
from contextlib import AsyncExitStack
from types import SimpleNamespace

import httpx
import pytest

import umi.competition_cohort_dispatch_host as dispatch
from umi.competition_cohort_clip_delivery import ClipDeliveryConfig
from umi.competition_cohort_dispatch_host import ServiceDispatchConfig, ServiceDispatchHost
from umi.competition_cohort_review_http import CohortReviewPeerConfig
from umi.competition_cohort_service_export import ServiceWorkLookup, SignedServiceWorkResponse
from umi.competition_cohort_service_transport import ServiceWorkTransport
from umi.open_competition import digest
from umi.private_files import PrivateStateBusyError, lock_private_file
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_service_authority import base_policy as base_policy
from .test_competition_cohort_service_authority import chain as chain
from .test_competition_cohort_service_authority import chain_config as chain_config
from .test_competition_cohort_service_authority import endpoint as endpoint
from .test_competition_cohort_service_authority import execution as execution
from .test_competition_cohort_service_authority import granted as granted
from .test_competition_cohort_service_authority import harness as harness
from .test_competition_cohort_service_authority import known_video_bytes as known_video_bytes
from .test_competition_cohort_service_authority import legacy_scenario as legacy_scenario
from .test_competition_cohort_service_authority import miner_policy as miner_policy
from .test_competition_cohort_service_authority import original_harness as original_harness
from .test_competition_cohort_service_authority import policy as policy
from .test_competition_cohort_service_authority import receipt_scenario as receipt_scenario
from .test_competition_cohort_service_authority import recovery as recovery
from .test_competition_cohort_service_authority import recovery_case as recovery_case
from .test_competition_cohort_service_authority import relay as relay
from .test_competition_cohort_service_authority import runtime as runtime
from .test_competition_cohort_service_authority import scenario as scenario
from .test_competition_cohort_service_authority import (
    service_catalog_inputs as service_catalog_inputs,
)
from .test_competition_cohort_service_authority import service_owner as service_owner
from .test_competition_cohort_service_authority import shared_control_group as shared_control_group
from .test_competition_cohort_service_review import networked as networked
from .test_competition_cohort_service_review import reviewed as reviewed
from .test_competition_cohort_service_worker import loop as loop


async def test_dispatch_logs_worker_failure_boundary(caplog):
    report = {
        "status": "cohort_service_worker",
        "work_pending": 1,
        "last_retry_details": [
            {
                "error_type": "builtins.ValueError",
                "reason_code": "validation_failed",
                "source_frames": [],
            }
        ],
    }

    class Worker:
        async def run(self, stop, *, poll_seconds, report):
            report(value)

    value = report
    host = object.__new__(ServiceDispatchHost)
    host.config = SimpleNamespace(poll_seconds=5)
    host.last_reports = {}

    async def worker(_):
        return Worker()

    host.worker = worker
    with caplog.at_level("INFO", logger="umi.competition_cohort_dispatch_host"):
        await host._run_queue("ab" * 32, asyncio.Event())
    record = next(r for r in caplog.records if r.name == "umi.competition_cohort_dispatch_host")
    logged = json.loads(record.getMessage().split(" report=", 1)[1])
    assert logged == report == host.last_reports["ab" * 32]


async def test_legacy_service_configuration_keeps_canonical_bytes(host):
    raw = canonical_json_bytes(host.open().config)
    assert b'"request_window_version"' not in raw
    assert b'"request_window_miner_hotkeys"' not in raw
    recovered = ServiceDispatchConfig.model_validate_json(raw)
    assert recovered.request_window_version == 1
    assert recovered.request_window_miner_hotkeys is None
    assert canonical_json_bytes(recovered) == raw

    selected = recovered.model_copy(
        update={"request_window_version": 2, "request_window_miner_hotkeys": ()}
    )
    retained = ServiceDispatchConfig.model_validate_json(canonical_json_bytes(selected))
    assert retained.request_window_version == 2
    assert retained.request_window_miner_hotkeys == ()


@pytest.fixture
async def host(networked, tmp_path, monkeypatch):
    s, c, p = networked, networked.c, networked.p
    network = s.worker().transport.transport
    monkeypatch.setattr(dispatch, "CompetitionTransportFinality", lambda *_: p.finality)
    monkeypatch.setattr(
        dispatch,
        "ServiceWorkTransport",
        lambda *a, **kw: ServiceWorkTransport(*a, **kw, transport=network),
    )
    catalog = digest(c.assignment.catalog.catalog)
    cohort = c.assignment.round.cohort_sha256
    peers = tuple(
        CohortReviewPeerConfig(
            origin=f"https://reviewer{i}.example",
            signer=peer.signer,
            token_file=str(tmp_path / f"token-{i}"),
            timeout_seconds=10,
        )
        for i, peer in enumerate(s.peers)
    )
    cfg = ServiceDispatchConfig(
        schema="umi-cohort-service-dispatch-config/1",
        origins=p.c.config,
        clips=ClipDeliveryConfig(
            schema="umi-cohort-clip-delivery-config/1",
            directory=str(tmp_path / "clips"),
            videos_directory=str(tmp_path / "videos"),
            origin="https://clips.example",
            upload_token_file=str(tmp_path / "upload-token"),
        ),
        poll_seconds=1,
    )
    service = SimpleNamespace(
        config=SimpleNamespace(
            dispatch=cfg,
            admission_owner=SimpleNamespace(
                reviewers=peers, owner_hotkey=p.validator.hotkey.ss58_address
            ),
        ),
        intake=SimpleNamespace(policy=p.c.policy, config=SimpleNamespace(cohorts=p.e.cfg.cohorts)),
        provider=p.c.provider,
        history=s.history,
        queues={catalog: c.queue},
        cohorts={catalog: cohort},
    )
    lifecycle = SimpleNamespace(
        _request_source=lambda key: SimpleNamespace(transport=p.transport_policy)
    )

    class Routing(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            i = int(request.url.host.removeprefix("reviewer").split(".")[0])
            return await s.peers[i].requests.client._transport.handle_async_request(request)

    async def clips(sha):
        assert sha == p.service_video.sha256
        return p.service_video

    async with httpx.AsyncClient(transport=Routing()) as client:

        def open_host():
            return ServiceDispatchHost(
                service,
                lifecycle,
                p.provider(state_directory=str(tmp_path / "host-origins")),
                client,
                ("v" * 32, "v" * 32),
                p.validator.hotkey,
                s.sign,
                clips,
            )

        yield SimpleNamespace(open=open_host, catalog=catalog, s=s, lifecycle=lifecycle)


async def test_configured_dispatch_uses_native_votes_and_recovers_after_restart(host):
    h, s = host.open(), host.s
    assert h.timeout_seconds == h.config.operation_timeout_seconds == 2400
    worker = await h.worker(host.catalog)
    # Original selection already exists in this fixture. Live input composition
    # independently checks the same authority, media identity and request window.
    fresh = await worker.inputs(s.c.assignment)
    assert fresh.video == s.p.service_video and fresh.window == s.c.window
    report = await worker.poll_once()
    if report["work_pending"]:
        await worker._advance(s.c.assignment.admission)
    terminal = worker.terminals.read(s.c.assignment)
    assert terminal is not None and s.p.model.calls == 1
    assert s.signatures == 2
    original = canonical_json_bytes(terminal)
    s.offline = True
    restarted = await host.open().worker(host.catalog)
    assert (await restarted.poll_once())["work_complete"] == 1
    assert canonical_json_bytes(restarted.terminals.read(s.c.assignment)) == original
    assert s.p.model.calls == 1 and s.signatures == 2


async def test_native_work_export_routes_only_selected_catalog(host):
    h, s = host.open(), host.s
    request = ServiceWorkLookup(
        schema="umi-service-work-lookup/1", claim=s.c.claim, challenge="a1" * 32
    )
    signed = SignedServiceWorkResponse.model_validate_json(await h.respond(request))
    assert signed.response.assignment == s.c.assignment
    assert signed.response.challenge == request.challenge
    claim = s.c.claim.model_copy(
        update={"claim": s.c.claim.claim.model_copy(update={"catalog_sha256": "ff" * 32})}
    )
    with pytest.raises(ValueError, match="outside"):
        await h.respond(request.model_copy(update={"claim": claim}))


async def test_recurring_dispatch_waits_for_inputs_then_drains(host):
    h, stop = host.open(), asyncio.Event()
    original = host.lifecycle._request_source

    def unavailable(_):
        raise FileNotFoundError("not delivered")

    host.lifecycle._request_source = unavailable
    task = asyncio.create_task(h.run(stop))
    try:

        async def waiting():
            while host.catalog not in h.last_reports:
                await asyncio.sleep(0.01)

        await asyncio.wait_for(waiting(), timeout=5)
        assert h.last_reports[host.catalog]["status"] == "cohort_dispatch_waiting_inputs"
        host.lifecycle._request_source = original

        async def complete():
            while h.last_reports[host.catalog].get("work_complete") != 1:
                await asyncio.sleep(0.01)

        await asyncio.wait_for(complete(), timeout=15)
    finally:
        stop.set()
        await asyncio.wait_for(task, timeout=5)
    assert all(t.done() for t in h.tasks.values())
    # The worker lease was released, permitting native resume without reset.
    worker = await host.open().worker(host.catalog)
    assert (await worker.poll_once())["work_complete"] == 1


@pytest.mark.parametrize("fault", [None, "startup", "backups", "policy"])
async def test_dispatch_owns_origin_provider_until_context_drains(host, monkeypatch, fault):
    h, events = host.open(), []
    cfg = h.config.origins.model_copy(
        update={"proof_rpc_fallback_urls": ("wss://backup-one.example", "wss://backup-two.example")}
    )
    if fault == "backups":
        cfg = cfg.model_copy(update={"proof_rpc_fallback_urls": ()})
    if fault == "policy":
        cfg = cfg.model_copy(update={"policy_sha256": "ff" * 32})
    h.service.config.dispatch = h.config.model_copy(update={"origins": cfg})

    class Provider:
        def __init__(self, config, policy):
            self.policy = policy
            events.append("created")

        async def start(self):
            events.append("started")
            if fault == "startup":
                raise OSError("fixture failed startup")

        async def aclose(self):
            events.append("closed")

    monkeypatch.setattr(dispatch, "CohortEndpointFinalityProvider", Provider)

    async def run():
        async with AsyncExitStack() as resources:
            result = await dispatch.start_service_dispatch(
                h.service,
                h.lifecycle,
                resources,
                h.client,
                h.credentials,
                h.key,
                h.sign,
                "a" * 64,
            )
            assert isinstance(result, ServiceDispatchHost)
            assert events == ["created", "started"]

    if fault:
        with pytest.raises((ValueError, OSError)):
            await run()
    else:
        await run()
    assert events == ([] if fault in ("backups", "policy") else ["created", "started", "closed"])


@pytest.mark.parametrize("version", [1, 2])
@pytest.mark.parametrize("miner_scope", ["all", "matched", "empty", "other"])
async def test_service_request_windows_are_scoped_to_qualified_miners(host, version, miner_scope):
    from umi.competition_cohort_request_window import CohortAttemptRequestWindow

    h, s = host.open(), host.s
    selected_miners = {
        "all": None,
        "matched": (s.c.assignment.admission.submission.submission.hotkey,),
        "empty": (),
        "other": (s.p.validator.hotkey.ss58_address,),
    }[miner_scope]
    h.config = ServiceDispatchConfig.model_validate_json(
        canonical_json_bytes(
            h.config.model_copy(
                update={
                    "request_window_version": version,
                    "request_window_miner_hotkeys": selected_miners,
                }
            )
        )
    )
    worker = await h.worker(host.catalog)
    captured = await worker.inputs(s.c.assignment)
    if version == 2 and miner_scope in {"all", "matched"}:
        assert isinstance(captured.window, CohortAttemptRequestWindow)
        assert captured.window != s.c.window
    else:
        assert captured.window == s.c.window
    assert s.p.model.calls == 0 and s.signatures == 0


async def test_attempt_window_reads_finalized_head_after_real_journal_contention(host, monkeypatch):
    h, s = host.open(), host.s
    h.config = h.config.model_copy(update={"request_window_version": 2})
    original = dispatch.ServiceWorkRequests.latest
    capture = dispatch.capture_cohort_attempt_window
    events = []

    def latest(requests, *args):
        events.append("latest")
        if len(events) == 1:
            held = lock_private_file(requests.journal.lock_path)
            try:
                with pytest.raises(PrivateStateBusyError) as caught:
                    original(requests, *args)
                events.append("busy")
                raise caught.value
            finally:
                os.close(held)
        return original(requests, *args)

    head = s.p.finality.finalized_head_height

    async def finalized_head():
        if events:
            events.append("head")
        return await head()

    async def capture_window(*args):
        assert events == ["latest", "busy", "latest", "head"]
        return await capture(*args)

    monkeypatch.setattr(dispatch.ServiceWorkRequests, "latest", latest)
    monkeypatch.setattr(s.p.finality, "finalized_head_height", finalized_head)
    monkeypatch.setattr(dispatch, "capture_cohort_attempt_window", capture_window)
    worker = await h.worker(host.catalog)
    captured = await worker.inputs(s.c.assignment)
    assert captured.video == s.p.service_video
    # The native capture independently rechecks finality after host issuance.
    assert events == ["latest", "busy", "latest", "head", "head"]
    assert s.p.model.calls == 0 and s.signatures == 0
