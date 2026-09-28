"""Configured endpoint host with native peers/miner; chain and inference are fixtures."""

import asyncio
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI

from umi import competition_cohort_endpoint_host as host_module
from umi.competition_cohort_clip_delivery import ClipDeliveryConfig
from umi.competition_cohort_endpoint_host import EndpointHost, EndpointHostConfig
from umi.competition_cohort_endpoint_vote_http import endpoint_vote_routes
from umi.competition_cohort_execution_journal import CohortExecutionJournal
from umi.competition_cohort_review_http import CohortReviewPeerConfig
from umi.competition_cohort_service_quality import ServiceTerms
from umi.competition_cohort_settlement_delivery import SettlementEvidenceFiles
from umi.competition_reward_manifest import RewardReplayRequirement, StandingRewardManifest
from umi.open_competition import digest, identity, sign_object
from umi.policy import scoring_policy_hash
from umi.private_files import publish_private_model
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_endpoint_scheduler import base_policy as base_policy
from .test_competition_cohort_endpoint_scheduler import chain as chain
from .test_competition_cohort_endpoint_scheduler import chain_config as chain_config
from .test_competition_cohort_endpoint_scheduler import decisions as decisions
from .test_competition_cohort_endpoint_scheduler import delivery as delivery
from .test_competition_cohort_endpoint_scheduler import endpoint as endpoint
from .test_competition_cohort_endpoint_scheduler import execution as execution
from .test_competition_cohort_endpoint_scheduler import granted as granted
from .test_competition_cohort_endpoint_scheduler import harness as harness
from .test_competition_cohort_endpoint_scheduler import known_video_bytes as known_video_bytes
from .test_competition_cohort_endpoint_scheduler import legacy_scenario as legacy_scenario
from .test_competition_cohort_endpoint_scheduler import policy as policy
from .test_competition_cohort_endpoint_scheduler import receipt_scenario as receipt_scenario
from .test_competition_cohort_endpoint_scheduler import recovery as recovery
from .test_competition_cohort_endpoint_scheduler import recovery_case as recovery_case
from .test_competition_cohort_endpoint_scheduler import relay as relay
from .test_competition_cohort_endpoint_scheduler import retiring as retiring
from .test_competition_cohort_endpoint_scheduler import runtime as runtime
from .test_competition_cohort_endpoint_scheduler import scenario as scenario
from .test_competition_cohort_endpoint_scheduler import scheduled as scheduled
from .test_competition_cohort_endpoint_scheduler import signing as signing
from .test_open_competition import wallet


@pytest.fixture
async def installed(scheduled, tmp_path, monkeypatch):
    q, p, s = scheduled, scheduled.p, scheduled.s
    n = SimpleNamespace(
        q=q,
        hosts={},
        configs={},
        apps={},
        calls=[],
        signatures=[],
        fail=False,
        drop=False,
        media_fail=False,
        media_calls=0,
        damage=None,
        hang=False,
        entered=asyncio.Event(),
        cleaning=asyncio.Event(),
        release=asyncio.Event(),
    )
    names = {
        identity(wallet(name).hotkey.ss58_address): name
        for name in ("Charlie", "Dave", "Eve", "Ferdie")
    }
    names = {identity(e.hotkey): names[identity(e.hotkey)] for e in p.c.policy.evaluators}
    terms = ServiceTerms(
        schema="umi-cohort-service-terms/1",
        policy_sha256=digest(p.c.policy),
        transport_policy_sha256=scoring_policy_hash(p.transport_policy),
        service_pool_bps=7000,
        stratum_weights={"fingerspelling": 1, "continuous": 1},
    )
    manifest = StandingRewardManifest(
        schema="umi-standing-reward-manifest/1",
        policy_sha256=digest(p.c.policy),
        cohorts=(
            RewardReplayRequirement(
                cohort_sha256=p.e.r.cohort, terms_sha256=digest(terms), catalog_sha256s=("ab" * 32,)
            ),
        ),
    )

    class Routes(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            n.calls.append(request.url.path)
            if n.fail:
                raise httpx.ConnectError("peer offline", request=request)
            app = n.apps[request.url.host]
            response = await httpx.ASGITransport(app=app).handle_async_request(request)
            if n.drop and (not isinstance(n.drop, str) or request.url.path.endswith(n.drop)):
                raise httpx.ReadTimeout("ack lost", request=request)
            if response.status_code == 200 and n.damage:
                raw = await response.aread()
                if n.damage == "noncanonical":
                    raw = b" " + raw
                elif n.damage == "identity":
                    raw = canonical_json_bytes(sign_object(s.plan.body, wallet(s.own)))
                elif n.damage == "signature":
                    raw = raw.replace(b'"signature":"0x', b'"signature":"0x00', 1)
                elif n.damage == "redirect":
                    return httpx.Response(302, headers={"location": "https://untrusted.example"})
                return httpx.Response(
                    200, content=raw, headers={"content-type": "application/json"}
                )
            return response

    def token(name):
        return "peer-" + name * 8

    async def clips(sha):
        n.media_calls += 1
        if n.hang:
            n.entered.set()
            try:
                await asyncio.Event().wait()
            finally:
                n.cleaning.set()
                await n.release.wait()
        if n.media_fail:
            raise OSError("private clip unavailable")
        return next(r.video for r in p.requests if r.video.sha256 == sha)

    # Native finality adapter is separately qualified; this fixture supplies its
    # actual pinned transport windows, not real network finality.
    def blocks(provider, transport):
        assert provider is p.c.provider and transport == p.transport_policy
        return p.finality

    monkeypatch.setattr(host_module, "CompetitionTransportFinality", blocks)
    async with httpx.AsyncClient(transport=Routes()) as client:

        def host(name):
            root = tmp_path / ("installed-" + name)
            requests, decisions = s.signer(name).journal.config, s.d.worker(name).journal.config
            reviewers = tuple(
                CohortReviewPeerConfig(
                    signer=wallet(other).hotkey.ss58_address,
                    origin="https://" + other.lower() + ".example",
                    token_file=str(root / (other + "-token")),
                )
                for who, other in sorted(names.items())
                if other != name
            )
            config = EndpointHostConfig(
                schema="umi-cohort-endpoint-host/1",
                requests=requests,
                decisions=decisions,
                origins=p.config,
                clips=ClipDeliveryConfig(
                    schema="umi-cohort-clip-delivery-config/1",
                    directory=str(root / "clips"),
                    videos_directory=str(root / "videos"),
                    origin="https://clips.example",
                    upload_token_file=str(root / "upload-token"),
                ),
                objects_directory=str(root / "objects"),
                transport_directory=str(root / "transports"),
                reviewers=reviewers,
            )
            files = SettlementEvidenceFiles(Path(config.objects_directory))
            files.publish(digest(terms), lambda _: canonical_json_bytes(terms))
            publish_private_model(
                Path(config.transport_directory) / (terms.transport_policy_sha256 + ".json"),
                p.transport_policy,
                maximum_bytes=8 * 1024**2,
            )
            cfg = (
                p.e.journal().config
                if name == s.own
                else p.e.cfg.model_copy(
                    update={
                        "directory": str(root / "execution"),
                        "signer": wallet(name).hotkey.ss58_address,
                    }
                )
            )
            box = p.e.box if name == s.own else p.e.r.inbox(wallet(name).hotkey.ss58_address)
            benchmark = SimpleNamespace(
                provider=p.c.provider,
                history=p.e.box.history,
                execution=CohortExecutionJournal(cfg, p.c.policy),
                inbox=box,
                config=SimpleNamespace(batch_size=16, concurrency=4),
            )

            async def sign(body):
                n.signatures.append((name, digest(body)))
                return sign_object(body, wallet(name))

            selected = SimpleNamespace(endpoint=config, manifest=manifest, policy=p.c.policy)
            result = EndpointHost(
                selected,
                benchmark,
                p.provider(),
                client,
                tuple(token(names[identity(peer.signer)]) for peer in reviewers),
                wallet(name),
                sign,
                clips,
            )
            result.recovery.transport = p.delivery_recovery.transport
            n.configs[name] = selected
            return result

        n.make = host
        for name in names.values():
            native = host(name)
            n.hosts[name] = native
            app = FastAPI()
            app.include_router(endpoint_vote_routes(native, token=token(name)))
            n.apps[name.lower() + ".example"] = app
        n.host = n.hosts[s.own]
        n.client = client
        yield n


async def complete(n):
    for _ in range(15):
        report = await n.host.worker.poll_once()
        terminal = n.host.worker.schedule.complete(n.q.slot)
        if terminal is not None:
            return terminal
    raise AssertionError(report)


async def test_native_host_delivers_votes_and_finishes_without_repeating_work(installed):
    n, p = installed, installed.q.p
    terminal = await complete(n)
    assert len(terminal.cases) == len(p.e.job.cases)
    assert p.model.calls == len(p.e.job.cases)
    assert any(path.endswith("/request") for path in n.calls)
    assert any(path.endswith("/decision") for path in n.calls)
    counts = len(n.signatures), len(n.calls), p.model.calls, n.media_calls
    n.fail = n.media_fail = True
    p.c.finality.fail = True
    n.host = n.make(n.q.s.own)
    report = await n.host.worker.poll_once()
    assert report["assignments_complete"] == 1
    assert n.host.worker.schedule.complete(n.q.slot) == terminal
    assert counts == (len(n.signatures), len(n.calls), p.model.calls, n.media_calls)


@pytest.mark.parametrize("kind", ["request", "decision"])
async def test_lost_vote_ack_retains_intents_and_recovers_after_restart(installed, kind):
    n = installed
    n.drop = kind
    report = await n.host.worker.poll_once()
    assert report["batch_pending"] > 0
    assert n.q.p.model.calls == (0 if kind == "request" else 1)
    signatures = list(n.signatures)
    assert signatures
    n.drop = False
    n.host = n.make(n.q.s.own)
    await complete(n)
    assert all(n.signatures.count(item) == 1 for item in signatures)
    assert n.q.p.model.calls == len(n.q.p.e.job.cases)


@pytest.mark.parametrize("damage", ["noncanonical", "identity", "signature", "redirect"])
async def test_corrupt_remote_vote_does_not_reach_dispatch(installed, damage):
    n = installed
    n.damage = damage
    with pytest.raises((ValueError, OSError)):
        await n.host.peer(wallet(n.q.s.other).hotkey.ss58_address).request_vote(n.q.s.plan)
    assert n.q.p.model.calls == 0


async def test_wrong_transport_rejected_before_signing(installed):
    n = installed
    plan = n.q.s.plan
    wrong = plan.model_copy(
        update={
            "transport": plan.transport.model_copy(
                update={"activation_block": plan.transport.activation_block + 1}
            )
        }
    )
    with pytest.raises(ValueError, match="another transport"):
        await n.host.request_vote(wrong)
    assert not n.signatures


async def test_authentication_precedes_request_parsing(installed):
    n = installed
    response = await n.client.post(
        "https://" + n.q.s.other.lower() + ".example/internal/cohorts/endpoint/votes/request",
        content=b"broken",
    )
    assert response.status_code == 401 and not n.signatures


async def test_recurring_worker_waits_for_missing_media_then_completes(installed):
    n = installed
    n.media_fail = True
    stop = asyncio.Event()
    reports = []
    task = asyncio.create_task(n.host.worker.run(stop, poll_seconds=0.01, report=reports.append))
    try:

        async def wait_pending():
            while not reports:
                await asyncio.sleep(0.01)

        await asyncio.wait_for(wait_pending(), 30)
        assert reports[-1]["batch_pending"] > 0 and not n.signatures
        n.media_fail = False

        async def wait_complete():
            while n.host.worker.schedule.complete(n.q.slot) is None:
                if task.done():
                    task.result()
                await asyncio.sleep(0.01)

        await asyncio.wait_for(wait_complete(), 60)
    finally:
        stop.set()
        await asyncio.wait_for(task, 30)
    assert n.q.p.model.calls == len(n.q.p.e.job.cases)


@pytest.mark.parametrize("recurring", [False, True])
async def test_repeated_cancel_drains_owned_fetch_then_resumes(installed, recurring):
    n = installed
    n.hang = True
    worker = n.host.worker
    task = asyncio.create_task(worker.run(asyncio.Event()) if recurring else worker.poll_once())
    try:
        await asyncio.wait_for(n.entered.wait(), 30)
        task.cancel()
        await asyncio.wait_for(n.cleaning.wait(), 30)
        task.cancel()
        await asyncio.sleep(0.01)
        assert not task.done()
        assert worker.schedule.load(n.q.slot) is not None
    finally:
        n.release.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 30)
    n.hang = False
    n.host = n.make(n.q.s.own)
    await complete(n)
    assert n.q.p.model.calls == len(n.q.p.e.job.cases)
