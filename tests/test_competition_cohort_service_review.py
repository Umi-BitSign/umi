"""Native owner lookup, proof replay and durable service voting.

RPC, verified blocks, codec/proof verification, DNS and inference use fixtures.
No installed host or live chain reward effect is represented.
"""

import asyncio
import hashlib
import json
from dataclasses import replace

import bittensor as bt
import httpx
import pytest
from fastapi import FastAPI

from umi.competition_cohort_service_authority import ServiceWorkAuthority
from umi.competition_cohort_service_export import (
    PATH,
    ServiceWorkExporter,
    ServiceWorkHTTPClient,
    ServiceWorkReader,
    SignedServiceWorkResponse,
    service_work_routes,
)
from umi.competition_cohort_service_grant import service_grant_slot
from umi.competition_cohort_service_peers import ServiceWorkPeerReviews
from umi.competition_cohort_service_queue import ServiceWorkQueue
from umi.competition_cohort_service_requests import ServiceWorkRequests
from umi.competition_cohort_service_review import (
    ServiceRequestReview,
    ServiceRetryReview,
    ServiceReviewConfig,
    ServiceWorkReviewer,
    certify_service_retry,
    service_retry_decision,
)
from umi.competition_cohort_service_vote_http import ServiceVotePeer, service_vote_routes
from umi.competition_execution import execution_boundary
from umi.competition_historical_registration import HistoricalRegistrationProvider
from umi.open_competition import digest, sign_object, verify_signature
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
from .test_competition_cohort_service_grants import fresh_window
from .test_competition_cohort_service_worker import finish, history_tip, wallet
from .test_competition_cohort_service_worker import loop as loop
from .test_competition_historical_registration import change_block


@pytest.fixture
async def reviewed(loop, tmp_path):
    s, c, p = loop, loop.c, loop.p
    chain = p.c
    s.lookups, s.signatures, s.archive_reads = 0, 0, 0
    original_at = chain.finality.verified_block_at
    blocks = {}

    async def move(height):
        encoded = change_block(chain, height)
        block = await original_at(height)
        evidence = canonical_json_bytes(
            {**json.loads(block.finality_evidence), "block": {"scale_header": encoded}}
        )
        blocks[height] = replace(
            block,
            finality_evidence=evidence,
            finality_evidence_sha256=hashlib.sha256(evidence).hexdigest(),
        )

    await move(chain.finality.ref.block_number)

    async def at(height):
        return blocks.get(height)

    chain.finality.verified_block_at = at
    chain.config = chain.config.model_copy(update={"state_directory": str(tmp_path / "proofs")})

    def provider():
        return HistoricalRegistrationProvider(
            chain.config,
            chain.policy,
            finality=chain.finality,
            proofs=chain.proofs,
            now_ms=lambda: chain.clock.now,
        )

    chain.provider = provider()
    observed = await chain.provider.collect()
    original = c.assignment
    c.cfg = c.cfg.model_copy(update={"directory": str(tmp_path / "native-queue")})
    c.queue = ServiceWorkQueue(c.cfg, chain.policy)
    c.queue.install(
        original.catalog,
        original.round,
        original.source,
        observed,
        expected_tip_sha256=history_tip(original.source.history),
    )
    c.queue.admit(
        c.claim,
        original.admission.submission,
        original.admission.participant,
        original.source,
        observed,
        expected_tip_sha256=history_tip(original.source.history),
    )
    c.assignment = c.queue.assignment(c.claim)
    archive_bytes = await chain.provider.retained_archive(execution_boundary(observed))
    await move(p.finality.head)
    s.move = move

    async def history(cohort):
        if s.offline:
            raise OSError("history offline")
        assert cohort == c.assignment.round.cohort_sha256
        return p.e.r.h.source

    async def archive(expected):
        s.archive_reads += 1
        assert expected == c.assignment.admission.observation
        return archive_bytes

    async def owner_sign(body):
        return sign_object(body, p.validator)

    exporter = ServiceWorkExporter(c.queue, p.validator.hotkey.ss58_address, owner_sign)
    app = FastAPI()
    app.include_router(service_work_routes(exporter, token="t" * 32))
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app))
    http = ServiceWorkHTTPClient(client, "https://coordinator.example", token="t" * 32)

    async def fetch(request):
        s.lookups += 1
        if s.offline:
            raise OSError("owner offline")
        return await http(request)

    owner = ServiceWorkReader(chain.policy, p.validator.hotkey.ss58_address, fetch)
    s.exporter, s.client, s.reader, s.fetch = exporter, client, owner, fetch
    s.requests = ServiceWorkRequests(c.queue, p.transport_policy)
    s.body = s.requests.prepare(
        c.claim,
        p.validator.hotkey.ss58_address,
        p.service_video,
        c.window,
        p.e.r.h.source,
        await chain.provider.collect(),
    )

    def reviewer(name="Charlie"):
        async def sign(body):
            s.signatures += 1
            return sign_object(body, wallet(name))

        config = ServiceReviewConfig(
            schema="umi-service-review-config/1",
            directory=str(tmp_path / ("review-" + name)),
            policy_sha256=digest(chain.policy),
            signer=wallet(name).hotkey.ss58_address,
            owner=p.validator.hotkey.ss58_address,
            cohorts=p.e.cfg.cohorts,
        )

        async def current_round():
            return bt.timelock.current_round()

        return ServiceWorkReviewer(
            config,
            chain.policy,
            p.transport_policy,
            provider(),
            p.finality,
            history,
            owner,
            archive,
            current_round,
            sign,
        )

    s.reviewer, s.history = reviewer, history
    origins = p.provider(state_directory=str(tmp_path / "origins"))
    authority = ServiceWorkAuthority(c.queue, chain.provider, history, origins)
    s.origin, s.observation = authority.origin, authority.observe
    s.reviewers = {}
    for name in ("Charlie", "Dave"):
        reviewer_ = reviewer(name)

        async def vote(body, reviewer_=reviewer_):
            parent = (
                None
                if body.parent_grant_slot is None
                else s.requests.certificate(body.parent_grant_slot)
            )
            return await reviewer_.attest(ServiceRequestReview(body=body, parent=parent))

        s.reviewers[wallet(name).hotkey.ss58_address] = vote
    try:
        yield s
    finally:
        await client.aclose()


async def test_independent_service_votes_drive_native_miner_and_recover_offline(reviewed):
    s = reviewed
    worker, terminal, _ = await finish(s)
    assert s.p.model.calls == 1 and s.signatures == 2 and s.archive_reads == 2
    assert terminal.terminal.work_sha256 == s.c.assignment.admission.work_sha256
    s.offline = True
    old = await s.reviewer().attest(ServiceRequestReview(body=s.body))
    verify_signature(s.body, old)
    assert s.signatures == 2
    _, recovered, _ = await finish(s)
    assert recovered == terminal
    assert worker.requests.latest(s.c.claim, s.p.validator.hotkey.ss58_address) == s.body


@pytest.fixture
async def networked(reviewed):
    s, clients, peers = reviewed, [], []
    s.unavailable, s.deliveries = set(), []
    for name in ("Charlie", "Dave"):
        app = FastAPI()
        native = s.reviewer(name)

        class Reviewer:
            def __init__(self, native, name):
                self.native, self.name = native, name

            async def attest(self, review):
                s.deliveries.append((self.name, type(review).__name__))
                if self.name in s.unavailable:
                    raise OSError("PRIVATE_REVIEWER_FAILURE")
                return await self.native.attest(review)

        app.include_router(service_vote_routes(Reviewer(native, name), token="v" * 32))
        client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app))
        clients.append(client)
        peers.append(
            ServiceVotePeer(
                client,
                "https://reviewer.example",
                policy=s.p.c.policy,
                cohorts=s.p.e.cfg.cohorts,
                signer=wallet(name).hotkey.ss58_address,
                token="v" * 32,
            )
        )
    s.peers = tuple(peers)
    s.peer_reviews = ServiceWorkPeerReviews(s.requests, s.peers)
    s.reviewers, s.retry = s.peer_reviews.reviewers, s.peer_reviews.retry
    try:
        yield s
    finally:
        for client in clients:
            await client.aclose()


@pytest.mark.parametrize("service_catalog_inputs", [False, "precommitted"], indirect=True)
async def test_http_votes_complete_original_work_without_local_signer_callbacks(networked):
    s = networked
    _, terminal, _ = await finish(s)
    assert s.p.model.calls == 1 and s.signatures == 2
    assert set(s.deliveries) == {
        ("Charlie", "ServiceRequestReview"),
        ("Dave", "ServiceRequestReview"),
    }
    assert terminal.terminal.work_sha256 == s.c.assignment.admission.work_sha256
    s.unavailable = {"Charlie", "Dave"}
    _, recovered, _ = await finish(s)
    assert recovered == terminal and len(s.deliveries) == 2


async def test_partial_retry_votes_survive_restart_and_finish_through_http(networked, monkeypatch):
    s = networked
    review = await retired_attempt(s, monkeypatch)
    s.unavailable.add("Dave")
    with pytest.raises(ValueError):
        await s.retry(review.grant, review.retirement)
    assert s.signatures == 3
    s.unavailable = {"Charlie"}
    peer_reviews = ServiceWorkPeerReviews(s.requests, s.peers)
    s.retry = peer_reviews.retry
    before = len(s.deliveries)
    cert = await s.retry(review.grant, review.retirement)
    assert cert.decision == service_retry_decision(review)
    assert s.deliveries[before:] == [("Dave", "ServiceRetryReview")]
    s.unavailable.add("Dave")
    assert (
        await ServiceWorkPeerReviews(s.requests, s.peers).retry(review.grant, review.retirement)
        == cert
    )
    assert len(s.deliveries) == before + 1
    s.unavailable.clear()
    s.c.window = fresh_window(s.p, s.body.request, monkeypatch)
    await s.move(s.p.finality.head)
    worker, terminal, _ = await finish(s)
    assert worker.requests.latest(s.c.claim, s.p.validator.hotkey.ss58_address).attempt_number == 2
    assert terminal.terminal.work_sha256 == s.c.assignment.admission.work_sha256
    assert s.p.model.calls == 1 and s.signatures == 6


@pytest.mark.parametrize("failure", ["auth", "signer", "body", "canonical", "redirect"])
async def test_service_peer_rejects_wrong_or_unauthenticated_vote(networked, failure):
    s, peer = networked, networked.peers[0]
    review = ServiceRequestReview(body=s.body)
    if failure == "auth":
        peer.requests.token = "x" * 32
    else:
        body = (
            s.body
            if failure != "body"
            else s.body.model_copy(update={"attempt_number": s.body.attempt_number + 1})
        )
        signed = canonical_json_bytes(
            sign_object(body, wallet("Charlie" if failure != "signer" else "Dave"))
        )

        async def tampered(request):
            return httpx.Response(
                302 if failure == "redirect" else 200,
                content=b" " + signed if failure == "canonical" else signed,
                headers={
                    "content-type": "application/json",
                    "location": "https://elsewhere.example",
                },
            )

        peer.requests.client = httpx.AsyncClient(transport=httpx.MockTransport(tampered))
    try:
        with pytest.raises((OSError, ValueError)):
            await peer.attest(review)
    finally:
        if failure != "auth":
            await peer.requests.client.aclose()
    assert s.signatures == 0


async def test_http_retry_certificate_recovers_lost_commit_ack_without_peers(
    networked, monkeypatch
):
    s = networked
    review = await retired_attempt(s, monkeypatch)
    original = s.requests.journal.put
    lost = []

    def committed(kind, key, value):
        result = original(kind, key, value)
        if kind == "service_retry_certificate" and not lost:
            lost.append(True)
            raise OSError("commit acknowledgement lost")
        return result

    monkeypatch.setattr(s.requests.journal, "put", committed)
    with pytest.raises(OSError):
        await s.retry(review.grant, review.retirement)
    assert s.signatures == 4
    before = list(s.deliveries)
    s.unavailable = {"Charlie", "Dave"}
    cert = await ServiceWorkPeerReviews(s.requests, s.peers).retry(review.grant, review.retirement)
    assert cert.decision == service_retry_decision(review)
    assert s.deliveries == before and s.signatures == 4


async def test_transport_view_preserves_owned_proofs_and_requires_same_pins(reviewed):
    from umi.competition_transport_finality import CompetitionTransportFinality
    from umi.policy import scoring_policy_hash

    s = reviewed
    provider = s.p.c.provider
    # The registration and miner fixtures have different bootstrap pins. A
    # configured shared observer must select matching pins explicitly.
    with pytest.raises(ValueError):
        CompetitionTransportFinality(provider, s.p.transport_policy)
    transport = s.p.transport_policy.model_copy(
        update={
            "implementation_pins": s.p.transport_policy.implementation_pins.model_copy(
                update={
                    "live_chain": provider.config.chain_pin,
                    "finality_verifier": provider.config.finality_pin,
                }
            )
        }
    )
    view = CompetitionTransportFinality(provider, transport)
    height = await view.finalized_head_height()
    original = await provider._finality.verified_block_at(height)
    block = await view.verified_block_at(height)
    assert block == replace(original, scoring_policy_hash=scoring_policy_hash(transport))
    assert block.finality_evidence == original.finality_evidence
    assert (await provider._finality.verified_block_at(height)) == original
    bad = s.p.transport_policy.model_copy(
        update={
            "implementation_pins": s.p.transport_policy.implementation_pins.model_copy(
                update={"live_chain": None}
            )
        }
    )
    with pytest.raises(ValueError):
        CompetitionTransportFinality(provider, bad)


@pytest.mark.parametrize("service_catalog_inputs", [True, "precommitted"], indirect=True)
async def test_instantiated_service_host_recovers_vote_with_input_files_and_owner_offline(
    reviewed, tmp_path, monkeypatch
):
    from pathlib import Path
    from types import SimpleNamespace

    from umi import competition_cohort_review_boot as boot
    from umi import competition_cohort_service_selection as selection
    from umi.competition_cohort_history_http import CohortHistoryExporter, cohort_history_routes
    from umi.competition_cohort_intake import CohortIntake, CohortIntakeConfig
    from umi.competition_reward_decisions import StandingRewardSeries
    from umi.competition_reward_manifest import RewardReplayRequirement, StandingRewardManifest
    from umi.grandpa_finality import FINNEY_GENESIS_HASH
    from umi.policy import scoring_policy_hash

    from .test_competition_cohort_review_boot import config_for, with_service

    s, native = reviewed, reviewed.reviewer("Charlie")
    source = await s.history(s.body.assignment.round.cohort_sha256)
    cohort, history = s.body.assignment.round.cohort_sha256, source.history
    if history.authority.authority.schema_ != "umi-cohort-recovery-authority/2":
        pytest.skip("installed standing host needs standing authority")
    manifest = StandingRewardManifest(
        schema="umi-standing-reward-manifest/1",
        policy_sha256=digest(s.p.c.policy),
        cohorts=(
            RewardReplayRequirement(
                cohort_sha256=cohort,
                terms_sha256=digest(s.c.terms),
                catalog_sha256s=(digest(s.body.assignment.catalog.catalog),),
            ),
        ),
    )
    series = StandingRewardSeries(
        schema="umi-standing-reward-series/1",
        genesis_hash=FINNEY_GENESIS_HASH,
        netuid=78,
        policy_sha256=digest(s.p.c.policy),
        policy_epoch=1,
        manifest_sha256=digest(manifest),
        control_hotkey=wallet("Charlie").hotkey.ss58_address,
        recovery=history.authority,
        cohorts=(history.plan,),
        validators=(wallet("Charlie").hotkey.ss58_address,),
        maximum_proof_lag_blocks=300,
        maximum_transaction_lifetime_blocks=128,
        lifetime="until_superseded_or_revoked",
    )
    chain = s.p.c.config.model_copy(
        update={
            "state_directory": str(tmp_path / "host-chain"),
            "proof_rpc_fallback_urls": ("wss://one.example", "wss://two.example"),
        }
    )
    c = config_for(
        SimpleNamespace(series=series, policy=s.p.c.policy, manifest=manifest, chain=chain),
        tmp_path / "host",
    )
    c = with_service(
        c.model_copy(
            update={
                "owner_hotkey": s.p.validator.hotkey.ss58_address,
                "signing": c.signing.model_copy(
                    update={"signer": wallet("Charlie").hotkey.ss58_address}
                ),
            }
        )
    )
    intake = CohortIntake(
        CohortIntakeConfig(directory=str(tmp_path / "owner-history"), cohorts=c.signing.cohorts),
        c.policy,
        initialize=True,
    )
    # This fixture starts with certified earlier phases, not an intake run.
    # Seed their exact history/evidence through the native recovery store.
    capture = await native.provider.collect()
    with intake._connection() as (_, store):
        store.admit(
            history.plan,
            history.authority,
            c.policy,
            admitted_at_block=history.genesis.admitted_at_block,
        )
        for decision in source.decisions:
            store.retain_source(cohort, decision)
        store.publish_history(history, c.policy, current_block=capture.snapshot.block)

    async def sign(body):
        return sign_object(body, s.p.validator)

    owner = FastAPI()
    owner.include_router(service_work_routes(s.exporter, token="o" * 32))
    owner.include_router(
        cohort_history_routes(CohortHistoryExporter(intake, c.owner_hotkey, sign), token="o" * 32)
    )
    original_client = httpx.AsyncClient
    monkeypatch.setattr(
        boot.httpx,
        "AsyncClient",
        lambda **kwargs: original_client(transport=httpx.ASGITransport(app=owner), **kwargs),
    )
    monkeypatch.setattr(boot, "_token", lambda p: ("o" if p == c.owner_token_file else "v") * 32)
    monkeypatch.setattr(boot, "load_named_hotkey", lambda *a: wallet("Charlie"))
    monkeypatch.setattr(
        boot, "HistoricalRegistrationProvider", lambda *a: s.reviewer("Charlie").provider
    )
    # Window finality and historical-registration finality are separately
    # controlled fixture ports. Native transport-view binding is tested above.
    monkeypatch.setattr(selection, "CompetitionTransportFinality", lambda *a: s.p.finality)
    archive = await native.archive(s.body.assignment.admission.observation)
    monkeypatch.setattr(boot.SettlementRegistrationFiles, "_read", lambda *a: archive)
    files = []
    async with (
        boot.phase_review_app(c) as app,
        original_client(transport=httpx.ASGITransport(app=app)) as client,
    ):
        peer = ServiceVotePeer(
            client,
            "https://reviewer.example",
            policy=c.policy,
            cohorts=c.signing.cohorts,
            signer=c.signing.signer,
            token="v" * 32,
        )
        with pytest.raises(OSError):
            await peer.attest(ServiceRequestReview(body=s.body))
        for folder, key, value in (
            ("terms", digest(s.c.terms), s.c.terms),
            ("transport", scoring_policy_hash(s.p.transport_policy), s.p.transport_policy),
        ):
            path = Path(c.inputs_directory) / folder / (key + ".json")
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            path.write_bytes(canonical_json_bytes(value))
            path.chmod(0o600)
            files.append(path)
        vote = await peer.attest(ServiceRequestReview(body=s.body))
        verify_signature(s.body, vote)
    for path in files:
        path.unlink()

    async def unavailable(*args):
        raise OSError("all owner inputs unavailable after restart")

    monkeypatch.setattr(CohortHistoryExporter, "respond", unavailable)
    monkeypatch.setattr(ServiceWorkExporter, "respond", unavailable)
    async with (
        boot.phase_review_app(c) as app,
        original_client(transport=httpx.ASGITransport(app=app)) as client,
    ):
        peer = ServiceVotePeer(
            client,
            "https://reviewer.example",
            policy=c.policy,
            cohorts=c.signing.cohorts,
            signer=c.signing.signer,
            token="v" * 32,
        )
        assert await peer.attest(ServiceRequestReview(body=s.body)) == vote


@pytest.mark.parametrize("kind", ["service_request_intent", "service_request_vote"])
async def test_service_vote_recovers_lost_committed_ack(reviewed, monkeypatch, kind):
    s, reviewer = reviewed, reviewed.reviewer()
    saved = []
    if kind.endswith("intent"):
        original = reviewer.journal.put_many

        def interrupted(records, **kwargs):
            records = tuple(records)
            result = original(records, **kwargs)
            if any(k == kind for k, _, _ in records):
                saved.append(True)
                raise OSError("committed intent reply lost")
            return result

        monkeypatch.setattr(reviewer.journal, "put_many", interrupted)
    else:
        original = reviewer.journal.put

        def interrupted(k, key, value):
            result = original(k, key, value)
            if k == kind:
                saved.append(True)
                raise OSError("committed vote reply lost")
            return result

        monkeypatch.setattr(reviewer.journal, "put", interrupted)
    with pytest.raises(OSError):
        await reviewer.attest(ServiceRequestReview(body=s.body))
    assert saved == [True]
    if kind.endswith("vote"):
        s.offline = True
    signature = await s.reviewer().attest(ServiceRequestReview(body=s.body))
    verify_signature(s.body, signature)
    assert s.signatures == 1 and s.archive_reads == 1


@pytest.mark.parametrize("damage", ["challenge", "signer", "claim", "bytes", "auth"])
async def test_service_lookup_rejects_substitution(reviewed, damage):
    s = reviewed

    async def fetch(request):
        if damage == "auth":
            response = await s.client.post(
                "https://coordinator.example" + PATH,
                content=canonical_json_bytes(request),
                headers={"content-type": "application/json"},
            )
            assert response.status_code == 401
            raise OSError("unauthenticated")
        raw = await s.fetch(request)
        signed = SignedServiceWorkResponse.model_validate_json(raw)
        response = signed.response
        if damage == "challenge":
            response = response.model_copy(update={"challenge": "00" * 32})
        elif damage == "claim":
            response = response.model_copy(
                update={
                    "assignment": response.assignment.model_copy(
                        update={
                            "admission": response.assignment.admission.model_copy(
                                update={"ordinal": 2}
                            )
                        }
                    )
                }
            )
        key = wallet("Alice") if damage == "signer" else s.p.validator
        raw = canonical_json_bytes(
            SignedServiceWorkResponse(response=response, signature=sign_object(response, key))
        )
        return raw + b" " if damage == "bytes" else raw

    reader = ServiceWorkReader(s.p.c.policy, s.p.validator.hotkey.ss58_address, fetch)
    with pytest.raises((OSError, ValueError)):
        await reader(s.c.assignment)
    assert s.signatures == 0


@pytest.mark.parametrize("damage", ["proof", "window", "owner", "history"])
async def test_service_review_requires_independent_evidence(reviewed, damage):
    s, reviewer = reviewed, reviewed.reviewer()
    if damage == "proof":
        s.p.c.rpc.bad_proof = True
    elif damage == "window":
        s.p.finality.blocks.pop(s.body.request.issued_block)
    elif damage == "owner":

        async def absent(assignment):
            raise FileNotFoundError("original work missing")

        reviewer.owner = absent
    else:
        from .test_competition_cohort_order_signer import source_for

        s.p.e.r.h.source = source_for(s.p.e.r.h.batch, s.p.e.r.h.batch["history"])
    with pytest.raises((OSError, ValueError, RuntimeError)):
        await reviewer.attest(ServiceRequestReview(body=s.body))
    assert s.signatures == 0


async def test_cancelled_signing_keeps_lease_until_durable_vote(reviewed):
    s, reviewer = reviewed, reviewed.reviewer()
    entered, release = asyncio.Event(), asyncio.Event()
    original = reviewer.sign

    async def slow(value):
        entered.set()
        try:
            await release.wait()
        except asyncio.CancelledError:
            # A signer may already own a non-cancellable hardware/thread operation.
            await release.wait()
        return await original(value)

    reviewer.sign = slow
    task = asyncio.create_task(reviewer.attest(ServiceRequestReview(body=s.body)))
    await asyncio.wait_for(entered.wait(), timeout=20)
    task.cancel()
    await asyncio.sleep(0)
    with pytest.raises(BlockingIOError), s.reviewer().journal.locked():
        pass
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    s.offline = True
    await s.reviewer().attest(ServiceRequestReview(body=s.body))
    assert s.signatures == 1


async def test_service_review_resumes_original_intent_after_long_signing_outage(reviewed):
    s, reviewer = reviewed, reviewed.reviewer()

    async def unavailable(value):
        raise OSError("signer temporarily offline")

    reviewer.sign = unavailable
    with pytest.raises(OSError):
        await reviewer.attest(ServiceRequestReview(body=s.body))
    assert s.archive_reads == 1 and s.signatures == 0
    await s.move(s.p.finality.head + 1000000)
    s.p.finality.blocks.clear()
    recovered = s.reviewer()

    async def missing(expected):
        raise FileNotFoundError("original archive source offline")

    recovered.archive = missing
    vote = await recovered.attest(ServiceRequestReview(body=s.body))
    verify_signature(s.body, vote)
    assert s.signatures == 1 and s.archive_reads == 1


async def test_service_review_cannot_change_selected_request_after_restart(reviewed):
    s = reviewed
    await s.reviewer().attest(ServiceRequestReview(body=s.body))
    request = s.body.request.model_copy(
        update={
            "video": s.body.request.video.model_copy(
                update={"url": "https://example.com/other.mp4"}
            )
        }
    )
    changed = s.body.model_copy(update={"request": request})
    with pytest.raises(ValueError, match="original intent"):
        await s.reviewer().attest(ServiceRequestReview(body=changed))
    assert s.signatures == 1


async def retired_attempt(s, monkeypatch):
    worker = s.worker()
    grant = await worker._certificate(s.body)
    s.p.finality.head = s.body.request.deadline_block + 3000
    await s.move(s.p.finality.head)
    monkeypatch.setattr(
        bt.timelock, "current_round", lambda: s.body.request.response_close_round + 500
    )
    result = await worker.transport.advance(service_grant_slot(s.body))
    assert result.retirement.receipt.result == "no_response_retained"
    assert result.response is None and s.p.model.calls == 0
    return ServiceRetryReview(grant=grant, retirement=result.retirement)


async def test_native_retry_review_and_fresh_window_finish_original_work(reviewed, monkeypatch):
    s = reviewed
    review = await retired_attempt(s, monkeypatch)
    decision = service_retry_decision(review)
    votes = tuple([await s.reviewer(n).attest(review) for n in ("Charlie", "Dave")])
    certificate = certify_service_retry(review, s.p.c.policy, s.p.transport_policy, votes)
    assert certificate.decision == decision

    async def retry(grant, retired):
        assert ServiceRetryReview(grant=grant, retirement=retired) == review
        return certificate

    s.retry = retry
    s.c.window = fresh_window(s.p, s.body.request, monkeypatch)
    await s.move(s.p.finality.head)
    worker, terminal, _ = await finish(s)
    body = worker.requests.latest(s.c.claim, s.p.validator.hotkey.ss58_address)
    assert body.attempt_number == 2 and body.assignment == s.body.assignment
    assert s.p.model.calls == 1 and s.signatures == 6
    s.offline = True
    assert await s.reviewer().attest(review) == votes[0]
    assert terminal.terminal.work_sha256 == s.body.assignment.admission.work_sha256


@pytest.mark.parametrize("damage", ["early_round", "signature", "response"])
async def test_retry_rejects_early_or_unfenced_replacement(reviewed, monkeypatch, damage):
    s = reviewed
    review = await retired_attempt(s, monkeypatch)
    if damage == "early_round":
        monkeypatch.setattr(
            bt.timelock, "current_round", lambda: s.body.request.response_close_round - 1
        )
    else:
        fence = review.retirement
        if damage == "signature":
            fence = fence.model_copy(
                update={"signature": sign_object(fence.receipt, wallet("Alice"))}
            )
        else:
            body = fence.receipt.model_copy(
                update={"result": "response_retained", "response_sha256": "ab" * 32}
            )
            fence = fence.model_copy(
                update={"receipt": body, "signature": sign_object(body, s.p.miner.wallet)}
            )
        review = review.model_copy(update={"retirement": fence})
    with pytest.raises(ValueError):
        await s.reviewer().attest(review)
    assert s.signatures == 2
