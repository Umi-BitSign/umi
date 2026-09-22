from __future__ import annotations

import asyncio
import sqlite3
import time
from pathlib import Path

import httpx
import pytest

from umi import competition_rounds as rounds
from umi import competition_settlement_delivery as delivery
from umi import competition_settlement_transport as transport
from umi.competition_evaluator import ContinuousEvaluator, EvaluatorConfig, _read
from umi.competition_package import PreparedCompetitionPackage, load_competition_package
from umi.competition_publication import PublicationReplayLimits, settlement_publication_digest
from umi.open_competition import digest, identity, sign_object
from umi.protocol import canonical_json_bytes

from .competition_checkpoint import bind_submission_checkpoint
from .test_competition_chain import chain_config as chain_config
from .test_competition_package import package_limits as package_limits
from .test_competition_package import release_identity as release_identity
from .test_competition_rounds import deployment_for
from .test_competition_settlement_signing import policy as policy
from .test_competition_settlement_signing import setup as signing_fixture
from .test_open_competition import wallet

signing_setup = signing_fixture


@pytest.fixture
def replay_limits(request):
    return PublicationReplayLimits(
        maximum_roster_bytes=1_000_000,
        maximum_certificate_bytes=4 * 1024**2,
        maximum_evidence_bytes=getattr(request, "param", 5_000_000),
    )


@pytest.fixture
def setup(signing_setup, chain_config, package_limits, release_identity, tmp_path, monkeypatch):
    # Delivery/state tests reuse the signer's synthetic both-track fixture.
    # Local execution is isolated there; these tests do not attest real model quality.
    s = signing_setup
    public_launch = deployment_for(
        s.round.public_schedule, s.round.eligible_tracks
    ).launch_identity()
    checkpoint = tmp_path / "intake-checkpoint"
    s.store = bind_submission_checkpoint(s.store, public_launch, checkpoint)
    config = rounds.RoundCoordinatorConfig(
        schema="umi-round-coordinator-config/2",
        policy_sha256=digest(s.policy),
        public_launch=public_launch,
        chain=chain_config.model_copy(
            update={
                "policy_sha256": digest(s.policy),
                "state_directory": str(tmp_path / "chain"),
                "collection_timeout_seconds": 10,
            }
        ),
        state_directory=str(tmp_path / "coordinator"),
        intake_directory=str(s.store.directory),
        submission_head_checkpoint_directory=str(checkpoint),
        plan_directory=str(tmp_path / "plans"),
        certificate_directory=str(tmp_path / "cutoffs"),
        replay_limits=s.limits,
        settlement_directory=str(tmp_path / "proposals"),
        settlement_delivery=rounds.SettlementDeliveryConfig(
            state_directory=str(tmp_path / "delivery"),
            certificate_directory=str(tmp_path / "delivery-output"),
            package_directory=str(tmp_path / "packages"),
            package_limits=package_limits,
            release_identity=release_identity,
        ),
    )
    s.provider = s.signers[0].worker.provider
    s.coordinator = rounds.RoundCoordinator(config, s.policy, s.provider)
    proposal = rounds.RoundProposal.model_validate_json(
        canonical_json_bytes(s.signers[0].cutoffs.get("intent", "1"))
    )
    r = proposal.cutoff.round
    plan = rounds.RoundPlan(
        schema="umi-round-plan/2",
        suite=s.suite,
        public_schedule=r.public_schedule,
        eligible_tracks=r.eligible_tracks,
        intake_opened_block=r.public_schedule.intake_opened_block,
        not_before_block=r.public_schedule.roster_close_earliest_block,
        admission_close_by_block=r.public_schedule.roster_close_latest_block,
        signing_close_block=r.public_schedule.work_signing_close_block,
        evaluation_close_block=r.public_schedule.evaluation_close_block,
        reveal_block=r.public_schedule.protected_reference_reveal_block,
        evidence_cutoff_block=r.public_schedule.evidence_cutoff_block,
        valid_through_block=r.public_schedule.round_valid_through_block,
    )
    s.coordinator.journal.put("plan", r.suite_sha256, plan)
    s.coordinator.journal.put("prepared", r.suite_sha256, proposal)
    for signer in s.signers:
        s.coordinator.journal.put(
            "vote",
            digest(proposal) + ":" + identity(signer.worker.config.evaluator_hotkey),
            signer.cutoffs.get("vote", "1"),
        )
    s.app = rounds.create_round_app(config, s.policy, provider_factory=lambda *_: s.provider)
    s.clients = []
    for signer in s.signers:
        client = transport.SettlementSigningClient(
            signer.worker,
            "https://rounds.example",
            signer.cutoffs,
            s.store,
            limits=s.limits,
            transport=httpx.ASGITransport(app=s.app),
        )
        monkeypatch.setattr(client.signer, "_local_evidence", signer._local_evidence)
        s.clients.append(client)
    s.config, s.queue = config, s.coordinator.settlement_queue
    yield s
    for path in Path(config.settlement_delivery.package_directory).iterdir():
        if path.is_dir():
            path.chmod(0o700)


def package(s):
    files = list(Path(s.config.settlement_delivery.certificate_directory).glob("*.package.json"))
    assert len(files) == 1
    result = _read(files[0], PreparedCompetitionPackage)
    return result, load_competition_package(
        Path(result.package_path),
        expected_package_sha256=result.package_sha256,
        expected_policy_sha256=digest(s.policy),
        observed_release=s.config.settlement_delivery.release_identity,
        limits=s.config.settlement_delivery.package_limits,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("replay_limits", [5_000_000, 256 * 1024**2], indirect=True)
async def test_coordinator_cycle_to_http_signatures_to_verified_70_30_package(setup):
    s = setup
    result = await s.coordinator.cycle()
    assert result["settlement_prepared"] == 1 and result["settlement_held"] == 0
    assert (await s.clients[0].sync_once()) == {"endorsed": 1, "held": 0}
    assert not list(Path(s.config.settlement_delivery.certificate_directory).glob("*.json"))
    assert (await s.clients[1].sync_once()) == {"endorsed": 1, "held": 0}
    prepared, verified = package(s)
    assert verified.retained_settlement == s.settlement
    assert verified.policy.endpoint_reward_bps == 7000 and verified.policy.model_reward_bps == 3000
    assert len(verified.settlement_certificate.signatures) == 2
    assert not prepared.chain_submission_authorized
    assert not verified.chain_submission_authorized
    prior = canonical_json_bytes(verified)
    fresh = rounds.RoundCoordinator(s.config, s.policy, s.provider)
    assert (await fresh.cycle())["settlement_held"] == 0
    assert canonical_json_bytes(package(s)[1]) == prior


@pytest.mark.asyncio
@pytest.mark.parametrize("replay_limits", [256 * 1024**2], indirect=True)
async def test_large_profile_serializes_requests_through_response_send(setup, monkeypatch):
    s = setup
    entered, release = asyncio.Event(), asyncio.Event()
    calls = 0

    async def pending(*args, **kwargs):
        nonlocal calls
        calls += 1
        return 0, ()

    monkeypatch.setattr(s.queue, "pending", pending)
    app = rounds.FastAPI()
    transport.attach_settlement_route(app, s.queue)

    async def delayed_app(scope, receive, send):
        async def delayed_send(message):
            if message["type"] == "http.response.body" and not entered.is_set():
                entered.set()
                await release.wait()
            await send(message)

        await app(scope, receive, delayed_send)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=delayed_app), base_url="https://rounds.example"
    ) as client:

        async def query():
            return await client.post(
                transport.ROUTE,
                content=canonical_json_bytes(signed_query(s)),
                headers={"Content-Type": "application/json"},
            )

        first = asyncio.create_task(query())
        try:
            await asyncio.wait_for(entered.wait(), timeout=2)
            assert (await query()).status_code == 503
            assert calls == 1
        finally:
            release.set()
            assert (await first).status_code == 200
        assert (await query()).status_code == 200
        assert calls == 2


@pytest.mark.asyncio
async def test_response_send_cancellation_releases_capacity():
    capacity = asyncio.Semaphore(1)
    await capacity.acquire()
    response = transport._CapacityResponse(b"{}", capacity)

    async def cancelled(message):
        raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await response({"type": "http"}, None, cancelled)
    await asyncio.wait_for(capacity.acquire(), timeout=0.1)


@pytest.mark.asyncio
async def test_unknown_invalid_and_self_interested_votes_do_not_create_a_certificate(setup):
    s = setup
    vote = await s.signers[0].endorse(s.prepared)
    with pytest.raises(ValueError, match="unknown"):
        await s.queue.accept(vote)
    await s.queue.prepare(s.prepared)
    bad = vote.model_copy(
        update={"signature": sign_object(s.prepared.publication, wallet("Alice"))}
    )
    with pytest.raises(ValueError):
        await s.queue.accept(bad)
    assert s.queue.journal.get("certificate", "1") is None


@pytest.mark.asyncio
async def test_conflict_after_preparation_prevents_discovery_and_vote_acceptance(setup):
    s = setup
    vote = await s.signers[0].endorse(s.prepared)
    await s.queue.prepare(s.prepared)
    with sqlite3.connect(s.store.path) as db:
        db.create_function("umi_writer_generation", 0, lambda: 2)
        db.execute("INSERT INTO round_conflicts VALUES (?,?)", (digest(s.round), 160))
    assert (await s.queue.pending(vote.signature.hotkey))[1] == ()
    with pytest.raises(ValueError):
        await s.queue.accept(vote)
    assert s.queue.journal.get("certificate", "1") is None


@pytest.mark.asyncio
@pytest.mark.parametrize("block", [159, 171, 301])
@pytest.mark.parametrize("replay_limits", [5_000_000, 256 * 1024**2], indirect=True)
async def test_early_or_expired_preparations_do_not_enter_discovery(setup, block):
    s = setup
    s.provider.block = block
    with pytest.raises(ValueError, match="window"):
        await s.queue.prepare(s.prepared)
    assert s.queue.journal.get("intent", "1") is None


@pytest.mark.asyncio
@pytest.mark.parametrize("replay_limits", [5_000_000, 256 * 1024**2], indirect=True)
async def test_late_new_vote_is_rejected_without_retiming(setup):
    s = setup
    await s.queue.prepare(s.prepared)
    vote = await s.signers[0].endorse(s.prepared)
    s.provider.block = 171
    with pytest.raises(ValueError, match="outside"):
        await s.queue.accept(vote)
    assert s.queue.journal.get("certificate", "1") is None
    assert (await s.queue.pending(vote.signature.hotkey))[1] == ()


@pytest.mark.asyncio
async def test_package_failure_keeps_quorum_and_cycle_repairs_delivery(setup, monkeypatch):
    s = setup
    assert (await s.coordinator.cycle())["settlement_held"] == 0
    prepared = s.queue._prepared(s.round.sequence)
    votes = [await signer.endorse(prepared) for signer in s.signers]
    await s.queue.accept(votes[0])
    original = delivery.prepare_competition_package
    monkeypatch.setattr(
        delivery,
        "prepare_competition_package",
        lambda **_: (_ for _ in ()).throw(OSError("disk full")),
    )
    with pytest.raises(OSError):
        await s.queue.accept(votes[1])
    certificate = s.queue.journal.get("certificate", "1")
    assert certificate is not None
    monkeypatch.setattr(delivery, "prepare_competition_package", original)
    fresh = rounds.RoundCoordinator(s.config, s.policy, s.provider)
    assert (await fresh.cycle())["settlement_held"] == 0
    assert canonical_json_bytes(package(s)[1].settlement_certificate) == canonical_json_bytes(
        certificate
    )


def signed_query(s, *, name="Charlie", offset=0):
    key = wallet(name)
    query = transport.SettlementQuery(
        schema="umi-settlement-query/1",
        policy_sha256=digest(s.policy),
        hotkey=key.hotkey.ss58_address,
        nonce_unix_ns=str(time.time_ns() + offset),
    )
    return transport.SignedSettlementQuery(query=query, signature=sign_object(query, key))


@pytest.mark.asyncio
async def test_transport_requires_current_unique_evaluator_authentication(setup):
    s = setup
    await s.coordinator.cycle()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=s.app), base_url="https://rounds.example"
    ) as client:

        async def send(raw, **headers):
            return await client.post(
                transport.ROUTE,
                content=raw,
                headers={"Content-Type": "application/json", **headers},
            )

        raw = canonical_json_bytes(signed_query(s))
        first = await send(raw)
        assert first.status_code == 200 and first.headers["cache-control"] == "no-store"
        assert transport.SettlementReply.model_validate_json(first.content).proposals == (
            s.queue._prepared(s.round.sequence),
        )
        assert (await send(raw)).status_code == 401
        assert (await send(canonical_json_bytes(signed_query(s, name="Alice")))).status_code == 401
        assert (
            await send(canonical_json_bytes(signed_query(s, offset=-31_000_000_000)))
        ).status_code == 401
        assert (await send(b" " * (transport.MAX_REQUEST + 1))).status_code == 413
        assert (await send(b"private", **{"Content-Encoding": "gzip"})).status_code == 400
        assert (await send(raw + b" ")).status_code == 401


@pytest.mark.asyncio
async def test_large_profile_pending_cursor_advances_one_record_at_a_time(setup, monkeypatch):
    from umi.competition_settlement_capacity import settlement_capacity

    queue = setup.queue
    queue.capacity = settlement_capacity(
        setup.limits.model_copy(update={"maximum_evidence_bytes": 256 * 1024**2})
    )
    with queue.journal.transaction() as db:
        db.executemany(
            "INSERT INTO settlement_index VALUES (?,?,?,?)",
            [(i, str(i), 0, 2**53 - 1) for i in (1, 2, 3)],
        )
    observed = []

    def held(sequence):
        observed.append(sequence)
        raise ValueError("held proposal")

    monkeypatch.setattr(queue, "_prepared", held)
    hotkey = setup.signers[0].worker.config.evaluator_hotkey
    cursor = 0
    for expected in (1, 2, 3):
        cursor, proposals = await queue.pending(hotkey, after=cursor)
        assert cursor == expected and proposals == () and observed == list(range(1, expected + 1))


@pytest.mark.asyncio
async def test_large_profile_client_rejects_multiple_proposals(setup):
    from umi.competition_settlement_capacity import settlement_capacity

    signed = signed_query(setup)
    reply = transport.SettlementReply(
        query_sha256=digest(signed.query),
        policy_sha256=digest(setup.policy),
        cursor=setup.round.sequence,
        proposals=(setup.prepared, setup.prepared),
    )

    def respond(_):
        return httpx.Response(
            200, content=canonical_json_bytes(reply), headers={"Content-Type": "application/json"}
        )

    with pytest.raises(ValueError, match="configured page size"):
        await transport.request_settlement(
            "https://rounds.example",
            signed,
            transport=httpx.MockTransport(respond),
            capacity=settlement_capacity(
                setup.limits.model_copy(update={"maximum_evidence_bytes": 256 * 1024**2})
            ),
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["query", "cursor", "kind", "encoding", "redirect"])
async def test_client_rejects_unbound_or_wrong_kind_replies(setup, change):
    s = setup
    signed = signed_query(s)
    reply = transport.SettlementReply(
        query_sha256=digest(signed.query), policy_sha256=digest(s.policy)
    )
    if change == "query":
        reply = reply.model_copy(update={"query_sha256": "ff" * 32})
    elif change == "cursor":
        reply = reply.model_copy(update={"proposals": (s.prepared,)})
    elif change == "kind":
        reply = reply.model_copy(
            update={
                "accepted_publication_sha256": settlement_publication_digest(s.prepared.publication)
            }
        )

    def respond(_):
        return httpx.Response(
            302 if change == "redirect" else 200,
            content=canonical_json_bytes(reply),
            headers={
                "Content-Type": "application/json",
                "Content-Encoding": "br" if change == "encoding" else "identity",
            },
        )

    with pytest.raises(ValueError):
        await transport.request_settlement(
            "https://rounds.example", signed, transport=httpx.MockTransport(respond)
        )


def test_delivery_config_requires_preparation_and_disjoint_paths(setup):
    s = setup
    for fields in (
        {"settlement_directory": None},
        {"settlement_directory": s.config.settlement_delivery.package_directory},
    ):
        with pytest.raises(ValueError):
            rounds.RoundCoordinatorConfig.model_validate_json(
                canonical_json_bytes(s.config.model_copy(update=fields))
            )


@pytest.mark.asyncio
async def test_discovery_index_corruption_and_cursor_bounds_are_rejected(setup):
    s = setup
    await s.queue.prepare(s.prepared)
    hotkey = s.signers[0].worker.config.evaluator_hotkey
    for cursor in (-1, True, 2**53):
        with pytest.raises(ValueError, match="cursor"):
            await s.queue.pending(hotkey, after=cursor)
    with s.queue.journal.transaction() as db:
        db.execute("UPDATE settlement_index SET publication=?", ("ff" * 32,))
    assert (await s.queue.pending(hotkey))[1] == ()


@pytest.mark.asyncio
async def test_changed_retained_preparation_holds_across_restart(setup):
    s = setup
    await s.queue.prepare(s.prepared)
    changed = s.prepared.model_copy(
        update={
            "cutoff": s.prepared.cutoff.model_copy(
                update={
                    "signatures": tuple(reversed(s.prepared.cutoff.signatures)),
                }
            ),
        }
    )
    with pytest.raises(ValueError):
        await s.queue.prepare(changed)
    fresh = rounds.RoundCoordinator(s.config, s.policy, s.provider)
    assert (await fresh.settlement_queue.pending(s.signers[0].worker.config.evaluator_hotkey))[
        1
    ] == ()


@pytest.mark.asyncio
@pytest.mark.parametrize("replay_limits", [5_000_000, 256 * 1024**2], indirect=True)
async def test_expiry_during_package_creation_cannot_advertise_delivery(setup, monkeypatch):
    s = setup
    await s.queue.prepare(s.prepared)
    votes = [await signer.endorse(s.prepared) for signer in s.signers]
    await s.queue.accept(votes[0])
    original = delivery.prepare_competition_package

    def advance(**kwargs):
        result = original(**kwargs)
        s.provider.block = 171
        return result

    monkeypatch.setattr(delivery, "prepare_competition_package", advance)
    assert await s.queue.accept(votes[1]) == votes[1].publication_sha256
    assert s.queue.journal.get("certificate", "1") is not None
    assert s.queue.journal.get("package", "1") is None
    assert not list(Path(s.config.settlement_delivery.certificate_directory).glob("*.json"))


@pytest.mark.asyncio
async def test_evaluator_config_starts_and_joins_its_settlement_client(
    setup, tmp_path, monkeypatch
):
    s = setup
    key = wallet("Charlie")
    fields = {
        name: str(tmp_path / ("worker-" + name))
        for name in (
            "wallet_path",
            "state_directory",
            "order_directory",
            "reveal_directory",
            "peer_directory",
            "outbox_directory",
            "archive_directory",
            "video_directory",
        )
    }
    config = EvaluatorConfig(
        schema="umi-evaluator-config/1",
        policy_sha256=digest(s.policy),
        chain=s.config.chain,
        evaluator_hotkey=key.hotkey.ss58_address,
        wallet_name="test",
        hotkey_name="test",
        round_coordinator_origin="https://rounds.example",
        settlement_review_directory=str(tmp_path / "independent-reviews"),
        settlement_replay_limits=s.limits,
        **fields,
    )
    for change in (
        {"settlement_replay_limits": None},
        {"round_coordinator_origin": None},
        {"settlement_review_directory": config.wallet_path},
    ):
        with pytest.raises(ValueError):
            EvaluatorConfig.model_validate_json(
                canonical_json_bytes(config.model_copy(update=change))
            )
    worker = ContinuousEvaluator(config, s.policy, key, s.provider)
    assert isinstance(worker.settlement_client, transport.SettlementSigningClient)
    assert worker.settlement_client.signer.reviews is worker.review_store
    assert worker.review_store.directory == Path(config.settlement_review_directory)
    assert not worker.review_store.submissions()
    entered = asyncio.Event()

    async def pending():
        entered.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(worker.settlement_client, "sync_once", pending)
    monkeypatch.setattr(worker.round_client, "sync_once", pending)
    try:
        await worker.poll_once()
        await asyncio.wait_for(entered.wait(), timeout=1)
        original = worker._settlement_task
        await worker.poll_once()
        assert worker._settlement_task is original
    finally:
        await worker.aclose()
    assert original.cancelled() and worker._settlement_task is None


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", ["prepare", "discover", "publish"])
@pytest.mark.parametrize("replay_limits", [5_000_000, 256 * 1024**2], indirect=True)
async def test_conflict_during_finality_collection_is_rechecked_before_output(setup, stage):
    s = setup
    votes = [await signer.endorse(s.prepared) for signer in s.signers]
    if stage != "prepare":
        await s.queue.prepare(s.prepared)
    if stage == "publish":
        await s.queue.accept(votes[0])
    original = s.provider.collect
    calls = 0

    async def conflict():
        nonlocal calls
        capture = await original()
        calls += 1
        if calls == {"prepare": 1, "discover": 2, "publish": 3}[stage]:
            with sqlite3.connect(s.store.path) as db:
                db.create_function("umi_writer_generation", 0, lambda: 2)
                db.execute("INSERT INTO round_conflicts VALUES (?,?)", (digest(s.round), 160))
        return capture

    s.provider.collect = conflict
    if stage == "discover":
        assert (await s.queue.pending(votes[0].signature.hotkey))[1] == ()
    else:
        with pytest.raises(ValueError):
            if stage == "prepare":
                await s.queue.prepare(s.prepared)
            else:
                await s.queue.accept(votes[1])
    assert s.queue.journal.get("package", "1") is None
    assert not list(Path(s.config.settlement_delivery.certificate_directory).glob("*.json"))
