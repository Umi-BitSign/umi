from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from umi import competition_rounds as rounds
from umi.competition_evaluator import _publish, _read
from umi.competition_execution import execution_boundary
from umi.open_competition import digest, sign_object
from umi.protocol import canonical_json_bytes

from .test_competition_chain import chain_config as chain_config
from .test_competition_evaluator import Provider
from .test_competition_round_preparation import setup as preparation_fixture
from .test_open_competition import policy as policy
from .test_open_competition import snapshot, wallet

preparation = preparation_fixture


class OwnedProvider(Provider):
    def __init__(self, block=120):
        super().__init__(block)
        self.history = []
        self.historical_change = None
        self.advance_during_proof = None

    async def collect_at(self, height):
        self.history.append(height)
        result = await Provider(height).collect()
        if self.advance_during_proof is not None:
            self.block = self.advance_during_proof
        if self.historical_change is not None:
            result = self.historical_change(result)
        return result

    async def start(self):
        pass

    async def aclose(self):
        pass


@pytest.fixture
def setup(preparation, chain_config, tmp_path):
    policy = preparation.policy
    config = rounds.RoundCoordinatorConfig(
        schema="umi-round-coordinator-config/1",
        policy_sha256=digest(policy),
        chain=chain_config.model_copy(
            update={
                "policy_sha256": digest(policy),
                "state_directory": str(tmp_path / "round-chain"),
                "collection_timeout_seconds": 10,
            }
        ),
        state_directory=str(tmp_path / "round-state"),
        intake_directory=str(preparation.store.directory),
        plan_directory=str(tmp_path / "round-plans"),
        certificate_directory=str(tmp_path / "round-certificates"),
        replay_limits=preparation.options["limits"],
    )
    plan = rounds.RoundPlan(
        schema="umi-round-plan/1",
        suite=preparation.options["suite"],
        not_before_block=120,
        admission_close_by_block=125,
        signing_close_block=130,
        evaluation_close_block=140,
        reveal_block=150,
        evidence_cutoff_block=160,
        valid_through_block=190,
    )
    plan_path = Path(config.plan_directory) / (digest(plan.suite) + ".json")
    _publish(plan_path, plan)
    provider = OwnedProvider()
    coordinator = rounds.RoundCoordinator(config, policy, provider)
    app = rounds.create_round_app(config, policy, provider_factory=lambda *_: provider)
    transport = httpx.ASGITransport(app=app)
    workers = []
    for name in ("Charlie", "Dave"):
        signer = wallet(name)
        owned = OwnedProvider()

        async def boundary(owned=owned):
            return execution_boundary(await owned.collect())

        workers.append(
            SimpleNamespace(
                config=SimpleNamespace(
                    state_directory=str(tmp_path / name),
                    evaluator_hotkey=signer.hotkey.ss58_address,
                    maximum_orders=1024,
                    maximum_journal_bytes=1024**3,
                ),
                policy=policy,
                wallet=signer,
                provider=owned,
                boundary=boundary,
            )
        )
    clients = tuple(
        rounds.RoundSigningClient(w, "https://rounds.example", transport=transport) for w in workers
    )
    return SimpleNamespace(
        config=config,
        policy=policy,
        plan=plan,
        plan_path=plan_path,
        provider=provider,
        coordinator=coordinator,
        app=app,
        transport=transport,
        workers=workers,
        clients=clients,
    )


async def prepare(setup):
    result = await setup.coordinator.cycle()
    assert result["prepared"] == 1 and result["held"] == 0
    return setup.coordinator.proposals()[0]


@pytest.mark.asyncio
async def test_owned_preparation_and_independent_http_votes_publish_cutoff(setup):
    proposal = await prepare(setup)
    assert b'"references"' not in canonical_json_bytes(proposal)
    assert proposal.cutoff.registration_snapshot == snapshot(120)
    assert len(proposal.submissions) == 2
    assert not list(Path(setup.config.certificate_directory).glob("*.json"))
    await setup.clients[0].sync_once()
    assert not list(Path(setup.config.certificate_directory).glob("*.json"))
    await setup.clients[1].sync_once()
    path = Path(setup.config.certificate_directory) / (
        proposal.cutoff.round_sha256 + ".cutoff.json"
    )
    certificate = _read(path, rounds.SignedCutoffPublication)
    assert len(certificate.signatures) == 2
    rounds.verify_cutoff_publication(
        certificate,
        policy=setup.policy,
        submissions=proposal.submissions,
        limits=setup.config.replay_limits,
    )
    assert [w.provider.history for w in setup.workers] == [[120], [120]]
    assert not proposal.chain_submission_authorized


@pytest.mark.asyncio
async def test_lost_ack_retry_reuses_vote_after_signing_window_and_restart(setup):
    proposal = await prepare(setup)
    await setup.clients[0].endorse(proposal)
    raw = setup.clients[0].journal.get("vote", "1")
    setup.provider.block = 131
    recovered = rounds.RoundSigningClient(
        setup.workers[0], "https://rounds.example", transport=setup.transport
    )
    assert await recovered.endorse(proposal) == "endorsed"
    assert recovered.journal.get("vote", "1") == raw
    assert setup.workers[0].provider.history == [120]
    setup.workers[1].provider.block = 131
    assert await setup.clients[1].endorse(proposal) == "expired"
    assert setup.clients[1].journal.get("vote", "1") is None


@pytest.mark.asyncio
async def test_proof_failure_does_not_reserve_sequence_or_sign(setup):
    proposal = await prepare(setup)
    provider = setup.workers[0].provider

    async def unavailable(_height):
        raise ValueError("exact historical proof unavailable")

    original = provider.collect_at
    provider.collect_at = unavailable
    with pytest.raises(ValueError, match="historical proof unavailable"):
        await setup.clients[0].endorse(proposal)
    for kind, key in (("intent", "1"), ("vote", "1"), ("suite", digest(setup.plan.suite))):
        assert setup.clients[0].journal.get(kind, key) is None
    provider.collect_at = original
    assert await setup.clients[0].endorse(proposal) == "endorsed"


@pytest.mark.asyncio
async def test_proof_finishing_after_window_does_not_sign(setup):
    proposal = await prepare(setup)
    setup.workers[0].provider.advance_during_proof = 131
    with pytest.raises(ValueError, match="window elapsed"):
        await setup.clients[0].endorse(proposal)
    assert setup.clients[0].journal.get("vote", "1") is None
    assert setup.clients[0].journal.get("intent", "1") is None


@pytest.mark.asyncio
async def test_preparation_crash_recovers_original_cutoff_after_admission_close(setup, monkeypatch):
    original = setup.coordinator.journal.put

    def crash(kind, key, value):
        if kind == "prepared":
            raise OSError("interrupted after store commit")
        return original(kind, key, value)

    monkeypatch.setattr(setup.coordinator.journal, "put", crash)
    assert (await setup.coordinator.cycle())["held"] == 1
    setup.provider.block = 126
    recovered = rounds.RoundCoordinator(setup.config, setup.policy, setup.provider)
    assert (await recovered.cycle())["prepared"] == 1
    assert recovered.proposals()[0].cutoff.round.submission_close_block == 120


@pytest.mark.asyncio
async def test_changed_plan_is_held_across_restart(setup):
    await prepare(setup)
    changed = setup.plan.model_copy(update={"signing_close_block": 129})
    setup.plan_path.write_bytes(canonical_json_bytes(changed))
    assert (await setup.coordinator.cycle())["held"] == 1
    setup.plan_path.write_bytes(canonical_json_bytes(setup.plan))
    recovered = rounds.RoundCoordinator(setup.config, setup.policy, setup.provider)
    assert (await recovered.cycle())["held"] == 1
    with pytest.raises(ValueError, match="conflict held"):
        recovered.proposals()


@pytest.mark.asyncio
async def test_independent_signer_refuses_different_proposal_for_reserved_sequence(setup):
    proposal = await prepare(setup)
    await setup.clients[0].endorse(proposal)
    changed = proposal.model_copy(update={"signing_close_block": 129})
    with pytest.raises(ValueError, match="conflict retained"):
        await setup.clients[0].endorse(changed)
    recovered = rounds.RoundSigningClient(
        setup.workers[0], "https://rounds.example", transport=setup.transport
    )
    with pytest.raises(ValueError, match="conflict held"):
        await recovered.endorse(proposal)


@pytest.mark.asyncio
async def test_coordinator_rejects_regressed_head_after_restart(setup):
    await prepare(setup)
    setup.provider.block = 119
    recovered = rounds.RoundCoordinator(setup.config, setup.policy, setup.provider)
    with pytest.raises(ValueError, match="head regressed"):
        await recovered.cycle()


@pytest.mark.asyncio
async def test_http_authentication_nonce_and_body_bounds(setup):
    query = rounds.RoundQuery(
        schema="umi-round-query/1",
        policy_sha256=digest(setup.policy),
        hotkey=setup.workers[0].config.evaluator_hotkey,
        nonce_unix_ns=str(time.time_ns()),
    )
    signed = rounds.SignedRoundQuery(
        query=query, signature=sign_object(query, setup.workers[0].wallet)
    )
    async with httpx.AsyncClient(
        transport=setup.transport, base_url="https://rounds.example"
    ) as client:
        headers = {"Content-Type": "application/json"}
        response = await client.post(
            rounds.ROUTE, content=canonical_json_bytes(signed), headers=headers
        )
        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store"
        assert (
            await client.post(rounds.ROUTE, content=canonical_json_bytes(signed), headers=headers)
        ).status_code == 401
        assert (
            await client.post(rounds.ROUTE, content=b"x" * 16385, headers=headers)
        ).status_code == 413
        assert (await client.post(rounds.ROUTE, content=b"{}", headers=headers)).status_code == 401


def test_round_journal_capacity_and_private_state(tmp_path):
    journal = rounds.RoundJournal(tmp_path / "journal", {"policy": "test"}, maximum_rounds=1)
    journal.put("intent", "1", {"a": 1})
    with pytest.raises(ValueError, match="record capacity"):
        journal.put("intent", "2", {"a": 2})
    with sqlite3.connect(journal.path) as db:
        assert db.execute("SELECT COUNT(*) FROM records").fetchone()[0] == 1
    journal.path.chmod(0o644)
    with pytest.raises(ValueError, match="private and owned"):
        journal.get("intent", "1")


@pytest.mark.asyncio
async def test_ineligible_evaluator_does_not_vote(setup):
    proposal = await prepare(setup)
    worker = setup.workers[0]
    worker.config.evaluator_hotkey = wallet("Alice").hotkey.ss58_address
    worker.config.state_directory = str(Path(worker.config.state_directory).parent / "ineligible")
    worker.wallet = wallet("Alice")
    client = rounds.RoundSigningClient(worker, "https://different.example")
    assert await client.endorse(proposal) == "ineligible"
    assert client.journal.get("vote", "1") is None


@pytest.mark.asyncio
async def test_client_keeps_later_rounds_moving_after_one_proposal_fails(setup, monkeypatch):
    proposal = await prepare(setup)
    # Discovery is an untrusted transport. A failed proof must not starve peers.
    other = proposal.model_copy(
        update={
            "cutoff": proposal.cutoff.model_copy(
                update={"round": proposal.cutoff.round.model_copy(update={"sequence": 2})}
            )
        }
    )
    calls = []

    async def query(**_):
        return SimpleNamespace(proposals=(proposal, other))

    async def endorse(value):
        calls.append(value.cutoff.round.sequence)
        if value is proposal:
            raise ValueError("temporarily unavailable proof")

    monkeypatch.setattr(setup.clients[0], "query", query)
    monkeypatch.setattr(setup.clients[0], "endorse", endorse)
    await setup.clients[0].sync_once()
    assert calls == [1, 2]
    assert setup.clients[0].cursor == 2


def plan_at(setup, marker, block):
    return setup.plan.model_copy(
        update={
            "suite": setup.plan.suite.model_copy(
                update={
                    "cases": tuple(
                        c.model_copy(update={"case_id": f"{marker * 100 + i:064x}"})
                        for i, c in enumerate(setup.plan.suite.cases)
                    )
                }
            ),
            "not_before_block": block,
            "admission_close_by_block": block + 5,
            "signing_close_block": block + 10,
            "evaluation_close_block": block + 20,
            "reveal_block": block + 30,
            "evidence_cutoff_block": block + 40,
            "valid_through_block": block + 70,
        }
    )


@pytest.mark.asyncio
async def test_new_round_is_discovered_without_paging_expired_archive(setup):
    await prepare(setup)
    # More than four pages of retained history, with a restarted evaluator.
    for n in range(1, 18):
        block = 120 + n * 2
        plan = plan_at(setup, n, block)
        _publish(Path(setup.config.plan_directory) / (digest(plan.suite) + ".json"), plan)
        setup.provider.block = block
        assert (await setup.coordinator.cycle())["held"] == 0
    setup.provider.block = 170
    plan = plan_at(setup, 30, 170)
    _publish(Path(setup.config.plan_directory) / (digest(plan.suite) + ".json"), plan)
    assert (await setup.coordinator.cycle())["held"] == 0
    reply = await setup.clients[0].query()
    assert [p.cutoff.round.sequence for p in reply.proposals] == [19]
    for worker, client in zip(setup.workers, setup.clients, strict=True):
        worker.provider.block = 170
        await client.sync_once()
        assert worker.provider.history == [170]
    assert len(list(Path(setup.config.certificate_directory).glob("*.json"))) == 1
    assert len(setup.coordinator.journal.keys("prepared")) == 19


@pytest.mark.asyncio
async def test_known_future_plan_is_prioritized_when_its_window_opens(setup):
    await prepare(setup)
    for n in range(1, 12):
        expired = plan_at(setup, n, 100)
        key = digest(expired.suite)
        _publish(Path(setup.config.plan_directory) / (key + ".json"), expired)
        setup.coordinator.journal.put("plan", key, expired)
    future = plan_at(setup, 90, 180)
    key = digest(future.suite)
    _publish(Path(setup.config.plan_directory) / (key + ".json"), future)
    assert (await setup.coordinator.cycle())["waiting"] == 1
    setup.provider.block = 180
    recovered = rounds.RoundCoordinator(setup.config, setup.policy, setup.provider)
    assert (await recovered.cycle())["held"] == 0
    assert recovered.proposals(block=180)[0].cutoff.round.suite_sha256 == key


@pytest.mark.asyncio
async def test_expired_snapshot_is_not_advertised_even_if_signing_window_remains(setup):
    plan = setup.plan.model_copy(update={"signing_close_block": 135})
    setup.plan_path.write_bytes(canonical_json_bytes(plan))
    await prepare(setup)
    setup.provider.block = 131  # Policy maximum snapshot age is ten blocks.
    assert not (await setup.clients[0].query()).proposals
    assert setup.coordinator.proposals()  # Historical records remain inspectable.


@pytest.mark.asyncio
async def test_held_plan_is_not_advertised_to_evaluators(setup):
    await prepare(setup)
    setup.plan_path.write_bytes(
        canonical_json_bytes(setup.plan.model_copy(update={"signing_close_block": 129}))
    )
    assert (await setup.coordinator.cycle())["held"] == 1
    assert not (await setup.clients[0].query()).proposals


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "column,value",
    [
        ("sequence", 42),
        ("proposal", "00" * 32),
        ("snapshot_block", 119),
        ("signing_close", 129),
    ],
)
async def test_retained_index_must_match_canonical_proposal(setup, column, value):
    await prepare(setup)
    with sqlite3.connect(setup.coordinator.journal.path) as db:
        db.execute(f"UPDATE round_index SET {column}=?", (value,))
    with pytest.raises(ValueError, match="index binding"):
        setup.coordinator.proposals()


@pytest.mark.asyncio
@pytest.mark.parametrize("missing", ["intent", "suite"])
async def test_retained_vote_requires_its_original_reservations(setup, missing):
    proposal = await prepare(setup)
    await setup.clients[0].endorse(proposal)
    with sqlite3.connect(setup.clients[0].journal.path) as db:
        db.execute("DELETE FROM records WHERE kind=?", (missing,))
    with pytest.raises(ValueError, match="missing its signing reservation"):
        await setup.clients[0].endorse(proposal)
    assert setup.workers[0].provider.history == [120]


@pytest.mark.asyncio
async def test_reservation_without_vote_recovers_after_signing_interruption(setup, monkeypatch):
    proposal = await prepare(setup)
    sign = rounds.sign_cutoff_publication

    def interrupted(*_):
        raise OSError("signer interrupted")

    monkeypatch.setattr(rounds, "sign_cutoff_publication", interrupted)
    with pytest.raises(OSError, match="signer interrupted"):
        await setup.clients[0].endorse(proposal)
    assert setup.clients[0].journal.get("intent", "1") is not None
    assert setup.clients[0].journal.get("vote", "1") is None
    monkeypatch.setattr(rounds, "sign_cutoff_publication", sign)
    recovered = rounds.RoundSigningClient(
        setup.workers[0], "https://rounds.example", transport=setup.transport
    )
    assert await recovered.endorse(proposal) == "endorsed"


@pytest.mark.asyncio
async def test_provider_snapshot_disagreement_refuses_to_sign(setup):
    proposal = await prepare(setup)

    def different(capture):
        snap = capture.snapshot.model_copy(update={"registrations": ()})
        return replace(
            capture,
            snapshot=snap,
            provenance={
                **capture.provenance,
                "snapshot_sha256": digest(snap),
            },
        )

    setup.workers[0].provider.historical_change = different
    with pytest.raises(ValueError, match="registration snapshot differs"):
        await setup.clients[0].endorse(proposal)
    assert setup.clients[0].journal.get("intent", "1") is None


@pytest.mark.asyncio
async def test_cancelled_proof_cannot_leave_a_signature(setup):
    proposal = await prepare(setup)
    started, cleaned = asyncio.Event(), asyncio.Event()

    async def stalled(_height):
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            cleaned.set()

    setup.workers[0].provider.collect_at = stalled
    task = asyncio.create_task(setup.clients[0].endorse(proposal))
    await asyncio.wait_for(started.wait(), 2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert cleaned.is_set()
    assert setup.clients[0].journal.get("vote", "1") is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fault", ["query", "policy", "cursor", "duplicate", "kind", "redirect", "encoding"]
)
async def test_client_rejects_unbound_or_replayed_transport_reply(setup, fault):
    proposal = await prepare(setup)

    def handler(request):
        query = rounds.SignedRoundQuery.model_validate_json(request.content).query
        data = rounds.RoundReply(
            query_sha256=digest(query), policy_sha256=digest(setup.policy), proposals=(proposal,)
        ).model_dump(mode="json")
        headers = {"Content-Type": "application/json"}
        code = 200
        if fault in {"query", "policy"}:
            data[f"{fault}_sha256"] = "ff" * 32
        elif fault == "duplicate":
            data["proposals"] *= 2
        elif fault == "kind":
            data["accepted_proposal_sha256"] = digest(proposal)
        elif fault == "redirect":
            code, headers["Location"] = 302, "https://other.example"
        elif fault == "encoding":
            headers["Content-Encoding"] = "unknown"
        return httpx.Response(code, content=canonical_json_bytes(data), headers=headers)

    setup.clients[0].transport = httpx.MockTransport(handler)
    with pytest.raises(ValueError):
        await setup.clients[0].query(after_sequence=1 if fault == "cursor" else 0)


@pytest.mark.asyncio
async def test_http_errors_are_not_cacheable_and_release_capacity(setup):
    async with httpx.AsyncClient(transport=setup.transport, base_url="https://rounds.example") as c:
        for _ in range(5):
            response = await c.post(
                rounds.ROUTE, content=b"{}", headers={"Content-Type": "application/json"}
            )
            assert response.status_code == 401
            assert response.headers["cache-control"] == "no-store"
        response = await c.post(
            rounds.ROUTE, content=b"{}", headers={"Content-Type": "application/octet-stream"}
        )
        assert response.status_code == 400
        assert response.headers["cache-control"] == "no-store"


def test_journal_rejects_oversized_retained_objects_before_decode(tmp_path, monkeypatch):
    journal = rounds.RoundJournal(tmp_path / "j", {"policy": "test"})
    journal.put("intent", "1", {"small": True})
    with sqlite3.connect(journal.path) as db:
        db.execute("UPDATE records SET body=?", (b" " * (rounds.MAX_BYTES + 1),))
    real_loads = json.loads

    def guarded(raw, *args, **kwargs):
        assert len(raw) <= rounds.MAX_BYTES
        return real_loads(raw, *args, **kwargs)

    monkeypatch.setattr(rounds.json, "loads", guarded)
    with pytest.raises(ValueError, match="byte bound"):
        journal.get("intent", "1")
    with pytest.raises(ValueError, match="byte bound"):
        journal.put("intent", "1", {"small": True})


@pytest.mark.asyncio
async def test_round_server_lifespan_owns_provider_lock_and_drains_polling(setup, monkeypatch):
    started, cleaned = asyncio.Event(), asyncio.Event()
    events = []

    async def start():
        events.append("start")

    async def close():
        assert cleaned.is_set()
        events.append("close")

    async def stalled(_self):
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            cleaned.set()

    setup.provider.start, setup.provider.aclose = start, close
    monkeypatch.setattr(rounds.RoundCoordinator, "cycle", stalled)
    async with setup.app.router.lifespan_context(setup.app):
        await asyncio.wait_for(started.wait(), 2)
        second = rounds.create_round_app(
            setup.config, setup.policy, provider_factory=lambda *_: setup.provider
        )
        with pytest.raises((OSError, ValueError)):
            async with second.router.lifespan_context(second):
                pytest.fail("second coordinator obtained the lease")
    assert events == ["start", "close"]
    lease = rounds._lock_file(Path(setup.config.state_directory) / "coordinator.lock")
    os.close(lease)


@pytest.mark.asyncio
async def test_startup_failure_closes_provider_and_releases_lock(setup):
    closed = []

    async def start():
        raise OSError("provider startup unavailable")

    async def close():
        closed.append(True)

    setup.provider.start, setup.provider.aclose = start, close
    with pytest.raises(OSError, match="startup unavailable"):
        async with setup.app.router.lifespan_context(setup.app):
            pytest.fail("provider startup was skipped")
    assert closed == [True]
    lease = rounds._lock_file(Path(setup.config.state_directory) / "coordinator.lock")
    os.close(lease)


@pytest.mark.asyncio
async def test_polling_reports_bounded_failure_without_reference_or_exception_leak(
    setup, monkeypatch
):
    reports, reported = [], asyncio.Event()

    async def failure(_self):
        raise ValueError("SECRET PROTECTED REFERENCE")

    def report(value):
        reports.append(value)
        reported.set()

    monkeypatch.setattr(rounds.RoundCoordinator, "cycle", failure)
    app = rounds.create_round_app(
        setup.config, setup.policy, provider_factory=lambda *_: setup.provider, report=report
    )
    async with app.router.lifespan_context(app):
        await asyncio.wait_for(reported.wait(), 2)
    assert reports == [{"status": "round_poll_failed", "chain_submission_authorized": False}]


def test_cli_routes_private_coordinator_config_without_constructing_wallet(
    setup, monkeypatch, tmp_path
):
    import bittensor as bt

    from umi.competition_cli import main

    policy_path, config_path = tmp_path / "policy.json", tmp_path / "config.json"
    policy_path.write_bytes(canonical_json_bytes(setup.policy))
    config_path.write_bytes(canonical_json_bytes(setup.config))
    calls = []
    monkeypatch.setattr(bt, "Wallet", lambda **_: pytest.fail("coordinator constructed a wallet"))
    monkeypatch.setattr(
        rounds, "serve_rounds", lambda c, p, *, legacy=None: calls.append((c, p, legacy))
    )
    main(["--policy", str(policy_path), "serve-round-coordinator", "--config", str(config_path)])
    assert calls == [(setup.config, setup.policy, None)]


@pytest.mark.asyncio
async def test_recovery_cannot_retime_a_store_preparation_under_a_new_plan(setup, preparation):
    preparation.store.prepare_round(**preparation.options)
    changed = setup.plan.model_copy(update={"evaluation_close_block": 141})
    setup.plan_path.write_bytes(canonical_json_bytes(changed))
    assert (await setup.coordinator.cycle())["held"] == 1
    assert not setup.coordinator.proposals()
