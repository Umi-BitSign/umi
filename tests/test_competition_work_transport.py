from __future__ import annotations

import asyncio
import os
from pathlib import Path

import httpx
import pytest

from umi import competition_rounds as rounds
from umi import competition_work_transport as transport
from umi.competition_evaluator import SignedEvaluationOrder, _publish, _read
from umi.competition_work_plans import RoundWorkAssets, RoundWorkConfig
from umi.open_competition import digest, identity, sign_object
from umi.policy import scoring_policy_hash
from umi.protocol import canonical_json_bytes

from .test_competition_chain import chain_config as chain_config
from .test_competition_work_queue import policy as policy
from .test_competition_work_queue import runtime as runtime
from .test_competition_work_queue import setup as queue_fixture
from .test_competition_work_queue import signing as signing
from .test_competition_work_queue import work as work

queue_setup = queue_fixture


@pytest.fixture
def setup(queue_setup, chain_config, tmp_path):
    item = queue_setup
    p = item.work.policy
    chain = chain_config.model_copy(update={"policy_sha256": digest(p)})
    config = rounds.RoundCoordinatorConfig(
        schema="umi-round-coordinator-config/1",
        policy_sha256=digest(p),
        chain=chain.model_copy(
            update={
                "state_directory": str(tmp_path / "round-chain"),
                "collection_timeout_seconds": 10,
            }
        ),
        state_directory=str(tmp_path / "round-state"),
        intake_directory=str(tmp_path / "intake"),
        plan_directory=str(tmp_path / "plans"),
        certificate_directory=str(tmp_path / "cutoffs"),
        replay_limits=rounds.PublicationReplayLimits(
            maximum_roster_bytes=4 * 1024**2,
            maximum_certificate_bytes=4 * 1024**2,
            maximum_evidence_bytes=16 * 1024**2,
        ),
        work=RoundWorkConfig(
            state_directory=str(tmp_path / "round-work"),
            asset_directory=str(tmp_path / "assets"),
            order_directory=str(tmp_path / "round-orders"),
            publication_directory=str(tmp_path / "round-publications"),
            transport_chain=chain.model_copy(
                update={
                    "state_directory": str(tmp_path / "transport-chain"),
                    "collection_timeout_seconds": 10,
                }
            ),
            legacy_policy_sha256=scoring_policy_hash(item.work.item.legacy_policy),
            minimum_issue_ms=1000,
        ),
    )
    coordinator = rounds.RoundCoordinator(
        config,
        p,
        item.provider,
        legacy=item.work.item.legacy_policy,
        transport_provider=item.signers[0].transport_provider,
    )
    proposal = rounds.RoundProposal.model_validate_json(
        canonical_json_bytes(
            item.signers[0].cutoffs.get("intent", str(item.model.body.round.sequence))
        )
    )
    r = proposal.cutoff.round
    private = rounds.RoundPlan(
        schema="umi-round-plan/1",
        suite=item.work.item.suite,
        not_before_block=r.submission_close_block,
        admission_close_by_block=r.submission_close_block,
        signing_close_block=proposal.signing_close_block,
        evaluation_close_block=r.evaluation_close_block,
        reveal_block=r.reveal_block,
        evidence_cutoff_block=proposal.cutoff.cutoff_schedule.evidence_cutoff_block,
        valid_through_block=r.valid_through_block,
    )
    suite_id = r.suite_sha256
    coordinator.journal.put("plan", suite_id, private)
    coordinator.journal.put("prepared", suite_id, proposal)
    for signer in item.signers:
        vote = signer.cutoffs.get("vote", str(r.sequence))
        coordinator.journal.put(
            "vote", digest(proposal) + ":" + identity(signer.worker.config.evaluator_hotkey), vote
        )
    _publish(Path(config.plan_directory) / (suite_id + ".json"), private)
    assets = RoundWorkAssets(
        schema="umi-round-work-assets/1",
        suite_sha256=suite_id,
        incumbent=item.work.plan.incumbent,
        runtime=item.work.plan.runtime,
        videos=item.work.options["videos"],
    )
    _publish(Path(config.work.asset_directory) / (suite_id + ".json"), assets)
    app = rounds.create_round_app(
        config,
        p,
        provider_factory=lambda *_: item.provider,
        legacy=item.work.item.legacy_policy,
        transport_provider=item.signers[0].transport_provider,
    )
    item.clients = [
        transport.WorkSigningClient(
            s.worker,
            "https://rounds.example",
            s.cutoffs,
            transport_provider=s.transport_provider,
            minimum_issue_ms=1000,
            legacy=item.work.item.legacy_policy,
            transport=httpx.ASGITransport(app=app),
        )
        for s in item.signers
    ]
    item.config, item.coordinator, item.app = config, coordinator, app
    return item


@pytest.mark.asyncio
async def test_continuous_round_work_is_signed_and_published_through_http(setup):
    setup.provider.block += 1
    assert setup.provider.block > setup.model.body.round.submission_close_block + 1
    # Work still advances after cutoff signing has closed, without a new proposal.
    result = await setup.coordinator.cycle()
    assert result["held"] == 0
    assert result["prepared"] == 1
    for _ in range(3):
        for client in setup.clients:
            await client.sync_once()
    paths = list(Path(setup.config.work.order_directory).glob("*.json"))
    assert len(paths) == 2
    orders = [_read(p, SignedEvaluationOrder) for p in paths]
    assert sorted(o.order.submission.submission.track for o in orders) == ["endpoint", "model"]
    assert len(list(Path(setup.config.work.publication_directory).glob("*.json"))) == 1
    assert all(b'"references"' not in p.read_bytes() for p in paths)
    # A restarted coordinator and duplicate polls preserve all delivered bytes.
    before = [p.read_bytes() for p in paths]
    restarted = rounds.RoundCoordinator(
        setup.config,
        setup.work.policy,
        setup.provider,
        legacy=setup.work.item.legacy_policy,
        transport_provider=setup.signers[0].transport_provider,
    )
    assert (await restarted.cycle())["held"] == 0
    assert before == [p.read_bytes() for p in paths]


def signed_query(setup, *, nonce_offset=0):
    worker = setup.workers[0]
    query = transport.WorkQuery(
        schema="umi-work-query/1",
        policy_sha256=digest(setup.work.policy),
        hotkey=worker.config.evaluator_hotkey,
        nonce_unix_ns=str(setup.clock.now * 1_000_000 + nonce_offset),
    )
    return transport.SignedWorkQuery(query=query, signature=sign_object(query, worker.wallet))


@pytest.mark.asyncio
async def test_work_request_replay_and_byte_limits_are_rejected_without_logging_inputs(setup):
    await setup.coordinator.cycle()
    signed = signed_query(setup)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=setup.app), base_url="https://rounds.example"
    ) as client:

        async def send(raw, **headers):
            return await client.post(
                transport.ROUTE,
                content=raw,
                headers={"Content-Type": "application/json", **headers},
            )

        first = await send(canonical_json_bytes(signed))
        assert first.status_code == 200 and first.headers["cache-control"] == "no-store"
        assert b'"references"' not in first.content
        duplicate = await send(canonical_json_bytes(signed))
        assert duplicate.status_code == 401 and duplicate.headers["cache-control"] == "no-store"
        oversized = await send(b" " * (transport.MAX_REQUEST + 1))
        assert oversized.status_code == 413
        compressed = await send(b"sensitive-input", **{"Content-Encoding": "gzip"})
        assert compressed.status_code == 400 and b"sensitive-input" not in compressed.content
        stale = await send(canonical_json_bytes(signed_query(setup, nonce_offset=-31_000_000_000)))
        assert stale.status_code == 401


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["query", "cursor", "kind", "encoding", "redirect"])
async def test_client_rejects_unbound_or_wrong_kind_replies(setup, change):
    signed = signed_query(setup)
    reply = transport.WorkReply(
        query_sha256=digest(signed.query), policy_sha256=digest(setup.work.policy)
    )
    if change == "query":
        reply = reply.model_copy(update={"query_sha256": "ff" * 32})
    elif change == "cursor":
        reply = reply.model_copy(update={"statements": (setup.model,)})
    elif change == "kind":
        reply = reply.model_copy(update={"accepted_statement_sha256": digest(setup.model)})

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
        await transport.request_work(
            "https://rounds.example", signed, transport=httpx.MockTransport(respond)
        )


@pytest.mark.asyncio
async def test_missing_assets_hold_work_without_retiming_the_cutoff(setup):
    path = Path(setup.config.work.asset_directory) / (setup.model.body.round.suite_sha256 + ".json")
    path.rename(path.with_suffix(".held"))
    assert (await setup.coordinator.cycle())["held"] == 1
    assert not list(Path(setup.config.work.order_directory).glob("*.json"))
    assert len(list(Path(setup.config.certificate_directory).glob("*.cutoff.json"))) == 1
    path.with_suffix(".held").rename(path)
    assert (await setup.coordinator.cycle())["held"] == 0


def test_round_work_directories_and_transport_must_match(setup):
    raw = setup.config.model_dump(mode="json", by_alias=True)
    raw["work"]["asset_directory"] = raw["intake_directory"]
    with pytest.raises(ValueError, match="overlap"):
        rounds.RoundCoordinatorConfig.model_validate(raw)
    raw = setup.config.model_dump(mode="json", by_alias=True)
    raw["work"]["transport_chain"]["policy_sha256"] = "ff" * 32
    with pytest.raises(ValueError, match="matching transport"):
        rounds.RoundCoordinatorConfig.model_validate(raw)


@pytest.mark.asyncio
@pytest.mark.parametrize("fail_transport_start", [False, True])
async def test_coordinator_owns_and_closes_both_providers(setup, fail_transport_start, monkeypatch):
    events = []
    entered, drained = asyncio.Event(), asyncio.Event()
    owned_transport = setup.signers[0].transport_provider

    async def chain_start():
        events.append("chain-start")

    async def chain_close():
        events.append("chain-close")

    async def transport_start():
        events.append("transport-start")
        if fail_transport_start:
            raise OSError("injected startup failure")

    async def transport_close():
        assert fail_transport_start or drained.is_set()
        events.append("transport-close")

    async def poll(_):
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            drained.set()

    setup.provider.start, setup.provider.aclose = chain_start, chain_close
    owned_transport.start, owned_transport.aclose = transport_start, transport_close
    monkeypatch.setattr(rounds.RoundCoordinator, "cycle", poll)
    if fail_transport_start:
        with pytest.raises(OSError, match="injected startup"):
            async with setup.app.router.lifespan_context(setup.app):
                pytest.fail("startup failure was ignored")
    else:
        async with setup.app.router.lifespan_context(setup.app):
            await asyncio.wait_for(entered.wait(), 2)
    assert events == ["chain-start", "transport-start", "transport-close", "chain-close"]


def test_older_round_index_migration_preserves_the_original_execution_boundary(setup):
    journal = setup.coordinator.journal
    with journal.transaction() as db:
        db.execute("ALTER TABLE round_index DROP COLUMN execution_close")
    restarted = rounds.RoundCoordinator(
        setup.config,
        setup.work.policy,
        setup.provider,
        legacy=setup.work.item.legacy_policy,
        transport_provider=setup.signers[0].transport_provider,
    )
    block = setup.model.body.round.evaluation_close_block
    assert restarted.journal.prepared_entries(block=block - 1, for_work=True)
    assert restarted.journal.prepared_entries(block=block, for_work=True) == []


@pytest.mark.asyncio
async def test_client_reports_a_bounded_hold_when_cutoff_reservation_is_missing(setup):
    await setup.coordinator.cycle()
    with setup.clients[0].signer.cutoffs.transaction() as db:
        db.execute("DELETE FROM records WHERE kind='vote'")
    result = await setup.clients[0].sync_once()
    assert result == {"endorsed": 0, "held": 2}


def evaluator_config(setup, tmp_path):
    from umi.competition_evaluator import EvaluatorConfig

    root = tmp_path / "continuous-evaluator"
    paths = {
        name: str(root / name)
        for name in (
            "wallet_path",
            "state_directory",
            "order_directory",
            "reveal_directory",
            "peer_directory",
            "outbox_directory",
            "archive_directory",
            "video_directory",
            "dispatch_directory",
        )
    }
    return EvaluatorConfig(
        schema="umi-evaluator-config/1",
        policy_sha256=digest(setup.work.policy),
        evaluator_hotkey=setup.workers[0].config.evaluator_hotkey,
        wallet_name="test",
        hotkey_name="test",
        round_coordinator_origin="https://rounds.example",
        legacy_policy_sha256=scoring_policy_hash(setup.work.item.legacy_policy),
        chain=setup.config.chain.model_copy(update={"state_directory": str(root / "chain")}),
        work_signing_chain=setup.config.work.transport_chain.model_copy(
            update={"state_directory": str(root / "work-chain")}
        ),
        work_minimum_issue_ms=1000,
        **paths,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [None, "chain-start", "work-start", "work-close"])
async def test_evaluator_work_lifecycle_drains_task_and_closes_both_observers(
    setup, tmp_path, monkeypatch, failure
):
    import bittensor as bt

    from umi import competition_dispatch, competition_evaluator

    events = []
    entered, drained = asyncio.Event(), asyncio.Event()
    config = evaluator_config(setup, tmp_path)

    class Owned:
        def __init__(self, name):
            self.name = name

        async def start(self):
            event = self.name + "-start"
            events.append(event)
            if failure == event:
                raise OSError(event)

        async def aclose(self):
            event = self.name + "-close"
            if entered.is_set():
                assert drained.is_set(), "observer closed before work task drained"
            events.append(event)
            if failure == event:
                raise OSError(event)

    async def work_poll(_):
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            drained.set()

    async def cutoff_poll(_):
        return 0

    monkeypatch.setattr(bt, "Wallet", lambda **kw: setup.workers[0].wallet)
    monkeypatch.setattr(
        competition_evaluator, "FinalizedRegistrationProvider", lambda *_: Owned("chain")
    )
    monkeypatch.setattr(competition_dispatch, "DispatchFinalityProvider", lambda *_: Owned("work"))
    monkeypatch.setattr(transport.WorkSigningClient, "sync_once", work_poll)
    monkeypatch.setattr(rounds.RoundSigningClient, "sync_once", cutoff_poll)
    task = asyncio.create_task(
        competition_evaluator.run_evaluator(
            config, setup.work.policy, legacy=setup.work.item.legacy_policy
        )
    )
    try:
        if failure in {"chain-start", "work-start"}:
            with pytest.raises(OSError, match=failure):
                await asyncio.wait_for(task, 3)
        else:
            await asyncio.wait_for(entered.wait(), 3)
            task.cancel()
            with pytest.raises(OSError if failure else asyncio.CancelledError):
                await task
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    assert events[-2:] == ["work-close", "chain-close"]
    assert events[0] == "chain-start"
    if failure != "chain-start":
        assert events[1] == "work-start"
    lease = competition_evaluator._lock_file(Path(config.state_directory) / "evaluator.lock")
    os.close(lease)


@pytest.mark.parametrize("field", ["margin", "policy", "overlap", "origin", "timeout"])
def test_evaluator_work_config_rejects_unpaired_or_unbound_inputs(setup, tmp_path, field):
    from umi.competition_evaluator import EvaluatorConfig

    raw = evaluator_config(setup, tmp_path).model_dump(mode="json", by_alias=True)
    if field == "margin":
        raw["work_minimum_issue_ms"] = None
    elif field == "policy":
        raw["work_signing_chain"]["policy_sha256"] = "ff" * 32
    elif field == "overlap":
        raw["work_signing_chain"]["state_directory"] = raw["wallet_path"]
    elif field == "origin":
        raw["round_coordinator_origin"] = None
    else:
        raw["work_signing_chain"]["collection_timeout_seconds"] = 16
    with pytest.raises(ValueError):
        EvaluatorConfig.model_validate(raw)


def test_pre_work_evaluator_binding_remains_usable_with_fields_omitted(setup, tmp_path):
    from umi.competition_evaluator import EvaluatorConfig, EvaluatorJournal

    raw = evaluator_config(setup, tmp_path).model_dump(mode="json", by_alias=True)
    raw.pop("work_signing_chain")
    raw.pop("work_minimum_issue_ms")
    config = EvaluatorConfig.model_validate(raw)
    journal = EvaluatorJournal(config)
    with journal.transaction() as db:
        binding = bytes(db.execute("SELECT body FROM binding").fetchone()[0])
    assert b"work_signing_chain" not in binding and b"work_minimum_issue_ms" not in binding
    EvaluatorJournal(config)
