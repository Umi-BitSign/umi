"""Both-track service integration with synthetic keys, data and CPU adapter.

Cutoffs, work, sealed endpoint responses, independent execution journals and
settlements use their real signatures and authenticated in-process transports.
This is not a protected-data quality, production latency or rights approval.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from types import SimpleNamespace

import bittensor as bt
import httpx
import pytest
from fastapi.testclient import TestClient

from umi import competition_execution as execution
from umi import competition_rounds as rounds
from umi.competition_artifacts import preserve_bundle
from umi.competition_dispatch import EndpointDispatcher
from umi.competition_evaluator import (
    ContinuousEvaluator,
    EvaluatorConfig,
    SignedEvaluationOrder,
    _read,
)
from umi.competition_exchange import ExchangeConfig, ExchangeUnavailableError, create_exchange_app
from umi.competition_feed import create_assignment_feed
from umi.competition_package import PreparedCompetitionPackage, load_competition_package
from umi.competition_promotion_delivery import ReviewedPromotion
from umi.competition_publication import PublicationReplayLimits
from umi.competition_review_history import EvaluatorReviewStore
from umi.competition_round_assets import ArchivedRoundWorkAssets
from umi.competition_scheduling import AssignmentPublicationJournal
from umi.competition_store import AgreedPromotionReview, AttestedPromotionReview, CompetitionStore
from umi.competition_void import AttestedEvaluationVoid
from umi.competition_work_plans import RoundWorkConfig
from umi.drand import DrandPulse
from umi.open_competition import Registration, digest, sign_object
from umi.policy import scoring_policy_hash
from umi.protocol import canonical_json_bytes
from umi.window import QUICKNET_GENESIS_MS, QUICKNET_PERIOD_MS

from .test_competition_authorization import build_authorization_fixture
from .test_competition_dispatch import authorization as original_authorization
from .test_competition_dispatch import dispatch as dispatch
from .test_competition_endpoint_execution import paired_setup as paired_setup
from .test_competition_evaluator import completed, put
from .test_competition_package import package_limits as package_limits
from .test_competition_package import release_identity as release_identity
from .test_competition_rounds import OwnedProvider
from .test_competition_runner import runtime as runtime
from .test_drand import ROUND, pulse_record
from .test_open_competition import bundle_at, review_for, snapshot, wallet
from .test_open_competition import policy as policy


@pytest.fixture
def authorization(policy, runtime, tmp_path, monkeypatch, request):
    baseline = bundle_at(tmp_path / "baseline")
    candidate = bundle_at(tmp_path / "candidate", "candidate", digest(baseline))
    unstable = (
        bundle_at(tmp_path / "unstable", "unstable", digest(baseline))
        if getattr(request, "param", "scored") == "void"
        else None
    )
    if unstable is not None:
        original_snapshot = snapshot

        def with_eve(block=110):
            value = original_snapshot(block)
            return value.model_copy(
                update={
                    "registrations": tuple(
                        sorted(
                            (
                                *value.registrations,
                                Registration(uid=8, hotkey=wallet("Eve").hotkey.ss58_address),
                            ),
                            key=lambda r: r.uid,
                        )
                    )
                }
            )

        monkeypatch.setattr("tests.test_competition_lifecycle.snapshot", with_eve)
        monkeypatch.setattr("tests.test_competition_evaluator.snapshot", with_eve)
    policy = policy.model_copy(update={"evaluation_runtime_sha256": digest(runtime)})
    legacy = original_authorization.__wrapped__(policy).legacy_policy
    now = 1789300000000000000
    monkeypatch.setattr(time, "time_ns", lambda: now)
    monkeypatch.setattr(time, "time", lambda: time.time_ns() / 1_000_000_000)
    initial = build_authorization_fixture(policy, legacy_policy=legacy)
    now += (ROUND - initial.request.reveal_round) * QUICKNET_PERIOD_MS * 1_000_000
    item = build_authorization_fixture(
        policy,
        legacy_policy=legacy,
        incumbent_sha256=digest(baseline),
        model_bundle=candidate,
        extra_model_bundle=unstable,
    )
    assert item.request.reveal_round == ROUND
    monkeypatch.setattr(
        bt.timelock,
        "current_round",
        lambda: (time.time_ns() // 1_000_000 - QUICKNET_GENESIS_MS) // QUICKNET_PERIOD_MS + 1,
    )
    item.baseline, item.candidate, item.runtime = baseline, candidate, runtime
    item.unstable = unstable
    return item


@pytest.fixture
def feed(authorization, tmp_path, monkeypatch):
    # Start empty. Only independently signed work delivered through the exchange
    # may publish assignments; the helper's example certificate is never seeded.
    item = authorization
    issuance = item.finalized_blocks.blocks[item.request.issued_block]
    clock = SimpleNamespace(ns=max(time.time_ns(), issuance.timestamp_ms * 1_000_000 + 1000))
    monkeypatch.setattr(time, "time_ns", lambda: clock.ns)
    journal = AssignmentPublicationJournal(tmp_path / "journal", item.policy, item.legacy_policy)
    nonce_path = tmp_path / "nonces" / "feed.sqlite3"
    app = create_assignment_feed(journal, nonce_path=nonce_path)
    with TestClient(app) as client:
        yield SimpleNamespace(
            item=item, journal=journal, clock=clock, nonce_path=nonce_path, client=client
        )


def seed_store(path, item, archive):
    store = CompetitionStore(path, item.policy)
    store.initialize_baseline(item.baseline, archive)
    for signed in item.submissions:
        store.admit(signed, snapshot(1000), 1000)
    return store


@pytest.fixture
def lifecycle(paired_setup, package_limits, release_identity, tmp_path, monkeypatch):
    setup = paired_setup
    dispatch = setup.dispatch
    item = dispatch.feed.item
    preserve_bundle(item.candidate, tmp_path / "candidate", setup.archive, item.policy)
    if item.unstable is not None:
        preserve_bundle(item.unstable, tmp_path / "unstable", setup.archive, item.policy)
    original_run = execution.execute_offline_case
    unstable_calls = 0

    async def run(**kwargs):
        nonlocal unstable_calls
        result = await original_run(**kwargs)
        if item.unstable is not None and kwargs["bundle"] == item.unstable:
            # Only the first real adapter invocation returns "hello". The other
            # evaluator observes different output for that same case, regardless
            # of task ordering. All output bytes still pass ordinary replay.
            unstable_calls += 1
            text = "hello" if unstable_calls == 1 else "different"
            return result.model_copy(
                update={
                    "output": result.output.model_copy(update={"hypothesis": text}),
                    "stdout_hex": (text + "\n").encode().hex(),
                }
            )
        if kwargs["bundle"] == item.candidate:
            return result.model_copy(
                update={
                    "output": result.output.model_copy(update={"hypothesis": "hello"}),
                    "stdout_hex": b"hello\n".hex(),
                }
            )
        return result

    monkeypatch.setattr(execution, "execute_offline_case", run)

    class TransportFinality(type(dispatch.provider)):
        # Each worker has a separate owned-source test port. No real observer
        # executable or chain endpoint is started by this in-process test.
        def __init__(self, *_):
            pass

        async def start(self):
            pass

        async def aclose(self):
            pass

    monkeypatch.setattr("umi.competition_dispatch.DispatchFinalityProvider", TransportFinality)
    limits = PublicationReplayLimits(
        maximum_roster_bytes=1_000_000,
        maximum_certificate_bytes=4 * 1024**2,
        maximum_evidence_bytes=5_000_000,
    )

    def chain(name):
        return dispatch.config.chain.model_copy(
            update={"state_directory": str(tmp_path / name), "collection_timeout_seconds": 10}
        )

    config = rounds.RoundCoordinatorConfig(
        schema="umi-round-coordinator-config/1",
        policy_sha256=digest(item.policy),
        chain=chain("round-chain"),
        state_directory=str(tmp_path / "round-state"),
        intake_directory=str(tmp_path / "intake"),
        plan_directory=str(tmp_path / "plans"),
        certificate_directory=str(tmp_path / "cutoffs"),
        replay_limits=limits,
        work=RoundWorkConfig(
            state_directory=str(tmp_path / "work-state"),
            asset_directory=str(tmp_path / "assets"),
            order_directory=str(tmp_path / "work-orders"),
            publication_directory=str(tmp_path / "work-publications"),
            transport_chain=chain("work-chain"),
            legacy_policy_sha256=scoring_policy_hash(item.legacy_policy),
            minimum_issue_ms=1000,
        ),
        settlement_directory=str(tmp_path / "settlements"),
        promotion_delivery=rounds.PromotionDeliveryConfig(
            reviewed_directory=str(tmp_path / "reviewed-promotions"),
            archive_directory=str(setup.archive),
        ),
        settlement_delivery=rounds.SettlementDeliveryConfig(
            state_directory=str(tmp_path / "settlement-state"),
            certificate_directory=str(tmp_path / "settlement-certificates"),
            package_directory=str(tmp_path / "packages"),
            package_limits=package_limits,
            release_identity=release_identity,
        ),
    )
    store = seed_store(Path(config.intake_directory), item, setup.archive)
    r = item.round
    plan = rounds.RoundPlan(
        schema="umi-round-plan/1",
        suite=item.suite,
        not_before_block=r.submission_close_block,
        admission_close_by_block=r.submission_close_block,
        signing_close_block=r.submission_close_block + 1,
        evaluation_close_block=r.evaluation_close_block,
        reveal_block=r.reveal_block,
        evidence_cutoff_block=r.reveal_block + 3,
        valid_through_block=r.valid_through_block,
    )
    put(Path(config.plan_directory) / (digest(item.suite) + ".json"), plan)
    assets = ArchivedRoundWorkAssets(
        schema="umi-round-work-assets/2",
        suite_sha256=digest(item.suite),
        runtime=item.runtime,
        videos=tuple(a.request.video for a in item.publication.publication.assignments[:3]),
    )
    put(Path(config.work.asset_directory) / (digest(item.suite) + ".json"), assets)
    provider = OwnedProvider(r.submission_close_block)
    coordinator = rounds.RoundCoordinator(
        config,
        item.policy,
        provider,
        legacy=item.legacy_policy,
        transport_provider=dispatch.provider,
    )
    app = rounds.create_round_app(
        config,
        item.policy,
        provider_factory=lambda *_: provider,
        legacy=item.legacy_policy,
        transport_provider=dispatch.provider,
    )
    exchange_config = ExchangeConfig(
        schema="umi-evaluator-exchange-config/1",
        policy_sha256=digest(item.policy),
        chain=chain("exchange-chain"),
        state_directory=str(tmp_path / "exchange-state"),
        order_directory=config.work.order_directory,
        reveal_directory=str(tmp_path / "exchange-reveals"),
        intake_directory=config.intake_directory,
        legacy_policy_sha256=scoring_policy_hash(item.legacy_policy),
    )
    put(Path(exchange_config.reveal_directory) / (digest(item.suite) + ".json"), item.suite)
    exchange_app = create_exchange_app(
        exchange_config,
        item.policy,
        legacy=item.legacy_policy,
        provider_factory=lambda *_: provider,
    )
    fetched = []

    class Pulses:
        async def fetch(self, number):
            fetched.append(number)
            assert number == ROUND
            return DrandPulse(**pulse_record())

    drivers, review_stores = [], []
    for index, signer in enumerate(item.evaluator_wallets[:2]):
        root = tmp_path / f"worker-{index}"
        review_store = EvaluatorReviewStore(root / "reviews", item.policy, limits=limits)
        review_store.initialize_baseline(item.baseline, setup.archive)
        cfg = EvaluatorConfig(
            schema="umi-evaluator-config/1",
            policy_sha256=digest(item.policy),
            chain=chain(f"worker-{index}-chain"),
            evaluator_hotkey=signer.hotkey.ss58_address,
            wallet_name="test",
            hotkey_name="test",
            archive_directory=str(setup.archive),
            video_directory=str(setup.videos),
            dispatch_directory=str(dispatch.feed.journal.path.parent),
            assignment_directory=dispatch.config.publication_directory,
            legacy_policy_sha256=scoring_policy_hash(item.legacy_policy),
            exchange_origin="https://exchange.example",
            round_coordinator_origin="https://rounds.example",
            work_signing_chain=chain(f"worker-{index}-work-chain"),
            work_minimum_issue_ms=1000,
            settlement_review_directory=str(review_store.directory),
            settlement_replay_limits=limits,
            **{
                name: str(root / name)
                for name in (
                    "wallet_path",
                    "state_directory",
                    "order_directory",
                    "reveal_directory",
                    "peer_directory",
                    "outbox_directory",
                )
            },
        )
        driver = ContinuousEvaluator(
            cfg,
            item.policy,
            signer,
            OwnedProvider(provider.block),
            legacy=item.legacy_policy,
            pulse_client=Pulses(),
        )
        driver.round_client.transport = httpx.ASGITransport(app=app)
        driver.work_client.transport = httpx.ASGITransport(app=app)
        driver.settlement_client.transport = httpx.ASGITransport(app=app)
        driver.exchange.transport = httpx.ASGITransport(app=exchange_app)
        drivers.append(driver)
        review_stores.append(review_store)
    yield SimpleNamespace(
        item=item,
        paired=setup,
        config=config,
        provider=provider,
        coordinator=coordinator,
        store=store,
        plan=plan,
        drivers=drivers,
        reviews=review_stores,
        fetched=fetched,
        exchange_config=exchange_config,
    )
    packages = Path(config.settlement_delivery.package_directory)
    if packages.exists():
        for path in packages.iterdir():
            if path.is_dir():
                path.chmod(0o700)


async def tick(driver):
    await driver.poll_once()
    tasks = list(driver._tasks.values())
    tasks += [
        task
        for name in ("_round_task", "_work_task", "_exchange_task", "_settlement_task")
        if (task := getattr(driver, name)) is not None
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    # The production poll loop retries transport failures. All completion,
    # evidence and exact inference-count assertions below remain required.
    assert not [
        r
        for r in results
        if isinstance(r, BaseException) and not isinstance(r, ExchangeUnavailableError)
    ], results


def completed_voids(driver):
    return [
        _read(path, AttestedEvaluationVoid)
        for path in Path(driver.config.outbox_directory).glob("*.void.json")
    ]


async def complete_first_round(lifecycle):
    s = lifecycle
    item, dispatch = s.item, s.paired.dispatch
    void_count = int(item.unstable is not None)
    inference_count = 18 + 12 * void_count
    try:
        result = await s.coordinator.cycle()
        assert result["prepared"] == 1 and result["held"] == 0, result
        proposal = s.coordinator.proposals()[0]
        assert proposal.cutoff.round == item.round
        assert proposal.submissions == item.submissions
        # Cutoff endorsement also derives work, so use the owned issuance head.
        s.provider.block = item.request.issued_block
        for driver in s.drivers:
            driver.provider.block = s.provider.block
            await driver.round_client.sync_once()
            assert driver.round_client.journal.get("vote", str(item.round.sequence)) is not None
        assert all(not review.submissions() for review in s.reviews)
        for _ in range(3):
            for driver in s.drivers:
                result = await driver.work_client.sync_once()
                assert result["held"] == 0, result
        for review in s.reviews:
            entries = review.submissions()
            assert len(entries) == len(item.submissions)
            assert all(e["receipt"]["first_observed_block"] == s.provider.block for e in entries)
            assert all("accepted_block" not in e["receipt"] for e in entries)
        orders = [
            _read(path, SignedEvaluationOrder)
            for path in Path(s.config.work.order_directory).glob("*.json")
        ]
        assert sorted(o.order.submission.submission.track for o in orders) == [
            "endpoint",
            "model",
            *(["model"] if void_count else []),
        ]
        assert all(b'"references"' not in canonical_json_bytes(o) for o in orders)
        assert not list(Path(dispatch.config.publication_directory).glob("*.json"))
        for driver in s.drivers:
            await driver.exchange.sync_once()
        assert len(list(Path(dispatch.config.publication_directory).glob("*.json"))) == 1
        dispatchers = [dispatch.driver]
        dispatchers.append(
            EndpointDispatcher(
                dispatch.config.model_copy(
                    update={"evaluator_hotkey": s.drivers[1].config.evaluator_hotkey}
                ),
                dispatch.feed.journal,
                dispatch.provider,
                item.evaluator_wallets[1],
                transport=dispatch.driver.transport,
            )
        )
        try:
            for turn in range(6):
                for driver in s.drivers:
                    await tick(driver)
                for driver in dispatchers:
                    await driver.poll_once()
                    await driver.drain()
                await dispatch.miner.competition_authority.poll_once()
                dispatch.feed.clock.ns += 1
                if turn == 0:
                    dispatch.feed.clock.ns += (
                        dispatch.config.discovery_grace_seconds * 1_000_000_000
                    )
            assert [d._counts["completed"] for d in dispatchers] == [3, 3]
        finally:
            for driver in dispatchers:
                await driver.aclose()
        assert all(not completed(driver) for driver in s.drivers)
        s.provider.block = item.round.reveal_block
        for driver in s.drivers:
            driver.provider.block = s.provider.block
        for _ in range(10):
            for driver in s.drivers:
                await tick(driver)
            if all(
                len(completed(d)) == 2 and len(completed_voids(d)) == void_count for d in s.drivers
            ):
                break
        for driver in s.drivers:
            await driver.exchange.sync_once()
        results = [
            {e.attested_result.result.submission_sha256: e for e in completed(d)} for d in s.drivers
        ]
        assert len(results[0]) == 2 and results[0] == results[1]
        void_results = [completed_voids(d) for d in s.drivers]
        assert len(void_results[0]) == void_count and void_results[0] == void_results[1]
        if void_count:
            assert void_results[0][0].void.reason == "observation_disagreement"
            assert void_results[0][0].void.submission_sha256 == digest(
                item.extra_model_submission.submission
            )
        assert s.fetched == [ROUND, ROUND]
        assert dispatch.miner.translator.calls == 6
        assert len([c for c in s.paired.calls if isinstance(c, dict)]) == inference_count

        # Each reviewer uses its own completed evidence and admission history.
        # Synthetic rights/reconstruction reviews are explicitly test inputs.
        model_id = digest(item.model_submission.submission)
        attested = results[0][model_id].attested_result
        review_body = review_for(item.policy, item.model_submission, item.round, attested).review
        review_body = AgreedPromotionReview.model_validate(
            {
                **review_body.model_dump(mode="json", by_alias=True),
                "schema": "umi-model-promotion-review/2",
                "round_sha256": digest(item.round),
                "submission_sha256": digest(item.model_submission.submission),
                "previous_promotion_sha256": s.store.baseline_summary()["promotion_sha256"],
                "sequence": 1,
            }
        )
        reviewed = AttestedPromotionReview(
            review=review_body,
            signatures=tuple(sign_object(review_body, w) for w in item.evaluator_wallets[:2]),
        )
        value = ReviewedPromotion(
            schema="umi-reviewed-promotion-delivery/1",
            review=reviewed,
            round=item.round,
            submission=item.model_submission,
        )
        put(
            Path(s.config.promotion_delivery.reviewed_directory)
            / (digest(reviewed.review) + ".json"),
            value,
        )
        observed_start = s.provider.block
        s.provider.block = observed_start + 2
        assert await s.coordinator.apply_promotions() == {
            "promotions_applied": 1,
            "promotions_held": 0,
        }
        for index, driver in enumerate(s.drivers):
            driver.provider.block = observed_start + index
            await driver.round_client.sync_once()
        promotions = [store.baseline() for store in (*s.reviews, s.store)]
        assert promotions[0] == promotions[1] == promotions[2]
        assert promotions[0]["sequence"] == 1
        for index, store in enumerate((*s.reviews, s.store)):
            with store._connection() as connection:
                assert connection.execute(
                    "SELECT observed_block FROM promotion_receipts WHERE sequence=1"
                ).fetchone() == (observed_start + index,)
        s.provider.block = s.plan.evidence_cutoff_block
        for driver in s.drivers:
            driver.provider.block = s.provider.block
        result = await s.coordinator.cycle()
        assert result["settlement_prepared"] == 1 and result["settlement_held"] == 0, result
        for driver in s.drivers:
            assert await driver.settlement_client.sync_once() == {"endorsed": 1, "held": 0}
        paths = list(
            Path(s.config.settlement_delivery.certificate_directory).glob("*.package.json")
        )
        assert len(paths) == 1
        prepared = _read(paths[0], PreparedCompetitionPackage)
        package = load_competition_package(
            Path(prepared.package_path),
            expected_package_sha256=prepared.package_sha256,
            expected_policy_sha256=digest(item.policy),
            observed_release=s.config.settlement_delivery.release_identity,
            limits=s.config.settlement_delivery.package_limits,
        )
        weights = package.retained_settlement.projection.weights
        assert weights[6] == 45875 and weights[247] == 19660
        assert weights[8] == 0
        assert sum(weights) == 65535 and weights.count(0) == 254
        settlement = package.retained_settlement
        assert settlement.schema_ == f"umi-competition-settlement/{1 + void_count}"
        assert len(settlement.results) == 2 + void_count
        assert {r.submission_sha256 for r in settlement.results} == set(item.round.roster)
        assert not package.chain_submission_authorized
        # Exact retries cannot rerun inference or replace a settled publication.
        prior = paths[0].read_bytes()
        for driver in s.drivers:
            await tick(driver)
        assert paths[0].read_bytes() == prior
        assert len([c for c in s.paired.calls if isinstance(c, dict)]) == inference_count
    finally:
        for driver in s.drivers:
            await driver.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("authorization", ["scored", "void"], indirect=True)
async def test_both_tracks_execute_promote_and_deliver_70_30_from_empty_service_journals(lifecycle):
    await complete_first_round(lifecycle)


@pytest.mark.asyncio
async def test_next_round_survives_restart_and_executes_the_promoted_incumbent(lifecycle):
    s = lifecycle
    await complete_first_round(s)
    item, dispatch = s.item, s.paired.dispatch
    first_round = canonical_json_bytes(item.round)
    first_suite = digest(item.suite)
    first_model = item.round.incumbent_model_sha256
    packages = Path(s.config.settlement_delivery.certificate_directory)
    first_path = next(packages.glob("*.package.json"))
    first_package = first_path.read_bytes()
    first_calls = len([c for c in s.paired.calls if isinstance(c, dict)])

    # A real second Quicknet pulse, retrieved from the pinned public chain.
    # https://api.drand.sh/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971/public/1001440
    next_pulse = DrandPulse.from_json(
        {
            "round": 1001440,
            "randomness": "f3f26e281cebb4df390b78bd3f8d062bdbba5ab284107396d22ea7827e23943a",
            "signature": (
                "ad7995595d1cce98dcacde09dc1ceeb377508d9cf0e32d43078f1f43397245c37"
                "a213f897f694f542050ae6ed76c83bd"
            ),
        },
        expected_round=1001440,
    )

    def next_fixture():
        return build_authorization_fixture(
            item.policy,
            legacy_policy=item.legacy_policy,
            incumbent_sha256=digest(item.candidate),
            model_bundle=item.candidate,
            window_index=1,
            sequence=2,
        )

    next_item = next_fixture()
    dispatch.feed.clock.ns += (
        (next_pulse.round - next_item.request.reveal_round) * QUICKNET_PERIOD_MS * 1_000_000
    )
    next_item = next_fixture()
    assert next_item.request.reveal_round == next_pulse.round
    issuance = next_item.finalized_blocks.blocks[next_item.request.issued_block]
    dispatch.feed.clock.ns = max(dispatch.feed.clock.ns, issuance.timestamp_ms * 1_000_000 + 1)
    assert next_item.policy == item.policy
    # sr25519 re-signing may change signature bytes; the retained admission and
    # its exact original signature remain in the store across both rounds.
    assert tuple(s.submission for s in next_item.submissions) == tuple(
        s.submission for s in item.submissions
    )
    assert next_item.round.submission_close_block > item.round.valid_through_block
    # Preserve the owned-source test object's old block history for replay.
    item.finalized_blocks.blocks.update(next_item.finalized_blocks.blocks)
    item.finalized_blocks.head = next_item.finalized_blocks.head
    for field in ("request", "suite", "round", "cases", "schedule", "publication"):
        setattr(item, field, getattr(next_item, field))

    plan = s.plan.model_copy(
        update={
            "suite": item.suite,
            "not_before_block": item.round.submission_close_block,
            "admission_close_by_block": item.round.submission_close_block,
            "signing_close_block": item.round.submission_close_block + 1,
            "evaluation_close_block": item.round.evaluation_close_block,
            "reveal_block": item.round.reveal_block,
            "evidence_cutoff_block": item.round.reveal_block + 3,
            "valid_through_block": item.round.valid_through_block,
        }
    )
    assets = ArchivedRoundWorkAssets(
        schema="umi-round-work-assets/2",
        suite_sha256=digest(item.suite),
        runtime=item.runtime,
        videos=tuple(a.request.video for a in item.publication.publication.assignments[:3]),
    )
    put(Path(s.config.plan_directory) / (digest(item.suite) + ".json"), plan)
    put(Path(s.config.work.asset_directory) / (digest(item.suite) + ".json"), assets)
    # Exchange owns the reveal inbox; evaluator inboxes are populated over HTTPS.
    exchange_reveals = Path(s.exchange_config.reveal_directory)
    put(exchange_reveals / (digest(item.suite) + ".json"), item.suite)

    # Restart coordinator and both evaluator clients from their existing journals.
    s.provider.block = item.round.submission_close_block
    s.coordinator = rounds.RoundCoordinator(
        s.config,
        item.policy,
        s.provider,
        legacy=item.legacy_policy,
        transport_provider=dispatch.provider,
    )
    app = rounds.create_round_app(
        s.config,
        item.policy,
        provider_factory=lambda *_: s.provider,
        legacy=item.legacy_policy,
        transport_provider=dispatch.provider,
    )

    class NextPulse:
        async def fetch(self, number):
            s.fetched.append(number)
            assert number == next_pulse.round
            return next_pulse

    restarted = []
    for driver in s.drivers:
        new = ContinuousEvaluator(
            driver.config,
            item.policy,
            driver.wallet,
            OwnedProvider(s.provider.block),
            legacy=item.legacy_policy,
            pulse_client=NextPulse(),
        )
        for client in (new.round_client, new.work_client, new.settlement_client):
            client.transport = httpx.ASGITransport(app=app)
        new.exchange.transport = driver.exchange.transport
        restarted.append(new)
    s.drivers = restarted
    dispatchers = [
        EndpointDispatcher(
            dispatch.config.model_copy(update={"evaluator_hotkey": d.config.evaluator_hotkey}),
            dispatch.feed.journal,
            dispatch.provider,
            d.wallet,
            transport=dispatch.driver.transport,
        )
        for d in s.drivers
    ]
    try:
        await s.coordinator.cycle()
        proposal = next(p for p in s.coordinator.proposals() if p.cutoff.round.sequence == 2)
        assert proposal.cutoff.round == item.round
        assert proposal.cutoff.round.incumbent_model_sha256 == digest(item.candidate)
        s.provider.block = item.request.issued_block
        for driver in s.drivers:
            driver.provider.block = s.provider.block
            await driver.round_client.sync_once()
        for _ in range(3):
            for driver in s.drivers:
                await driver.work_client.sync_once()
        orders = [
            _read(p, SignedEvaluationOrder)
            for p in Path(s.config.work.order_directory).glob("*.json")
        ]
        second_orders = [o for o in orders if o.order.round.sequence == 2]
        assert len(second_orders) == 2
        assert all(digest(o.order.incumbent) == digest(item.candidate) for o in second_orders)
        assert all(
            digest(o.order.incumbent) == first_model for o in orders if o.order.round.sequence == 1
        )
        for driver in s.drivers:
            await driver.exchange.sync_once()
        for _ in range(6):
            for driver in s.drivers:
                await tick(driver)
            for driver in dispatchers:
                await driver.poll_once()
                await driver.drain()
            await dispatch.miner.competition_authority.poll_once()
            # A restarted dispatcher may ingest an old publication first. Each
            # newly discovered publication gets its own full discovery grace.
            dispatch.feed.clock.ns += dispatch.config.discovery_grace_seconds * 1_000_000_000
        assert [d._counts["completed"] for d in dispatchers] == [3, 3], [
            d._counts for d in dispatchers
        ]
        s.provider.block = item.round.reveal_block
        for driver in s.drivers:
            driver.provider.block = s.provider.block
        for _ in range(10):
            for driver in s.drivers:
                await tick(driver)
            if all(len(completed(d)) == 4 for d in s.drivers):
                break
        assert all(len(completed(d)) == 4 for d in s.drivers)
        for driver in s.drivers:
            await driver.exchange.sync_once()
        s.provider.block = plan.evidence_cutoff_block
        for driver in s.drivers:
            driver.provider.block = s.provider.block
        result = await s.coordinator.cycle()
        assert result["settlement_prepared"] >= 1 and result["settlement_held"] == 0, result
        for driver in s.drivers:
            result = await driver.settlement_client.sync_once()
            assert result == {"endorsed": 1, "held": 0}, result
        paths = list(packages.glob("*.package.json"))
        assert len(paths) == 2 and first_path.read_bytes() == first_package
        second_path = next(p for p in paths if p != first_path)
        prepared = _read(second_path, PreparedCompetitionPackage)
        package = load_competition_package(
            Path(prepared.package_path),
            expected_package_sha256=prepared.package_sha256,
            expected_policy_sha256=digest(item.policy),
            observed_release=s.config.settlement_delivery.release_identity,
            limits=s.config.settlement_delivery.package_limits,
        )
        assert package.retained_settlement.projection.weights[6] == 45875
        assert package.retained_settlement.projection.weights[247] == 19660
        assert not package.chain_submission_authorized
        prior = second_path.read_bytes()
        for driver in s.drivers:
            await tick(driver)
        assert second_path.read_bytes() == prior and first_path.read_bytes() == first_package
        assert s.fetched == [ROUND, ROUND, next_pulse.round, next_pulse.round]
        calls = [c for c in s.paired.calls if isinstance(c, dict)]
        assert len(calls) == first_calls + 18
        assert all(digest(c["bundle"]) == digest(item.candidate) for c in calls[first_calls:])
        assert dispatch.miner.translator.calls == 12
        retained = s.store.prepared_round(first_suite, s.config.replay_limits)
        assert canonical_json_bytes(retained["cutoff_publication"]["round"]) == first_round
    finally:
        for driver in (*s.drivers, *dispatchers):
            await driver.aclose()
