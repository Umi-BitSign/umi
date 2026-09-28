"""Native request closure/controller recovery; synthetic finality and inference."""

import sqlite3
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from umi.competition_cohort_coordinator import CohortRecoveryCoordinator
from umi.competition_cohort_intake import CohortIntakePublisher
from umi.competition_cohort_intake_records import read_participation
from umi.competition_cohort_progress_signer import (
    CertifiedPhaseObserver,
    CohortProgressSigner,
    CohortProgressSignerConfig,
)
from umi.competition_cohort_recovery import StandingCohortRecoveryAuthority
from umi.competition_cohort_recovery_store import CohortRecoveryStore
from umi.competition_cohort_request_phase import NativeRequestProgressSource
from umi.competition_cohort_request_review import RequestProgressReviewer
from umi.competition_round_journal import RoundJournal
from umi.concurrency import run_owned_thread
from umi.open_competition import digest, identity, sign_object

from .cohort_settlement_original_fixture import publish_original_intake, select_original_sources
from .test_competition_cohort_service_grants import base_policy as base_policy
from .test_competition_cohort_service_grants import chain as chain
from .test_competition_cohort_service_grants import chain_config as chain_config
from .test_competition_cohort_service_grants import endpoint as endpoint
from .test_competition_cohort_service_grants import execution as execution
from .test_competition_cohort_service_grants import granted as granted
from .test_competition_cohort_service_grants import harness as harness
from .test_competition_cohort_service_grants import known_video_bytes as known_video_bytes
from .test_competition_cohort_service_grants import legacy_scenario as legacy_scenario
from .test_competition_cohort_service_grants import miner_policy as miner_policy
from .test_competition_cohort_service_grants import original_harness as original_harness
from .test_competition_cohort_service_grants import policy as policy
from .test_competition_cohort_service_grants import receipt_scenario as receipt_scenario
from .test_competition_cohort_service_grants import recovery as recovery
from .test_competition_cohort_service_grants import recovery_case as recovery_case
from .test_competition_cohort_service_grants import relay as relay
from .test_competition_cohort_service_grants import runtime as runtime
from .test_competition_cohort_service_grants import scenario as scenario
from .test_competition_cohort_service_grants import service as service
from .test_competition_cohort_service_grants import service_catalog_inputs as service_catalog_inputs
from .test_competition_cohort_service_grants import service_closed as service_closed
from .test_competition_cohort_service_grants import service_owner as service_owner
from .test_competition_cohort_service_grants import shared_control_group as shared_control_group
from .test_competition_cohort_service_queue import capture
from .test_open_competition import wallet


@pytest.fixture
def request_owner(service_closed, tmp_path, monkeypatch):
    if not isinstance(
        service_closed["history"].authority.authority, StandingCohortRecoveryAuthority
    ):
        pytest.skip("automatic request runtime selects standing authority")
    return make_request_owner(service_closed, tmp_path, monkeypatch)


def make_request_owner(service_closed, tmp_path, monkeypatch):
    b, c = service_closed, service_closed["service_case"]
    config = select_original_sources(tmp_path / "originals", b["history"])
    intake = publish_original_intake(config.intake, b)
    # The parent fixture produced terminal work and a seal for builder tests.
    # Start this isolated owner before that fence; the tested observer creates it.
    with c.queue.journal.transaction() as db:
        db.execute("DELETE FROM records WHERE kind='service_work_seal'")
    h = SimpleNamespace(
        b=b,
        c=c,
        intake=intake,
        block=b["closure"].observation.block,
        withheld=False,
        calls=[],
        fail=False,
        bad_proof=False,
        offline=False,
        sources=config,
    )
    with intake._connection() as (_, store):
        h.state, _ = store.status(digest(b["history"].plan))
    h.cohort = h.state.cohort_sha256
    h.duration = (
        next(t.target_block for t in h.state.targets if t.phase == "requests")
        - h.state.observed_at_block
    )
    assert h.duration > 0

    def external(key):
        if key not in b["objects"]:
            raise FileNotFoundError(key)
        return b["objects"][key]

    def reopen():
        return NativeRequestProgressSource(
            intake,
            RoundJournal(tmp_path / "completion", {"cohort": h.cohort}),
            roster=b["roster"],
            catalogs=(c.assignment.catalog,),
            queues=(c.queue,),
            transport=b["transport"],
            orders=lambda: b["orders"],
            terminals=lambda order, who: (
                None if h.withheld else b["terminals"].get((digest(order), identity(who)))
            ),
            objects=external,
            maximum_sample_gap_blocks=300,
        )

    h.reopen = reopen
    h.source = reopen()

    def sample(block=None, serving=True):
        if block is not None:
            h.block = block
        return h.source.observe(h.state, capture(h.block), serving=serving)

    def run_window():
        first = h.block
        sample()
        while h.block < first + h.duration:
            result = sample(min(h.block + 300, first + h.duration))
        return result

    h.sample, h.window = sample, run_window

    class Provider:
        policy = b["policy"]

        async def collect(self):
            if h.offline:
                raise OSError("RPC offline")
            return capture(h.block)

        async def review_archive(self, observation, raw, metadata):
            if h.bad_proof or (raw, metadata) != (b"proof", b"metadata"):
                raise ValueError("original proof invalid")
            snaps = [
                b["roster"].intake_seal.snapshot,
                *(read_participation(raw).snapshot for _, raw in b["records"]),
            ]
            snap = next(
                (s for s in snaps if s.block == observation.block),
                capture(observation.block).snapshot,
            )
            return SimpleNamespace(
                original=observation,
                snapshot=snap,
                replayed_at=SimpleNamespace(block_number=h.block),
            )

    async def archive(observation):
        return b"proof", b"metadata"

    def signer(name):
        reviewer = RequestProgressReviewer(h.source, Provider(), archive)
        monkeypatch.setattr(
            reviewer.queue,
            "evidence",
            lambda cohort, key: (dict(b["records"])[key], b"proof", b"metadata"),
        )
        cfg = CohortProgressSignerConfig(
            schema="umi-cohort-progress-signer-config/1",
            directory=str(tmp_path / "request-progress-signers" / name),
            policy_sha256=digest(b["policy"]),
            signer=wallet(name).hotkey.ss58_address,
            cohorts=intake.config.cohorts,
        )

        async def sign(body):
            if name == "Dave" and h.fail:
                raise OSError("peer offline")
            h.calls.append((name, digest(body)))
            return sign_object(body, wallet(name))

        return CohortProgressSigner(cfg, reviewer, sign)

    h.provider, h.signer = Provider(), signer
    return h


def test_automatic_request_owner_requires_standing_authority(service_closed, tmp_path, monkeypatch):
    if isinstance(service_closed["history"].authority.authority, StandingCohortRecoveryAuthority):
        pytest.skip("standing authority is exercised by the owner and controller tests")
    with pytest.raises(ValueError, match="requires standing cohort authority"):
        make_request_owner(service_closed, tmp_path, monkeypatch)


def test_request_observer_closes_native_queues_and_retains_originals(request_owner):
    h = request_owner
    assert h.c.queue.retained_seal() is None
    progress = h.window()
    assert progress.completion == "complete"
    original = h.source.read(progress)
    assert h.c.queue.retained_seal().accepted == h.b["service_seal"].accepted
    # The entire terminal read-set is now local; no external completion JSON
    # or successful fetch from the upstream evidence store is needed on replay.
    h.b["objects"].clear()
    h.source = h.reopen()
    assert h.source.read(progress) == original


def test_request_window_restores_offline_time_before_sealing(request_owner):
    h = request_owner
    h.sample()
    h.source = h.reopen()
    late = h.sample(h.block + 30000)
    assert late.completion == "pending"
    assert h.c.queue.retained_seal() is None
    assert late.unavailable_blocks >= 30000
    progress = h.window()
    assert progress.completion == "complete"
    assert h.source.read(progress).record.fence.observation.block == h.block


def test_request_sampler_retains_window_without_replaying_or_sealing(request_owner):
    h = request_owner
    first = h.sample()
    start = h.block
    orders = h.source.orders

    def no_replay():
        pytest.fail("readiness sampler must not enumerate execution or seal queues")

    h.source.orders = no_replay
    while h.block < start + h.duration:
        h.block = min(h.block + 300, start + h.duration)
        h.source.sample_service(h.state, capture(h.block), serving=True)
    assert h.c.queue.retained_seal() is None
    assert h.source.journal.get("request_window_fence", h.state.tip_sha256) is None
    h.source.orders = orders
    complete = h.sample()
    assert complete.completion == "complete"
    assert complete.unavailable_blocks == first.unavailable_blocks
    original = h.source.read(complete)
    assert h.source.sample_service(h.state, capture(h.block + 100000), serving=False) is None
    assert h.source.read(complete) == original


def test_request_sampler_rejects_another_phase_without_observing(request_owner):
    h = request_owner
    with pytest.raises(ValueError, match="active owned history"):
        h.source.sample_service(
            h.state.model_copy(update={"phase": "intake"}), capture(h.block), serving=True
        )
    with h.intake._connection() as (db, _):
        assert (
            db.execute(
                "SELECT 1 FROM sqlite_master WHERE name='cohort_service_observations'"
            ).fetchone()
            is None
        )


def test_missing_evaluator_remains_pending_after_window_and_long_outage(request_owner):
    h = request_owner
    h.withheld = True
    assert h.window().completion == "pending"
    seal = h.c.queue.retained_seal()
    assert seal is not None
    h.source = h.reopen()
    assert h.sample(h.block + 100000).completion == "pending"
    assert h.c.queue.retained_seal() == seal
    h.withheld = False
    result = h.sample(h.block + 1)
    assert result.completion == "complete"
    assert h.source.read(result).record.fence.observation.block == seal.observation.block


@pytest.mark.parametrize("damage", ["service", "original", "queue", "prefix", "progress", "proof"])
async def test_damaged_request_completion_cannot_be_signed(request_owner, damage):
    h = request_owner
    progress = h.window()
    if damage == "service":
        with h.intake._connection() as (db, _):
            db.execute(
                "DELETE FROM cohort_service_observations WHERE phase='requests' AND sequence=1"
            )
    elif damage == "original":
        with h.source.journal.transaction() as db:
            db.execute(
                "DELETE FROM records WHERE kind='endpoint_replay_object' AND id=?",
                (h.b["service_terminal"].terminal.response_sha256,),
            )
    elif damage == "queue":
        with h.c.queue.journal.transaction() as db:
            db.execute("DELETE FROM records WHERE kind='service_work_seal'")
    elif damage == "prefix":
        with h.c.queue.journal.transaction() as db:
            db.execute("DELETE FROM service_claims")
    elif damage == "progress":
        progress = progress.model_copy(update={"unavailable_blocks": 0})
    else:
        h.bad_proof = True
    messages = {
        "service": "incomplete or inconsistent",
        "original": "object is unavailable",
        "queue": "owner queue fence",
        "prefix": "owner's accepted prefix",
        "progress": "has not been retained",
        "proof": "original proof invalid",
    }
    with pytest.raises((OSError, ValueError), match=messages[damage]):
        await h.signer("Charlie").attest(progress)
    assert not h.calls


def test_request_observer_waits_for_service_terminal_without_repeating_work(request_owner):
    h = request_owner
    work = h.b["service_terminal"].terminal.work_sha256
    original = h.c.queue.journal.get("service_terminal", work)
    with h.c.queue.journal.transaction() as db:
        db.execute("DELETE FROM records WHERE kind='service_terminal' AND id=?", (work,))
    assert h.window().completion == "pending"
    h.source = h.reopen()
    assert h.sample(h.block + 100000).completion == "pending"
    h.c.queue.journal.put("service_terminal", work, original)
    progress = h.sample(h.block + 1)
    assert progress.completion == "complete"
    h.source.read(progress)
    assert h.c.queue.journal.get("service_terminal", work) == original


@pytest.mark.parametrize("stage", ["queue", "progress"])
def test_interrupted_request_closure_resumes_native_work(request_owner, monkeypatch, stage):
    h = request_owner
    owner = h.c.queue if stage == "queue" else h.source.journal
    method = "seal" if stage == "queue" else "put"
    original = getattr(owner, method)
    interrupted = False

    def fail(*args, **kwargs):
        nonlocal interrupted
        result = original(*args, **kwargs)
        if not interrupted and (
            stage == "queue"
            or (args[0] == "request_progress" and args[2].progress.completion == "complete")
        ):
            interrupted = True
            raise OSError("committed owner write lost its acknowledgement")
        return result

    monkeypatch.setattr(owner, method, fail)
    with pytest.raises(OSError, match="acknowledgement"):
        h.window()
    seal = h.c.queue.retained_seal()
    assert seal is not None
    h.source = h.reopen()
    recovered = h.sample(h.block + 100000)
    assert recovered.completion == "complete"
    assert h.c.queue.retained_seal() == seal
    assert h.source.read(recovered).record.fence.observation.block == seal.observation.block


@contextmanager
def request_controller(h, tmp_path, publication=None):
    db = sqlite3.connect(tmp_path / "controller.sqlite3")
    store = CohortRecoveryStore(db)
    history, policy = h.b["history"], h.b["policy"]
    store.admit(
        history.plan, history.authority, policy, admitted_at_block=history.genesis.admitted_at_block
    )
    for d in h.b["decisions"].values():
        store.retain_source(h.cohort, d)
    store.publish_history(history, policy, current_block=h.block)

    async def decision(cohort, key):
        from umi.competition_cohort_coordinator import CohortDecisionInput

        return store.source(cohort, key, CohortDecisionInput)

    publisher = (
        publication(decision)
        if publication
        else CohortIntakePublisher(h.intake, h.provider.collect, decision)
    )

    async def sample(state, observed):
        return await run_owned_thread(lambda: h.source.observe(state, observed, serving=True))

    def observer():
        return CertifiedPhaseObserver(
            sample, tuple(h.signer(n) for n in ("Charlie", "Dave")), policy
        )

    def controller():
        ports = observer()
        return CohortRecoveryCoordinator(
            store,
            h.cohort,
            policy,
            history.genesis_signatures,
            h.provider,
            None,
            ports.certify,
            publisher,
            sample_progress=ports.sample,
            attest_progress=ports.attest,
        )

    try:
        yield SimpleNamespace(
            reopen=controller,
            store=store,
            publisher=publisher,
            observer=observer,
            decision=decision,
        )
    finally:
        db.close()


async def test_request_controller_recovers_original_certificate_after_peer_outage(
    request_owner, tmp_path
):
    h = request_owner
    progress = h.window()
    with request_controller(h, tmp_path) as control:
        h.fail = True
        with pytest.raises(ValueError, match="evaluator quorum"):
            await control.reopen().tick()
        assert len(h.calls) == 1
        h.source = h.reopen()
        h.block += 100000
        h.fail = False
        await control.reopen().tick()
        state, _ = control.store.status(h.cohort)
        assert state.phase == "reference_reveal"
        assert state.observed_at_block == progress.observed_at_block
        assert len(h.calls) == 4
        assert len(set(h.calls)) == 4
        assert (
            h.intake.history(h.cohort).transitions[-1].transition.observed_at_block
            == progress.observed_at_block
        )


@pytest.mark.parametrize("failure", ["objects", "proof", "history_ack"])
async def test_request_publication_recovers_after_certification(
    request_owner, tmp_path, monkeypatch, failure
):
    from umi import competition_cohort_request_publication as module
    from umi.competition_cohort_order_signer import CohortOrderHistory
    from umi.private_files import read_private_model

    h = request_owner
    h.window()
    handoff = tmp_path / "handoff" / (h.cohort + ".json")
    failed, proofs = [], []

    async def proof(observation):
        if failure == "proof" and not failed:
            failed.append(True)
            raise OSError("proof delivery interrupted")
        proofs.append(observation)

    def publication(decisions):
        return module.CohortRequestSettlementPublisher(
            h.source,
            h.provider.collect,
            decisions,
            proof,
            sources=h.sources,
            history_directory=handoff.parent,
        )

    original_publish = module.publish_private_model

    def publish(*args, **kwargs):
        original_publish(*args, **kwargs)
        if failure == "history_ack" and not failed:
            failed.append(True)
            raise OSError("handoff acknowledgement lost")

    monkeypatch.setattr(module, "publish_private_model", publish)
    with request_controller(h, tmp_path, publication) as control:
        original_object = control.publisher.files.publish

        def object_publish(*args):
            original_object(*args)
            if failure == "objects" and not failed:
                failed.append(True)
                raise OSError("object publication interrupted")

        monkeypatch.setattr(control.publisher.files, "publish", object_publish)
        with pytest.raises(OSError, match=r"interrupted|acknowledgement lost"):
            await control.reopen().tick()
        assert control.store.status(h.cohort)[0].phase == "reference_reveal"
        assert handoff.exists() == (failure == "history_ack")
        calls = tuple(h.calls)
        h.block += 100000
        h.source = h.reopen()
        h.source.external = lambda _: pytest.fail("delivery must use retained originals")
        control.publisher.source = h.source
        await control.publisher(h.intake.history(h.cohort))
        first = handoff.read_bytes()
        await control.publisher(h.intake.history(h.cohort))
        assert handoff.read_bytes() == first
        assert tuple(h.calls) == calls
        delivered = read_private_model(handoff, CohortOrderHistory, maximum_bytes=8 * 1024**2)
        assert delivered.history == h.intake.history(h.cohort)
        assert set(map(digest, proofs)) == set(digest(d.observation) for d in delivered.decisions)
        exported = control.publisher._export(h.block)
        assert all(control.publisher.files(k) == raw for k, raw in exported.objects.items())


@pytest.mark.parametrize("failure", ["missing_seal", "revoked_during_delivery"])
async def test_request_publication_rechecks_native_authority_and_evidence(
    request_owner, tmp_path, failure
):
    from umi.competition_cohort_request_publication import CohortRequestSettlementPublisher

    from .test_competition_cohort_consumers import transition

    h = request_owner
    h.window()
    handoff = tmp_path / "handoff" / (h.cohort + ".json")
    interrupted = []

    async def proof(observation):
        if not interrupted:
            interrupted.append(True)
            raise OSError("delivery interrupted after certification")
        if failure == "revoked_during_delivery":
            current = h.intake.history(h.cohort)
            if current.transitions[-1].transition.operation != "revoke":
                with h.intake._connection() as (_, store):
                    revoked = transition(current, h.b["policy"], "revoke", h.block)
                    store.publish_history(revoked, h.b["policy"], current_block=h.block)

    def publication(decisions):
        return CohortRequestSettlementPublisher(
            h.source,
            h.provider.collect,
            decisions,
            proof,
            sources=h.sources,
            history_directory=handoff.parent,
        )

    with request_controller(h, tmp_path, publication) as control:
        with pytest.raises(OSError, match="delivery interrupted after certification"):
            await control.reopen().tick()
        current = h.intake.history(h.cohort)
        calls = tuple(h.calls)
        if failure == "missing_seal":
            with h.c.queue.journal.transaction() as db:
                db.execute("DELETE FROM records WHERE kind='service_work_seal'")
            expected = "owner queue fence"
        else:
            expected = "authority changed during delivery"
        with pytest.raises(ValueError, match=expected):
            await control.publisher(current)
        assert tuple(h.calls) == calls
        assert not handoff.exists()


@pytest.mark.parametrize("service_catalog_inputs", [True, "precommitted"], indirect=True)
async def test_configured_request_factory_replays_delivered_terminals_and_exports(
    request_owner, tmp_path
):
    from contextlib import AsyncExitStack
    from pathlib import Path

    import httpx

    from umi.competition_cohort_admission_queue import CohortAdmissionQueue
    from umi.competition_cohort_lifecycle_host import LifecycleHost
    from umi.competition_cohort_preparation import PreparedCohortRound
    from umi.competition_cohort_request_export import (
        RequestReviewRequest,
        SignedRequestReviewResponse,
    )
    from umi.competition_cohort_request_readiness import RequestReadiness
    from umi.competition_cohort_service_host import ServiceAdmissionHost
    from umi.competition_cohort_settlement_delivery import SettlementEvidenceFiles
    from umi.competition_execution import execution_boundary
    from umi.competition_reward_decisions import StandingRewardSeries
    from umi.competition_reward_manifest import StandingRewardManifest
    from umi.competition_settlement import PromotionHeadBinding
    from umi.competition_store import CompetitionStore
    from umi.grandpa_finality import FINNEY_GENESIS_HASH
    from umi.policy import scoring_policy_hash
    from umi.private_files import publish_private_model
    from umi.protocol import canonical_json_bytes

    from .test_competition_cohort_lifecycle_host import configured

    h, b = request_owner, request_owner.b
    catalog = h.c.assignment.catalog
    manifest = StandingRewardManifest(
        schema="umi-standing-reward-manifest/1",
        policy_sha256=digest(b["policy"]),
        cohorts=(
            {
                "cohort_sha256": h.cohort,
                "terms_sha256": digest(h.c.terms),
                "catalog_sha256s": (digest(catalog.catalog),),
            },
        ),
    )
    series = StandingRewardSeries(
        schema="umi-standing-reward-series/1",
        genesis_hash=FINNEY_GENESIS_HASH,
        netuid=78,
        policy_sha256=digest(b["policy"]),
        policy_epoch=1,
        manifest_sha256=digest(manifest),
        control_hotkey=wallet("Ferdie").hotkey.ss58_address,
        recovery=b["history"].authority,
        cohorts=(b["history"].plan,),
        validators=(wallet("Charlie").hotkey.ss58_address,),
        maximum_proof_lag_blocks=2,
        maximum_transaction_lifetime_blocks=128,
        lifetime="until_superseded_or_revoked",
    )
    h.precommitted = catalog, manifest, series
    c = configured(h, tmp_path / "configured")
    c = c.model_copy(
        update={
            "admission_owner": c.admission_owner.model_copy(
                update={"maximum_sample_gap_blocks": 300}
            )
        }
    )
    h.provider.config = SimpleNamespace(maximum_head_age_ms=120000, maximum_future_skew_ms=30000)
    h.provider.ensure_observer_running = lambda: None

    async def archive(_):
        return b"proof", b"metadata"

    async def sign(body):
        return sign_object(body, wallet("Charlie"))

    # The earlier preparation and inference are retained fixture originals.
    # The tested factory reads their real publication formats and owned queue.
    h.provider.retained_archive = archive
    promotion = CompetitionStore(tmp_path / "promotion", b["policy"])
    service = ServiceAdmissionHost(
        c, h.intake, promotion, h.provider.collect, archive, provider=h.provider
    )
    service.queues[digest(catalog.catalog)] = h.c.queue
    originals = c.lifecycle.sources
    prepared = PreparedCohortRound(
        schema="umi-prepared-cohort-round/1",
        roster=b["roster"],
        promotion_head=PromotionHeadBinding(
            sequence=0,
            promotion_sha256="a1" * 32,
            model_sha256=b["roster"].round.incumbent_model_sha256,
            contributor_hotkey=None,
        ),
        observation=execution_boundary(capture(b["roster"].round.prepared_at_block)),
    )
    publish_private_model(Path(originals.round_directory) / (h.cohort + ".json"), prepared)
    publish_private_model(
        Path(originals.transport_directory) / (scoring_policy_hash(b["transport"]) + ".json"),
        b["transport"],
    )
    SettlementEvidenceFiles(Path(originals.objects_directory)).publish(
        digest(h.c.terms), lambda _: canonical_json_bytes(h.c.terms)
    )
    service.history = lambda cohort: run_owned_thread(
        CohortAdmissionQueue(h.intake).history, cohort
    )
    serving = False

    async def ready(request):
        value = RequestReadiness(
            schema="umi-cohort-request-readiness/1",
            nonce=request.url.params["nonce"],
            policy_sha256=digest(b["policy"]),
            cohort_sha256=h.cohort,
            recovery_tip_sha256=h.state.tip_sha256,
            catalog_sha256s=(digest(catalog.catalog),),
            observation=execution_boundary(capture(h.block)),
            ready=serving,
        )
        return httpx.Response(200, json=value.model_dump(mode="json", by_alias=True))

    async with AsyncExitStack() as resources:
        client = await resources.enter_async_context(
            httpx.AsyncClient(transport=httpx.MockTransport(ready))
        )
        host = LifecycleHost(service, resources, client, ("v" * 32, "v" * 32), sign)
        for terminal in b["terminals"].values():
            host.files.publish(
                terminal,
                b["objects"].__getitem__,
                b["policy"],
                opened_at_block=h.state.observed_at_block,
                completed_by_block=h.block,
            )
        driver = await host._requests(h.cohort)
        unavailable = await driver.sample_service(h.state, capture(h.block))
        assert not unavailable.serving
        assert h.c.queue.retained_seal() is None
        serving = True
        h.source = host.requests[h.cohort]
        progress = h.window()
        assert progress.completion == "complete"
        response = SignedRequestReviewResponse.model_validate_json(
            await host.respond(
                RequestReviewRequest(
                    schema="umi-request-review-request/1",
                    challenge="ab" * 32,
                    progress=progress,
                )
            )
        )
        assert response.response.evidence.record.progress == progress
        calls = tuple(h.calls)
        h.source.external = lambda _: pytest.fail("completed review must retain its own originals")
        assert h.source.read(progress).record.progress == progress
        assert tuple(h.calls) == calls
