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


@pytest.mark.parametrize("receipt_scenario", ["standing"], indirect=True)
def test_stale_service_head_rejects_before_native_terminal_replay(request_owner, monkeypatch):
    """Reproduce a capture becoming stale before the service inventory lease."""
    from unittest.mock import Mock

    from umi import competition_cohort_request_phase as phase
    from umi.competition_round_journal import FinalizedHeadRegression

    h = request_owner
    first = h.block
    h.sample()
    before_close = first + h.duration - 1
    while h.block < before_close:
        assert h.sample(min(h.block + 300, before_close)).completion == "pending"
    stale_block = h.block + 1
    advanced_block = stale_block + 1
    h.c.queue.journal.observe(advanced_block)
    replay = Mock(wraps=phase.select_request_tail)
    monkeypatch.setattr(phase, "select_request_tail", replay)
    with pytest.raises(FinalizedHeadRegression) as raised:
        h.sample(stale_block)
    names = []
    trace = raised.value.__traceback__
    while trace is not None:
        names.append(trace.tb_frame.f_code.co_name)
        trace = trace.tb_next
    assert replay.call_count == 0
    assert "closure_inventory" in names and "seal_locked" not in names
    assert h.c.queue.retained_seal() is None
    with h.c.queue.journal.read_transaction() as db:
        assert db.execute("SELECT block FROM highwater").fetchall() == [(advanced_block,)]
    progress = h.sample(advanced_block)
    assert progress.completion == "complete"
    assert h.c.queue.retained_seal().accepted == h.b["service_seal"].accepted


@pytest.mark.asyncio
@pytest.mark.parametrize("receipt_scenario", ["standing"], indirect=True)
@pytest.mark.parametrize("fence_kind", ["ordinary", "tail"])
async def test_retained_fence_seals_before_delayed_readiness_and_replay(
    request_owner, monkeypatch, fence_kind
):
    from umi import competition_cohort_request_phase as phase
    from umi.competition_cohort_order_signer import CohortOrderHistory
    from umi.competition_cohort_request_readiness import LiveRequestPhaseObserver
    from umi.competition_cohort_request_tail import MINIMUM_REQUEST_OPEN_MS
    from umi.competition_cohort_service_api import ServiceWorkAdmissionAPI
    from umi.competition_historical_registration import HistoricalRegistration
    from umi.competition_round_journal import FinalizedHeadRegression
    from umi.protocol import canonical_json_bytes

    h = request_owner
    opened = HistoricalRegistration(
        None, h.source.request_opening(h.state), SimpleNamespace(block_number=h.block), 1000
    )

    def observed():
        value = capture(h.block)
        value.provenance["timestamp_ms"] = 1000 + MINIMUM_REQUEST_OPEN_MS
        return value

    native_seal = h.c.queue.seal_locked

    def interrupt_seal(*args, **kwargs):
        raise OSError("interrupted before native sealing")

    # Preparation cannot invent a cutoff or close admissions before selection.
    h.source.seal_fenced(h.state, observed())
    assert h.c.queue.retained_seal() is None
    monkeypatch.setattr(h.c.queue, "seal_locked", interrupt_seal)
    with pytest.raises(OSError, match="before native sealing"):
        if fence_kind == "ordinary":
            h.window()
        else:
            h.source.observe(h.state, observed(), serving=False, opened=opened)
    kind = "request_window_fence" if fence_kind == "ordinary" else "request_tail_fence"
    original_fence = h.source.journal.get(kind, h.state.tip_sha256)
    assert original_fence is not None and h.c.queue.retained_seal() is None
    monkeypatch.setattr(h.c.queue, "seal_locked", native_seal)

    # A malformed retained fence is not authority to create an immutable seal.
    with h.source.journal.transaction() as db:
        db.execute("UPDATE records SET body=? WHERE kind=?", (b"{}", kind))
    with pytest.raises(ValueError):
        h.source.seal_fenced(h.state, observed())
    assert h.c.queue.retained_seal() is None
    with h.source.journal.transaction() as db:
        db.execute(
            "UPDATE records SET body=? WHERE kind=?", (canonical_json_bytes(original_fence), kind)
        )

    h.source = h.reopen()
    h.block += 1
    current = observed()
    # The preparation path keeps the original monotonic refusal for stale input.
    h.c.queue.journal.observe(h.block)
    with pytest.raises(FinalizedHeadRegression):
        h.source.seal_fenced(h.state, capture(h.block - 1))
    assert h.c.queue.retained_seal() is None
    stages = []
    select = phase.select_request_tail

    def replay(**kwargs):
        result = select(**kwargs)
        stages.append("replay")
        h.c.queue.journal.observe(h.block + 2)
        return result

    monkeypatch.setattr(phase, "select_request_tail", replay)

    with h.intake._connection() as (_, store):
        history, decisions, _, _, _ = h.source._state(store, h.state)
    current_history = CohortOrderHistory(history=history, decisions=decisions)

    async def ready(state, supplied):
        assert state == h.state and supplied is current
        stages.append("readiness")
        # The actual admission API writer owns the compound lease and can
        # advance while readiness awaits network. The coordinator's original
        # capture remains unchanged through the complete native observation.
        await run_owned_thread(
            ServiceWorkAdmissionAPI._remember,
            h.c.queue,
            current_history,
            capture(h.block + 1),
        )
        return fence_kind == "ordinary"

    async def clock(state):
        assert state == h.state
        stages.append("opening_clock")
        return opened if fence_kind == "tail" else None

    live = LiveRequestPhaseObserver(
        h.source, "https://owner.example", client=None, opening_clock=clock
    )
    monkeypatch.setattr(live, "_ready", ready)
    progress = await live(h.state, current)
    assert stages == ["readiness", "opening_clock", "replay"]
    assert progress.completion == "complete"
    assert progress.observed_at_block == current.snapshot.block
    seal = h.c.queue.retained_seal()
    assert seal.observation.block == h.block
    assert seal.accepted == h.b["service_seal"].accepted
    assert h.source.journal.get(kind, h.state.tip_sha256) == original_fence
    with h.c.queue.journal.read_transaction() as db:
        assert db.execute("SELECT block FROM highwater").fetchall() == [(h.block + 2,)]
    native = h.source.read(progress)
    h.source = h.reopen()
    assert h.source.read(progress) == native


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
    method = "seal_locked" if stage == "queue" else "put"
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
    assert interrupted
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


@pytest.mark.asyncio
@pytest.mark.parametrize("receipt_scenario", ["standing"], indirect=True)
@pytest.mark.parametrize("mode", ["legacy", "prepared", "unfinished"])
async def test_first_fence_delayed_readiness_native_regression(request_owner, monkeypatch, mode):
    import httpx

    from umi.competition_cohort_order_signer import CohortOrderHistory
    from umi.competition_cohort_request_readiness import LiveRequestPhaseObserver, RequestReadiness
    from umi.competition_cohort_request_tail import MINIMUM_REQUEST_OPEN_MS
    from umi.competition_cohort_service_api import ServiceWorkAdmissionAPI
    from umi.competition_execution import execution_boundary
    from umi.competition_historical_registration import HistoricalRegistration
    from umi.competition_round_journal import FinalizedHeadRegression

    h = request_owner
    h.withheld = mode == "unfinished"
    opened = HistoricalRegistration(
        None, h.source.request_opening(h.state), SimpleNamespace(block_number=h.block), 1000
    )
    with h.intake._connection() as (_, store):
        history, decisions, _, _, _ = h.source._state(store, h.state)
    current_history = CohortOrderHistory(history=history, decisions=decisions)

    def observed():
        value = capture(h.block)
        value.provenance["timestamp_ms"] = 1000 + MINIMUM_REQUEST_OPEN_MS
        return value

    async def ready(request):
        h.block += 1
        await run_owned_thread(
            ServiceWorkAdmissionAPI._remember, h.c.queue, current_history, observed()
        )
        result = RequestReadiness(
            schema="umi-cohort-request-readiness/1",
            nonce=request.url.params["nonce"],
            policy_sha256=digest(h.b["policy"]),
            cohort_sha256=h.cohort,
            recovery_tip_sha256=h.state.tip_sha256,
            catalog_sha256s=tuple(digest(c.catalog) for c in h.source.catalogs),
            observation=execution_boundary(observed()),
            ready=True,
        )
        return httpx.Response(200, json=result.model_dump(mode="json", by_alias=True))

    async def clock(state):
        assert state == h.state
        h.block += 1
        await run_owned_thread(
            ServiceWorkAdmissionAPI._remember, h.c.queue, current_history, observed()
        )
        return opened

    assert h.c.queue.retained_seal() is None
    assert h.source.journal.get("request_tail_fence", h.state.tip_sha256) is None
    old = observed()
    async with httpx.AsyncClient(transport=httpx.MockTransport(ready)) as client:
        live = LiveRequestPhaseObserver(
            h.source, "https://owner.example", client=client, opening_clock=clock
        )
        if mode == "legacy":
            with pytest.raises(FinalizedHeadRegression):
                await live(h.state, old)
            assert h.c.queue.retained_seal() is None
            assert h.source.journal.get("request_tail_fence", h.state.tip_sha256) is None
            assert old.snapshot.block == h.block - 2
            return

        from umi.private_files import PrivateStateBusyError

        native_state = h.source._state
        orders = h.source.orders
        calls = []

        def replay_state(store, state):
            # History authenticates after capture with admissions already
            # owned; a competing writer cannot age the captured highwater.
            result = native_state(store, state)
            with pytest.raises(PrivateStateBusyError):
                ServiceWorkAdmissionAPI._remember(h.c.queue, current_history, capture(h.block + 1))
            calls.append("state_replay")
            return result

        def replay_orders():
            # Once preparation owns admissions, expensive replay cannot age its
            # capture through a legitimate competing compound admission writer.
            with pytest.raises(PrivateStateBusyError):
                ServiceWorkAdmissionAPI._remember(h.c.queue, current_history, capture(h.block + 1))
            calls.append("orders_replay")
            return orders()

        monkeypatch.setattr(h.source, "_state", replay_state)
        monkeypatch.setattr(h.source, "orders", replay_orders)
        async with live.prepare(h.state) as sample:
            current = observed()
            with pytest.raises(PrivateStateBusyError):
                await run_owned_thread(
                    ServiceWorkAdmissionAPI._remember,
                    h.c.queue,
                    current_history,
                    capture(h.block + 1),
                )
            progress = await sample(current)
            with pytest.raises(RuntimeError, match="no longer available"):
                await sample(current)
        monkeypatch.setattr(h.source, "_state", native_state)
        monkeypatch.setattr(h.source, "orders", orders)
        assert calls == ["state_replay", "orders_replay"]
        assert progress.observed_at_block == current.snapshot.block == h.block
        assert old.snapshot.block == h.block - 2
        assert h.source.request_opening(h.state) == opened.original
        if mode == "unfinished":
            assert progress.completion == "pending"
            assert h.c.queue.retained_seal() is None
            assert h.source.journal.get("request_tail_fence", h.state.tip_sha256) is None
        else:
            assert progress.completion == "complete"
            seal = h.c.queue.retained_seal()
            assert seal.observation == execution_boundary(current)
            assert seal.accepted == h.b["service_seal"].accepted
            record = h.source.read(progress)
            h.source = h.reopen()
            assert h.source.read(progress) == record
        # Success and pending both release the original native lease.
        ServiceWorkAdmissionAPI._remember(h.c.queue, current_history, capture(h.block + 1))


@pytest.mark.asyncio
@pytest.mark.parametrize("receipt_scenario", ["standing"], indirect=True)
@pytest.mark.parametrize("failure", ["capture", "cancel", "tail_seal", "ordinary_seal"])
async def test_prepared_native_cleanup_and_retained_fence_restart(
    request_owner, monkeypatch, failure
):
    import asyncio

    from umi.competition_cohort_request_readiness import LiveRequestPhaseObserver
    from umi.competition_cohort_request_tail import MINIMUM_REQUEST_OPEN_MS
    from umi.competition_historical_registration import HistoricalRegistration
    from umi.private_files import PrivateStateBusyError

    h = request_owner
    opened = HistoricalRegistration(
        None, h.source.request_opening(h.state), SimpleNamespace(block_number=h.block), 1000
    )

    def observed():
        value = capture(h.block)
        value.provenance["timestamp_ms"] = 1000 + MINIMUM_REQUEST_OPEN_MS
        return value

    async def readiness(state):
        assert state == h.state
        return "0" * 32, None

    async def clock(state):
        assert state == h.state
        return None if failure == "ordinary_seal" else opened

    def live_source():
        live = LiveRequestPhaseObserver(
            h.source, "https://owner.example", client=None, opening_clock=clock
        )
        monkeypatch.setattr(live, "_fetch_readiness", readiness)
        return live

    live = live_source()
    if failure == "capture":
        with pytest.raises(OSError, match="capture interrupted"):
            async with live.prepare(h.state):
                raise OSError("capture interrupted")
    elif failure == "cancel":
        prepared = asyncio.Event()

        async def cancelled_capture():
            async with live.prepare(h.state):
                prepared.set()
                await asyncio.Event().wait()

        task = asyncio.create_task(cancelled_capture())
        await asyncio.wait_for(prepared.wait(), 30)
        with pytest.raises(PrivateStateBusyError), h.c.queue.journal.locked():
            pass
        task.cancel()
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 30)
    else:
        original = h.c.queue.seal_locked

        def interrupted(*args, **kwargs):
            raise OSError("seal interrupted")

        monkeypatch.setattr(h.c.queue, "seal_locked", interrupted)
        with pytest.raises(OSError, match="seal interrupted"):
            if failure == "ordinary_seal":
                h.window()
            else:
                async with live.prepare(h.state) as sample:
                    await sample(observed())
        monkeypatch.setattr(h.c.queue, "seal_locked", original)

    assert h.c.queue.retained_seal() is None
    with h.c.queue.journal.locked():
        pass
    with h.intake._connection() as (_, store):
        assert store.status(h.cohort)[0] == h.state
    before = h.source.journal.get(
        "request_window_fence" if failure == "ordinary_seal" else "request_tail_fence",
        h.state.tip_sha256,
    )
    assert (before is not None) is failure.endswith("seal")
    h.source = h.reopen()
    h.block += 1
    async with live_source().prepare(h.state) as sample:
        progress = await sample(observed())
    assert h.c.queue.retained_seal() is not None
    if failure == "ordinary_seal":
        # A retained ordinary fence is sealed even when dispatch is unavailable
        # and no original clock was supplied for a new tail decision.
        assert progress.completion == "pending"
        assert h.source.journal.get("request_window_fence", h.state.tip_sha256) == before
    else:
        assert progress.completion == "complete"
        if before is not None:
            assert h.source.journal.get("request_tail_fence", h.state.tip_sha256) == before
        retained = h.source.read(progress)
        h.source = h.reopen()
        assert h.source.read(progress) == retained


@pytest.mark.asyncio
@pytest.mark.parametrize("receipt_scenario", ["standing"], indirect=True)
@pytest.mark.parametrize("fence_kind", [None, "ordinary", "tail"])
async def test_failed_opening_proof_still_finishes_only_retained_native_fence(
    request_owner, monkeypatch, fence_kind
):
    from umi.competition_cohort_request_readiness import LiveRequestPhaseObserver
    from umi.competition_cohort_request_tail import MINIMUM_REQUEST_OPEN_MS
    from umi.competition_historical_registration import HistoricalRegistration

    h = request_owner
    opened = HistoricalRegistration(
        None, h.source.request_opening(h.state), SimpleNamespace(block_number=h.block), 1000
    )

    def observed():
        value = capture(h.block)
        value.provenance["timestamp_ms"] = 1000 + MINIMUM_REQUEST_OPEN_MS
        return value

    original_seal = h.c.queue.seal_locked

    def interrupted(*args, **kwargs):
        raise OSError("seal interrupted before clock failure")

    if fence_kind is not None:
        monkeypatch.setattr(h.c.queue, "seal_locked", interrupted)
        with pytest.raises(OSError, match="seal interrupted"):
            if fence_kind == "ordinary":
                h.window()
            else:
                h.source.observe(h.state, observed(), serving=False, opened=opened)
        monkeypatch.setattr(h.c.queue, "seal_locked", original_seal)
    kind = "request_window_fence" if fence_kind == "ordinary" else "request_tail_fence"
    retained = h.source.journal.get(kind, h.state.tip_sha256)
    assert (retained is not None) is (fence_kind is not None)
    assert h.c.queue.retained_seal() is None
    with h.source.journal.read_transaction() as db:
        progress_before = db.execute(
            "SELECT id, body FROM records WHERE kind='request_progress' ORDER BY id"
        ).fetchall()
    clock_error = OSError("original opening proof is temporarily unavailable")

    async def clock(state):
        assert state == h.state
        raise clock_error

    async def readiness(state):
        assert state == h.state
        return "0" * 32, None

    live = LiveRequestPhaseObserver(
        h.source, "https://owner.example", client=None, opening_clock=clock
    )
    monkeypatch.setattr(live, "_fetch_readiness", readiness)
    h.block += 1
    current = observed()
    with pytest.raises(OSError) as caught:
        async with live.prepare(h.state) as sample:
            await sample(current)
    assert caught.value is clock_error
    assert h.source.journal.get(kind, h.state.tip_sha256) == retained
    seal = h.c.queue.retained_seal()
    assert (seal is not None) is (fence_kind is not None)
    if seal is not None:
        assert seal.observation.block == current.snapshot.block
        assert seal.accepted == h.b["service_seal"].accepted
    with h.source.journal.read_transaction() as db:
        assert (
            db.execute(
                "SELECT id, body FROM records WHERE kind='request_progress' ORDER BY id"
            ).fetchall()
            == progress_before
        )
    with h.c.queue.journal.locked():
        pass
    with h.intake._connection() as (_, store):
        assert store.status(h.cohort)[0] == h.state
    assert h.source.request_opening(h.state) == opened.original


@pytest.mark.asyncio
@pytest.mark.parametrize("receipt_scenario", ["standing"], indirect=True)
async def test_prepared_capture_persists_fresh_proof_with_native_retention(
    request_owner, chain_config, tmp_path, monkeypatch
):
    import asyncio
    import sqlite3
    import threading
    from dataclasses import replace

    from umi.chain_evidence import FinalizedSnapshotRef
    from umi.competition_chain import FinalizedRegistrationProvider
    from umi.competition_cohort_request_preparation import prepared_request_thread
    from umi.competition_cohort_service_host import _SharedFreshFinality
    from umi.competition_finality_cache import VerifiedRegistrationCache
    from umi.validator_chain import FinalizedProofCollector

    from .test_competition_chain import _Finality, _Rpc, _Runtime, _Verifier

    h = request_owner
    config = chain_config.model_copy(
        update={
            "state_directory": str(tmp_path / "prepared-finality"),
            "policy_sha256": digest(h.b["policy"]),
        }
    )
    # Only the chain/proof ports are synthetic. The provider, cold shared
    # cache, owned persistence thread and both retention readers are native.
    monkeypatch.setattr("umi.validator_chain.bittensor_core.Runtime", _Runtime)
    finality = _Finality(config, h.b["policy"])
    first = capture(h.block)
    finality.ref = FinalizedSnapshotRef(
        block_number=h.block,
        block_hash=first.snapshot.block_hash,
        parent_hash="0x" + "01" * 32,
        state_root=first.provenance["state_root"],
    )
    rpc = _Rpc(finality)
    proofs = FinalizedProofCollector(
        rpc, finality=finality, verifier=_Verifier(finality, rpc.values)
    )
    calls = []

    def retained_registration_blocks():
        calls.append(threading.get_ident())
        return h.intake.retained_registration_blocks() | h.c.queue.retained_registration_blocks()

    retained = retained_registration_blocks()
    assert retained
    calls.clear()
    provider = FinalizedRegistrationProvider(
        config,
        h.b["policy"],
        finality=finality,
        proofs=proofs,
        now_ms=lambda: finality.timestamp + 1000,
        retained_capture_blocks=retained_registration_blocks,
    )
    cache = VerifiedRegistrationCache(
        provider,
        h.b["policy"],
        maximum_cache_age_seconds=300,
        maximum_head_age_ms=config.maximum_head_age_ms,
        maximum_future_skew_ms=config.maximum_future_skew_ms,
        public_wait_seconds=1,
        background_collection_timeout_seconds=config.collection_timeout_seconds,
        wall_clock_ms=lambda: finality.timestamp + 1000,
    )
    shared = _SharedFreshFinality(provider, cache.collect_for_cohort_recovery, h.b["policy"])
    try:
        for index in range(2):
            if index:
                finality.ref = replace(
                    finality.ref, block_number=h.block + 1, block_hash="0x" + "dd" * 32
                )
            pending = None
            completed_inside_preparation = False
            try:
                async with prepared_request_thread(h.source.prepare(h.state)) as sample:
                    pending = asyncio.create_task(shared.collect())
                    completed, _ = await asyncio.wait((pending,), timeout=30)
                    completed_inside_preparation = pending in completed
                    if completed_inside_preparation:
                        current = pending.result()
                        progress = await sample(current, serving=False)
                        assert progress.completion == "pending"
            finally:
                # Release preparation before draining a failed regression, so
                # the historical intake-lock cycle cannot orphan its worker.
                if pending is not None:
                    await asyncio.wait_for(pending, 30)
            assert completed_inside_preparation, "fresh persistence waited for intake preparation"
            assert current.snapshot.block == h.block + index
            assert len(calls) == index + 1
            assert all(worker != threading.get_ident() for worker in calls)
        with sqlite3.connect(provider._path) as db:
            assert db.execute("SELECT block FROM captures ORDER BY block").fetchall() == [
                (h.block,),
                (h.block + 1,),
            ]
            assert db.execute("SELECT block FROM observed_head").fetchone() == (h.block + 1,)
    finally:
        await cache.aclose()
        await provider.aclose()
    assert h.c.queue.retained_seal() is None
    with h.c.queue.journal.locked():
        pass
    assert retained_registration_blocks() == retained


@pytest.mark.asyncio
@pytest.mark.parametrize("receipt_scenario", ["standing"], indirect=True)
@pytest.mark.parametrize("fence_kind", ["ordinary", "tail", "unacknowledged_tail"])
@pytest.mark.parametrize("suspended", ["readiness", "opening"])
async def test_retained_native_fence_seals_before_suspended_preparation_probe(
    request_owner, monkeypatch, fence_kind, suspended
):
    import asyncio

    from umi.competition_cohort_request_readiness import LiveRequestPhaseObserver
    from umi.competition_cohort_request_tail import MINIMUM_REQUEST_OPEN_MS
    from umi.competition_historical_registration import HistoricalRegistration

    h = request_owner
    opened = HistoricalRegistration(
        None, h.source.request_opening(h.state), SimpleNamespace(block_number=h.block), 1000
    )

    def observed():
        value = capture(h.block)
        value.provenance["timestamp_ms"] = 1000 + MINIMUM_REQUEST_OPEN_MS
        return value

    original_seal = h.c.queue.seal_locked

    def interrupted(*args, **kwargs):
        raise OSError("fence retained before seal")

    monkeypatch.setattr(h.c.queue, "seal_locked", interrupted)
    with pytest.raises(OSError, match="fence retained"):
        if fence_kind == "ordinary":
            h.window()
        else:
            h.source.observe(h.state, observed(), serving=False, opened=opened)
    monkeypatch.setattr(h.c.queue, "seal_locked", original_seal)
    kind = "request_window_fence" if fence_kind == "ordinary" else "request_tail_fence"
    retained = h.source.journal.get(kind, h.state.tip_sha256)
    assert retained is not None and h.c.queue.retained_seal() is None
    if fence_kind == "unacknowledged_tail":
        with h.source.journal.transaction() as db:
            db.execute("DELETE FROM records WHERE kind=? AND id=?", (kind, h.state.tip_sha256))
        assert h.source.journal.get(kind, h.state.tip_sha256) is None
    assert h.source.has_fence_hint(h.state)
    with h.source.journal.read_transaction() as db:
        before = db.execute(
            "SELECT id,body FROM records WHERE kind='request_progress' ORDER BY id"
        ).fetchall()
    blocked, release = asyncio.Event(), asyncio.Event()
    probes, captures, samplers = [], [], []
    h.block += 1
    current = observed()

    async def pause(stage):
        probes.append(stage)
        if stage == suspended:
            blocked.set()
            await release.wait()

    async def readiness(state):
        assert state == h.state
        await pause("readiness")
        return "0" * 32, None

    async def clock(state):
        assert state == h.state
        await pause("opening")
        return None

    live = LiveRequestPhaseObserver(
        h.source, "https://owner.example", client=None, opening_clock=clock
    )
    monkeypatch.setattr(live, "_fetch_readiness", readiness)

    async def work():
        async with live.prepare(h.state) as sample:
            # This is the coordinator's sole capture point. No network probe
            # has started; native fence authentication runs on this capture.
            assert probes == []
            captures.append(current)
            samplers.append(sample)
            return await sample(current)

    task = asyncio.create_task(work())
    try:
        await asyncio.wait_for(blocked.wait(), 60)
        assert not task.done() and captures == [current]
        seal = h.c.queue.retained_seal()
        assert seal is not None and seal.observation.block == current.snapshot.block
        assert seal.accepted == h.b["service_seal"].accepted
        assert h.source.journal.get(kind, h.state.tip_sha256) == retained
        with h.source.journal.read_transaction() as db:
            assert (
                db.execute(
                    "SELECT id,body FROM records WHERE kind='request_progress' ORDER BY id"
                ).fetchall()
                == before
            )
        with pytest.raises(RuntimeError, match="no longer available"):
            await samplers[0](current)
        # The early native seal released both resources before the probe waits.
        with h.c.queue.journal.locked():
            pass
        with h.intake._connection() as (_, store):
            assert store.status(h.cohort)[0] == h.state
        release.set()
        progress = await asyncio.wait_for(task, 60)
        assert progress.completion == "pending"
        assert h.c.queue.retained_seal() == seal
        assert captures == [current]
        assert h.source.request_opening(h.state) == opened.original
        with pytest.raises(RuntimeError, match="no longer available"):
            await samplers[0](current)
    finally:
        release.set()
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("receipt_scenario", ["standing"], indirect=True)
@pytest.mark.parametrize("kind", ["request_window_fence", "request_tail_fence"])
async def test_fence_presence_hint_cannot_authorize_invalid_native_fence(
    request_owner, monkeypatch, kind
):
    from umi.competition_cohort_request_readiness import LiveRequestPhaseObserver

    h = request_owner
    h.source.journal.put(kind, h.state.tip_sha256, {"unverified": True})
    assert h.source.has_fence_hint(h.state)

    async def probe(state):
        pytest.fail("invalid native fence must fail before network probes")

    live = LiveRequestPhaseObserver(
        h.source, "https://owner.example", client=None, opening_clock=probe
    )
    monkeypatch.setattr(live, "_fetch_readiness", probe)
    with pytest.raises((ValueError, FileNotFoundError)):
        async with live.prepare(h.state) as sample:
            await sample(capture(h.block))
    assert h.c.queue.retained_seal() is None
    with h.c.queue.journal.locked():
        pass
    with h.intake._connection() as (_, store):
        assert store.status(h.cohort)[0] == h.state
