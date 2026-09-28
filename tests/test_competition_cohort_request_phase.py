"""Native request closure/controller recovery; synthetic finality and inference."""

import sqlite3
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


async def test_request_controller_recovers_original_certificate_after_peer_outage(
    request_owner, tmp_path
):
    h = request_owner
    progress = h.window()
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

    publisher = CohortIntakePublisher(h.intake, h.provider.collect, decision)

    async def sample(state, observed):
        return await run_owned_thread(lambda: h.source.observe(state, observed, serving=True))

    def controller():
        ports = CertifiedPhaseObserver(
            sample, tuple(h.signer(n) for n in ("Charlie", "Dave")), policy
        )
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

    h.fail = True
    with pytest.raises(ValueError, match="evaluator quorum"):
        await controller().tick()
    assert len(h.calls) == 1
    h.source = h.reopen()
    h.block += 100000
    h.fail = False
    await controller().tick()
    state, _ = store.status(h.cohort)
    assert state.phase == "reference_reveal"
    assert state.observed_at_block == progress.observed_at_block
    assert len(h.calls) == 4
    assert len(set(h.calls)) == 4
    assert (
        h.intake.history(h.cohort).transitions[-1].transition.observed_at_block
        == progress.observed_at_block
    )
    db.close()
