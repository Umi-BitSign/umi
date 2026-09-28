"""Native intake/controller/journals with synthetic finality and signing faults."""

from __future__ import annotations

import asyncio
import sqlite3
from types import SimpleNamespace

import httpx
import pytest

from umi.competition_cohort_coordinator import (
    CohortDecisionInput,
    CohortProgressIntent,
    CohortRecoveryCoordinator,
    _choice,
    replay_cohort_decisions,
)
from umi.competition_cohort_intake import CohortIntakePublisher, history_tip
from umi.competition_cohort_intake_phase import CohortIntakePhaseObserver
from umi.competition_cohort_intake_review import IntakeProgressReviewer, NativeIntakeProgressSource
from umi.competition_cohort_progress_signer import (
    CertifiedIntakeObserver,
    CohortProgressSigner,
    CohortProgressSignerConfig,
)
from umi.competition_cohort_readiness import LiveIntakePhaseObserver, intake_readiness
from umi.competition_cohort_recovery_store import CohortRecoveryStore
from umi.competition_execution import execution_boundary
from umi.open_competition import digest, sign_object
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_consumers import scenario as scenario
from .test_competition_cohort_intake import capture_at
from .test_competition_cohort_intake import intake as intake
from .test_competition_cohort_intake_phase import healthy, observe
from .test_competition_cohort_intake_phase import phase as phase
from .test_competition_cohort_recovery import recovery as recovery
from .test_open_competition import policy as policy
from .test_open_competition import wallet


@pytest.fixture
def harness(phase, scenario, tmp_path):
    h = SimpleNamespace(
        phase=phase,
        policy=scenario["policy"],
        block=300,
        calls=[],
        proofs=[],
        fail=set(),
        offline=False,
        signers={},
        root=tmp_path,
    )
    h.source = NativeIntakeProgressSource(phase.intake)

    class Provider:
        policy = h.policy

        async def collect(self):
            if h.offline:
                raise OSError("RPC unavailable")
            return capture_at(h.block)

        async def review_archive(self, expected, raw, metadata):
            h.proofs.append(expected)
            assert (raw, metadata) == (b"proof", b"metadata")
            return SimpleNamespace(
                snapshot=capture_at(expected.block).snapshot,
                replayed_at=SimpleNamespace(block_number=h.block),
            )

    async def archive(expected):
        return b"proof", b"metadata"

    def signer(name="Charlie"):
        reviewer = IntakeProgressReviewer(h.source, Provider(), archive)

        def evidence(cohort, consent):
            return reviewer.queue.record(cohort, consent), b"proof", b"metadata"

        reviewer.queue.evidence = evidence

        async def sign(body):
            # Both progress and decision persist their intent before hotkey I/O.
            with current.journal.transaction() as db:
                saved = [
                    r[0] for r in db.execute("SELECT body FROM records WHERE kind LIKE '%_intent'")
                ]
                assert any(canonical_json_bytes(body) in row for row in saved)
            h.calls.append((name, body))
            if name in h.fail:
                raise OSError("signing reply lost")
            return sign_object(body, wallet(name))

        config = CohortProgressSignerConfig(
            schema="umi-cohort-progress-signer-config/1",
            directory=str(tmp_path / name),
            policy_sha256=digest(h.policy),
            signer=wallet(name).hotkey.ss58_address,
            cohorts=phase.intake.config.cohorts,
        )
        current = CohortProgressSigner(config, reviewer, sign)
        h.signers[name] = current
        return current

    h.signer = signer
    return h


def test_completion_review_reconstructs_exact_seal_and_service_evidence(phase, scenario):
    result = healthy(phase, scenario)
    source = NativeIntakeProgressSource(phase.intake)
    reviewed = source.read(result.progress)
    assert reviewed.seal == result.seal
    assert reviewed.record.service == result.service
    assert len(reviewed.consents) == 1
    assert reviewed.record.history_sha256 == digest(scenario["intake_history"])


@pytest.mark.parametrize(
    "field,value",
    [
        ("unavailable_blocks", 1),
        ("evidence_sha256", "ab" * 32),
        ("phase_result_sha256", "ab" * 32),
        ("recovery_tip_sha256", "ab" * 32),
        ("observed_at_block", 299),
        ("phase", "requests"),
    ],
)
def test_changed_completion_cannot_be_reviewed(phase, scenario, field, value):
    result = healthy(phase, scenario)
    with pytest.raises(ValueError):
        NativeIntakeProgressSource(phase.intake).read(
            result.progress.model_copy(update={field: value})
        )


def test_pending_sample_can_be_reviewed_after_new_samples_arrive(phase, scenario):
    result = observe(phase, scenario, 200)
    observe(phase, scenario, 205)
    assert (
        NativeIntakeProgressSource(phase.intake).read(result.progress).record.service
        == result.service
    )


def test_missing_or_changed_service_prefix_rejects_a_completion(phase, scenario):
    result = healthy(phase, scenario)
    with phase.intake._connection() as (db, _):
        db.execute("DELETE FROM cohort_service_observations WHERE sequence=2")
    with pytest.raises(ValueError, match=r"incomplete|inconsistent"):
        NativeIntakeProgressSource(phase.intake).read(result.progress)


async def test_completed_vote_is_idempotent_and_available_after_restart_offline(harness, scenario):
    h = harness
    result = healthy(h.phase, scenario)
    vote = await h.signer().attest(result.progress)
    assert len(h.proofs) == 2  # seal plus original participant
    h.offline = True
    assert await h.signer().attest(result.progress) == vote
    assert len(h.calls) == 1


async def test_lost_signature_recovers_same_body_after_four_hour_outage(harness, scenario):
    h = harness
    result = healthy(h.phase, scenario)
    h.fail.add("Charlie")
    with pytest.raises(OSError):
        await h.signer().attest(result.progress)
    h.block += 1200
    h.fail.clear()
    await h.signer().attest(result.progress)
    assert len(h.calls) == 2 and h.calls[0] == h.calls[1]
    assert h.source.read(result.progress).seal == result.seal


async def test_invalid_registration_proof_prevents_hotkey_use(harness, scenario):
    h = harness
    result = healthy(h.phase, scenario)
    signer = h.signer()

    async def invalid(*args):
        raise ValueError("historical proof mismatch")

    signer.reviewer.provider.review_archive = invalid
    with pytest.raises(ValueError, match="proof mismatch"):
        await signer.attest(result.progress)
    assert h.calls == []


async def test_owned_finality_must_reach_claimed_observation(harness, scenario):
    h = harness
    result = healthy(h.phase, scenario)
    h.block = 299
    with pytest.raises(ValueError, match="ahead"):
        await h.signer().attest(result.progress)
    assert h.calls == []


async def test_missing_quorum_keeps_successful_vote_for_retry(harness, scenario):
    h = harness
    result = healthy(h.phase, scenario)

    async def native(*args):
        return result

    ports = CertifiedIntakeObserver(native, [h.signer(n) for n in ("Charlie", "Dave")], h.policy)
    h.fail.add("Dave")
    with pytest.raises(ValueError, match="quorum"):
        await ports(None, None)
    h.fail.clear()
    attested = await ports(None, None)
    assert len(attested.signatures) == 2
    assert [n for n, _ in h.calls].count("Charlie") == 1
    assert [n for n, _ in h.calls].count("Dave") == 2


async def test_cancellation_drains_signing_before_releasing_journal(harness, scenario):
    h = harness
    progress = healthy(h.phase, scenario).progress
    signer = h.signer()
    entered, release = asyncio.Event(), asyncio.Event()

    async def delayed(body):
        entered.set()
        try:
            await release.wait()
        except asyncio.CancelledError:
            await release.wait()
        return sign_object(body, wallet("Charlie"))

    signer.sign = delayed
    task = asyncio.create_task(signer.attest(progress))
    await asyncio.wait_for(entered.wait(), 5)
    task.cancel()
    await asyncio.sleep(0)
    assert not task.done()
    with pytest.raises((OSError, ValueError)), h.signer().journal.locked():
        pass
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    await h.signer().attest(progress)


async def test_controller_recovers_outage_and_lost_publication(harness, scenario):
    h = harness
    history = scenario["intake_history"]
    cohort = digest(history.plan)
    path = h.root / "coordinator.sqlite3"
    db = sqlite3.connect(path)
    store = CohortRecoveryStore(db)
    store.admit(history.plan, history.authority, h.policy, admitted_at_block=160)
    lost_reply = False
    signers = [h.signer(n) for n in ("Charlie", "Dave")]

    async def collect():
        return capture_at(h.block)

    async def ready(request):
        value = intake_readiness(
            h.phase.intake,
            cohort,
            capture_at(h.block),
            nonce=request.url.params["nonce"],
            archive_available=True,
        )
        return httpx.Response(
            200, content=canonical_json_bytes(value), headers={"content-type": "application/json"}
        )

    def native():
        return LiveIntakePhaseObserver(
            h.phase, "https://intake.example", transport=httpx.MockTransport(ready)
        )

    async def source(cohort, key):
        return store.source(cohort, key, CohortDecisionInput)

    publisher = CohortIntakePublisher(h.phase.intake, collect, source)

    async def publish(value):
        nonlocal lost_reply
        await publisher(value)
        if lost_reply and value.transitions:
            lost_reply = False
            raise OSError("lost publication acknowledgement")

    ports = CertifiedIntakeObserver(native(), signers, h.policy)

    def controller():
        return CohortRecoveryCoordinator(
            store,
            cohort,
            h.policy,
            history.genesis_signatures,
            SimpleNamespace(collect=collect),
            ports,
            ports.certify,
            publish,
            sample_progress=ports.sample,
            attest_progress=ports.attest,
        )

    try:
        h.block = 200
        assert (await controller().tick())["status"] == "waiting_phase_progress"
        h.block = 1400  # four-hour gap, past the original policy expiry
        lost_reply = True
        with pytest.raises(OSError, match="acknowledgement"):
            await controller().tick()
        state, pending = store.status(cohort)
        assert state.sequence == 1 and pending is None and state.targets[0].target_block == 1500
        signed_calls = len(h.calls)
        db.close()
        db = sqlite3.connect(path)
        store = CohortRecoveryStore(db)
        h.phase = CohortIntakePhaseObserver(h.phase.intake)
        ports.observe = native()
        ports.signers = tuple(h.signer(n) for n in ("Charlie", "Dave"))
        assert (await controller().tick())["status"] == "waiting_phase_progress"
        assert len(h.calls) >= signed_calls
        for block in range(1405, 1505, 5):
            h.block = block
            result = await controller().tick()
        assert result["phase"] == "preparation"
        assert result["sequence"] == 2
        closed = h.phase.intake.history(cohort)
        assert len(closed.transitions) == 2
        assert len({t.transition.predecessor_sha256 for t in closed.transitions}) == 2
        assert h.phase.intake.sealed(cohort, closed.transitions[-1].transition.predecessor_sha256)
    finally:
        db.close()


async def test_partial_decision_recovers_original_observation(harness, scenario):
    h = harness
    native = healthy(h.phase, scenario)
    history = scenario["intake_history"]
    state, _, _ = replay_cohort_decisions(history, h.policy, lambda _: None)
    charlie, dave = h.signer("Charlie"), h.signer("Dave")

    async def observe(*args):
        return native

    ports = CertifiedIntakeObserver(observe, (charlie, dave), h.policy)
    progress = await ports(state, capture_at(h.block))
    evidence = CohortDecisionInput(
        schema="umi-cohort-decision-input/1",
        progress=progress,
        observation=execution_boundary(capture_at(h.block)),
    )
    proposed, _ = _choice(state, history.authority.authority, h.policy, evidence, 0, 0)
    h.fail.add("Dave")
    with pytest.raises(ValueError, match="quorum"):
        await ports.certify(proposed, evidence)
    h.block = 1500
    h.fail.clear()
    ports.signers = (h.signer("Charlie"), h.signer("Dave"))
    result = await ports.certify(proposed, evidence)
    assert result.transition == proposed and result.transition.observed_at_block == 300
    decision_calls = [(n, b) for n, b in h.calls if b.schema_ == proposed.schema_]
    assert [n for n, _ in decision_calls].count("Charlie") == 1
    assert [n for n, _ in decision_calls].count("Dave") == 2
    conflicting = proposed.model_copy(update={"observed_at_block": 301})
    with pytest.raises(ValueError, match="reserved"):
        await ports.signers[0].certify(conflicting, evidence)


async def test_controller_recovers_partial_progress_after_repeated_outages(
    harness, scenario
):
    h = harness
    native = healthy(h.phase, scenario)
    history = scenario["intake_history"]
    cohort = digest(history.plan)
    path = h.root / "progress-recovery.sqlite3"
    db = sqlite3.connect(path)
    store = CohortRecoveryStore(db)
    store.admit(history.plan, history.authority, h.policy, admitted_at_block=160)
    sampled = []

    async def sample(state, capture):
        sampled.append(capture.snapshot.block)
        return native

    async def collect():
        return capture_at(h.block)

    async def source(cohort, key):
        return store.source(cohort, key, CohortDecisionInput)

    publish = CohortIntakePublisher(h.phase.intake, collect, source)

    def controller():
        ports = CertifiedIntakeObserver(
            sample, [h.signer(n) for n in ("Charlie", "Dave")], h.policy
        )
        return CohortRecoveryCoordinator(
            store,
            cohort,
            h.policy,
            history.genesis_signatures,
            SimpleNamespace(collect=collect),
            ports,
            ports.certify,
            publish,
            sample_progress=ports.sample,
            attest_progress=ports.attest,
        )

    try:
        h.fail.add("Dave")
        for block in (300, 1500):
            h.block = block
            with pytest.raises(ValueError, match="quorum"):
                await controller().tick()
            retained = store.progress_intent(cohort, history_tip(history), CohortProgressIntent)
            assert retained.progress == native.progress and retained.observation.block == 300
            assert store.status(cohort)[1] is None
            db.close()
            db = sqlite3.connect(path)
            store = CohortRecoveryStore(db)
        h.block = 2700
        h.fail.clear()
        result = await controller().tick()
        assert result["phase"] == "preparation" and result["sequence"] == 1
        assert sampled == [300]
        assert store.progress_intent(cohort, result["tip_sha256"], CohortProgressIntent) is None
        calls = [(n, b) for n, b in h.calls if b.schema_ == native.progress.schema_]
        assert [n for n, _ in calls].count("Charlie") == 1
        assert [n for n, _ in calls].count("Dave") == 3
        assert all(b == native.progress for _, b in calls)
    finally:
        db.close()
