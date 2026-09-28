"""Native preparation certification and controller recovery; synthetic chain boundaries."""

from __future__ import annotations

import sqlite3
from collections import Counter
from functools import partial
from types import SimpleNamespace

import pytest

from umi.competition_artifacts import preserve_bundle
from umi.competition_cohort_coordinator import (
    CohortDecisionInput,
    CohortProgressIntent,
    CohortRecoveryCoordinator,
    _choice,
)
from umi.competition_cohort_intake import CohortIntakePublisher, history_tip
from umi.competition_cohort_preparation_owner import CohortPreparation
from umi.competition_cohort_preparation_phase import NativePreparationProgressSource
from umi.competition_cohort_preparation_review import PreparationProgressReviewer
from umi.competition_cohort_progress_signer import (
    CertifiedPhaseObserver,
    CohortProgressSigner,
    CohortProgressSignerConfig,
)
from umi.competition_cohort_recovery_store import CohortRecoveryStore
from umi.competition_cohort_roster import verify_recoverable_roster_membership
from umi.competition_execution import execution_boundary
from umi.competition_store import AdmissionCapacity, AdmissionCapacityError, CompetitionStore
from umi.open_competition import digest, sign_object
from umi.protocol import canonical_json_bytes

from .test_competition_chain import chain as chain
from .test_competition_chain import chain_config as chain_config
from .test_competition_cohort_admission_queue import relay as relay
from .test_competition_cohort_admission_queue import submit
from .test_competition_cohort_admission_review import accepted as accepted
from .test_competition_cohort_admission_signer import closed_source
from .test_competition_cohort_admission_signer import harness as harness
from .test_competition_cohort_consumers import scenario as scenario
from .test_competition_cohort_consumers import transition
from .test_competition_cohort_intake import capture_at
from .test_competition_cohort_intake import intake as intake
from .test_competition_cohort_preparation import preparation as preparation
from .test_competition_cohort_recovery import recovery as recovery
from .test_competition_historical_registration import archive as archive
from .test_open_competition import bundle_at, wallet
from .test_open_competition import policy as policy


@pytest.fixture
def reviewed(preparation, tmp_path, monkeypatch):
    h = preparation
    h.certify()
    h.source = NativePreparationProgressSource(h.owner)
    h.block, h.calls, h.fail, h.proofs = 330, [], set(), []
    h.missing, h.bad, h.offline = None, False, False
    with h.queue._connection() as (_, store):
        h.state, _ = store.status(h.cohort)
    h.progress = h.source.observe(h.state, capture_at(h.block))
    h.prepared = h.source.read(h.progress).prepared
    h.root = tmp_path

    def evidence(cohort, consent):
        if consent == h.missing:
            raise FileNotFoundError("original consent archive unavailable")
        return h.queue.record(cohort, consent), b"proof", b"metadata"

    monkeypatch.setattr(h.queue, "evidence", evidence)

    class Provider:
        policy = h.intake.policy

        async def collect(self):
            if h.offline:
                raise OSError("RPC unavailable")
            return capture_at(h.block)

        async def review_archive(self, observation, raw, metadata):
            h.proofs.append(observation)
            if h.bad or (raw, metadata) != (b"proof", b"metadata"):
                raise ValueError("original proof mismatch")
            return SimpleNamespace(
                snapshot=capture_at(observation.block).snapshot,
                replayed_at=SimpleNamespace(block_number=h.block),
            )

    async def archive(observation):
        return b"proof", b"metadata"

    def signer(name="Charlie"):
        config = CohortProgressSignerConfig(
            schema="umi-cohort-progress-signer-config/1",
            directory=str(tmp_path / name),
            policy_sha256=digest(h.intake.policy),
            signer=wallet(name).hotkey.ss58_address,
            cohorts=h.intake.config.cohorts,
        )
        reviewer = PreparationProgressReviewer(h.source, Provider(), archive)

        async def sign(body):
            with value.journal.transaction() as db:
                rows = db.execute("SELECT body FROM records WHERE kind LIKE '%_intent'")
                assert any(canonical_json_bytes(body) in row[0] for row in rows)
            h.calls.append((name, body))
            if (name, body.schema_) in h.fail:
                raise OSError("signing response lost")
            return sign_object(body, wallet(name))

        value = CohortProgressSigner(config, reviewer, sign)
        return value

    h.signer, h.provider = signer, Provider()
    return h


async def test_preparation_review_checks_all_original_archives_and_recovers_offline_vote(reviewed):
    h = reviewed
    signer = h.signer()
    first = await signer.attest(h.progress)
    # Original preparation/current progress, seal/closure, and both consent records.
    assert Counter(p.block for p in h.proofs) == Counter({330: 1, 300: 1, 210: 1, 240: 1})
    h.offline = True
    h.bad = True
    assert await h.signer().attest(h.progress) == first
    assert len(h.calls) == 1


@pytest.mark.parametrize("failure", ["proof", "old_consent", "selected_consent", "finality"])
async def test_missing_or_invalid_original_evidence_prevents_signing(reviewed, failure):
    h = reviewed
    if failure == "proof":
        h.bad = True
    elif failure == "finality":
        h.block = 329
    else:
        receipt = h.old if failure == "old_consent" else h.selected
        h.missing = receipt["proposed_admission"]["consent_sha256"]
    with pytest.raises((OSError, ValueError)):
        await h.signer().attest(h.progress)
    assert not h.calls


@pytest.mark.parametrize(
    "field,value",
    [
        ("unavailable_blocks", 1),
        ("observed_at_block", 331),
        ("phase", "requests"),
        ("phase_result_sha256", "ab" * 32),
        ("evidence_sha256", "ab" * 32),
        ("recovery_tip_sha256", "ab" * 32),
    ],
)
async def test_altered_preparation_progress_cannot_be_signed(reviewed, field, value):
    h = reviewed
    with pytest.raises((OSError, ValueError)):
        await h.signer().attest(h.progress.model_copy(update={field: value}))
    assert not h.calls


async def test_changed_decision_observation_is_rejected_before_transition_signature(reviewed):
    h = reviewed
    ports = CertifiedPhaseObserver(
        h.source.sample, (h.signer("Charlie"), h.signer("Dave")), h.intake.policy
    )
    progress = await ports.attest(h.progress)
    evidence = CohortDecisionInput(
        schema="umi-cohort-decision-input/1",
        progress=progress,
        observation=execution_boundary(capture_at(331)),
    )
    proposed, _ = _choice(h.state, h.history.authority.authority, h.intake.policy, evidence, 0, 0)
    with pytest.raises(ValueError, match="original finalized observation"):
        await ports.signers[0].certify(proposed, evidence)
    assert all(body.schema_ == "umi-cohort-phase-progress/1" for _, body in h.calls)


@pytest.mark.parametrize("stage", ["progress", "decision", "publication"])
async def test_controller_recovers_exact_preparation_after_long_outage(reviewed, stage):
    h = reviewed
    path = h.root / "control.sqlite3"
    lost = False
    publications = []
    db = sqlite3.connect(path)
    store = CohortRecoveryStore(db)
    store.admit(
        h.history.plan,
        h.history.authority,
        h.intake.policy,
        admitted_at_block=h.history.genesis.admitted_at_block,
    )
    store.retain_source(h.cohort, h.closing)
    store.publish_history(h.history, h.intake.policy, current_block=h.block)

    async def decision(cohort, key):
        return store.source(cohort, key, CohortDecisionInput)

    publisher = CohortIntakePublisher(h.intake, h.provider.collect, decision)

    async def publish(history):
        nonlocal lost
        await publisher(history)
        publications.append(digest(history))
        if (
            stage == "publication"
            and not lost
            and len(history.transitions) > len(h.history.transitions)
        ):
            lost = True
            raise OSError("history publication reply lost")

    def controller():
        ports = CertifiedPhaseObserver(
            h.source.sample, tuple(h.signer(n) for n in ("Charlie", "Dave")), h.intake.policy
        )
        return CohortRecoveryCoordinator(
            store,
            h.cohort,
            h.intake.policy,
            h.history.genesis_signatures,
            h.provider,
            None,
            ports.certify,
            publish,
            sample_progress=ports.sample,
            attest_progress=ports.attest,
        )

    if stage != "publication":
        h.fail.add(
            (
                "Dave",
                "umi-cohort-phase-progress/1"
                if stage == "progress"
                else "umi-cohort-recovery-transition/1",
            )
        )
    try:
        with pytest.raises((OSError, ValueError)):
            await controller().tick()
        intent = (
            store.progress_intent(h.cohort, h.state.tip_sha256, CohortProgressIntent)
            if stage == "progress"
            else None
        )
        if intent is not None:
            assert intent.progress == h.progress
        original_calls = tuple(h.calls)
        h.fail.clear()
        h.block += 100_000
        db.close()
        db = sqlite3.connect(path)
        store = CohortRecoveryStore(db)
        if stage == "publication":
            # The real controller retries history before attempting the next
            # phase. This preparation-only fixture has no request observer.
            before = len(publications)
            with pytest.raises(ValueError, match="preparation progress"):
                await controller().tick()
            assert len(publications) == before + 1
            assert publications[-1] == publications[-2]
            assert tuple(h.calls) == original_calls
        else:
            result = await controller().tick()
            assert result["phase"] == "requests"
        current = h.intake.history(h.cohort)
        assert len(current.transitions) == 2
        prepared_decision = store.source(
            h.cohort, current.transitions[-1].transition.evidence_sha256, CohortDecisionInput
        )
        assert prepared_decision.observation.block == 330
        assert prepared_decision.progress.progress.phase_result_sha256 == digest(
            h.prepared.roster.round
        )
        with h.queue._connection() as (owned, _):
            verify_recoverable_roster_membership(
                h.prepared.roster,
                h.intake.policy,
                current,
                decision_source=partial(store.source, h.cohort, model=CohortDecisionInput),
                intake_records=h.intake._records(owned, current),
                expected_tip_sha256=history_tip(current),
                current_block=h.block,
            )
        counts = Counter((name, digest(body)) for name, body in h.calls)
        assert all(count <= 2 for count in counts.values())
        assert all(count == 1 for (name, _), count in counts.items() if name == "Charlie")
        for name, body in original_calls:
            assert (name, digest(body)) in counts
    finally:
        db.close()


async def test_revocation_during_proof_review_prevents_signature(reviewed):
    h = reviewed
    signer = h.signer()
    archive = signer.reviewer.archive

    async def revoked(observation):
        current = transition(h.history, h.intake.policy, "revoke", 350)
        h.intake.publish(current, capture_at(350), decision_inputs=(h.closing,))
        return await archive(observation)

    signer.reviewer.archive = revoked
    with pytest.raises(ValueError, match="active owned history"):
        await signer.attest(h.progress)
    assert not h.calls


@pytest.mark.parametrize("changed", [False, True])
async def test_preparation_review_uses_native_archive_and_owned_header_validation(
    relay, tmp_path, changed
):
    h = relay
    await submit(h)
    await h.reviewer("Charlie").poll_once()
    await h.reviewer("Dave").poll_once()
    closed = closed_source(h)
    h.intake.seal(h.cohort, h.archive.capture, expected_tip_sha256=history_tip(h.source.history))
    capture = await h.archive.reviewer.collect()
    h.intake.publish(closed.history, capture, closure_input=closed.closure)
    promotion = CompetitionStore(tmp_path / "promotion", h.intake.policy)
    bundle = bundle_at(tmp_path / "model")
    preserve_bundle(bundle, tmp_path / "model", tmp_path / "model-archive", h.intake.policy)
    promotion.initialize_baseline(bundle, tmp_path / "model-archive")
    source = NativePreparationProgressSource(CohortPreparation(h.queue, promotion))
    with h.queue._connection() as (_, store):
        state, _ = store.status(h.cohort)
    progress = source.observe(state, capture)

    async def archive_for(observation):
        raw, metadata = await h.archive.reviewer.retained_archive(observation)
        return raw, b"changed" if changed else metadata

    reviewer = PreparationProgressReviewer(source, h.archive.reviewer, archive_for)
    before = len(h.archive.chain.verifier.checked)
    if changed:
        with pytest.raises(ValueError):
            await reviewer.review(progress)
    else:
        result = await reviewer.review(progress)
        assert result.progress == progress
        assert len(h.archive.chain.verifier.checked) > before
        assert result.history_sha256 == digest(closed.history)


def test_progress_capacity_failure_preserves_round_and_recovers_with_more_space(reviewed):
    h = reviewed
    with h.queue._connection() as (db, _):
        before = db.execute("SELECT COUNT(*) FROM cohort_preparation_progress").fetchone()[0]
    h.intake.capacity = AdmissionCapacity(maximum_bytes=1)
    with pytest.raises(AdmissionCapacityError):
        h.source.observe(h.state, capture_at(340))
    with h.queue._connection() as (db, _):
        assert (
            db.execute("SELECT COUNT(*) FROM cohort_preparation_progress").fetchone()[0] == before
        )
    assert h.source.read(h.progress).prepared == h.prepared
    h.intake.capacity = AdmissionCapacity()
    later = h.source.observe(h.state, capture_at(100_330))
    assert h.source.read(later).prepared == h.prepared
    assert {330, 100_330} <= h.intake.retained_registration_blocks()


def test_retained_read_cannot_silently_create_a_new_round(preparation):
    h = preparation
    with pytest.raises(FileNotFoundError, match="not retained"):
        h.owner.retained(h.cohort, expected_tip_sha256=history_tip(h.history), current_block=330)
