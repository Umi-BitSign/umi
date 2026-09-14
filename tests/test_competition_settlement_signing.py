from __future__ import annotations

import sqlite3
from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi import competition_settlement_signing as signing
from umi.competition_evaluator import IndependentEvidenceObservation, SignedExecutionAnnouncement
from umi.competition_execution import execution_boundary, execution_slot
from umi.competition_package import (
    CompetitionPackageEvidence,
    CompetitionPackageEvidenceEntry,
    CompetitionPackageRoster,
)
from umi.competition_publication import (
    SignedSettlementPublication,
    build_cutoff_publication,
    build_settlement_publication,
    settlement_signer_eligible,
    verify_settlement_publication,
)
from umi.competition_rounds import CutoffEndorsement, RoundJournal, RoundProposal
from umi.competition_settlement_preparation import SettlementPreparation
from umi.competition_store import CompetitionStore
from umi.open_competition import Evaluator, digest
from umi.protocol import canonical_json_bytes

from .test_competition_evaluator import agree, completed, execute
from .test_competition_evaluator import chain_config as chain_config
from .test_competition_evaluator import model_setup as model_setup
from .test_competition_evaluator import runtime as runtime
from .test_competition_evaluator import setup as execution_fixture
from .test_competition_publication import _certificate, _scenario
from .test_competition_publication import replay_limits as replay_limits
from .test_competition_rounds import OwnedProvider
from .test_open_competition import policy as policy
from .test_open_competition import snapshot, wallet

execution_setup = execution_fixture


@pytest.fixture
def setup(policy, replay_limits, tmp_path, monkeypatch):
    """Signing-state unit fixture; actual local execution is tested separately below."""
    s = _scenario(policy, tmp_path / "reviewed", replay_limits)
    cutoff = build_cutoff_publication(
        round_=s.round,
        cutoff_schedule=s.schedule,
        registration_snapshot=snapshot(120),
        submissions=s.submissions,
        policy=policy,
        limits=replay_limits,
    )
    certificate = _certificate(cutoff)
    publication = build_settlement_publication(
        cutoff_certificate=certificate,
        retained_settlement=s.settlement,
        submissions=s.submissions,
        evidence=s.evidence,
        policy=policy,
        limits=replay_limits,
    )
    s.prepared = SettlementPreparation(
        schema="umi-settlement-preparation/1",
        cutoff=certificate,
        publication=publication,
        roster=CompetitionPackageRoster(
            schema="umi-competition-replay-roster/1", submissions=s.submissions
        ),
        evidence=CompetitionPackageEvidence(
            schema="umi-competition-replay-evidence/1",
            entries=tuple(
                CompetitionPackageEvidenceEntry(submission=a, evidence=b) for a, b in s.evidence
            ),
        ),
    )
    proposal = RoundProposal(
        schema="umi-round-proposal/1",
        cutoff=cutoff,
        submissions=s.submissions,
        signing_close_block=125,
    )
    s.signers = []
    s.local_checks = []
    for index, name in enumerate(("Charlie", "Dave")):
        key = wallet(name)
        owned = OwnedProvider(160)

        async def boundary(owned=owned):
            return execution_boundary(await owned.collect())

        worker = SimpleNamespace(
            config=SimpleNamespace(
                state_directory=str(tmp_path / name),
                evaluator_hotkey=key.hotkey.ss58_address,
                maximum_orders=1024,
                maximum_journal_bytes=1024**3,
            ),
            policy=policy,
            wallet=key,
            provider=owned,
            boundary=boundary,
        )
        cutoffs = RoundJournal(tmp_path / (name + "-cutoffs"), {"name": name})
        cutoffs.put("intent", "1", proposal)
        cutoffs.put("suite", s.round.suite_sha256, {"proposal": digest(proposal)})
        cutoffs.put(
            "vote",
            "1",
            CutoffEndorsement(
                proposal_sha256=digest(proposal), signature=certificate.signatures[index]
            ),
        )
        signer = signing.IndependentSettlementSigner(worker, cutoffs, s.store, limits=replay_limits)
        monkeypatch.setattr(signer, "_local_evidence", lambda p, h: s.local_checks.append(h))
        s.signers.append(signer)
    s.limits = replay_limits
    return s


@pytest.mark.asyncio
async def test_two_endorsements_verify_the_complete_70_30_publication(setup):
    s = setup
    votes = [await signer.endorse(s.prepared) for signer in s.signers]
    certificate = SignedSettlementPublication(
        publication=s.prepared.publication, signatures=tuple(v.signature for v in votes)
    )
    assert (
        verify_settlement_publication(
            certificate,
            cutoff_certificate=s.prepared.cutoff,
            policy=s.policy,
            submissions=s.submissions,
            evidence=s.evidence,
            retained_settlement=s.settlement,
            limits=s.limits,
        )
        == s.prepared.publication
    )
    assert s.policy.endpoint_reward_bps == 7000 and s.policy.model_reward_bps == 3000
    assert s.local_checks == [160, 160, 160, 160, 160, 160]
    assert all(x.worker.provider.history == [160] for x in s.signers)
    assert not certificate.publication.chain_submission_authorized


@pytest.mark.asyncio
async def test_restart_exact_vote_is_retained_without_resigning(setup, monkeypatch):
    s, signer = setup, setup.signers[0]
    vote = await signer.endorse(s.prepared)
    fresh = signing.IndependentSettlementSigner(
        signer.worker, signer.cutoffs, s.store, limits=s.limits
    )
    monkeypatch.setattr(fresh, "_local_evidence", lambda *_: None)
    monkeypatch.setattr(signing, "sign_settlement_publication", lambda *_: pytest.fail("re-signed"))
    assert await fresh.endorse(s.prepared) == vote
    assert signer.worker.provider.history == [160]


@pytest.mark.asyncio
@pytest.mark.parametrize("damage", ["missing_intent", "missing_suite", "held_cutoff"])
async def test_missing_or_conflicting_cutoff_cannot_sign(setup, damage):
    s, signer = setup, setup.signers[0]
    with signer.cutoffs.transaction() as db:
        if damage == "held_cutoff":
            db.execute("INSERT INTO holds VALUES ('1')")
        else:
            db.execute("DELETE FROM records WHERE kind=?", (damage.removeprefix("missing_"),))
    with pytest.raises(ValueError):
        await signer.endorse(s.prepared)
    assert signer.journal.get("vote", "1") is None


@pytest.mark.asyncio
@pytest.mark.parametrize("block", [159, 171, 301])
async def test_early_stale_or_expired_signing_does_not_reserve(setup, block):
    s, signer = setup, setup.signers[0]
    signer.worker.provider.block = block
    with pytest.raises(ValueError, match="window"):
        await signer.endorse(s.prepared)
    assert signer.journal.get("intent", "1") is None


@pytest.mark.asyncio
@pytest.mark.parametrize("damage", ["snapshot", "unowned", "elapsed", "promotion_conflict"])
async def test_rechecks_after_owned_historical_proof(setup, damage):
    s, signer = setup, setup.signers[0]
    provider = signer.worker.provider
    if damage == "elapsed":
        provider.advance_during_proof = 171
    else:

        def change(capture):
            if damage == "snapshot":
                return replace(capture, snapshot=snapshot(159))
            if damage == "unowned":
                return replace(capture, provenance={})
            with sqlite3.connect(s.store.path) as db:
                db.execute("INSERT INTO round_conflicts VALUES (?,?)", (digest(s.round), 160))
            return capture

        provider.historical_change = change
    with pytest.raises(ValueError):
        await signer.endorse(s.prepared)
    assert signer.journal.get("vote", "1") is None


@pytest.mark.asyncio
@pytest.mark.parametrize("damage", ["execution_conflict", "cutoff_conflict"])
async def test_rechecks_conflicts_after_the_final_owned_head(setup, monkeypatch, damage):
    s, signer = setup, setup.signers[0]
    original = signer.worker.boundary
    captures = 0
    conflicted = False

    async def boundary():
        nonlocal captures, conflicted
        result = await original()
        captures += 1
        if captures == 3:
            if damage == "cutoff_conflict":
                with signer.cutoffs.transaction() as db:
                    db.execute("INSERT INTO holds VALUES ('1')")
            else:
                conflicted = True
        return result

    def local_evidence(*_):
        if conflicted:
            raise ValueError("local execution became conflicted during the final head read")

    monkeypatch.setattr(signer.worker, "boundary", boundary)
    monkeypatch.setattr(signer, "_local_evidence", local_evidence)
    monkeypatch.setattr(
        signing, "sign_settlement_publication", lambda *_: pytest.fail("signed after conflict")
    )
    with pytest.raises(ValueError):
        await signer.endorse(s.prepared)
    assert captures == 3
    assert signer.journal.get("vote", "1") is None


@pytest.mark.asyncio
async def test_missing_reviewed_promotion_never_imports_remote_head(setup, tmp_path):
    s, signer = setup, setup.signers[0]
    signer.reviews = CompetitionStore(tmp_path / "empty-reviews", s.policy)
    with pytest.raises(ValueError, match="history is missing"):
        await signer.endorse(s.prepared)
    assert signer.reviews.baseline() is None


@pytest.mark.asyncio
async def test_signature_persistence_failure_preserves_pre_sign_intent(setup, monkeypatch):
    s, signer = setup, setup.signers[0]
    original = signer.journal.put

    def fail(kind, slot, value):
        if kind == "vote":
            assert signer.journal.get("intent", slot) is not None
            raise OSError("disk full")
        return original(kind, slot, value)

    monkeypatch.setattr(signer.journal, "put", fail)
    with pytest.raises(OSError):
        await signer.endorse(s.prepared)
    assert signer.journal.get("vote", "1") is None
    monkeypatch.setattr(signer.journal, "put", original)
    assert await signer.endorse(s.prepared)


@pytest.mark.asyncio
async def test_changed_valid_proposal_holds_the_sequence_across_restart(setup, monkeypatch):
    s, signer = setup, setup.signers[0]
    await signer.endorse(s.prepared)
    other = build_settlement_publication(
        cutoff_certificate=s.prepared.cutoff,
        retained_settlement=s.settlement.model_copy(update={"observed_block": 161}),
        submissions=s.submissions,
        evidence=s.evidence,
        policy=s.policy,
        limits=s.limits,
    )
    signer.worker.provider.block = 161
    with pytest.raises(ValueError, match="conflict"):
        await signer.endorse(s.prepared.model_copy(update={"publication": other}))
    fresh = signing.IndependentSettlementSigner(
        signer.worker, signer.cutoffs, s.store, limits=s.limits
    )
    monkeypatch.setattr(fresh, "_local_evidence", lambda *_: None)
    with pytest.raises(ValueError, match="conflict"):
        await fresh.endorse(s.prepared)


@pytest.mark.asyncio
async def test_window_expiring_during_final_replay_cannot_sign(setup, monkeypatch):
    s, signer = setup, setup.signers[0]
    calls = 0

    def replay(*_):
        nonlocal calls
        calls += 1
        if calls == 2:
            signer.worker.provider.block = 171

    monkeypatch.setattr(signer, "_local_evidence", replay)
    with pytest.raises(ValueError, match="window"):
        await signer.endorse(s.prepared)
    assert signer.journal.get("intent", "1") is None


@pytest.mark.asyncio
async def test_missing_execution_cannot_use_coordinator_records(setup, monkeypatch):
    s, signer = setup, setup.signers[0]

    def missing(slot, *, void=False):
        raise ValueError("local settlement execution evidence is incomplete")

    signer.worker.journal = SimpleNamespace(settlement_evidence=missing)
    monkeypatch.setattr(
        signer,
        "_local_evidence",
        signing.IndependentSettlementSigner._local_evidence.__get__(signer),
    )
    with pytest.raises(ValueError, match="incomplete"):
        await signer.endorse(s.prepared)
    assert signer.journal.get("intent", "1") is None


@pytest.mark.asyncio
async def test_recipient_hotkey_cannot_obtain_a_settlement_signature(setup, monkeypatch):
    s, signer = setup, setup.signers[0]
    signer.worker.config.evaluator_hotkey = wallet("Alice").hotkey.ss58_address
    monkeypatch.setattr(signing, "sign_settlement_publication", lambda *_: pytest.fail("signed"))
    with pytest.raises(ValueError, match="self-interested"):
        await signer.endorse(s.prepared)
    assert signer.journal.get("intent", "1") is None


def test_submitter_group_alias_is_also_excluded(setup):
    s = setup
    alias = Evaluator(hotkey=wallet("Alice").hotkey.ss58_address, control_group="c")
    policy = s.policy.model_copy(update={"evaluators": (*s.policy.evaluators, alias)})
    assert not settlement_signer_eligible(
        wallet("Charlie").hotkey.ss58_address, s.prepared.publication, policy, s.submissions
    )
    assert settlement_signer_eligible(
        wallet("Dave").hotkey.ss58_address, s.prepared.publication, policy, s.submissions
    )


@pytest.mark.parametrize("damage", ["size", "digest", "noncanonical"])
def test_local_review_head_corruption_is_rejected(setup, damage):
    s = setup
    with sqlite3.connect(s.store.path) as db:
        if damage == "size":
            db.execute("UPDATE promotions SET body=zeroblob(1100000) WHERE sequence=1")
        elif damage == "digest":
            db.execute("UPDATE promotions SET digest=? WHERE sequence=1", ("0" * 64,))
        else:
            db.execute("UPDATE promotions SET body=CAST(body AS TEXT)||' ' WHERE sequence=1")
    with pytest.raises(ValueError):
        s.store.reviewed_promotion_head(digest(s.round), maximum_bytes=1_000_000)


def local_preparation(s, driver):
    return SimpleNamespace(
        publication=SimpleNamespace(
            round=s.order.order.round,
            settlement=SimpleNamespace(
                suite=s.suite, cutoff_schedule=SimpleNamespace(evidence_cutoff_block=160)
            ),
        ),
        evidence=SimpleNamespace(
            entries=(
                SimpleNamespace(submission=s.order.order.submission, evidence=completed(driver)[0]),
            )
        ),
    )


@pytest.mark.asyncio
async def test_actual_local_execution_and_receipt_are_required(execution_setup):
    s = execution_setup
    await execute(s.drivers)
    await agree(s)
    for driver in s.drivers:
        prepared = local_preparation(s, driver)
        # Exercise the production verifier against the actual evaluator journals.
        signer = SimpleNamespace(worker=driver)
        signing.IndependentSettlementSigner._local_evidence(signer, prepared, 160)
        slot = execution_slot(
            s.order.order.round, s.order.order.submission, driver.config.evaluator_hotkey
        )
        with driver.journal.transaction() as db:
            db.execute("UPDATE orders SET conflict=1 WHERE slot=?", (slot,))
        with pytest.raises(ValueError, match="conflicted"):
            signing.IndependentSettlementSigner._local_evidence(signer, prepared, 160)


@pytest.mark.asyncio
async def test_late_local_receipt_is_not_repaired_from_coordinator_claim(execution_setup):
    s = execution_setup
    await execute(s.drivers)
    await agree(s)
    driver = s.drivers[0]
    prepared = local_preparation(s, driver)
    slot = execution_slot(
        s.order.order.round, s.order.order.submission, driver.config.evaluator_hotkey
    )
    receipt = driver.journal.get(slot, "independent_observation", IndependentEvidenceObservation)
    receipt = receipt.model_copy(
        update={"observed": receipt.observed.model_copy(update={"block": 161})}
    )
    with driver.journal.transaction() as db:
        db.execute(
            "UPDATE artifacts SET body=? WHERE slot=? AND kind='independent_observation'",
            (canonical_json_bytes(receipt), slot),
        )
    with pytest.raises(ValueError, match="by cutoff"):
        signing.IndependentSettlementSigner._local_evidence(
            SimpleNamespace(worker=driver), prepared, 160
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("damage", ["missing", "signature", "noncanonical", "oversize"])
async def test_local_announcement_is_required_bounded_and_authenticated(execution_setup, damage):
    s = execution_setup
    await execute(s.drivers)
    await agree(s)
    driver = s.drivers[0]
    prepared = local_preparation(s, driver)
    slot = execution_slot(
        s.order.order.round, s.order.order.submission, driver.config.evaluator_hotkey
    )
    announcement = driver.journal.get(slot, "announcement", SignedExecutionAnnouncement)
    with driver.journal.transaction() as db:
        if damage == "missing":
            db.execute("DELETE FROM artifacts WHERE slot=? AND kind='announcement'", (slot,))
        elif damage == "oversize":
            db.execute(
                "UPDATE artifacts SET body=zeroblob(67108865) WHERE slot=? AND kind='announcement'",
                (slot,),
            )
        elif damage == "noncanonical":
            db.execute(
                "UPDATE artifacts SET body=CAST(body AS TEXT)||' ' "
                "WHERE slot=? AND kind='announcement'",
                (slot,),
            )
        else:
            altered = announcement.model_copy(
                update={
                    "signature": announcement.signature.model_copy(
                        update={"signature": "0x" + "00" * 64}
                    )
                }
            )
            db.execute(
                "UPDATE artifacts SET body=? WHERE slot=? AND kind='announcement'",
                (canonical_json_bytes(altered), slot),
            )
    with pytest.raises(ValueError):
        signing.IndependentSettlementSigner._local_evidence(
            SimpleNamespace(worker=driver), prepared, 160
        )
