"""Durable signing with native journals/consent and synthetic chain proof ports."""

from __future__ import annotations

import asyncio
import hashlib
import json
import sqlite3
import threading
from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi.competition_cohort_admission_journal import (
    CohortAdmissionJournal,
    CohortAdmissionSignerConfig,
    admission_slot,
)
from umi.competition_cohort_admission_signer import (
    AdmissionHistory,
    CohortAdmissionSigner,
    certify_admission,
)
from umi.competition_cohort_coordinator import (
    AttestedCohortPhaseProgress,
    CohortDecisionInput,
    CohortPhaseProgress,
)
from umi.competition_cohort_intake import CohortIntake, history_tip
from umi.competition_cohort_intake_records import read_participation
from umi.competition_cohort_intake_seal import build_intake_seal
from umi.competition_cohort_participation import verify_participant_admission
from umi.competition_cohort_recovery import propose_recovery_transition
from umi.concurrency import run_owned_thread
from umi.open_competition import digest, sign_object
from umi.protocol import canonical_json_bytes

from .test_competition_chain import chain as chain
from .test_competition_chain import chain_config as chain_config
from .test_competition_cohort_admission_review import accepted as accepted
from .test_competition_cohort_consumers import scenario as scenario
from .test_competition_cohort_consumers import transition
from .test_competition_cohort_intake import request_for
from .test_competition_cohort_recovery import recovery as recovery
from .test_competition_cohort_recovery import signatures, signed_transition
from .test_competition_historical_registration import archive as archive
from .test_competition_historical_registration import change_block
from .test_open_competition import policy as policy
from .test_open_competition import wallet


@pytest.fixture
def harness(archive, accepted, tmp_path):
    intake_config, history, raw, receipt = accepted
    h = SimpleNamespace(
        archive=archive,
        raw=raw,
        receipt=receipt,
        source=AdmissionHistory(history),
        calls=[],
        fail=False,
        configs={},
        intake_config=intake_config,
    )

    async def current(cohort):
        assert cohort == digest(history.plan)
        return h.source

    def worker(name="Charlie", **overrides):
        config = CohortAdmissionSignerConfig(
            schema="umi-cohort-admission-signer-config/1",
            directory=str(tmp_path / name),
            policy_sha256=digest(archive.chain.policy),
            signer=wallet(name).hotkey.ss58_address,
            cohorts=intake_config.cohorts,
            **overrides,
        )
        h.configs[name] = config
        store = CohortAdmissionJournal(config, archive.chain.policy)

        async def sign(admission):
            retained = store.load(admission_slot(raw))
            assert retained[0].admission == admission and retained[1:4] == (
                raw,
                archive.raw,
                archive.metadata,
            )
            signature = sign_object(admission, wallet(name))
            h.calls.append((name, admission, signature))
            if h.fail:
                raise OSError("signature response lost")
            return signature

        return CohortAdmissionSigner(store, archive.reviewer, current, sign)

    h.worker = worker
    return h


async def test_two_independent_votes_form_a_native_admission_certificate(harness):
    h = harness
    votes = [await h.worker(name).attest(h.raw) for name in ("Charlie", "Dave")]
    certificate = certify_admission(votes, h.archive.chain.policy)
    record = read_participation(h.raw)
    assert (
        verify_participant_admission(
            certificate,
            record.request.signed_submission,
            record.request.consent,
            h.source.history,
            h.archive.chain.policy,
            h.archive.capture.snapshot,
            expected_tip_sha256=history_tip(h.source.history),
            current_block=h.archive.fresh.height,
        )
        == h.receipt.proposed_admission
    )
    with pytest.raises(ValueError, match="quorum"):
        certify_admission(votes[:1], h.archive.chain.policy)
    with pytest.raises(ValueError, match="unique"):
        certify_admission([votes[0], votes[0]], h.archive.chain.policy)


async def test_four_hour_outage_after_lost_signature_reuses_intent_and_original_evidence(harness):
    h = harness
    first = h.worker()
    h.fail = True
    with pytest.raises(OSError):
        await first.attest(h.raw)
    slot = admission_slot(h.raw)
    original = first.journal.load(slot)
    assert original[4] is None and len(h.calls) == 1
    # Retained evidence remains usable when the coordinator's old archive is unavailable.
    with sqlite3.connect(h.archive.reviewer._path) as db:
        db.execute("DELETE FROM captures")
        db.execute("DELETE FROM artifacts")
    a = h.archive
    a.chain.clock.now += 4 * 60 * 60 * 1000
    encoded = change_block(a.chain, a.fresh.height + 1200)
    proof = canonical_json_bytes(
        {**json.loads(a.fresh.finality_evidence), "block": {"scale_header": encoded}}
    )
    a.blocks[a.chain.finality.ref.block_number] = replace(
        a.fresh,
        height=a.chain.finality.ref.block_number,
        block_hash=a.chain.finality.ref.block_hash,
        timestamp_ms=a.chain.finality.timestamp,
        finality_evidence=proof,
        finality_evidence_sha256=hashlib.sha256(proof).hexdigest(),
    )
    h.source = AdmissionHistory(
        transition(
            h.source.history,
            a.chain.policy,
            "extend",
            a.chain.finality.ref.block_number,
            extension=1200,
        )
    )
    h.fail = False
    restarted = h.worker()
    vote = await restarted.recover(slot)
    assert h.calls[0][1] == h.calls[1][1] == vote.admission
    assert restarted.journal.load(slot)[:4] == original[:4]
    # A lost acknowledgement after commit returns the same signature even offline.
    a.chain.clock.now += 180_000
    assert await h.worker().recover(slot) == vote
    assert len(h.calls) == 2


async def test_conflicting_original_or_archive_never_changes_reserved_body(harness):
    h = harness
    h.fail = True
    worker = h.worker()
    with pytest.raises(OSError):
        await worker.attest(h.raw)
    body = json.loads(h.raw)
    body["observation"]["evidence_sha256"] = "ff" * 32
    with pytest.raises(ValueError, match="reserved"):
        await worker.attest(canonical_json_bytes(body))
    with pytest.raises(ValueError, match=r"changed.*evidence"):
        await worker.attest(h.raw, registration_archive=(h.archive.raw, b"wrong"))
    assert len(h.calls) == 1


@pytest.mark.parametrize(
    "failure", ["missing_artifact", "changed_artifact", "changed_intent", "hold"]
)
async def test_corruption_is_detected_before_signature_retry(harness, failure):
    h = harness
    h.fail = True
    worker = h.worker()
    with pytest.raises(OSError):
        await worker.attest(h.raw)
    slot = admission_slot(h.raw)
    with worker.journal.journal.transaction() as db:
        if failure == "missing_artifact":
            db.execute("DELETE FROM records WHERE kind='admission_registration'")
        elif failure == "changed_artifact":
            db.execute(
                "UPDATE records SET body=? WHERE kind='admission_metadata'", (b'{"hex":"00"}',)
            )
        elif failure == "changed_intent":
            raw = db.execute("SELECT body FROM records WHERE kind='admission_intent'").fetchone()[0]
            body = json.loads(raw)
            body["admission"]["uid"] = 1
            db.execute(
                "UPDATE records SET body=? WHERE kind='admission_intent'",
                (canonical_json_bytes(body),),
            )
        else:
            db.execute("INSERT INTO holds VALUES (?)", (slot,))
    with pytest.raises(ValueError):
        await h.worker().recover(slot)
    assert len(h.calls) == 1


async def test_history_rollback_and_revocation_block_new_signing(harness):
    h = harness
    worker = h.worker()
    original = h.source
    h.source = AdmissionHistory(
        transition(
            original.history,
            h.archive.chain.policy,
            "extend",
            h.archive.fresh.height,
            extension=1200,
        )
    )
    h.fail = True
    with pytest.raises(OSError):
        await worker.attest(h.raw)
    h.source = original
    with pytest.raises(ValueError, match="rolled back"):
        await h.worker().recover(admission_slot(h.raw))
    h.source = AdmissionHistory(
        transition(original.history, h.archive.chain.policy, "revoke", h.archive.fresh.height)
    )
    with pytest.raises(ValueError, match="revoked"):
        await h.worker().recover(admission_slot(h.raw))
    assert len(h.calls) == 1


def closed_source(h, *, unselected=False):
    a = h.archive
    history = h.source.history
    policy = a.chain.policy
    seal = build_intake_seal(
        history,
        policy,
        a.expected,
        a.capture.snapshot,
        ((h.receipt.proposed_admission.consent_sha256, h.raw),),
        expected_tip_sha256=history_tip(history),
    )
    if unselected:
        seal = seal.model_copy(
            update={"selected": (seal.selected[0].model_copy(update={"record_sha256": "ff" * 32}),)}
        )
    progress = CohortPhaseProgress(
        schema="umi-cohort-phase-progress/1",
        cohort_sha256=digest(history.plan),
        recovery_tip_sha256=history_tip(history),
        phase="intake",
        observed_at_block=a.old.height,
        unavailable_blocks=0,
        completion="complete",
        phase_result_sha256=digest(seal),
        evidence_sha256=digest(seal),
    )
    evidence = CohortDecisionInput(
        schema="umi-cohort-decision-input/1",
        progress=AttestedCohortPhaseProgress(progress=progress, signatures=signatures(progress)),
        observation=a.expected,
    )
    from umi.competition_cohort_history import verify_cohort_history

    view = verify_cohort_history(
        history, policy, expected_tip_sha256=history_tip(history), current_block=a.old.height
    )
    proposal = propose_recovery_transition(
        view.state,
        history.authority.authority,
        operation="close_phase",
        observed_at_block=a.old.height,
        evidence_sha256=digest(evidence),
    )
    history = history.model_copy(
        update={"transitions": (*history.transitions, signed_transition(proposal))}
    )
    return AdmissionHistory(history, seal, evidence)


@pytest.mark.parametrize("failure", [None, "missing_seal", "unselected", "bad_closure"])
async def test_closed_intake_requires_the_exact_quorum_selected_record(harness, failure):
    h = harness
    h.source = closed_source(h, unselected=failure == "unselected")
    if failure == "missing_seal":
        h.source = replace(h.source, seal=None)
    if failure == "bad_closure":
        p = h.source.closure.progress.model_copy(
            update={"signatures": h.source.closure.progress.signatures[:1]}
        )
        h.source = replace(h.source, closure=h.source.closure.model_copy(update={"progress": p}))
    if failure is None:
        assert (await h.worker().attest(h.raw)).admission == h.receipt.proposed_admission
    else:
        with pytest.raises((ValueError, FileNotFoundError)):
            await h.worker().attest(h.raw)
        assert not h.calls


async def test_capacity_failure_is_retryable_after_enlarging_operational_budget(harness):
    h = harness
    worker = h.worker(maximum_bytes=1024)
    with pytest.raises(ValueError, match="capacity"):
        await worker.attest(h.raw)
    assert not h.calls
    assert (await h.worker().attest(h.raw)).admission == h.receipt.proposed_admission


async def test_two_workers_cannot_sign_concurrently_from_the_same_state(harness):
    h = harness
    first = h.worker()
    second = h.worker()
    entered, released = asyncio.Event(), asyncio.Event()
    sign = first.sign

    async def waiting(body):
        entered.set()
        await released.wait()
        return await sign(body)

    first.sign = waiting
    task = asyncio.create_task(first.attest(h.raw))
    try:
        await asyncio.wait_for(entered.wait(), 2)
        with pytest.raises(BlockingIOError):
            await second.attest(h.raw)
    finally:
        released.set()
    vote = await task
    assert await second.attest(h.raw) == vote and len(h.calls) == 1


async def test_cancellation_drains_signing_before_unlock_and_retry(harness):
    h = harness
    worker = h.worker()
    other = h.worker()
    entered, release = threading.Event(), threading.Event()

    def blocking(body):
        entered.set()
        assert release.wait(5)
        return sign_object(body, wallet("Charlie"))

    async def sign(body):
        return await run_owned_thread(blocking, body)

    worker.sign = sign
    task = asyncio.create_task(worker.attest(h.raw))
    try:
        for _ in range(1000):
            if entered.is_set():
                break
            if task.done():
                await task
            await asyncio.sleep(0.001)
        assert entered.is_set()
        task.cancel()
        await asyncio.sleep(0.02)
        with pytest.raises(BlockingIOError):
            await other.attest(h.raw)
    finally:
        release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    saved = other.journal.load(admission_slot(h.raw))
    assert saved[4] is None
    assert (await other.recover(admission_slot(h.raw))).admission == saved[0].admission


async def test_failed_reservation_transaction_rolls_back_before_signing(harness, monkeypatch):
    h = harness
    worker = h.worker()
    put = worker.journal.journal.put_many

    def failed_commit(records, *, index=None):
        records = tuple(records)
        if any(kind == "admission_intent" for kind, _, _ in records):

            def fail(db):
                assert (
                    db.execute(
                        "SELECT COUNT(*) FROM records WHERE kind='admission_intent'"
                    ).fetchone()[0]
                    == 1
                )
                raise OSError("reservation transaction interrupted")

            return put(records, index=fail)
        return put(records, index=index)

    monkeypatch.setattr(worker.journal.journal, "put_many", failed_commit)
    with pytest.raises(OSError, match="reservation"):
        await worker.attest(h.raw)
    assert not h.calls
    assert worker.journal.load(admission_slot(h.raw)) is None
    assert not worker.journal.journal.keys("admission_record")
    assert (await h.worker().attest(h.raw)).admission == h.receipt.proposed_admission


@pytest.mark.parametrize("committed", [False, True])
async def test_vote_commit_failure_or_lost_ack_recovers_exact_body(harness, monkeypatch, committed):
    h = harness
    worker = h.worker()
    commit = worker.journal.commit

    def fail(slot, vote):
        if committed:
            commit(slot, vote)
        raise OSError("vote commit response lost")

    monkeypatch.setattr(worker.journal, "commit", fail)
    with pytest.raises(OSError, match="vote commit"):
        await worker.attest(h.raw)
    saved = worker.journal.load(admission_slot(h.raw))
    assert (saved[4] is not None) is committed
    vote = await h.worker().recover(admission_slot(h.raw))
    assert vote.admission == h.calls[0][1]
    assert len(h.calls) == (1 if committed else 2)
    if committed:
        assert vote == saved[4]


@pytest.mark.parametrize("failure", ["wrong_signer", "wrong_body"])
async def test_invalid_signer_response_does_not_commit_a_vote(harness, failure):
    h = harness
    worker = h.worker()

    async def invalid(body):
        if failure == "wrong_body":
            body = body.model_copy(update={"uid": 1})
        return sign_object(body, wallet("Dave" if failure == "wrong_signer" else "Charlie"))

    worker.sign = invalid
    with pytest.raises(ValueError):
        await worker.attest(h.raw)
    assert worker.journal.load(admission_slot(h.raw))[4] is None
    assert (
        await h.worker().recover(admission_slot(h.raw))
    ).admission == h.receipt.proposed_admission


async def test_history_change_during_review_retries_before_signing(harness):
    h = harness
    worker = h.worker()
    calls = 0
    extended = AdmissionHistory(
        transition(
            h.source.history,
            h.archive.chain.policy,
            "extend",
            h.archive.fresh.height,
            extension=1200,
        )
    )

    async def history(cohort):
        nonlocal calls
        calls += 1
        return h.source if calls == 1 else extended

    worker.history = history
    with pytest.raises(OSError, match="history changed"):
        await worker.attest(h.raw)
    assert not h.calls and worker.journal.load(admission_slot(h.raw)) is None
    h.source = extended
    assert (await h.worker().attest(h.raw)).admission == h.receipt.proposed_admission


async def test_signer_reviews_peer_archive_without_own_registration_capture(harness):
    h = harness
    with sqlite3.connect(h.archive.reviewer._path) as db:
        db.execute("DELETE FROM captures")
        db.execute("DELETE FROM artifacts")
    worker = h.worker()
    with pytest.raises(FileNotFoundError):
        await worker.attest(h.raw)
    with pytest.raises(ValueError):
        await worker.attest(h.raw, registration_archive=(h.archive.raw, b"wrong metadata"))
    assert not h.calls and worker.journal.load(admission_slot(h.raw)) is None
    vote = await worker.attest(h.raw, registration_archive=(h.archive.raw, h.archive.metadata))
    assert vote.admission == h.receipt.proposed_admission


async def test_cancellation_drains_reservation_before_unlock_without_signing(harness, monkeypatch):
    h = harness
    worker, other = h.worker(), h.worker()
    reserve = worker.journal.reserve
    entered, release = threading.Event(), threading.Event()

    def blocking(*args):
        entered.set()
        assert release.wait(5)
        return reserve(*args)

    monkeypatch.setattr(worker.journal, "reserve", blocking)
    task = asyncio.create_task(worker.attest(h.raw))
    try:
        for _ in range(1000):
            if entered.is_set():
                break
            if task.done():
                await task
            await asyncio.sleep(0.001)
        assert entered.is_set()
        task.cancel()
        await asyncio.sleep(0.02)
        with pytest.raises(BlockingIOError):
            await other.attest(h.raw)
    finally:
        release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert not h.calls
    assert other.journal.load(admission_slot(h.raw))[4] is None
    assert (await other.recover(admission_slot(h.raw))).admission == h.receipt.proposed_admission


async def test_signing_timeout_leaves_original_intent_retryable(harness):
    h = harness
    worker = h.worker(signing_timeout_seconds=1)
    cancelled = asyncio.Event()

    async def slow(body):
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    worker.sign = slow
    with pytest.raises(TimeoutError):
        await worker.attest(h.raw)
    assert cancelled.is_set()
    assert worker.journal.load(admission_slot(h.raw))[4] is None
    assert (
        await h.worker().recover(admission_slot(h.raw))
    ).admission == h.receipt.proposed_admission


async def test_certificate_rejects_mixed_bodies(harness):
    h = harness
    first, second = [await h.worker(name).attest(h.raw) for name in ("Charlie", "Dave")]
    other = second.admission.model_copy(update={"uid": 1})
    second = second.model_copy(
        update={"admission": other, "signature": sign_object(other, wallet("Dave"))}
    )
    with pytest.raises(ValueError, match="different bodies"):
        certify_admission([first, second], h.archive.chain.policy)


async def test_vote_capacity_preserves_prior_and_resumes_after_increase(harness, scenario):
    h = harness
    first = h.worker(maximum_votes=1)
    vote = await first.attest(h.raw)
    intake = CohortIntake(h.intake_config, h.archive.chain.policy)
    request = request_for(scenario, block=h.archive.old.height)
    bob = wallet("Bob")
    sub = request.signed_submission.submission.model_copy(
        update={"hotkey": bob.hotkey.ss58_address}
    )
    consent = request.consent.consent.model_copy(
        update={"hotkey": sub.hotkey, "submission_sha256": digest(sub)}
    )
    request = request.model_copy(
        update={
            "signed_submission": request.signed_submission.__class__(
                submission=sub, signature=sign_object(sub, bob)
            ),
            "consent": request.consent.__class__(
                consent=consent, signature=sign_object(consent, bob)
            ),
        }
    )
    intake.retain(request, h.archive.capture)
    with intake._connection() as (db, _):
        records = tuple(raw for _, raw in intake._records(db, h.source.history))
    second = next(
        raw for raw in records if read_participation(raw).proposed_admission != vote.admission
    )
    with pytest.raises(ValueError, match="vote capacity"):
        await first.attest(second)
    assert first.journal.load(admission_slot(second)) is None
    assert await first.attest(h.raw) == vote
    assert len(h.calls) == 1
    enlarged = h.worker(maximum_votes=2)

    async def sign(body):
        saved = enlarged.journal.load(admission_slot(second))
        assert saved[0].admission == body and saved[1] == second
        return sign_object(body, wallet("Charlie"))

    enlarged.sign = sign
    assert (await enlarged.attest(second)).admission == read_participation(
        second
    ).proposed_admission
    assert await enlarged.attest(h.raw) == vote
