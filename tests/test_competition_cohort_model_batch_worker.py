"""Native batch ownership, durable recovery and bounded async lifetimes."""

import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi.competition_cohort_admission_deadline import (
    OperatorAdmissionDeadline,
    PendingReservedAdmissions,
)
from umi.competition_cohort_admission_journal import CohortAdmissionVote
from umi.competition_cohort_admission_queue import CohortAdmissionQueue
from umi.competition_cohort_intake import CohortIntake, history_tip
from umi.competition_cohort_intake_records import read_participation
from umi.competition_cohort_model_acceptance_store import (
    CohortModelAcceptances,
    PendingModelArtifacts,
)
from umi.competition_cohort_model_acceptance_worker import ModelAcceptanceWorker
from umi.competition_cohort_model_batch import (
    SignedModelBatchCertificationAdoption,
    prepare_model_batch_certification_adoption,
)
from umi.competition_cohort_model_batch_review import ModelBatchArtifactVote
from umi.competition_cohort_model_batch_store import CohortModelBatchStore
from umi.competition_cohort_model_batch_worker import ModelBatchAcceptanceWorker
from umi.competition_cohort_recovery import (
    CohortEvaluationSuiteAdoption,
    propose_recovery_transition,
)
from umi.open_competition import digest, sign_object
from umi.private_files import publish_private_model
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_intake import capture_at, seal_and_close
from .test_competition_cohort_model_acceptance import base_policy as base_policy
from .test_competition_cohort_model_acceptance import certify, replace_model_submission
from .test_competition_cohort_model_acceptance import legacy_scenario as legacy_scenario
from .test_competition_cohort_model_acceptance import policy as policy
from .test_competition_cohort_model_acceptance import prepared as prepared
from .test_competition_cohort_model_acceptance import receipt_scenario as receipt_scenario
from .test_competition_cohort_model_acceptance import recovery as recovery
from .test_competition_cohort_model_acceptance import runtime as runtime
from .test_competition_cohort_recovery import signatures, signed_transition
from .test_open_competition import wallet

pytestmark = pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True)


@pytest.fixture
def batch_owner(prepared, tmp_path):
    owner, cohort, subs, inputs = prepared
    history = owner.intake.history(cohort)
    deadline = OperatorAdmissionDeadline(
        schema="umi-cohort-operator-admission-deadline/1",
        cohort_sha256=cohort,
        authority_sha256=digest(history.authority.authority),
        authorized_history_tip_sha256=history_tip(history),
        close_new_admissions_at_unix_ms=1,
        source_sha256="a1" * 32,
        operator_plan_sha256="b2" * 32,
        reason="Retained operator deadline for deterministic fixture",
    )
    owner.intake = CohortIntake(
        owner.intake.config.model_copy(update={"admission_deadlines": (deadline,)}),
        owner.intake.policy,
        eligible_tracks=owner.intake.tracks,
    )
    state = SimpleNamespace(pending=0, captures=0, calls=[], promoted=[])
    owner.intake.pending_admission_uploads = lambda *args: {
        "completed": 2,
        "total": 2 + state.pending,
        "pending": state.pending,
    }
    body = prepare_model_batch_certification_adoption(
        history,
        owner.intake.policy,
        expected_tip_sha256=history_tip(history),
        effective_at_block=221,
    )
    adoption = SignedModelBatchCertificationAdoption(adoption=body, signatures=signatures(body))

    async def capture():
        state.captures += 1
        return capture_at(230)

    async def promote(publication):
        state.promoted.append(publication.certificate.acceptance.submission_sha256)

    def peer(name):
        async def attest(request):
            state.calls.append((name, digest(request)))
            return ModelBatchArtifactVote(
                batch=request.batch, signature=sign_object(request.batch, wallet(name))
            )

        return SimpleNamespace(signer=wallet(name).hotkey.ss58_address, attest_batch=attest)

    worker = SimpleNamespace(
        owner=owner,
        capture=capture,
        inputs=tmp_path / "inputs",
        output=tmp_path / "output",
        prepare_review=None,
        promote=promote,
        reviewers=(peer("Charlie"), peer("Dave")),
    )
    publish_private_model(worker.inputs / "model-reviews" / (inputs.model_sha256 + ".json"), inputs)
    return SimpleNamespace(
        owner=owner,
        cohort=cohort,
        subs=subs,
        inputs=inputs,
        adoption=adoption,
        worker=worker,
        state=state,
        create=lambda: ModelBatchAcceptanceWorker(worker, tmp_path / "adoptions"),
    )


async def test_real_batch_preserves_prior_individual_publication_and_older_intents(batch_owner):
    r = batch_owner
    original = r.owner.publish(certify(r.owner, r.cohort, r.subs[0], r.inputs), capture_at(220))
    original_bytes = canonical_json_bytes(original)
    earlier = r.owner.prepare(r.cohort, digest(r.subs[1]), r.inputs, capture_at(220))
    report = await r.create().poll_cohort(r.cohort, r.adoption)
    assert report["completed"] == report["total"] == 2
    assert len(r.state.calls) == 2 and len({key for _, key in r.state.calls}) == 1
    assert r.state.promoted == [digest(r.subs[1])]
    reopened = CohortModelAcceptances(r.owner.intake, r.owner.archive)
    assert canonical_json_bytes(reopened.retained(r.cohort, digest(r.subs[0]))) == original_bytes
    late = reopened.retained(r.cohort, digest(r.subs[1]))
    assert late.certificate.acceptance == earlier
    assert late.certificate.batch_proof.certificate.batch.certified_at_block == 230
    assert earlier.accepted_at_block == 220
    assert reopened.export(r.cohort, digest(r.subs[1]), r.worker.output) == late


@pytest.mark.parametrize("deadline", ["open", "absent", "closed"])
async def test_prospective_selection_preserves_scalar_intake_until_retained_cutoff(
    batch_owner, monkeypatch, deadline
):
    r = batch_owner
    batch = r.create()
    publish_private_model(batch.directory / (r.cohort + ".json"), r.adoption)
    if deadline == "absent":
        r.owner.intake._admission_deadlines.clear()
    elif deadline == "open":
        original = r.owner.intake._admission_deadlines[r.cohort]
        r.owner.intake._admission_deadlines[r.cohort] = original.model_copy(
            update={"close_new_admissions_at_unix_ms": 9999999999999}
        )
    worker = ModelAcceptanceWorker(
        r.owner,
        r.worker.capture,
        r.worker.inputs,
        r.worker.output,
        batch_certification_adoptions_directory=batch.directory,
    )
    scalar, final = [], []

    async def scalar_review(cohort, submission):
        assert deadline != "closed", "closed selected cohort must use final batch"
        scalar.append(digest(submission))

    async def final_batch(cohort, adoption):
        assert deadline == "closed", "open intake must retain independent scalar review"
        final.append(cohort)
        return {"status": "completed"}

    monkeypatch.setattr(worker, "_one", scalar_review)
    monkeypatch.setattr(worker.batch_worker, "poll_cohort", final_batch)
    await worker.poll_once()
    assert set(scalar) == (set() if deadline == "closed" else {digest(s) for s in r.subs})
    assert final == ([r.cohort] if deadline == "closed" else [])
    assert r.state.captures == 0


async def test_completed_batch_restarts_after_phase_advance_without_capture_or_reselection(
    batch_owner, monkeypatch
):
    r = batch_owner
    first = await r.create().poll_cohort(r.cohort, r.adoption)
    history = r.owner.intake.history(r.cohort)
    closed, evidence, _ = seal_and_close(
        r.owner.intake, {"intake_history": history, "policy": r.owner.intake.policy}
    )
    r.owner.intake.publish(closed, capture_at(300), closure_input=evidence)

    def forbidden(*args, **kwargs):
        raise AssertionError("completed historical cohort must reuse durable result")

    monkeypatch.setattr(r.owner, "review_request", forbidden)
    monkeypatch.setattr(CohortModelBatchStore, "_selected", forbidden)
    monkeypatch.setattr(r.worker, "capture", forbidden)
    monkeypatch.setattr(r.owner, "ensure_payload", forbidden)
    assert await r.create().poll_cohort(r.cohort, r.adoption) == first


@pytest.mark.parametrize("damage", ["export", "completion", "manifest", "request"])
async def test_completed_batch_corruption_is_explicit_repair(batch_owner, damage):
    r = batch_owner
    await r.create().poll_cohort(r.cohort, r.adoption)
    with r.owner.intake._connection() as (db, _):
        if damage == "export":
            db.execute(
                "DELETE FROM cohort_model_batch_records "
                "WHERE kind LIKE 'export:%' AND record_key=?",
                (digest(r.subs[0]),),
            )
        elif damage == "completion":
            db.execute(
                "UPDATE cohort_model_batch_records SET body=? WHERE kind='completion'",
                (canonical_json_bytes({"invalid": True}),),
            )
        else:
            db.execute("DELETE FROM cohort_model_batch_records WHERE kind=?", (damage,))
    with pytest.raises(ValueError, match="repair required"):
        await r.create().poll_cohort(r.cohort, r.adoption)


@pytest.mark.parametrize("case", ["missing", "future", "pending"])
def test_final_batch_requires_closed_new_issuance_and_drained_reservations(batch_owner, case):
    r = batch_owner
    if case == "missing":
        r.owner.intake._admission_deadlines.clear()
    elif case == "future":
        selected = r.owner.intake._admission_deadlines[r.cohort]
        r.owner.intake._admission_deadlines[r.cohort] = selected.model_copy(
            update={
                "close_new_admissions_at_unix_ms": 2**62,
            }
        )
    else:
        r.state.pending = 1
    store = r.create().store
    assert store.selected(r.cohort).submissions
    with pytest.raises((PendingModelArtifacts, PendingReservedAdmissions)):
        store.selected(r.cohort, require_drained=True)


async def test_preparation_reuses_inputs_and_serial_intents_after_reservation_drain(
    batch_owner, monkeypatch
):
    r = batch_owner
    r.state.pending = 1
    worker = r.create()
    native = r.owner.prepare
    prepared_calls = []

    def prepare(*args):
        prepared_calls.append(args[1])
        return native(*args)

    monkeypatch.setattr(r.owner, "prepare", prepare)
    with pytest.raises(PendingReservedAdmissions):
        await worker.poll_cohort(r.cohort, r.adoption)
    assert len(prepared_calls) == 2
    assert worker.store.retained_request(r.cohort, r.adoption) is None
    r.state.pending = 0
    await r.create().poll_cohort(r.cohort, r.adoption)
    assert len(prepared_calls) == 2


async def test_replacement_before_finalization_reuses_unchanged_intent_and_selects_latest(
    batch_owner, monkeypatch
):
    r = batch_owner
    monkeypatch.setattr("umi.competition_cohort_intake.time.time_ns", lambda: 0)
    worker = r.create()
    with pytest.raises(PendingModelArtifacts, match="new-admission closure"):
        await worker.poll_cohort(r.cohort, r.adoption)
    unchanged = r.owner.intent(r.cohort, digest(r.subs[1]))
    replacement = replace_model_submission(r.owner, r.cohort, r.subs[0])
    queue = CohortAdmissionQueue(r.owner.intake)
    key, _ = next((k, s) for k, s in r.owner.entries(r.cohort) if s == replacement)
    record = read_participation(queue.record(r.cohort, key))
    for signature in signatures(record.proposed_admission):
        queue.publish_vote(
            CohortAdmissionVote(admission=record.proposed_admission, signature=signature),
            capture_at(230),
        )
    monkeypatch.setattr("umi.competition_cohort_intake.time.time_ns", lambda: 2_000_000)
    await r.create().poll_cohort(r.cohort, r.adoption)
    assert r.owner.intent(r.cohort, digest(r.subs[1])) == unchanged
    retained = r.create().store.retained_request(r.cohort, r.adoption)
    assert {q.acceptance.submission_sha256 for q in retained.requests} == {
        digest(replacement),
        digest(r.subs[1]),
    }
    assert all(q.acceptance.submission_sha256 != digest(r.subs[0]) for q in retained.requests)


async def test_two_reviewers_overlap_and_individual_vote_survives_lost_response(batch_owner):
    r = batch_owner
    worker = r.create()
    request = await worker._prepare(r.cohort, r.adoption)
    entered = asyncio.Event()
    calls = []
    first, second = r.worker.reviewers
    first_attest, second_attest = first.attest_batch, second.attest_batch

    async def left(req):
        calls.append("left")
        await asyncio.wait_for(entered.wait(), 5)
        return await first_attest(req)

    async def right(req):
        calls.append("right")
        entered.set()
        raise OSError("lost response")

    first.attest_batch, second.attest_batch = left, right
    with pytest.raises(PendingModelArtifacts):
        await worker._quorum(request)
    assert set(calls) == {"left", "right"}
    assert len(worker.store.votes(request)) == 1
    second.attest_batch = second_attest
    manifest = await r.create()._quorum(request)
    assert len(manifest.certificate.signatures) == 2
    assert calls == ["left", "right"]


async def test_interrupted_publication_resumes_only_unfinished_member(batch_owner):
    r = batch_owner
    failed = digest(r.subs[0])
    attempts = []

    async def interrupted(publication):
        key = publication.certificate.acceptance.submission_sha256
        attempts.append(key)
        if key == failed:
            raise OSError("temporary destination unavailable")

    r.worker.promote = interrupted
    with pytest.raises(PendingModelArtifacts):
        await r.create().poll_cohort(r.cohort, r.adoption)
    assert set(attempts) == {digest(sub) for sub in r.subs}

    async def repaired(publication):
        attempts.append(publication.certificate.acceptance.submission_sha256)

    r.worker.promote = repaired
    report = await r.create().poll_cohort(r.cohort, r.adoption)
    assert report["status"] == "completed"
    assert attempts.count(failed) == 2
    assert attempts.count(digest(r.subs[1])) == 1
    assert len(r.state.calls) == 2


async def test_frozen_batch_retains_vote_and_header_after_authenticated_intake_amendment(
    batch_owner,
):
    r = batch_owner
    worker = r.create()
    request = await worker._prepare(r.cohort, r.adoption)
    peer = r.worker.reviewers[1]
    original_attest = peer.attest_batch

    async def unavailable(_):
        raise OSError("reviewer temporarily unavailable")

    peer.attest_batch = unavailable
    with pytest.raises(PendingModelArtifacts):
        await worker._quorum(request)
    prior_vote = worker.store.votes(request)[0]
    history = r.owner.intake.history(r.cohort)
    with r.owner.intake._connection() as (_, store):
        state, _ = store.status(r.cohort)
    suite = CohortEvaluationSuiteAdoption(
        schema="umi-cohort-evaluation-suite-adoption/1",
        original_plan=history.plan,
        previous_suite_sha256=history.plan.suite_sha256,
        suite_sha256="4a" * 32,
        selection_manifest_sha256="4b" * 32,
    )
    amendment = propose_recovery_transition(
        state,
        history.authority.authority,
        operation="adopt_evaluation_suite",
        observed_at_block=240,
        evidence_sha256=digest(suite),
        evaluation_suite_adoption=suite,
    )
    r.owner.intake.publish(
        history.model_copy(
            update={
                "transitions": (*history.transitions, signed_transition(amendment)),
            }
        ),
        capture_at(240),
    )

    async def capture():
        return capture_at(250)

    r.worker.capture = capture
    peer.attest_batch = original_attest
    resumed = r.create()
    assert resumed.store.retained_request(r.cohort, r.adoption) == request
    assert (await resumed.poll_cohort(r.cohort, r.adoption))["status"] == "completed"
    assert prior_vote in resumed.store.votes(request)
    assert len(r.state.calls) == 2
    for sub in r.subs:
        publication = r.owner.retained(r.cohort, digest(sub))
        assert publication.certificate.batch_proof.certificate.batch == request.batch
        assert publication.certificate.acceptance.accepted_at_block == 230


async def test_lost_final_checkpoint_recovers_exports_without_new_capture(batch_owner, monkeypatch):
    r = batch_owner
    worker = r.create()

    def interrupted(*args):
        raise OSError("interrupted after export commits")

    monkeypatch.setattr(worker.store, "mark_completed", interrupted)
    with pytest.raises(OSError, match="after export"):
        await worker.poll_cohort(r.cohort, r.adoption)

    def forbidden(*args):
        raise AssertionError("all exports complete: no new capture or preparation")

    monkeypatch.setattr(r.worker, "capture", forbidden)
    monkeypatch.setattr(r.owner, "prepare", forbidden)
    report = await r.create().poll_cohort(r.cohort, r.adoption)
    assert report["status"] == "completed"
    assert len(r.state.calls) == 2


async def test_unexpected_reviewer_error_drains_sibling_checkpoint(batch_owner):
    r = batch_owner
    worker = r.create()
    request = await worker._prepare(r.cohort, r.adoption)
    started, release = asyncio.Event(), asyncio.Event()
    first, second = r.worker.reviewers
    native = second.attest_batch

    async def broken(req):
        await started.wait()
        raise TypeError("unexpected reviewer fault")

    async def slow(req):
        started.set()
        await release.wait()
        return await native(req)

    first.attest_batch, second.attest_batch = broken, slow
    task = asyncio.create_task(worker._quorum(request))
    await started.wait()
    await asyncio.sleep(0)
    assert not task.done()
    release.set()
    with pytest.raises(TypeError, match="unexpected reviewer fault"):
        await task
    assert len(worker.store.votes(request)) == 1


@pytest.mark.parametrize("cancel", [False, True])
async def test_bounded_work_drains_siblings_before_exception_or_cancellation(batch_owner, cancel):
    worker = batch_owner.create()
    started, release, durable = asyncio.Event(), asyncio.Event(), []

    async def operation(item):
        if item == 0:
            await started.wait()
            if not cancel:
                raise TypeError("unexpected preparation fault")
        else:
            started.set()
            await release.wait()
            durable.append(item)

    task = asyncio.create_task(
        worker._bounded((0, 1), operation, cohort=batch_owner.cohort, stage="test_owned_batch")
    )
    await started.wait()
    if cancel:
        task.cancel()
    await asyncio.sleep(0)
    assert not task.done()
    release.set()
    with pytest.raises(asyncio.CancelledError if cancel else TypeError):
        await task
    assert durable == [1]


async def test_bounded_preparation_never_exceeds_ten_and_completes_out_of_order(batch_owner):
    worker = batch_owner.create()
    active, maximum, finished = 0, 0, []
    saturated, release = asyncio.Event(), asyncio.Event()

    async def operation(item):
        nonlocal active, maximum
        active += 1
        maximum = max(maximum, active)
        if active == 10:
            saturated.set()
        await release.wait()
        if item == 0:
            await asyncio.sleep(0.01)
        finished.append(item)
        active -= 1

    task = asyncio.create_task(
        worker._bounded(
            range(23), operation, cohort=batch_owner.cohort, stage="test_bounded_preparation"
        )
    )
    await asyncio.wait_for(saturated.wait(), 5)
    assert maximum == 10
    release.set()
    await task
    assert maximum == 10 and sorted(finished) == list(range(23))
    assert finished[-1] == 0


async def test_malformed_export_checkpoint_cannot_skip_publication(batch_owner):
    r = batch_owner
    worker = r.create()
    request = await worker._prepare(r.cohort, r.adoption)
    key = request.requests[0].acceptance.submission_sha256
    with r.owner.intake._connection() as (db, _):
        worker.store._put(
            db,
            r.cohort,
            "export:" + digest(request.batch),
            key,
            {
                "destination": str(r.worker.output),
                "submission_sha256": key,
                "batch_sha256": digest(request.batch),
                "publication_sha256": "invalid",
            },
        )
    with pytest.raises(ValueError, match="checkpoint changed"):
        worker.store.exported(request, key, r.worker.output)


@pytest.mark.parametrize("concurrency", [0, 17, True, 1.5, "10"])
def test_worker_rejects_unbounded_preparation(batch_owner, concurrency):
    with pytest.raises(ValueError, match="outside bounds"):
        ModelBatchAcceptanceWorker(batch_owner.worker, Path("unused"), concurrency=concurrency)
