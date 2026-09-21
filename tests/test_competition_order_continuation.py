from __future__ import annotations

import json
import sqlite3
from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi import competition_work_signing as signing
from umi.competition_artifacts import preserve_bundle
from umi.competition_dispatch_capacity import capacity_job
from umi.competition_publication import PublicationReplayLimits
from umi.competition_review_history import EvaluatorReviewStore
from umi.competition_scheduling import assignment_key
from umi.competition_work_plans import evaluation_order_proposals
from umi.open_competition import digest, identity, verify_signature
from umi.protocol import canonical_json_bytes

from .test_competition_work_plans import sign_publications, two_endpoint_work
from .test_competition_work_signing import chain_config as chain_config
from .test_competition_work_signing import policy as policy
from .test_competition_work_signing import runtime as runtime
from .test_competition_work_signing import setup as setup
from .test_competition_work_signing import work as _work_fixture

work_fixture = _work_fixture


@pytest.fixture
def work(work_fixture, request):
    return two_endpoint_work(work_fixture) if getattr(request, "param", False) else work_fixture


def _reservation_bytes(journal):
    with sqlite3.connect(journal.path) as db:
        return {
            name: db.execute(f"SELECT * FROM {name} ORDER BY 1").fetchall()
            for (name,) in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'reservation_%'"
            ).fetchall()
        }


def _corrupt(path, sql, args=()):
    """Damage only a disposable fixture, restoring fences to test binding checks."""
    with sqlite3.connect(path) as db:
        triggers = db.execute("SELECT name,sql FROM sqlite_master WHERE type='trigger'").fetchall()
        for name, _ in triggers:
            db.execute(f'DROP TRIGGER "{name}"')
        db.execute(sql, args)
        for _, definition in triggers:
            db.execute(definition)


def _head(setup, milliseconds=100_001):
    setup.clock.now += milliseconds
    signer, worker = setup.signers[0], setup.workers[0]
    signer.transport_provider.head = replace(
        signer.transport_provider.head,
        height=signer.transport_provider.head.height + 1,
        timestamp_ms=setup.clock.now,
    )
    worker.provider.block = signer.transport_provider.head.height
    return signer.transport_provider.head


async def _admitted(setup, *, claim=True):
    signer, worker = setup.signers[0], setup.workers[0]
    await signer.endorse(setup.authorization)
    plan_id = digest(setup.work.plan)
    receipt = worker.dispatch.reservation(plan_id, evaluator_hotkey=worker.config.evaluator_hotkey)
    complete = signer.admission.journal.get("complete", plan_id)
    head = _head(setup)
    publication = setup.endpoint.body.publication
    worker.dispatch.publish(
        publication,
        observed=head,
        announcements=(setup.work.options["announcement"],),
    )
    assignment = next(
        a
        for a in publication.publication.assignments
        if identity(a.evaluator_hotkey) == identity(worker.config.evaluator_hotkey)
    )
    with sqlite3.connect(worker.dispatch.path) as db:
        qualification = json.loads(
            db.execute("SELECT document FROM reservation_qualifications").fetchone()[0]
        )
    claim_args = {
        "key": assignment_key(publication, assignment),
        "observed": head,
        "issuance": setup.work.options["issuance"],
        "expected_dispatch_profile": qualification["plan"]["profile_sha256"],
    }
    token = worker.dispatch.claim(**claim_args) if claim else None
    return SimpleNamespace(
        signer=signer,
        worker=worker,
        plan_id=plan_id,
        receipt=receipt,
        complete=complete,
        head=head,
        token=token,
        claim_args=claim_args,
        qualification=qualification,
    )


@pytest.mark.parametrize("restart", [False, True])
async def test_late_exact_order_signs_during_dispatch_without_changing_reservations(
    setup, monkeypatch, restart
):
    fixture = await _admitted(setup)
    worker, signer = fixture.worker, fixture.signer
    journal = worker.dispatch
    with pytest.raises(ValueError, match="prior claim outcome"):
        journal.reservation(fixture.plan_id, evaluator_hotkey=worker.config.evaluator_hotkey)
    before = _reservation_bytes(journal)
    events = journal.events(fixture.token.assignment_key)
    proof_allowance = journal._proof_allowance
    with journal._transaction() as db:
        assert proof_allowance(db) > 0
    if restart:
        signer = signing.IndependentWorkSigner(
            worker,
            signer.cutoffs,
            minimum_issue_ms=signer.minimum_issue_ms,
            legacy=signer.legacy,
            transport_provider=signer.transport_provider,
        )

    def no_new_dispatch(**kwargs):
        pytest.fail("evaluation continuation attempted dispatch admission")

    monkeypatch.setattr(journal, "reserve_batch", no_new_dispatch)
    vote = await signer.endorse(setup.endpoint)
    verify_signature(setup.endpoint.body, vote.signature)
    assert signer.admission.verify(setup.work.plan, order=setup.endpoint.body) == fixture.complete
    assert (
        journal.retained_reservation(
            fixture.plan_id, evaluator_hotkey=worker.config.evaluator_hotkey
        )
        == fixture.receipt
    )
    assert _reservation_bytes(journal) == before
    assert journal.events(fixture.token.assignment_key) == events
    assert journal.status(fixture.token.assignment_key)["state"] == "uncertain_dispatched"
    with pytest.raises(ValueError, match="uncertain work is never retried"):
        journal.claim(**fixture.claim_args)
    with journal._transaction() as db:
        assert proof_allowance(db) > 0
    assert await signer.endorse(setup.endpoint) == vote


async def test_existing_order_does_not_recharge_a_failed_remaining_timing_envelope(setup):
    fixture = await _admitted(setup, claim=False)
    job = capacity_job(
        setup.authorization.body, setup.authorization.body.assignments[0], fixture.worker.legacy
    )
    # The original issue gate is still open, but insufficient time remains for
    # the conservative whole-dispatch envelope and its deadline reserve.
    _head(setup, job.issue_close_ms - setup.clock.now - 2000)
    fixture.worker.dispatch.observe(observed=fixture.signer.transport_provider.head)
    with pytest.raises(ValueError, match=r"cannot fit|deadline reserve"):
        fixture.worker.dispatch.reservation(
            fixture.plan_id, evaluator_hotkey=fixture.worker.config.evaluator_hotkey
        )
    assert await fixture.signer.endorse(setup.endpoint)


@pytest.mark.parametrize("record", ["manifest", "complete"])
async def test_missing_completed_admission_cannot_use_continuation(setup, record):
    fixture = await _admitted(setup)
    _corrupt(fixture.signer.admission.journal.path, "DELETE FROM records WHERE kind=?", (record,))
    with pytest.raises(ValueError, match=r"complete|manifest|prior claim outcome"):
        await fixture.signer.endorse(setup.endpoint)
    assert fixture.signer.journal.get("intent", signing.statement_slot(setup.endpoint)) is None
    with pytest.raises(ValueError, match=r"complete|manifest"):
        fixture.signer.admission.reserve(
            setup.work.plan, (setup.authorization.body,), setup.endpoint.body, continuing_order=True
        )


async def test_partial_native_admission_cannot_be_promoted_to_continuation(setup, monkeypatch):
    signer, worker = setup.signers[0], setup.workers[0]
    reserve = worker.journal.reserve_orders

    def interrupted(*args):
        reserve(*args)
        raise RuntimeError("interrupted after native commit")

    with monkeypatch.context() as patch:
        patch.setattr(worker.journal, "reserve_orders", interrupted)
        with pytest.raises(RuntimeError, match="interrupted"):
            await signer.endorse(setup.authorization)
    assert signer.admission.journal.get("manifest", digest(setup.work.plan)) is not None
    with pytest.raises(ValueError, match="requires complete"):
        signer.admission.reserve(
            setup.work.plan, (setup.authorization.body,), setup.endpoint.body, continuing_order=True
        )
    assert signer.journal.get("intent", signing.statement_slot(setup.endpoint)) is None


@pytest.mark.parametrize("owner", ["signing", "execution", "evaluator", "dispatch"])
async def test_continuation_still_requires_every_native_receipt(setup, monkeypatch, owner):
    fixture = await _admitted(setup)
    stores = {
        "signing": fixture.signer.journal,
        "execution": fixture.worker.executions,
        "evaluator": fixture.worker.journal,
        "dispatch": fixture.worker.dispatch,
    }
    method = "retained_reservation" if owner == "dispatch" else "reservation"
    monkeypatch.setattr(stores[owner], method, lambda *args, **kwargs: None)
    with pytest.raises(ValueError, match="native reservation receipt"):
        await fixture.signer.endorse(setup.endpoint)
    assert fixture.signer.journal.get("intent", signing.statement_slot(setup.endpoint)) is None


@pytest.mark.parametrize(
    "mutation",
    [
        "complete",
        "qualification",
        "allowance",
        "assignment",
        "proof",
        "consumption",
        "profile",
        "order_allowance",
    ],
)
async def test_continuation_rejects_changed_native_bindings(setup, mutation):
    fixture = await _admitted(setup)
    journal = fixture.worker.dispatch
    if mutation == "complete":
        changed = {**fixture.complete, "manifest_sha256": "aa" * 32}
        _corrupt(
            fixture.signer.admission.journal.path,
            "UPDATE records SET body=? WHERE kind='complete'",
            (canonical_json_bytes(changed),),
        )
    elif mutation == "qualification":
        changed = {
            **fixture.qualification,
            "qualified_at_unix_ms": fixture.qualification["qualified_at_unix_ms"] - 1,
        }
        _corrupt(
            journal.path,
            "UPDATE reservation_qualifications SET document=?",
            (canonical_json_bytes(changed),),
        )
    elif mutation == "allowance":
        _corrupt(journal.path, "UPDATE reservation_publications SET allowance=allowance+1")
    elif mutation == "assignment":
        _corrupt(
            journal.path,
            "DELETE FROM reservation_assignments WHERE id=?",
            (fixture.token.assignment_key,),
        )
    elif mutation == "proof":
        _corrupt(
            journal.path,
            "DELETE FROM blocks WHERE height=?",
            (setup.work.options["announcement"].height,),
        )
    elif mutation == "consumption":
        _corrupt(journal.path, "DELETE FROM reservation_consumptions")
    elif mutation == "profile":
        _corrupt(journal.path, "DELETE FROM metadata WHERE key LIKE 'dispatch_profile:%'")
    else:
        _corrupt(
            fixture.worker.journal.path, "UPDATE capacity_orders SET maximum_bytes=maximum_bytes+1"
        )
    with pytest.raises(ValueError):
        await fixture.signer.endorse(setup.endpoint)
    assert fixture.signer.journal.get("intent", signing.statement_slot(setup.endpoint)) is None


@pytest.mark.parametrize(
    "failure", ["stale", "issue_closed", "evaluation_closed", "quorum", "order_changed"]
)
async def test_continuation_preserves_signing_authority_and_original_windows(setup, failure):
    fixture = await _admitted(setup)
    statement = setup.endpoint
    if failure == "stale":
        setup.clock.now += 60_001
    elif failure == "issue_closed":
        job = capacity_job(
            setup.authorization.body, setup.authorization.body.assignments[0], fixture.worker.legacy
        )
        setup.clock.now = job.issue_close_ms - fixture.signer.minimum_issue_ms
    elif failure == "evaluation_closed":
        fixture.worker.provider.block = statement.body.round.evaluation_close_block
    elif failure == "quorum":
        publication = statement.body.publication.model_copy(update={"signatures": ()})
        statement = statement.model_copy(
            update={"body": statement.body.model_copy(update={"publication": publication})}
        )
    else:
        order = statement.body.model_copy(
            update={"evaluators": tuple(reversed(statement.body.evaluators))}
        )
        statement = statement.model_copy(update={"body": order})
    with pytest.raises(ValueError):
        await fixture.signer.endorse(statement)
    assert fixture.signer.journal.get("intent", signing.statement_slot(statement)) is None


@pytest.mark.parametrize(
    "failure", ["lost_native", "evaluation_closed", "issue_closed", "final_proof"]
)
async def test_continuation_rechecks_native_receipts_and_time_immediately_before_signing(
    setup, monkeypatch, failure
):
    fixture = await _admitted(setup)
    original = fixture.signer.admission.reserve
    verify = fixture.signer.admission.verify

    def changed_after_preparation(*args, **kwargs):
        result = original(*args, **kwargs)
        if failure == "lost_native":
            monkeypatch.setattr(fixture.worker.executions, "reservation", lambda *args: None)
        return result

    def changed_after_verification(*args, **kwargs):
        result = verify(*args, **kwargs)
        if failure == "evaluation_closed":
            fixture.worker.provider.block = setup.endpoint.body.round.evaluation_close_block
        elif failure == "issue_closed":
            job = capacity_job(
                setup.authorization.body,
                setup.authorization.body.assignments[0],
                fixture.worker.legacy,
            )
            setup.clock.now = job.issue_close_ms
        elif failure == "final_proof":

            async def unavailable():
                raise ValueError("fresh owned finality unavailable")

            monkeypatch.setattr(fixture.worker, "boundary", unavailable)
        return result

    monkeypatch.setattr(fixture.signer.admission, "reserve", changed_after_preparation)
    monkeypatch.setattr(fixture.signer.admission, "verify", changed_after_verification)
    with pytest.raises(ValueError):
        await fixture.signer.endorse(setup.endpoint)
    assert fixture.signer.journal.get("intent", signing.statement_slot(setup.endpoint)) is None


async def test_authorization_cannot_request_order_continuation(setup):
    fixture = await _admitted(setup)
    with pytest.raises(ValueError, match="requires complete"):
        fixture.signer.admission.reserve(
            setup.work.plan,
            (setup.authorization.body,),
            setup.authorization.body,
            continuing_order=True,
        )
    with pytest.raises(ValueError, match="order differs"):
        fixture.signer.admission.verify(setup.work.plan, order=setup.authorization.body)


async def test_retained_receipt_still_rejects_stale_owned_finality(setup):
    fixture = await _admitted(setup)
    setup.clock.now += 60_001
    with pytest.raises(ValueError, match="fresh owned finality"):
        fixture.worker.dispatch.retained_reservation(
            fixture.plan_id, evaluator_hotkey=fixture.worker.config.evaluator_hotkey
        )


@pytest.mark.parametrize("work", [True], indirect=True)
async def test_completed_publication_order_continues_while_another_claim_is_unknown(setup):
    fixture = await _admitted(setup)
    publication = next(
        body
        for body in signing.endpoint_proposals(**setup.work.options)
        if body != setup.authorization.body
    )
    statement = setup.authorization.model_copy(update={"body": publication})
    # Another endpoint authorization remains subject to recovery qualification.
    with pytest.raises(ValueError, match="prior claim outcome"):
        await fixture.signer.endorse(statement)
    assert fixture.signer.journal.get("intent", signing.statement_slot(statement)) is None
    signed = sign_publications(setup.work, (publication,))[0]
    journal = fixture.worker.dispatch
    journal.publish(
        signed, observed=fixture.head, announcements=(setup.work.options["announcement"],)
    )
    for assignment in publication.assignments:
        if identity(assignment.evaluator_hotkey) != identity(
            fixture.worker.config.evaluator_hotkey
        ):
            continue
        token = journal.claim(
            **{
                **fixture.claim_args,
                "key": assignment_key(signed, assignment),
            }
        )
        journal.complete(token, evidence=b"retained-opaque-outcome-not-yet-verified")
    order = evaluation_order_proposals(
        plan=setup.work.plan,
        policy=setup.work.policy,
        legacy=fixture.worker.legacy,
        publications=(signed,),
    )[0]
    with pytest.raises(ValueError, match="prior claim outcome"):
        journal.reservation(
            fixture.plan_id, evaluator_hotkey=fixture.worker.config.evaluator_hotkey
        )
    assert await fixture.signer.endorse(setup.endpoint.model_copy(update={"body": order}))
    assert journal.status(fixture.token.assignment_key)["state"] == "uncertain_dispatched"


async def test_continuation_requires_the_retained_review_receipt(setup, tmp_path, monkeypatch):
    worker, plan = setup.workers[0], setup.work.plan
    archive = tmp_path / "review-archive"
    preserve_bundle(plan.incumbent, tmp_path / "incumbent", archive, setup.work.policy)
    worker.review_store = EvaluatorReviewStore(
        tmp_path / "reviews",
        setup.work.policy,
        limits=PublicationReplayLimits(
            maximum_roster_bytes=16 * 1024**2,
            maximum_certificate_bytes=16 * 1024**2,
            maximum_evidence_bytes=16 * 1024**2,
        ),
    )
    worker.review_store.initialize_baseline(plan.incumbent, archive)

    async def collect_at(height):
        from .test_competition_evaluator import Provider

        capture = await Provider(height).collect()
        snapshot = plan.cutoff.publication.registration_snapshot
        return replace(
            capture,
            snapshot=snapshot,
            provenance={
                **capture.provenance,
                "snapshot_sha256": digest(snapshot),
                "block_hash": snapshot.block_hash,
            },
        )

    worker.provider.collect_at = collect_at
    fixture = await _admitted(setup)
    assert "review" in fixture.complete["receipts"]
    monkeypatch.setattr(worker.review_store, "reservation", lambda *args: None)
    with pytest.raises(ValueError, match="native reservation receipt"):
        await fixture.signer.endorse(setup.endpoint)
    assert fixture.signer.journal.get("intent", signing.statement_slot(setup.endpoint)) is None


async def test_retained_receipt_still_enforces_logical_capacity(setup, monkeypatch):
    fixture = await _admitted(setup)
    monkeypatch.setattr(fixture.worker.dispatch, "maximum_bytes", 1)
    with pytest.raises(ValueError, match="capacity"):
        fixture.worker.dispatch.retained_reservation(
            fixture.plan_id, evaluator_hotkey=fixture.worker.config.evaluator_hotkey
        )


async def test_changed_order_cannot_spend_an_existing_reservation(setup):
    fixture = await _admitted(setup)
    order = setup.endpoint.body.model_copy(
        update={"cases": tuple(reversed(setup.endpoint.body.cases))}
    )
    with pytest.raises(ValueError, match="order differs"):
        fixture.signer.admission.reserve(
            setup.work.plan, (setup.authorization.body,), order, continuing_order=True
        )
    with pytest.raises(ValueError, match="order differs"):
        fixture.signer.admission.verify(setup.work.plan, order=order)
