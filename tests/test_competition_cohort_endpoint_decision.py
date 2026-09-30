"""Miner retirement through durable independent reviewer votes and case selection.

Canonical requests, HTTP authentication, miner replies, signatures and private
journals are real. Chain/finality, DNS and inference are fixture boundaries.
These tests do not install a service or authorize replacement inference.
"""

import asyncio
from dataclasses import replace
from types import SimpleNamespace

import bittensor as bt
import pytest

from umi.competition_cohort_endpoint_decision import (
    CohortEndpointCaseReview,
    case_decision_slot,
    certify_case_decision,
    validate_case_review,
    verify_case_decision,
)
from umi.competition_cohort_endpoint_decision_signer import (
    CohortEndpointDecisionConfig,
    CohortEndpointDecisionJournal,
    CohortEndpointDecisionSigner,
)
from umi.competition_cohort_endpoint_decision_worker import CohortEndpointCaseCoordinator
from umi.open_competition import identity, sign_object
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_endpoint_retirement import base_policy as base_policy
from .test_competition_cohort_endpoint_retirement import chain as chain
from .test_competition_cohort_endpoint_retirement import chain_config as chain_config
from .test_competition_cohort_endpoint_retirement import delivery as delivery
from .test_competition_cohort_endpoint_retirement import endpoint as endpoint
from .test_competition_cohort_endpoint_retirement import execution as execution
from .test_competition_cohort_endpoint_retirement import expire_both, translate
from .test_competition_cohort_endpoint_retirement import granted as granted
from .test_competition_cohort_endpoint_retirement import harness as harness
from .test_competition_cohort_endpoint_retirement import known_video_bytes as known_video_bytes
from .test_competition_cohort_endpoint_retirement import legacy_scenario as legacy_scenario
from .test_competition_cohort_endpoint_retirement import policy as policy
from .test_competition_cohort_endpoint_retirement import receipt_scenario as receipt_scenario
from .test_competition_cohort_endpoint_retirement import recovery as recovery
from .test_competition_cohort_endpoint_retirement import recovery_case as recovery_case
from .test_competition_cohort_endpoint_retirement import relay as relay
from .test_competition_cohort_endpoint_retirement import retiring as retiring
from .test_competition_cohort_endpoint_retirement import runtime as runtime
from .test_competition_cohort_endpoint_retirement import scenario as scenario
from .test_competition_cohort_order_signer import source_for
from .test_open_competition import wallet


@pytest.fixture
async def decisions(retiring, tmp_path, monkeypatch):
    p = retiring
    d = SimpleNamespace(p=p, fail_sign=False, calls=[], journals={}, overrides={})

    async def evidence(kind="absent", index=0):
        if kind != "absent":
            p.model.fail = kind == "failed"
            assert (await translate(p, index=index)).status_code == 200
        else:
            expire_both(p, monkeypatch)
        case = p.e.job.cases[index].case_id
        result = await p.retirement.retire(p.retire_slot, case)
        assert result.status == "retained", result
        return CohortEndpointCaseReview(
            schema="umi-cohort-endpoint-case-review/1",
            assignment=p.e.assignment,
            selection=p.delivery_selection,
            retirement=result.value,
            recovered=p.delivery_recovery.retained(p.retire_slot, case),
        )

    def worker(name="Charlie"):
        base = p.e.cfg.model_dump(by_alias=True)
        for key in ("schema", "directory", "signer", "maximum_attempts"):
            base.pop(key)
        cfg = CohortEndpointDecisionConfig(
            schema="umi-cohort-endpoint-decision-config/1",
            directory=str(tmp_path / ("decision-" + name)),
            signer=wallet(name).hotkey.ss58_address,
            **{**base, **d.overrides},
        )
        journal = CohortEndpointDecisionJournal(cfg, p.c.policy)
        d.journals[name] = journal

        async def sign(body):
            retained = journal.load(case_decision_slot(body))
            assert retained is not None and retained.decision == body
            assert journal.journal.reservation(case_decision_slot(body)) is not None
            d.calls.append((name, canonical_json_bytes(body)))
            if d.fail_sign:
                raise OSError("signature interrupted")
            return sign_object(body, wallet(name))

        return CohortEndpointDecisionSigner(
            journal, p.c.provider, p.e.box.history, bt.timelock.current_round, sign
        )

    d.evidence, d.worker = evidence, worker
    return d


@pytest.mark.parametrize("kind", ["ok", "failed", "absent"])
async def test_case_decisions_survive_lost_ack_closure_and_offline_restart(decisions, kind):
    d = decisions
    review = await d.evidence(kind)
    _, body = validate_case_review(review, d.p.c.policy)
    assert body.disposition == ("retry_required" if kind == "absent" else "retain_response")
    a, b = d.worker(), d.worker("Dave")
    av, bv = await a.attest(review), await b.attest(review)
    slot = case_decision_slot(body)
    with pytest.raises(ValueError):
        await a.certify(slot)
    await a.collect(slot, bv)
    certificate = await a.certify(slot)
    assert verify_case_decision(certificate, review, d.p.c.policy) == certificate
    assert not body.transport_authorized and not body.original_receipt_timing_proven
    assert not body.chain_submission_authorized
    d.p.c.finality.fail = True
    d.p.e.r.h.source = source_for(d.p.e.r.h.batch, d.p.e.r.h.batch["history"])
    d.fail_sign = True
    assert await d.worker().recover(slot) == av
    assert await d.worker("Dave").recover(slot) == bv
    assert await d.worker().certify(slot) == certificate
    assert len(d.calls) == 2


async def test_partial_signature_interruption_resumes_identical_intent(decisions):
    d = decisions
    review = await d.evidence()
    _, body = validate_case_review(review, d.p.c.policy)
    slot = case_decision_slot(body)
    d.fail_sign = True
    with pytest.raises(OSError, match="signature interrupted"):
        await d.worker().attest(review)
    original = d.journals["Charlie"].load(slot)
    d.fail_sign = False
    await d.worker().recover(slot)
    assert d.journals["Charlie"].load(slot) == original
    assert len(d.calls) == 2 and d.calls[0] == d.calls[1]


@pytest.mark.parametrize("after", [False, True])
async def test_vote_commit_interruption_recovers_without_new_selection(
    decisions, monkeypatch, after
):
    d = decisions
    review = await d.evidence()
    worker = d.worker()
    db, real = worker.journal.journal, worker.journal.journal.put

    def interrupted(kind, key, value):
        if kind == "endpoint_decision_vote":
            if after:
                real(kind, key, value)
            raise OSError("commit interrupted")
        return real(kind, key, value)

    with monkeypatch.context() as m:
        m.setattr(db, "put", interrupted)
        with pytest.raises(OSError, match="commit interrupted"):
            await worker.attest(review)
    d.fail_sign = after
    await d.worker().attest(review)
    assert len(d.calls) == (1 if after else 2)


@pytest.mark.parametrize("after", [False, True])
async def test_certificate_commit_recovers_offline(decisions, monkeypatch, after):
    d = decisions
    review = await d.evidence()
    a, b = d.worker(), d.worker("Dave")
    av, bv = await a.attest(review), await b.attest(review)
    body = validate_case_review(review, d.p.c.policy)[1]
    slot = case_decision_slot(body)
    await a.collect(slot, bv)
    db, real = a.journal.journal, a.journal.journal.put

    def interrupted(kind, key, value):
        if kind == "endpoint_decision_certificate":
            if after:
                real(kind, key, value)
            raise OSError("certificate interrupted")
        return real(kind, key, value)

    with monkeypatch.context() as m:
        m.setattr(db, "put", interrupted)
        with pytest.raises(OSError, match="certificate interrupted"):
            await a.certify(slot)
    d.p.c.finality.fail = True
    expected = certify_case_decision(review, (av, bv), d.p.c.policy)
    assert await d.worker().certify(slot) == expected
    assert len(d.calls) == 2


@pytest.mark.parametrize("field", ["selection_sha256", "case_id", "grant", "request", "signature"])
async def test_corrupt_retirement_never_gets_a_vote(decisions, field):
    d = decisions
    review = await d.evidence()
    retired = review.retirement
    if field in ("selection_sha256", "case_id"):
        retired = retired.model_copy(update={field: "cd" * 32})
    else:
        signed = retired.retirement
        body = signed.receipt
        if field == "signature":
            signed = signed.model_copy(update={"signature": sign_object(body, wallet("Alice"))})
        else:
            body = body.model_copy(
                update={field + "_sha256" if field == "grant" else "request_digest": "cd" * 32}
            )
            signed = signed.model_copy(
                update={"receipt": body, "signature": sign_object(body, wallet("Bob"))}
            )
        retired = retired.model_copy(update={"retirement": signed})
    with pytest.raises(ValueError):
        await d.worker().attest(review.model_copy(update={"retirement": retired}))
    assert not d.calls


@pytest.mark.parametrize("which", ["block", "round"])
async def test_reviewers_require_their_own_expiry_observation(decisions, monkeypatch, which):
    d = decisions
    review = await d.evidence()
    if which == "block":
        d.p.c.finality.ref = replace(
            d.p.c.finality.ref, block_number=review.retirement.observed_block - 1
        )
    else:
        monkeypatch.setattr(
            bt.timelock, "current_round", lambda: review.retirement.observed_round - 1
        )
    with pytest.raises(ValueError):
        await d.worker().attest(review)
    assert not d.calls


@pytest.mark.parametrize("damage", ["missing", "case", "selection", "body"])
async def test_successful_response_cannot_be_discarded_or_substituted(decisions, damage):
    d = decisions
    review = await d.evidence("ok")
    recovered = review.recovered
    if damage == "missing":
        recovered = None
    elif damage == "body":
        recovered = recovered.model_copy(
            update={"response": recovered.response.model_copy(update={"envelope_hex": "ab"})}
        )
    else:
        recovered = recovered.model_copy(
            update={"case_id" if damage == "case" else "selection_sha256": "ab" * 32}
        )
    with pytest.raises(ValueError):
        await d.worker().attest(review.model_copy(update={"recovered": recovered}))
    assert not d.calls


async def test_same_attempt_cannot_change_retained_review(decisions):
    d = decisions
    review = await d.evidence()
    worker = d.worker()
    await worker.attest(review)
    changed = review.model_copy(
        update={
            "retirement": review.retirement.model_copy(update={"origin_evidence_sha256": "cd" * 32})
        }
    )
    with pytest.raises(ValueError, match="another decision intent"):
        await d.worker().attest(changed)
    assert len(d.calls) == 1


async def test_late_offline_reviewer_can_finish_partial_quorum(decisions):
    d = decisions
    review = await d.evidence()
    a = d.worker()
    av = await a.attest(review)
    d.p.c.finality.ref = replace(
        d.p.c.finality.ref, block_number=d.p.c.finality.ref.block_number + 3000
    )
    bv = await d.worker("Dave").attest(review)
    slot = case_decision_slot(validate_case_review(review, d.p.c.policy)[1])
    await d.worker().collect(slot, bv)
    assert await d.worker().certify(slot) == certify_case_decision(review, (av, bv), d.p.c.policy)


async def test_new_vote_rejected_after_phase_closure(decisions):
    d = decisions
    review = await d.evidence()
    d.p.e.r.h.source = source_for(d.p.e.r.h.batch, d.p.e.r.h.batch["history"])
    with pytest.raises(ValueError):
        await d.worker().attest(review)
    assert not d.calls


async def test_competing_request_waits_for_owned_vote_commit(decisions, monkeypatch):
    import threading

    d = decisions
    review = await d.evidence()
    worker = d.worker()
    entered, release = threading.Event(), threading.Event()
    real = worker.journal.collect

    def held(*args):
        entered.set()
        assert release.wait(10)
        return real(*args)

    monkeypatch.setattr(worker.journal, "collect", held)
    task = asyncio.create_task(worker.attest(review))
    await asyncio.to_thread(entered.wait, 10)
    assert entered.is_set()
    task.cancel()
    next_task = asyncio.create_task(worker.attest(review))
    try:
        await asyncio.sleep(0.03)
        assert not task.done() and not next_task.done()
    finally:
        release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    await next_task
    assert len(d.calls) == 1


def coordinator(d, *, offline=False, bad=False):
    own_name = next(
        n
        for n in ("Charlie", "Dave", "Eve", "Ferdie")
        if identity(wallet(n).hotkey.ss58_address) == identity(d.p.e.cfg.signer)
    )

    async def peer(hotkey, review):
        if offline:
            raise OSError("reviewer offline")
        name = next(
            n
            for n in ("Charlie", "Dave", "Eve", "Ferdie")
            if identity(wallet(n).hotkey.ss58_address) == identity(hotkey)
        )
        signature = await d.worker(name).attest(review)
        if bad:
            return sign_object(validate_case_review(review, d.p.c.policy)[1], wallet("Alice"))
        return signature

    return CohortEndpointCaseCoordinator(d.p.retirement, d.worker(own_name), peer)


@pytest.mark.parametrize("kind", ["ok", "failed", "absent"])
async def test_composed_retirement_to_certificate_replays_offline(decisions, kind):
    d = decisions
    await d.evidence(kind)
    p = d.p
    result = await coordinator(d).advance(p.retire_slot, p.case_id)
    assert result.status == "certified", result
    before = list(d.calls)
    p.c.finality.fail = True
    d.fail_sign = True
    repeated = await coordinator(d, offline=True).advance(p.retire_slot, p.case_id)
    assert repeated.certificate == result.certificate
    assert d.calls == before
    assert p.model.calls == (0 if kind == "absent" else 1)


@pytest.mark.parametrize("bad", [False, True])
async def test_unavailable_or_bad_peer_keeps_case_pending_until_recovery(decisions, bad):
    d = decisions
    await d.evidence()
    p = d.p
    first = await coordinator(d, offline=not bad, bad=bad).advance(p.retire_slot, p.case_id)
    assert first.status == "pending" and first.certificate is None
    assert first.reason == "case_decision_quorum_pending"
    second = await coordinator(d).advance(p.retire_slot, p.case_id)
    assert second.status == "certified"
    assert second.certificate.decision.disposition == "retry_required"
    assert p.model.calls == 0


async def test_mixed_cases_keep_success_and_failure_while_missing_case_retries(decisions):
    d = decisions
    success = await d.evidence("ok", index=0)
    failure = await d.evidence("failed", index=1)
    missing = await d.evidence("absent", index=2)
    service = coordinator(d)
    outputs = []
    for review in (success, failure, missing):
        result = await service.advance(d.p.retire_slot, review.retirement.case_id)
        assert result.status == "certified"
        outputs.append(result.certificate.decision)
    assert [x.disposition for x in outputs] == [
        "retain_response",
        "retain_response",
        "retry_required",
    ]
    assert len({case_decision_slot(x) for x in outputs}) == 3
    assert d.p.model.calls == 2
    for review in (success, failure):
        assert (
            d.p.delivery_recovery.retained(d.p.retire_slot, review.retirement.case_id)
            == review.recovered
        )


@pytest.mark.parametrize("after", [False, True])
async def test_coordinator_ack_interruption_recovers_frozen_quorum(decisions, monkeypatch, after):
    d = decisions
    await d.evidence()
    p = d.p
    db = p.delivery_recovery.journal.journal
    real = db.put

    def broken(kind, key, value):
        if kind == "endpoint_case_decision":
            if after:
                real(kind, key, value)
            raise OSError("coordinator acknowledgement lost")
        return real(kind, key, value)

    with monkeypatch.context() as m:
        m.setattr(db, "put", broken)
        with pytest.raises(OSError, match="acknowledgement lost"):
            await coordinator(d).advance(p.retire_slot, p.case_id)
    before = list(d.calls)
    p.c.finality.fail = True
    d.fail_sign = True
    result = await coordinator(d, offline=True).advance(p.retire_slot, p.case_id)
    assert result.status == "certified"
    assert d.calls == before


async def test_capacity_growth_preserves_prior_case_and_resumes_next(decisions):
    d = decisions
    first, second = await d.evidence(), await d.evidence(index=1)
    d.overrides["maximum_votes"] = 1
    a = d.worker()
    await a.attest(first)
    before = list(d.calls)
    with pytest.raises(ValueError, match="capacity"):
        await a.attest(second)
    assert d.calls == before
    d.overrides["maximum_votes"] = 2
    a = d.worker()
    await a.attest(first)
    await a.attest(second)
    assert len(d.calls) == 2


async def test_duplicate_or_insufficient_votes_do_not_form_quorum(decisions):
    d = decisions
    review = await d.evidence()
    vote = await d.worker().attest(review)
    for votes in ((), (vote,), (vote, vote)):
        with pytest.raises(ValueError):
            certify_case_decision(review, votes, d.p.c.policy)


async def test_changed_decision_certificate_is_rejected(decisions):
    d = decisions
    review = await d.evidence()
    a, b = await d.worker().attest(review), await d.worker("Dave").attest(review)
    cert = certify_case_decision(review, (a, b), d.p.c.policy)
    damaged = cert.model_copy(
        update={"decision": cert.decision.model_copy(update={"disposition": "retain_response"})}
    )
    with pytest.raises(ValueError):
        verify_case_decision(damaged, review, d.p.c.policy)


async def test_coordinator_stops_after_independent_quorum(decisions):
    d = decisions
    await d.evidence()
    service = coordinator(d)
    real, calls = service.request_vote, []

    async def tracked(hotkey, review):
        calls.append(hotkey)
        assert len(calls) <= d.p.c.policy.required_evaluator_groups - 1
        return await real(hotkey, review)

    service.request_vote = tracked
    result = await service.advance(d.p.retire_slot, d.p.case_id)
    assert result.status == "certified"
    assert len(calls) == d.p.c.policy.required_evaluator_groups - 1
