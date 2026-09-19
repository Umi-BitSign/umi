from __future__ import annotations

import asyncio
import threading

import pytest

from umi import competition_work_signing as signing
from umi.open_competition import digest

from .test_competition_work_signing import chain_config as chain_config
from .test_competition_work_signing import policy as policy
from .test_competition_work_signing import runtime as runtime
from .test_competition_work_signing import setup as setup
from .test_competition_work_signing import work as work


@pytest.mark.asyncio
async def test_first_endorsement_reserves_entire_mixed_cohort_before_signature(setup, monkeypatch):
    signer, worker = setup.signers[0], setup.workers[0]
    plan_id = digest(setup.work.plan)
    original = signing.sign_object
    observed = []

    def sign(*args):
        completed = signer.admission.journal.get("complete", plan_id)
        assert completed is not None
        assert set(completed["receipts"]) == {"signing", "execution", "evaluator", "dispatch"}
        receipt = worker.journal.reservation(plan_id)
        assert len(receipt["orders"]) == len(setup.work.plan.submissions)
        assert worker.journal.orders() == []
        assert all(worker.executions.status(o["slot"]) is None for o in receipt["orders"])
        observed.append(completed)
        return original(*args)

    monkeypatch.setattr(signing, "sign_object", sign)
    await signer.endorse(setup.authorization)
    await signer.endorse(setup.model)
    await signer.endorse(setup.endpoint)
    assert len(observed) == 3 and all(value == observed[0] for value in observed)


@pytest.mark.asyncio
async def test_mixed_round_model_waits_for_endpoint_inventory_without_partial_signing(setup):
    signer = setup.signers[0]
    with pytest.raises(ValueError, match="endpoint assignments first"):
        await signer.endorse(setup.model)
    assert signer.journal.get("intent", signing.statement_slot(setup.model)) is None
    assert signer.admission.journal.get("manifest", digest(setup.work.plan)) is None
    await signer.endorse(setup.authorization)
    assert await signer.endorse(setup.model)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "owner,method",
    [
        ("signing", "reserve_records"),
        ("execution", "reserve_jobs"),
        ("evaluator", "reserve_orders"),
        ("admission", "put"),
    ],
)
async def test_crash_after_native_commit_leaves_no_new_signature_and_exact_retry_finishes(
    setup,
    monkeypatch,
    owner,
    method,
):
    signer, worker = setup.signers[0], setup.workers[0]
    stores = {
        "signing": signer.journal,
        "execution": worker.executions,
        "evaluator": worker.journal,
        "admission": signer.admission.journal,
    }
    store = stores[owner]
    original = getattr(store, method)
    calls = []

    def interrupted(*args, **kwargs):
        original(*args, **kwargs)
        raise RuntimeError("simulated death after durable reservation")

    def never_sign(*args):
        calls.append(1)
        pytest.fail("signature preceded complete admission")

    with monkeypatch.context() as patch:
        patch.setattr(store, method, interrupted)
        patch.setattr(signing, "sign_object", never_sign)
        with pytest.raises(RuntimeError, match="simulated death"):
            await signer.endorse(setup.authorization)
    slot = signing.statement_slot(setup.authorization)
    assert signer.journal.get("intent", slot) is None and not calls
    old = signer.admission.journal.get("manifest", digest(setup.work.plan))
    restarted = signing.IndependentWorkSigner(
        worker,
        signer.cutoffs,
        minimum_issue_ms=1000,
        legacy=worker.legacy,
        transport_provider=signer.transport_provider,
    )
    vote = await restarted.endorse(setup.authorization)
    assert restarted.admission.journal.get("manifest", digest(setup.work.plan)) == old
    assert await restarted.endorse(setup.authorization) == vote


@pytest.mark.asyncio
@pytest.mark.parametrize("owner", ["signing", "execution", "evaluator"])
async def test_full_cohort_capacity_failure_is_before_any_work_intent_or_signature(
    setup,
    monkeypatch,
    owner,
):
    signer, worker = setup.signers[0], setup.workers[0]
    if owner == "signing":
        signer.journal.maximum_bytes = 1024
    elif owner == "execution":
        worker.executions.maximum_jobs = len(setup.work.plan.submissions) - 1
    else:
        worker.journal.config = worker.journal.config.model_copy(
            update={"maximum_orders": len(setup.work.plan.submissions) - 1}
        )

    def never_sign(*args):
        pytest.fail("full-cohort capacity failure reached signer")

    monkeypatch.setattr(signing, "sign_object", never_sign)
    with pytest.raises(ValueError, match=r"capacity|excessive evaluator order reservation"):
        await signer.endorse(setup.authorization)
    assert signer.journal.get("intent", signing.statement_slot(setup.authorization)) is None
    assert signer.admission.journal.get("complete", digest(setup.work.plan)) is None


@pytest.mark.asyncio
async def test_published_endpoint_uses_less_than_reserved_capacity_and_allows_next_vote(setup):
    from .test_competition_work_plans import sign_publications

    signer, worker = setup.signers[0], setup.workers[0]
    await signer.endorse(setup.authorization)
    batch_id = digest(setup.work.plan)
    before = worker.dispatch.reservation(batch_id, evaluator_hotkey=worker.config.evaluator_hotkey)
    signed = sign_publications(setup.work, (setup.authorization.body,))[0]
    worker.dispatch.publish(
        signed,
        observed=setup.work.options["issuance"],
        announcements=(setup.work.options["announcement"],),
    )
    after = worker.dispatch.reservation(batch_id, evaluator_hotkey=worker.config.evaluator_hotkey)
    assert before == after
    assert await signer.endorse(setup.endpoint)
    assert signer.admission.journal.get("complete", digest(setup.work.plan)) is not None


@pytest.mark.asyncio
async def test_lost_native_receipt_blocks_later_new_endorsement(setup, monkeypatch):
    signer = setup.signers[0]
    await signer.endorse(setup.authorization)
    monkeypatch.setattr(setup.workers[0].executions, "reservation", lambda batch: None)
    with pytest.raises(ValueError, match="native reservation receipt"):
        await signer.endorse(setup.model)
    assert signer.journal.get("intent", signing.statement_slot(setup.model)) is None


@pytest.mark.asyncio
async def test_capacity_work_cannot_silently_consume_last_issue_margin(setup, monkeypatch):
    signer = setup.signers[0]
    original = signer.admission.reserve

    def expire_after_reservation(*args):
        result = original(*args)
        setup.workers[0].provider.block = setup.model.body.round.evaluation_close_block
        return result

    monkeypatch.setattr(signer.admission, "reserve", expire_after_reservation)
    with pytest.raises(ValueError, match="execution window"):
        await signer.endorse(setup.authorization)
    assert signer.admission.journal.get("complete", digest(setup.work.plan)) is not None
    assert signer.journal.get("intent", signing.statement_slot(setup.authorization)) is None


@pytest.mark.asyncio
async def test_cancellation_drains_native_commits_before_unlocking_signer(setup, monkeypatch):
    signer, worker = setup.signers[0], setup.workers[0]
    original = signer.admission.reserve
    entered, release = threading.Event(), threading.Event()

    def pause(*args):
        entered.set()
        assert release.wait(timeout=10)
        return original(*args)

    monkeypatch.setattr(signer.admission, "reserve", pause)
    task = asyncio.create_task(signer.endorse(setup.authorization))
    try:
        assert await asyncio.to_thread(entered.wait, 5), "reservation did not start"
        task.cancel()
        await asyncio.sleep(0)
        task.cancel()
        other = signing.IndependentWorkSigner(
            worker,
            signer.cutoffs,
            minimum_issue_ms=1000,
            legacy=worker.legacy,
            transport_provider=signer.transport_provider,
        )
        with pytest.raises(BlockingIOError):
            await other.endorse(setup.authorization)
        assert not task.done()
    finally:
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert signer.journal.get("vote", signing.statement_slot(setup.authorization)) is None
    assert await other.endorse(setup.authorization)
