"""Protocol fences survive response loss; physical model isolation remains a host boundary."""

import asyncio
import hashlib
import sqlite3
from dataclasses import replace

import bittensor as bt
import pytest

from umi import miner as module
from umi.endpoint_protocol import COHORT_RETIRE_PATH, RESPONSE_RECOVERY_PATH
from umi.endpoint_retirement import SignedEndpointRetirementReceipt, verify_retirement_receipt
from umi.miner_resources import (
    MinerAssignmentBinding,
    MinerResourceError,
    SQLiteMinerResourceLedger,
)
from umi.open_competition import digest

from .test_competition_cohort_miner import (
    base_policy as base_policy,
)
from .test_competition_cohort_miner import (
    chain as chain,
)
from .test_competition_cohort_miner import (
    chain_config as chain_config,
)
from .test_competition_cohort_miner import (
    delivery as delivery,
)
from .test_competition_cohort_miner import (
    endpoint as endpoint,
)
from .test_competition_cohort_miner import (
    execution as execution,
)
from .test_competition_cohort_miner import (
    grant,
    request,
    translate,
)
from .test_competition_cohort_miner import (
    granted as granted,
)
from .test_competition_cohort_miner import (
    harness as harness,
)
from .test_competition_cohort_miner import (
    known_video_bytes as known_video_bytes,
)
from .test_competition_cohort_miner import (
    legacy_scenario as legacy_scenario,
)
from .test_competition_cohort_miner import (
    policy as policy,
)
from .test_competition_cohort_miner import (
    receipt_scenario as receipt_scenario,
)
from .test_competition_cohort_miner import (
    recovery as recovery,
)
from .test_competition_cohort_miner import (
    recovery_case as recovery_case,
)
from .test_competition_cohort_miner import (
    relay as relay,
)
from .test_competition_cohort_miner import (
    runtime as runtime,
)
from .test_competition_cohort_miner import (
    scenario as scenario,
)
from .test_competition_cohort_order_signer import source_for


async def retire(p, index=0):
    return await request(p, COHORT_RETIRE_PATH, p.requests[index])


def expire(p, monkeypatch):
    req = p.requests[0]
    p.finality.head = req.deadline_block + 1
    monkeypatch.setattr(bt.timelock, "current_round", lambda: req.response_close_round + 1)


def verify(p, reply):
    assert reply.status_code == 200, reply.text
    assert reply.headers["cache-control"] == "no-store"
    return verify_retirement_receipt(
        SignedEndpointRetirementReceipt.model_validate_json(reply.content),
        request=p.requests[0],
        grant_sha256=digest(p.grant),
        miner_hotkey=p.miner.hotkey_ss58,
        evaluator_hotkey=p.validator.hotkey.ss58_address,
    )


def reopen(p, capacity=8):
    old = p.miner.resource_ledger
    old.close()
    new = SQLiteMinerResourceLedger(
        old._path,
        miner_hotkey=p.miner.hotkey_ss58,
        scoring_policy_sha256=p.miner.scoring_policy_sha256,
        limits=old._limits,
        maximum_recovery_assignments=capacity,
    )
    p.miner = replace(p.rebuild(), resource_ledger=new)
    return new


@pytest.mark.parametrize("failure", [False, True])
async def test_retirement_preserves_sealed_response_and_failure(granted, monkeypatch, failure):
    p = granted
    assert (await grant(p)).status_code == 200
    p.model.fail = failure
    original = await translate(p)
    assert original.status_code == 200, original.text
    first = await retire(p)
    receipt = verify(p, first)
    assert receipt.receipt.result == "response_retained"
    assert receipt.receipt.response_sha256 == hashlib.sha256(original.content).hexdigest()
    assert p.model.calls == 1
    assert (await translate(p)).status_code == 409
    p.miner.resource_ledger.prune_closed_windows(p.requests[0].response_close_round)
    with_reopen = reopen(p, capacity=0)
    try:
        p.e.r.h.source = source_for(p.e.r.h.batch, p.e.r.h.batch["history"])
        p.c.finality.fail = True
        expire(p, monkeypatch)
        again = await retire(p)
        assert again.content == first.content
        recovered = await request(p, RESPONSE_RECOVERY_PATH, p.requests[0])
        assert recovered.content == original.content
        assert recovered.headers["x-umi-signature"] == original.headers["x-umi-signature"]
        assert p.model.calls == 1
    finally:
        with_reopen.close()


async def test_unstarted_expired_request_is_fenced_across_restart(granted, monkeypatch):
    p = granted
    assert (await grant(p)).status_code == 200
    expire(p, monkeypatch)
    result = await retire(p)
    receipt = verify(p, result)
    assert receipt.receipt.result == "no_response_retained"
    assert receipt.receipt.response_sha256 is None
    assert p.model.calls == p.fetcher.calls == 0
    binding = MinerAssignmentBinding.from_request(
        p.requests[0], validator_hotkey=p.validator.hotkey.ss58_address
    )
    new = reopen(p)
    try:
        with pytest.raises(MinerResourceError, match="request_retired"):
            new.record_request(binding, observed_wire_bytes=1)
        assert (await retire(p)).content == result.content
        assert (
            new._connection.execute("SELECT value FROM metadata WHERE key='schema'").fetchone()[0]
            == "umi-miner-resource-ledger/2"
        )
    finally:
        new.close()


@pytest.mark.parametrize("expired", ["neither", "block", "round"])
async def test_unexpired_opportunity_cannot_be_retired(granted, monkeypatch, expired):
    p = granted
    assert (await grant(p)).status_code == 200
    if expired == "block":
        p.finality.head = p.requests[0].deadline_block + 1
    if expired == "round":
        monkeypatch.setattr(
            bt.timelock, "current_round", lambda: p.requests[0].response_close_round + 1
        )
    assert (await retire(p)).status_code == 202
    assert (
        p.miner.resource_ledger._connection.execute(
            "SELECT COUNT(*) FROM request_retirements"
        ).fetchone()[0]
        == 0
    )
    assert p.model.calls == 0


async def test_pending_retirement_drains_active_work_and_keeps_its_response(granted, monkeypatch):
    p = granted
    assert (await grant(p)).status_code == 200
    started, release = asyncio.Event(), asyncio.Event()
    original = p.fetcher.fetch

    async def waiting(*args):
        started.set()
        await release.wait()
        return await original(*args)

    monkeypatch.setattr(p.fetcher, "fetch", waiting)
    work = asyncio.create_task(translate(p))
    try:
        await asyncio.wait_for(started.wait(), 3)
        expire(p, monkeypatch)
        pending = await retire(p)
        assert pending.status_code == 202, pending.text
        assert not work.done()
        count = p.miner.resource_ledger._connection.execute(
            "SELECT COUNT(*) FROM request_retirements"
        ).fetchone()[0]
        assert count == 1
    finally:
        release.set()
    result = await work
    assert result.status_code == 200, result.text
    final = verify(p, await retire(p))
    assert final.receipt.response_sha256 == hashlib.sha256(result.content).hexdigest()
    assert p.model.calls == 1


@pytest.mark.parametrize("fault", ["intent", "sign", "receipt", "after_commit"])
async def test_interrupted_retirement_resumes_exact_intent(granted, monkeypatch, fault):
    p = granted
    assert (await grant(p)).status_code == 200
    expire(p, monkeypatch)
    ledger = p.miner.resource_ledger
    original = getattr(
        ledger, "prepare_retirement" if fault == "intent" else "commit_retirement_receipt"
    )

    def fail(*args, **kw):
        if fault == "after_commit":
            original(*args, **kw)
        raise OSError("interrupted retirement")

    if fault == "sign":
        target, name = module, "sign_object"
    else:
        target, name = (
            ledger,
            "prepare_retirement" if fault == "intent" else "commit_retirement_receipt",
        )
    with monkeypatch.context() as m:
        m.setattr(target, name, fail)
        assert (await retire(p)).status_code == 503
    new = reopen(p)
    try:

        async def unavailable():
            raise OSError("no finality after persisted intent")

        monkeypatch.setattr(p.finality, "finalized_head_height", unavailable)
        result = await retire(p)
        receipt = verify(p, result)
        assert receipt.receipt.result == "no_response_retained"
        assert (await retire(p)).content == result.content
        assert p.model.calls == 0
    finally:
        new.close()


async def test_grant_and_request_binding_are_required(granted, monkeypatch):
    p = granted
    expire(p, monkeypatch)
    assert (await retire(p)).status_code == 422
    assert (await grant(p)).status_code == 200
    bad = p.requests[0].model_copy(update={"window_id": "ab" * 32})
    assert (await request(p, COHORT_RETIRE_PATH, bad)).status_code == 422
    assert (
        p.miner.resource_ledger._connection.execute(
            "SELECT COUNT(*) FROM request_retirements"
        ).fetchone()[0]
        == 0
    )


async def test_retirement_capacity_can_grow_without_forgetting_request(granted, monkeypatch):
    p = granted
    assert (await grant(p)).status_code == 200
    expire(p, monkeypatch)
    p.miner.resource_ledger._maximum_recovery_assignments = 0
    assert (await retire(p)).status_code == 503
    p.miner.resource_ledger._maximum_recovery_assignments = 8
    verify(p, await retire(p))
    assert p.model.calls == 0


async def test_concurrent_retires_return_one_receipt(granted, monkeypatch):
    p = granted
    assert (await grant(p)).status_code == 200
    expire(p, monkeypatch)
    results = await asyncio.gather(retire(p), retire(p))
    assert all(r.status_code in (200, 202) for r in results)
    final = await retire(p)
    verify(p, final)
    assert all(r.content == final.content for r in results if r.status_code == 200)
    assert p.model.calls == 0


async def test_retired_request_cannot_record_a_later_response(granted):
    p = granted
    assert (await grant(p)).status_code == 200
    result = await translate(p)
    assert result.status_code == 200
    verify(p, await retire(p))
    binding = MinerAssignmentBinding.from_request(
        p.requests[0], validator_hotkey=p.validator.hotkey.ss58_address
    )
    with pytest.raises(MinerResourceError, match="request_retired"):
        p.miner.resource_ledger.record_response(
            binding, body=result.content, signature=result.headers["x-umi-signature"]
        )


@pytest.mark.parametrize("field", ["receipt_intent", "receipt"])
async def test_corrupt_retirement_cannot_restart(granted, monkeypatch, field):
    p = granted
    assert (await grant(p)).status_code == 200
    expire(p, monkeypatch)
    verify(p, await retire(p))
    old = p.miner.resource_ledger
    old.close()
    with sqlite3.connect(old._path) as db:
        db.execute("UPDATE request_retirements SET " + field + "=?", (b"{}",))
    with pytest.raises(ValueError):
        reopen(p)


async def test_admitted_but_queued_work_cannot_run_after_retirement(granted, monkeypatch):
    p = granted
    assert (await grant(p)).status_code == 200
    ledger = p.miner.resource_ledger
    binding = MinerAssignmentBinding.from_request(
        p.requests[0], validator_hotkey=p.validator.hotkey.ss58_address
    )
    lock = module._assignment_lock(p.miner, binding.assignment_id)
    entered = asyncio.Event()
    original = ledger.record_request

    def admitted(*args, **kwargs):
        result = original(*args, **kwargs)
        entered.set()
        return result

    monkeypatch.setattr(ledger, "record_request", admitted)
    await lock.acquire()
    work = asyncio.create_task(translate(p))
    try:
        await asyncio.wait_for(entered.wait(), 10)
        expire(p, monkeypatch)
        assert (await retire(p)).status_code == 202
    finally:
        lock.release()
    reply = await work
    assert reply.status_code == 409
    assert reply.json()["detail"] == "request_retired"
    verify(p, await retire(p))
    assert p.model.calls == p.fetcher.calls == 0


async def test_cancelled_retirement_commit_keeps_assignment_lock_until_drained(
    granted, monkeypatch
):
    import threading

    p = granted
    assert (await grant(p)).status_code == 200
    expire(p, monkeypatch)
    ledger = p.miner.resource_ledger
    original = ledger.commit_retirement_receipt
    entered, release = threading.Event(), threading.Event()

    def delayed(*args):
        entered.set()
        assert release.wait(10)
        return original(*args)

    monkeypatch.setattr(ledger, "commit_retirement_receipt", delayed)
    task = asyncio.create_task(retire(p))
    try:
        assert await asyncio.to_thread(entered.wait, 10)
        task.cancel()
        await asyncio.sleep(0.03)
        assert not task.done()
        binding = MinerAssignmentBinding.from_request(
            p.requests[0], validator_hotkey=p.validator.hotkey.ss58_address
        )
        assert module._assignment_lock(p.miner, binding.assignment_id).locked()
    finally:
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
    verify(p, await retire(p))
    assert p.model.calls == 0


async def test_unavailable_grant_storage_is_retryable(granted, monkeypatch):
    p = granted

    async def offline(*args, **kwargs):
        raise OSError("temporary private journal contention")

    with monkeypatch.context() as m:
        m.setattr(p.miner.competition_authority, "retirement_grant", offline)
        assert (await retire(p)).status_code == 503
    assert (await grant(p)).status_code == 200
    expire(p, monkeypatch)
    verify(p, await retire(p))
