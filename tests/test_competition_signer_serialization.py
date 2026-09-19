from __future__ import annotations

import asyncio
import multiprocessing
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from umi import competition_work_signing as signing
from umi.concurrency import run_owned_thread
from umi.private_files import lock_private_file

from .async_ownership import PausedCall
from .test_competition_work_signing import chain_config as chain_config
from .test_competition_work_signing import policy as policy
from .test_competition_work_signing import runtime as runtime
from .test_competition_work_signing import setup as setup
from .test_competition_work_signing import work as work


def _hold_signer_lock(path, ready, release):
    descriptor = lock_private_file(Path(path))
    try:
        ready.set()
        if not release.wait(20):
            raise RuntimeError("test did not release the child signer lock")
    finally:
        os.close(descriptor)


def _reopen(setup):
    signer = setup.signers[0]
    return signing.IndependentWorkSigner(
        setup.workers[0],
        signer.cutoffs,
        transport_provider=signer.transport_provider,
        legacy=setup.work.item.legacy_policy,
        minimum_issue_ms=1000,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("cancel", [False, True])
@pytest.mark.parametrize("failure", [False, True])
@pytest.mark.parametrize(
    "stage", ["statement", "cutoff", "vote", "observation", "proposals", "dispatch"]
)
async def test_signer_drains_preparation_before_releasing_its_lease(
    setup, monkeypatch, stage, cancel, failure
):
    signer, worker = setup.signers[0], setup.workers[0]
    other = _reopen(setup)
    owner, name = {
        "statement": (signing, "validate_statement"),
        "cutoff": (signer, "_reserved_cutoff"),
        "vote": (signer.journal, "get"),
        "observation": (signer.journal, "observe"),
        "proposals": (signing, "endpoint_proposals"),
        "dispatch": (worker.dispatch, "reserve_batch"),
    }[stage]
    original = getattr(owner, name)
    sign = signing.sign_object
    signatures = []

    def count_signatures(*args, **kwargs):
        signatures.append(args[0])
        return sign(*args, **kwargs)

    def while_locked(*args, **kwargs):
        with pytest.raises(BlockingIOError), other.journal.locked():
            pytest.fail("preparation outlived the signing lease")
        result = original(*args, **kwargs)
        if failure:
            raise OSError("injected preparation failure")
        return result

    paused = PausedCall(while_locked)
    with monkeypatch.context() as patch:
        patch.setattr(owner, name, paused)
        patch.setattr(signing, "sign_object", count_signatures)
        operation = paused.drive(signer.endorse(setup.authorization), signer.serial, cancel=cancel)
        if cancel:
            with pytest.raises(asyncio.CancelledError):
                await operation
        elif failure:
            with pytest.raises(OSError, match="injected preparation failure"):
                await operation
        else:
            assert await operation
    slot = signing.statement_slot(setup.authorization)
    if cancel or failure:
        assert not signatures
        assert signer.journal.get("vote", slot) is None
    else:
        assert len(signatures) == 1
    # Any completed capacity reservation is reusable. A cancelled preparation
    # never authorizes a signature or releases a still-running storage operation.
    vote = await other.endorse(setup.authorization)
    assert await other.endorse(setup.authorization) == vote


@pytest.mark.asyncio
@pytest.mark.parametrize("cancel", [False, True])
async def test_retained_vote_check_is_owned_and_never_signs_again(setup, monkeypatch, cancel):
    signer = setup.signers[0]
    vote = await signer.endorse(setup.authorization)
    paused = PausedCall(signer.journal.get)

    def forbidden(*args):
        pytest.fail("retained endorsement was signed again")

    with monkeypatch.context() as patch:
        patch.setattr(signer.journal, "get", paused)
        patch.setattr(signing, "sign_object", forbidden)
        operation = paused.drive(signer.endorse(setup.authorization), signer.serial, cancel=cancel)
        if cancel:
            with pytest.raises(asyncio.CancelledError):
                await operation
        else:
            assert await operation == vote
        assert await _reopen(setup).endorse(setup.authorization) == vote


@pytest.mark.asyncio
async def test_other_process_lock_prevents_endorsement_before_any_signing(setup, monkeypatch):
    signer = setup.signers[0]
    calls = []
    original_sign = signing.sign_object

    def counted_sign(*args, **kwargs):
        calls.append(args[0])
        return original_sign(*args, **kwargs)

    monkeypatch.setattr(signing, "sign_object", counted_sign)
    context = multiprocessing.get_context("spawn")
    ready, release = context.Event(), context.Event()
    child = context.Process(
        target=_hold_signer_lock, args=(str(signer.journal.lock_path), ready, release)
    )
    child.start()
    try:
        assert await asyncio.to_thread(ready.wait, 10)
        with pytest.raises(BlockingIOError):
            await signer.endorse(setup.authorization)
        slot = signing.statement_slot(setup.authorization)
        assert signer.journal.get("intent", slot) is None
        assert signer.journal.get("vote", slot) is None
        assert not calls
    finally:
        release.set()
        await asyncio.to_thread(child.join, 10)
        if child.is_alive():
            child.terminate()
            await asyncio.to_thread(child.join, 5)
    assert child.exitcode == 0
    child.close()
    vote = await signer.endorse(setup.authorization)
    assert len(calls) == 1
    assert await _reopen(setup).endorse(setup.authorization) == vote
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_distinct_signer_instances_cover_vote_lookup_through_persistence(setup, monkeypatch):
    signer = setup.signers[0]
    other = _reopen(setup)
    boundary = setup.workers[0].boundary
    entered, release = asyncio.Event(), asyncio.Event()
    calls = []
    original_sign = signing.sign_object

    async def paused_boundary():
        entered.set()
        await release.wait()
        return await boundary()

    def counted_sign(*args, **kwargs):
        calls.append(args[0])
        return original_sign(*args, **kwargs)

    monkeypatch.setattr(setup.workers[0], "boundary", paused_boundary)
    monkeypatch.setattr(signing, "sign_object", counted_sign)
    first = asyncio.create_task(signer.endorse(setup.authorization))
    try:
        await asyncio.wait_for(entered.wait(), 5)
        with pytest.raises(BlockingIOError):
            await other.endorse(setup.authorization)
        assert not calls
        release.set()
        vote = await asyncio.wait_for(first, 5)
    finally:
        release.set()
        if not first.done():
            first.cancel()
            await asyncio.gather(first, return_exceptions=True)
    assert await other.endorse(setup.authorization) == vote
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_cancellation_keeps_process_lock_until_owned_provider_stops(setup, monkeypatch):
    signer = setup.signers[0]
    other = _reopen(setup)
    worker = setup.workers[0]
    original_boundary = worker.boundary
    entered, release = threading.Event(), threading.Event()
    drained = threading.Event()
    calls = []
    original_sign = signing.sign_object

    def blocked_read():
        entered.set()
        try:
            if not release.wait(20):
                raise RuntimeError("test did not release the owned provider")
        finally:
            drained.set()

    async def boundary():
        await run_owned_thread(blocked_read)
        return await original_boundary()

    def counted_sign(*args, **kwargs):
        calls.append(args[0])
        return original_sign(*args, **kwargs)

    monkeypatch.setattr(worker, "boundary", boundary)
    monkeypatch.setattr(signing, "sign_object", counted_sign)
    pending = asyncio.create_task(signer.endorse(setup.authorization))
    try:
        assert await asyncio.to_thread(entered.wait, 5)
        pending.cancel()
        # A loop barrier lets cancellation reach the owned-task await without
        # relying on a wall-clock sleep or cancelling the provider thread.
        barrier = asyncio.Event()
        asyncio.get_running_loop().call_soon(barrier.set)
        await barrier.wait()
        assert not pending.done()
        assert not drained.is_set()
        with pytest.raises(BlockingIOError):
            await other.endorse(setup.authorization)
        pending.cancel()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(pending, 5)
    finally:
        release.set()
        if not pending.done():
            pending.cancel()
            await asyncio.gather(pending, return_exceptions=True)
    assert drained.is_set()
    assert not calls
    assert signer.journal.get("vote", signing.statement_slot(setup.authorization)) is None
    monkeypatch.setattr(worker, "boundary", original_boundary)
    assert await other.endorse(setup.authorization)
    assert len(calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("delay", ["executor_queue", "receipt_verification"])
async def test_delayed_model_signing_recollects_finality_before_signing(setup, monkeypatch, delay):
    signer, worker = setup.signers[0], setup.workers[0]
    authorization = await signer.endorse(setup.authorization)
    entered, release = asyncio.Event(), threading.Event()
    loop = asyncio.get_running_loop()
    calls, blocker = [], None
    original_sign = signing.sign_object

    def counted_sign(*args, **kwargs):
        calls.append(args[0])
        return original_sign(*args, **kwargs)

    def wait_for_release():
        if not release.wait(20):
            raise RuntimeError("test did not release the delayed signer")

    monkeypatch.setattr(signing, "sign_object", counted_sign)
    if delay == "executor_queue":
        # Occupy the actual per-operation executor before its signing task is
        # queued. The production context manager remains its shutdown owner.
        def queued_executor(*args, **kwargs):
            nonlocal blocker
            executor = ThreadPoolExecutor(*args, **kwargs)
            blocker = executor.submit(wait_for_release)
            submit = executor.submit

            def queued_submit(function, *call_args, **call_kwargs):
                pending = submit(function, *call_args, **call_kwargs)
                entered.set()
                return pending

            monkeypatch.setattr(executor, "submit", queued_submit)
            return executor

        monkeypatch.setattr(signing, "ThreadPoolExecutor", queued_executor)
    else:
        original_verify = signer.admission.verify

        def delayed_verify(plan):
            original_verify(plan)
            loop.call_soon_threadsafe(entered.set)
            wait_for_release()

        monkeypatch.setattr(signer.admission, "verify", delayed_verify)

    pending = asyncio.create_task(signer.endorse(setup.model))
    try:
        await asyncio.wait_for(entered.wait(), 5)
        assert not pending.done() and not calls
        worker.provider.block = setup.model.body.round.evaluation_close_block
        release.set()
        with pytest.raises(ValueError, match="outside its execution window"):
            await asyncio.wait_for(pending, 5)
    finally:
        release.set()
        if not pending.done():
            pending.cancel()
        await asyncio.gather(pending, return_exceptions=True)
        if blocker is not None:
            blocker.result()

    slot = signing.statement_slot(setup.model)
    assert not calls
    assert signer.journal.get("intent", slot) is None
    assert signer.journal.get("vote", slot) is None
    if delay == "executor_queue":
        monkeypatch.setattr(signing, "ThreadPoolExecutor", ThreadPoolExecutor)
    else:
        monkeypatch.setattr(signer.admission, "verify", original_verify)
    # Finality never regresses for a retry. The old exact vote remains reusable,
    # while another attempt to endorse the model at the closed head still fails.
    assert await _reopen(setup).endorse(setup.authorization) == authorization
    with pytest.raises(ValueError, match="outside its execution window"):
        await signer.endorse(setup.model)
    assert not calls and signer.journal.get("vote", slot) is None


@pytest.mark.asyncio
@pytest.mark.parametrize("stop", ["caller_cancellation", "proof_timeout"])
async def test_final_signing_proof_drains_before_releasing_process_lock(setup, monkeypatch, stop):
    signer, worker = setup.signers[0], setup.workers[0]
    await signer.endorse(setup.authorization)
    other = _reopen(setup)
    original_boundary, original_verify = worker.boundary, signer.admission.verify
    verified, entered, release, drained = (threading.Event() for _ in range(4))
    proof_cancelled = asyncio.Event()
    calls = []
    if stop == "proof_timeout":
        monkeypatch.setattr(
            worker,
            "config",
            worker.config.model_copy(
                update={
                    "chain": worker.config.chain.model_copy(
                        update={"collection_timeout_seconds": 1}
                    )
                }
            ),
        )

    def verify(plan):
        original_verify(plan)
        verified.set()

    def blocked_proof():
        entered.set()
        try:
            if not release.wait(20):
                raise RuntimeError("test did not release the final signing proof")
        finally:
            drained.set()

    async def boundary():
        if verified.is_set():
            await run_owned_thread(blocked_proof, on_cancel=proof_cancelled.set)
        return await original_boundary()

    monkeypatch.setattr(signer.admission, "verify", verify)
    monkeypatch.setattr(worker, "boundary", boundary)
    monkeypatch.setattr(signing, "sign_object", lambda *args, **kwargs: calls.append(args[0]))
    pending = asyncio.create_task(signer.endorse(setup.model))
    try:
        assert await asyncio.to_thread(entered.wait, 5)
        if stop == "caller_cancellation":
            for _ in range(2):
                pending.cancel()
                barrier = asyncio.Event()
                asyncio.get_running_loop().call_soon(barrier.set)
                await barrier.wait()
                assert not pending.done() and not drained.is_set()
                with pytest.raises(BlockingIOError):
                    await other.endorse(setup.model)
        else:
            await asyncio.wait_for(proof_cancelled.wait(), 5)
            assert not pending.done() and not drained.is_set()
            with pytest.raises(BlockingIOError):
                await other.endorse(setup.model)
        release.set()
        expected = asyncio.CancelledError if stop == "caller_cancellation" else asyncio.TimeoutError
        with pytest.raises(expected):
            await asyncio.wait_for(pending, 5)
    finally:
        release.set()
        if not pending.done():
            pending.cancel()
        await asyncio.gather(pending, return_exceptions=True)
    assert drained.is_set() and not calls
    slot = signing.statement_slot(setup.model)
    assert signer.journal.get("intent", slot) is None
    assert signer.journal.get("vote", slot) is None
    descriptor = lock_private_file(signer.journal.lock_path)
    os.close(descriptor)


@pytest.mark.asyncio
async def test_final_signing_proof_runs_with_one_default_executor_worker(setup, monkeypatch):
    signer, worker = setup.signers[0], setup.workers[0]
    await signer.endorse(setup.authorization)
    loop = asyncio.get_running_loop()
    run_in_executor = loop.run_in_executor
    original_boundary, original_verify = worker.boundary, signer.admission.verify
    original_sign = signing.sign_object
    verified = threading.Event()
    proof_threads, signing_threads = [], []

    def verify(plan):
        original_verify(plan)
        verified.set()

    async def boundary():
        if verified.is_set():
            # This read-only fixture probe has no durable effects. Its own
            # timeout makes a regression fail instead of deadlocking the test.
            proof_threads.append(
                await asyncio.wait_for(asyncio.to_thread(threading.get_ident), timeout=2)
            )
        return await original_boundary()

    def sign(*args, **kwargs):
        signing_threads.append(threading.get_ident())
        return original_sign(*args, **kwargs)

    with ThreadPoolExecutor(max_workers=1) as default_executor:

        def one_default_executor(executor, function, *args):
            return run_in_executor(
                default_executor if executor is None else executor, function, *args
            )

        with monkeypatch.context() as patch:
            # Route ordinary default submissions to a real one-worker executor
            # without replacing pytest's event-loop-owned default executor.
            patch.setattr(loop, "run_in_executor", one_default_executor)
            patch.setattr(signer.admission, "verify", verify)
            patch.setattr(worker, "boundary", boundary)
            patch.setattr(signing, "sign_object", sign)
            vote = await asyncio.wait_for(signer.endorse(setup.model), 5)
    assert len(proof_threads) == len(signing_threads) == 1
    assert proof_threads[0] != signing_threads[0]
    assert await _reopen(setup).endorse(setup.model) == vote
