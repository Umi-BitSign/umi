"""Native model-review leases with tiny real journals and synthetic finality."""

import asyncio
import threading
import weakref
from types import SimpleNamespace

import pytest

from umi import competition_cohort_model_batch_review as batch
from umi import competition_cohort_model_review as models
from umi import host_memory_runtime as memory

from .test_competition_cohort_model_batch_adoption import adoption as adoption
from .test_competition_cohort_model_batch_review import batch_reviews as batch_reviews
from .test_competition_cohort_model_review import base_policy as base_policy
from .test_competition_cohort_model_review import legacy_scenario as legacy_scenario
from .test_competition_cohort_model_review import policy as policy
from .test_competition_cohort_model_review import prepared as prepared
from .test_competition_cohort_model_review import receipt_scenario as receipt_scenario
from .test_competition_cohort_model_review import recovery as recovery
from .test_competition_cohort_model_review import reviews as reviews
from .test_competition_cohort_model_review import runtime as runtime
from .test_host_memory_admission import provisioned as provisioned
from .test_host_memory_admission import selected
from .test_host_memory_runtime import bind

pytestmark = pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True)


async def test_batch_uses_one_shared_grant_without_blocking_owner_or_settlement(
    batch_reviews, provisioned, monkeypatch
):
    reviewer = batch_reviews.create(concurrency=2)
    peer = selected(provisioned)
    entered, release = asyncio.Event(), asyncio.Event()
    leases = []
    original = reviewer._review_inputs

    async def prepare(request, **kwargs):
        leases.append(memory._active.get())
        assert leases[-1] is not None and not leases[-1].closed
        if len(leases) == 2:
            entered.set()
        await release.wait()
        return await original(request, **kwargs)

    monkeypatch.setattr(reviewer, "_review_inputs", prepare)
    with bind(provisioned):
        task = asyncio.create_task(reviewer.attest_batch(batch_reviews.request))
        await asyncio.wait_for(entered.wait(), 5)
        assert leases[0] is leases[1]
        assert peer.try_acquire("transient") is None
        owner = peer.try_acquire("owner_export")
        coordinator = peer.try_settlement("0" * 64, "coordinator")
        independent = peer.try_settlement("1".zfill(64), "reviewer")
        assert owner is not None and coordinator is not None and independent is not None
        owner.close()
        coordinator.close()
        independent.close()
        release.set()
        vote = await task
        assert leases[0].closed
        # A completed batch still validates its exact request but needs no
        # graph lane, history, artifact reads or repeated signing.
        busy = peer.try_acquire("transient")
        assert busy is not None
        try:
            batch_reviews.original.state.online = False
            assert await asyncio.wait_for(reviewer.attest_batch(batch_reviews.request), 5) == vote
        finally:
            busy.close()
    assert len(batch_reviews.original.state.signing) == 1


async def test_cancelled_batch_keeps_grant_until_checkpoints_drain_and_reuses_them(
    batch_reviews, provisioned, monkeypatch
):
    reviewer = batch_reviews.create(concurrency=1)
    peer = selected(provisioned)
    entered, release = asyncio.Event(), asyncio.Event()
    original = reviewer._review_inputs

    async def prepare(request, **kwargs):
        entered.set()
        await release.wait()
        return await original(request, **kwargs)

    monkeypatch.setattr(reviewer, "_review_inputs", prepare)
    with bind(provisioned):
        task = asyncio.create_task(reviewer.attest_batch(batch_reviews.request))
        await asyncio.wait_for(entered.wait(), 5)
        task.cancel()
        await asyncio.sleep(0)
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done() and peer.try_acquire("transient") is None
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        available = peer.try_acquire("transient")
        assert available is not None
        available.close()
        assert not batch_reviews.original.state.signing
        restarted = batch_reviews.create(concurrency=1)

        async def forbidden(*args, **kwargs):
            raise AssertionError("completed native model preparation was repeated")

        monkeypatch.setattr(restarted, "_review_inputs", forbidden)
        vote = await restarted.attest_batch(batch_reviews.request)
        assert vote.batch == batch_reviews.request.batch
    assert len(batch_reviews.original.state.signing) == 1


async def test_serial_batch_discards_failed_item_graph_before_next_item(
    batch_reviews, provisioned, monkeypatch
):
    class Graph:
        pass

    references = []

    async def prepare(reviewer, request, history, block):
        if not references:
            graph = Graph()
            references.append(weakref.ref(graph))
            # Exception args and completed frames both own the rejected graph.
            raise ValueError(graph)
        assert references[0]() is None
        assert memory._active.get() is not None

    monkeypatch.setattr(batch, "_prepare_entry", prepare)
    reviewer = batch_reviews.create(concurrency=1)
    with bind(provisioned), pytest.raises(OSError, match="preparation remains incomplete"):
        await reviewer.attest_batch(batch_reviews.request)
    assert references[0]() is None
    assert not batch_reviews.original.state.signing
    lease = selected(provisioned).try_acquire("transient")
    assert lease is not None
    lease.close()


async def test_single_model_waits_for_phase_lane_then_reuses_committed_vote(
    reviews, provisioned, monkeypatch
):
    reviewer = reviews.create("Charlie")
    peer = selected(provisioned)
    busy = peer.try_acquire("transient")
    original = reviewer.history
    history_entered = asyncio.Event()

    async def history(cohort):
        assert memory._active.get() is not None
        history_entered.set()
        return await original(cohort)

    monkeypatch.setattr(reviewer, "history", history)
    with bind(provisioned):
        task = asyncio.create_task(reviewer.attest(reviews.request))
        # The task reaches its native lock before waiting for capacity.
        for _ in range(100):
            if reviewer.serial.locked():
                break
            await asyncio.sleep(0)
        assert reviewer.serial.locked() and not history_entered.is_set()
        busy.close()
        vote = await asyncio.wait_for(task, 5)
        assert history_entered.is_set()
        busy = peer.try_acquire("transient")
        assert busy is not None
        try:
            reviews.state.online = False
            assert await asyncio.wait_for(reviewer.attest(reviews.request), 5) == vote
        finally:
            busy.close()


async def test_batch_adoption_history_is_leased_and_completed_vote_bypasses_grant(
    adoption, provisioned, monkeypatch
):
    reviewer = adoption.create("Charlie")
    original = reviewer.history

    async def history(cohort):
        assert memory._active.get() is not None
        return await original(cohort)

    monkeypatch.setattr(reviewer, "history", history)
    with bind(provisioned):
        vote = await reviewer.attest_batch_adoption(adoption.request)
        busy = selected(provisioned).try_acquire("transient")
        assert busy is not None
        try:
            adoption.r.state.online = False
            assert (
                await asyncio.wait_for(reviewer.attest_batch_adoption(adoption.request), 5) == vote
            )
        finally:
            busy.close()


async def test_transport_repair_drains_native_thread_before_releasing_grant(
    reviews, provisioned, monkeypatch
):
    reviewer = reviews.create("Charlie")
    await reviewer.attest(reviews.request)
    entered, release = threading.Event(), threading.Event()
    peer = selected(provisioned)

    def repair(*args, **kwargs):
        assert memory._active.get() is not None
        entered.set()
        assert release.wait(5)
        return {"repaired": True}

    monkeypatch.setattr(models, "repair_journal_model_transport", repair)
    a = reviews.request.acceptance
    with bind(provisioned):
        task = asyncio.create_task(
            reviewer.repair_transport_qualification(
                a.cohort_sha256, a.submission_sha256, reason="test original transport repair"
            )
        )
        try:
            for _ in range(500):
                if entered.is_set():
                    break
                await asyncio.sleep(0.01)
            assert entered.is_set()
            task.cancel()
            await asyncio.sleep(0)
            task.cancel()
            await asyncio.sleep(0)
            assert not task.done() and peer.try_acquire("transient") is None
        finally:
            release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
    lease = peer.try_acquire("transient")
    assert lease is not None
    lease.close()


async def test_nested_model_work_refuses_before_history_instead_of_waiting_on_own_grant(
    reviews, provisioned
):
    reviewer = reviews.create("Charlie")

    @memory.memory_operation
    async def nested():
        return await reviewer.attest(reviews.request)

    with bind(provisioned):
        with pytest.raises(RuntimeError, match="nested host memory operation"):
            await asyncio.wait_for(nested(), 5)
        assert not reviewer.serial.locked() and not reviews.state.signing
        # The rejected nested attempt neither kept a lease nor reserved a vote.
        await asyncio.wait_for(reviewer.attest(reviews.request), 5)
    assert len(reviews.state.signing) == 1


async def test_retained_direct_transport_is_admitted_before_native_history_read(
    reviews, provisioned, monkeypatch
):
    reviewer = reviews.create("Charlie")
    calls = []

    def qualify(acceptance):
        lease = memory._active.get()
        assert lease is not None and not lease.closed
        calls.append(lease)

    monkeypatch.setattr(reviewer, "_qualify_transport", qualify)
    with bind(provisioned):
        await reviewer._qualify_retained_transport(reviews.request.acceptance)
    assert len(calls) == 1 and calls[0].closed


async def test_selected_profile_caps_actual_preparation_workers(batch_reviews, monkeypatch):
    reviewer = batch_reviews.create(concurrency=4)
    active = peak = completed = 0

    async def prepare(*args):
        nonlocal active, peak, completed
        active += 1
        peak = max(peak, active)
        try:
            await asyncio.sleep(0)
            completed += 1
        finally:
            active -= 1

    monkeypatch.setattr(batch, "_prepare_entry", prepare)
    monkeypatch.setattr(
        batch,
        "selected_workload",
        lambda: SimpleNamespace(profile=SimpleNamespace(maximum_preparation_workers=1)),
    )
    await batch._prepare_all(reviewer, batch_reviews.request, None, 1)
    assert peak == 1 and completed == len(batch_reviews.request.requests) and active == 0
