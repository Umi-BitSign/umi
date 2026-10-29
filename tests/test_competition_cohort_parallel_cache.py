"""Concurrent resident models on real files; no native inference is claimed."""

import asyncio
import json
import logging
import shutil
from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest

from umi.competition_cohort_execution_journal import IncumbentSourcePending
from umi.competition_cohort_parallel_cache import ModelPlan, ParallelModelCache
from umi.competition_model_cache_space import BootDiskModelCache, BootDiskModelCacheConfig
from umi.open_competition import digest
from umi.private_files import ensure_private_directory
from umi.protocol import StrictProtocolModel

from .test_host_memory_admission import provisioned as provisioned
from .test_host_model_execution import Runtime
from .test_host_model_execution import capacity as capacity
from .test_open_competition import bundle_at


class Job(StrictProtocolModel):
    name: str
    runtime: str = "inert"


class ExecutionJob(StrictProtocolModel):
    name: str
    runtime: Runtime


class Capacity:
    slots = (0, 1)

    def __init__(self):
        self.condition, self.active = asyncio.Condition(), 0
        self.prepare = asyncio.Lock()

    @asynccontextmanager
    async def hold(self, runtime, *, exclusive=False, preparation=False):
        if preparation:
            async with self.prepare:
                yield
            return
        count = 2 if exclusive else 1
        async with self.condition:
            await self.condition.wait_for(lambda: self.active + count <= 2)
            self.active += count
        try:
            yield
        finally:
            async with self.condition:
                self.active -= count
                self.condition.notify_all()


@pytest.fixture
def cache(tmp_path):
    root = tmp_path / "boot"
    ensure_private_directory(root)
    selected = root / "direct-model-cache"
    ensure_private_directory(selected)
    boot = BootDiskModelCacheConfig(
        schema="umi-boot-disk-model-cache/1",
        directory=str(root),
        maximum_allocated_bytes=16 * 1024**2,
    )
    bundles = {name: bundle_at(tmp_path / name, name) for name in ("a", "b", "c", "reference")}
    calls, evicted = [], []
    block, loading = asyncio.Event(), asyncio.Event()
    block.set()

    class Materializer:
        def cache_identity(self, request):
            return digest(bundles[request])

        async def resumable(self, request, archive):
            return (archive / digest(bundles[request]) / "model").is_dir()

        async def materialized(self, request, archive):
            return await self.resumable(request, archive)

        async def materialize(self, request, archive):
            if request == "c":
                loading.set()
                await block.wait()
            calls.append(request)
            ensure_private_directory(archive)
            model = archive / digest(bundles[request]) / "model"
            ensure_private_directory(model.parent)
            for f in bundles[request].files:
                ensure_private_directory(
                    model / f.path.rsplit("/", 1)[0] if "/" in f.path else model
                )
                path = model / f.path
                with path.open("wb") as stream:
                    stream.truncate(f.size_bytes)
                path.chmod(0o400)

    materializer = Materializer()

    async def source(job, role):
        name = job.name if role == "candidate" else "reference"
        return ModelPlan(name, bundles[name], materializer, digest(bundles[name]))

    async def evict(path):
        budget = BootDiskModelCache(boot, reserve_bytes=0)
        with budget.allocation_lease():
            shutil.rmtree(path)
            evicted.append(path)
            port.slot_identities.pop(path, None)

    port = SimpleNamespace(
        cache=selected,
        boot=boot,
        slot_identities={},
        slot_clock=0,
        artifacts=SimpleNamespace(
            config=SimpleNamespace(materialization_free_space_reserve_bytes=0)
        ),
        _source_plan=source,
        _evict_archive=evict,
    )
    admission = Capacity()
    helper = ParallelModelCache(port, admission, 2)
    return SimpleNamespace(
        helper=helper,
        port=port,
        calls=calls,
        evicted=evicted,
        bundles=bundles,
        admission=admission,
        block=block,
        loading=loading,
    )


async def test_source_reservation_callback_precedes_capacity_and_materialization(cache):
    s = cache
    callbacks = []

    async def before_reserve():
        assert s.admission.active == 0 and not s.admission.prepare.locked()
        assert not s.calls and not s.helper.pairs and not s.helper.pins
        callbacks.append("reserved")

    async with s.helper.scope(Job(name="a"), before_reserve=before_reserve):
        assert callbacks == ["reserved"]
        assert s.admission.active == 0 and sorted(s.calls) == ["a", "reference"]
        assert len(s.helper.pairs) == 1
    assert s.admission.active == 0 and not s.helper.pairs


async def test_pending_source_callback_never_acquires_or_materializes(cache):
    s = cache

    async def before_reserve():
        raise IncumbentSourcePending("shared incumbent source remains unfinished")

    with pytest.raises(IncumbentSourcePending):
        async with s.helper.scope(Job(name="a"), before_reserve=before_reserve):
            pytest.fail("pending source cannot enter model execution")
    assert not s.calls and not s.helper.pairs and not s.helper.pins
    assert s.admission.active == 0 and not s.admission.prepare.locked()


async def test_oversized_model_refuses_before_source_reservation_callback(cache):
    s = cache
    bundle = s.bundles["a"]
    s.bundles["a"] = bundle.model_copy(
        update={
            "files": (
                bundle.files[0].model_copy(update={"size_bytes": 32 * 1024**2}),
                *bundle.files[1:],
            )
        }
    )

    async def forbidden():
        pytest.fail("an infeasible first model must not reserve the shared source")

    with pytest.raises(OSError, match="exceeds the bounded boot cache"):
        async with s.helper.scope(Job(name="a"), before_reserve=forbidden):
            pytest.fail("oversized model cannot enter execution")
    assert not s.calls and not s.helper.pairs and s.admission.active == 0


async def test_candidate_only_scopes_fit_two_models_without_resolving_reference(cache, monkeypatch):
    s, job_a, job_b = cache, Job(name="a"), Job(name="b")
    original = s.port._source_plan
    resolved = []

    async def source(job, role):
        resolved.append(role)
        assert role == "candidate", "reused reference must not be resolved or restored"
        return await original(job, role)

    monkeypatch.setattr(s.port, "_source_plan", source)
    budget = s.helper.budget()
    cap = sum(budget.model_bytes(s.bundles[name]) for name in ("a", "b")) + 8192
    s.port.boot = s.port.boot.model_copy(update={"maximum_allocated_bytes": cap})
    async with (
        s.helper.scope(job_a, model_roles=("candidate",)),
        s.helper.scope(job_b, model_roles=("candidate",)),
    ):
        assert len(s.helper.pairs) == 2 and not s.helper.exclusive
        assert sorted(s.calls) == ["a", "b"]
        assert resolved == ["candidate", "candidate"]
        with pytest.raises(ValueError, match="omitted"):
            s.helper.plan(job_b, "incumbent")
        # The unchanged two-role working set cannot admit both candidates
        # under this same cap, demonstrating actual constrained residency.
        reference = await original(job_b, "incumbent")
        plans = {"candidate": s.helper.plan(job_b, "candidate"), "incumbent": reference}
        s.helper.concurrency = 3
        sizes = {p.identity: budget.model_bytes(p.bundle) for p in plans.values()}
        selected, reason, counts = await s.helper._selection(plans, s.helper.budget(), sizes)
        assert selected is None and reason == "cumulative_model_bytes"
        assert counts["working_model_bytes"] > counts["resident_capacity_bytes"]
    assert not s.helper.pairs and not any(s.helper.pins.values())


async def test_reservation_can_narrow_plans_before_loading_or_pinning(cache):
    s, job = cache, Job(name="a")

    async def before_reserve():
        return ("candidate",)

    async with s.helper.scope(job, before_reserve=before_reserve):
        assert s.calls == ["a"]
        assert s.helper.pins[digest(s.bundles["reference"])] == 0


async def test_reused_reference_is_evictable_while_candidate_reader_stays_protected(cache):
    s, job_a, job_b = cache, Job(name="a"), Job(name="b")
    for name in ("a", "b", "reference"):
        bundle = s.bundles[name]
        s.bundles[name] = bundle.model_copy(
            update={
                "files": tuple(
                    f.model_copy(update={"size_bytes": 256 * 1024}) if f.role == "weights" else f
                    for f in bundle.files
                )
            }
        )
    async with s.helper.scope(job_a):
        pass
    # The shared materializer deliberately creates sparse fixtures. Allocate
    # the two retained weights here so admitting b must reclaim actual bytes.
    for name in ("a", "reference"):
        bundle = s.bundles[name]
        slot = next(path for path, ident in s.helper.assigned.items() if ident == digest(bundle))
        for f in bundle.files:
            if f.role == "weights":
                path = slot / digest(bundle) / "model" / f.path
                path.chmod(0o600)
                path.write_bytes(b"\0" * f.size_bytes)
                path.chmod(0o400)
    reference_path = next(
        path
        for path, identity in s.helper.assigned.items()
        if identity == digest(s.bundles["reference"])
    )
    budget = s.helper.budget()
    cap = sum(budget.model_bytes(s.bundles[name]) for name in ("a", "b")) + 8192
    s.port.boot = s.port.boot.model_copy(update={"maximum_allocated_bytes": cap})
    async with s.helper.scope(job_a, model_roles=("candidate",)):
        candidate = s.helper.plan(job_a, "candidate")
        candidate_path = await s.helper.acquire(candidate, job_a.runtime)
        try:
            async with s.helper.scope(job_b, model_roles=("candidate",)):
                assert reference_path in s.evicted
                assert not (reference_path / digest(s.bundles["reference"])).exists()
                assert (candidate_path / digest(candidate.bundle) / "model").is_dir()
                assert s.helper.readers[candidate_path] == 1
                assert s.calls == ["a", "reference", "b"]
        finally:
            await s.helper.release(candidate_path)


@pytest.mark.parametrize(
    "reason",
    [
        "cache_allocation_owner",
        "individual_model_capacity",
        "requested_pair_exclusive",
        "active_pair_exclusive",
        "pair_concurrency",
        "model_slot_count",
        "cumulative_model_bytes",
    ],
)
async def test_capacity_refusal_reports_existing_decision_without_extra_scan(
    cache, monkeypatch, reason
):
    s, calls = cache, []
    a = await s.port._source_plan(Job(name="a"), "candidate")
    b = await s.port._source_plan(Job(name="b"), "candidate")
    ref = await s.port._source_plan(Job(name="a"), "incumbent")
    s.helper.pairs["existing"] = {"candidate": a}
    plans, sizes, capacity = {"candidate": b}, {b.identity: 6}, 10
    if reason == "cache_allocation_owner":
        capacity = None
    elif reason == "individual_model_capacity":
        capacity = 5
    elif reason == "requested_pair_exclusive":
        plans["incumbent"], sizes[ref.identity] = ref, 6
    elif reason == "active_pair_exclusive":
        s.helper.exclusive = True
    elif reason == "pair_concurrency":
        s.helper.concurrency = 1
    elif reason == "model_slot_count":
        s.helper.slots = s.helper.slots[:1]

    async def resident(_):
        calls.append(True)
        return capacity

    monkeypatch.setattr(s.helper, "_resident_capacity", resident)
    budget = SimpleNamespace(model_bytes=lambda _: 6)
    selected, observed, counts = await s.helper._selection(plans, budget, sizes)
    assert selected is None and observed == reason and calls == [True]
    assert counts["active_pair_count"] == 1 and counts["resident_capacity_bytes"] == capacity


async def test_unchanged_capacity_decision_logs_once_while_queue_heartbeats_continue(
    cache, monkeypatch, caplog
):
    caplog.set_level(logging.INFO, logger="umi.competition.progress")
    polls = []

    async def selection(*_):
        polls.append(True)
        return None, "pair_concurrency", {"active_pair_count": 2, "pair_limit": 2}

    async def changed():
        if len(polls) == 3:
            raise asyncio.CancelledError

    monkeypatch.setattr(cache.helper, "_selection", selection)
    monkeypatch.setattr(cache.helper, "_capacity_changed", changed)
    with pytest.raises(asyncio.CancelledError):
        async with cache.helper.scope(Job(name="a")):
            pytest.fail("capacity refusal cannot enter execution")
    events = [
        json.loads(record.message)
        for record in caplog.records
        if record.name == "umi.competition.progress"
    ]
    decisions = [event for event in events if event.get("stage") == "model_pair_capacity"]
    assert len(polls) == 3 and len(decisions) == 1
    assert decisions[0]["active_pair_count"] == decisions[0]["pair_limit"] == 2
    assert decisions[0]["reason_code"] == "pair_concurrency"
    assert decisions[0]["eta_seconds"] is None and decisions[0]["stalled_or_retrying"]
    assert not cache.calls and not cache.helper.pairs


async def test_two_pairs_share_reference_and_keep_ready_reads_off_the_transfer_lane(cache):
    s, a, b, c = cache, Job(name="a"), Job(name="b"), Job(name="c")
    a_exit, b_exit, c_exit = asyncio.Event(), asyncio.Event(), asyncio.Event()
    entered = {name: asyncio.Event() for name in "abc"}

    async def pair(job, stop):
        async with s.helper.scope(job):
            entered[job.name].set()
            plan = s.helper.plan(job, "candidate")
            path = await s.helper.acquire(plan, job.runtime)
            try:
                await stop.wait()
                assert (path / digest(plan.bundle) / "model").is_dir()
            finally:
                await s.helper.release(path)

    first, second = asyncio.create_task(pair(a, a_exit)), asyncio.create_task(pair(b, b_exit))
    third = None
    try:
        await asyncio.wait_for(asyncio.gather(entered["a"].wait(), entered["b"].wait()), 3)
        assert s.admission.active == 0 and sorted(s.calls) == ["a", "b", "reference"]
        assert len(s.helper.pairs) == 2
        assert sum(s.helper.readers.values()) == 2
        s.block.clear()
        third = asyncio.create_task(pair(c, c_exit))
        a_exit.set()
        await asyncio.wait_for(s.loading.wait(), 3)
        reference = s.helper.plan(b, "incumbent")
        path = await asyncio.wait_for(s.helper.acquire(reference, b.runtime), 0.5)
        await s.helper.release(path)
        assert (path / digest(reference.bundle) / "model").is_dir()
        s.block.set()
        await asyncio.wait_for(entered["c"].wait(), 3)
    finally:
        s.block.set()
        a_exit.set()
        b_exit.set()
        c_exit.set()
        await asyncio.gather(first, second, *(() if third is None else (third,)))
    assert not s.helper.pairs and s.admission.active == 0


async def test_cancelling_pairs_releases_readers_and_keeps_bounded_restart_work(cache):
    s, entered, release = cache, asyncio.Queue(), asyncio.Event()

    async def pair(name):
        job = Job(name=name)
        async with s.helper.scope(job):
            path = await s.helper.acquire(s.helper.plan(job, "candidate"), job.runtime)
            try:
                await entered.put(path)
                await release.wait()
            finally:
                await s.helper.release(path)

    tasks = [asyncio.create_task(pair(name)) for name in ("a", "b")]
    try:
        await asyncio.wait_for(asyncio.gather(entered.get(), entered.get()), 3)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    assert not s.helper.pairs and not any(s.helper.readers.values()) and s.admission.active == 0
    assert (s.port.cache / "slot-0002").is_dir()
    before = list(s.calls)
    s.port.slot_identities.clear()
    restarted = ParallelModelCache(s.port, s.admission, 2)
    async with restarted.scope(Job(name="a")), restarted.scope(Job(name="b")):
        assert s.calls == before


async def test_restart_reuses_original_slots_without_reloading_payload(cache):
    s, job = cache, Job(name="a")
    with pytest.raises(RuntimeError, match="restart"):
        async with s.helper.scope(job):
            raise RuntimeError("restart")
    assert sorted(s.calls) == ["a", "reference"]
    s.port.slot_identities.clear()
    restarted = ParallelModelCache(s.port, s.admission, 2)
    async with restarted.scope(job):
        assert sorted(s.calls) == ["a", "reference"]


async def test_completed_job_keeps_reference_for_next_batch(cache):
    s = cache
    async with s.helper.scope(Job(name="a")):
        pass
    assert sorted(s.calls) == ["a", "reference"]
    async with s.helper.scope(Job(name="b")):
        assert sorted(s.calls) == ["a", "b", "reference"]
    assert not (s.port.cache / "slot-0002").exists()


@pytest.mark.parametrize("limit", ["quota", "physical"])
async def test_large_pair_keeps_exclusive_single_model_fallback(cache, monkeypatch, limit):
    s, job = cache, Job(name="a")
    for name in ("a", "reference"):
        bundle = s.bundles[name]
        files = tuple(
            f.model_copy(update={"size_bytes": 4 * 1024**2}) if f.role == "weights" else f
            for f in bundle.files
        )
        s.bundles[name] = bundle.model_copy(update={"files": files})
    if limit == "quota":
        s.port.boot = s.port.boot.model_copy(update={"maximum_allocated_bytes": 6 * 1024**2})
    else:
        from umi import competition_model_cache_space as space

        def usage(_):
            allocated, _ = BootDiskModelCache(s.port.boot, reserve_bytes=0)._allocation()
            return SimpleNamespace(free=max(0, 6 * 1024**2 - allocated))

        monkeypatch.setattr(space.shutil, "disk_usage", usage)
    async with s.helper.scope(job):
        assert s.helper.exclusive and s.admission.active == 0 and s.calls == []
        candidate = s.helper.plan(job, "candidate")
        reference = s.helper.plan(job, "incumbent")
        first = await s.helper.acquire(candidate, job.runtime)
        await s.helper.release(first)
        second = await s.helper.acquire(reference, job.runtime)
        await s.helper.release(second)
        assert not (first / digest(candidate.bundle)).exists()
        assert (second / digest(reference.bundle) / "model").is_dir()
    assert s.admission.active == 0


async def test_second_pair_waits_for_physical_room_without_restarting_preparation(
    cache, monkeypatch
):
    from umi import competition_model_cache_space as space

    s, budget = cache, cache.helper.budget()
    sizes = {k: budget.model_bytes(v) for k, v in s.bundles.items()}
    physical = [sizes["a"] + sizes["reference"] + 8192]

    def usage(_):
        allocated, _ = s.helper.budget()._allocation()
        return SimpleNamespace(free=max(0, physical[0] - allocated))

    monkeypatch.setattr(space.shutil, "disk_usage", usage)
    s.helper.capacity_poll_seconds = 0.01
    entered = {k: asyncio.Event() for k in ("a", "b")}
    stop = asyncio.Event()

    async def pair(name):
        async with s.helper.scope(Job(name=name)):
            entered[name].set()
            await stop.wait()

    first = asyncio.create_task(pair("a"))
    second = None
    try:
        await asyncio.wait_for(entered["a"].wait(), 3)
        second = asyncio.create_task(pair("b"))
        await asyncio.sleep(0.05)
        assert not entered["b"].is_set()
        assert sorted(s.calls) == ["a", "reference"]
        assert len(s.helper.pairs) == 1
        physical[0] = sum(sizes[k] for k in ("a", "b", "reference")) + 65536
        async with s.helper.condition:
            s.helper.condition.notify_all()
        await asyncio.wait_for(entered["b"].wait(), 3)
        assert sorted(s.calls) == ["a", "b", "reference"]
    finally:
        stop.set()
        await asyncio.gather(first, *(() if second is None else (second,)))


async def test_external_capacity_loss_keeps_one_owned_preparation_and_cancels_cleanly(
    cache, monkeypatch
):
    s, checked, space_ready = cache, asyncio.Event(), False
    calls = []

    def fits(self, models):
        calls.append(tuple(models))
        checked.set()
        return space_ready

    monkeypatch.setattr(BootDiskModelCache, "fits_materializations", fits)
    s.helper.capacity_poll_seconds = 3600
    entered, stop = asyncio.Event(), asyncio.Event()

    async def pair():
        async with s.helper.scope(Job(name="a")):
            entered.set()
            await stop.wait()

    task = asyncio.create_task(pair())
    try:
        await asyncio.wait_for(checked.wait(), 3)
        await asyncio.sleep(0.01)
        assert len(calls) == 1 and not entered.is_set() and s.calls == []
        space_ready = True
        async with s.helper.condition:
            s.helper.condition.notify_all()
        await asyncio.wait_for(entered.wait(), 3)
        assert len(calls) == 2 and sorted(s.calls) == ["a", "reference"]
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    assert not s.helper.pairs and not any(s.helper.readers.values())
    assert s.admission.active == 0


async def test_nonfitting_pair_does_not_block_a_smaller_ready_pair(cache, monkeypatch):
    from umi import competition_model_cache_space as space

    s = cache
    for name, amount in [("a", 4 * 1024**2), ("b", 4 * 1024**2), ("reference", 1024**2)]:
        bundle = s.bundles[name]
        s.bundles[name] = bundle.model_copy(
            update={
                "files": tuple(
                    f.model_copy(update={"size_bytes": amount}) if f.role == "weights" else f
                    for f in bundle.files
                )
            }
        )

    def usage(_):
        allocated, _ = s.helper.budget()._allocation()
        return SimpleNamespace(free=max(0, 6 * 1024**2 - allocated))

    monkeypatch.setattr(space.shutil, "disk_usage", usage)
    s.helper.capacity_poll_seconds = 0.01
    entered = {k: asyncio.Event() for k in ("a", "b", "c")}
    stop = asyncio.Event()

    async def pair(name):
        async with s.helper.scope(Job(name=name)):
            entered[name].set()
            await stop.wait()

    tasks = [asyncio.create_task(pair("a"))]
    try:
        await asyncio.wait_for(entered["a"].wait(), 3)
        tasks.append(asyncio.create_task(pair("b")))
        await asyncio.sleep(0.05)
        assert s.admission.active == 0 and not entered["b"].is_set()
        assert len(s.helper.pairs) == 1
        tasks.append(asyncio.create_task(pair("c")))
        await asyncio.wait_for(entered["c"].wait(), 3)
        assert not entered["b"].is_set() and s.admission.active == 0
        assert len(s.helper.pairs) == 2
        assert sorted(s.calls) == ["a", "c", "reference"]
    finally:
        stop.set()
        await asyncio.gather(*tasks)


async def test_cancelled_transfer_keeps_other_pairs_readable(cache):
    s, job = cache, Job(name="a")
    async with s.helper.scope(job):
        plan = s.helper.plan(job, "candidate")
        path = await s.helper.acquire(plan, job.runtime)
        s.block.clear()

        async def downloading():
            async with s.helper.scope(Job(name="c")):
                pytest.fail("blocked transfer entered execution")

        pending = asyncio.create_task(downloading())
        try:
            await asyncio.wait_for(s.loading.wait(), 3)
            pending.cancel()
            with pytest.raises(asyncio.CancelledError):
                await pending
            assert (path / digest(plan.bundle) / "model").is_dir()
            assert s.admission.active == 0 and s.helper.readers[path] == 1
        finally:
            s.block.set()
            await s.helper.release(path)


async def test_real_admission_prepares_two_pairs_then_runs_with_2034_gib(
    cache, capacity, monkeypatch
):
    from umi import host_memory_admission as native

    s, admission = cache, capacity.start()
    s.helper = ParallelModelCache(s.port, admission, 2)
    # Reproduce the old hold-and-wait envelope with actual root-bound leases:
    # 2 * 8 GiB model slots + 1 GiB preparation + 4 GiB reserve + 2 GiB background.
    first = admission.controller.try_acquire_group("transient", 1)
    second = admission.controller.try_acquire_group("transient", 1)
    assert first and second
    monkeypatch.setattr(native, "_available_memory", lambda: 21_332_116 * 1024)
    try:
        assert admission.controller.try_acquire_group("owner_export", 1) is None
    finally:
        first.close()
        second.close()

    prepared, invoked = asyncio.Queue(), asyncio.Queue()
    begin = asyncio.Event()
    finished = {name: asyncio.Event() for name in ("a", "b")}
    active = 0

    async def pair(name):
        nonlocal active
        job = ExecutionJob(name=name, runtime=capacity.runtime)
        async with s.helper.scope(job):
            await prepared.put(name)
            await begin.wait()
            path = await s.helper.acquire(s.helper.plan(job, "candidate"), job.runtime)
            try:
                async with admission.invocation(job.runtime):
                    active += 1
                    try:
                        assert active == 1
                        assert admission.controller.try_acquire_group("transient", 1) is None
                        await invoked.put(name)
                        await finished[name].wait()
                    finally:
                        active -= 1
            finally:
                await s.helper.release(path)

    tasks = [asyncio.create_task(pair(name)) for name in ("a", "b")]
    try:
        assert set(await asyncio.wait_for(asyncio.gather(prepared.get(), prepared.get()), 5)) == {
            "a",
            "b",
        }
        assert len(s.helper.pairs) == 2 and sorted(s.calls) == ["a", "b", "reference"]
        # Both resident pairs leave native slots unowned, so the feasible
        # single-model-plus-preparation envelope still has its full headroom.
        model = admission.controller.try_acquire_group("transient", 1)
        assert model
        try:
            preparation = admission.controller.try_acquire_group("owner_export", 1)
            assert preparation
            preparation.close()
        finally:
            model.close()
        begin.set()
        first_name = await asyncio.wait_for(invoked.get(), 5)
        await asyncio.sleep(0)
        assert invoked.empty()
        finished[first_name].set()
        second_name = await asyncio.wait_for(invoked.get(), 5)
        assert first_name != second_name
        finished[second_name].set()
        await asyncio.wait_for(asyncio.gather(*tasks), 5)
    finally:
        begin.set()
        for event in finished.values():
            event.set()
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    assert not s.helper.pairs and not any(s.helper.readers.values())


async def test_real_admission_exclusive_swaps_release_native_slots_between_models(
    cache, capacity, monkeypatch
):
    from umi import host_memory_admission as native

    s, admission = cache, capacity.start()
    s.helper = ParallelModelCache(s.port, admission, 2)
    for name in ("a", "reference"):
        bundle = s.bundles[name]
        s.bundles[name] = bundle.model_copy(
            update={
                "files": tuple(
                    f.model_copy(update={"size_bytes": 4 * 1024**2}) if f.role == "weights" else f
                    for f in bundle.files
                )
            }
        )
    s.port.boot = s.port.boot.model_copy(update={"maximum_allocated_bytes": 6 * 1024**2})
    monkeypatch.setattr(native, "_available_memory", lambda: 21_332_116 * 1024)
    job = ExecutionJob(name="a", runtime=capacity.runtime)

    async def run():
        async with s.helper.scope(job):
            assert s.helper.exclusive
            for role in ("candidate", "incumbent"):
                plan = s.helper.plan(job, role)
                path = await s.helper.acquire(plan, job.runtime)
                try:
                    async with admission.invocation(job.runtime):
                        assert (path / digest(plan.bundle) / "model").is_dir()
                        assert admission.controller.try_acquire_group("transient", 1) is None
                finally:
                    await s.helper.release(path)
                # A completed invocation has released its capacity even while
                # the pair still owns the exclusive single-model swap path.
                available = admission.controller.try_acquire_group("transient", 1)
                assert available
                available.close()

    await asyncio.wait_for(run(), 5)
    assert sorted(s.calls) == ["a", "reference"]
    assert not s.helper.pairs and not s.helper.exclusive and not any(s.helper.readers.values())


async def test_cancelled_native_waiter_releases_readers_and_reuses_prepared_models(
    cache, capacity, monkeypatch
):
    from umi import host_memory_admission as native

    s, admission = cache, capacity.start()
    s.helper = ParallelModelCache(s.port, admission, 2)
    monkeypatch.setattr(native, "_available_memory", lambda: 13 * 1024**3)
    job = ExecutionJob(name="a", runtime=capacity.runtime)
    reading = asyncio.Event()

    async def waiting():
        async with s.helper.scope(job):
            path = await s.helper.acquire(s.helper.plan(job, "candidate"), job.runtime)
            try:
                reading.set()
                async with admission.invocation(job.runtime):
                    pytest.fail("native memory reserve is unavailable")
            finally:
                await s.helper.release(path)

    task = asyncio.create_task(waiting())
    try:
        await asyncio.wait_for(reading.wait(), 5)
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert not s.helper.pairs and not any(s.helper.readers.values())
    assert not any(s.helper.pins.values())
    assert sorted(s.calls) == ["a", "reference"]
    before = list(s.calls)
    monkeypatch.setattr(native, "_available_memory", lambda: 21_332_116 * 1024)
    s.port.slot_identities.clear()
    restarted = ParallelModelCache(s.port, admission, 2)
    async with restarted.scope(job), admission.invocation(job.runtime):
        assert s.calls == before
    available = admission.controller.try_acquire_group("transient", 1)
    assert available
    available.close()
