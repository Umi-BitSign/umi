"""Concurrent resident models on real files; no native inference is claimed."""

import asyncio
import shutil
from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest

from umi.competition_cohort_parallel_cache import ModelPlan, ParallelModelCache
from umi.competition_model_cache_space import BootDiskModelCache, BootDiskModelCacheConfig
from umi.open_competition import digest
from umi.private_files import ensure_private_directory
from umi.protocol import StrictProtocolModel

from .test_open_competition import bundle_at


class Job(StrictProtocolModel):
    name: str
    runtime: str = "inert"


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
        assert s.admission.active == 2 and sorted(s.calls) == ["a", "b", "reference"]
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


async def test_cancelling_pairs_releases_readers_and_expanded_slots(cache):
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
    assert not (s.port.cache / "slot-0002").exists()


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


async def test_large_pair_keeps_exclusive_single_model_fallback(cache):
    s, job = cache, Job(name="a")
    for name in ("a", "reference"):
        bundle = s.bundles[name]
        files = tuple(
            f.model_copy(update={"size_bytes": 4 * 1024**2}) if f.role == "weights" else f
            for f in bundle.files
        )
        s.bundles[name] = bundle.model_copy(update={"files": files})
    s.port.boot = s.port.boot.model_copy(update={"maximum_allocated_bytes": 6 * 1024**2})
    async with s.helper.scope(job):
        assert s.helper.exclusive and s.admission.active == 2 and s.calls == []
        candidate = s.helper.plan(job, "candidate")
        reference = s.helper.plan(job, "incumbent")
        first = await s.helper.acquire(candidate, job.runtime)
        await s.helper.release(first)
        second = await s.helper.acquire(reference, job.runtime)
        await s.helper.release(second)
        assert not (first / digest(candidate.bundle)).exists()
        assert (second / digest(reference.bundle) / "model").is_dir()
    assert s.admission.active == 0


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
            assert s.admission.active == 1 and s.helper.readers[path] == 1
        finally:
            s.block.set()
            await s.helper.release(path)
