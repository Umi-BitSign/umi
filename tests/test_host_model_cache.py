"""Bundle-cache ownership, bounded native preparation and restart fixtures."""

import asyncio
import json
import os
import shutil
import sys
from contextlib import contextmanager
from pathlib import Path
from threading import Event
from types import SimpleNamespace

import pytest

from umi import host_model_cache as cache
from umi.competition_cohort_public_progress import PUBLIC_COHORT_PROGRESS, PUBLIC_COHORT_SCOPE
from umi.competition_cpu_cache import CpuBundleCacheEvidence, validate_bundle_cache_evidence
from umi.competition_cpu_timing import CpuTimingInfrastructureError
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_open_competition import bundle_at

INVOCATION = "ef" * 32


async def no_container(invocation):
    assert len(invocation) == 64


@pytest.fixture
def prepared(tmp_path):
    source = tmp_path / "source"
    bundle = bundle_at(source)
    archive = tmp_path / "archive"
    model = archive / digest(bundle) / "model"
    shutil.copytree(source, model)
    for path in model.iterdir():
        with path.open("rb") as stream:
            os.fsync(stream.fileno())
    return bundle, archive, model


def zero_pages(fd, size, page, stop, advance):
    assert not stop.is_set()
    count = (size + page - 1) // page
    advance(count)
    return count


async def test_conditioned_receipt_counts_and_cached_public_progress(prepared, monkeypatch):
    bundle, archive, model = prepared
    monkeypatch.setattr(cache, "_evict_file", zero_pages)
    cohort = "ec" * 32
    token = PUBLIC_COHORT_SCOPE.set(cohort)
    try:
        async with cache.model_cache_lease(
            archive, bundle, exclusive=True, invocation_sha256=INVOCATION, reconcile=no_container
        ) as lease:
            receipt = await lease.condition(bundle, INVOCATION)
            assert receipt.file_count == len(bundle.files)
            assert receipt.total_bytes == sum(f.size_bytes for f in bundle.files)
            assert receipt.total_pages == len(bundle.files)
            assert receipt.resident_pages == 0
            assert (
                validate_bundle_cache_evidence(
                    receipt,
                    model_sha256=digest(bundle),
                    invocation_sha256=INVOCATION,
                    measured_start_us=receipt.finished_monotonic_us,
                )
                is receipt
            )
            snapshot = PUBLIC_COHORT_PROGRESS.snapshot(cohort)
            text = json.dumps(snapshot)
            assert "model_cache_conditioning" in text
            assert "eta_basis" in text and "elapsed_seconds" in text
            assert str(archive) not in text and INVOCATION not in text
            assert digest(bundle) not in text
            assert snapshot["components"]["work"]["completed"] == len(bundle.files)
            with pytest.raises(CpuTimingInfrastructureError, match="lacks_owned"):
                await lease.condition(bundle, INVOCATION)
            lease.cleaned()
    finally:
        PUBLIC_COHORT_SCOPE.reset(token)
    assert (archive / (".cpu-cache-" + digest(bundle) + ".lock")).stat().st_size == 0
    assert not any(p.name.startswith(".cpu-cache") for p in model.iterdir())


@pytest.mark.parametrize("mutation", ["model", "invocation", "time"])
def test_cache_receipt_replay_rejects_other_model_attempt_or_future(mutation):
    evidence = CpuBundleCacheEvidence(
        schema="umi-cpu-bundle-cache-evidence/1",
        model_sha256="ab" * 32,
        invocation_sha256=INVOCATION,
        file_count=1,
        total_bytes=100,
        total_pages=1,
        page_size=4096,
        started_monotonic_us=10,
        finished_monotonic_us=20,
    )
    options = dict(
        model_sha256=evidence.model_sha256, invocation_sha256=INVOCATION, measured_start_us=20
    )
    options[
        {"model": "model_sha256", "invocation": "invocation_sha256", "time": "measured_start_us"}[
            mutation
        ]
    ] = 19 if mutation == "time" else "cd" * 32
    with pytest.raises(ValueError, match="original cold-bundle"):
        validate_bundle_cache_evidence(evidence, **options)


@pytest.mark.skipif(sys.platform != "linux", reason="Linux page cache protocol")
def test_real_owned_sparse_file_evicts_with_bounded_nonfaulting_mincore(tmp_path):
    path = tmp_path / "sparse"
    with path.open("w+b") as stream:
        stream.truncate(2 * cache.WINDOW_BYTES + 17)
        os.fsync(stream.fileno())
        completed = []
        pages = cache._evict_file(
            stream.fileno(),
            path.stat().st_size,
            os.sysconf("SC_PAGE_SIZE"),
            Event(),
            completed.append,
        )
    assert len(completed) == 3
    assert max(completed) <= cache.WINDOW_BYTES // os.sysconf("SC_PAGE_SIZE")
    assert pages == sum(completed)


def test_large_streaming_bundle_never_reads_or_maps_payload_beyond_window(tmp_path, monkeypatch):
    # Sparse 9 GiB represents supported streaming models larger than an 8 GiB
    # invocation reservation. Kernel observations are mocked; no pages allocated.
    path = tmp_path / "streaming"
    size = 9 * 1024**3 + 1
    with path.open("wb") as stream:
        stream.truncate(size)
    windows = []

    @contextmanager
    def mapped(fd, offset, length):
        windows.append((offset, length))
        assert length <= cache.WINDOW_BYTES
        yield SimpleNamespace(mincore=lambda address, count, vector: 0), 1

    monkeypatch.setattr(cache, "_mincore_window", mapped)
    advised = []
    monkeypatch.setattr(cache.os, "posix_fadvise", lambda *args: advised.append(args))
    with path.open("rb") as stream:
        pages = cache._evict_file(stream.fileno(), size, 4096, Event(), lambda n: None)
    assert pages == (size + 4095) // 4096
    assert len(windows) == 145
    assert advised[0][2] == pages * 4096
    assert path.stat().st_blocks * 512 < 1024**2


def test_nonzero_mincore_observation_is_infrastructure_failure(tmp_path, monkeypatch):
    def resident(address, length, vector):
        vector[0] = 1
        return 0

    @contextmanager
    def mapped(*args):
        yield SimpleNamespace(mincore=resident), 1

    monkeypatch.setattr(cache, "_mincore_window", mapped)
    path = tmp_path / "payload"
    path.write_bytes(b"abc")
    with (
        path.open("rb") as stream,
        pytest.raises(CpuTimingInfrastructureError, match="pages_remain"),
    ):
        cache._evict_file(stream.fileno(), 3, 4096, Event(), lambda n: None)


async def test_cross_process_reader_blocks_only_same_model_and_releases_on_exit(prepared, tmp_path):
    bundle, archive, _ = prepared
    other = bundle_at(tmp_path / "other", marker="other")
    key = archive / (".cpu-cache-" + digest(bundle) + ".lock")
    worker = await asyncio.create_subprocess_exec(
        sys.executable,
        "-I",
        "-B",
        "-c",
        "import fcntl,sys; f=open(sys.argv[1],'a+b'); "
        "fcntl.flock(f,fcntl.LOCK_SH); print('ready',flush=True); sys.stdin.read()",
        str(key),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
    )
    try:
        assert await worker.stdout.readline() == b"ready\n"
        entered = asyncio.Event()

        async def waiting():
            async with cache.model_cache_lease(
                archive,
                bundle,
                exclusive=True,
                invocation_sha256=INVOCATION,
                reconcile=no_container,
            ) as lease:
                entered.set()
                lease.cleaned()

        # Test child-created lock has the same owner-private permissions as service.
        key.chmod(0o600)
        task = asyncio.create_task(waiting())
        async with cache.model_cache_lease(
            archive, other, exclusive=True, invocation_sha256="ad" * 32, reconcile=no_container
        ) as lease:
            assert not entered.is_set()
            lease.cleaned()
        worker.stdin.close()
        await worker.wait()
        await asyncio.wait_for(task, 3)
        assert entered.is_set()
    finally:
        if worker.returncode is None:
            worker.kill()
            await worker.wait()


async def test_cancelled_wait_does_not_unlock_other_reader(prepared):
    bundle, archive, _ = prepared
    async with cache.model_cache_lease(archive, bundle):
        pending = asyncio.create_task(
            cache.model_cache_lease(
                archive,
                bundle,
                exclusive=True,
                invocation_sha256=INVOCATION,
                reconcile=no_container,
            ).__aenter__()
        )
        await asyncio.sleep(0)
        assert not pending.done()
        pending.cancel()
        with pytest.raises(asyncio.CancelledError):
            await pending
    async with cache.model_cache_lease(
        archive, bundle, exclusive=True, invocation_sha256=INVOCATION, reconcile=no_container
    ) as lease:
        lease.cleaned()


async def test_conditioning_cancellation_drains_thread_before_releasing_lease(
    prepared, monkeypatch
):
    bundle, archive, _ = prepared
    began, cancellation, release = Event(), Event(), Event()

    def slow(fd, size, page, stop, advance):
        began.set()
        assert stop.wait(3)
        cancellation.set()
        assert release.wait(3)
        raise InterruptedError("drained")

    monkeypatch.setattr(cache, "_evict_file", slow)

    async def condition():
        async with cache.model_cache_lease(
            archive, bundle, exclusive=True, invocation_sha256=INVOCATION, reconcile=no_container
        ) as lease:
            await lease.condition(bundle, INVOCATION)

    task = asyncio.create_task(condition())
    assert await asyncio.to_thread(began.wait, 3)
    task.cancel()
    assert await asyncio.to_thread(cancellation.wait, 3)
    assert not task.done()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    recovered = []

    async def reconcile(invocation):
        recovered.append(invocation)

    async with cache.model_cache_lease(
        archive, bundle, exclusive=True, invocation_sha256="ad" * 32, reconcile=reconcile
    ) as lease:
        lease.cleaned()
    assert recovered == [INVOCATION]


async def test_owner_death_marker_reconciles_exact_invocation_before_new_owner(prepared):
    bundle, archive, _ = prepared
    script = """import asyncio,os,sys
sys.path.insert(0,sys.argv[1])
from umi.host_model_cache import model_cache_lease
from umi.open_competition import ModelBundle
async def reconcile(invocation): pass
async def main():
    async with model_cache_lease(sys.argv[2], ModelBundle.model_validate_json(sys.argv[3]),
            exclusive=True, invocation_sha256=sys.argv[4], reconcile=reconcile):
        os._exit(0)
asyncio.run(main())
"""
    worker = await asyncio.create_subprocess_exec(
        sys.executable,
        "-I",
        "-B",
        "-c",
        script,
        str(Path(cache.__file__).parents[1]),
        str(archive),
        canonical_json_bytes(bundle).decode(),
        INVOCATION,
    )
    assert await worker.wait() == 0
    with pytest.raises(CpuTimingInfrastructureError, match="needs_reconciliation"):
        async with cache.model_cache_lease(archive, bundle):
            pytest.fail("stale container was treated as gone")
    called = []

    async def reconcile(invocation):
        called.append(invocation)

    async with cache.model_cache_lease(
        archive, bundle, exclusive=True, invocation_sha256="ad" * 32, reconcile=reconcile
    ) as lease:
        assert called == [INVOCATION]
        assert lease._marker() == "ad" * 32
        lease.cleaned()


async def test_failed_cleanup_marker_is_retained_and_failed_recovery_refuses(prepared):
    bundle, archive, _ = prepared
    async with cache.model_cache_lease(
        archive, bundle, exclusive=True, invocation_sha256=INVOCATION, reconcile=no_container
    ):
        pass  # Simulated failed container cleanup: deliberately no cleaned().

    async def failed(invocation):
        assert invocation == INVOCATION
        raise OSError("container remains")

    with pytest.raises(OSError, match="container remains"):
        async with cache.model_cache_lease(
            archive, bundle, exclusive=True, invocation_sha256="ad" * 32, reconcile=failed
        ):
            pytest.fail("recovery failure lost retained ownership")
    async with cache.model_cache_lease(
        archive, bundle, exclusive=True, invocation_sha256="ad" * 32, reconcile=no_container
    ) as lease:
        lease.cleaned()


async def test_retirement_waits_for_readers(prepared):
    bundle, archive, _ = prepared
    entered = asyncio.Event()

    async def retire():
        async with cache.model_cache_retirement(archive):
            entered.set()

    async with cache.model_cache_lease(archive, bundle):
        pending = asyncio.create_task(retire())
        await asyncio.sleep(0)
        assert not entered.is_set()
    await asyncio.wait_for(pending, 3)
    assert entered.is_set()


@pytest.mark.parametrize("damage", ["symlink", "hardlink", "changed", "owner"])
async def test_bundle_metadata_damage_is_not_cache_success(prepared, monkeypatch, tmp_path, damage):
    bundle, archive, model = prepared
    target = model / bundle.files[0].path
    if damage == "symlink":
        target.unlink()
        target.symlink_to(tmp_path / "missing")
    elif damage == "hardlink":
        os.link(target, tmp_path / "link")
    elif damage == "owner":
        monkeypatch.setattr(cache.os, "geteuid", lambda: os.getuid() + 1)
    else:

        def mutate(fd, size, page, stop, advance):
            with target.open("ab") as stream:
                stream.write(b"x")
            return zero_pages(fd, size, page, stop, advance)

        monkeypatch.setattr(cache, "_evict_file", mutate)
    with pytest.raises((ValueError, OSError, CpuTimingInfrastructureError)):
        async with cache.model_cache_lease(
            archive, bundle, exclusive=True, invocation_sha256=INVOCATION, reconcile=no_container
        ) as lease:
            await lease.condition(bundle, INVOCATION)


async def test_retirement_reconciles_retained_orphan_before_unlink(prepared):
    bundle, archive, _ = prepared
    async with cache.model_cache_lease(
        archive, bundle, exclusive=True, invocation_sha256=INVOCATION, reconcile=no_container
    ):
        pass
    with pytest.raises(CpuTimingInfrastructureError, match="needs_reconciliation"):
        async with cache.model_cache_retirement(archive):
            pytest.fail("orphan container was discarded with its cache")
    called = []

    async def reconcile(invocation):
        called.append(invocation)

    async with cache.model_cache_retirement(archive, reconcile=reconcile):
        assert called == [INVOCATION]
        shutil.rmtree(archive)
    assert not archive.exists()


async def test_ordinary_runner_automatically_joins_shared_reader_exclusion(prepared, monkeypatch):
    from umi import competition_runner as runner

    bundle, archive, _ = prepared
    running, release, timed_entered = asyncio.Event(), asyncio.Event(), asyncio.Event()

    async def inner(**arguments):
        lease = arguments["model_cache_lease"]
        assert not lease.exclusive
        lease.check(bundle)
        running.set()
        await release.wait()
        return "legacy-result"

    monkeypatch.setattr(runner, "_execute_offline_case", inner)
    ordinary = asyncio.create_task(
        runner.execute_offline_case(
            bundle=bundle,
            archive=archive,
            runtime=object(),
            policy=object(),
            case_id="ab" * 32,
            video_sha256="cd" * 32,
            video=b"fixture",
        )
    )

    async def timed_reader():
        async with cache.model_cache_lease(
            archive, bundle, exclusive=True, invocation_sha256=INVOCATION, reconcile=no_container
        ) as lease:
            timed_entered.set()
            lease.cleaned()

    contender = None
    try:
        await asyncio.wait_for(running.wait(), 3)
        contender = asyncio.create_task(timed_reader())
        await asyncio.sleep(0)
        assert not timed_entered.is_set()
        release.set()
        assert await ordinary == "legacy-result"
        await asyncio.wait_for(contender, 3)
        assert timed_entered.is_set()
    finally:
        release.set()
        if not ordinary.done():
            ordinary.cancel()
        if contender is not None and not contender.done():
            contender.cancel()
        await asyncio.gather(
            ordinary, *(() if contender is None else (contender,)), return_exceptions=True
        )
