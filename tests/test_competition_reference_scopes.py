"""Each native reward replay retains its reference across another caller's switch."""

import asyncio
import os
from threading import Event

import pytest

from umi import competition_artifacts as native
from umi import competition_cohort_reference_preparation as references
from umi.open_competition import digest

from .test_competition_reference_working_set import case as case
from .test_competition_reference_working_set import policy as policy
from .test_open_competition import bundle_at


def switching_worker(case):
    second = bundle_at(case.root / "second-source", "second-cohort")
    native.preserve_bundle(second, case.root / "second-source", case.archive, case.artifacts.policy)
    worker = case.create()
    worker._source = lambda selected: (
        case.source if selected == "first" else references._Source(second)
    )
    return worker, case.archive / digest(case.bundle), case.archive / digest(second)


async def test_scope_keeps_reference_through_different_cohort_cache_switch(case):
    worker, first, second = switching_worker(case)
    async with worker.scope("first"):
        await worker.ensure("second")
        assert first.exists() and second.exists()
        assert native.verify_preserved_bundle(
            case.bundle, case.archive, case.artifacts.policy
        ) == digest(case.bundle)
    assert not first.exists() and second.exists()
    worker.close()
    assert second.exists()  # The preexisting second bundle is never owned here.


async def test_overlapping_scopes_retire_only_after_last_reader(case):
    worker, first, second = switching_worker(case)
    async with worker.scope("first"):
        async with worker.scope("first"):
            await worker.ensure("second")
            assert first.exists()
        assert first.exists()
    assert not first.exists() and second.exists()
    worker.close()
    assert len(case.calls) == 1


async def test_scoped_reference_outlives_persistent_owner_shutdown(case):
    worker = case.create()
    async with worker.scope(None):
        worker.close()
        assert worker.active is None
        assert (case.archive / digest(case.bundle)).exists()
    assert not (case.archive / digest(case.bundle)).exists()


async def test_cancelled_replay_releases_only_its_reference(case):
    worker, first, second = switching_worker(case)
    entered = asyncio.Event()

    async def replay():
        async with worker.scope("first"):
            entered.set()
            await asyncio.Event().wait()

    task = asyncio.create_task(replay())
    await asyncio.wait_for(entered.wait(), timeout=5)
    await worker.ensure("second")
    assert first.exists()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert not first.exists() and second.exists()
    worker.close()


async def test_cancellation_during_scope_acquisition_cannot_leak_shared_fd(case, monkeypatch):
    worker = case.create()
    await worker.ensure(None)
    acquired, release = Event(), Event()
    original = references.lock_private_file

    def delayed(*args, **kwargs):
        fd = original(*args, **kwargs)
        acquired.set()
        if not release.wait(5):
            os.close(fd)
            raise AssertionError("fixture did not release owned acquisition")
        return fd

    monkeypatch.setattr(references, "lock_private_file", delayed)

    async def replay():
        async with worker.scope(None):
            raise AssertionError("cancelled acquisition entered replay")

    task = asyncio.create_task(replay())
    assert await asyncio.to_thread(acquired.wait, 5)
    task.cancel()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    worker.close()
    assert not (case.archive / digest(case.bundle)).exists()


async def test_scope_keeps_legacy_readonly_path_free_of_new_ownership(case):
    native.preserve_bundle(case.bundle, case.root / "source", case.archive, case.artifacts.policy)
    case.artifacts.config.reference_preservation_directory = None
    worker = case.create()
    async with worker.scope(None):
        assert worker.active is None
        assert not (case.archive / ".reference-working-set").exists()
    worker.close()
    assert (case.archive / digest(case.bundle)).exists()
