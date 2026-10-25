"""Shared native checkpoints queue without blocking their async holder."""

import asyncio

import pytest

from umi.competition_transport_verification import (
    ByteCheckpoints,
    TransferProgress,
    owned_byte_checkpoint,
)
from umi.private_files import PrivateStateBusyError


async def test_waiter_keeps_holder_running_and_reports_wait_then_acquisition(tmp_path):
    waiting = asyncio.Event()
    reports = []

    def report(value):
        reports.append(value)
        if value.get("reason_code") == "shared_byte_checkpoint_busy":
            waiting.set()

    with TransferProgress("test", 1, report) as progress:
        holder = ByteCheckpoints(tmp_path / "store", {}, progress)
        with holder:

            async def consume():
                async with owned_byte_checkpoint(
                    ByteCheckpoints(holder.root, {}, progress), progress
                ) as saved:
                    saved.remember("file", "generation", "a" * 64)

            task = asyncio.create_task(consume())
            await asyncio.wait_for(waiting.wait(), timeout=3)
            assert not task.done()
        await asyncio.wait_for(task, timeout=3)
        with ByteCheckpoints(holder.root, {}, progress) as saved:
            assert saved.load("file", "generation") == "a" * 64
    assert any(r.get("reason_code") == "shared_byte_checkpoint_acquired" for r in reports)
    assert all(r["eta_seconds"] is None for r in reports if r["status"] == "retrying")


async def test_cancelled_waiter_never_releases_the_holder(tmp_path):
    waiting = asyncio.Event()
    with TransferProgress(
        "test",
        1,
        lambda event: (
            waiting.set() if event.get("reason_code") == "shared_byte_checkpoint_busy" else None
        ),
    ) as progress:
        holder = ByteCheckpoints(tmp_path / "store", {}, progress)
        with holder:

            async def consume():
                async with owned_byte_checkpoint(
                    ByteCheckpoints(holder.root, {}, progress), progress
                ):
                    raise AssertionError("waiter acquired the held store")

            task = asyncio.create_task(consume())
            await asyncio.wait_for(waiting.wait(), timeout=3)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            with pytest.raises(PrivateStateBusyError), ByteCheckpoints(holder.root, {}, progress):
                pass


async def test_cancelled_holder_releases_its_own_lease(tmp_path):
    entered = asyncio.Event()
    with TransferProgress("test", 1) as progress:

        async def consume():
            async with owned_byte_checkpoint(
                ByteCheckpoints(tmp_path / "store", {}, progress), progress
            ):
                entered.set()
                await asyncio.Event().wait()

        task = asyncio.create_task(consume())
        await asyncio.wait_for(entered.wait(), timeout=3)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        with ByteCheckpoints(tmp_path / "store", {}, progress):
            pass


async def test_unsafe_lock_is_refused_without_retry(tmp_path):
    root = tmp_path / "store"
    root.mkdir(mode=0o700)
    (root / ".verification.lock").symlink_to(tmp_path / "unrelated")
    reports = []
    with (
        TransferProgress("test", 1, reports.append) as progress,
        pytest.raises((ValueError, OSError)),
    ):
        async with owned_byte_checkpoint(ByteCheckpoints(root, {}, progress), progress):
            raise AssertionError("unsafe store was accepted")
    assert not any(r.get("reason_code") == "shared_byte_checkpoint_busy" for r in reports)
