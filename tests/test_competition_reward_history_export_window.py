"""Already admitted exports overlap; one owner applies and drains them."""

import asyncio
from threading import Barrier, Event, Lock
from types import SimpleNamespace

import pytest

from umi import competition_remote_proof_store as transport
from umi import competition_reward_history_parallel as parallel
from umi.competition_reward_history_checkpoint import HistoryCheckpointRepairRequired
from umi.competition_reward_proof_archive import RewardProofArchive
from umi.concurrency import await_owned_task

from .test_competition_remote_proof_store import EvidenceServer, store


def reader_for(export, *, count=2):
    values = [{"snapshot": {"block_number": h}, "exports": []} for h in range(10, 10 + count)]
    retained = {value["snapshot"]["block_number"]: value for value in values}
    loads, applied, delivered = [], [], []

    def load(height):
        loads.append(height)
        return retained[height]

    def remember(value, *, repair_reason):
        assert repair_reason == "new_export_destination"
        retained[value["snapshot"]["block_number"]] = value

    reader = SimpleNamespace(
        export_archive=object(),
        _export_fields=export,
        _export_identity=lambda: "destination",
        checkpoints=SimpleNamespace(load=load, remember=remember),
        progress=SimpleNamespace(record=lambda stage, height: delivered.append((stage, height))),
        _apply_checkpoint=lambda value: applied.append(value["snapshot"]["block_number"]),
    )
    entries = [(h, {"proof": str(h).encode()}, True) for h in retained]
    return reader, entries, values, retained, loads, applied, delivered


@pytest.mark.asyncio
async def test_later_export_finishes_first_but_effects_stay_ordered():
    loop = asyncio.get_running_loop()
    started = [asyncio.Event(), asyncio.Event()]
    release = [Event(), Event()]
    second_remembered = asyncio.Event()

    def export(height, fields, archive):
        loop.call_soon_threadsafe(started[height - 10].set)
        assert release[height - 10].wait(3)

    reader, entries, values, retained, loads, applied, delivered = reader_for(export)
    remember = reader.checkpoints.remember

    def remembered(value, **kwargs):
        remember(value, **kwargs)
        if value["snapshot"]["block_number"] == 11:
            loop.call_soon_threadsafe(second_remembered.set)

    reader.checkpoints.remember = remembered
    task = asyncio.create_task(
        parallel._apply_prepared_window(reader, entries, values, asyncio.Event())
    )
    try:
        await asyncio.wait_for(asyncio.gather(*(event.wait() for event in started)), 3)
        release[1].set()
        await asyncio.wait_for(second_remembered.wait(), 3)
        assert applied == [] and retained[11]["exports"] == ["destination"]
    finally:
        for event in release:
            event.set()
        await task
    assert applied == [10, 11] and sorted(loads) == [10, 11]
    assert sorted(delivered) == [("exported", 10), ("exported", 11)]


@pytest.mark.asyncio
async def test_failed_predecessor_drains_and_retains_later_export():
    second_exported = Event()

    def export(height, fields, archive):
        if height == 10:
            assert second_exported.wait(3)
            raise OSError("first export interrupted")
        second_exported.set()

    reader, entries, values, retained, loads, applied, delivered = reader_for(export)
    with pytest.raises(OSError, match="first export interrupted"):
        await parallel._apply_prepared_window(reader, entries, values, asyncio.Event())
    assert applied == []
    assert retained[10] == values[0] and retained[11]["exports"] == ["destination"]
    assert delivered == [("exported", 11)] and sorted(loads) == [10, 11]


@pytest.mark.asyncio
@pytest.mark.parametrize("cancel", [False, True])
async def test_stop_or_repeated_cancellation_drains_exports_before_return(cancel):
    loop = asyncio.get_running_loop()
    started = [asyncio.Event(), asyncio.Event()]
    release, stop = Event(), asyncio.Event()

    def export(height, fields, archive):
        loop.call_soon_threadsafe(started[height - 10].set)
        assert release.wait(3)

    reader, entries, values, retained, _, applied, delivered = reader_for(export)
    window = asyncio.create_task(parallel._apply_prepared_window(reader, entries, values, stop))
    owner = asyncio.create_task(await_owned_task(window, on_cancel=stop.set))
    try:
        await asyncio.wait_for(asyncio.gather(*(event.wait() for event in started)), 3)
        if cancel:
            owner.cancel()
            await asyncio.sleep(0)
            owner.cancel()
        else:
            stop.set()
        await asyncio.sleep(0)
        assert not owner.done()
    finally:
        release.set()
        if cancel:
            with pytest.raises(asyncio.CancelledError):
                await owner
        else:
            await owner
    assert applied == [] and len(delivered) == 2
    assert all(value["exports"] == ["destination"] for value in retained.values())


@pytest.mark.asyncio
async def test_changed_checkpoint_refuses_publication_and_apply():
    exports = []
    reader, entries, values, retained, _, applied, _ = reader_for(
        lambda height, *_: exports.append(height), count=1
    )
    retained[10] = {**retained[10], "changed": True}
    with pytest.raises(HistoryCheckpointRepairRequired, match="checkpoint changed"):
        await parallel._apply_prepared_window(reader, entries, values, asyncio.Event())
    assert exports == [] and applied == []


@pytest.mark.asyncio
@pytest.mark.parametrize("archive_selected", [False, True])
async def test_one_admitted_entry_and_no_archive_keep_sequential_behavior(archive_selected):
    exports = []
    reader, entries, values, _, loads, applied, _ = reader_for(
        lambda height, *_: exports.append(height), count=1
    )
    if not archive_selected:
        reader.export_archive = None
    await parallel._apply_prepared_window(reader, entries, values, asyncio.Event())
    assert exports == ([10] if archive_selected else [])
    assert loads == applied == [10]


@pytest.mark.asyncio
@pytest.mark.parametrize("bound", ["workers", "bytes"])
async def test_actual_two_frame_exports_share_existing_transport_admission(
    tmp_path, monkeypatch, bound
):
    loop = asyncio.get_running_loop()
    admitted, release, byte_wait = asyncio.Event(), Event(), asyncio.Event()
    enter = Barrier(2)
    lock, active, peak, peak_bytes = Lock(), 0, 0, 0
    selected = None

    class Server(EvidenceServer):
        def send(self, request):
            nonlocal active, peak, peak_bytes
            if request.method != "PUT":
                return super().send(request)
            with lock:
                active += 1
                peak = max(peak, active)
                with selected._lock:
                    peak_bytes = max(peak_bytes, selected._publishing_bytes)
                    assert len(selected._publishing_keys) <= transport.PROOF_PUBLICATION_WORKERS
                    assert (
                        selected._publishing_bytes <= transport.MAX_ACTIVE_PROOF_PUBLICATION_BYTES
                    )
                if active == transport.PROOF_PUBLICATION_WORKERS:
                    loop.call_soon_threadsafe(admitted.set)
            try:
                assert release.wait(3)
                return super().send(request)
            finally:
                with lock:
                    active -= 1

    if bound == "bytes":
        monkeypatch.setattr(transport, "MAX_PROOF_OBJECT_BYTES", 2048)
        monkeypatch.setattr(transport, "MAX_ACTIVE_PROOF_PUBLICATION_BYTES", 2048)
        emit = transport.TransferProgress.emit

        def observed(progress, state, *, reason=None):
            if reason == "proof_publication_byte_budget_wait":
                loop.call_soon_threadsafe(byte_wait.set)
            return emit(progress, state, reason=reason)

        monkeypatch.setattr(transport.TransferProgress, "emit", observed)
    server = Server()
    selected = store(tmp_path / "remote-owner", server)
    archive = RewardProofArchive(tmp_path / "archive", remote=selected)

    def export(height, fields, ignored):
        enter.wait(timeout=3)
        archive.write("history", f"{height:064x}", context={}, fields=fields)

    reader, _, values, _, _, applied, _ = reader_for(export)
    entries = [
        (h, {f"field{i}": (f"{h}-{i}-".encode() * 240)[:1200] for i in range(4)}, True)
        for h in (10, 11)
    ]
    task = asyncio.create_task(
        parallel._apply_prepared_window(reader, entries, values, asyncio.Event())
    )
    try:
        await asyncio.wait_for((admitted if bound == "workers" else byte_wait).wait(), 3)
    finally:
        release.set()
        await task
    assert applied == [10, 11]
    assert peak <= transport.PROOF_PUBLICATION_WORKERS
    if bound == "workers":
        assert peak == transport.PROOF_PUBLICATION_WORKERS
    else:
        assert peak_bytes <= 2048 and byte_wait.is_set()
    assert selected._publishing_keys == set() and selected._publishing_bytes == 0
