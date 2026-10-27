"""Actual spawn workers through native histories, checkpoints and restart."""

import asyncio
import json
import multiprocessing
import sys
import threading
from contextlib import asynccontextmanager
from pathlib import Path

import pytest

from umi import competition_reward_history_workers as workers
from umi.competition_reward_history import RewardControlHistoryReader
from umi.competition_reward_history_checkpoint import HistoryCheckpointRepairRequired
from umi.competition_reward_history_workers import (
    HistoryVerificationProfile,
    HistoryWorkerError,
    HistoryWorkers,
    HistoryWorkerSelection,
)
from umi.competition_reward_proof_archive import RewardProofArchive, history_archive_key
from umi.competition_verification_rules import runtime_identity
from umi.encoding import account_id32
from umi.historical_header_recovery import HistoricalHeaderRecoveryPending
from umi.open_competition import digest
from umi.substrate_proof import SubstrateProofLimits
from umi.validator_chain_scan import ValidatorChainScanError

from .history_worker_fixtures import fixture_data, initialize
from .test_competition_reward_control_writes import commit
from .test_competition_reward_history import chain as chain
from .test_competition_reward_history import chain_config as chain_config
from .test_competition_reward_history import control as control
from .test_competition_reward_history import historical as historical
from .test_competition_reward_history import history_case as history_case
from .test_competition_reward_history import policy as policy
from .test_competition_reward_history import series_case as series_case
from .test_validator_chain_scan import extrinsic, success

pytestmark = pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)


def profile(**kw):
    return HistoryVerificationProfile(schema="umi-history-verification-profile/1", **kw)


def selection(provider, hotkey):
    executor = provider._runtime_executor
    return HistoryWorkerSelection(
        provider._runtime_pin,
        provider._storage_codec is not None,
        str(provider.resources.proof_binary),
        provider.config.proof_binary_sha256,
        SubstrateProofLimits(),
        5.0,
        provider._proofs._limits,
        None if executor is None else provider._runtime_proofs._limits,
        None if executor is None else str(provider.resources.runtime_metadata_binary),
        provider.config.runtime_metadata_binary_sha256,
        None if executor is None else executor.timeout_seconds,
        "0x" + provider.config.chain_pin.genesis_block_hash,
        provider.config.finality_pin.release_sha256_by_target[provider.config.target_triple],
        digest(provider.config),
        hotkey,
        runtime_identity(),
    )


def inject_spawn_fixture(monkeypatch, native_selection, fixture):
    constructor = workers._SpawnWorker
    created = []

    def create(selected):
        assert selected == native_selection
        worker = constructor(selected, initializer=initialize, initializer_args=(fixture,))
        created.append(worker)
        return worker

    monkeypatch.setattr(workers, "_SpawnWorker", create)
    monkeypatch.setattr(
        HistoryWorkerSelection,
        "from_provider",
        classmethod(lambda cls, provider, hotkey: native_selection),
    )
    return created


@pytest.fixture
async def parallel_case(history_case, tmp_path, monkeypatch):
    return await retained_parallel_case(history_case, tmp_path, monkeypatch)


async def retained_parallel_case(h, tmp_path, monkeypatch):
    """Retain original serial frames, then run native spawned offline consumers."""
    for _ in range(100):
        try:
            expected = await h.reader.advance(
                h.item.provider, through_block=h.end, maximum_blocks=4096
            )
        except HistoricalHeaderRecoveryPending:
            continue
        if expected.history is not None:
            break
    else:
        pytest.fail("original retained history did not converge")
    frames, decoded, events = {}, {}, {}
    for height in range(h.reader.first_block, h.end + 1):
        fields = h.reader._load(height)
        frames[height] = fields
        body = json.loads(fields["evidence"])
        at = {
            w.extrinsic_index: w.decision_sha256
            for w in expected.history.writes
            if w.block_number == height
        }
        for i, raw in enumerate(body["extrinsics"]):
            raw = bytes.fromhex(raw)
            decoded[raw] = extrinsic(raw, commit(at[i]), account_id32(h.item.hotkey))
        events[bytes.fromhex(body["events"]["value"])] = [success(i) for i in at]
    fixture = fixture_data(
        [(v["slot_evidence"], v["slot_metadata"], v["evidence"]) for v in frames.values()],
        decoded,
        events,
    )
    h.native_selection = selection(h.item.provider, h.item.hotkey)
    h.pools = inject_spawn_fixture(monkeypatch, h.native_selection, fixture)
    h.fixture, h.expected, h.frames = fixture, expected, frames
    old = h.reader

    def open_reader(maximum_bytes=None):
        return RewardControlHistoryReader(
            tmp_path / "parallel-history",
            control_hotkey=old.hotkey,
            chain_config_sha256=old.config_sha256,
            first_block=old.first_block,
            maximum_bytes=old.journal.maximum_bytes if maximum_bytes is None else maximum_bytes,
            verification_profile=profile(),
        )

    h.open_parallel = open_reader
    h.reader = open_reader()
    with h.reader.journal.locked():
        for height, fields in frames.items():
            h.reader._save_fields(height, fields)
    h.offline_through = h.end
    return h


async def test_spawned_native_history_matches_serial_and_restart_reuses_receipts(
    parallel_case, monkeypatch
):
    h = parallel_case
    actual = await h.reader.advance(h.item.provider, through_block=h.end)
    assert actual == h.expected
    assert h.reader.progress.native_completed == len(h.frames)
    assert h.reader.progress.latest["applied_blocks"] == len(h.frames)
    assert h.reader.progress.latest["captured_blocks"] == len(h.frames)
    assert h.reader.progress.latest["verified_blocks"] == len(h.frames)
    assert h.reader.progress.latest["exported_blocks"] == 0
    assert h.reader.progress.latest["replicated_blocks"] is None
    assert len(h.pools) == 2
    assert all(not child.is_alive() for child in multiprocessing.active_children())
    h.reader = h.open_parallel()

    def forbidden(*_):
        raise AssertionError("unchanged completed payload was reread")

    monkeypatch.setattr(h.reader, "_load", forbidden)
    assert await h.reader.advance(h.item.provider, through_block=h.end) == actual
    assert h.reader.progress.native_completed == 0
    assert len(h.pools) == 2


async def test_out_of_order_completion_is_checkpointed_before_predecessor(
    parallel_case, monkeypatch
):
    h = parallel_case
    first = h.reader.first_block
    h.fixture["delay"] = {first: 2.0}
    remember = h.reader.checkpoints.remember
    completed = []

    def record(value, **kw):
        remember(value, **kw)
        completed.append(value["snapshot"]["block_number"])

    monkeypatch.setattr(h.reader.checkpoints, "remember", record)
    assert await h.reader.advance(h.item.provider, through_block=h.end) == h.expected
    assert completed.index(first + 1) < completed.index(first)
    assert [w.block_number for w in h.expected.history.writes] == sorted(
        w.block_number for w in h.expected.history.writes
    )


async def test_failed_predecessor_preserves_later_native_result_for_repair(parallel_case):
    h = parallel_case
    first = h.reader.first_block
    h.fixture["wrong_result"] = {first}
    with pytest.raises(HistoryWorkerError, match="private invocation"):
        await h.reader.advance(h.item.provider, through_block=h.end)
    assert h.reader._next == first
    assert h.reader.checkpoints.load(first) is None
    assert h.reader.checkpoints.load(first + 1) is not None
    assert h.reader.progress.latest["verified_blocks"] == 1
    assert h.reader.progress.latest["applied_blocks"] == 0
    h.fixture.pop("wrong_result")
    h.reader = h.open_parallel()
    assert await h.reader.advance(h.item.provider, through_block=h.end) == h.expected
    assert h.reader.progress.native_completed == len(h.frames) - 1


async def test_source_mutation_requires_explicit_scoped_parallel_repair(parallel_case, monkeypatch):
    h = parallel_case
    first = h.reader.first_block
    remember = h.reader.checkpoints.remember
    affected = first + 1

    def mutate(value, **kw):
        if value["snapshot"]["block_number"] == affected:
            with h.reader.journal.transaction() as db:
                db.execute(
                    "UPDATE records SET body=body WHERE kind='control_history_block' AND id=?",
                    (str(affected),),
                )
        return remember(value, **kw)

    monkeypatch.setattr(h.reader.checkpoints, "remember", mutate)
    with pytest.raises(HistoryCheckpointRepairRequired):
        await h.reader.advance(h.item.provider, through_block=h.end)
    h.reader = h.open_parallel()
    assert (
        await h.reader.repair_checkpoints(
            h.item.provider, through_block=h.end, reason="qualified changed source revision"
        )
        == h.expected
    )
    assert h.reader.checkpoints.load(first)["repair"] is None
    assert (
        h.reader.checkpoints.load(affected)["repair"]["reason"]
        == "qualified changed source revision"
    )


async def test_export_failure_retains_native_success_then_resume(
    parallel_case, tmp_path, monkeypatch
):
    h = parallel_case
    h.reader.export_archive = RewardProofArchive(tmp_path / "export")

    def failed(*_):
        raise OSError("replica unavailable")

    monkeypatch.setattr(h.reader, "_export_fields", failed)
    with pytest.raises(OSError, match="replica unavailable"):
        await h.reader.advance(h.item.provider, through_block=h.end)
    assert h.reader.checkpoints.load(h.reader.first_block) is not None
    assert h.reader.checkpoints.load(h.reader.first_block + 1) is not None
    h.reader = h.open_parallel()
    h.reader.export_archive = RewardProofArchive(tmp_path / "export")
    assert await h.reader.advance(h.item.provider, through_block=h.end) == h.expected
    assert h.reader.progress.native_completed == len(h.frames) - 2
    assert h.reader.progress.latest["exported_blocks"] == len(h.frames)
    assert h.reader.progress.latest["replicated_blocks"] is None


async def test_later_export_success_survives_failed_predecessor_and_restart(
    parallel_case, tmp_path, monkeypatch
):
    h = parallel_case
    first = h.reader.first_block
    destination = tmp_path / "export"
    h.reader.export_archive = RewardProofArchive(destination)
    export = h.reader._export_fields
    second_exported = threading.Event()

    def interrupted(height, fields, archive):
        if height == first:
            assert second_exported.wait(5)
            raise OSError("predecessor export interrupted")
        export(height, fields, archive)
        if height == first + 1:
            second_exported.set()

    monkeypatch.setattr(h.reader, "_export_fields", interrupted)
    with pytest.raises(OSError, match="predecessor export interrupted"):
        await h.reader.advance(h.item.provider, through_block=h.end)
    assert h.reader._next == first
    assert h.reader.checkpoints.load(first)["exports"] == []
    assert h.reader.checkpoints.load(first + 1)["exports"] == [h.reader._export_identity()]
    second_key = history_archive_key(h.reader.config_sha256, h.reader.hotkey, first + 1)
    assert (
        h.reader.export_archive.read("history", second_key, bounds=h.reader._field_bounds)[1]
        == (h.frames[first + 1])
    )

    h.reader = h.open_parallel()
    h.reader.export_archive = RewardProofArchive(destination)
    load, copy = h.reader._load, h.reader.export_archive.copy_encoded_transport

    def unchanged_source(height):
        assert height != first + 1, "completed later export must not reload its proof fields"
        return load(height)

    def unchanged_export(kind, key, **kwargs):
        assert key != second_key, "completed later export must not repeat transport"
        return copy(kind, key, **kwargs)

    monkeypatch.setattr(h.reader, "_load", unchanged_source)
    monkeypatch.setattr(h.reader.export_archive, "copy_encoded_transport", unchanged_export)
    assert await h.reader.advance(h.item.provider, through_block=h.end) == h.expected
    assert h.reader.progress.native_completed == len(h.frames) - 2
    assert h.reader.progress.latest["exported_blocks"] == len(h.frames)


@pytest.mark.parametrize("signal", ["cancel", "shutdown"])
async def test_repeated_cancellation_drains_workers_and_provider_before_close(
    parallel_case, monkeypatch, signal
):
    h = parallel_case
    h.reader.shutdown_event = asyncio.Event()
    first = h.reader.first_block
    h.fixture["delay"] = {first: 1.0, first + 1: 1.0}
    submitted = asyncio.Event()
    submit = HistoryWorkers.submit

    def started(pool, **kw):
        result = submit(pool, **kw)
        if kw["snapshot"].block_number == first + 1:
            submitted.set()
        return result

    monkeypatch.setattr(HistoryWorkers, "submit", started)
    task = asyncio.create_task(h.reader.advance(h.item.provider, through_block=h.end))
    await asyncio.wait_for(submitted.wait(), timeout=15)
    close = asyncio.create_task(h.item.provider.aclose())
    if signal == "cancel":
        task.cancel()
    else:
        h.reader.shutdown_event.set()
    await asyncio.sleep(0.01)
    if signal == "cancel":
        task.cancel()
    else:
        h.reader.shutdown_event.set()
    assert not close.done()
    if signal == "cancel":
        with pytest.raises(asyncio.CancelledError):
            await task
        assert not h.reader.shutdown_event.is_set()
    else:
        result = await task
        assert result.history is None and result.next_block == first
    await close
    assert h.reader.checkpoints.load(first) is not None
    assert h.reader.checkpoints.load(first + 1) is not None
    assert not multiprocessing.active_children()
    if signal == "shutdown":
        await h.restart()
        h.reader = h.open_parallel()
        assert await h.reader.advance(h.item.provider, through_block=h.end) == h.expected
        assert h.reader.progress.native_completed == len(h.frames) - 2


async def test_worker_crash_drains_without_claiming_history(parallel_case):
    h = parallel_case
    h.fixture["crash"] = {h.reader.first_block}
    with pytest.raises(HistoryWorkerError, match="process exited"):
        await h.reader.advance(h.item.provider, through_block=h.end)
    assert h.reader._next == h.reader.first_block
    assert not multiprocessing.active_children()
    h.fixture.pop("crash")
    h.reader = h.open_parallel()
    assert await h.reader.advance(h.item.provider, through_block=h.end) == h.expected


async def test_crashed_worker_cleans_actual_native_group_and_drains_healthy_peer(
    parallel_case, tmp_path
):
    h = parallel_case
    first = h.reader.first_block
    tool = tmp_path / "native-tool"
    pid_path = tmp_path / "native-tool.pid"
    tool.write_text(
        "#!"
        + sys.executable
        + "\nimport os,time\n"
        + "open("
        + repr(str(pid_path))
        + ", 'w').write(str(os.getpid()))\n"
        + "time.sleep(60)\n"
    )
    tool.chmod(0o700)
    h.fixture["orphan_native"] = {first: (str(tool), str(pid_path))}
    with pytest.raises(HistoryWorkerError, match="process exited"):
        await h.reader.advance(h.item.provider, through_block=h.end)
    child_pid = int(pid_path.read_text())
    try:
        state = Path(f"/proc/{child_pid}/stat").read_text().split()[2]
    except FileNotFoundError:
        state = None
    assert state in {None, "Z"}, "native child survived failed worker group cleanup"
    assert h.reader.checkpoints.load(first) is None
    assert h.reader.checkpoints.load(first + 1) is not None
    assert not multiprocessing.active_children()


async def test_missing_frame_capture_and_gap_retry_preserve_parallel_checkpoints(parallel_case):
    h = parallel_case
    missing = h.reader.first_block + 1
    with h.reader.journal.transaction() as db:
        db.execute(
            "DELETE FROM records WHERE kind='control_history_block' AND id=?", (str(missing),)
        )
    h.reader = h.open_parallel()
    h.offline_through = -1
    h.fail_block = missing
    with pytest.raises(ValidatorChainScanError, match="block_body_fetch_failed"):
        await h.reader.advance(h.item.provider, through_block=h.end)
    assert h.reader._next == missing
    assert h.reader.checkpoints.load(missing - 1) is not None
    assert h.reader.checkpoints.load(missing) is None
    assert h.reader.progress.latest["captured_blocks"] == len(h.frames) - 1
    h.fail_block = None
    assert await h.reader.advance(h.item.provider, through_block=h.end) == h.expected
    assert h.reader.progress.latest["captured_blocks"] == len(h.frames)


async def test_one_worker_byte_window_keeps_supported_inputs_and_bounds_dispatch(
    parallel_case, monkeypatch
):
    h = parallel_case
    h.reader.verification_profile = profile(
        workers=1, maximum_in_flight=1, maximum_in_flight_bytes=workers.MAX_FRAME_BYTES
    )
    submit = HistoryWorkers.submit
    pending = []

    def bounded(pool, **kw):
        future = submit(pool, **kw)
        pending.append((len(pool._pending), pool._bytes))
        return future

    monkeypatch.setattr(HistoryWorkers, "submit", bounded)
    assert await h.reader.advance(h.item.provider, through_block=h.end) == h.expected
    assert all(count == 1 and size <= workers.MAX_FRAME_BYTES for count, size in pending)
    assert len(h.pools) == 1


async def test_one_frame_byte_window_does_not_prefetch_fresh_capture(history_case, monkeypatch):
    h = history_case
    first = h.reader.first_block
    h.reader.verification_profile = profile(maximum_in_flight_bytes=workers.MAX_FRAME_BYTES)
    prepare = h.reader._prepare
    requested = []

    async def bounded(provider, height):
        # The previous frame must be durably applied before another raw frame
        # enters a one-frame admission window, even with four selected workers.
        assert h.reader._next == height
        if height > first:
            assert h.reader.checkpoints.load(height - 1) is not None
        requested.append(height)
        return await prepare(provider, height)

    monkeypatch.setattr(h.reader, "_prepare", bounded)
    result = await h.reader.advance(h.item.provider, through_block=h.end, maximum_blocks=2)
    assert result.next_block == first + 2 and result.history is None
    assert requested == [first, first + 1]
    assert h.body_requests == requested


async def test_parallel_windows_refresh_once_each_and_restart_checks_fresh_tip(
    parallel_case, monkeypatch
):
    h = parallel_case
    provider = h.item.provider
    acquire = provider._finality.verified_finalized_snapshot
    heads = []

    async def counted():
        head = await acquire()
        heads.append(head)
        return head

    monkeypatch.setattr(provider._finality, "verified_finalized_snapshot", counted)

    async def unavailable():
        pytest.fail("historical windows must not request an RPC head cross-check")

    monkeypatch.setattr(provider._proofs, "finalized_snapshot", unavailable)
    assert await h.reader.advance(provider, through_block=h.end) == h.expected
    window_size = min(
        h.reader.verification_profile.maximum_in_flight,
        h.reader.verification_profile.maximum_in_flight_bytes // workers.MAX_FRAME_BYTES,
    )
    assert len(heads) == (len(h.frames) + window_size - 1) // window_size
    before = len(heads)
    h.reader = h.open_parallel()
    assert await h.reader.advance(provider, through_block=h.end) == h.expected
    assert len(heads) == before + 1
    assert h.reader.progress.native_completed == 0


async def test_failed_later_header_drains_and_retains_started_worker(parallel_case, monkeypatch):
    h = parallel_case
    provider = h.item.provider
    window = provider._control_header_window
    first = h.reader.first_block
    h.fixture["delay"] = {first: 0.2}

    @asynccontextmanager
    async def fail_second():
        async with window() as resolve:

            async def checked(ref, header):
                if ref.block_number == first + 1:
                    raise ValueError("injected second historical header failure")
                return await resolve(ref, header)

            yield checked

    with monkeypatch.context() as patch:
        patch.setattr(provider, "_control_header_window", fail_second)
        with pytest.raises(ValueError, match="second historical header failure"):
            await h.reader.advance(provider, through_block=h.end)
    assert h.reader.checkpoints.load(first) is not None
    assert h.reader.checkpoints.load(first + 1) is None
    assert not provider._lock.locked()
    assert all(not child.is_alive() for child in multiprocessing.active_children())
    h.reader = h.open_parallel()
    assert await h.reader.advance(provider, through_block=h.end) == h.expected
    assert h.reader.progress.native_completed == len(h.frames) - 1


async def test_loading_next_frame_overlaps_started_native_work(parallel_case, monkeypatch):
    h = parallel_case
    first = h.reader.first_block
    submitted = []
    submit, load = HistoryWorkers.submit, h.reader._load

    def started(pool, **kw):
        result = submit(pool, **kw)
        submitted.append(kw["snapshot"].block_number)
        return result

    def checked(height):
        if height == first + 1:
            assert first in submitted, "the first native worker waited for the whole input batch"
        return load(height)

    monkeypatch.setattr(HistoryWorkers, "submit", started)
    monkeypatch.setattr(h.reader, "_load", checked)
    assert await h.reader.advance(h.item.provider, through_block=h.end) == h.expected
    assert submitted == list(h.frames)


async def test_later_load_failure_drains_and_retains_started_native_result(
    parallel_case, monkeypatch
):
    h = parallel_case
    first = h.reader.first_block
    load = h.reader._load

    def failed(height):
        if height == first + 1:
            raise OSError("retained frame unavailable")
        return load(height)

    with monkeypatch.context() as patch:
        patch.setattr(h.reader, "_load", failed)
        with pytest.raises(OSError, match="retained frame unavailable"):
            await h.reader.advance(h.item.provider, through_block=h.end)
    assert h.reader.checkpoints.load(first) is not None
    assert h.reader.checkpoints.load(first + 1) is None
    assert not h.item.provider._lock.locked()
    assert not multiprocessing.active_children()
    h.reader = h.open_parallel()
    assert await h.reader.advance(h.item.provider, through_block=h.end) == h.expected
    assert h.reader.progress.native_completed == len(h.frames) - 1


async def test_cancel_during_next_frame_load_drains_loader_and_native_worker(
    parallel_case, monkeypatch
):
    h = parallel_case
    first = h.reader.first_block
    loop = asyncio.get_running_loop()
    loading, release = asyncio.Event(), threading.Event()
    load = h.reader._load

    def blocked(height):
        if height == first + 1:
            loop.call_soon_threadsafe(loading.set)
            if not release.wait(timeout=15):
                raise TimeoutError("test did not release retained frame loader")
        return load(height)

    monkeypatch.setattr(h.reader, "_load", blocked)
    task = asyncio.create_task(h.reader.advance(h.item.provider, through_block=h.end))
    close = None
    try:
        await asyncio.wait_for(loading.wait(), timeout=15)
        close = asyncio.create_task(h.item.provider.aclose())
        task.cancel()
        await asyncio.sleep(0)
        task.cancel()
        assert not task.done()
        assert not close.done()
    finally:
        release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    if close is not None:
        await close
    assert h.reader.checkpoints.load(first) is not None
    assert h.reader.checkpoints.load(first + 1) is None
    assert not multiprocessing.active_children()


async def test_streamed_import_persists_exports_and_restarts_without_payload_reads(
    parallel_case, tmp_path, monkeypatch
):
    h = parallel_case
    original = h.reader
    imported, exported = (
        RewardProofArchive(tmp_path / "import"),
        RewardProofArchive(tmp_path / "export"),
    )
    for height, fields in h.frames.items():
        imported.write(
            "history",
            history_archive_key(original.config_sha256, original.hotkey, height),
            context=original._archive_context(height),
            fields=fields,
        )

    def open_reader():
        return RewardControlHistoryReader(
            tmp_path / "import-consumer",
            control_hotkey=original.hotkey,
            chain_config_sha256=original.config_sha256,
            first_block=original.first_block,
            maximum_bytes=original.journal.maximum_bytes,
            archive=imported,
            export_archive=exported,
            verification_profile=profile(),
        )

    h.reader = open_reader()
    submitted = set()
    submit, read = HistoryWorkers.submit, imported.read

    def started(pool, **kw):
        result = submit(pool, **kw)
        submitted.add(kw["snapshot"].block_number)
        return result

    second_key = history_archive_key(
        original.config_sha256, original.hotkey, original.first_block + 1
    )

    def checked(kind, key, **kw):
        if key == second_key:
            assert original.first_block in submitted
        return read(kind, key, **kw)

    monkeypatch.setattr(HistoryWorkers, "submit", started)
    monkeypatch.setattr(imported, "read", checked)
    assert await h.reader.advance(h.item.provider, through_block=h.end) == h.expected
    assert h.reader.progress.latest["exported_blocks"] == len(h.frames)
    for height, fields in h.frames.items():
        key = history_archive_key(original.config_sha256, original.hotkey, height)
        context, retained = exported.read("history", key, bounds=h.reader._field_bounds)
        assert context == original._archive_context(height)
        assert retained == fields
    h.reader = open_reader()

    def forbidden(*args, **kwargs):
        pytest.fail("completed imported/exported proof bytes were reread after restart")

    monkeypatch.setattr(imported, "read", forbidden)
    monkeypatch.setattr(h.reader, "_load", forbidden)
    assert await h.reader.advance(h.item.provider, through_block=h.end) == h.expected
    assert h.reader.progress.native_completed == 0
