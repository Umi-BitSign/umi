"""Actual spawn workers through native histories, checkpoints and restart."""

import asyncio
import json
import multiprocessing
import sys
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
from umi.competition_reward_proof_archive import RewardProofArchive
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


async def test_repeated_cancellation_drains_workers_and_provider_before_close(
    parallel_case, monkeypatch
):
    h = parallel_case
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
    task.cancel()
    await asyncio.sleep(0.01)
    task.cancel()
    assert not close.done()
    with pytest.raises(asyncio.CancelledError):
        await task
    await close
    assert h.reader.checkpoints.load(first) is not None
    assert h.reader.checkpoints.load(first + 1) is not None
    assert not multiprocessing.active_children()


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
