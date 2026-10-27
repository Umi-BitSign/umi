"""Single-owner ordered application of independently proved history blocks."""

from __future__ import annotations

import asyncio
from contextlib import suppress
from dataclasses import asdict
from functools import partial

from .competition_chain_state import _cache_usage
from .competition_reward_control_evidence import archive_header_hint
from .competition_reward_history_checkpoint import ABI, HistoryCheckpointRepairRequired
from .competition_reward_history_workers import (
    MAX_FRAME_BYTES,
    HistoryWorkers,
    HistoryWorkerSelection,
)
from .competition_reward_proof_archive import history_archive_key
from .competition_transport_verification import TransferProgress
from .concurrency import await_owned_task, run_owned_thread
from .host_memory_runtime import compact_memory_error, history_memory_window


async def _load_input(reader, height):
    reader.progress.preparation_start(
        "retained_history_loading", height, "load_checkpoint_or_selected_retained_frame"
    )
    reader.progress.report(reader, "running")
    try:
        completed = await run_owned_thread(reader.checkpoints.load, height)
    except HistoryCheckpointRepairRequired:
        reader.progress.invalidate(height)
        if not reader._repair_reason:
            raise
        completed = None
    if completed is not None:
        return completed, None, True
    fields = await run_owned_thread(reader._load, height)
    retained = fields is not None
    if fields is None and reader.archive is not None:
        try:
            context, fields = await run_owned_thread(
                partial(
                    reader.archive.read,
                    "history",
                    history_archive_key(reader.config_sha256, reader.hotkey, height),
                    bounds=reader._field_bounds,
                )
            )
        except FileNotFoundError:
            pass
        else:
            if context != reader._archive_context(height):
                raise ValueError("imported history changes its requested domain")
    return None, fields, retained


async def _persist(reader, pool, future, fields, retained):
    # This owned task is never cancelled by a caller. It spans the independent
    # native check and durable result, including successful later heights when
    # a predecessor fails, export fails or shutdown is requested.
    # This is the owner's native worker wait, including worker queue time,
    # not a CPU-time measurement. Source/checkpoint persistence follows it.
    with TransferProgress(
        "history_native_worker_wait", 1, unit="blocks", planning_unit_seconds=(0.01, 300)
    ) as progress:
        await asyncio.wait((future,))
        result = pool.result(future)
        progress.advance(1)
    height = result.snapshot.block_number
    save_error = None
    if not retained:
        try:
            await run_owned_thread(reader._save_fields, height, fields)
        except Exception as error:
            if height not in reader._source_tokens:
                raise
            save_error = error
    value = {
        "schema": ABI,
        "owner": reader.checkpoints.owner,
        "semantics": reader.checkpoints.semantics,
        "snapshot": asdict(result.snapshot),
        "header": result.header,
        "control_sha256": result.control_sha256,
        "committed_at_block": result.committed_at_block,
        "slot_evidence_sha256": result.slot_evidence_sha256,
        "slot_metadata_sha256": result.slot_metadata_sha256,
        "write_evidence_sha256": result.write_evidence_sha256,
        "writes": [list(item) for item in result.writes],
        "unresolved_extrinsics": list(result.unresolved_extrinsics),
        "sources": reader._source_tokens[height],
        "exports": [],
        "repair": (
            {"reason": reader._repair_reason, "operation": reader._repair_id}
            if reader._repair_reason
            else None
        ),
    }
    try:
        await run_owned_thread(
            partial(reader.checkpoints.remember, value, repair_reason=reader._repair_reason)
        )
    except Exception:
        if save_error is not None:
            raise save_error from None
        raise
    reader.progress.native_finished(height)
    reader.progress.report(reader, "running")
    if save_error is not None:
        raise save_error
    return value


async def _window(reader, provider, pool, entries, stop, *, last_height):
    tasks = []
    error = None
    reader.progress.preparation_start(
        "owned_history_provider_wait",
        entries[0][0] if entries else None,
        "acquire_running_owned_provider_lock",
    )
    reader.progress.report(reader, "running")
    async with provider._lock:
        if provider._closed or not provider._owned:
            raise ValueError("parallel history requires a running owned provider")
        _cache_usage(provider._cache_root, provider.config.maximum_cache_bytes)
        try:
            if entries and not stop.is_set():
                reader.progress.preparation_start(
                    "owned_history_header_resolution",
                    entries[0][0],
                    "resolve_finalized_head_for_bounded_native_batch",
                )
                reader.progress.report(reader, "running")
                async with provider._control_header_window() as resolve:
                    for height, fields, retained in entries:
                        if stop.is_set():
                            break
                        reader.progress.preparation_start(
                            "retained_history_header", height, "decode_retained_header_hint"
                        )
                        reader.progress.report(reader, "running")
                        snapshot, header = await run_owned_thread(
                            archive_header_hint, fields["slot_evidence"]
                        )
                        if snapshot.block_number != height:
                            raise ValueError("history frame differs from selected owner context")
                        reader.progress.preparation_start(
                            "owned_history_header_resolution",
                            height,
                            "resolve_header_and_finalized_ancestry_before_native_submission",
                        )
                        reader.progress.report(reader, "running")
                        timestamp, ceiling = await resolve(snapshot, header)
                        if stop.is_set():
                            break
                        reader.progress.native_start(
                            retained=retained, repair=bool(reader._repair_reason)
                        )
                        reader.progress.report(reader, "running")
                        future = pool.submit(
                            snapshot=snapshot,
                            header=header,
                            timestamp=timestamp,
                            ceiling=ceiling,
                            fields=fields,
                        )
                        tasks.append(
                            (
                                future,
                                asyncio.create_task(
                                    _persist(reader, pool, future, fields, retained)
                                ),
                            )
                        )
                        # Start this native check before loading the next frame.
                        # The list grows only within the original bounded window;
                        # no extra raw frame, worker slot or byte budget is added.
                        if height < last_height and not stop.is_set():
                            completed, following, following_retained = await _load_input(
                                reader, height + 1
                            )
                            if completed is None and following is not None:
                                entries.append((height + 1, following, following_retained))
            # Checkpoint coroutines run as each worker finishes; gathering here
            # never imposes block order on durable completion.
            results = await asyncio.gather(*(task for _, task in tasks), return_exceptions=True)
            error = next((result for result in results if isinstance(result, BaseException)), None)
            _cache_usage(provider._cache_root, provider.config.maximum_cache_bytes)
        finally:
            for future, task in tasks:
                with suppress(Exception, asyncio.CancelledError):
                    await await_owned_task(task)
                pool.release(future)
        if error is not None:
            raise error
    return [result for result in results if isinstance(result, dict)]


async def _export_prepared(reader, height, fields, value, stop):
    # This task owns the original native success through its separate durable
    # delivery fact. It never applies history and never admits another frame.
    if stop.is_set():
        return None
    if await run_owned_thread(reader.checkpoints.load, height) != value:
        raise HistoryCheckpointRepairRequired("checkpoint changed during parallel verification")
    if stop.is_set():
        return None
    if reader.export_archive is not None:
        await run_owned_thread(reader._export_fields, height, fields, reader.export_archive)
        value = {**value, "exports": [reader._export_identity()]}
        await run_owned_thread(
            partial(reader.checkpoints.remember, value, repair_reason="new_export_destination")
        )
        reader.progress.record("exported", height)
    return value


async def _apply_prepared_window(reader, entries, values, stop):
    tasks = []
    try:
        for value, (height, fields, _) in zip(values, entries, strict=False):
            if stop.is_set():
                break
            if reader.export_archive is None:
                value = await _export_prepared(reader, height, fields, value, stop)
                if value is None or stop.is_set():
                    break
                reader._apply_checkpoint(value)
            else:
                tasks.append(
                    asyncio.create_task(_export_prepared(reader, height, fields, value, stop))
                )
        # Export only this already admitted window. The shared remote store
        # retains its eight-object and aggregate-byte admission across tasks.
        # The owner alone applies effects, in original height order.
        for task in tasks:
            value = await await_owned_task(task)
            if value is None or stop.is_set():
                break
            reader._apply_checkpoint(value)
    finally:
        # A failed predecessor or cancellation must not abandon a later
        # successful export or release its fields/leases before it is durable.
        for task in tasks:
            with suppress(Exception, asyncio.CancelledError):
                await await_owned_task(task)


async def _run(reader, provider, last, stop):
    profile = reader.verification_profile
    # Conservative raw-frame slots include a maximum permitted block; large
    # evidence lowers throughput rather than failing an accepted input.
    count = min(profile.maximum_in_flight, profile.maximum_in_flight_bytes // MAX_FRAME_BYTES)
    async with history_memory_window(profile.required_memory_bytes):
        pool = fields = values = None
        entries = []
        failure = None
        try:
            while reader._next <= last and not stop.is_set():
                await reader._restore_prefix(provider, last)
                if reader._next > last or stop.is_set():
                    break
                entries = []
                window_last = min(last, reader._next + count - 1)
                completed, fields, retained = await _load_input(reader, reader._next)
                if completed is None and fields is not None:
                    entries.append((reader._next, fields, retained))
                if not entries:
                    # Online capture still owns native verification. Reuse its
                    # bounded pipeline instead of serializing capture, source
                    # persistence and export for every missing frame. A one-frame
                    # profile must not admit lookahead.
                    await reader._advance_capture_locked(
                        provider, window_last, prefetch=count >= 2, stop=stop
                    )
                    continue
                if pool is None:
                    pool = HistoryWorkers(
                        profile, HistoryWorkerSelection.from_provider(provider, reader.hotkey)
                    )
                values = await _window(
                    reader, provider, pool, entries, stop, last_height=window_last
                )
                await _apply_prepared_window(reader, entries, values, stop)
        except BaseException as error:
            failure = compact_memory_error(error)
        finally:
            try:
                if pool is not None:
                    await pool.close()
            except BaseException as error:
                if failure is None:
                    failure = compact_memory_error(error)
            entries.clear()
            pool = fields = values = None
            reader._prepared_encodings.clear()
            reader._source_tokens.clear()
        if failure is not None:
            raise failure from None


class _HistoryStop:
    """Local cancellation must not request shutdown of unrelated owners."""

    def __init__(self, shutdown_event):
        self.local = asyncio.Event()
        self.shutdown_event = shutdown_event

    def is_set(self):
        return self.local.is_set() or (
            self.shutdown_event is not None and self.shutdown_event.is_set()
        )

    def set(self):
        self.local.set()


async def advance_parallel_locked(reader, provider, last):
    """Caller retains reader and journal locks until all native children drain."""
    stop = _HistoryStop(reader.shutdown_event)
    task = asyncio.create_task(_run(reader, provider, last, stop))
    await await_owned_task(task, on_cancel=stop.set)
