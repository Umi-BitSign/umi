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


async def _load_input(reader, height, *, report=True):
    if report:
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


class _FrameInputs:
    """Own bounded speculative reads, retaining all consumed bytes until apply."""

    def __init__(self, reader, stop, first, last):
        self.reader, self.stop = reader, stop
        self.next, self.last = first, last
        self.tasks = {}
        self.bytes = 0
        self.boundary = False

    def _fill(self):
        limit = self.reader.verification_profile.maximum_in_flight_bytes
        while (
            self.next <= self.last
            and not self.boundary
            and not self.stop.is_set()
            and self.bytes + MAX_FRAME_BYTES <= limit
        ):
            height = self.next
            self.next += 1
            self.bytes += MAX_FRAME_BYTES
            self.tasks[height] = asyncio.create_task(self._load(height))

    async def _load(self, height):
        size = 0
        try:
            result = await _load_input(self.reader, height, report=False)
            completed, fields, _ = result
            if completed is not None or fields is None:
                self.boundary = True
            else:
                size = sum(map(len, fields.values()))
                if size > MAX_FRAME_BYTES:
                    raise ValueError("history frame exceeds its reserved byte bound")
            return result
        except BaseException:
            self.boundary = True
            raise
        finally:
            # No await between releasing the reservation and charging residency.
            self.bytes += size - MAX_FRAME_BYTES

    async def take(self, height):
        self._fill()
        if self.stop.is_set() or height not in self.tasks:
            return None, None, False
        # Only the ordered owner changes the visible preparation stage. A later
        # download must not replace a header wait or claim native completion.
        self.reader.progress.preparation_start(
            "retained_history_loading", height, "load_checkpoint_or_selected_retained_frame"
        )
        self.reader.progress.report(self.reader, "running")
        result = await await_owned_task(self.tasks[height], on_cancel=self.stop.set)
        del self.tasks[height]
        self._fill()
        return result

    async def __aenter__(self):
        self._fill()
        return self

    async def __aexit__(self, *_):
        # Gaps, completed checkpoints and failed predecessors end this window.
        # Drain every started read before releasing its bytes or source tokens.
        for height, task in self.tasks.items():
            with suppress(Exception, asyncio.CancelledError):
                await await_owned_task(task, on_cancel=self.stop.set)
            self.reader._prepared_encodings.pop(height, None)
            self.reader._source_tokens.pop(height, None)
        self.tasks.clear()


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


async def _window(reader, provider, pool, entries, stop, *, last_height, inputs=None):
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
                        if height < last_height and not stop.is_set() and inputs is not None:
                            completed, following, following_retained = await inputs.take(height + 1)
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
    # Fresh capture has no retained sizes to account before admission. Retained
    # inputs reserve one maximum frame for each read, then charge its actual
    # bytes for the rest of the window. Both paths keep the same byte ceiling.
    capture_count = min(
        profile.maximum_in_flight, profile.maximum_in_flight_bytes // MAX_FRAME_BYTES
    )
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
                fields = None
                window_last = min(last, reader._next + profile.maximum_in_flight - 1)
                async with _FrameInputs(reader, stop, reader._next, window_last) as inputs:
                    completed, fields, retained = await inputs.take(reader._next)
                    if completed is None and fields is not None:
                        entries.append((reader._next, fields, retained))
                        if pool is None:
                            pool = HistoryWorkers(
                                profile,
                                HistoryWorkerSelection.from_provider(provider, reader.hotkey),
                            )
                        values = await _window(
                            reader,
                            provider,
                            pool,
                            entries,
                            stop,
                            last_height=window_last,
                            inputs=inputs,
                        )
                if not entries:
                    # Online capture retains serialized native verification, but
                    # uses every admitted frame for overlapping source persistence
                    # and export. A one-frame profile still forbids lookahead.
                    await reader._advance_capture_locked(
                        provider,
                        min(last, reader._next + capture_count - 1),
                        maximum_in_flight=capture_count,
                        stop=stop,
                    )
                    continue
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
