"""Non-authoritative progress for the native block-history stage.

Restored receipts count toward completion, never toward measured proof throughput.
These estimates describe history only, not certification or reward completion.
"""

from __future__ import annotations

import asyncio
import logging
import time
from contextlib import suppress

from .concurrency import run_owned_thread

logger = logging.getLogger(__name__)


class HistoryProgress:
    heartbeat_seconds = 30.0
    stalled_seconds = 60.0
    planning_blocks_per_second = (0.1, 2.0)

    def __init__(self, first_block):
        self.first_block = first_block
        self.native_completed = 0
        self.native_applied = 0
        self._new_native = set()
        self.durable = {name: set() for name in ("captured", "verified", "exported")}
        self.counts = dict.fromkeys(self.durable, 0)
        self.inventory_through = first_block - 1
        self.export_identity = None
        self.inventory_completed = 0
        self.restored_completed = 0
        self.target = None
        self.state = "pending"
        self.stage = "native_history"
        self.active = False
        self.started = self.changed = time.monotonic()
        self.elapsed = self.native_elapsed = 0.0
        self.native_started = None
        self.last_next = first_block
        self.last_emitted = 0.0
        self.latest = {}

    def start(self, target, next_block, *, repair=False):
        now = time.monotonic()
        if target != self.target:
            self.target = target
            self.counts = {
                name: sum(height <= target for height in heights)
                for name, heights in self.durable.items()
            }
            self.native_elapsed = 0.0
            self.native_completed = self.restored_completed = self.native_applied = 0
            self._new_native.clear()
        self.started = self.changed = now
        self.active = True
        self.last_next = next_block
        self.state = "running"
        self.stage = "scoped_checkpoint_repair" if repair else "checkpoint_restore"
        self.native_started = None

    def record(self, stage, height):
        values = self.durable[stage]
        if height not in values:
            values.add(height)
            if self.target is not None and height <= self.target:
                self.counts[stage] += 1

    def native_finished(self, height):
        self.native_completed += 1
        self._new_native.add(height)
        self.record("captured", height)
        self.record("verified", height)

    def applied(self, height):
        if height in self._new_native:
            self._new_native.remove(height)
            self.native_applied += 1

    def invalidate(self, height):
        for stage in ("verified", "exported"):
            if height in self.durable[stage]:
                self.durable[stage].remove(height)
                if self.target is not None and height <= self.target:
                    self.counts[stage] -= 1

    async def inventory(self, reader):
        identity = None if reader.export_archive is None else reader._export_identity()
        if identity != self.export_identity:
            self.export_identity = identity
            self.inventory_through = self.first_block - 1
            self.durable["exported"].clear()
            self.counts["exported"] = 0
        first = self.inventory_through + 1
        if first > self.target:
            return
        started = time.monotonic()
        total = self.target - first + 1
        self.stage = "history_progress_inventory"
        for low in range(first, self.target + 1, 512):
            high = min(low + 511, self.target)
            rows = await run_owned_thread(reader.checkpoints.progress_rows, low, high, identity)
            for stage, heights in zip(self.durable, rows, strict=True):
                for height in heights:
                    self.record(stage, height)
            self.inventory_through = high
            self.inventory_completed = high - first + 1
            elapsed = time.monotonic() - started
            with suppress(Exception):
                logger.info(
                    "reward_history_inventory_progress %s",
                    {
                        "stage": self.stage,
                        "state": "completed" if high == self.target else "running",
                        "completed_blocks": self.inventory_completed,
                        "total_blocks": total,
                        "elapsed_seconds": elapsed,
                        "percent": 100.0 * self.inventory_completed / total,
                        "eta_seconds": (total - self.inventory_completed)
                        * elapsed
                        / self.inventory_completed,
                        "eta_basis": "measured_compact_metadata_inventory_rate",
                        "eta_scope": "progress_inventory_only",
                    },
                )

    def native_start(self, *, retained=False, repair=False):
        self.stage = (
            "scoped_checkpoint_repair"
            if repair
            else "legacy_checkpoint_migration"
            if retained
            else "native_history"
        )
        if self.native_started is None:
            self.native_started = time.monotonic()

    def native_stop(self):
        if self.native_started is not None:
            self.native_elapsed += time.monotonic() - self.native_started
            self.native_started = None

    def finish(self):
        self.native_stop()
        if self.active:
            self.elapsed += time.monotonic() - self.started
            self.active = False

    def report(self, reader, state, *, error_type=None, force=False):
        # A broken diagnostics sink must never change a native result or error.
        try:
            now = time.monotonic()
            if reader._next != self.last_next:
                self.changed, self.last_next = now, reader._next
            self.state = state
            total = max(0, self.target - self.first_block + 1)
            done = min(total, max(0, reader._next - self.first_block))
            remaining = total - done
            stalled = (
                self.active
                and now - self.changed >= self.stalled_seconds
                and state not in {"completed", "pending", "retrying", "repair_required"}
            )
            native_elapsed = self.native_elapsed + (
                now - self.native_started if self.native_started is not None else 0.0
            )
            eta = rate = None
            planning = None
            basis = "waiting_for_native_samples"
            proof_rate = self.native_completed / native_elapsed if native_elapsed > 0 else None
            pipeline_rate = self.native_applied / native_elapsed if native_elapsed > 0 else None
            sampled = (
                self.native_applied
                if getattr(reader, "verification_profile", None)
                else self.native_completed
            )
            if state == "completed":
                eta, basis = 0.0, "complete_selected_history_interval"
            elif stalled or state in {"retrying", "repair_required"}:
                basis = "withdrawn_stalled_or_retrying"
            elif sampled >= 3 and native_elapsed >= 1.0:
                rate = sampled / native_elapsed
                eta, basis = (
                    remaining / rate,
                    (
                        "measured_ordered_pipeline_blocks_per_active_second"
                        if getattr(reader, "verification_profile", None)
                        else "measured_native_blocks_per_active_second"
                    ),
                )
            elif remaining:
                low, high = self.planning_blocks_per_second
                planning = [remaining / high, remaining / low]
                basis = f"planning_assumption_{low:g}_to_{high:g}_native_blocks_per_second"
            self.latest = {
                "stage": self.stage,
                "state": "stalled" if stalled else state,
                "first_block": self.first_block,
                "target_block": self.target,
                "next_block": reader._next,
                "completed_blocks": done,
                "total_blocks": total,
                "percent": 100.0 * done / total if total else 0.0,
                "native_completed": self.native_completed,
                "captured_blocks": self.counts["captured"],
                "verified_blocks": self.counts["verified"],
                "verified_ahead_of_applied_blocks": max(0, self.counts["verified"] - done),
                "exported_blocks": self.counts["exported"],
                "export_scope": "selected_local_proof_archive",
                "replicated_blocks": None,
                "replication_basis": "remote_delivery_receipts_not_available_to_history_owner",
                "applied_blocks": done,
                "restored_completed": self.restored_completed,
                "elapsed_seconds": self.elapsed + (now - self.started if self.active else 0.0),
                "native_elapsed_seconds": native_elapsed,
                "blocks_per_second": rate,
                "native_verified_blocks_per_second": proof_rate,
                "ordered_native_blocks_per_second": pipeline_rate,
                "eta_seconds": eta,
                "planning_eta_seconds": planning,
                "eta_basis": basis,
                "eta_scope": "history_only_assuming_remaining_blocks_need_native_verification",
                "error_type": error_type,
            }
            if force or state != "running" or now - self.last_emitted >= self.heartbeat_seconds:
                self.last_emitted = now
                logger.info("reward_history_progress %s", self.latest)
        except Exception:
            pass

    async def monitor(self, reader, stop):
        while not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), timeout=self.heartbeat_seconds)
            except asyncio.TimeoutError:
                self.report(reader, self.state, force=True)
