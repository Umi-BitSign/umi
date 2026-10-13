"""Non-authoritative progress for the native block-history stage.

Restored receipts count toward completion, never toward measured proof throughput.
These estimates describe history only, not certification or reward completion.
"""

from __future__ import annotations

import asyncio
import logging
import time

logger = logging.getLogger(__name__)


class HistoryProgress:
    heartbeat_seconds = 30.0
    stalled_seconds = 60.0
    planning_blocks_per_second = (0.1, 2.0)

    def __init__(self, first_block):
        self.first_block = first_block
        self.native_completed = 0
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
            self.native_elapsed = 0.0
            self.native_completed = self.restored_completed = 0
        self.started = self.changed = now
        self.active = True
        self.last_next = next_block
        self.state = "running"
        self.stage = "scoped_checkpoint_repair" if repair else "checkpoint_restore"
        self.native_started = None

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
            if state == "completed":
                eta, basis = 0.0, "complete_selected_history_interval"
            elif stalled or state in {"retrying", "repair_required"}:
                basis = "withdrawn_stalled_or_retrying"
            elif self.native_completed >= 3 and native_elapsed >= 1.0:
                rate = self.native_completed / native_elapsed
                eta, basis = remaining / rate, "measured_native_blocks_per_active_second"
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
                "restored_completed": self.restored_completed,
                "elapsed_seconds": self.elapsed + (now - self.started if self.active else 0.0),
                "native_elapsed_seconds": native_elapsed,
                "blocks_per_second": rate,
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
