"""Non-authoritative progress for the native block-history stage.

Restored receipts count toward completion, never toward measured proof throughput.
These estimates describe history only, not certification or reward completion.
"""

from __future__ import annotations

import asyncio
import logging
import time
from contextlib import contextmanager, suppress

from .concurrency import run_owned_thread

logger = logging.getLogger(__name__)


class HistoryProgress:
    heartbeat_seconds = 30.0
    stalled_seconds = 60.0
    planning_blocks_per_second = (0.1, 2.0)
    preparation_planning_seconds = (1.0, 300.0)

    def __init__(self, first_block):
        self.first_block = first_block
        self.native_completed = 0
        self.native_applied = 0
        self._new_native = set()
        self.durable = {name: set() for name in ("captured", "verified", "exported")}
        self.counts = dict.fromkeys(self.durable, 0)
        self.retained_local_exports = set()
        self.retained_local_export_count = 0
        self.inventory_through = first_block - 1
        self.export_identity = None
        self.inventory_completed = 0
        self.restored_completed = 0
        self.completed_admission_through = first_block - 1
        self.target = None
        self.state = "pending"
        self.stage = "native_history"
        self.active = False
        self.started = self.changed = time.monotonic()
        self.elapsed = self.native_elapsed = 0.0
        self.native_started = None
        self.wall_started = self.wall_finished = self.native_wall_started = None
        self.native_stage = None
        self.retry_next = None
        self.last_next = first_block
        self.last_emitted = 0.0
        self.latest = {}
        self.remote_export_selected = False
        self.local_release = None
        self.preparation = None
        self.restoration = None
        self.ancestry_progress = None
        self._ancestry_watch = None
        self._ancestry_sample = None
        self.forecast = None
        self.forecast_health = None

    def start(self, target, next_block, *, repair=False):
        now = time.monotonic()
        reset = target != self.target or next_block < self.last_next
        if reset:
            self.target = target
            self.counts = {
                name: sum(height <= target for height in heights)
                for name, heights in self.durable.items()
            }
            self.retained_local_export_count = sum(
                height <= target for height in self.retained_local_exports
            )
            self.native_elapsed = 0.0
            self.native_completed = self.restored_completed = self.native_applied = 0
            self._new_native.clear()
            self.elapsed = 0.0
            self.wall_started, self.wall_finished = now, None
            self.native_wall_started = self.native_stage = self.retry_next = None
            self.restoration = None
            self._ancestry_sample = None
        if reset or next_block != self.last_next:
            self.changed = now
        self.started = now
        self.active = True
        self.last_next = next_block
        self.state = "running"
        self.stage = (
            "scoped_checkpoint_repair" if repair else self.native_stage or "history_preparation"
        )
        self.native_started = None
        self.preparation = None
        self.ancestry_progress = None

    def record(self, stage, height):
        if stage == "exported" and height in self.retained_local_exports:
            self.retained_local_exports.remove(height)
            if self.target is not None and height <= self.target:
                self.retained_local_export_count -= 1
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

    def retained_local_export(self, height):
        if height not in self.retained_local_exports:
            self.retained_local_exports.add(height)
            if self.target is not None and height <= self.target:
                self.retained_local_export_count += 1

    def applied(self, height):
        if height in self._new_native:
            self._new_native.remove(height)
            self.native_applied += 1

    def invalidate(self, height):
        if height in self.retained_local_exports:
            self.retained_local_exports.remove(height)
            if self.target is not None and height <= self.target:
                self.retained_local_export_count -= 1
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
            self.retained_local_exports.clear()
            self.retained_local_export_count = 0
        first = self.inventory_through + 1
        if first > self.target:
            return
        started = time.monotonic()
        total = self.target - first + 1
        prior_stage = self.stage
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
        if self.stage == "history_progress_inventory":
            self.stage = prior_stage

    def preparation_start(self, stage, height, reason):
        """Describe owned preparation without counting it as native proof work."""
        self.stage = stage
        self.preparation = {
            "stage": stage,
            "height": height,
            "reason": reason,
            "started": time.monotonic(),
            "finished": None,
        }

    def restore_start(self, first, total, *, admission=False, started=None):
        self.ancestry_progress = None
        stage = "completed_admission_restore" if admission else "checkpoint_restore"
        if self.restoration is not None and (
            self.restoration["stage"],
            self.restoration["height"],
            self.restoration["total"],
        ) == (stage, first, total):
            self.stage, self.preparation = stage, self.restoration
            self.preparation["finished"] = None
        else:
            self.preparation_start(
                stage,
                first,
                "restore_completed_admission"
                if admission
                else "restore_completed_checkpoint_batch",
            )
            self.preparation["total"] = total
            if started is not None:
                self.preparation["started"] = started
            self.restoration = self.preparation

    def native_start(self, *, retained=False, repair=False):
        self.preparation = None
        self.restoration = None
        self.ancestry_progress = None
        self.stage = (
            "scoped_checkpoint_repair"
            if repair
            else "legacy_checkpoint_migration"
            if retained
            else "native_history"
        )
        self.native_stage = self.stage
        if self.native_wall_started is None:
            self.native_wall_started = time.monotonic()
        if self.native_started is None:
            self.native_started = time.monotonic()

    def native_stop(self):
        if self.native_started is not None:
            self.native_elapsed += time.monotonic() - self.native_started
            self.native_started = None

    def finish(self):
        self.native_stop()
        if self.preparation is not None and self.preparation["finished"] is None:
            self.preparation["finished"] = time.monotonic()
        if self.active:
            self.elapsed += time.monotonic() - self.started
            self.active = False

    @contextmanager
    def watch_ancestry(self, telemetry, target):
        """Observe only this awaited native substage; never issue proof facts."""
        prior, self._ancestry_watch = self._ancestry_watch, (telemetry, target)
        try:
            yield
        finally:
            self._ancestry_watch = prior

    def _ancestry_activity(self, ancestry, now):
        key = ancestry.get("anchor_evidence_sha256"), ancestry.get("target_block")
        completed = ancestry.get("completed_links")
        if not isinstance(key[0], str) or type(key[1]) is not int or type(completed) is not int:
            return
        previous = self._ancestry_sample
        highest = previous[1] if previous is not None and previous[0] == key else 0
        self._ancestry_sample = (key, max(highest, completed))
        if completed > highest and ancestry.get("state") == "running":
            self.changed = now
            self.retry_next = None

    def report(self, reader, state, *, error_type=None, force=False, ancestry_progress=None):
        # A broken diagnostics sink must never change a native result or error.
        try:
            now = time.monotonic()
            if ancestry_progress is None and self._ancestry_watch is not None:
                telemetry, target = self._ancestry_watch
                if telemetry.active and telemetry.latest.get("target_block") == target:
                    ancestry_progress = telemetry.latest
            if ancestry_progress is not None:
                self.ancestry_progress = dict(ancestry_progress)
                self.stage = "owned_historical_ancestry"
                self._ancestry_activity(self.ancestry_progress, now)
            if reader._next != self.last_next:
                self.changed, self.last_next = now, reader._next
            if self.retry_next is not None and reader._next != self.retry_next:
                self.retry_next = None
            self.state = state
            total = max(0, self.target - self.first_block + 1)
            done = min(total, max(0, reader._next - self.first_block))
            remaining = total - done
            stalled = (
                self.active
                and now - self.changed >= self.stalled_seconds
                and state not in {"completed", "pending", "retrying", "repair_required"}
            )
            if stalled or state in {"retrying", "repair_required"}:
                self.retry_next = reader._next
            if state == "completed" and self.wall_finished is None:
                self.wall_finished = now
            wall_now = now if self.wall_finished is None else self.wall_finished
            elapsed = 0.0 if self.wall_started is None else wall_now - self.wall_started
            native_wall_elapsed = (
                0.0 if self.native_wall_started is None else wall_now - self.native_wall_started
            )
            native_elapsed = self.native_elapsed + (
                now - self.native_started if self.native_started is not None else 0.0
            )
            eta = rate = None
            planning = None
            basis = "waiting_for_native_samples"
            proof_rate = self.native_completed / native_elapsed if native_elapsed > 0 else None
            pipeline_rate = self.native_applied / native_elapsed if native_elapsed > 0 else None
            # Both serial prefetch and parallel workers may verify ahead of the
            # applied prefix. Only newly verified AND applied blocks predict
            # completion; restored checkpoints never enter this numerator.
            sampled = self.native_applied
            preparation = self.preparation
            restoring_export = (
                self.stage == "checkpoint_export"
                and preparation is not None
                and preparation["stage"] == "checkpoint_restore"
            )
            if (
                preparation is not None
                and preparation["stage"] != self.stage
                and not restoring_export
            ):
                preparation = None
            preparation_elapsed = (
                (now if preparation["finished"] is None else preparation["finished"])
                - preparation["started"]
                if preparation is not None
                else None
            )
            preparation_planning = None
            preparation_basis = None
            preparation_eta = preparation_done = preparation_total = None
            if preparation is not None:
                preparation_total = preparation.get("total")
                if preparation_total is not None:
                    preparation_done = min(
                        preparation_total, max(0, reader._next - preparation["height"])
                    )
                if (
                    stalled
                    or self.retry_next is not None
                    or state in {"retrying", "repair_required"}
                    or not self.active
                ):
                    preparation_basis = "withdrawn_stalled_retrying_or_stopped"
                elif preparation_elapsed <= self.preparation_planning_seconds[1]:
                    preparation_planning = [
                        max(0.0, bound - preparation_elapsed)
                        for bound in self.preparation_planning_seconds
                    ]
                    preparation_basis = "planning_local_retained_reads_or_responsive_archive_rpc"
                else:
                    preparation_basis = "withdrawn_preparation_exceeded_planning_range"
                if preparation_total is not None and preparation_done == preparation_total:
                    preparation_eta, preparation_planning = 0.0, None
                    preparation_basis = "completed_checkpoint_restore_batch"
                elif (
                    preparation_done is not None
                    and preparation_done >= 3
                    and preparation_elapsed >= 1
                    and self.active
                    and not stalled
                    and self.retry_next is None
                ):
                    preparation_eta = (
                        (preparation_total - preparation_done)
                        * preparation_elapsed
                        / preparation_done
                    )
                    preparation_planning = None
                    preparation_basis = "measured_checkpoint_restore_blocks_per_wall_second"
            if state == "completed":
                eta, basis = 0.0, "complete_selected_history_interval"
            elif stalled or state in {"retrying", "repair_required"} or self.retry_next is not None:
                basis = "withdrawn_stalled_or_retrying"
            elif preparation is not None:
                # Native throughput excludes the first ancestry resolution. A
                # native-only extrapolation is not an ETA for this pending wait.
                basis = "waiting_for_retained_history_preparation"
            elif self.ancestry_progress is not None:
                basis = "waiting_for_owned_historical_ancestry"
            elif sampled >= 3 and native_wall_elapsed >= 1.0:
                rate = sampled / native_wall_elapsed
                eta, basis = (
                    remaining / rate,
                    "measured_ordered_native_blocks_per_wall_second",
                )
            elif remaining:
                low, high = self.planning_blocks_per_second
                planning = [remaining / high, remaining / low]
                basis = f"planning_assumption_{low:g}_to_{high:g}_native_blocks_per_second"
            completed_admission = max(
                0, min(self.target, self.completed_admission_through) - self.first_block + 1
            )
            verified = self.counts["verified"] + completed_admission
            self.latest = {
                "stage": self.stage,
                "ancestry_progress": self.ancestry_progress,
                "stage_reason": None if preparation is None else preparation["reason"],
                "active_block": reader._next
                if restoring_export
                else None
                if preparation is None
                else preparation["height"],
                "stage_elapsed_seconds": preparation_elapsed,
                "stage_completed_blocks": preparation_done,
                "stage_total_blocks": preparation_total,
                "stage_eta_seconds": preparation_eta,
                "stage_planning_eta_seconds": preparation_planning,
                "stage_eta_basis": preparation_basis,
                "stage_eta_scope": (
                    "current_checkpoint_restore_batch_only"
                    if preparation_total is not None
                    else "current_retained_preparation_only"
                )
                if preparation is not None
                else None,
                "state": "stalled" if stalled else state,
                "first_block": self.first_block,
                "target_block": self.target,
                "next_block": reader._next,
                "completed_blocks": done,
                "total_blocks": total,
                "percent": 100.0 * done / total if total else 0.0,
                "native_completed": self.native_completed,
                "native_applied": self.native_applied,
                "captured_blocks": self.counts["captured"],
                "verified_blocks": verified,
                "completed_admission_blocks": completed_admission,
                "verified_ahead_of_applied_blocks": max(0, verified - done),
                "exported_blocks": self.counts["exported"],
                "retained_local_export_blocks": self.retained_local_export_count,
                "export_scope": "selected_r2_proof_archive"
                if self.remote_export_selected
                else "selected_local_proof_archive",
                "replicated_blocks": self.counts["exported"]
                if self.remote_export_selected
                else None,
                "replication_basis": "completed_delivery_to_selected_immutable_r2_namespace"
                if self.remote_export_selected
                else "remote_delivery_receipts_not_available_to_history_owner",
                "local_release": self.local_release,
                "applied_blocks": done,
                "restored_completed": self.restored_completed,
                "elapsed_seconds": elapsed,
                "active_elapsed_seconds": self.elapsed
                + (now - self.started if self.active else 0.0),
                "native_elapsed_seconds": native_elapsed,
                "native_wall_elapsed_seconds": native_wall_elapsed,
                "rate_window_scope": "current_process_and_target_since_first_native_attempt",
                "blocks_per_second": rate,
                "native_verified_blocks_per_second": proof_rate,
                "ordered_native_blocks_per_second": pipeline_rate,
                "eta_seconds": eta,
                "planning_eta_seconds": planning,
                "eta_basis": basis,
                "eta_scope": "history_only_assuming_remaining_blocks_need_native_verification",
                "error_type": error_type,
            }
            if self.ancestry_progress is not None:
                ancestry = self.ancestry_progress
                unavailable = stalled or state in {"retrying", "repair_required"} or not self.active
                self.latest.update(
                    active_block=ancestry.get("target_block"),
                    stage_elapsed_seconds=ancestry.get("elapsed_seconds"),
                    stage_eta_seconds=None if unavailable else ancestry.get("eta_seconds"),
                    stage_planning_eta_seconds=None
                    if unavailable
                    else ancestry.get("planning_eta_seconds"),
                    stage_eta_basis="withdrawn_stalled_retrying_or_stopped"
                    if unavailable
                    else ancestry.get("eta_basis"),
                    stage_eta_scope=ancestry.get("eta_scope"),
                )
            if force or state != "running" or now - self.last_emitted >= self.heartbeat_seconds:
                self.last_emitted = now
                if self.forecast is not None:
                    try:
                        accounting = self.forecast.observe(dict(self.latest))
                    except Exception as error:
                        self.forecast.ledger.note_failure(
                            "consumer_observation_failed", error=error
                        )
                        accounting = {
                            "status": "capacity_required"
                            if self.forecast.ledger.capacity_required
                            else "repair_required",
                            "certification_authority": False,
                        }
                    self.latest["forecast_accounting"] = accounting
                elif self.forecast_health is not None:
                    self.latest["forecast_accounting"] = {
                        "status": self.forecast_health,
                        "certification_authority": False,
                    }
                logger.info("reward_history_progress %s", self.latest)
        except Exception:
            pass

    async def monitor(self, reader, stop):
        while not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), timeout=self.heartbeat_seconds)
            except asyncio.TimeoutError:
                self.report(reader, self.state, force=True)
