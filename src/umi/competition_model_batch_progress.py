"""Bounded metadata work inventory and non-authoritative model-batch forecasts."""

from __future__ import annotations

import json
import logging
import math
import time
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .competition_chunked_model_backup import ChunkedBackupSelection
from .competition_forecast import ForecastAttempt, ForecastCapacityRequired
from .competition_transport_verification import TransferProgress
from .open_competition import digest

_LOG = logging.getLogger("umi.competition.progress")
# This bounds telemetry memory only. Reaching it never refuses native work:
# untracked file reuse is conservatively omitted from the planning inventory.
_MAX_TRACKED_FILES = 131072
_RATE_WINDOW_MODELS = 64
_HEAD_STAGES = ("chunked_model_remote_metadata", "chunked_model_generation_confirmation")


@dataclass(frozen=True)
class ModelReviewWork:
    model_sha256: str
    declared_bytes: int
    potential_payload_bytes: int
    generation_heads: int
    files: int
    reuse_inventory_complete: bool


class ModelWorkInventory:
    """Count signed metadata without reading payloads or asserting byte facts."""

    def __init__(self) -> None:
        self.seen: set[str] = set()
        self.complete = True

    def add(self, selection: ChunkedBackupSelection, *, metadata_only: bool) -> ModelReviewWork:
        binding = selection.binding
        scope = (
            binding.policy_sha256,
            binding.endpoint,
            binding.bucket,
            binding.object_key_prefix,
        )
        potential, chunks = 0, set()
        for record, item in zip(selection.bundle.files, selection.package.files, strict=True):
            key = digest(
                [
                    scope,
                    record.sha256,
                    record.size_bytes,
                    [(c.sha256, c.size_bytes) for c in item.chunks],
                ]
            )
            if key not in self.seen:
                potential += record.size_bytes
                if len(self.seen) < _MAX_TRACKED_FILES:
                    self.seen.add(key)
                else:
                    self.complete = False
            chunks.update(c.sha256 for c in item.chunks)
        return ModelReviewWork(
            binding.model_sha256,
            sum(record.size_bytes for record in selection.bundle.files),
            0 if metadata_only else potential,
            2 * len(chunks),
            len(selection.bundle.files),
            self.complete,
        )


class ModelBatchProgress:
    """Pair child telemetry with its model, preserving native verification ownership.

    Component rates are local to this invocation. Potential file bytes assume
    unchanged generations and a usable shared store; they are never successful
    verification facts. Forecasts deliberately leave active partial work
    uncredited, and are planning estimates rather than probability bounds.
    """

    def __init__(self, stage: str, work: tuple[ModelReviewWork, ...], report=None) -> None:
        self.work, self.report = work, report
        self.progress = TransferProgress(
            stage, len(work), self._emit, unit="models", planning_unit_seconds=(1, 3600)
        )
        self.events: dict[int, dict[str, dict]] = {}
        self.wall: dict[int, float] = {}
        self.samples: dict[int, tuple] = {}
        self.declared_total = sum(w.declared_bytes for w in work)
        self.payload_total = self.payload_left = sum(w.potential_payload_bytes for w in work)
        self.heads_total = self.heads_left = sum(w.generation_heads for w in work)
        self.files_left = sum(w.files for w in work)
        self.declared_completed = self.observed_native = self.observed_restored = 0
        self.observed_heads = 0
        self.inventory_complete = all(w.reuse_inventory_complete for w in work)
        self.invalidated = False
        self.repairing: set[int] = set()
        self.revised: set[int] = set()
        self.forecast = ForecastAttempt.current(
            stage, "models", {"review_kind": "model_byte_batch"}
        )

    def __enter__(self):
        self.progress.__enter__()
        return self

    def __exit__(self, *args):
        return self.progress.__exit__(*args)

    def child_report(self, index: int):
        forward = self.progress.child_report()

        def report(event):
            # Use the parent's lock for callbacks and its heartbeat thread;
            # a second batch lock could invert monitor/callback lock ordering.
            with self.progress.lock:
                if index in self.wall:
                    # Preserve a late historical event without treating it as
                    # activity in a newer model or counting the same work twice.
                    self._emit(event)
                    return
                stage = event.get("stage")
                if stage in (*_HEAD_STAGES, "chunked_model_verification"):
                    prior = self.events.setdefault(index, {}).get(stage, {})
                    if prior.get("status") != "completed":
                        self.events[index][stage] = dict(event)
                        if stage in _HEAD_STAGES:
                            self.observed_heads += event.get("completed_units", 0) - prior.get(
                                "completed_units", 0
                            )
                        else:
                            self.observed_native += event.get("native_bytes", 0) - prior.get(
                                "native_bytes", 0
                            )
                            self.observed_restored += event.get("restored_bytes", 0) - prior.get(
                                "restored_bytes", 0
                            )
                if event.get("status") == "repair_required" and index not in self.wall:
                    self.repairing.add(index)
                if event.get("status") == "refused" and index not in self.wall:
                    self.invalidated = True
                forward(event)

        return report

    def advance(self, index: int, elapsed: float) -> None:
        with self.progress.lock:
            if index in self.wall:
                self.invalidated = True
                self.progress.emit("retrying", reason="duplicate_model_completion")
                return
            # The native caller advances only after its byte/receipt checks
            # complete. This is not a caller-supplied reuse verdict.
            if index in self.repairing:
                self.repairing.remove(index)
                self.revised.add(index)
            self.wall[index] = elapsed
            self._record_component(index)
            self.events.pop(index, None)
            item = self.work[index]
            self.payload_left -= item.potential_payload_bytes
            self.heads_left -= item.generation_heads
            self.files_left -= item.files
            self.declared_completed += item.declared_bytes
            before = self.progress.last_emit
            self.progress.advance(1)
            if self.progress.last_emit == before:
                self.progress.emit("running", reason="model_completed")

    def _record_component(self, index):
        wall = self.wall[index]
        events = self.events.get(index, {})
        heads = [events.get(stage, {}) for stage in _HEAD_STAGES]
        if any(e.get("status") != "completed" for e in heads):
            return
        head_count = sum(e["completed_units"] for e in heads)
        if head_count != self.work[index].generation_heads:
            self.invalidated = True
            return
        head_seconds = sum(e["elapsed_seconds"] for e in heads)
        verified = events.get("chunked_model_verification")
        if verified is None:
            if self.work[index].potential_payload_bytes:
                return
            native, verification = 0, max(0, wall - head_seconds)
        elif verified.get("status") == "completed":
            native = verified["native_bytes"]
            verification = max(0, verified["elapsed_seconds"] - heads[1]["elapsed_seconds"])
            if native > self.work[index].potential_payload_bytes:
                self.revised.add(index)
        else:
            return
        self.samples[index] = (index, native, verification, head_count, head_seconds, wall)
        if len(self.samples) > _RATE_WINDOW_MODELS:
            del self.samples[min(self.samples)]

    def _components(self):
        return list(self.samples.values())

    def _forecast(self):
        samples = self._components()
        payload_left, heads_left, files_left = self.payload_left, self.heads_left, self.files_left
        cached = [s for s in samples if s[1] <= 1024**2 and self.work[s[0]].files]
        local_cost = min((s[2] / self.work[s[0]].files for s in cached), default=None)
        head_count = sum(s[3] for s in samples)
        head_seconds = sum(s[4] for s in samples)
        head_cost = head_seconds / head_count if head_count else None
        bulk = [s for s in samples if s[1] > 1024**2]
        payload_cost = None
        if bulk and local_cost is not None:
            payload_cost = sum(
                max(0, s[2] - self.work[s[0]].files * local_cost) for s in bulk
            ) / sum(s[1] for s in bulk)
        component = {
            "declared_bytes_total": self.declared_total,
            "declared_bytes_completed": self.declared_completed,
            "potential_distinct_file_bytes_total": self.payload_total,
            "native_payload_bytes_observed": self.observed_native,
            "restored_payload_bytes_observed": self.observed_restored,
            "generation_HEAD_operations_total": self.heads_total,
            "generation_HEAD_operations_observed": self.observed_heads,
            "completed_component_models": len(samples),
            "payload_rate_models": len(bulk),
            "cached_file_rate_models": len(cached),
            "potential_payload_bytes_remaining": payload_left,
            "generation_HEAD_operations_remaining": heads_left,
            "local_files_remaining": files_left,
            "active_partial_work_credited": False,
            "reuse_inventory_complete": self.inventory_complete,
            "component_rate_window_max_models": _RATE_WINDOW_MODELS,
            "component_rate_scope": "recent_completed_models_in_this_invocation",
            "probability_coverage_calibrated": False,
            "work_plan_invalidated": self.invalidated,
            "work_plan_revised_models": len(self.revised),
            "active_repair_models": len(self.repairing),
            "planning_range_basis": "0.5x_to_2x_component_sensitivity_not_probability_bounds",
        }
        if self.invalidated:
            return None, None, "withdrawn_work_plan_requires_repair_or_replanning", component
        if self.repairing:
            return None, None, "withdrawn_active_native_repair", component
        if (
            (payload_left and payload_cost is None)
            or (heads_left and head_cost is None)
            or (files_left and local_cost is None)
        ):
            # Explicit initial planning, not a model-count throughput forecast.
            planning = [
                payload_left / (100 * 1024**2) + heads_left / 200 + files_left * 0.001,
                payload_left / 1024**2 + heads_left + files_left * 0.1,
            ]
            component["planning_range_basis"] = (
                "1_to_100_MiB_per_second_1_to_200_HEADs_per_second_0.001_to_0.1_seconds_per_file"
            )
            return None, planning, "planning_components_waiting_for_native_samples", component
        residual = max(
            0,
            sum(s[5] - s[4] - s[2] for s in samples) / len(samples) if samples else 0,
        )
        parts = {
            "payload_seconds": payload_left * (payload_cost or 0),
            "generation_HEAD_seconds": heads_left * (head_cost or 0),
            "local_file_seconds": files_left * (local_cost or 0),
            "model_residual_seconds": (len(self.work) - len(self.wall)) * residual,
        }
        eta = sum(parts.values())
        component.update(parts)
        return (
            eta,
            [eta * 0.5, eta * 2],
            "planning_native_components_after_completed_repair"
            if self.revised
            else "planning_native_components_unchanged_generations",
            component,
        )

    def _emit(self, event):
        if event.get("stage") == self.progress.stage:
            event = dict(event)
            event["model_count_eta_seconds"] = event.get("eta_seconds")
            event["model_count_planning_eta_seconds"] = event.get("planning_eta_seconds")
            eta, planning, basis, components = self._forecast()
            state = event["status"]
            if state == "completed":
                eta, planning, basis = 0, None, "completed_model_batch"
            elif state in {"stalled", "retrying", "refused", "repair_required", "waiting"}:
                eta, planning, basis = None, None, "withdrawn_stalled_or_retrying"
            if eta is not None and (not math.isfinite(eta) or eta < 0):
                eta, planning, basis = None, None, "withdrawn_invalid_component_samples"
            event.update(
                eta_seconds=eta,
                planning_eta_seconds=planning,
                planning_seconds_per_unit=None,
                eta_basis=basis,
                eta_scope="authenticated_model_batch_excludes_boot_adoption_and_upload_recovery",
                estimated_finish_utc=None
                if eta is None
                else (datetime.now(timezone.utc) + timedelta(seconds=eta)).isoformat(),
                component_work=components,
                inventory_scope="planning_metadata_only_native_stores_decide_reuse",
            )
            if self.forecast is None:
                event["forecast_accounting"] = {"status": "unselected"}
            else:
                body = {
                    "observed_unix_ms": time.time_ns() // 1_000_000,
                    "state": "interrupted"
                    if event.get("reason_code") == "stage_interrupted"
                    else "completed"
                    if state == "completed"
                    else state,
                    "completed": event["completed_units"],
                    "total": event["total_units"],
                    "eta_seconds": eta,
                    "eta_basis": basis,
                    "elapsed_seconds": event["elapsed_seconds"],
                    "eta_samples": components["completed_component_models"],
                    "eta_ignored_fast_samples": 0,
                    "eta_assumption": (
                        "unchanged_generations_and_shared_file_availability; "
                        "active_partial_work_uncredited; component_planning_not_probability_bounds"
                    ),
                    "forecast_classification": "planning_scenario"
                    if eta is not None or planning is not None
                    else "unknown",
                    "forecast_finish_range_seconds": planning,
                    "forecast_range_basis": components["planning_range_basis"],
                    "forecast_rate_semantics": "umi-model-batch-native-components/1",
                }
                try:
                    event["forecast_accounting"] = self.forecast.observe(body)
                except ForecastCapacityRequired:
                    event["forecast_accounting"] = {"status": "capacity_required"}
                except Exception as error:
                    with suppress(Exception):
                        self.forecast.ledger.note_failure(
                            "consumer_observation_failed", error=error
                        )
                    event["forecast_accounting"] = {"status": "repair_required"}
        if self.report is None:
            _LOG.info(json.dumps(event, separators=(",", ":")))
        else:
            self.report(event)
