"""Retain forecasts issued by an owned native history reader.

Each selected fixed interval is a distinct diagnostic work scope. These facts
are neither native proof authority nor a forecast of rewards or a moving tip.
"""

from __future__ import annotations

import logging
import os
import re
import sqlite3
import time
import uuid

from .competition_forecast import ForecastCapacityRequired, ForecastLedger
from .open_competition import digest

logger = logging.getLogger("umi.competition_reward_history_progress")
# A forced checkpoint-export observation can be emitted for every retained
# block. Qualification measured 4,260 database bytes/observation, so 100,000
# such emissions need about 406 MiB before other scopes or repair copies.
# This is a storage budget, not preallocation or a cohort-duration promise.
DEFAULT_HISTORY_FORECAST_BYTES = 512 * 1024**2
_INVOCATION = uuid.uuid4().hex


def select_history_forecasts(reader, *, root, config, resources, role, predecessor=False):
    """Select diagnostics only after the caller acquired the real owning lease."""
    try:
        prefix = "predecessor_" if predecessor else ""
        series = getattr(config, prefix + "series")
        identity = {
            "series_sha256": digest(series),
            "policy_sha256": digest(config.policy),
            "chain_config_sha256": reader.config_sha256,
            "first_block": reader.first_block,
            "checkpoint_owner": reader.checkpoints.owner,
            "verifier_semantics": reader.checkpoints.semantics,
            "role": role,
            "operation": "native_control_history",
            "workload_regime_sha256": digest(
                {
                    "verification_profile": digest(reader.verification_profile),
                    "service": digest(config.service),
                    "runtime_profile": digest(getattr(config, prefix + "eligibility")),
                    "runtime_adoptions": digest(getattr(config, prefix + "runtime_adoptions")),
                    "runtime_proof_reads": config.runtime_proof_reads,
                }
            ),
        }
        ledger = ForecastLedger(
            root / "history-forecast-accounting",
            maximum_bytes=config.forecast_accounting_bytes,
        )
        resources.callback(ledger.close)
        reader.progress.forecast = HistoryForecast(ledger, identity)
    except ForecastCapacityRequired:
        reader.progress.forecast_health = "capacity_required"
    except (OSError, ValueError, TypeError, sqlite3.Error):
        reader.progress.forecast_health = "repair_required"
    if reader.progress.forecast_health is not None:
        logger.warning(
            "native_history_forecast_accounting status=%s "
            "eta_basis=restore_or_expand_diagnostic_accounting certification_authority=false",
            reader.progress.forecast_health,
        )


class HistoryForecast:
    def __init__(self, ledger, identity):
        self.ledger, self.identity = ledger, identity
        invocation = os.environ.get("INVOCATION_ID", "")
        self.invocation = invocation if re.fullmatch(r"[0-9a-f]{32}", invocation) else _INVOCATION
        self.attempt = None
        self.target = self.last_next = self.scope = None
        self.revision = 0
        self.last_unknown = None

    def _common(self, now):
        return {
            **self.identity,
            "stage": "selected_native_history_interval",
            "unit": "blocks",
            "target_block": self.target,
            "attempt": self.attempt,
            "invocation": self.invocation,
            "observed_unix_ms": now,
        }

    def observe(self, body):
        """Persist the emitted estimate, not an independent faster extrapolation."""
        now = time.time_ns() // 1_000_000
        target, next_block = body["target_block"], body["next_block"]
        changed = target != self.target
        regressed = self.last_next is not None and next_block < self.last_next
        if changed or regressed:
            if self.attempt is not None:
                self.ledger.append(
                    self.attempt + ":reset",
                    self.scope,
                    "attempt_reset",
                    {
                        **self._common(now),
                        "reason": "changed_target" if changed else "cursor_regression",
                        "new_target_block": target,
                        "completion_observed": False,
                    },
                )
            self.target = target
            self.attempt = uuid.uuid4().hex
            self.scope = digest({**self.identity, "target_block": target})
            self.revision = 0
        self.last_next = next_block
        unknown = None
        if body["state"] != "completed" and all(
            body[key] is None
            for key in (
                "eta_seconds",
                "planning_eta_seconds",
                "stage_eta_seconds",
                "stage_planning_eta_seconds",
            )
        ):
            unknown = {
                key: value
                for key, value in body.items()
                if not key.endswith("elapsed_seconds")
            }
            if unknown.get("ancestry_progress") is not None:
                unknown["ancestry_progress"] = {
                    key: value
                    for key, value in unknown["ancestry_progress"].items()
                    if not key.endswith("elapsed_seconds")
                }
            if unknown == self.last_unknown:
                return {
                    **self.ledger.status(self.scope, observed_unix_ms=now),
                    "attempt": self.attempt,
                    "observation_retention": "unchanged_unknown_heartbeat",
                }
        common = self._common(now)
        self.ledger.append(self.scope + ":start", self.scope, "scope_started", common)
        self.ledger.append(self.attempt + ":start", self.scope, "attempt_started", common)
        self.revision += 1
        eta, planning = body["eta_seconds"], body["planning_eta_seconds"]
        stage_eta, stage_planning = body["stage_eta_seconds"], body["stage_planning_eta_seconds"]
        values = {
            **common,
            "revision": self.revision,
            "state": body["state"],
            "completed": body["completed_blocks"],
            "total": body["total_blocks"],
            "finish_unix_ms": None if eta is None else now + round(eta * 1000),
            "finish_range_unix_ms": None
            if planning is None
            else [now + round(value * 1000) for value in planning],
            "range_basis": "uncalibrated_planning_assumptions"
            if planning is not None
            else "not_yet_calibrated",
            "classification": "completed_observation"
            if body["state"] == "completed"
            else "measured_substage"
            if eta is not None
            else "planning_scenario"
            if planning is not None
            else "unknown",
            "revision_reason": "initial" if self.revision == 1 else "new_owner_observation",
            "rate_semantics": "umi-history-ordered-new-native-per-invocation-target-wall-time/1",
            "scope_kind": "fixed_history_interval_only",
            "chain_growth_included": False,
            "activation_work_included": False,
            "assumptions": [
                "selected target remains fixed",
                "remaining blocks need native verification",
                "native throughput excludes restored successful checkpoints",
                "no future restart or new blocker",
                "moving finalized head and reward activation are outside this estimate",
            ],
            "native_progress": body,
            "substage_finish_unix_ms": None
            if stage_eta is None
            else now + round(stage_eta * 1000),
            "substage_finish_range_unix_ms": None
            if stage_planning is None
            else [now + round(value * 1000) for value in stage_planning],
            "substage_outcome_basis": "retained_observation_only_no_independent_completion_event",
        }
        self.ledger.append(
            self.attempt + ":observation:" + str(self.revision),
            self.scope,
            "observation" if body["state"] == "completed" else "forecast",
            values,
        )
        self.last_unknown = unknown
        if body["state"] == "completed":
            self.ledger.append(
                self.attempt + ":terminal",
                self.scope,
                "attempt_terminal",
                {
                    **common,
                    "state": "completed",
                    "outcome_basis": "native_reader_returned_complete_selected_interval",
                    "rewards_live": False,
                },
            )
        return {**self.ledger.status(self.scope, observed_unix_ms=now), "attempt": self.attempt}
