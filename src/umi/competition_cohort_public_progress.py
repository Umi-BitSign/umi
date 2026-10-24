"""Bounded, process-local public diagnostics; never protocol authority.

Only explicit public fields enter this view. Reading it does no RPC, model I/O,
history replay or database work. Owners restore counts from their journals after
restart; an empty view is unknown rather than zero or completed.
"""

import re
import time
from collections import OrderedDict
from contextlib import contextmanager
from contextvars import ContextVar
from copy import deepcopy
from threading import RLock

_FIELDS = (
    "phase",
    "stage",
    "status",
    "state",
    "completed",
    "total",
    "percent",
    "elapsed_seconds",
    "eta_seconds",
    "planning_eta_seconds",
    "eta_basis",
    "eta_scope",
    "eta_assumptions",
    "estimated_finish_unix_ms",
    "stalled_or_retrying",
    "stalled",
    "repair_required",
    "blocked_count",
    "roster_sha256",
    "selection_scope",
    "sample_certificates",
    "certificates_per_second",
    "submission_sha256",
    "error_type",
    "scope",
    "unit",
    "work_id",
    "ready",
    "not_before_unix_ms",
    "chain_timestamp_ms",
    "observed_at_block",
    "target_block",
    "rest_clock",
    "cutover_unix_ms",
    "exported_executions",
    "exported_comparisons",
    "delivered_orders",
    "delivered_order_executions",
    "projected_executions",
    "projection_basis",
    "rate_completed_models",
    "rate_sample_seconds",
    "rate_epoch_sha256",
    "rate_producers",
    "rate_probe_status",
    "rate_probe_http_status",
    "rate_probe_attempts",
    "rate_probe_failures",
    "rate_probe_timeouts",
)


class CohortProgressSnapshots:
    def __init__(self, maximum_cohorts=256):
        self.lock = RLock()
        self.entries = OrderedDict()
        self.maximum_cohorts = maximum_cohorts

    def record(self, kind, body):
        cohort = body.get("cohort_sha256")
        if not isinstance(cohort, str) or re.fullmatch(r"[0-9a-f]{64}", cohort) is None:
            return
        if kind not in {
            "lifecycle",
            "certification",
            "intake_certification",
            "acceptance",
            "work",
            "request_start",
            "execution",
        }:
            return
        now = time.monotonic()
        public = {key: body[key] for key in _FIELDS if key in body}
        public["observed_unix_ms"] = time.time_ns() // 1_000_000
        if public.get("eta_seconds") is not None and public.get("estimated_finish_unix_ms") is None:
            public["estimated_finish_unix_ms"] = public["observed_unix_ms"] + int(
                public["eta_seconds"] * 1000
            )
        with self.lock:
            entry = self.entries.setdefault(cohort, {})
            old = entry.get("lifecycle")
            if kind == "lifecycle" and (old is None or old[1].get("phase") != public.get("phase")):
                entry["phase_started"] = now
            entry[kind] = (now, public)
            if kind == "work" and type(public.get("work_id")) is int:
                active = entry.setdefault("active_work", OrderedDict())
                work_id = public["work_id"]
                if public.get("state") in {"started", "running", "waiting"}:
                    active[work_id] = (now, public)
                    while len(active) > 32:
                        active.popitem(last=False)
                else:
                    active.pop(work_id, None)
            self.entries.move_to_end(cohort)
            while len(self.entries) > self.maximum_cohorts:
                self.entries.popitem(last=False)

    def snapshot(self, cohort):
        now = time.monotonic()
        with self.lock:
            entry = deepcopy(self.entries.get(cohort, {}))
        active = entry.get("active_work", {})
        if active:
            # Keep an unfinished copy visible between unrelated short completed
            # operations. Insertion order follows substage starts, not heartbeat
            # ordering; nested work takes precedence over its enclosing meter.
            entry["work"] = next(reversed(active.values()))
        parts = {}
        for kind in (
            "lifecycle",
            "certification",
            "intake_certification",
            "acceptance",
            "work",
            "request_start",
            "execution",
        ):
            if kind in entry:
                observed, value = entry[kind]
                age = max(0, now - observed)
                value.update(age_seconds=round(age, 3), stale=age > 120)
                if kind == "acceptance" and value.get("status") == "running":
                    value["elapsed_seconds"] = round(age, 3)
                parts[kind] = value
        phase = parts.get("lifecycle", {}).get("phase")
        selected = parts.get("lifecycle", {})
        stage = selected.get("stage", "awaiting_observation")
        if phase == "preparation" and selected.get("status") == "waiting_request_rest":
            selected = parts.get("request_start", selected)
            stage = "waiting_request_rest"
        if phase in (None, "intake"):
            for kind in ("certification", "intake_certification"):
                if kind in parts:
                    certification = parts[kind]
                    complete = (
                        type(certification.get("total")) is int
                        and certification.get("completed") == certification["total"]
                    )
                    if not (complete and stage in {"progress_review", "decision_certification"}):
                        selected = certification
                        stage = "model_certification"
                    break
        quorum_stage = {
            "progress_review": f"{phase}_progress_quorum",
            "decision_certification": f"{phase}_decision_quorum",
        }.get(stage)
        if phase == "requests" and "execution" in parts and quorum_stage is None:
            selected = parts["execution"]
            stage = selected["stage"]
        if quorum_stage is not None:
            # Concurrent model exports must not hide the phase transition that
            # follows completed certification. Keep its own meter and ETA.
            for observed, work in reversed(active.values()):
                if work.get("stage") == quorum_stage and observed >= entry.get("phase_started", 0):
                    entry["work"] = (observed, work)
                    age = max(0, now - observed)
                    parts["work"] = dict(work, age_seconds=round(age, 3), stale=age > 120)
                    break
        if stage not in {"model_certification", "waiting_request_rest"} and "work" in parts:
            observed, work = entry["work"]
            earlier_phase = (
                phase == "requests"
                and "execution" in parts
                and (
                    work.get("stage") == "lifecycle_history_publication"
                    or work.get("stage", "").startswith(
                        (
                            "model_acceptance_",
                            "preparation_",
                            "intake_",
                            "legacy_model_",
                            "chunked_model_",
                        )
                    )
                )
            )
            # Do not call the previous phase's last 100% substage current work.
            if (
                not earlier_phase
                and observed >= entry.get("phase_started", 0)
                and work.get("state")
                in {
                    "started",
                    "running",
                    "waiting",
                }
            ):
                selected = parts["work"]
                stage = selected["stage"]
        result = dict(
            schema="umi-public-cohort-progress/1",
            cohort_sha256=cohort,
            phase=phase,
            stage=stage,
            completed=None,
            total=None,
            percent=None,
            elapsed_seconds=None,
            eta_seconds=None,
            eta_basis="awaiting_current_stage_measurement",
            eta_scope="current_stage_only",
            estimated_finish_unix_ms=None,
            stalled_or_retrying=False,
            overall_percent=None,
            overall_eta_seconds=None,
            overall_eta_basis="end_to_end_forecast_not_established",
            certification_authority=False,
            components=parts,
        )
        result.update({key: value for key, value in selected.items() if key != "stage"})
        result["phase"] = phase
        result["stage"] = stage
        operation = parts.get("acceptance", {})
        if (
            stage == "model_certification"
            and operation.get("status") == "pending"
            and not (
                operation.get("stage") == "retained_lookup"
                and operation.get("error_type") == "PendingModelArtifacts"
            )
        ):
            result["stalled_or_retrying"] = True
        eta = selected.get("eta_seconds")
        if selected.get("stale"):
            result.update(
                eta_seconds=None,
                estimated_finish_unix_ms=None,
                eta_basis="stale_observation",
                stalled_or_retrying=True,
            )
        elif result.get("stalled_or_retrying") or result.get("stalled"):
            result.update(
                eta_seconds=None, estimated_finish_unix_ms=None, eta_basis="stalled_or_retrying"
            )
        elif eta is not None and eta > 0:
            age = selected.get("age_seconds", 0)
            if age >= eta:
                result.update(
                    eta_seconds=None,
                    estimated_finish_unix_ms=None,
                    eta_basis="forecast_overdue",
                    stalled_or_retrying=True,
                )
            else:
                result["eta_seconds"] = round(eta - age, 3)
        return result


PUBLIC_COHORT_PROGRESS = CohortProgressSnapshots()
PUBLIC_COHORT_SCOPE = ContextVar("umi_public_cohort_progress", default=None)
EXECUTION_JOB_SCOPE = ContextVar("umi_execution_progress_job", default=None)


@contextmanager
def execution_job_scope(job_sha256):
    """Attribute diagnostics without retaining private job or model objects."""
    selected = (
        job_sha256
        if type(job_sha256) is str and re.fullmatch(r"[0-9a-f]{64}", job_sha256)
        else None
    )
    token = EXECUTION_JOB_SCOPE.set(selected)
    try:
        yield
    finally:
        EXECUTION_JOB_SCOPE.reset(token)
