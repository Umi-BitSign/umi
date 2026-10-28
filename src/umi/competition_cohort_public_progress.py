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

DIRECT_UPLOAD_PROGRESS_FIELDS = (
    "objects_pending",
    "objects_retrying",
    "objects_ready",
    "objects_terminal",
    "objects_total",
    "objects_classified",
    "objects_unclassified",
    "objects_selected",
    "objects_superseded",
    "objects_ineligible",
    "selected_objects_pending_verification",
    "selected_source_bytes_total",
    "selected_source_bytes_remaining",
    "selection_count_scope",
    "selection_refresh_required",
    "object_count_status",
    "object_count_scope",
    "active_object_position",
    "active_object_position_scope",
    "active_object_sha256",
    "active_object_stage",
    "model_sha256",
    "participation_enqueue_retrying",
)

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
    "eta_samples",
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
    "error_stage",
    "cause_type",
    "sqlite_errorcode",
    "sqlite_errorname",
    "queue_completed",
    "queue_total",
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
    "exported_inferences",
    "reused_incumbent_observations",
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
    "released_local_bytes",
    "reason_code",
    "operation",
    "acceptance_owner_cohort_sha256",
    "acceptance_owner_stage",
    "acceptance_queue_wait_seconds",
    "acceptance_queue_eta_scope",
    "selected_cohort_sha256",
    "queue_wait_seconds",
    "queue_wait_scope",
    *DIRECT_UPLOAD_PROGRESS_FIELDS,
    "source_object_key_sha256",
    "object_role",
    "owner_report_observed_unix_ms",
    "evaluator",
    "role",
    "producer_epoch_sha256",
    "series_sha256",
    "publication",
    "refresh",
)


_HISTORICAL_PROGRESS_FIELDS = (
    "stage",
    "status",
    "scope",
    "unit",
    "completed",
    "total",
    "percent",
    "elapsed_seconds",
    "eta_seconds",
    "planning_eta_seconds",
    "eta_basis",
    "eta_scope",
    "eta_assumptions",
    "eta_samples",
    "stalled_or_retrying",
    "repair_required",
    "error_type",
    "error_stage",
    "cause_type",
    "reason_code",
    "sqlite_errorcode",
    "sqlite_errorname",
    "excluded_without_receipt_this_poll",
)


def _historical_progress(body):
    if type(body) is not dict:
        return {}
    result = {}
    for key in _HISTORICAL_PROGRESS_FIELDS:
        if key not in body:
            continue
        value = body.get(key)
        if key == "planning_eta_seconds":
            if value is None or (
                type(value) is list
                and len(value) == 2
                and all(type(item) in (int, float) for item in value)
            ):
                result[key] = value
        elif value is None or type(value) in (str, bool, int, float):
            result[key] = value
    return result


def _age_participation(value, age):
    if value.get("status") not in {"running", "retrying"}:
        return
    value["elapsed_seconds"] = round(value.get("elapsed_seconds", 0) + age, 3)
    eta = value.get("eta_seconds")
    if type(eta) in (int, float):
        if age > eta:
            value["eta_seconds"] = None
            value["eta_basis"] = "forecast_overdue"
            value["stalled_or_retrying"] = True
        else:
            value["eta_seconds"] = round(max(0.0, eta - age), 3)
    planning = value.get("planning_eta_seconds")
    if (
        isinstance(planning, list)
        and len(planning) == 2
        and all(type(item) in (int, float) for item in planning)
    ):
        if age > planning[1]:
            value["planning_eta_seconds"] = None
            value["eta_basis"] = "planning_range_exceeded_retrying"
            value["stalled_or_retrying"] = True
        else:
            value["planning_eta_seconds"] = [round(max(0.0, item - age), 1) for item in planning]


def is_cached_cohort_progress_request(method, path):
    """Select only the fixed cache-only GET route, never another public read."""
    prefix, suffix = "/v1/competition/cohorts/", "/progress"
    return (
        method == "GET"
        and isinstance(path, str)
        and path.startswith(prefix)
        and path.endswith(suffix)
        and re.fullmatch(r"[0-9a-f]{64}", path[len(prefix) : -len(suffix)]) is not None
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
            "direct_uploads",
            "reserved_participation",
            "work",
            "request_start",
            "execution",
            "execution_workers",
            "storage_retirement",
            "settlement",
        }:
            return
        now = time.monotonic()
        public = {key: body[key] for key in _FIELDS if key in body}
        if kind == "reserved_participation" and "historical_recovery" in body:
            public["historical_recovery"] = _historical_progress(body["historical_recovery"])
        if kind == "execution_workers":
            from .competition_cohort_execution_work import MAX_STAGES, public_stage

            rows = body.get("workers", [])
            if type(rows) is not list or len(rows) > 64:
                raise ValueError("evaluator work inventory exceeds its bound")
            workers, remaining = [], MAX_STAGES
            for row in rows:
                if type(row) is not dict:
                    raise ValueError("invalid evaluator work observation")
                evaluator = row.get("evaluator")
                if type(evaluator) is not str or re.fullmatch(r"[0-9a-f]{64}", evaluator) is None:
                    raise ValueError("invalid evaluator work identity")
                stages = row.get("stages", [])
                if type(stages) is not list or len(stages) > MAX_STAGES:
                    raise ValueError("invalid evaluator stage inventory")
                selected = [public_stage(s) for s in stages[:remaining]]
                remaining -= len(selected)
                status = row.get("status")
                if status not in {
                    "current",
                    "unavailable",
                    "epoch_unavailable",
                    "invalid_or_unavailable",
                }:
                    raise ValueError("invalid evaluator observation status")
                workers.append(
                    dict(
                        evaluator=evaluator,
                        status=status,
                        stages=selected,
                        omitted_stages=len(stages) - len(selected),
                    )
                )
            public["workers"] = workers
        observed_ms = time.time_ns() // 1_000_000
        if kind == "settlement" and type(body.get("observed_unix_ms")) is int:
            # Remote samplers must not freshen an old producer heartbeat.
            observed_ms = body["observed_unix_ms"]
            now -= max(0, time.time_ns() // 1_000_000 - observed_ms) / 1000
        public["observed_unix_ms"] = observed_ms
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

    def active_work_snapshot(self, cohort):
        """Copy bounded emitted stages only; no native operations on HTTP GET."""
        from .competition_cohort_execution_work import aged_stage

        now = time.monotonic()
        with self.lock:
            values = deepcopy(tuple(self.entries.get(cohort, {}).get("active_work", {}).values()))
        return [aged_stage(work, max(0, now - observed)) for observed, work in values]

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
            "direct_uploads",
            "reserved_participation",
            "work",
            "request_start",
            "execution",
            "execution_workers",
            "storage_retirement",
            "settlement",
        ):
            if kind in entry:
                observed, value = entry[kind]
                age = max(0, now - observed)
                value.update(age_seconds=round(age, 3), stale=age > 120)
                if kind == "direct_uploads":
                    field = (
                        "elapsed_seconds"
                        if value.get("status") == "running"
                        else "queue_wait_seconds"
                    )
                    value[field] = round(value.get(field, 0) + age, 3)
                if kind == "execution_workers":
                    from .competition_cohort_execution_work import aged_stage

                    for worker in value["workers"]:
                        worker["stages"] = [aged_stage(s, age) for s in worker["stages"]]
                if kind == "reserved_participation":
                    _age_participation(value, age)
                    if "historical_recovery" in value:
                        _age_participation(value["historical_recovery"], age)
                if (kind == "acceptance" and value.get("status") == "running") or kind in {
                    "certification",
                    "intake_certification",
                }:
                    if kind == "acceptance":
                        value["elapsed_seconds"] = round(age, 3)
                    planning = value.get("planning_eta_seconds")
                    if (
                        isinstance(planning, list)
                        and len(planning) == 2
                        and all(type(v) in (int, float) for v in planning)
                    ):
                        if age > planning[1]:
                            value["planning_eta_seconds"] = None
                            value["eta_basis"] = "planning_range_exceeded_retrying"
                            value["stalled_or_retrying"] = True
                        else:
                            value["planning_eta_seconds"] = [
                                round(max(0.0, planning[0] - age), 1),
                                round(max(0.0, planning[1] - age), 1),
                            ]
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
                    if not (
                        complete
                        and stage
                        in {
                            "automatic_progression_held",
                            "progress_review",
                            "decision_certification",
                        }
                    ):
                        selected = certification
                        stage = "model_certification"
                    break
            if stage == "model_certification" and (
                selected.get("stale")
                or (selected.get("stalled_or_retrying") and not selected.get("repair_required"))
            ):
                # A roster meter can lack new certificates while the owner is
                # actively verifying the next model. Show that live work and
                # keep the certificate count in components.
                work = parts.get("work")
                live_work = (
                    work is not None
                    and not work["stale"]
                    and work.get("state") in {"started", "running", "waiting"}
                    and isinstance(work.get("stage"), str)
                    and entry["work"][0] >= entry.get("phase_started", 0)
                )
                acceptance = parts.get("acceptance")
                live_acceptance = (
                    acceptance is not None
                    and not acceptance["stale"]
                    and acceptance.get("status") == "running"
                    and isinstance(acceptance.get("stage"), str)
                )
                if live_work and work["stage"].startswith(
                    ("model_acceptance_", "model_promotion_")
                ):
                    selected = work
                    stage = work["stage"]
                elif live_acceptance:
                    selected = acceptance
                    stage = "model_acceptance_" + acceptance["stage"]
                elif live_work:
                    # Nested transfer stages can outlive their enclosing
                    # acceptance heartbeat while still reporting live bytes.
                    selected = work
                    stage = work["stage"]
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
        if (
            stage not in {"model_certification", "waiting_request_rest"}
            and selected is not parts.get("acceptance")
            and "work" in parts
        ):
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
                and not parts["work"]["stale"]
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
        settlement = parts.get("settlement")
        if settlement is not None and phase in {
            "reference_reveal",
            "evidence",
            "review",
            "certification",
            "first_admission",
            "complete",
        }:
            # Intake's native loop ends at handoff. Later owner-produced stages
            # retain their independent scope and never inherit an intake100%.
            selected = settlement
            phase = settlement.get("phase") or phase
            stage = settlement.get("stage", "settlement_diagnostics_unavailable")
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
        if (
            phase in (None, "intake")
            and stage != "model_certification"
            and "intake_certification" in parts
        ):
            # A failed acceptance item does not make unrelated current work
            # idle. Keep its unresolved count visible beside the active stage.
            result["blocked_count"] = parts["intake_certification"].get("blocked_count", 0)
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
