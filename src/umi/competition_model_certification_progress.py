"""Thread-safe diagnostics for the selected roster; never admission authority."""

import time
from collections import OrderedDict
from threading import RLock

from .competition_cohort_public_progress import PUBLIC_COHORT_PROGRESS


class ModelCertificationProgress:
    def __init__(self):
        self.lock = RLock()
        self.holds = OrderedDict()
        self.samples = {}

    def operation(self, cohort, submission, stage, *, error_type=None):
        key = (cohort, submission)
        with self.lock:
            if error_type is not None:
                self.holds[key] = dict(stage=stage, error_type=error_type)
                self.holds.move_to_end(key)
                while len(self.holds) > 4096:
                    self.holds.popitem(last=False)
            elif self.holds.get(key, {}).get("stage") == stage:
                self.holds.pop(key, None)

    def report(self, inventory, *, now=None):
        now = time.monotonic() if now is None else now
        cohort = inventory["cohort_sha256"]
        scope = inventory["roster_sha256"]
        done, total = inventory["completed"], inventory["total"]
        with self.lock:
            sample_key = (cohort, inventory.get("selection_scope", "native_selected_roster"))
            prior = self.samples.get(sample_key)
            if prior is None or prior["scope"] != scope:
                prior = dict(
                    scope=scope, started=now, baseline=done, last=done, high=done, last_progress=now
                )
                self.samples[sample_key] = prior
            if done > prior["last"]:
                prior["last_progress"] = now
            prior["high"] = max(prior["high"], done)
            prior["last"] = done
            elapsed = max(0, now - prior["started"])
            delta = done - prior["baseline"]
            holds = [
                dict(submission_sha256=k, **self.holds[(cohort, k)])
                for k in inventory["pending_submission_sha256s"]
                if (cohort, k) in self.holds
            ]
            regressed = done < prior["high"]
            remaining = total - done
            rate = delta / elapsed if delta > 0 and elapsed > 0 else None
            idle = remaining > 0 and now - prior["last_progress"] > 300
            eta = (
                0
                if not remaining
                else (
                    remaining / rate
                    if rate and not holds and not regressed and not idle
                    else None
                )
            )
            # A replacement roster has no comparable completion rate yet. Show
            # an explicitly labeled planning range, then withdraw it if work
            # stops advancing. The range uses prior completed acceptance-stage
            # durations and never borrows a rate from the superseded roster.
            planning = (
                [
                    max(0, 30 * remaining - elapsed),
                    max(0, 1200 * remaining - elapsed),
                ]
                if remaining and eta is None and not holds and not regressed and not idle
                else None
            )
            basis = (
                "complete"
                if not remaining
                else "acceptance_inventory_repair_required"
                if regressed
                else "blocked_acceptance_stage"
                if holds
                else "certificate_completion_idle"
                if idle
                else "measured_current_roster_certificate_throughput"
                if eta is not None
                else "planning_30_to_1200_seconds_per_remaining_certificate"
                if planning is not None
                else "awaiting_current_roster_completion_samples"
            )
            result = dict(
                schema="umi-model-certification-progress/1",
                **inventory,
                remaining=remaining,
                percent=100 * done / total if total else 100,
                elapsed_seconds=elapsed,
                sample_certificates=max(0, delta),
                certificates_per_second=rate,
                eta_seconds=eta,
                planning_eta_seconds=planning,
                eta_basis=basis,
                eta_scope=(
                    (
                        "latest_model_submission_certification_only; "
                        if inventory.get("selection_scope") == "latest_model_submissions"
                        else "selected_model_certification_only; "
                    )
                    + "preparation, evaluation and activation remain separate"
                ),
                eta_assumptions=(
                    "remaining models have comparable cost; "
                    "no unresolved holds, new roster replacements or cross-cohort queue wait"
                ),
                estimated_finish_unix_ms=None if eta is None else int((time.time() + eta) * 1000),
                blocked_count=len(holds),
                blocked=holds,
                repair_required=regressed,
                stalled_or_retrying=bool(holds)
                or regressed
                or idle,
                rate_scope="this observer process and unchanged selected roster",
                certification_authority=False,
            )
            kind = (
                "intake_certification"
                if inventory.get("selection_scope") == "latest_model_submissions"
                else "certification"
            )
            PUBLIC_COHORT_PROGRESS.record(kind, result)
            return result
