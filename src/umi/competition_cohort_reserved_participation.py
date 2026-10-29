"""Continue already signed, payload-ready reservations without a client session.

The existing verifier queues advisory metadata during its ordinary pass. This
separate serial owner performs the shared participation path; neither polling
nor restart rereads payloads or invents authority to expire an accepted upload.
"""

import logging
import sqlite3
import time
from bisect import bisect_right

from .competition_cohort_direct_model_owner import DirectModelUploadPending
from .competition_cohort_direct_model_upload import SignedDirectModelUploadCompletion
from .competition_cohort_participation import CohortParticipationRequest
from .competition_cohort_participation_delivery import participation_retry_details
from .competition_cohort_public_progress import PUBLIC_COHORT_PROGRESS
from .concurrency import run_owned_thread
from .open_competition import digest
from .protocol import canonical_json_bytes

_LOG = logging.getLogger("umi.competition.progress")
_READY = "direct-participation-ready"
_DONE = "direct-participation-completed"


class _UnselectedReservation(ValueError):
    """Scheduling exclusion only; a prior native receipt must still finish."""


def _hex32(value):
    return (
        isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)
    )


def queue_ready_participation(owner, reservation):
    """Persist one bounded hint; the admission path still checks native authority."""
    body = reservation.reservation
    upload = body.payload.upload_sha256
    expected = {
        "schema": "umi-direct-participation-ready/1",
        "upload_sha256": upload,
        "model_sha256": body.payload.model_sha256,
    }
    prior = owner.journal.get(_READY, upload)
    if prior is None:
        owner.journal.put(_READY, upload, expected)
    elif prior != expected:
        raise ValueError("retained participation readiness differs; repair required")


class ReservedParticipationWorker:
    def __init__(self, owners, delivery, *, batch_size=2, poll_seconds=5):
        if type(batch_size) is not int or not 1 <= batch_size <= 16:
            raise ValueError("reserved participation batch must be between 1 and 16")
        if type(poll_seconds) is not int or not 1 <= poll_seconds <= 60:
            raise ValueError("reserved participation poll must be between 1 and 60 seconds")
        self.owners, self.delivery, self.batch_size = owners, delivery, batch_size
        self.poll_seconds = poll_seconds
        self._after, self._started, self._samples = {}, {}, {}
        self._cadence = {}
        self._forecast = {}
        self._completed = {}
        self._completion_after = {}
        self._completion_inventory = {}
        self._lane_next = {}
        self._cohort_next = 0

    @staticmethod
    def _eligible(owner, upload, selection):
        if selection is None:
            raise DirectModelUploadPending("reserved participation selection refresh required")
        fence, excluded = selection
        if not owner._selection_authority_current(fence):
            raise DirectModelUploadPending("reserved participation selection refresh required")
        with owner.journal.read_transaction() as db:
            if owner.journal.selection_fence(db) != fence[0]:
                raise DirectModelUploadPending("reserved participation selection refresh required")
        if upload in excluded:
            raise _UnselectedReservation("reserved participation is no longer selected")

    def _inventory(self, owner):
        # Reuse the verifier's latest eligibility projection. Native intake still
        # validates the exact cutoff, reservation, history and registration.
        fence = owner._continuation_selection
        with owner.journal.read_transaction() as db:
            ready = owner.journal.keys(_READY, db=db)
            completed_keys = set(owner.journal.keys(_DONE, db=db))
            reused = self._completed.setdefault(owner.config.cohort_sha256, set())
            if not reused <= completed_keys or not completed_keys <= set(ready):
                raise ValueError("completed participation checkpoint missing; repair required")
            if db.execute(
                "SELECT 1 FROM records r JOIN holds h ON h.id=r.id WHERE r.kind=? LIMIT 1",
                (_READY,),
            ).fetchone():
                raise ValueError("completed participation conflict held; repair required")
        # Snapshot only bounded identities; parse each uncached native record
        # under its own read, so a whole queue cannot block promotion COMMIT.
        done, pending = set(), []
        for upload in ready:
            if upload in reused:
                done.add(upload)
                continue
            value = owner.journal.get(_READY, upload)
            if (
                not isinstance(value, dict)
                or value.get("schema") != "umi-direct-participation-ready/1"
                or value.get("upload_sha256") != upload
                or not _hex32(value.get("model_sha256"))
            ):
                raise ValueError("retained participation readiness needs repair")
            completed = owner.journal.get(_DONE, upload)
            if completed is not None:
                if (
                    not isinstance(completed, dict)
                    or completed.get("schema") != "umi-direct-participation-completed/1"
                    or completed.get("upload_sha256") != upload
                    or completed.get("model_sha256") != value["model_sha256"]
                    or not _hex32(completed.get("record_sha256"))
                ):
                    raise ValueError("retained participation completion needs repair")
                done.add(upload)
                reused.add(upload)
            else:
                pending.append(upload)
        recoveries = self._recoveries(owner)
        return fence, done, pending, recoveries

    def _recoveries(self, owner):
        with owner.journal.read_transaction() as db:
            _, _, kinds = owner.journal._record_capacity(db)
            owner.journal._check_original_counts(kinds)
            fence = (
                *(
                    kinds.get(kind, 0)
                    for kind in (
                        "direct-request",
                        "direct-reservation",
                        "direct-intent",
                        "direct-completion",
                        "direct-object",
                        "direct-superseded",
                    )
                ),
                db.execute("SELECT COUNT(*) FROM holds").fetchone()[0],
            )
        cohort = owner.config.cohort_sha256
        previous = self._completion_inventory.get(cohort)
        if previous is not None and previous[0] == fence:
            return list(previous[1])
        recoveries = []
        # Upload capacity bounds requests, not reservation generations. Reuse
        # the current-attempt index and only rebuild on immutable-input changes.
        # Close every native read before digest/signature parsing. In particular
        # never retain a whole-cohort reader against concurrent promotion writes.
        for upload in owner.journal.keys("direct-request"):
            attempt = owner.journal.latest_attempt(upload)
            if attempt is None:
                continue
            raw = owner.journal.get("direct-reservation", attempt.attempt_id)
            if raw is None:
                continue
            if not isinstance(raw, dict) or not isinstance(raw.get("reservation"), dict):
                raise ValueError("retained completion reservation needs repair")
            key = digest(raw["reservation"])
            if (
                owner.journal.get("direct-object", key) is None
                and owner.journal.get("direct-superseded", key) is None
                and owner.journal.get("direct-completion", key) is not None
            ):
                reservation = owner._reservation_by_digest(key)
                recoveries.append((key, reservation.reservation.payload.upload_sha256))
        recoveries.sort()
        self._completion_inventory[cohort] = (fence, tuple(recoveries))
        return recoveries

    @staticmethod
    def _request(owner, upload):
        raw = owner.journal.get("direct-request", upload)
        if raw is None:
            raise ValueError("retained participation request missing; repair required")
        request = CohortParticipationRequest.model_validate_json(canonical_json_bytes(raw))
        if digest(request) != upload or (
            request.consent.consent.cohort_sha256 != owner.config.cohort_sha256
        ):
            raise ValueError("retained participation request identity differs")
        return request

    def _bind_cadence(self, cohort, selection, selected_ready):
        # This identity contains only existing immutable metadata, never model
        # bytes. Restarts and changed readiness/selection start a fresh forecast.
        identity = None if selection is None else (selection, frozenset(selected_ready))
        prior = self._cadence.get(cohort)
        if identity is None:
            self._cadence.pop(cohort, None)
            self._forecast.pop(cohort, None)
        elif prior is None or prior[0] != identity:
            self._cadence[cohort] = (identity, [])
            self._forecast.pop(cohort, None)
            self._started[(cohort, "selected_ready_participation_checkpoints")] = time.monotonic()

    def _observe_cadence(self, cohort, done):
        value = self._cadence.get(cohort)
        if value is not None:
            observations = value[1]
            observations.append((time.monotonic(), done))
            del observations[:-32]

    def _progress(self, cohort, done, total, *, stage, scope, error=None):
        pending = None if total is None else total - done
        samples = self._samples.get((cohort, scope), [])
        now = time.monotonic()
        elapsed = now - self._started.setdefault((cohort, scope), now)
        selected = scope == "selected_ready_participation_checkpoints"
        observations = self._cadence.get(cohort, (None, []))[1] if selected else []
        cadence_samples = max(0, len(observations) - 1)
        gained = done - observations[0][1] if cadence_samples else 0
        cadence_elapsed = now - observations[0][0] if cadence_samples else 0
        idle = selected and bool(pending) and bool(cadence_samples) and gained == 0
        forecast = self._forecast.get(cohort) if selected else None
        overdue = bool(
            selected and pending and forecast and done <= forecast[0] and now >= forecast[1]
        )
        eta = (
            0
            if pending == 0
            else pending * cadence_elapsed / gained
            if selected and cadence_samples and gained > 0 and error is None and not overdue
            else None
            if selected
            else pending * sum(samples) / len(samples)
            if samples and error is None
            else None
        )
        if selected and pending and eta is not None:
            if forecast is None or done > forecast[0]:
                self._forecast[cohort] = (done, now + eta)
            else:
                # A repeated snapshot/no-progress visit cannot move the last
                # issued finish time forward. Expiry stays visible until work
                # advances; the next gain then includes the intervening stall.
                eta = forecast[1] - now
        planning = None
        if pending and not cadence_samples and selected and error is None:
            # Planning only until two visits establish the wall-clock cadence.
            # Both bounded allowances, other cohorts and poll sleeps contribute;
            # a successful item's short execution time is not the lane rate.
            slots = max(1, self.batch_size // 2)
            visits = (pending + slots - 1) // slots
            if self.batch_size == 1:
                visits *= 2  # A populated historical lane takes alternate visits.
            cycle = len(self.owners.owners) * (
                self.poll_seconds
                + 2 * self.batch_size * (self.delivery.capture_timeout_seconds + 30)
            )
            planning = [1, visits * cycle]
        elif pending and not selected and not samples and error is None:
            planning = [1, pending * (self.delivery.capture_timeout_seconds + 30)]
        value = {
            "cohort_sha256": cohort,
            "stage": stage,
            "scope": scope,
            "status": "retrying" if error else "completed" if pending == 0 else "running",
            "completed": done,
            "total": total,
            "percent": None if total is None else 100 * done / total if total else 100,
            "elapsed_seconds": round(elapsed, 3),
            "eta_seconds": None if eta is None else round(eta, 3),
            "planning_eta_seconds": planning,
            "eta_basis": "completed"
            if pending == 0
            else "blocked_or_retrying"
            if error
            else "selected_checkpoint_forecast_overdue"
            if overdue
            else "selected_checkpoint_completion_idle"
            if idle
            else "selected_checkpoint_wallclock_cadence"
            if selected and cadence_samples
            else "planning_wallclock_poll_range"
            if selected
            else ("completed_requests_in_this_process" if samples else "planning_range"),
            "eta_scope": scope,
            "eta_assumptions": (
                "same selected ready requests and process; serial cohort rotation, "
                "poll sleeps and both recovery/participation allowances included; "
                "before measured cadence, each attempt assumes capture budget plus 30 seconds; "
                "registration and original evidence available; "
                "excludes payload verification and certification"
            )
            if selected
            else (
                "registration and original evidence available; "
                "excludes payload verification and certification"
            ),
            "eta_samples": cadence_samples if selected else len(samples),
            "stalled_or_retrying": error is not None or idle or overdue,
            "error_type": None,
            "repair_required": False,
            "reason_code": None,
            "unit": "ready_request_checkpoints",
            **(error or {}),
        }
        return value

    def _report(self, cohort, done, total, *, stage, error=None, scope=None, **details):
        value = self._progress(
            cohort,
            done,
            total,
            stage=stage,
            error=error,
            scope=scope or "completed_upload_receipts_in_current_poll",
        )
        value.update(details)
        PUBLIC_COHORT_PROGRESS.record("reserved_participation", value)
        _LOG.info("reserved_model_participation %s", canonical_json_bytes(value).decode("ascii"))
        return value

    def _batch(self, cohort, selected, historical):
        """Share the configured allowance; batch one alternates both queues."""
        lanes = []
        for scope, pending in (("selected", selected), ("historical", historical)):
            split = bisect_right(pending, self._after.get((cohort, scope), ""))
            lanes.append(pending[split:] + pending[:split])
        lane = self._lane_next.get(cohort, 0)
        batch = []
        for _ in range(min(self.batch_size, len(selected) + len(historical))):
            if not lanes[lane]:
                lane = 1 - lane
            batch.append((("selected", "historical")[lane], lanes[lane].pop(0)))
            lane = 1 - lane
        self._lane_next[cohort] = lane
        return batch

    async def poll_once(self):
        # Rotate cohorts as well as requests; one provider outage cannot consume
        # every bounded batch. Successful requests persist their native receipt.
        cohorts = tuple(self.owners.owners)
        cohort = cohorts[self._cohort_next % len(cohorts)]
        self._cohort_next += 1
        owner = self.owners.owners[cohort]
        phase = None if self.owners.intake_phase is None else self.owners.intake_phase(cohort)
        try:
            selection, done, pending, recoveries = await run_owned_thread(self._inventory, owner)
        except (ValueError, OSError, RuntimeError, sqlite3.Error) as error:
            self._cadence.pop(cohort, None)
            self._forecast.pop(cohort, None)
            return self._report(
                cohort,
                0,
                None,
                stage="selection_pending",
                scope="selected_ready_participation_checkpoints",
                error=participation_retry_details(error, stage="ready_inventory"),
            )
        excluded = frozenset() if selection is None else selection[1]
        selected = [] if selection is None else [key for key in pending if key not in excluded]
        historical = pending if selection is None else [key for key in pending if key in excluded]
        selected_done = 0 if selection is None else len(done - excluded)
        historical_done = len(done) - selected_done
        selected_total = None if selection is None else selected_done + len(selected)
        self._bind_cadence(cohort, selection, set(selected) | (done - excluded))
        historical_total = historical_done + len(historical)
        queue_total = len(done) + len(pending)
        selected_scope = "selected_ready_participation_checkpoints"
        historical_scope = (
            "unclassified_ready_receipt_checkpoints"
            if selection is None
            else "historical_ready_receipt_checkpoints"
        )
        errors = {"selected": None, "historical": None}
        skipped = 0

        def publish():
            historical_progress = self._progress(
                cohort,
                historical_done,
                historical_total,
                stage="historical_receipt_recovery",
                scope=historical_scope,
                error=errors["historical"],
            )
            historical_progress["excluded_without_receipt_this_poll"] = skipped
            if historical_done < historical_total:
                # Excluded queue entries may have no native receipt at all.
                # Completion timings cannot estimate that unresolved population.
                historical_progress.update(
                    eta_seconds=None,
                    planning_eta_seconds=None,
                    eta_basis=(
                        "blocked_or_retrying"
                        if errors["historical"]
                        else "prior_receipt_existence_unknown"
                    ),
                    eta_assumptions=(
                        "historical checkpoints include excluded requests without receipts"
                    ),
                )
            error = errors["selected"]
            if selection is None and error is None:
                error = {
                    "error_type": "owner_selection_unobserved",
                    "reason_code": "owner_selection_unobserved",
                    "error_stage": "selection",
                }
            return self._report(
                cohort,
                selected_done,
                selected_total,
                stage="selection_pending" if selection is None else "ready_reserved_participation",
                scope=selected_scope,
                error=error,
                queue_completed=len(done),
                queue_total=queue_total,
                historical_recovery=historical_progress,
            )

        publish()
        last_error = None
        recovered = 0
        split = bisect_right([key for key, _ in recoveries], self._completion_after.get(cohort, ""))
        recoveries = recoveries[split:] + recoveries[:split]
        for key, upload in recoveries[: self.batch_size]:
            self._completion_after[cohort] = key
            try:
                if phase is not None and phase != "intake":
                    continue
                await run_owned_thread(self._eligible, owner, upload, selection)
                signed = SignedDirectModelUploadCompletion.model_validate_json(
                    canonical_json_bytes(
                        await run_owned_thread(owner.journal.get, "direct-completion", key)
                    )
                )
                self._report(
                    cohort, recovered, len(recoveries), stage="completed_upload_receipt_recovery"
                )
                # Original complete() reconciles provider success before local
                # receipt, without re-uploading or reading model bytes.
                await owner.complete(signed, now_unix_ms=time.time_ns() // 1_000_000)
                recovered += 1
            except _UnselectedReservation:
                continue
            except (ValueError, OSError, RuntimeError, sqlite3.Error) as error:
                last_error = participation_retry_details(
                    error, stage="completed_upload_receipt_recovery"
                )
        if recoveries:
            recovery_report = self._report(
                cohort,
                recovered,
                len(recoveries),
                stage="completed_upload_receipt_recovery",
                error=last_error,
            )
            if not pending:
                return recovery_report
        for lane, upload in self._batch(cohort, selected, historical):
            self._after[(cohort, lane)] = upload
            started = time.monotonic()
            try:

                def guard(upload=upload):
                    if phase is not None and phase != "intake":
                        raise _UnselectedReservation("cohort intake has advanced")
                    self._eligible(owner, upload, selection)

                request = await run_owned_thread(self._request, owner, upload)
                receipt = await self.delivery.retain(
                    request, before_retain=guard, admission_lock=owner._mutex
                )
                await run_owned_thread(
                    owner.journal.put,
                    _DONE,
                    upload,
                    {
                        "schema": "umi-direct-participation-completed/1",
                        "upload_sha256": upload,
                        "model_sha256": request.signed_submission.submission.model_revision,
                        "record_sha256": receipt["record_sha256"],
                    },
                )
                done.add(upload)
                if lane == "selected":
                    selected_done += 1
                else:
                    historical_done += 1
                if lane == "historical":
                    samples = self._samples.setdefault((cohort, historical_scope), [])
                    samples.append(time.monotonic() - started)
                    del samples[:-32]
            except _UnselectedReservation:
                skipped += 1
            except (ValueError, OSError, RuntimeError, sqlite3.Error) as error:
                # No terminal hold: our verification, review, registration or
                # archival outage cannot disqualify a timely signed upload.
                errors[lane] = participation_retry_details(
                    error, stage="participation_continuation"
                )
            publish()
        self._observe_cadence(cohort, selected_done)
        return publish()
