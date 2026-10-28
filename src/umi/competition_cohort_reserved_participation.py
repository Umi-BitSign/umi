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
    def __init__(self, owners, delivery, *, batch_size=2):
        if type(batch_size) is not int or not 1 <= batch_size <= 16:
            raise ValueError("reserved participation batch must be between 1 and 16")
        self.owners, self.delivery, self.batch_size = owners, delivery, batch_size
        self._after, self._started, self._samples = {}, {}, {}
        self._completed = {}
        self._completion_after = {}
        self._completion_inventory = {}
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
        done, pending = 0, []
        for upload in ready:
            if upload in reused:
                done += 1
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
                done += 1
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

    def _report(self, cohort, done, total, *, stage, error=None):
        pending = None if total is None else total - done
        samples = self._samples.get(cohort, []) if stage == "ready_reserved_participation" else []
        elapsed = time.monotonic() - self._started.setdefault(cohort, time.monotonic())
        eta = (
            0
            if pending == 0
            else pending * sum(samples) / len(samples)
            if samples and error is None
            else None
        )
        value = {
            "cohort_sha256": cohort,
            "stage": stage,
            "status": "retrying" if error else "completed" if pending == 0 else "running",
            "completed": done,
            "total": total,
            "percent": None if total is None else 100 * done / total if total else 100,
            "elapsed_seconds": round(elapsed, 3),
            "eta_seconds": None if eta is None else round(eta, 3),
            "planning_eta_seconds": (
                [1, pending * (self.delivery.capture_timeout_seconds + 30)]
                if pending and not samples and error is None
                else None
            ),
            "eta_basis": "blocked_or_retrying"
            if error
            else ("completed_requests_in_this_process" if samples else "planning_range"),
            "eta_scope": "ready_reserved_participation_only",
            "eta_assumptions": (
                "registration and original evidence available; "
                "excludes payload verification and certification"
            ),
            "eta_samples": len(samples),
            "stalled_or_retrying": error is not None,
            "error_type": error,
            "repair_required": error == "ValueError"
            or bool(error and error.endswith("RepairRequired")),
            "reason_code": (
                "retained_participation_metadata_repair_required"
                if error == "ValueError"
                else "reserved_participation_retrying"
                if error
                else None
            ),
            "unit": "ready_requests",
        }
        PUBLIC_COHORT_PROGRESS.record("reserved_participation", value)
        _LOG.info("reserved_model_participation %s", canonical_json_bytes(value).decode("ascii"))
        return value

    async def poll_once(self):
        # Rotate cohorts as well as requests; one provider outage cannot consume
        # every bounded batch. Successful requests persist their native receipt.
        cohorts = tuple(self.owners.owners)
        cohort = cohorts[self._cohort_next % len(cohorts)]
        self._cohort_next += 1
        owner = self.owners.owners[cohort]
        phase = None if self.owners.intake_phase is None else self.owners.intake_phase(cohort)
        try:
            fence, done, pending, recoveries = await run_owned_thread(self._inventory, owner)
        except (ValueError, OSError, RuntimeError, sqlite3.Error) as error:
            return self._report(
                cohort, 0, None, stage="selection_pending", error=type(error).__name__
            )
        total = done + len(pending)
        if fence is None and not total and not recoveries:
            return self._report(
                cohort, 0, None, stage="selection_pending", error="owner_selection_unobserved"
            )
        self._report(cohort, done, total, stage="ready_reserved_participation")
        split = bisect_right(pending, self._after.get(cohort, ""))
        pending = pending[split:] + pending[:split]
        last_error = None
        recovered = 0
        split = bisect_right([key for key, _ in recoveries], self._completion_after.get(cohort, ""))
        recoveries = recoveries[split:] + recoveries[:split]
        for key, upload in recoveries[: self.batch_size]:
            self._completion_after[cohort] = key
            try:
                if phase is not None and phase != "intake":
                    continue
                await run_owned_thread(self._eligible, owner, upload, fence)
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
                last_error = type(error).__name__
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
        for upload in pending[: self.batch_size]:
            self._after[cohort] = upload
            started = time.monotonic()
            try:

                def guard(upload=upload):
                    if phase is not None and phase != "intake":
                        raise _UnselectedReservation("cohort intake has advanced")
                    self._eligible(owner, upload, fence)

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
                done += 1
                samples = self._samples.setdefault(cohort, [])
                samples.append(time.monotonic() - started)
                del samples[:-32]
            except _UnselectedReservation:
                total -= 1
            except (ValueError, OSError, RuntimeError, sqlite3.Error) as error:
                # No terminal hold: our verification, review, registration or
                # archival outage cannot disqualify a timely signed upload.
                last_error = type(error).__name__
            self._report(
                cohort, done, total, stage="ready_reserved_participation", error=last_error
            )
        return self._report(
            cohort, done, total, stage="ready_reserved_participation", error=last_error
        )
