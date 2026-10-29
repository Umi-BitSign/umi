"""One idempotent participation path for HTTP retries and retained consent."""

import asyncio
import re
import sqlite3
from contextlib import nullcontext
from functools import partial

from .competition_cohort_admission_queue import CohortAdmissionQueue
from .competition_cohort_intake import CohortAdmissionClosed
from .competition_cohort_intake_records import read_participation
from .competition_store import AdmissionCapacityError
from .concurrency import run_owned_thread
from .open_competition import digest


class ParticipationUnavailable(OSError):
    """The exact signed participation can resume after its owner is ready."""

    def __init__(self, message, *, stage):
        super().__init__(message)
        self.stage = stage
        self.reason_code = _UNAVAILABLE_REASONS[stage]


_UNAVAILABLE_REASONS = {
    "receipt_lookup": "participation_receipt_unavailable",
    "payload_prerequisite": "participation_payload_prerequisite_unavailable",
    "registration_capture": "participation_registration_unavailable",
    "native_retention": "participation_retention_unavailable",
    "evidence_preservation": "participation_evidence_unavailable",
}


def participation_retry_details(error, *, stage=None):
    """Expose bounded diagnostic identities, never exception text or arguments."""
    chain, seen = [], set()
    current = error
    while current is not None and id(current) not in seen and len(chain) < 8:
        chain.append(current)
        seen.add(id(current))
        current = current.__cause__

    def name(value):
        kind = type(value).__name__
        return kind if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", kind) else "Exception"

    repair = any(
        (isinstance(item, ValueError) and not isinstance(item, AdmissionCapacityError))
        or name(item).endswith("RepairRequired")
        for item in chain
    )
    wrapped = next((item for item in chain if isinstance(item, ParticipationUnavailable)), None)
    details = {
        "error_type": name(error),
        "cause_type": name(chain[-1]),
        "error_stage": stage if wrapped is None else wrapped.stage,
        "reason_code": (
            wrapped.reason_code
            if wrapped is not None
            else "retained_participation_metadata_repair_required"
            if repair
            else "reserved_participation_retrying"
        ),
        "repair_required": repair,
    }
    for item in chain:
        if not isinstance(item, sqlite3.Error):
            continue
        code, label = (
            getattr(item, "sqlite_errorcode", None),
            getattr(item, "sqlite_errorname", None),
        )
        if type(code) is int and 0 <= code <= 2**31 - 1:
            details["sqlite_errorcode"] = code
        if isinstance(label, str) and re.fullmatch(r"SQLITE_[A-Z0-9_]{1,64}", label):
            details["sqlite_errorname"] = label
        break
    return details


class ParticipationDelivery:
    def __init__(
        self, intake, capture, *, archive=None, models=None, capture_timeout_seconds=120, queue=None
    ):
        if (
            type(capture_timeout_seconds) not in (int, float)
            or not 1 <= capture_timeout_seconds <= 3600
        ):
            raise ValueError("cohort capture timeout must be between 1 and 3600 seconds")
        self.intake, self.capture = intake, capture
        self.archive, self.models = archive, models
        self.capture_timeout_seconds = capture_timeout_seconds
        self.queue = CohortAdmissionQueue(intake) if queue is None else queue

    async def retain(self, signed, *, before_retain=None, admission_lock=None):
        """Resume the original receipt/evidence before doing any new capture."""
        try:
            prior = await run_owned_thread(self.intake.receipt, signed)
        except (ValueError, OSError, sqlite3.Error) as error:
            raise ParticipationUnavailable(
                "retained cohort intake unavailable; retry unchanged", stage="receipt_lookup"
            ) from error
        newly_retained = False

        def retained():
            nonlocal newly_retained
            newly_retained = True

        if prior is None:
            if before_retain is not None:
                await run_owned_thread(before_retain)
            try:
                if self.models is not None:
                    await run_owned_thread(self.models.require_payload, signed)
            except (OSError, sqlite3.Error) as error:
                raise ParticipationUnavailable(
                    "cohort intake unavailable; retry unchanged", stage="payload_prerequisite"
                ) from error
            try:
                current = await asyncio.wait_for(
                    self.capture(), timeout=self.capture_timeout_seconds
                )
            except Exception as error:
                raise ParticipationUnavailable(
                    "registration observation unavailable; retry unchanged",
                    stage="registration_capture",
                ) from error
            try:
                # The direct owner supplies its issuance lock. Capture and
                # archive stay outside it; selection and native retention form
                # one admission boundary with concurrent replacement issuance.
                async with admission_lock if admission_lock is not None else nullcontext():
                    if before_retain is not None:
                        await run_owned_thread(before_retain)
                    prior = await run_owned_thread(
                        partial(
                            self.intake.retain,
                            signed,
                            current,
                            reservation_provider=getattr(
                                self.models, "admission_reservation", None
                            ),
                            on_retained=retained,
                        )
                    )
            except CohortAdmissionClosed:
                raise
            except (AdmissionCapacityError, OSError, sqlite3.Error) as error:
                raise ParticipationUnavailable(
                    "cohort intake unavailable; retry unchanged", stage="native_retention"
                ) from error
        already_preserved = await self._preserve(signed)
        if newly_retained and already_preserved:
            # Archives are shared across consents: a new participation can be
            # ready without inserting any additional evidence blob.
            self.intake.readiness_wakes.notify("admissions")
        return prior

    async def _preserve(self, signed):
        # Production supplies the archive. Rehearsal routers may omit it;
        # participation without its original proof remains pending certification.
        if self.archive is None:
            return False
        cohort = signed.consent.consent.cohort_sha256
        consent = digest(signed.consent.consent)
        try:
            try:
                await run_owned_thread(self.queue.evidence, cohort, consent)
            except FileNotFoundError:
                raw = await run_owned_thread(self.queue.record, cohort, consent)
                original = read_participation(raw).observation
                evidence, metadata = await self.archive(original)
                await run_owned_thread(
                    self.queue.attach_evidence, cohort, consent, evidence, metadata
                )
                # The new evidence commit already notified admission owners.
                return False
            return True
        except (ValueError, OSError, sqlite3.Error) as error:
            raise ParticipationUnavailable(
                "admission evidence unavailable; retry unchanged", stage="evidence_preservation"
            ) from error
