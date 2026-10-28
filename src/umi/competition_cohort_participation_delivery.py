"""One idempotent participation path for HTTP retries and retained consent."""

import asyncio
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
                "retained cohort intake unavailable; retry unchanged"
            ) from error
        if prior is None:
            if before_retain is not None:
                await run_owned_thread(before_retain)
            try:
                if self.models is not None:
                    await run_owned_thread(self.models.require_payload, signed)
            except (OSError, sqlite3.Error) as error:
                raise ParticipationUnavailable(
                    "cohort intake unavailable; retry unchanged"
                ) from error
            try:
                current = await asyncio.wait_for(
                    self.capture(), timeout=self.capture_timeout_seconds
                )
            except Exception as error:
                raise ParticipationUnavailable(
                    "registration observation unavailable; retry unchanged"
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
                        )
                    )
            except CohortAdmissionClosed:
                raise
            except (AdmissionCapacityError, OSError, sqlite3.Error) as error:
                raise ParticipationUnavailable(
                    "cohort intake unavailable; retry unchanged"
                ) from error
        await self._preserve(signed)
        return prior

    async def _preserve(self, signed):
        # Production supplies the archive. Rehearsal routers may omit it;
        # participation without its original proof remains pending certification.
        if self.archive is None:
            return
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
        except (ValueError, OSError, sqlite3.Error) as error:
            raise ParticipationUnavailable(
                "admission evidence unavailable; retry unchanged"
            ) from error
