"""Public service claims backed by the native owner queue.

The host supplies selected queues, current owned history, a finalized capture
provider, original registration archives and an owned verified roster port.
``prepared_service_roster`` adapts CohortPreparation without preparing a new round.
Production supplies its intake owner to serialize publication with admission and
must fence old writers before migrating state.
These routes neither authenticate finality themselves nor authorize service credit.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import sqlite3
from collections.abc import Awaitable, Callable, Mapping
from functools import partial

from fastapi import APIRouter, HTTPException, Query, Request, Response

from .competition_chain import RegistrationCapture
from .competition_cohort_intake import CohortIntake, history_tip
from .competition_cohort_order_signer import (
    CohortOrderHistory,
    CohortOrderParticipant,
    remember_order_history,
)
from .competition_cohort_preparation_owner import CohortPreparation
from .competition_cohort_roster import RecoverableRosterEvidence
from .competition_cohort_service_queue import MAX_ADMISSION_BYTES, ServiceWorkQueue
from .competition_cohort_service_seal import MAX_SERVICE_SEAL_BYTES
from .competition_cohort_service_work import (
    MAX_CLAIM_BYTES,
    ServiceWorkAdmission,
    SignedServiceWorkClaim,
    review_service_catalog,
    service_claim_key,
    verify_service_claim,
)
from .competition_execution import ExecutionBoundary, execution_boundary
from .competition_registration_archive import (
    MAX_ARCHIVE_BYTES,
    MAX_METADATA_BYTES,
    RegistrationArchive,
)
from .concurrency import run_owned_thread, wait_for_owned
from .open_competition import digest, identity
from .protocol import canonical_json_bytes

PATH = "/v1/competition/service-work"
ServiceRoster = Callable[
    [str, CohortOrderHistory, RegistrationCapture], Awaitable[RecoverableRosterEvidence]
]
_UNAVAILABLE = (ValueError, OSError, RuntimeError, sqlite3.Error, asyncio.TimeoutError)


def prepared_service_roster(preparation: CohortPreparation) -> ServiceRoster:
    """Read and replay the original native preparation, including sealed membership."""

    async def retained(cohort, source, capture):
        value = await run_owned_thread(
            partial(
                preparation.retained,
                cohort,
                expected_tip_sha256=history_tip(source.history),
                current_block=execution_boundary(capture).block,
            )
        )
        return value.roster

    return retained


def _check_archive(snapshot, observation, raw, metadata):
    archive = RegistrationArchive(raw, metadata)
    if (
        archive.snapshot != snapshot
        or archive.evidence_sha256 != observation.evidence_sha256
        or archive.roots != {observation.state_root}
    ):
        raise ValueError("service archive differs from original owned registration")


class ServiceAdmissionArchive:
    """Private original proof bytes, charged to the queue's native journal capacity.

    Archive parsing binds bytes to an owned observation; independent proof replay
    remains the historical registration provider/reviewer's responsibility.
    """

    def __init__(self, queue: ServiceWorkQueue):
        self.queue, self.journal = queue, queue.journal
        with self.journal.locked(), self.journal.transaction() as db:
            self.journal._enable_reservations(db)
            db.execute(
                "CREATE TABLE IF NOT EXISTS service_admission_artifacts "
                "(digest TEXT PRIMARY KEY, body BLOB NOT NULL)"
            )

    @staticmethod
    def _read(db, key, maximum):
        row = db.execute(
            "SELECT substr(body,1,?) FROM service_admission_artifacts WHERE digest=?",
            (maximum + 1, key),
        ).fetchone()
        if row is None:
            raise FileNotFoundError("original service registration archive is pending")
        raw = row[0]
        if (
            type(raw) is not bytes
            or not 0 < len(raw) <= maximum
            or hashlib.sha256(raw).hexdigest() != key
        ):
            raise ValueError("retained service registration archive changed")
        return raw

    def read(self, admission: ServiceWorkAdmission) -> tuple[bytes, bytes]:
        with self.journal.locked(), self.journal.transaction() as db:
            raw = self._read(db, admission.observation.evidence_sha256, MAX_ARCHIVE_BYTES)
            metadata = self._read(
                db, json.loads(raw)["runtime_metadata_sha256"], MAX_METADATA_BYTES
            )
            _check_archive(admission.registration, admission.observation, raw, metadata)
            return raw, metadata

    def attach(
        self,
        admission: ServiceWorkAdmission,
        raw: bytes,
        metadata: bytes,
        *,
        db: sqlite3.Connection | None = None,
    ) -> None:
        """Join a new admission transaction, or repair an older missing archive."""
        _check_archive(admission.registration, admission.observation, raw, metadata)

        def index(connection):
            for value in (raw, metadata):
                key = hashlib.sha256(value).hexdigest()
                old = connection.execute(
                    "SELECT substr(body,1,?) FROM service_admission_artifacts WHERE digest=?",
                    (len(value) + 1, key),
                ).fetchone()
                if old is not None and old[0] != value:
                    raise ValueError("retained service registration archive changed")
                connection.execute(
                    "INSERT OR IGNORE INTO service_admission_artifacts VALUES (?,?)", (key, value)
                )

        if db is not None:
            index(db)
            return
        with self.journal.locked():
            # put_many charges auxiliary BLOB tables and commits both artifacts
            # together. Queue records and accepted obligations are never removed.
            self.journal.put_many((), index=index)


class ServiceWorkAdmissionAPI:
    def __init__(
        self,
        queues: Mapping[str, ServiceWorkQueue],
        capture: Callable[[], Awaitable[RegistrationCapture]],
        history: Callable[[str], Awaitable[CohortOrderHistory]],
        roster: ServiceRoster,
        archive: Callable[[ExecutionBoundary], Awaitable[tuple[bytes, bytes]]],
        *,
        intake: CohortIntake | None = None,
        timeout_seconds: float = 2400,
    ):
        if (
            not queues
            or any(key != queue.config.catalog_sha256 for key, queue in queues.items())
            or len({digest(queue.policy) for queue in queues.values()}) != 1
        ):
            raise ValueError("service API requires explicit catalog selectors and one policy")
        if type(timeout_seconds) not in (int, float) or not 1 <= timeout_seconds <= 3600:
            raise ValueError("service API timeout must be between 1 and 3600 seconds")
        if not all(callable(port) for port in (capture, history, roster, archive)):
            raise ValueError("service API requires all owned admission ports")
        if intake is not None and any(intake.policy != q.policy for q in queues.values()):
            raise ValueError("service API intake owner belongs to another policy")
        self.queues = dict(queues)
        self.intake = intake
        self.capture, self.history, self.roster, self.archive = capture, history, roster, archive
        self.timeout = timeout_seconds
        self.archives = {key: ServiceAdmissionArchive(q) for key, q in self.queues.items()}
        self.serial = {key: asyncio.Lock() for key in self.queues}

    def selected(self, catalog: str) -> ServiceWorkQueue:
        if catalog not in self.queues:
            raise HTTPException(404, "selected service catalog not found")
        return self.queues[catalog]

    async def _call(self, awaitable):
        return await wait_for_owned(awaitable, timeout=self.timeout)

    @staticmethod
    def _remember(queue, source, capture):
        with queue.journal.locked():
            catalog, _ = queue._catalog()
            body = catalog.catalog
            # Retain closure/revocation before refusing new claims. A subsequent
            # stale history response must not reopen the queue.
            remember_order_history(
                queue.journal,
                {body.cohort_sha256: body.authority_sha256},
                queue.policy,
                source,
                execution_boundary(capture).block,
            )

    async def _current(self, queue):
        catalog, round_ = await run_owned_thread(queue._catalog)
        cohort = catalog.catalog.cohort_sha256
        source = await self._call(self.history(cohort))
        capture = await self._call(self.capture())
        await run_owned_thread(self._remember, queue, source, capture)
        await run_owned_thread(
            partial(
                review_service_catalog,
                catalog,
                round_,
                queue.policy,
                source,
                expected_tip_sha256=history_tip(source.history),
                current_block=execution_boundary(capture).block,
            )
        )
        supplied_roster = await self._call(self.roster(cohort, source, capture))
        roster = await run_owned_thread(self._check_roster, supplied_roster, round_)
        return catalog, source, capture, roster

    @staticmethod
    def _check_roster(value, round_):
        # Large retained rosters must not block the listener while they are
        # serialized and revalidated. Keep the complete original checks in the
        # owned operation, including cancellation drain before releasing serial.
        roster = RecoverableRosterEvidence.model_validate_json(canonical_json_bytes(value))
        if roster.round != round_ or tuple(
            (digest(p.record.request.signed_submission.submission), digest(p.admission.admission))
            for p in roster.participants
        ) != tuple((p.submission_sha256, p.admission_sha256) for p in round_.participants):
            raise ValueError("owned roster differs from the original prepared round")
        return roster

    async def _unchanged(self, queue, source):
        latest = await self._call(self.history(digest(source.history.plan)))
        if latest != source:
            current = await self._call(self.capture())
            await run_owned_thread(self._remember, queue, latest, current)
            raise OSError("service history changed during admission; retry current history")

    def _commit(self, queue, signed, submission, participant, source, capture, raw, metadata):
        def index(db, admission):
            self.archives[queue.config.catalog_sha256].attach(admission, raw, metadata, db=db)

        admit = partial(
            queue.admit,
            signed,
            submission,
            participant,
            source,
            capture,
            expected_tip_sha256=history_tip(source.history),
            index=index,
        )
        if self.intake is None:
            # In-process fixtures or a host with equivalent external ownership.
            return admit()
        with self.intake._connection() as (_, store):
            if store.published_history(digest(source.history.plan)) != source.history:
                raise OSError("intake published history changed before service admission")
            return admit()

    async def admit(self, catalog: str, signed: SignedServiceWorkClaim):
        queue = self.selected(catalog)
        async with self.serial[catalog]:
            # Recovery must precede every live history, preparation and capture call.
            admission = await run_owned_thread(queue.lookup, signed)
            if admission is None:
                _, source, capture, roster = await self._current(queue)
                member = next(
                    (
                        p
                        for p in roster.participants
                        if digest(p.record.request.signed_submission.submission)
                        == signed.claim.submission_sha256
                        and identity(p.record.request.signed_submission.submission.hotkey)
                        == identity(signed.claim.hotkey)
                    ),
                    None,
                )
                if member is None:
                    raise HTTPException(409, "claim is outside the original prepared roster")
                participant = CohortOrderParticipant(
                    consent=member.record.request.consent,
                    admission=member.admission,
                    admission_snapshot=member.record.snapshot,
                )
                boundary = execution_boundary(capture)
                raw, metadata = await self._call(self.archive(boundary))
                await run_owned_thread(_check_archive, capture.snapshot, boundary, raw, metadata)
                await self._unchanged(queue, source)
                admission = await run_owned_thread(
                    self._commit,
                    queue,
                    signed,
                    member.record.request.signed_submission,
                    participant,
                    source,
                    capture,
                    raw,
                    metadata,
                )
            retained = self.archives[catalog]
            try:
                await run_owned_thread(retained.read, admission)
            except FileNotFoundError:
                raw, metadata = await self._call(self.archive(admission.observation))
                await run_owned_thread(retained.attach, admission, raw, metadata)
            return {
                "schema": "umi-public-service-work-admission/1",
                "status": "accepted",
                "catalog_sha256": catalog,
                "claim_sha256": service_claim_key(admission.claim.claim),
                "admission_sha256": digest(admission),
                "work_sha256": admission.work_sha256,
                "ordinal": admission.ordinal,
                "service_credit_authorized": False,
                "chain_submission_authorized": False,
            }

    @staticmethod
    def _capacity(queue, archive_bytes=0):
        with queue.journal.locked(), queue.journal.transaction() as db:
            catalog, _ = queue._catalog(db)
            count = db.execute("SELECT COUNT(*) FROM service_claims").fetchone()[0]
            _, used, _ = queue.journal._capacity(db)
            seal_reserved = queue.journal._obligation(
                db, "service_work_seal", queue.config.catalog_sha256
            )
            needed = (
                MAX_ADMISSION_BYTES
                + (0 if seal_reserved else MAX_SERVICE_SEAL_BYTES)
                + archive_bytes
            )
            remaining = max(0, min(len(catalog.catalog.work), queue.config.maximum_claims) - count)
            sealed = queue.journal.get("service_work_seal", queue.config.catalog_sha256, db=db)
            reason = (
                "sealed"
                if sealed is not None
                else "capacity_exhausted"
                if not remaining or queue.journal.maximum_bytes - used <= needed
                else "accepting"
            )
            return reason, remaining

    async def readiness(self, catalog: str, nonce: str):
        queue = self.selected(catalog)
        result = {
            "schema": "umi-public-service-work-readiness/1",
            "catalog_sha256": catalog,
            "nonce": nonce,
            "ready": False,
            "reason_code": "owner_inputs_unavailable",
            "service_credit_authorized": False,
            "chain_submission_authorized": False,
        }
        async with self.serial[catalog]:
            try:
                result["reason_code"] = "queue_unavailable"
                reason, remaining = await run_owned_thread(self._capacity, queue)
                result.update(reason_code=reason, remaining_claims=remaining)
                if reason != "accepting":
                    return result
                result["reason_code"] = "owner_inputs_unavailable"
                _, source, capture, _ = await self._current(queue)
                result["reason_code"] = "archive_unavailable"
                boundary = execution_boundary(capture)
                raw, metadata = await self._call(self.archive(boundary))
                await run_owned_thread(_check_archive, capture.snapshot, boundary, raw, metadata)
                result["reason_code"] = "owner_inputs_unavailable"
                await self._unchanged(queue, source)
                reason, remaining = await run_owned_thread(
                    self._capacity, queue, len(raw) + len(metadata) + 128
                )
                result.update(reason_code=reason, remaining_claims=remaining)
                if reason != "accepting":
                    return result
                result.update(
                    ready=True,
                    reason_code="accepting",
                    recovery_tip_sha256=history_tip(source.history),
                    observed_at_block=boundary.block,
                )
            except FileNotFoundError:
                if result["reason_code"] == "queue_unavailable":
                    result["reason_code"] = "catalog_pending"
            except _UNAVAILABLE:
                pass
        return result


def service_admission_routes(api: ServiceWorkAdmissionAPI) -> APIRouter:
    router = APIRouter()

    @router.get(PATH)
    async def catalogs(response: Response):
        response.headers["Cache-Control"] = "no-store"
        entries = []
        try:
            for key, queue in sorted(api.queues.items()):
                entry = {
                    "catalog_sha256": key,
                    "claims_url": f"{PATH}/{key}/claims",
                    "readiness_url": f"{PATH}/{key}/readiness",
                }
                try:
                    signed, round_ = await run_owned_thread(queue._catalog)
                except FileNotFoundError:
                    entries.append({**entry, "status": "pending_installation"})
                    continue
                body = signed.catalog
                entries.append(
                    {
                        **entry,
                        "status": "installed",
                        "policy_sha256": body.policy_sha256,
                        "cohort_sha256": body.cohort_sha256,
                        "authority_sha256": body.authority_sha256,
                        "round_sha256": digest(round_),
                        "service_terms_sha256": body.service_terms_sha256,
                        "work_items": len(body.work),
                        "selection_rule": body.selection_rule,
                        "credit_rule": body.credit_rule,
                    }
                )
        except _UNAVAILABLE as error:
            raise HTTPException(503, "selected service catalogs unavailable") from error
        return {"schema": "umi-public-service-work-catalogs/1", "catalogs": entries}

    @router.get(PATH + "/{catalog}/readiness")
    async def readiness(
        catalog: str, response: Response, nonce: str = Query(pattern=r"^[0-9a-f]{32}$")
    ):
        response.headers["Cache-Control"] = "no-store"
        return await api.readiness(catalog, nonce)

    @router.post(PATH + "/{catalog}/claims")
    async def claim(catalog: str, request: Request, response: Response):
        api.selected(catalog)
        response.headers["Cache-Control"] = "no-store"
        if request.headers.get("content-type", "").split(";", 1)[0].strip() != "application/json":
            raise HTTPException(415, "application/json required")

        async def body():
            value = bytearray()
            async for part in request.stream():
                if len(value) + len(part) > MAX_CLAIM_BYTES:
                    raise HTTPException(413, "service claim request too large")
                value.extend(part)
            return bytes(value)

        try:
            signed = SignedServiceWorkClaim.model_validate_json(
                await wait_for_owned(body(), timeout=10)
            )
            signed = await run_owned_thread(verify_service_claim, signed)
        except asyncio.TimeoutError as error:
            raise HTTPException(408, "request body timed out; retry unchanged") from error
        except ValueError as error:
            raise HTTPException(422, "invalid signed service claim") from error
        if signed.claim.catalog_sha256 != catalog:
            raise HTTPException(409, "claim belongs to another selected catalog")
        try:
            return await api.admit(catalog, signed)
        except _UNAVAILABLE as error:
            raise HTTPException(503, "service admission unavailable; retry unchanged") from error

    return router
