"""Durable global FIFO admission for precommitted service work.

Accepted claims and storage allowances survive lost replies and outages. This
owner component has no per-identity quota, attempt timer or dispatch authority.
The host must authenticate its phase/proof sources and serialize its lifecycle.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field

from .competition_chain import RegistrationCapture
from .competition_cohort_endpoint_archive import JournalEndpointObjects
from .competition_cohort_evaluation import RecoverableEvaluationRound
from .competition_cohort_intake import history_tip
from .competition_cohort_order_signer import (
    CohortOrderHistory,
    CohortOrderParticipant,
    remember_order_history,
)
from .competition_cohort_service_seal import (
    MAX_SERVICE_SEAL_BYTES,
    ServiceAcceptedWork,
    ServiceWorkSeal,
    sealed_service_assignments,
)
from .competition_cohort_service_work import (
    MAX_SERVICE_REQUEST_BYTES,
    ServiceWorkAdmission,
    ServiceWorkAssignment,
    ServiceWorkCatalog,
    SignedServiceWorkCatalog,
    SignedServiceWorkClaim,
    review_service_admission,
    review_service_catalog,
    service_claim_key,
    service_work_key,
    verify_service_claim,
)
from .competition_execution import execution_boundary
from .competition_round_journal import RecordReservation, RoundJournal
from .open_competition import CompetitionPolicy, SignedSubmission, digest
from .private_files import Directory
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

MAX_ADMISSION_BYTES = 2 * 1024**2


class ServiceQueueBackpressure(ValueError):
    """No claim was accepted. A duplicate accepted claim still recovers."""


class ServiceWorkQueueConfig(StrictProtocolModel):
    schema_: Literal["umi-cohort-service-work-queue-config/1"] = Field(alias="schema")
    directory: Directory
    policy_sha256: Hex32
    catalog_sha256: Hex32
    service_terms_sha256: Hex32
    maximum_claims: Annotated[int, Field(ge=1, le=8192)] = 1024
    maximum_bytes: Annotated[int, Field(ge=1024, le=16 * 1024**3)] = 1024**3


class ServiceWorkQueue:
    def __init__(self, config: ServiceWorkQueueConfig, policy: CompetitionPolicy):
        self.config = ServiceWorkQueueConfig.model_validate_json(canonical_json_bytes(config))
        self.policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
        if self.config.policy_sha256 != digest(self.policy):
            raise ValueError("service queue policy binding differs")
        self.journal = RoundJournal(
            Path(self.config.directory),
            self.config.model_dump(
                mode="json", by_alias=True, exclude={"maximum_claims", "maximum_bytes"}
            ),
            maximum_rounds=8192,
            maximum_bytes=self.config.maximum_bytes,
            maximum_record_bytes=MAX_SERVICE_REQUEST_BYTES,
        )
        with self.journal.transaction() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS order_heads "
                "(cohort TEXT PRIMARY KEY, history TEXT NOT NULL)"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS service_claims "
                "(ordinal INTEGER PRIMARY KEY, claim_key TEXT UNIQUE NOT NULL, "
                "admission TEXT UNIQUE NOT NULL)"
            )

    def _catalog(self, db=None):
        key = self.config.catalog_sha256
        raw = self.journal.get("service_catalog", key, db=db)
        if raw is None:
            raise FileNotFoundError("service catalog has not been installed")
        signed = SignedServiceWorkCatalog.model_validate_json(canonical_json_bytes(raw))
        if (
            digest(signed.catalog) != key
            or signed.catalog.service_terms_sha256 != self.config.service_terms_sha256
        ):
            raise ValueError("service catalog differs from the configured selection")
        if isinstance(signed.catalog, ServiceWorkCatalog):
            round_key = signed.catalog.round_sha256
        else:
            round_key = self.journal.get("service_catalog_round", key, db=db)
            if not isinstance(round_key, str):
                raise FileNotFoundError("service catalog lacks its original prepared round")
        round_ = RecoverableEvaluationRound.model_validate_json(
            canonical_json_bytes(self.journal.get("service_round", round_key, db=db))
        )
        if digest(round_) != round_key or round_.cohort_sha256 != signed.catalog.cohort_sha256:
            raise ValueError("service round changed its content identity")
        return signed, round_

    def install(
        self,
        signed: SignedServiceWorkCatalog,
        round_: RecoverableEvaluationRound,
        source: CohortOrderHistory,
        capture: RegistrationCapture,
        *,
        expected_tip_sha256: str,
    ) -> None:
        signed = SignedServiceWorkCatalog.model_validate_json(canonical_json_bytes(signed))
        body = signed.catalog
        if (
            digest(body) != self.config.catalog_sha256
            or body.service_terms_sha256 != self.config.service_terms_sha256
        ):
            raise ValueError("catalog is not explicitly selected by the queue configuration")
        with self.journal.locked():
            if self.journal.get("service_catalog", digest(body)) is not None:
                old, retained_round = self._catalog()
                if old.catalog != body or retained_round != round_:
                    raise ValueError("installed service inventory cannot be replaced")
                return
            boundary = execution_boundary(capture)
            review_service_catalog(
                signed,
                round_,
                self.policy,
                source,
                expected_tip_sha256=expected_tip_sha256,
                current_block=boundary.block,
            )
            remember_order_history(
                self.journal,
                {body.cohort_sha256: body.authority_sha256},
                self.policy,
                source,
                boundary.block,
            )
            self.journal.put_many(
                (
                    ("service_catalog", digest(body), signed),
                    ("service_round", digest(round_), round_),
                    *(
                        ()
                        if isinstance(body, ServiceWorkCatalog)
                        else (("service_catalog_round", digest(body), digest(round_)),)
                    ),
                )
            )

    def _raw_admission(self, ordinal, db):
        row = db.execute(
            "SELECT claim_key,admission FROM service_claims WHERE ordinal=?", (ordinal,)
        ).fetchone()
        if row is None:
            raise FileNotFoundError("accepted service claim index is incomplete")
        work = service_work_key(self._catalog(db)[0].catalog, ordinal)
        raw = self.journal.get("service_admission", work, db=db)
        if raw is None:
            raise FileNotFoundError("accepted service admission is missing")
        value = ServiceWorkAdmission.model_validate_json(canonical_json_bytes(raw))
        if (
            value.ordinal != ordinal
            or value.work_sha256 != work
            or digest(value) != row[1]
            or service_claim_key(value.claim.claim) != row[0]
        ):
            raise ValueError("service admission index differs from retained evidence")
        return value

    def _read(self, ordinal: int, db) -> ServiceWorkAdmission:
        value = self._raw_admission(ordinal, db)
        previous = None if ordinal == 1 else self._raw_admission(ordinal - 1, db)
        source = CohortOrderHistory.model_validate_json(
            canonical_json_bytes(self.journal.get("order_history", value.history_sha256, db=db))
        )
        if digest(source) != value.history_sha256:
            raise ValueError("service admission history changed its content identity")
        catalog, round_ = self._catalog(db)
        return review_service_admission(
            value, catalog, round_, source, self.policy, previous=previous
        )

    def lookup(self, signed: SignedServiceWorkClaim) -> ServiceWorkAdmission | None:
        signed = verify_service_claim(signed)
        key = service_claim_key(signed.claim)
        with self.journal.locked(), self.journal.transaction() as db:
            row = db.execute(
                "SELECT ordinal FROM service_claims WHERE claim_key=?", (key,)
            ).fetchone()
            if row is None:
                return None
            value = self._read(row[0], db)
            if value.claim.claim != signed.claim:
                raise ValueError("accepted claim nonce was reused with changed inputs")
            return value

    def admit(
        self,
        signed: SignedServiceWorkClaim,
        submission: SignedSubmission,
        participant: CohortOrderParticipant,
        source: CohortOrderHistory,
        capture: RegistrationCapture,
        *,
        expected_tip_sha256: str,
        index: Callable[[sqlite3.Connection, ServiceWorkAdmission], None] | None = None,
    ) -> ServiceWorkAdmission:
        """Commit new work and optional owner evidence in one bounded transaction.

        ``index(db, admission)`` runs only for a new claim, before the journal's
        final capacity check. It must use the supplied connection without
        committing or closing it. An exception rolls back the claim and evidence;
        duplicate recovery returns the original admission without this callback.
        """
        if index is not None and not callable(index):
            raise ValueError("service admission index must be callable")
        signed = verify_service_claim(signed)
        if signed.claim.catalog_sha256 != self.config.catalog_sha256:
            raise ValueError("service claim belongs to another catalog")
        claim_key = service_claim_key(signed.claim)
        with self.journal.locked():
            with self.journal.transaction() as db:
                row = db.execute(
                    "SELECT ordinal FROM service_claims WHERE claim_key=?", (claim_key,)
                ).fetchone()
                if row is not None:
                    value = self._read(row[0], db)
                    if (
                        value.claim.claim != signed.claim
                        or value.submission != submission
                        or value.participant != participant
                    ):
                        raise ValueError("accepted claim nonce was reused with changed inputs")
                    return value
                if self.journal.get("service_work_seal", self.config.catalog_sha256, db=db):
                    raise ServiceQueueBackpressure("service queue is sealed to new claims")
                count = db.execute("SELECT COUNT(*) FROM service_claims").fetchone()[0]
                previous = None if count == 0 else self._read(count, db)
            catalog, round_ = self._catalog()
            if count >= self.config.maximum_claims or count >= len(catalog.catalog.work):
                raise ServiceQueueBackpressure("service queue has no unreserved claim capacity")
            if history_tip(source.history) != expected_tip_sha256:
                raise ValueError("service admission has no current owned history tip")
            boundary = execution_boundary(capture)
            value = ServiceWorkAdmission(
                schema="umi-cohort-service-work-admission/1",
                catalog_sha256=self.config.catalog_sha256,
                claim=signed,
                ordinal=count + 1,
                predecessor_sha256=None if previous is None else digest(previous),
                work_sha256=service_work_key(catalog.catalog, count + 1),
                submission=submission,
                participant=participant,
                history_sha256=digest(source),
                registration=capture.snapshot,
                observation=boundary,
            )
            if len(canonical_json_bytes(value)) > MAX_ADMISSION_BYTES:
                raise ValueError("service admission exceeds its retained byte bound")
            review_service_admission(value, catalog, round_, source, self.policy, previous=previous)
            body = catalog.catalog
            remember_order_history(
                self.journal,
                {body.cohort_sha256: body.authority_sha256},
                self.policy,
                source,
                boundary.block,
            )
            # Reserve by the next work slot, not by an unaccepted nonce. A crash
            # before admission lets the next valid claim reuse the same allowance.
            self._reserve_seal()
            self.journal.reserve_records(
                value.work_sha256,
                (RecordReservation("service_admission", value.work_sha256, MAX_ADMISSION_BYTES),),
            )

            def publish(db):
                db.execute(
                    "INSERT INTO service_claims VALUES (?,?,?)",
                    (value.ordinal, claim_key, digest(value)),
                )
                if index is not None:
                    index(db, value)

            self.journal.put_many((("service_admission", value.work_sha256, value),), index=publish)
            return value

    def entries(
        self, *, after_ordinal: int = 0, limit: int = 64
    ) -> tuple[ServiceWorkAdmission, ...]:
        if (
            type(after_ordinal) is not int
            or not 0 <= after_ordinal <= 8192
            or type(limit) is not int
            or not 1 <= limit <= 256
        ):
            raise ValueError("invalid service queue page")
        with self.journal.locked(), self.journal.transaction() as db:
            rows = db.execute(
                "SELECT ordinal FROM service_claims WHERE ordinal>? ORDER BY ordinal LIMIT ?",
                (after_ordinal, limit),
            ).fetchall()
            return tuple(self._read(row[0], db) for row in rows)

    def assignment(self, signed: SignedServiceWorkClaim) -> ServiceWorkAssignment:
        """Export the exact accepted record; never invent a benchmark assignment."""
        signed = verify_service_claim(signed)
        with self.journal.locked(), self.journal.transaction() as db:
            row = db.execute(
                "SELECT ordinal FROM service_claims WHERE claim_key=?",
                (service_claim_key(signed.claim),),
            ).fetchone()
            if row is None:
                raise FileNotFoundError("service claim has not been admitted")
            value = self._read(row[0], db)
            if value.claim.claim != signed.claim:
                raise ValueError("accepted claim nonce was reused with changed inputs")
            return self._assignment(value, db)

    def _assignment(self, value, db):
        catalog, round_ = self._catalog(db)
        return ServiceWorkAssignment(
            catalog=catalog,
            round=round_,
            admission=value,
            previous=None if value.ordinal == 1 else self._raw_admission(value.ordinal - 1, db),
            source=CohortOrderHistory.model_validate_json(
                canonical_json_bytes(self.journal.get("order_history", value.history_sha256, db=db))
            ),
        )

    def _reserve_seal(self):
        key = self.config.catalog_sha256
        self.journal.reserve_records(
            digest(["umi-service-seal-reservation/1", key]),
            (RecordReservation("service_work_seal", key, MAX_SERVICE_SEAL_BYTES),),
        )

    def retained_seal(self) -> ServiceWorkSeal | None:
        """Read the owner's complete immutable fence without closing admissions."""
        with self.journal.locked():
            return self._retained_seal()

    def _retained_seal(self) -> ServiceWorkSeal | None:
        old = self.journal.get("service_work_seal", self.config.catalog_sha256)
        if old is None:
            return None
        catalog, round_ = self._catalog()
        value = ServiceWorkSeal.model_validate_json(canonical_json_bytes(old))
        assignments = tuple(
            sealed_service_assignments(
                value,
                JournalEndpointObjects(self.journal),
                self.policy,
                catalog=catalog,
                round_=round_,
            )
        )
        with self.journal.transaction() as db:
            rows = db.execute("SELECT ordinal FROM service_claims ORDER BY ordinal").fetchall()
            if tuple(r[0] for r in rows) != tuple(range(1, len(assignments) + 1)):
                raise ValueError("service seal differs from the owner's accepted prefix")
            for row, assignment in zip(rows, assignments, strict=True):
                if self._assignment(self._read(row[0], db), db) != assignment:
                    raise ValueError("service seal changed an original accepted assignment")
        return value

    def seal(self, source, capture, *, expected_tip_sha256: str) -> ServiceWorkSeal:
        """Close new admissions atomically; accepted work and duplicate claims survive.

        The host authenticates the current proof/history and later exports the
        seal with quorum request closure. Sealing does not finish pending work.
        """
        key = self.config.catalog_sha256
        objects = JournalEndpointObjects(self.journal)
        with self.journal.locked():
            catalog, round_ = self._catalog()
            old = self._retained_seal()
            if old is not None:
                return old
            boundary = execution_boundary(capture)
            review_service_catalog(
                catalog,
                round_,
                self.policy,
                source,
                expected_tip_sha256=expected_tip_sha256,
                current_block=boundary.block,
            )
            self._reserve_seal()
            remember_order_history(
                self.journal,
                {catalog.catalog.cohort_sha256: catalog.catalog.authority_sha256},
                self.policy,
                source,
                boundary.block,
            )
            # Hold the lifecycle lock through export and the final immutable
            # seal. Partial exports are harmless; no acceptance can interleave.
            with self.journal.transaction() as db:
                rows = db.execute("SELECT ordinal FROM service_claims ORDER BY ordinal").fetchall()
                if tuple(r[0] for r in rows) != tuple(range(1, len(rows) + 1)):
                    raise ValueError("service accepted prefix has a missing ordinal")
            accepted = []
            for row in rows:
                with self.journal.transaction() as db:
                    assignment = self._assignment(self._read(row[0], db), db)
                accepted.append(
                    ServiceAcceptedWork(
                        work_sha256=assignment.admission.work_sha256,
                        assignment_sha256=objects.put(assignment),
                    )
                )
            value = ServiceWorkSeal(
                schema="umi-cohort-service-work-seal/1",
                catalog_sha256=key,
                source_sha256=objects.put(source),
                observation=boundary,
                accepted=tuple(accepted),
            )
            for _ in sealed_service_assignments(
                value, objects, self.policy, catalog=catalog, round_=round_
            ):
                pass
            self.journal.put("service_work_seal", key, value)
            return value
