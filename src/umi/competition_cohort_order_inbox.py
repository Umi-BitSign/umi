"""Evaluator-owned durable assignment receipt; execution is a separate operation."""

from __future__ import annotations

import asyncio
import sqlite3
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Literal

from pydantic import Field

from .canonical_reuse import canonical_json_reuse
from .competition_assignment_reuse import AssignmentVerificationReuse, assignment_reuse_key
from .competition_cohort_execution_journal import CohortExecutionAssignment
from .competition_cohort_order_queue import (
    SignedOrderDeliveryReceipt,
    check_delivery_receipt,
    delivery_receipt,
)
from .competition_cohort_order_signer import (
    CohortOrderHistory,
    CohortOrderIntent,
    CohortOrderParticipant,
    CohortOrderSignerConfig,
    OrderFinality,
    order_slot,
    remember_order_history,
    review_order,
)
from .competition_cohort_orders import MAX_ORDER_BYTES, SignedRecoverableEvaluationOrder
from .competition_cohort_recovery import verify_recovery_quorum
from .competition_execution import execution_boundary
from .competition_round_journal import RecordReservation, RoundJournal
from .concurrency import run_owned_thread, wait_for_owned
from .open_competition import CompetitionPolicy, Signature, digest, identity
from .protocol import canonical_json_bytes


class CohortOrderInboxConfig(CohortOrderSignerConfig):
    schema_: Literal["umi-cohort-order-inbox-config/1"] = Field(alias="schema")


class CohortOrderInbox:
    def __init__(
        self,
        config: CohortOrderInboxConfig,
        policy: CompetitionPolicy,
        provider: OrderFinality,
        history: Callable[[str], Awaitable[CohortOrderHistory]],
        sign: Callable[[object], Awaitable[Signature]],
    ):
        self.config = CohortOrderInboxConfig.model_validate_json(canonical_json_bytes(config))
        self.policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
        if (
            self.config.policy_sha256 != digest(self.policy)
            or provider.policy != self.policy
            or identity(self.config.signer) not in {identity(e.hotkey) for e in policy.evaluators}
        ):
            raise ValueError("order inbox policy, recipient or finality binding differs")
        self.provider, self.history, self.sign = provider, history, sign
        self.cohorts = {c.cohort_sha256: c.authority_sha256 for c in self.config.cohorts}
        self.serial = asyncio.Lock()
        self._assignment_reuse = AssignmentVerificationReuse(purpose="order_inbox")
        self.journal = RoundJournal(
            Path(self.config.directory),
            self.config.model_dump(
                mode="json",
                by_alias=True,
                exclude={"maximum_votes", "maximum_bytes", "signing_timeout_seconds"},
            ),
            maximum_rounds=self.config.maximum_votes,
            maximum_bytes=self.config.maximum_bytes,
            maximum_record_bytes=MAX_ORDER_BYTES,
        )
        with self.journal.transaction() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS order_heads "
                "(cohort TEXT PRIMARY KEY, history TEXT NOT NULL)"
            )

    def _load(self, slot: str, *, db: sqlite3.Connection | None = None, records=None):
        raw = self.journal.get_raw("intent", slot, db=db) if records is None else records[0]
        if raw is None:
            return None
        intent = CohortOrderIntent.model_validate_json(raw)
        raw_certificate = (
            self.journal.get_raw("certificate", slot, db=db) if records is None else records[1]
        )
        certificate = SignedRecoverableEvaluationOrder.model_validate_json(
            b"null" if raw_certificate is None else raw_certificate
        )
        if (
            order_slot(intent.order) != slot
            or certificate.order != intent.order
            or self.cohorts.get(intent.order.round.cohort_sha256)
            != digest(intent.source.history.authority.authority)
        ):
            raise ValueError("retained inbox assignment changed")
        self._check_certificate(certificate)
        review_order(
            intent.order, intent.participant, intent.source, self.policy, intent.observation.block
        )
        return intent, certificate

    def assignment(self, slot: str) -> CohortExecutionAssignment:
        """Export only a durably acknowledged assignment, without signing."""
        # An accepting writer may hold its compound-operation mutex across
        # network calls. Acknowledged work needs only a consistent SQLite
        # snapshot of its immutable inputs, with fresh conflict checks. Static
        # proofs may be reused only for those exact bytes and owner bindings.
        with canonical_json_reuse():
            with self.journal.read_transaction() as db:
                records = tuple(
                    self.journal.get_raw(kind, slot, db=db)
                    for kind in ("intent", "certificate", "receipt")
                )
            key = None
            if all(raw is not None for raw in records):
                key = assignment_reuse_key(
                    self.journal, slot, records, self.config, self.policy, self.cohorts
                )

            def calculate():
                saved = self._load(slot, records=records)
                if saved is None:
                    raise FileNotFoundError("inbox assignment is unavailable")
                raw = records[2]
                if raw is None:
                    raise FileNotFoundError("inbox assignment acknowledgement is pending")
                receipt = check_delivery_receipt(
                    saved[1], SignedOrderDeliveryReceipt.model_validate_json(raw)
                )
                if identity(receipt.receipt.evaluator_hotkey) != identity(self.config.signer):
                    raise ValueError("inbox acknowledgement belongs to another evaluator")
                return CohortExecutionAssignment(
                    certificate=saved[1], participant=saved[0].participant, delivery=receipt
                )

            return (
                calculate() if key is None else self._assignment_reuse.resolve(slot, key, calculate)
            )

    def assignments(self, *, after: str = "", limit: int = 16) -> tuple[str, ...]:
        if type(limit) is not int or not 1 <= limit <= 256:
            raise ValueError("invalid inbox execution page size")
        with self.journal.transaction() as db:
            return tuple(
                row[0]
                for row in db.execute(
                    "SELECT i.id FROM records i JOIN records r ON i.id=r.id "
                    "WHERE i.kind='intent' AND r.kind='receipt' AND i.id>? ORDER BY i.id LIMIT ?",
                    (after, limit),
                )
            )

    def assignments_for_models(
        self, revisions: tuple[str, ...], *, limit: int, preferred=()
    ) -> tuple[str, ...]:
        """Bounded startup hints, never an assignment or execution authorization.

        Read only the compact retained certificate, not the intent's historical
        proof payload. The ordinary assignment reader still authenticates each
        selected item. No persisted input or fair cursor is changed.
        """
        if (
            type(limit) is not int
            or not 1 <= limit <= 32
            or len(revisions) > 32
            or len(preferred) > 32
            or any(
                len(value) != 64 or any(c not in "0123456789abcdef" for c in value)
                for value in (*revisions, *preferred)
            )
        ):
            raise ValueError("invalid resident model scheduling hints")
        if not revisions:
            return ()
        placeholders = ",".join("?" for _ in revisions)
        priority = (
            ("CASE WHEN c.id IN (" + ",".join("?" for _ in preferred) + ") THEN 0 ELSE 1 END,")
            if preferred
            else ""
        )
        with self.journal.read_transaction() as db:
            return tuple(
                row[0]
                for row in db.execute(
                    "SELECT c.id FROM records c JOIN records r ON c.id=r.id "
                    "WHERE c.kind='certificate' AND r.kind='receipt' AND "
                    "json_extract(CAST(c.body AS TEXT),"
                    "'$.order.submission.submission.model_revision') IN (" + placeholders + ") "
                    "ORDER BY " + priority + "c.id LIMIT ?",
                    (*revisions, *preferred, limit),
                )
            )

    def _check_certificate(self, certificate):
        delivery_receipt(certificate, self.config.signer)
        miner = identity(certificate.order.submission.submission.hotkey)
        if any(identity(s.hotkey) == miner for s in certificate.signatures):
            raise ValueError("miner cannot sign its own assignment")
        verify_recovery_quorum(certificate.order, certificate.signatures, self.policy)

    async def _acknowledge(self, slot, certificate):
        raw = await run_owned_thread(self.journal.get, "receipt", slot)
        if raw is not None:
            receipt = check_delivery_receipt(
                certificate,
                SignedOrderDeliveryReceipt.model_validate_json(canonical_json_bytes(raw)),
            )
            if identity(receipt.receipt.evaluator_hotkey) != identity(self.config.signer):
                raise ValueError("retained inbox receipt belongs to another recipient")
            return receipt
        body = delivery_receipt(certificate, self.config.signer)

        async def sign_and_commit():
            receipt = SignedOrderDeliveryReceipt(receipt=body, signature=await self.sign(body))
            check_delivery_receipt(certificate, receipt)
            await run_owned_thread(self.journal.put, "receipt", slot, receipt)
            return receipt

        return await wait_for_owned(sign_and_commit(), timeout=self.config.signing_timeout_seconds)

    async def lookup(self, slot: str) -> SignedOrderDeliveryReceipt | None:
        # Acknowledging an already retained assignment never authorizes execution.
        async with self.serial:
            with self.journal.locked():
                saved = await run_owned_thread(self._load, slot)
                return None if saved is None else await self._acknowledge(slot, saved[1])

    async def accept(
        self, certificate: SignedRecoverableEvaluationOrder, participant: CohortOrderParticipant
    ) -> SignedOrderDeliveryReceipt:
        certificate = SignedRecoverableEvaluationOrder.model_validate_json(
            canonical_json_bytes(certificate)
        )
        participant = CohortOrderParticipant.model_validate_json(canonical_json_bytes(participant))
        slot = order_slot(certificate.order)
        async with self.serial:
            with self.journal.locked():
                saved = await run_owned_thread(self._load, slot)
                if saved is not None:
                    if saved[1] != certificate or saved[0].participant != participant:
                        raise ValueError(
                            "inbox slot is already reserved for other assignment inputs"
                        )
                    return await self._acknowledge(slot, certificate)
                self._check_certificate(certificate)
                source = await self.history(certificate.order.round.cohort_sha256)
                observation = execution_boundary(await self.provider.collect())
                await run_owned_thread(
                    remember_order_history,
                    self.journal,
                    self.cohorts,
                    self.policy,
                    source,
                    observation.block,
                )
                await run_owned_thread(
                    review_order,
                    certificate.order,
                    participant,
                    source,
                    self.policy,
                    observation.block,
                )
                current = await self.history(certificate.order.round.cohort_sha256)
                if current != source:
                    observation = execution_boundary(await self.provider.collect())
                    await run_owned_thread(
                        remember_order_history,
                        self.journal,
                        self.cohorts,
                        self.policy,
                        current,
                        observation.block,
                    )
                    raise OSError("inbox history changed before assignment acceptance")
                intent = CohortOrderIntent(
                    schema="umi-cohort-order-intent/1",
                    order=certificate.order,
                    participant=participant,
                    source=source,
                    observation=observation,
                )
                await run_owned_thread(
                    self.journal.reserve_records, slot, (RecordReservation("receipt", slot, 4096),)
                )
                await run_owned_thread(
                    self.journal.put_many,
                    (("intent", slot, intent), ("certificate", slot, certificate)),
                )
                return await self._acknowledge(slot, certificate)
