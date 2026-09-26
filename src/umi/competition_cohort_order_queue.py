"""Private coordinator outbox: immutable selections, quorum votes and delivery receipts.

A delivery receipt acknowledges a retained assignment only. Neither this queue
nor its certificate authorizes live inference, closes work or grants rewards.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .competition_chain import RegistrationCapture
from .competition_cohort_intake import CohortIntakeBinding
from .competition_cohort_order_signer import (
    CohortOrderHistory,
    CohortOrderIntent,
    CohortOrderParticipant,
    CohortOrderVote,
    certify_order_votes,
    order_slot,
    remember_order_history,
    review_order,
)
from .competition_cohort_orders import (
    MAX_ORDER_BYTES,
    RecoverableEvaluationOrder,
    SignedRecoverableEvaluationOrder,
)
from .competition_cohort_recovery import verify_recovery_quorum
from .competition_execution import execution_boundary
from .competition_round_journal import RecordReservation, RoundJournal
from .open_competition import (
    CompetitionPolicy,
    Hotkey,
    Signature,
    digest,
    identity,
    verify_signature,
)
from .private_files import Directory
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


class CohortOrderQueueConfig(StrictProtocolModel):
    schema_: Literal["umi-cohort-order-queue-config/1"] = Field(alias="schema")
    directory: Directory
    policy_sha256: Hex32
    cohorts: Annotated[tuple[CohortIntakeBinding, ...], Field(min_length=1, max_length=512)]
    reviewers: Annotated[tuple[Hotkey, ...], Field(min_length=1, max_length=64)]
    maximum_orders: Annotated[int, Field(ge=1, le=32768)] = 4096
    maximum_bytes: Annotated[int, Field(ge=1024, le=16 * 1024**3)] = 1024**3

    @model_validator(mode="after")
    def ordered(self):
        for keys in (
            tuple(c.cohort_sha256 for c in self.cohorts),
            tuple(identity(k) for k in self.reviewers),
        ):
            if keys != tuple(sorted(set(keys))):
                raise ValueError("order queue authorities and reviewers must be unique and ordered")
        return self


class OrderDeliveryReceipt(StrictProtocolModel):
    schema_: Literal["umi-cohort-order-delivery-receipt/1"] = Field(alias="schema")
    slot: Hex32
    order_sha256: Hex32
    certificate_sha256: Hex32
    evaluator_hotkey: Hotkey


class SignedOrderDeliveryReceipt(StrictProtocolModel):
    receipt: OrderDeliveryReceipt
    signature: Signature


def delivery_receipt(
    certificate: SignedRecoverableEvaluationOrder, evaluator: str
) -> OrderDeliveryReceipt:
    if identity(evaluator) not in {identity(k) for k in certificate.order.evaluators}:
        raise ValueError("delivery recipient is not an assigned evaluator")
    return OrderDeliveryReceipt(
        schema="umi-cohort-order-delivery-receipt/1",
        slot=order_slot(certificate.order),
        order_sha256=digest(certificate.order),
        certificate_sha256=digest(certificate),
        evaluator_hotkey=evaluator,
    )


def check_delivery_receipt(
    certificate: SignedRecoverableEvaluationOrder, signed: SignedOrderDeliveryReceipt
) -> SignedOrderDeliveryReceipt:
    signed = SignedOrderDeliveryReceipt.model_validate_json(canonical_json_bytes(signed))
    if signed.receipt != delivery_receipt(certificate, signed.receipt.evaluator_hotkey) or identity(
        signed.signature.hotkey
    ) != identity(signed.receipt.evaluator_hotkey):
        raise ValueError("delivery receipt does not match its exact assignment or recipient")
    verify_signature(signed.receipt, signed.signature)
    return signed


def recipient_key(slot: str, hotkey: str) -> str:
    return digest({"slot": slot, "recipient": identity(hotkey)})


class CohortOrderQueue:
    def __init__(self, config: CohortOrderQueueConfig, policy: CompetitionPolicy):
        self.config = CohortOrderQueueConfig.model_validate_json(canonical_json_bytes(config))
        self.policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
        self.groups = {identity(e.hotkey): e.control_group for e in self.policy.evaluators}
        self.reviewers = {identity(k): k for k in self.config.reviewers}
        if (
            self.config.policy_sha256 != digest(self.policy)
            or not self.reviewers.keys() <= self.groups.keys()
            or len({self.groups[k] for k in self.reviewers}) < self.policy.required_evaluator_groups
        ):
            raise ValueError("order queue reviewers cannot form the configured policy quorum")
        self.cohorts = {c.cohort_sha256: c.authority_sha256 for c in self.config.cohorts}
        self.journal = RoundJournal(
            Path(self.config.directory),
            self.config.model_dump(
                mode="json", by_alias=True, exclude={"maximum_orders", "maximum_bytes"}
            ),
            # Up to 64 votes plus 64 delivery receipts per selected order.
            maximum_rounds=2 * self.config.maximum_orders,
            maximum_bytes=self.config.maximum_bytes,
            maximum_record_bytes=MAX_ORDER_BYTES,
        )
        with self.journal.transaction() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS order_heads "
                "(cohort TEXT PRIMARY KEY, history TEXT NOT NULL)"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS order_queue "
                "(slot TEXT PRIMARY KEY, cohort TEXT NOT NULL, delivered INTEGER NOT NULL)"
            )

            db.execute(
                "CREATE TABLE IF NOT EXISTS order_queue_cursors "
                "(cohort TEXT PRIMARY KEY, slot TEXT NOT NULL)"
            )

    def scan(self, cohort: str, *, limit: int = 16) -> tuple[str, ...]:
        """Advance the fair scan before work; unfinished entries remain pending."""
        if cohort not in self.cohorts or type(limit) is not int or not 1 <= limit <= 256:
            raise ValueError("invalid order queue scan")
        with self.journal.transaction() as db:
            old = db.execute(
                "SELECT slot FROM order_queue_cursors WHERE cohort=?", (cohort,)
            ).fetchone()
            after = "" if old is None else old[0]
            query = (
                "SELECT slot FROM order_queue WHERE cohort=? AND delivered=0 AND slot>? "
                "ORDER BY slot LIMIT ?"
            )
            rows = db.execute(query, (cohort, after, limit)).fetchall()
            if not rows and after:
                rows = db.execute(query, (cohort, "", limit)).fetchall()
            if rows:
                db.execute(
                    "INSERT INTO order_queue_cursors VALUES (?,?) ON CONFLICT(cohort) "
                    "DO UPDATE SET slot=excluded.slot",
                    (cohort, rows[-1][0]),
                )
            return tuple(r[0] for r in rows)

    def _intent(self, slot: str) -> CohortOrderIntent:
        raw = self.journal.get("intent", slot)
        if raw is None:
            raise FileNotFoundError("order queue has no retained selection")
        intent = CohortOrderIntent.model_validate_json(canonical_json_bytes(raw))
        if order_slot(intent.order) != slot or self.cohorts.get(
            intent.order.round.cohort_sha256
        ) != digest(intent.source.history.authority.authority):
            raise ValueError("retained queue selection changed its identity or authority")
        review_order(
            intent.order, intent.participant, intent.source, self.policy, intent.observation.block
        )
        return intent

    def intent(self, slot: str) -> CohortOrderIntent:
        with self.journal.locked():
            return self._intent(slot)

    def select(
        self,
        order: RecoverableEvaluationOrder,
        participant: CohortOrderParticipant,
        source: CohortOrderHistory,
        capture: RegistrationCapture,
    ) -> str:
        intent = CohortOrderIntent(
            schema="umi-cohort-order-intent/1",
            order=order,
            participant=participant,
            source=source,
            observation=execution_boundary(capture),
        )
        intent = CohortOrderIntent.model_validate_json(canonical_json_bytes(intent))
        slot = order_slot(intent.order)
        with self.journal.locked():
            if self.journal.get("intent", slot) is not None:
                prior = self._intent(slot)
                if prior.order != intent.order or prior.participant != intent.participant:
                    raise ValueError("order queue selection is already reserved for other inputs")
                return slot
            remember_order_history(
                self.journal, self.cohorts, self.policy, intent.source, intent.observation.block
            )
            review_order(order, participant, source, self.policy, intent.observation.block)
            miner = identity(intent.order.submission.submission.hotkey)
            voters = [k for k in self.reviewers if k != miner]
            if len({self.groups[k] for k in voters}) < self.policy.required_evaluator_groups:
                raise ValueError("order queue cannot obtain an independent non-miner quorum")
            allowances = [
                RecordReservation(
                    "order_certificate", slot, len(canonical_json_bytes(order)) + 65536
                ),
                *(
                    RecordReservation("queue_vote", recipient_key(slot, self.reviewers[k]), 2048)
                    for k in voters
                ),
                *(
                    RecordReservation("delivery", recipient_key(slot, k), 4096)
                    for k in order.evaluators
                ),
            ]
            self.journal.reserve_records(slot, allowances)

            def index(db):
                if (
                    db.execute("SELECT COUNT(*) FROM order_queue").fetchone()[0]
                    >= self.config.maximum_orders
                ):
                    raise ValueError("order queue capacity exhausted")
                db.execute(
                    "INSERT INTO order_queue VALUES (?,?,0)", (slot, order.round.cohort_sha256)
                )

            self.journal.put_many((("intent", slot, intent),), index=index)
        return slot

    def _certificate(self, slot: str, intent: CohortOrderIntent):
        raw = self.journal.get("order_certificate", slot)
        if raw is None:
            return None
        certificate = SignedRecoverableEvaluationOrder.model_validate_json(
            canonical_json_bytes(raw)
        )
        if certificate.order != intent.order or any(
            identity(s.hotkey) not in self.reviewers
            or identity(s.hotkey) == identity(intent.order.submission.submission.hotkey)
            for s in certificate.signatures
        ):
            raise ValueError("queue certificate changed the retained selection or reviewers")
        verify_recovery_quorum(certificate.order, certificate.signatures, self.policy)
        return certificate

    def certificate(self, slot: str) -> SignedRecoverableEvaluationOrder | None:
        with self.journal.locked():
            return self._certificate(slot, self._intent(slot))

    def _vote(self, intent: CohortOrderIntent, vote: CohortOrderVote) -> CohortOrderVote:
        vote = CohortOrderVote.model_validate_json(canonical_json_bytes(vote))
        author = identity(vote.signature.hotkey)
        if (
            vote.order_sha256 != digest(intent.order)
            or author not in self.reviewers
            or author == identity(intent.order.submission.submission.hotkey)
        ):
            raise ValueError("queue vote differs from the retained order or authorized reviewer")
        verify_signature(intent.order, vote.signature)
        return vote

    def missing_reviewers(self, slot: str) -> tuple[str, ...]:
        with self.journal.locked():
            intent = self._intent(slot)
            if self._certificate(slot, intent) is not None:
                return ()
            missing = []
            for author, key in self.reviewers.items():
                if author == identity(intent.order.submission.submission.hotkey):
                    continue
                raw = self.journal.get("queue_vote", recipient_key(slot, key))
                if raw is None:
                    missing.append(key)
                else:
                    vote = self._vote(
                        intent, CohortOrderVote.model_validate_json(canonical_json_bytes(raw))
                    )
                    if identity(vote.signature.hotkey) != author:
                        raise ValueError("queue vote is stored under another reviewer")
            return tuple(missing)

    def publish_vote(
        self, slot: str, vote: CohortOrderVote
    ) -> SignedRecoverableEvaluationOrder | None:
        # Collecting an already signed historical vote performs no new work.
        with self.journal.locked():
            intent = self._intent(slot)
            vote = self._vote(intent, vote)
            certificate = self._certificate(slot, intent)
            if certificate is not None:
                return certificate
            author = identity(vote.signature.hotkey)
            key = recipient_key(slot, vote.signature.hotkey)
            selected, groups = [], set()
            for who in self.reviewers:
                raw = self.journal.get("queue_vote", recipient_key(slot, self.reviewers[who]))
                retained = (
                    None
                    if raw is None
                    else self._vote(
                        intent, CohortOrderVote.model_validate_json(canonical_json_bytes(raw))
                    )
                )
                if retained is not None and identity(retained.signature.hotkey) != who:
                    raise ValueError("queue vote is stored under another reviewer")
                if who == author:
                    vote = retained or vote
                    retained = vote
                if retained is not None and self.groups[who] not in groups:
                    selected.append(retained)
                    groups.add(self.groups[who])
            records = [("queue_vote", key, vote)]
            if len(groups) >= self.policy.required_evaluator_groups:
                certificate = certify_order_votes(intent.order, selected, self.policy)
                records.append(("order_certificate", slot, certificate))
            self.journal.put_many(records)
            return certificate

    def check_current(
        self, slot: str, source: CohortOrderHistory, capture: RegistrationCapture
    ) -> None:
        with self.journal.locked():
            intent = self._intent(slot)
            block = execution_boundary(capture).block
            remember_order_history(self.journal, self.cohorts, self.policy, source, block)
            review_order(intent.order, intent.participant, source, self.policy, block)

    def acknowledge(self, slot: str, signed: SignedOrderDeliveryReceipt) -> None:
        with self.journal.locked():
            intent = self._intent(slot)
            certificate = self._certificate(slot, intent)
            if certificate is None:
                raise ValueError("delivery has no retained certificate")
            signed = check_delivery_receipt(certificate, signed)
            key = recipient_key(slot, signed.receipt.evaluator_hotkey)
            old = self.journal.get("delivery", key)
            if old is not None:
                checked = check_delivery_receipt(
                    certificate,
                    SignedOrderDeliveryReceipt.model_validate_json(canonical_json_bytes(old)),
                )
                if checked.receipt != signed.receipt:
                    raise ValueError("retained delivery changed its recipient")
                return

            def index(db):
                if all(
                    self.journal.get("delivery", recipient_key(slot, k), db=db) is not None
                    for k in intent.order.evaluators
                ):
                    db.execute("UPDATE order_queue SET delivered=1 WHERE slot=?", (slot,))

            self.journal.put_many((("delivery", key, signed),), index=index)

    def missing_recipients(self, slot: str) -> tuple[str, ...]:
        with self.journal.locked():
            intent = self._intent(slot)
            certificate = self._certificate(slot, intent)
            if certificate is None:
                return ()
            missing = []
            for who in intent.order.evaluators:
                raw = self.journal.get("delivery", recipient_key(slot, who))
                if raw is None:
                    missing.append(who)
                else:
                    signed = check_delivery_receipt(
                        certificate,
                        SignedOrderDeliveryReceipt.model_validate_json(canonical_json_bytes(raw)),
                    )
                    if identity(signed.receipt.evaluator_hotkey) != identity(who):
                        raise ValueError("delivery receipt is stored under another recipient")
            return tuple(missing)

    def pending(self, cohort: str, *, after: str = "", limit: int = 16) -> tuple[str, ...]:
        if cohort not in self.cohorts or type(limit) is not int or not 1 <= limit <= 256:
            raise ValueError("invalid order queue scan")
        with self.journal.transaction() as db:
            return tuple(
                r[0]
                for r in db.execute(
                    "SELECT slot FROM order_queue WHERE cohort=? AND delivered=0 AND slot>? "
                    "ORDER BY slot LIMIT ?",
                    (cohort, after, limit),
                )
            )
