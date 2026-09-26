"""Evaluator-owned durable assignment receipt; execution is a separate operation."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Literal

from pydantic import Field

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

    def _load(self, slot: str):
        raw = self.journal.get("intent", slot)
        if raw is None:
            return None
        intent = CohortOrderIntent.model_validate_json(canonical_json_bytes(raw))
        certificate = SignedRecoverableEvaluationOrder.model_validate_json(
            canonical_json_bytes(self.journal.get("certificate", slot))
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
