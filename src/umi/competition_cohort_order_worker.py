"""Bounded, restartable order review and per-evaluator delivery loop.

The host supplies independently authenticated history/finality and bounded ports
for native reviewer and inbox services. Ports must propagate cancellation and
own any blocking work. This loop never invokes an evaluator or submits weights.
"""

from __future__ import annotations

import asyncio
import sqlite3
from collections.abc import Awaitable, Callable
from contextlib import suppress
from typing import Protocol

from .competition_cohort_order_queue import CohortOrderQueue, SignedOrderDeliveryReceipt
from .competition_cohort_order_signer import (
    CohortOrderHistory,
    CohortOrderParticipant,
    CohortOrderVote,
    OrderFinality,
)
from .competition_cohort_orders import RecoverableEvaluationOrder, SignedRecoverableEvaluationOrder
from .concurrency import run_owned_thread, wait_for_owned
from .open_competition import identity

_RETRY = (OSError, ValueError, RuntimeError, sqlite3.Error)


class OrderReviewerPort(Protocol):
    async def lookup(self, reviewer: str, slot: str) -> CohortOrderVote | None: ...

    async def attest(
        self, reviewer: str, order: RecoverableEvaluationOrder, participant: CohortOrderParticipant
    ) -> CohortOrderVote: ...


class OrderDeliveryPort(Protocol):
    async def lookup(self, evaluator: str, slot: str) -> SignedOrderDeliveryReceipt | None: ...
    async def accept(
        self,
        evaluator: str,
        certificate: SignedRecoverableEvaluationOrder,
        participant: CohortOrderParticipant,
    ) -> SignedOrderDeliveryReceipt: ...


class CohortOrderWorker:
    def __init__(
        self,
        queue: CohortOrderQueue,
        provider: OrderFinality,
        history: Callable[[str], Awaitable[CohortOrderHistory]],
        reviewers: OrderReviewerPort,
        delivery: OrderDeliveryPort,
        *,
        batch_size: int = 16,
        operation_timeout_seconds: int = 30,
    ):
        if provider.policy != queue.policy:
            raise ValueError("order worker finality belongs to another policy")
        if type(batch_size) is not int or not 1 <= batch_size <= 256:
            raise ValueError("order worker batch is outside bounds")
        if type(operation_timeout_seconds) is not int or not 1 <= operation_timeout_seconds <= 1200:
            raise ValueError("order worker operation timeout is outside bounds")
        self.queue, self.provider, self.history = queue, provider, history
        self.reviewers, self.delivery = reviewers, delivery
        self.batch_size, self.timeout = batch_size, operation_timeout_seconds
        self.serial = asyncio.Lock()

    async def _current(self, slot, cohort):
        source = await self.history(cohort)
        capture = await self.provider.collect()
        await run_owned_thread(self.queue.check_current, slot, source, capture)

    async def poll_once(self) -> dict[str, str | int | bool]:
        async with self.serial:
            return await self._poll()

    async def _poll(self):
        votes = deliveries = retries = 0
        last_retry = {"last_retry_stage": "", "last_retry_slot": "", "last_retry_type": ""}

        def failed(stage, slot, error):
            nonlocal retries
            retries += 1
            last_retry.update(
                last_retry_stage=stage, last_retry_slot=slot, last_retry_type=type(error).__name__
            )

        for cohort in self.queue.cohorts:
            try:
                pending = await run_owned_thread(
                    lambda cohort=cohort: self.queue.scan(cohort, limit=self.batch_size)
                )
            except _RETRY as error:
                failed("scan", "", error)
                continue
            for slot in pending:
                try:
                    intent = await run_owned_thread(self.queue.intent, slot)
                    missing = await run_owned_thread(self.queue.missing_reviewers, slot)
                except _RETRY as error:
                    failed("selection", slot, error)
                    continue
                for reviewer in missing:
                    try:
                        vote = await wait_for_owned(
                            self.reviewers.lookup(reviewer, slot), timeout=self.timeout
                        )
                        if vote is None:
                            await wait_for_owned(self._current(slot, cohort), timeout=self.timeout)
                            vote = await wait_for_owned(
                                self.reviewers.attest(reviewer, intent.order, intent.participant),
                                timeout=self.timeout,
                            )
                        if identity(vote.signature.hotkey) != identity(reviewer):
                            raise ValueError("reviewer response belongs to another identity")
                        certificate = await run_owned_thread(self.queue.publish_vote, slot, vote)
                        votes += 1
                        if certificate is not None:
                            break
                    except _RETRY as error:
                        failed("vote", slot, error)
                try:
                    certificate = await run_owned_thread(self.queue.certificate, slot)
                    recipients = await run_owned_thread(self.queue.missing_recipients, slot)
                except _RETRY as error:
                    failed("certificate", slot, error)
                    continue
                for evaluator in recipients:
                    try:
                        # Recover a lost acknowledgement even after request closure,
                        # without issuing new work or consulting an online coordinator.
                        receipt = await wait_for_owned(
                            self.delivery.lookup(evaluator, slot), timeout=self.timeout
                        )
                        if receipt is None:
                            await wait_for_owned(self._current(slot, cohort), timeout=self.timeout)
                            receipt = await wait_for_owned(
                                self.delivery.accept(evaluator, certificate, intent.participant),
                                timeout=self.timeout,
                            )
                        if identity(receipt.receipt.evaluator_hotkey) != identity(evaluator):
                            raise ValueError("delivery response belongs to another identity")
                        await run_owned_thread(self.queue.acknowledge, slot, receipt)
                        deliveries += 1
                    except _RETRY as error:
                        failed("delivery", slot, error)
        return {
            "status": "order_delivery_retry" if retries else "order_delivery_current",
            "votes_retained": votes,
            "deliveries_acknowledged": deliveries,
            "retry_count": retries,
            **last_retry,
            "chain_submission_authorized": False,
        }

    async def run(
        self,
        stop: asyncio.Event,
        *,
        poll_seconds: float = 5,
        report: Callable[[dict], None] | None = None,
    ) -> None:
        if isinstance(poll_seconds, bool) or not 0 < poll_seconds <= 60:
            raise ValueError("order worker poll interval is outside bounds")
        while not stop.is_set():
            task, stopping = asyncio.create_task(self.poll_once()), asyncio.create_task(stop.wait())
            try:
                done, _ = await asyncio.wait((task, stopping), return_when=asyncio.FIRST_COMPLETED)
                if stopping in done:
                    return
                try:
                    result = task.result()
                except _RETRY:
                    result = {
                        "status": "order_delivery_retry",
                        "chain_submission_authorized": False,
                    }
                if report is not None:
                    report(result)
            finally:
                task.cancel()
                stopping.cancel()
                await asyncio.gather(task, stopping, return_exceptions=True)
            with suppress(asyncio.TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=poll_seconds)
