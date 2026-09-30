"""Select the complete certified benchmark roster and deliver its original orders."""

from __future__ import annotations

import asyncio
import logging
import sqlite3
from contextlib import suppress
from functools import partial
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field

from .competition_cohort_history import verify_cohort_history
from .competition_cohort_intake import history_tip
from .competition_cohort_order_http import OrderDeliveryPeer, OrderReviewPeer
from .competition_cohort_order_queue import CohortOrderQueue, CohortOrderQueueConfig
from .competition_cohort_order_signer import CohortOrderParticipant
from .competition_cohort_order_worker import CohortOrderWorker
from .competition_cohort_orders import RecoverableEvaluationOrder
from .competition_cohort_settlement_delivery import SettlementEvidenceFiles
from .competition_execution import ExecutionCase, execution_boundary
from .competition_runner import OFFLINE_RUNTIME, OfflineCpuRuntime
from .concurrency import await_owned_task, run_owned_thread, wait_for_owned
from .open_competition import EvaluationSuite, ModelBundle, digest, identity, validate_suite_profile
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

logger = logging.getLogger(__name__)
_RETRY = (OSError, ValueError, RuntimeError, sqlite3.Error, asyncio.TimeoutError)


class OrderHostConfig(StrictProtocolModel):
    schema_: Literal["umi-cohort-order-host/1"] = Field(alias="schema")
    queue: CohortOrderQueueConfig
    batch_size: Annotated[int, Field(ge=1, le=256)] = 16
    poll_seconds: Annotated[int, Field(ge=1, le=60)] = 5
    operation_timeout_seconds: Annotated[int, Field(ge=1, le=1200)] = 300


class _Selection(StrictProtocolModel):
    round_sha256: Hex32
    slots: Annotated[tuple[Hex32, ...], Field(min_length=1, max_length=512)]


class _Reviewers:
    def __init__(self, peers):
        self.peers = peers

    async def lookup(self, who, slot):
        return await self.peers[identity(who)].lookup(slot)

    async def attest(self, who, order, participant):
        return await self.peers[identity(who)].attest(order, participant)


class _Delivery:
    def __init__(self, peers):
        self.peers = peers

    async def lookup(self, who, slot):
        return await self.peers[identity(who)].lookup(slot)

    async def accept(self, who, certificate, participant):
        return await self.peers[identity(who)].accept(certificate, participant)


class CohortOrderHost:
    def __init__(self, service, client, credentials):
        self.config = c = OrderHostConfig.model_validate_json(
            canonical_json_bytes(service.config.orders)
        )
        owner = service.config.admission_owner
        policy = service.intake.policy
        if (
            c.queue.policy_sha256 != digest(policy)
            or c.queue.cohorts != service.intake.config.cohorts
            or tuple(identity(k) for k in c.queue.reviewers)
            != tuple(sorted(identity(p.signer) for p in owner.reviewers))
        ):
            raise ValueError("benchmark order queue differs from owned intake and reviewers")
        groups = {identity(e.hotkey): e.control_group for e in policy.evaluators}
        if (
            len({groups[identity(k)] for k in c.queue.reviewers})
            < policy.required_evaluator_groups
        ):
            raise ValueError("benchmark execution cannot form the policy evaluator quorum")
        self.queue = CohortOrderQueue(c.queue, policy)
        self.service, self.last_reports, self.selected = service, {}, {}
        self.files = SettlementEvidenceFiles(
            Path(service.config.lifecycle.sources.objects_directory)
        )
        peers = [{}, {}]
        for peer, token in zip(owner.reviewers, credentials, strict=True):
            for table, cls in zip(peers, (OrderReviewPeer, OrderDeliveryPeer), strict=True):
                table[identity(peer.signer)] = cls(
                    client,
                    peer.origin,
                    policy=policy,
                    cohorts=c.queue.cohorts,
                    signer=peer.signer,
                    token=token,
                    timeout_seconds=peer.timeout_seconds,
                )
        self.worker = CohortOrderWorker(
            self.queue,
            service.provider,
            service.history,
            _Reviewers(peers[0]),
            _Delivery(peers[1]),
            batch_size=c.batch_size,
            operation_timeout_seconds=c.operation_timeout_seconds,
        )

    def _select(self, prepared, source, capture):
        round_ = prepared.roster.round
        cohort = round_.cohort_sha256
        policy = self.queue.policy
        view = verify_cohort_history(
            source.history,
            policy,
            expected_tip_sha256=history_tip(source.history),
            current_block=execution_boundary(capture).block,
        )
        suite = EvaluationSuite.model_validate_json(self.files(round_.suite_sha256))
        validate_suite_profile(suite, policy)
        if suite.policy_sha256 != digest(policy):
            raise ValueError("benchmark suite belongs to another policy")
        incumbent = ModelBundle.model_validate_json(self.files(round_.incumbent_model_sha256))
        runtime = OFFLINE_RUNTIME.validate_json(self.files(round_.runtime_sha256))
        if not isinstance(runtime, OfflineCpuRuntime):
            raise ValueError("configured benchmark host requires the pinned CPU runtime")
        cases = tuple(
            ExecutionCase(case_id=c.case_id, video_sha256=c.video_sha256, stratum=c.stratum)
            for c in suite.cases
        )
        members = prepared.roster.participants
        if tuple(digest(p.record.request.signed_submission.submission) for p in members) != tuple(
            p.submission_sha256 for p in round_.participants
        ):
            raise ValueError("benchmark selection differs from the complete prepared roster")
        slots = []
        for member in members:
            record = member.record
            miner = identity(record.request.signed_submission.submission.hotkey)
            order = RecoverableEvaluationOrder(
                schema="umi-recoverable-evaluation-order/1",
                round=round_,
                preparation_closure_sha256=digest(view.closure("preparation")),
                submission=record.request.signed_submission,
                incumbent=incumbent,
                runtime=runtime,
                cases=cases,
                evaluators=tuple(k for k in self.queue.config.reviewers if identity(k) != miner),
            )
            participant = CohortOrderParticipant(
                consent=record.request.consent,
                admission=member.admission,
                admission_snapshot=record.snapshot,
            )
            slots.append(self.queue.select(order, participant, source, capture))
        # Publish only after every member has a durable original selection.
        # Delivery can proceed independently while a later selection is retried.
        self.queue.journal.put(
            "order_host_roster", cohort, _Selection(round_sha256=digest(round_), slots=tuple(slots))
        )
        return len(slots)

    def _retained(self, cohort):
        raw = self.queue.journal.get("order_host_roster", cohort)
        if raw is None:
            return None
        selected = _Selection.model_validate_json(canonical_json_bytes(raw))
        if len(set(selected.slots)) != len(selected.slots):
            raise ValueError("retained benchmark roster repeats an order")
        orders = tuple(self.queue.intent(slot).order for slot in selected.slots)
        if any(
            digest(o.round) != selected.round_sha256 or o.round.cohort_sha256 != cohort
            for o in orders
        ):
            raise ValueError("retained benchmark roster changed its round")
        if tuple(digest(o.submission.submission) for o in orders) != tuple(
            p.submission_sha256 for p in orders[0].round.participants
        ):
            raise ValueError("retained benchmark roster omits an accepted participant")
        return len(orders)

    async def select(self, cohort):
        if cohort in self.selected:
            return self.selected[cohort]
        selected = await run_owned_thread(self._retained, cohort)
        if selected is not None:
            self.selected[cohort] = selected
            return selected
        timeout = self.config.operation_timeout_seconds
        source = await wait_for_owned(self.service.history(cohort), timeout=timeout)
        capture = await wait_for_owned(self.service.provider.collect(), timeout=timeout)
        block = execution_boundary(capture).block
        view = verify_cohort_history(
            source.history,
            self.queue.policy,
            expected_tip_sha256=history_tip(source.history),
            current_block=block,
        )
        if view.state.phase != "requests":
            return 0
        prepared = await run_owned_thread(
            partial(
                self.service.preparation.retained,
                cohort,
                expected_tip_sha256=history_tip(source.history),
                current_block=block,
            )
        )
        if await wait_for_owned(self.service.history(cohort), timeout=timeout) != source:
            raise OSError("benchmark authority changed before order selection")
        self.selected[cohort] = await run_owned_thread(self._select, prepared, source, capture)
        return self.selected[cohort]

    def report(self, name, result):
        if self.last_reports.get(name) != result:
            logger.info(
                "cohort_order_host worker=%s report=%s", name, canonical_json_bytes(result).decode()
            )
        self.last_reports[name] = result

    async def _selection(self, stop):
        while not stop.is_set():
            for cohort in self.queue.cohorts:
                try:
                    count = await self.select(cohort)
                    result = {
                        "status": "orders_selected" if count else "orders_waiting",
                        "count": count,
                    }
                except _RETRY as error:
                    result = {"status": "order_selection_retry", "error_type": type(error).__name__}
                self.report(cohort, result)
            with suppress(asyncio.TimeoutError):
                await asyncio.wait_for(stop.wait(), self.config.poll_seconds)

    async def run(self, stop):
        tasks = (
            asyncio.create_task(self._selection(stop)),
            asyncio.create_task(
                self.worker.run(
                    stop,
                    poll_seconds=self.config.poll_seconds,
                    report=lambda result: self.report("delivery", result),
                )
            ),
        )
        stopping = asyncio.create_task(stop.wait())
        try:
            done, _ = await asyncio.wait((*tasks, stopping), return_when=asyncio.FIRST_COMPLETED)
            for task in done - {stopping}:
                task.result()
            if not stop.is_set():
                raise RuntimeError("benchmark order task exited before shutdown")
        finally:

            async def drain():
                for task in (*tasks, stopping):
                    task.cancel()
                await asyncio.gather(*tasks, stopping, return_exceptions=True)

            await await_owned_task(asyncio.create_task(drain()))
