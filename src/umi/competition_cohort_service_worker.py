"""Recurring accepted-service work, with retained requests and terminal results.

The host owns authenticated media, finality/history and independent review ports.
Each port call is bounded; outages impose no cumulative cohort expiry. Finished
responses and signatures recover before live inputs. The worker never grants
credit or closes a phase; independent closure and quality replay do that.
"""

from __future__ import annotations

import asyncio
import os
import sqlite3
from collections import Counter
from collections.abc import Awaitable, Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from functools import partial

import bittensor as bt

from .competition_chain import RegistrationCapture
from .competition_cohort_endpoint_decision_contracts import SignedCohortEndpointCaseDecision
from .competition_cohort_order_signer import CohortOrderHistory
from .competition_cohort_request_window import CohortAttemptRequestWindow, EndpointRequestWindow
from .competition_cohort_service_grant import (
    ServiceMinerGrant,
    ServiceRequestBody,
    service_grant_slot,
)
from .competition_cohort_service_terminal import ServiceTerminal, ServiceWorkTerminals
from .competition_cohort_service_transport import ServiceWorkTransport
from .competition_cohort_service_work import ServiceWorkAssignment
from .competition_execution import execution_boundary
from .competition_progress import _failure_details
from .concurrency import await_owned_task, run_owned_thread, wait_for_owned
from .endpoint_retirement import SignedEndpointRetirementReceipt
from .open_competition import Signature, digest, identity
from .private_files import PrivateStateBusyError, lock_private_file
from .private_state_wait import run_private_state_operation
from .protocol import Video

_RETRY = (OSError, ValueError, RuntimeError, sqlite3.Error, asyncio.TimeoutError)


@dataclass(frozen=True)
class ServiceRequestInputs:
    video: Video
    window: CohortAttemptRequestWindow | EndpointRequestWindow


ServiceInputs = Callable[[ServiceWorkAssignment], Awaitable[ServiceRequestInputs]]
ServiceObservation = Callable[
    [ServiceWorkAssignment], Awaitable[tuple[CohortOrderHistory, RegistrationCapture]]
]
ServiceRequestVote = Callable[[ServiceRequestBody], Awaitable[Signature]]
ServiceRetry = Callable[
    [ServiceMinerGrant, SignedEndpointRetirementReceipt],
    Awaitable[SignedCohortEndpointCaseDecision],
]
ServiceResultSign = Callable[[ServiceTerminal], Awaitable[Signature]]


class ServiceWorkWorker:
    def __init__(
        self,
        transport: ServiceWorkTransport,
        inputs: ServiceInputs,
        observation: ServiceObservation,
        reviewers: Mapping[str, ServiceRequestVote],
        retry: ServiceRetry,
        sign: ServiceResultSign,
        *,
        batch_size: int = 16,
        concurrency: int = 4,
    ):
        if (
            type(batch_size) is not int
            or not 1 <= batch_size <= 256
            or type(concurrency) is not int
            or not 1 <= concurrency <= 32
        ):
            raise ValueError("service worker capacity is outside bounds")
        self.transport, self.requests = transport, transport.requests
        self.queue, self.journal = self.requests.queue, self.requests.journal
        self.inputs, self.observation, self.retry, self.sign = inputs, observation, retry, sign
        self.terminals = ServiceWorkTerminals(self.requests)
        known = {identity(e.hotkey): e.control_group for e in self.requests.policy.evaluators}
        self.reviewers = {identity(k): v for k, v in reviewers.items()}
        self.reviewer_keys = {identity(k): k for k in reviewers}
        if len(self.reviewers) != len(reviewers) or not self.reviewers.keys() <= known.keys():
            raise ValueError("service reviewer identities differ from policy")
        self.batch_size, self.concurrency = batch_size, concurrency
        self.capacity = asyncio.Semaphore(concurrency)
        self.serial, self.vote_writes = asyncio.Lock(), asyncio.Lock()
        self._operation_stages = {}
        self._operation_lanes = {}
        with self.journal.transaction() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS service_worker_cursor "
                "(singleton INTEGER PRIMARY KEY CHECK(singleton=1), ordinal INTEGER NOT NULL)"
            )
        # Restart may change operational capacity, but never the evaluator.
        self.journal.put(
            "service_worker_binding",
            digest(["umi-service-worker/1"]),
            {
                "evaluator": identity(transport.evaluator),
                "transport": digest(self.requests.transport),
            },
        )

    async def _call(self, awaitable):
        return await wait_for_owned(awaitable, timeout=self.transport.timeout)

    async def _local(self, function, *args):
        return await run_private_state_operation(function, *args, timeout=self.transport.timeout)

    async def _certificate(self, body):
        slot = service_grant_slot(body)
        raw = await self._local(self.journal.get, "service_grant", slot)
        if raw is not None:
            return await self._local(self.requests.certificate, slot)

        async def vote(who, port):
            if who == identity(body.assignment.admission.submission.submission.hotkey):
                return
            key = self.requests._vote_key(slot, self.reviewer_keys[who])
            raw = await self._local(self.journal.get, "service_request_vote", key)
            try:
                signed = (
                    Signature.model_validate(raw)
                    if raw is not None
                    else await self._call(port(body))
                )
                if identity(signed.hotkey) != who:
                    raise ValueError("service request vote came from another reviewer")
                async with self.vote_writes:
                    await self._local(self.requests.collect, slot, signed)
                return who
            except _RETRY:
                # Another independent quorum may be available this pass.
                return

        tasks = [asyncio.create_task(vote(who, port)) for who, port in self.reviewers.items()]
        pending = set(tasks)
        groups = set()
        reviewer_groups = {
            identity(e.hotkey): e.control_group for e in self.requests.policy.evaluators
        }
        try:
            while pending:
                done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
                for task in done:
                    who = task.result()
                    if who is not None:
                        groups.add(reviewer_groups[who])
                if len(groups) >= self.requests.policy.required_evaluator_groups:
                    return await self._local(self.requests.certificate, slot)
            return await self._local(self.requests.certificate, slot)
        finally:
            # A redundant peer cannot delay a native policy quorum. Cancel its
            # delivery cooperatively, retaining any already committed signature.
            await self._stop_tasks(tasks)

    async def _prepare(self, assignment, *, parent=None, decision=None, retirement=None):
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.transport.timeout
        while True:
            inputs = await self._call(self.inputs(assignment))
            source, capture = await self._call(self.observation(assignment))
            try:
                return await run_owned_thread(
                    partial(
                        self.requests.prepare,
                        assignment.admission.claim,
                        self.transport.evaluator,
                        inputs.video,
                        inputs.window,
                        source,
                        capture,
                        parent=parent,
                        decision=decision,
                        retirement=retirement,
                    ),
                )
            except PrivateStateBusyError:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    raise
                # Never retry persistence with the same authority/head after a wait.
                await asyncio.sleep(min(1.0, remaining))

    def _stage(self, work, name):
        if work in self._operation_stages:
            self._operation_stages[work] = (name, asyncio.get_running_loop().time())

    async def _prepare_terminal(self, assignment, slot, response, retirement):
        work = assignment.admission.work_sha256
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.transport.timeout
        while True:
            self._stage(work, "terminal_observation")
            source, capture = await self._call(self.observation(assignment))
            self._stage(work, "terminal_preparation")
            try:
                return await run_owned_thread(
                    self.terminals.prepare,
                    slot,
                    response,
                    retirement,
                    source,
                    execution_boundary(capture),
                )
            except PrivateStateBusyError:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    raise
                # Recollect mutable authority after contention; never reissue
                # miner work or extend an old observation while waiting.
                await asyncio.sleep(min(1.0, remaining))

    def _ready_stage(self, admission):
        """Scheduling hints only; each stage still authenticates its native inputs."""
        work = admission.work_sha256
        if self.journal.get("service_terminal", work) is not None:
            return "completed"
        if self.journal.get("service_terminal_intent", work) is not None:
            return "certification"
        body = self.requests.latest(admission.claim, self.transport.evaluator)
        if body is None:
            return "preparation"
        slot = service_grant_slot(body)
        if self.journal.get("service_retirement", slot) is not None:
            return "certification"
        if self.journal.get("service_grant", slot) is None:
            return "preparation"
        if (
            self.journal.get("service_dispatch_intent", slot) is not None
            or bt.timelock.current_round() >= body.request.response_close_round
        ):
            # Unsent expiry must yield to native retirement/replacement too;
            # it is neither a missing send intent nor evidence of zero work.
            return "recovery"
        return "dispatch"

    async def _advance(self, admission, *, one_stage=False):
        work = admission.work_sha256
        self._stage(work, "assignment_read")
        assignment = await self._local(self.queue.assignment, admission.claim)
        self._stage(work, "terminal_read")
        # An absent terminal needs no second reconstruction of the accepted
        # assignment. Presence is only a hint: native read still authenticates
        # retained terminals and recovers interrupted immutable exports.
        retained = await self._local(
            self.journal.get_raw, "service_terminal", assignment.admission.work_sha256
        )
        if retained is not None and await self._local(self.terminals.read, assignment) is not None:
            return "completed", "original_terminal_retained"
        self._stage(work, "request_lineage")
        body = await self._local(self.requests.latest, admission.claim, self.transport.evaluator)
        if body is None:
            self._stage(work, "request_preparation")
            body = await self._prepare(assignment)
            if one_stage:
                return "pending", "request_prepared"
        slot = service_grant_slot(body)
        # A prepared terminal survives a signing outage and needs no new media,
        # chain observation, grant delivery, retirement or model execution.
        self._stage(work, "terminal_intent_read")
        intent = await self._local(
            self.journal.get, "service_terminal_intent", admission.work_sha256
        )
        if intent is not None:
            self._stage(work, "terminal_preparation")
            terminal = await self._local(self.terminals.prepare, slot)
        else:
            self._stage(work, "request_certificate")
            had_grant = await self._local(self.journal.get, "service_grant", slot)
            grant = await self._certificate(body)
            if one_stage and had_grant is None:
                return "pending", "request_certified"
            self._stage(work, "miner_transport")
            had_dispatch = await self._local(self.journal.get, "service_dispatch_intent", slot)
            had_retirement = await self._local(self.journal.get, "service_retirement", slot)
            result = await self.transport.advance(
                slot,
                retire=(
                    not one_stage
                    or had_dispatch is not None
                    or bt.timelock.current_round() >= body.request.response_close_round
                ),
            )
            if result.retirement is None:
                return "pending", result.reason
            if one_stage and had_retirement is None:
                return "pending", "retirement_retained"
            if result.response is None:
                self._stage(work, "replacement_review")
                certificate = await self._call(self.retry(grant, result.retirement))
                # Native selection verifies quorum, exact parent, signed fence,
                # original accepted work and the new live request window.
                self._stage(work, "replacement_preparation")
                await self._prepare(
                    assignment, parent=grant, decision=certificate, retirement=result.retirement
                )
                return "pending", "replacement_selected"
            terminal = await self._prepare_terminal(
                assignment, slot, result.response, result.retirement
            )
        self._stage(work, "terminal_signing")
        signature = await self._call(self.sign(terminal))
        self._stage(work, "terminal_retention")
        await self._local(self.terminals.retain, terminal, signature)
        return "completed", "terminal_retained"

    def _batch(self, *, advance=True):
        with self.journal.transaction() as db:
            row = db.execute(
                "SELECT ordinal FROM service_worker_cursor WHERE singleton=1"
            ).fetchone()
        after = 0 if row is None else row[0]
        rows = self.queue.entries(after_ordinal=after, limit=self.batch_size)
        if not rows and after:
            rows = self.queue.entries(limit=self.batch_size)
        if rows and advance:
            self._advance_cursor(rows[-1].ordinal)
        return rows

    def _advance_cursor(self, ordinal):
        with self.journal.transaction() as db:
            db.execute(
                "INSERT INTO service_worker_cursor VALUES (1,?) "
                "ON CONFLICT(singleton) DO UPDATE SET ordinal=excluded.ordinal",
                (ordinal,),
            )

    async def poll_once(self):
        async with self.serial:
            lease = lock_private_file(self.journal.root / "service-worker.lock")
            try:
                rows = await self._local(self._batch)
                miners = {identity(r.claim.claim.hotkey): asyncio.Lock() for r in rows}
                retries = []

                async def run(admission):
                    async with miners[identity(admission.claim.claim.hotkey)], self.capacity:
                        try:
                            return await self._advance(admission)
                        except _RETRY as error:
                            retries.append(_failure_details(error))
                            return "pending", type(error).__name__

                results = await self._gather(run(row) for row in rows)
                pending = [reason for status, reason in results if status == "pending"]
                examples = []
                for details in retries:
                    if details not in examples and len(examples) < 8:
                        examples.append(details)
                return {
                    "status": "cohort_service_worker",
                    "work_considered": len(rows),
                    "work_complete": sum(status == "completed" for status, _ in results),
                    "work_pending": len(pending),
                    "last_pending_reason": pending[-1] if pending else "",
                    "retry_count": len(retries),
                    "last_retry_details": retries[-1] if retries else [],
                    "retry_examples": examples,
                    "request_closure_authorized": False,
                    "chain_submission_authorized": False,
                }
            finally:
                os.close(lease)

    @staticmethod
    async def _gather(coroutines):
        tasks = [asyncio.create_task(c) for c in coroutines]

        async def collected():
            return await asyncio.gather(*tasks)

        collection = asyncio.create_task(collected())
        try:
            return await await_owned_task(collection, on_cancel=collection.cancel)
        finally:
            await ServiceWorkWorker._stop_tasks(tasks)

    @staticmethod
    async def _stop_tasks(tasks):
        tasks = tuple(tasks)
        for task in tasks:
            task.cancel()

        async def drained():
            await asyncio.gather(*tasks, return_exceptions=True)

        # Repeated shutdown signals must not release the process lease while
        # a signing operation, response write or native transport still runs.
        await await_owned_task(asyncio.create_task(drained()))

    async def _rolling_poll(self, active):
        results, retries = [], []
        for work, (_, task) in tuple(active.items()):
            if not task.done():
                continue
            del active[work]
            status, reason, details = task.result()
            results.append((status, reason))
            if details:
                retries.append(details)

        async def perform(admission):
            work = admission.work_sha256
            self._operation_stages[work] = ("starting", asyncio.get_running_loop().time())
            try:
                status, reason = await self._advance(admission, one_stage=True)
                return status, reason, []
            except _RETRY as error:
                return "pending", type(error).__name__, _failure_details(error)
            finally:
                self._operation_stages.pop(work, None)

        # Each phase owns bounded capacity. Persisted preparation, delivery and
        # retirement boundaries yield before entering another phase, so slow
        # reviewer/proof work cannot consume every ready miner's dispatch slot.
        lanes = ("preparation", "dispatch", "recovery", "certification")
        counts = Counter(self._operation_lanes[work] for work in active)
        for work in tuple(self._operation_lanes):
            if work not in active:
                del self._operation_lanes[work]
        if len(active) < len(lanes) * self.concurrency:
            rows = await self._local(partial(self._batch, advance=False))
            miners = {miner for miner, _ in active.values()}
            last = None
            for admission in rows:
                if all(counts[lane] >= self.concurrency for lane in lanes):
                    break
                last = admission.ordinal
                miner = identity(admission.claim.claim.hotkey)
                work = admission.work_sha256
                if work in active or miner in miners:
                    continue
                lane = await self._local(self._ready_stage, admission)
                if lane == "completed":
                    continue
                if counts[lane] >= self.concurrency:
                    continue
                self._operation_lanes[work] = lane
                counts[lane] += 1
                active[work] = (miner, asyncio.create_task(perform(admission)))
                miners.add(miner)
            if last is not None:
                # Rotate past this inspected page; capacity-blocked work stays
                # accepted and returns on the next complete cursor rotation.
                await self._local(self._advance_cursor, last)

        pending = [reason for status, reason in results if status == "pending"]
        examples = []
        for details in retries:
            if details not in examples and len(examples) < 8:
                examples.append(details)
        stages = [self._operation_stages[work] for work in active if work in self._operation_stages]
        oldest = min(stages, key=lambda value: value[1]) if stages else None
        return {
            "status": "cohort_service_worker",
            "work_considered": len(results),
            "work_complete": sum(status == "completed" for status, _ in results),
            "work_pending": len(pending),
            "in_flight_operations": len(active),
            "phase_capacity": self.concurrency,
            "in_flight_phase_counts": dict(sorted((k, v) for k, v in counts.items() if v)),
            "in_flight_stage_counts": dict(sorted(Counter(stage for stage, _ in stages).items())),
            "oldest_in_flight_stage": "" if oldest is None else oldest[0],
            "oldest_in_flight_stage_seconds": (
                0 if oldest is None else int(asyncio.get_running_loop().time() - oldest[1])
            ),
            "last_pending_reason": pending[-1] if pending else "",
            "retry_count": len(retries),
            "last_retry_details": retries[-1] if retries else [],
            "retry_examples": examples,
            "request_closure_authorized": False,
            "chain_submission_authorized": False,
        }

    async def run(self, stop: asyncio.Event, *, poll_seconds: float = 5, report=None):
        if isinstance(poll_seconds, bool) or not 0 < poll_seconds <= 60:
            raise ValueError("service worker poll interval is outside bounds")
        active = {}
        async with self.serial:
            lease = lock_private_file(self.journal.root / "service-worker.lock")
            try:
                while not stop.is_set():
                    task = asyncio.create_task(self._rolling_poll(active))
                    stopping = asyncio.create_task(stop.wait())
                    try:
                        done, _ = await asyncio.wait(
                            (task, stopping), return_when=asyncio.FIRST_COMPLETED
                        )
                        if stopping in done:
                            return
                        try:
                            result = task.result()
                        except _RETRY as error:
                            result = {
                                "status": "cohort_service_worker_retry",
                                "error_type": type(error).__name__,
                                "last_retry_details": _failure_details(error),
                            }
                        if report is not None:
                            report(result)
                    finally:
                        await self._stop_tasks((task, stopping))
                    with suppress(asyncio.TimeoutError):
                        await asyncio.wait_for(stop.wait(), timeout=poll_seconds)
            finally:
                try:
                    # Own the process lease until every send, signature and
                    # journal write has cooperatively completed cancellation.
                    await self._stop_tasks(task for _, task in active.values())
                finally:
                    os.close(lease)
