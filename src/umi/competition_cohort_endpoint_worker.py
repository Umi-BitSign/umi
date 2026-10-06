"""Drive every acknowledged endpoint assignment without a cumulative deadline.

The inbox inventory and persistent cursors survive restart. Each batch admits
bounded parallel work across miners, with at most one selected case per miner
assignment. Authenticated media, chain and reviewer ports remain host-owned.
"""

from __future__ import annotations

import asyncio
import sqlite3
from collections.abc import Awaitable, Callable
from contextlib import suppress

from .competition_cohort_attempt_worker import CohortEndpointAttemptWorker
from .competition_cohort_endpoint_archive import export_endpoint_archive
from .competition_cohort_endpoint_schedule import CohortEndpointSchedule
from .competition_cohort_execution_journal import CohortExecutionAssignment
from .competition_cohort_order_inbox import CohortOrderInbox
from .competition_progress import _failure_details
from .concurrency import await_owned_task, run_owned_thread, wait_for_owned
from .open_competition import digest, identity
from .policy import ScoringPolicy

_RETRY = (OSError, ValueError, RuntimeError, sqlite3.Error, asyncio.TimeoutError)
TransportPolicySource = Callable[[CohortExecutionAssignment], Awaitable[ScoringPolicy]]


class CohortEndpointWorker:
    def __init__(
        self,
        inbox: CohortOrderInbox,
        attempts: CohortEndpointAttemptWorker,
        transport_policy: TransportPolicySource,
        *,
        batch_size: int = 16,
        concurrency: int = 4,
        maximum_cases: int = 65536,
    ):
        owner = attempts.recovery.journal
        if (
            inbox.policy != owner.policy
            or inbox.cohorts != owner.cohorts
            or identity(inbox.config.signer) != identity(owner.config.signer)
        ):
            raise ValueError("endpoint worker inbox and evaluator bindings differ")
        if (
            type(batch_size) is not int
            or not 1 <= batch_size <= 256
            or type(concurrency) is not int
            or not 1 <= concurrency <= 32
        ):
            raise ValueError("endpoint worker capacity is outside bounds")
        a, b = inbox.journal.root, owner.journal.root
        if a == b or a in b.parents or b in a.parents:
            raise ValueError("endpoint worker and inbox state must remain separate")
        if attempts.requests.video_source is None:
            raise ValueError("endpoint worker requires a renewable video source")
        self.inbox, self.attempts, self.transport_policy = inbox, attempts, transport_policy
        self.schedule = CohortEndpointSchedule(attempts, maximum_cases=maximum_cases)
        self.batch_size = batch_size
        self.concurrency = concurrency
        self._prepare_turn = True
        self.capacity, self.serial = asyncio.Semaphore(concurrency), asyncio.Lock()

    async def _prepare(self, slot):
        schedule, requests = self.schedule, self.attempts.requests
        saved = await run_owned_thread(schedule.load, slot)
        if saved is None:
            assignment = await run_owned_thread(self.inbox.assignment, slot)
            if assignment.certificate.order.submission.submission.track != "endpoint":
                return "ignored", ""
            policy = await wait_for_owned(
                self.transport_policy(assignment),
                timeout=schedule.owner.config.read_timeout_seconds,
            )
            saved = await run_owned_thread(schedule.register, assignment, policy)
        if await run_owned_thread(schedule.complete, slot) is not None:
            await run_owned_thread(export_endpoint_archive, schedule, slot)
            return "completed", ""
        raw = await run_owned_thread(schedule.journal.get, "endpoint_recovery_selection", slot)
        if raw is not None:
            selected, assignment, _ = await run_owned_thread(self.attempts.recovery.selection, slot)
            if (
                assignment != saved.assignment
                or selected.transport_policy != saved.transport_policy
            ):
                raise ValueError("endpoint scheduler changed its selected request")
            return "prepared", ""
        plan = await requests.initial(saved.assignment, saved.transport_policy)
        result = await requests.advance(plan)
        return ("prepared", "") if result.selection is not None else ("pending", result.reason)

    async def poll_once(self) -> dict:
        async with self.serial:
            with self.schedule.owner.locked(digest(["umi-cohort-endpoint-scheduler/1"])):
                return await self._poll()

    async def _inbox_slots(self, *, advance=True):
        schedule = self.schedule
        after = await run_owned_thread(schedule.cursor, "inbox")
        slots = await run_owned_thread(
            lambda: self.inbox.assignments(after=after, limit=self.batch_size)
        )
        if not slots and after:
            slots = await run_owned_thread(lambda: self.inbox.assignments(limit=self.batch_size))
        if slots and advance:
            await run_owned_thread(schedule.advance_inbox, slots[-1])
        return slots

    async def _case(self, row):
        _, slot, case_id = row
        result = await self.attempts.advance(slot, case_id)
        if result["status"] == "completed":
            await run_owned_thread(self.schedule.retain_case, slot, case_id)
            if await run_owned_thread(self.schedule.complete, slot) is not None:
                await run_owned_thread(export_endpoint_archive, self.schedule, slot)
        return result["status"], result["reason"]

    async def _poll(self):
        schedule = self.schedule
        retries = []

        def failed(stage, slot, error):
            retries.append((stage, slot, type(error).__name__, _failure_details(error)))

        slots = ()
        try:
            slots = await self._inbox_slots()
        except _RETRY as error:
            failed("inbox_scan", "", error)

        async def prepare(slot):
            async with self.capacity:
                try:
                    return await self._prepare(slot)
                except _RETRY as error:
                    failed("prepare", slot, error)
                    return "pending", type(error).__name__

        rows = ()
        try:
            rows = await run_owned_thread(schedule.pending, self.batch_size)
        except _RETRY as error:
            failed("case_scan", "", error)

        async def case(row):
            obligation, _, _ = row
            async with self.capacity:
                try:
                    return await self._case(row)
                except _RETRY as error:
                    failed("case", obligation, error)
                    return "pending", type(error).__name__

        # Already selected work must advance before slow discovery/preparation
        # of another inbox page. A cold history replay or unavailable new miner
        # cannot postpone retirement and response recovery for existing cases.
        if rows:
            results = await self._gather(case(row) for row in rows)
            prepared = await self._gather(prepare(slot) for slot in slots)
        else:
            prepared = await self._gather(prepare(slot) for slot in slots)
            try:
                rows = await run_owned_thread(schedule.pending, self.batch_size)
            except _RETRY as error:
                failed("case_scan", "", error)
            results = await self._gather(case(row) for row in rows)
        last = retries[-1] if retries else ("", "", "", [])
        # A later discovery failure must not hide the failure advancing already
        # selected cases. Keep bounded, distinct traces without exception text,
        # endpoint URLs, authentication headers or response bodies.
        retry_examples = []
        for stage, _, error_type, details in retries:
            example = {"stage": stage, "error_type": error_type, "details": details}
            if example not in retry_examples and len(retry_examples) < 8:
                retry_examples.append(example)
        reasons = [reason for status, reason in (*prepared, *results) if status == "pending"]
        return {
            "status": "cohort_endpoint_scheduler",
            "assignments_considered": len(slots),
            "assignments_prepared": sum(status == "prepared" for status, _ in prepared),
            "assignments_complete": sum(status == "completed" for status, _ in prepared),
            "cases_considered": len(rows),
            "cases_completed": sum(status == "completed" for status, _ in results),
            "batch_pending": sum(status == "pending" for status, _ in (*prepared, *results)),
            "retry_count": len(retries),
            "last_retry_stage": last[0],
            "last_retry_slot": last[1],
            "last_retry_type": last[2],
            "last_retry_details": last[3],
            "retry_examples": retry_examples,
            "last_pending_reason": reasons[-1] if reasons else "",
            "request_closure_authorized": False,
            "chain_submission_authorized": False,
        }

    @staticmethod
    async def _gather(coros):
        async def collect():
            tasks = [asyncio.create_task(c) for c in coros]
            try:
                return await asyncio.gather(*tasks)
            finally:
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)

        task = asyncio.create_task(collect())
        return await await_owned_task(task, on_cancel=task.cancel)

    async def run(
        self,
        stop: asyncio.Event,
        *,
        poll_seconds: float = 5,
        report: Callable[[dict], None] | None = None,
    ) -> None:
        if isinstance(poll_seconds, bool) or not 0 < poll_seconds <= 60:
            raise ValueError("endpoint scheduler poll interval is outside bounds")
        active = {}
        async with self.serial:
            # Keep the scheduler owner until every in-flight operation has
            # completed cancellation and durable cleanup. Individual peers do
            # not hold a batch barrier over the next case of a ready miner.
            with self.schedule.owner.locked(digest(["umi-cohort-endpoint-scheduler/1"])):
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
                                    "status": "cohort_endpoint_scheduler_retry",
                                    "error_type": type(error).__name__,
                                    "retry_details": _failure_details(error),
                                    "request_closure_authorized": False,
                                    "chain_submission_authorized": False,
                                }
                            if report is not None:
                                report(result)
                        finally:

                            async def drain_tick(task=task, stopping=stopping):
                                task.cancel()
                                stopping.cancel()
                                await asyncio.gather(task, stopping, return_exceptions=True)

                            await await_owned_task(asyncio.create_task(drain_tick()))
                        with suppress(asyncio.TimeoutError):
                            await asyncio.wait_for(stop.wait(), timeout=poll_seconds)
                finally:

                    async def drain_operations():
                        for _, task in active.values():
                            task.cancel()
                        await asyncio.gather(
                            *(task for _, task in active.values()), return_exceptions=True
                        )

                    await await_owned_task(asyncio.create_task(drain_operations()))

    async def _rolling_poll(self, active):
        results, retries = [], []
        for slot, (stage, task) in tuple(active.items()):
            if not task.done():
                continue
            del active[slot]
            status, reason, details = task.result()
            results.append((stage, status, reason))
            if details:
                retries.append((stage, reason, details))

        async def perform(operation):
            try:
                status, reason = await operation()
                return status, reason, []
            except _RETRY as error:
                return "pending", type(error).__name__, _failure_details(error)

        def start(stage, slot, operation):
            active[slot] = (stage, asyncio.create_task(perform(operation)))

        # Reserve one discovery slot when capacity permits. With a single slot,
        # alternate preparation and cases; repeated pending cases cannot starve
        # assignments whose request selection has not yet been built.
        if (
            len(active) < self.concurrency
            and not any(stage == "prepare" for stage, _ in active.values())
            and (self.concurrency > 1 or self._prepare_turn)
        ):
            slots = await self._inbox_slots(advance=False)
            chosen = None
            for slot in slots:
                if slot in active:
                    continue
                selected = await run_owned_thread(
                    self.schedule.journal.get, "endpoint_recovery_selection", slot
                )
                terminal = await run_owned_thread(
                    self.schedule.journal.get, "endpoint_terminal_selection", slot
                )
                archive = await run_owned_thread(
                    self.schedule.journal.get, "endpoint_replay_archive", slot
                )
                if selected is not None and (terminal is None or archive is not None):
                    continue
                chosen = slot
                start("prepare", slot, lambda slot=slot: self._prepare(slot))
                self._prepare_turn = False
                break
            if chosen is not None or slots:
                # Do not skip a whole inbox page when only one operation was
                # admitted. A crash keeps the inbox and exact requests intact.
                await run_owned_thread(self.schedule.advance_inbox, chosen or slots[-1])

        if len(active) < self.concurrency:
            rows = await run_owned_thread(self.schedule.pending, self.batch_size)
            for row in rows:
                slot = row[1]
                if len(active) >= self.concurrency:
                    break
                if slot in active:
                    continue
                selected = await run_owned_thread(
                    self.schedule.journal.get, "endpoint_recovery_selection", slot
                )
                if selected is not None:
                    start("case", slot, lambda row=row: self._case(row))
                    self._prepare_turn = True
            if not active:
                self._prepare_turn = True

        last = retries[-1] if retries else ("", "", [])
        return {
            "status": "cohort_endpoint_scheduler",
            "assignments_considered": sum(stage == "prepare" for stage, _, _ in results),
            "assignments_prepared": sum(
                stage == "prepare" and status == "prepared" for stage, status, _ in results
            ),
            "assignments_complete": sum(
                stage == "prepare" and status == "completed" for stage, status, _ in results
            ),
            "cases_considered": sum(stage == "case" for stage, _, _ in results),
            "cases_completed": sum(
                stage == "case" and status == "completed" for stage, status, _ in results
            ),
            "batch_pending": sum(status == "pending" for _, status, _ in results),
            "in_flight_operations": len(active),
            "retry_count": len(retries),
            "last_retry_stage": last[0],
            "last_retry_type": last[1],
            "last_retry_details": last[2],
            "retry_examples": [
                {"stage": stage, "error_type": reason, "details": details}
                for stage, reason, details in retries[:8]
            ],
            "last_pending_reason": next(
                (reason for _, status, reason in reversed(results) if status == "pending"), ""
            ),
            "request_closure_authorized": False,
            "chain_submission_authorized": False,
        }
