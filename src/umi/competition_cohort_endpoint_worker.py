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

    async def _poll(self):
        schedule = self.schedule
        retries = []

        def failed(stage, slot, error):
            retries.append((stage, slot, type(error).__name__))

        slots = ()
        try:
            after = await run_owned_thread(schedule.cursor, "inbox")
            slots = await run_owned_thread(
                lambda: self.inbox.assignments(after=after, limit=self.batch_size)
            )
            if not slots and after:
                slots = await run_owned_thread(
                    lambda: self.inbox.assignments(limit=self.batch_size)
                )
            if slots:
                # Move the cursor before external reads. Accepted assignments
                # remain in the inbox and are revisited after wrap or restart.
                await run_owned_thread(schedule.advance_inbox, slots[-1])
        except _RETRY as error:
            failed("inbox_scan", "", error)

        async def prepare(slot):
            async with self.capacity:
                try:
                    return await self._prepare(slot)
                except _RETRY as error:
                    failed("prepare", slot, error)
                    return "pending", type(error).__name__

        prepared = await self._gather(prepare(slot) for slot in slots)
        rows = ()
        try:
            rows = await run_owned_thread(schedule.pending, self.batch_size)
        except _RETRY as error:
            failed("case_scan", "", error)

        async def case(row):
            obligation, slot, case_id = row
            async with self.capacity:
                try:
                    result = await self.attempts.advance(slot, case_id)
                    if result["status"] == "completed":
                        await run_owned_thread(schedule.retain_case, slot, case_id)
                        if await run_owned_thread(schedule.complete, slot) is not None:
                            await run_owned_thread(export_endpoint_archive, schedule, slot)
                    return result["status"], result["reason"]
                except _RETRY as error:
                    failed("case", obligation, error)
                    return "pending", type(error).__name__

        results = await self._gather(case(row) for row in rows)
        last = retries[-1] if retries else ("", "", "")
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
        while not stop.is_set():
            task, stopping = asyncio.create_task(self.poll_once()), asyncio.create_task(stop.wait())
            try:
                done, _ = await asyncio.wait((task, stopping), return_when=asyncio.FIRST_COMPLETED)
                if stopping in done:
                    return
                try:
                    result = task.result()
                except _RETRY as error:
                    result = {
                        "status": "cohort_endpoint_scheduler_retry",
                        "error_type": type(error).__name__,
                        "request_closure_authorized": False,
                        "chain_submission_authorized": False,
                    }
                if report is not None:
                    report(result)
            finally:

                async def drain(task=task, stopping=stopping):
                    task.cancel()
                    stopping.cancel()
                    await asyncio.gather(task, stopping, return_exceptions=True)

                await await_owned_task(asyncio.create_task(drain()))
            with suppress(asyncio.TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=poll_seconds)
