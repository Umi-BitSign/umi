"""Continuous recovery of accepted cohort model and comparator work.

The host owns current history/finality, the private inbox and the pinned sandbox.
Execution writes no weights and receives no reference text or signing key.
"""

from __future__ import annotations

import asyncio
import sqlite3
from collections.abc import Awaitable, Callable
from contextlib import suppress
from typing import Protocol

from .competition_cohort_execution import RecoverableExecutionEvidence, RecoverableExecutionJob
from .competition_cohort_execution_journal import (
    CohortExecutionAssignment,
    CohortExecutionAttempt,
    CohortExecutionJournal,
    step_count,
)
from .competition_cohort_order_inbox import CohortOrderInbox
from .competition_cohort_order_signer import (
    CohortOrderHistory,
    OrderFinality,
    order_slot,
    remember_order_history,
    review_order,
)
from .competition_execution import ExecutionBoundary, execution_boundary
from .competition_runner import OfflineCaseExecution
from .concurrency import run_owned_thread, wait_for_owned
from .open_competition import identity
from .protocol import canonical_json_bytes


class CohortSandbox(Protocol):
    async def reconcile(
        self, job: RecoverableExecutionJob, attempt: CohortExecutionAttempt
    ) -> None: ...
    async def invoke(
        self, job: RecoverableExecutionJob, attempt: CohortExecutionAttempt
    ) -> OfflineCaseExecution: ...


class CohortExecutionAuthority:
    def __init__(
        self,
        journal: CohortExecutionJournal,
        provider: OrderFinality,
        history: Callable[[str], Awaitable[CohortOrderHistory]],
    ):
        if provider.policy != journal.policy:
            raise ValueError("execution finality belongs to another policy")
        self.journal, self.provider, self.history = journal, provider, history

    async def current(
        self, assignment: CohortExecutionAssignment
    ) -> tuple[CohortOrderHistory, ExecutionBoundary]:
        timeout = self.journal.config.read_timeout_seconds
        cohort = assignment.certificate.order.round.cohort_sha256
        source = await wait_for_owned(self.history(cohort), timeout=timeout)
        boundary = execution_boundary(
            await wait_for_owned(self.provider.collect(), timeout=timeout)
        )
        # Local authenticated replay must be allowed to finish. An overall
        # timeout here would repeatedly discard a valid but slow verification.
        await run_owned_thread(
            remember_order_history,
            self.journal.journal,
            self.journal.cohorts,
            self.journal.policy,
            source,
            boundary.block,
        )
        await run_owned_thread(
            review_order,
            assignment.certificate.order,
            assignment.participant,
            source,
            self.journal.policy,
            boundary.block,
        )
        current = await wait_for_owned(self.history(cohort), timeout=timeout)
        if current != source:
            boundary = execution_boundary(
                await wait_for_owned(self.provider.collect(), timeout=timeout)
            )
            await run_owned_thread(
                remember_order_history,
                self.journal.journal,
                self.journal.cohorts,
                self.journal.policy,
                current,
                boundary.block,
            )
            raise OSError("cohort authority changed before execution progress")
        return source, boundary


class CohortExecutor(CohortExecutionAuthority):
    def __init__(
        self,
        journal: CohortExecutionJournal,
        provider: OrderFinality,
        history: Callable[[str], Awaitable[CohortOrderHistory]],
        sandbox: CohortSandbox,
    ):
        super().__init__(journal, provider, history)
        self.sandbox = sandbox

    async def advance(
        self, assignment: CohortExecutionAssignment
    ) -> RecoverableExecutionEvidence | None:
        """Finish at most one unfinished case/role, retaining every completed step."""
        assignment = CohortExecutionAssignment.model_validate_json(canonical_json_bytes(assignment))
        slot = order_slot(assignment.certificate.order)
        with self.journal.locked(slot):
            existing = await run_owned_thread(self.journal.journal.get, "assignment", slot)
            if existing is not None:
                if canonical_json_bytes(existing) != canonical_json_bytes(assignment):
                    raise ValueError("execution slot already contains another assignment")
                evidence = await run_owned_thread(self.journal.evidence, slot)
                if evidence is not None:
                    return evidence
            source, started = await self.current(assignment)
            job = await run_owned_thread(self.journal.retain, assignment, source, started.block)
            for index in range(step_count(job)):
                if await run_owned_thread(self.journal.step, job, index) is None:
                    break
            else:
                return await run_owned_thread(self.journal.evidence, slot)
            attempt = await run_owned_thread(self.journal.head, job, index)
            pending = (
                None
                if attempt is None
                else await run_owned_thread(self.journal.result, job, attempt)
            )
            if pending is None:
                if attempt is not None:
                    # No replacement while an uncertain prior sandbox can still run.
                    await wait_for_owned(self.sandbox.reconcile(job, attempt), timeout=30)
                    await run_owned_thread(self.journal.stopped, attempt)
                    source, started = await self.current(assignment)
                attempt = await run_owned_thread(self.journal.begin, job, index, source, started)

                async def invoke_and_retain():
                    result = await self.sandbox.invoke(job, attempt)
                    await run_owned_thread(self.journal.observe, job, attempt, result)

                # The signed per-inference limit is enforced by the sandbox. This
                # outer transport/cleanup allowance never expires the whole job.
                await wait_for_owned(invoke_and_retain(), timeout=job_policy_timeout(self.journal))
            _, finished = await self.current(assignment)
            await run_owned_thread(self.journal.finish, job, attempt, finished)
            return await run_owned_thread(self.journal.evidence, slot)


def job_policy_timeout(journal: CohortExecutionJournal) -> float:
    return journal.policy.maximum_inference_ms / 1000 + 60


class CohortExecutionWorker:
    def __init__(
        self, inbox: CohortOrderInbox, executor: CohortExecutor, *, batch_size=16, concurrency=4
    ):
        if (
            inbox.policy != executor.journal.policy
            or inbox.config.cohorts != executor.journal.config.cohorts
            or identity(inbox.config.signer) != identity(executor.journal.config.signer)
        ):
            raise ValueError("execution worker inbox and authority bindings differ")
        if (
            type(batch_size) is not int
            or not 1 <= batch_size <= 256
            or type(concurrency) is not int
            or not 1 <= concurrency <= 32
        ):
            raise ValueError("execution worker capacity is outside bounds")
        if (
            inbox.journal.root == executor.journal.journal.root
            or inbox.journal.root in executor.journal.journal.root.parents
            or executor.journal.journal.root in inbox.journal.root.parents
        ):
            raise ValueError("execution and inbox state must remain separate")
        self.inbox, self.executor, self.batch_size = inbox, executor, batch_size
        self.capacity = asyncio.Semaphore(concurrency)
        self.serial = asyncio.Lock()

    async def poll_once(self):
        async with self.serial:
            journal = self.executor.journal.journal

            def cursor():
                with journal.transaction() as db:
                    rows = db.execute("SELECT slot FROM execution_cursor LIMIT 2").fetchall()
                    if len(rows) > 1:
                        raise ValueError("execution cursor is invalid")
                    return rows[0][0] if rows else ""

            after = await run_owned_thread(cursor)
            slots = await run_owned_thread(
                lambda: self.inbox.assignments(after=after, limit=self.batch_size)
            )
            if not slots and after:
                slots = await run_owned_thread(
                    lambda: self.inbox.assignments(limit=self.batch_size)
                )
            if slots:

                def advance():
                    with journal.transaction() as db:
                        db.execute("DELETE FROM execution_cursor")
                        db.execute("INSERT INTO execution_cursor VALUES (?)", (slots[-1],))

                await run_owned_thread(advance)

            async def one(slot):
                async with self.capacity:
                    try:
                        assignment = await run_owned_thread(self.inbox.assignment, slot)
                        result = await self.executor.advance(assignment)
                        return slot, "complete" if result is not None else "progress", ""
                    except (OSError, ValueError, RuntimeError, sqlite3.Error) as error:
                        return slot, "pending", type(error).__name__

            tasks = [asyncio.create_task(one(slot)) for slot in slots]
            try:
                results = await asyncio.gather(*tasks)
            finally:
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
            pending = [r for r in results if r[1] == "pending"]
            return {
                "status": "cohort_execution_pending" if pending else "cohort_execution_current",
                "jobs_complete": sum(r[1] == "complete" for r in results),
                "steps_advanced": sum(r[1] == "progress" for r in results),
                "retry_count": len(pending),
                "last_retry_slot": pending[-1][0] if pending else "",
                "last_retry_type": pending[-1][2] if pending else "",
                "chain_submission_authorized": False,
            }

    async def run(
        self,
        stop: asyncio.Event,
        *,
        poll_seconds: float = 5,
        report: Callable[[dict], None] | None = None,
    ):
        if isinstance(poll_seconds, bool) or not 0 < poll_seconds <= 60:
            raise ValueError("execution poll interval is outside bounds")
        while not stop.is_set():
            task, stopping = asyncio.create_task(self.poll_once()), asyncio.create_task(stop.wait())
            try:
                done, _ = await asyncio.wait((task, stopping), return_when=asyncio.FIRST_COMPLETED)
                if stopping in done:
                    return
                try:
                    result = task.result()
                except (OSError, ValueError, RuntimeError, sqlite3.Error) as error:
                    result = {
                        "status": "cohort_execution_pending",
                        "last_retry_type": type(error).__name__,
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
