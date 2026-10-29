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

from .competition_cohort_execution import (
    RecoverableExecutionEvidence,
    RecoverableExecutionJob,
    RecoverableSharedIncumbentEvidence,
)
from .competition_cohort_execution_journal import (
    CohortExecutionAssignment,
    CohortExecutionAttempt,
    CohortExecutionJournal,
    ExecutionScopeState,
    IncumbentSourcePending,
    step_count,
)
from .competition_cohort_execution_retry import (
    resident_execution_retries,
    retry_resident_operation,
)
from .competition_cohort_order_inbox import CohortOrderInbox
from .competition_cohort_order_signer import (
    CohortOrderHistory,
    OrderFinality,
    order_slot,
    remember_closed_order_history,
    remember_order_history,
    review_order,
)
from .competition_execution import ExecutionBoundary, execution_boundary
from .competition_progress import report_execution_retry
from .competition_round_journal import FinalizedHeadRegression
from .competition_runner import OfflineCaseExecution
from .competition_transport_verification import TransferProgress
from .competition_verification_reuse import VerificationReuse
from .competition_work_progress import await_progress, review_scope
from .concurrency import await_owned_task, run_owned_thread, wait_for_owned
from .open_competition import digest, identity
from .protocol import canonical_json_bytes

SANDBOX_RECONCILIATION_TIMEOUT_SECONDS = 300


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
        self.verification_reuse = VerificationReuse(
            journal.journal.root / "authority-verification",
            owner={
                "schema": "umi-execution-authority-verification/1",
                "policy": digest(journal.policy),
                "cohorts": journal.cohorts,
                "signer": identity(journal.config.signer),
            },
        )

    def _verified(self, function, *args):
        source = next(value for value in args if isinstance(value, CohortOrderHistory))
        with (
            review_scope("execution_authority", digest(source.history.plan), reads=0),
            self.verification_reuse.selected(),
        ):
            return function(*args)

    async def current(
        self, assignment: CohortExecutionAssignment
    ) -> tuple[CohortOrderHistory, ExecutionBoundary]:
        # Other owned operations can advance this shared journal after proof
        # collection. Repeat the complete authority observation once, rather
        # than using the journal's head as a substitute for owned finality.
        for attempt in range(2):
            try:
                return await self._current(assignment)
            except FinalizedHeadRegression:
                if attempt:
                    raise
        raise AssertionError("execution authority exhausted without a result")

    async def _current(
        self, assignment: CohortExecutionAssignment
    ) -> tuple[CohortOrderHistory, ExecutionBoundary]:
        timeout = self.journal.config.read_timeout_seconds
        cohort = assignment.certificate.order.round.cohort_sha256
        source = await await_progress(
            retry_resident_operation(
                lambda: wait_for_owned(self.history(cohort), timeout=timeout), history=True
            ),
            stage="execution_owner_history",
            cohort=cohort,
        )
        closed = await await_progress(
            run_owned_thread(
                self._verified,
                remember_closed_order_history,
                self.journal.journal,
                self.journal.cohorts,
                self.journal.policy,
                source,
            ),
            stage="execution_history_phase",
            cohort=cohort,
        )
        if closed:
            raise ValueError("new order signatures require an open request phase")
        boundary = execution_boundary(
            await await_progress(
                wait_for_owned(self.provider.collect(), timeout=timeout),
                stage="execution_registration_capture",
                cohort=cohort,
            )
        )
        # Local authenticated replay must be allowed to finish. An overall
        # timeout here would repeatedly discard a valid but slow verification.
        await await_progress(
            run_owned_thread(
                self._verified,
                remember_order_history,
                self.journal.journal,
                self.journal.cohorts,
                self.journal.policy,
                source,
                boundary.block,
            ),
            stage="execution_history_review",
            cohort=cohort,
        )
        await await_progress(
            run_owned_thread(
                self._verified,
                review_order,
                assignment.certificate.order,
                assignment.participant,
                source,
                self.journal.policy,
                boundary.block,
            ),
            stage="execution_order_review",
            cohort=cohort,
        )
        current = await await_progress(
            retry_resident_operation(
                lambda: wait_for_owned(self.history(cohort), timeout=timeout), history=True
            ),
            stage="execution_history_freshness",
            cohort=cohort,
        )
        if current != source:
            boundary = execution_boundary(
                await wait_for_owned(self.provider.collect(), timeout=timeout)
            )
            await run_owned_thread(
                self._verified,
                remember_order_history,
                self.journal.journal,
                self.journal.cohorts,
                self.journal.policy,
                current,
                boundary.block,
            )
            raise OSError("cohort authority changed before execution progress")
        preparation = next(
            signed.transition
            for signed in source.history.transitions
            if digest(signed.transition) == assignment.certificate.order.preparation_closure_sha256
        )
        if boundary.block <= preparation.observed_at_block:
            # Native terminal replay requires every invocation/request to begin
            # strictly after preparation. A fast worker can observe the same
            # head that certified preparation; retain no attempt until it moves.
            raise OSError("waiting for finalized block after cohort preparation")
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

    async def _journal_progress(self, assignment, operation, *args):
        cohort = (
            assignment.round.cohort_sha256
            if isinstance(assignment, RecoverableExecutionJob)
            else assignment.certificate.order.round.cohort_sha256
        )
        with review_scope("execution_journal", cohort, reads=0):
            return await await_progress(
                run_owned_thread(operation, *args),
                stage="execution_journal_" + operation.__name__,
                cohort=cohort,
            )

    async def _first_unfinished(self, job):
        return await run_owned_thread(self.journal.first_unfinished, job)

    async def advance_batch(
        self, assignment: CohortExecutionAssignment
    ) -> RecoverableExecutionEvidence | None:
        """Drain one resident paired job, preserving the ordinary per-step path."""
        scope = getattr(self.sandbox, "execution_scope", None)
        if scope is None:
            return await self.advance(assignment)
        slot = order_slot(assignment.certificate.order)
        role_aware = getattr(self.sandbox, "execution_scope_roles", False)
        state = await self._completed(assignment, slot, scope_state=role_aware)
        evidence = state.evidence if role_aware and state is not None else state
        if evidence is not None:
            return evidence
        job = await self._journal_progress(assignment, self.journal.validate_assignment, assignment)
        scope_options = {}
        if role_aware and state is not None:
            scope_options["model_roles"] = state.model_roles
        if job.mode == "paired_model" and job.incumbent_observation_mode is not None:
            status = getattr(self.journal, "incumbent_source_status", None)
            if status is None:
                raise RuntimeError("shared incumbent scheduling requires its journal reader")
            readiness = await self._journal_progress(job, status, slot, job)
            if readiness == "pending":
                raise IncumbentSourcePending("shared incumbent source remains unfinished")
            if readiness == "unselected":
                # The first source uses the ordinary authenticated reservation
                # before any model resources. Supported caches first check their
                # source plans and fixed size bounds, without acquiring capacity.
                async def before_reserve():
                    with self.journal.locked(slot):
                        if role_aware:
                            prepared = await self._prepare_scope(assignment, slot)
                            return prepared.model_roles
                        await self._prepare_current(assignment, slot)

                if getattr(self.sandbox, "execution_scope_before_reserve", False):
                    scope_options["before_reserve"] = before_reserve
                else:
                    # Legacy/simple scopes have no pre-reservation cache checks.
                    await before_reserve()
            elif readiness != "ready":
                raise RuntimeError("shared incumbent scheduling status is invalid")
            elif role_aware and (state is None or state.model_roles != ("candidate",)):
                # A ready hint also includes first producers. Only the ordinary
                # current-authority/reuse path may establish candidate-only work.
                with self.journal.locked(slot):
                    prepared = await self._prepare_scope(assignment, slot)
                if prepared.evidence is not None:
                    return prepared.evidence
                scope_options["model_roles"] = prepared.model_roles
        scope_input = (
            job
            if getattr(self.sandbox, "prepared_execution_scope", False)
            else (assignment.certificate.order)
        )
        async with scope(scope_input, **scope_options) as enabled:
            if not enabled:
                return await self.advance(assignment)
            total = step_count(job)
            restored = await self._journal_progress(job, self.journal.checkpoint_count, job)
            reused = await self._journal_progress(job, self.journal.reused_checkpoint_count, job)
            with (
                resident_execution_retries(slot, self.journal.config.read_timeout_seconds),
                TransferProgress(
                    "model_pair_execution",
                    total,
                    unit="case_role_steps",
                    planning_unit_seconds=(1, job_policy_timeout(self.journal)),
                    idle_stall_seconds=job_policy_timeout(self.journal),
                ) as progress,
            ):
                progress.advance(restored, restored=True)
                # Each ordinary advance finishes at most one step. The extra
                # iteration covers an already-complete retained job; this is a
                # finite scheduling batch, not a new deadline or protocol gate.
                for _ in range(total - restored + 1):
                    result = await self.advance(assignment)
                    completed = await self._journal_progress(
                        job, self.journal.checkpoint_count, job
                    )
                    current_reused = await self._journal_progress(
                        job, self.journal.reused_checkpoint_count, job
                    )
                    if current_reused > reused:
                        progress.advance(current_reused - reused, restored=True)
                        reused = current_reused
                    if completed > progress.completed:
                        progress.advance(completed - progress.completed)
                    if result is not None:
                        return result
                raise RuntimeError("paired execution batch did not finish its retained steps")

    async def _completed(
        self, assignment: CohortExecutionAssignment, slot: str, *, scope_state=False
    ) -> (
        RecoverableExecutionEvidence
        | RecoverableSharedIncumbentEvidence
        | ExecutionScopeState
        | None
    ):
        existing = await run_owned_thread(self.journal.journal.get, "assignment", slot)
        if existing is not None:
            if canonical_json_bytes(existing) != canonical_json_bytes(assignment):
                raise ValueError("execution slot already contains another assignment")
            reader = self.journal.execution_scope_state if scope_state else self.journal.evidence
            return await run_owned_thread(reader, slot)
        return None

    async def _retain_current(self, assignment):
        source, started = await self.current(assignment)
        job = await self._journal_progress(
            assignment, self.journal.retain, assignment, source, started.block
        )
        return job, source, started

    async def _prepare_scope(self, assignment, slot):
        job, _, started = await self._retain_current(assignment)
        return await self._journal_progress(
            job, self.journal.prepare_execution_scope, slot, job, started
        )

    async def _prepare_current(self, assignment, slot):
        job, source, started = await self._retain_current(assignment)
        shared = await self._journal_progress(job, self.journal.reuse_incumbent, slot, job, started)
        return job, source, started, shared

    async def advance(
        self, assignment: CohortExecutionAssignment
    ) -> RecoverableExecutionEvidence | None:
        """Finish at most one unfinished case/role, retaining every completed step."""
        assignment = CohortExecutionAssignment.model_validate_json(canonical_json_bytes(assignment))
        slot = order_slot(assignment.certificate.order)
        # Completed evidence is immutable. Recurring readers must not compete
        # with endpoint recovery or terminal signing for the execution lock.
        evidence = await self._completed(assignment, slot)
        if evidence is not None:
            return evidence
        with self.journal.locked(slot):
            evidence = await self._completed(assignment, slot)
            if evidence is not None:
                return evidence
            job, source, started, shared = await self._prepare_current(assignment, slot)
            if shared is not None:
                return shared
            with review_scope("execution_journal", job.round.cohort_sha256, reads=0):
                index = await await_progress(
                    self._first_unfinished(job),
                    stage="execution_checkpoint_lookup",
                    cohort=job.round.cohort_sha256,
                )
            if index is None:
                return await self._journal_progress(job, self.journal.evidence, slot)
            attempt = await self._journal_progress(job, self.journal.head, job, index)
            pending = (
                None
                if attempt is None
                else await self._journal_progress(job, self.journal.result, job, attempt)
            )
            if pending is None:
                if attempt is not None:
                    # No replacement while an uncertain prior sandbox can still run.
                    await wait_for_owned(
                        self.sandbox.reconcile(job, attempt),
                        timeout=SANDBOX_RECONCILIATION_TIMEOUT_SECONDS,
                    )
                    await self._journal_progress(job, self.journal.stopped, attempt)
                    source, started = await self.current(assignment)
                attempt = await self._journal_progress(
                    job, self.journal.begin, job, index, source, started
                )

                async def invoke_and_retain():
                    result = await await_progress(
                        self.sandbox.invoke(job, attempt),
                        stage="execution_sandbox",
                        cohort=job.round.cohort_sha256,
                    )
                    # Drain the owned persistence attempt before cancellation
                    # releases the job lock; recovery reuses the exact result,
                    # exhaustion preserves the existing failure path.
                    await await_owned_task(
                        asyncio.create_task(
                            retry_resident_operation(
                                lambda: self._journal_progress(
                                    job, self.journal.observe, job, attempt, result
                                )
                            )
                        )
                    )

                # Restoration and shared cache queues precede inference. Give
                # them the configured read budget without consuming the signed
                # inference limit, which the sandbox enforces independently.
                await wait_for_owned(invoke_and_retain(), timeout=job_policy_timeout(self.journal))
            _, finished = await self.current(assignment)
            await self._journal_progress(job, self.journal.finish, job, attempt, finished)
            return await self._journal_progress(job, self.journal.evidence, slot)


def job_policy_timeout(journal: CohortExecutionJournal) -> float:
    return journal.config.read_timeout_seconds + journal.policy.maximum_inference_ms / 1000 + 60


class CohortExecutionWorker:
    def __init__(
        self,
        inbox: CohortOrderInbox,
        executor: CohortExecutor,
        *,
        batch_size=16,
        concurrency=4,
        defer_endpoint_until_terminal=False,
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
            or type(defer_endpoint_until_terminal) is not bool
        ):
            raise ValueError("execution worker capacity is outside bounds")
        if (
            inbox.journal.root == executor.journal.journal.root
            or inbox.journal.root in executor.journal.journal.root.parents
            or executor.journal.journal.root in inbox.journal.root.parents
        ):
            raise ValueError("execution and inbox state must remain separate")
        self.inbox, self.executor, self.batch_size = inbox, executor, batch_size
        self.concurrency = concurrency
        self.defer_endpoint_until_terminal = defer_endpoint_until_terminal
        self.capacity = asyncio.Semaphore(concurrency)
        # All assignments share one private inbox lock. Parallel sandbox jobs
        # must not make their own local reads compete for that nonblocking lock.
        self.inbox_reads = asyncio.Lock()
        self.serial = asyncio.Lock()
        self.source_priority_due = True
        self.resume_priority_due = True

    def _startup_resume(self):
        if not self.resume_priority_due:
            return ()
        try:
            inventory = getattr(self.executor.sandbox, "resume_model_revisions", None)
            revisions = () if inventory is None else inventory()
            slots = (
                self.inbox.assignments_for_models(
                    revisions,
                    limit=min(self.concurrency, self.batch_size),
                    preferred=self.executor.journal.recent_assignment_slots(),
                )
                if revisions
                else ()
            )
        except (OSError, ValueError, sqlite3.Error) as error:
            # Hints cannot suppress ordinary acknowledged work. Surface the
            # inventory issue; normal execution still enforces all cache and
            # journal checks rather than treating it as successful verification.
            report_execution_retry(slot=None, error=error)
            slots = ()
        # Give preserved work one turn. A failing hint cannot monopolize later
        # batches, and an out-of-order resume never advances the ordinary cursor.
        self.resume_priority_due = False
        return slots

    async def poll_once(self):
        async with self.serial:
            journal = self.executor.journal.journal

            def cursor():
                with journal.transaction() as db:
                    rows = db.execute("SELECT slot FROM execution_cursor LIMIT 2").fetchall()
                    if len(rows) > 1:
                        raise ValueError("execution cursor is invalid")
                    return rows[0][0] if rows else ""

            resumed = await run_owned_thread(self._startup_resume)
            after = await run_owned_thread(cursor)
            slots = resumed or await run_owned_thread(
                lambda: self.inbox.assignments(after=after, limit=self.batch_size)
            )
            if not slots and after:
                slots = await run_owned_thread(
                    lambda: self.inbox.assignments(limit=self.batch_size)
                )
            if slots and not resumed:

                def advance():
                    with journal.transaction() as db:
                        db.execute("DELETE FROM execution_cursor")
                        db.execute("INSERT INTO execution_cursor VALUES (?)", (slots[-1],))

                await run_owned_thread(advance)

            tasks = [asyncio.create_task(self._one(slot)) for slot in slots]
            try:
                results = await asyncio.gather(*tasks)
            finally:
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
            pending = [r for r in results if r[1] == "pending"]
            deferred = [r for r in results if r[1] == "deferred"]
            return {
                "status": (
                    "cohort_execution_pending"
                    if pending or deferred
                    else "cohort_execution_current"
                ),
                "jobs_complete": sum(r[1] == "complete" for r in results),
                "steps_advanced": sum(r[1] == "progress" for r in results),
                "jobs_deferred": len(deferred),
                "retry_count": len(pending),
                "last_retry_slot": pending[-1][0] if pending else "",
                "last_retry_type": pending[-1][2] if pending else "",
                "last_deferred_reason": deferred[-1][2] if deferred else "",
                "chain_submission_authorized": False,
            }

    async def _one(self, slot):
        async with self.capacity:
            journal = self.executor.journal.journal
            try:
                async with self.inbox_reads:
                    assignment = await run_owned_thread(self.inbox.assignment, slot)
                if self.defer_endpoint_until_terminal:
                    job = await run_owned_thread(
                        self.executor.journal.validate_assignment, assignment
                    )
                    if (
                        job.mode == "endpoint_incumbent"
                        and await run_owned_thread(journal.get, "endpoint_terminal_selection", slot)
                        is None
                    ):
                        # Endpoint origin capture and local incumbent execution
                        # share the assignment authority lock. Let the miner
                        # request become terminal before beginning a long local
                        # inference so the two workers cannot starve each other.
                        return slot, "deferred", "endpoint_terminal_pending"
                advance = getattr(self.executor, "advance_batch", self.executor.advance)
                result = await advance(assignment)
                return slot, "complete" if result is not None else "progress", ""
            except IncumbentSourcePending:
                return slot, "deferred", "incumbent_source_pending"
            except (
                OSError,
                ValueError,
                RuntimeError,
                sqlite3.Error,
                asyncio.TimeoutError,
            ) as error:
                report_execution_retry(slot=slot, error=error)
                return slot, "pending", type(error).__name__

    async def _rolling_poll(self, active):
        results = []
        for slot, task in tuple(active.items()):
            if task.done():
                results.append(task.result())
                del active[slot]
        if len(active) < self.concurrency:
            journal = self.executor.journal.journal

            def scan():
                with journal.transaction() as db:
                    rows = db.execute("SELECT slot FROM execution_cursor LIMIT 2").fetchall()
                    if len(rows) > 1:
                        raise ValueError("execution cursor is invalid")
                    after = rows[0][0] if rows else ""
                available = self.concurrency - len(active)
                chosen = [slot for slot in self._startup_resume() if slot not in active][:available]
                # One fixed source unlocks many consumers. Revisit it promptly
                # rather than putting each of its steps behind the whole roster.
                # Keep peer capacity; a single-slot host alternates with normal
                # work even if this source is repeatedly unavailable.
                if len(chosen) < available and (self.concurrency > 1 or self.source_priority_due):
                    sources = self.executor.journal.unfinished_incumbent_sources()
                    chosen.extend(
                        [slot for slot in sources if slot not in active and slot not in chosen][:1]
                    )
                self.source_priority_due = not bool(chosen)
                last = None
                if len(chosen) < available:
                    slots = self.inbox.assignments(after=after, limit=self.batch_size)
                    if not slots and after:
                        slots = self.inbox.assignments(limit=self.batch_size)
                    for slot in slots:
                        last = slot
                        if slot not in active and slot not in chosen:
                            chosen.append(slot)
                        if len(chosen) >= available:
                            break
                if last is not None:
                    with journal.transaction() as db:
                        db.execute("DELETE FROM execution_cursor")
                        db.execute("INSERT INTO execution_cursor VALUES (?)", (last,))
                return chosen

            async with self.inbox_reads:
                slots = await run_owned_thread(scan)
            for slot in slots:
                active[slot] = asyncio.create_task(self._one(slot))
        pending = [r for r in results if r[1] == "pending"]
        deferred = [r for r in results if r[1] == "deferred"]
        return {
            "status": "cohort_execution_pending"
            if pending or deferred or active
            else "cohort_execution_current",
            "jobs_complete": sum(r[1] == "complete" for r in results),
            "steps_advanced": sum(r[1] == "progress" for r in results),
            "jobs_deferred": len(deferred),
            "in_flight_operations": len(active),
            "retry_count": len(pending),
            "last_retry_slot": pending[-1][0] if pending else "",
            "last_retry_type": pending[-1][2] if pending else "",
            "last_deferred_reason": deferred[-1][2] if deferred else "",
            "chain_submission_authorized": False,
        }

    @staticmethod
    async def _drain(tasks):
        tasks = tuple(tasks)
        for task in tasks:
            task.cancel()

        async def drained():
            await asyncio.gather(*tasks, return_exceptions=True)

        # Keep the process alive until owned sandbox writes and cleanup drain,
        # even if repeated shutdown signals arrive.
        await await_owned_task(asyncio.create_task(drained()))

    async def run(
        self,
        stop: asyncio.Event,
        *,
        poll_seconds: float = 5,
        report: Callable[[dict], None] | None = None,
    ):
        if isinstance(poll_seconds, bool) or not 0 < poll_seconds <= 60:
            raise ValueError("execution poll interval is outside bounds")
        active = {}
        async with self.serial:
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
                        except (
                            OSError,
                            ValueError,
                            RuntimeError,
                            sqlite3.Error,
                            asyncio.TimeoutError,
                        ) as error:
                            result = {
                                "status": "cohort_execution_pending",
                                "last_retry_type": type(error).__name__,
                                "chain_submission_authorized": False,
                            }
                        if report is not None:
                            report(result)
                    finally:
                        await self._drain((task, stopping))
                    with suppress(asyncio.TimeoutError):
                        await asyncio.wait_for(stop.wait(), timeout=poll_seconds)
            finally:
                await self._drain(active.values())
