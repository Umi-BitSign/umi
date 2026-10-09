"""Seal and export completed local evaluation work while settlement waits.

Each evaluator uses its own configured journals and named key. Missing work,
busy job locks and unavailable storage leave the original obligation pending.
The round-robin cursor survives restart and never acknowledges remote delivery.
"""

import asyncio
import logging
import sqlite3
from collections.abc import Awaitable, Callable, Sequence
from contextlib import suppress
from functools import partial

from .competition_cohort_endpoint_archive import EndpointReplayArchive, JournalEndpointObjects
from .competition_cohort_execution_journal import CohortExecutionJournal
from .competition_cohort_order_signer import OrderFinality
from .competition_cohort_request_files import RequestCompletionFiles
from .competition_cohort_request_terminal import (
    RequestTerminal,
    SignedRequestTerminal,
    seal_request_terminal,
)
from .competition_progress import _failure_details
from .competition_round_journal import RoundJournal
from .concurrency import await_owned_task, run_owned_thread
from .open_competition import Signature, digest, identity

logger = logging.getLogger(__name__)


class RequestExportWorker:
    def __init__(
        self,
        executions: Sequence[CohortExecutionJournal],
        provider: OrderFinality,
        sign: Callable[[RequestTerminal], Awaitable[Signature]],
        files: RequestCompletionFiles,
        journal: RoundJournal,
        *,
        batch_size: int = 16,
        concurrency: int = 4,
    ):
        if type(batch_size) is not int or not 1 <= batch_size <= 256:
            raise ValueError("request export batch size is outside bounds")
        if type(concurrency) is not int or not 1 <= concurrency <= 16:
            raise ValueError("request export concurrency is outside bounds")
        if not executions or any(e.policy != provider.policy for e in executions):
            raise ValueError("request exporter needs its evaluator's selected execution journals")
        if len({identity(e.config.signer) for e in executions}) != 1:
            raise ValueError("request exporter cannot sign for several evaluators")
        roots = [e.journal.root for e in executions]
        if len(roots) != len(set(roots)):
            raise ValueError("request exporter repeats an execution journal")
        if (
            any(
                a == b or a in b.parents or b in a.parents
                for a in (files.root, journal.root)
                for b in roots
            )
            or files.root == journal.root
            or files.root in journal.root.parents
            or journal.root in files.root.parents
        ):
            raise ValueError("request export files, cursor and executions must remain separate")
        self.executions, self.provider, self.sign = tuple(executions), provider, sign
        self.files, self.journal, self.batch_size = files, journal, batch_size
        self.concurrency = concurrency
        self.serial = asyncio.Lock()
        with journal.transaction() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS request_export_cursor "
                "(owner TEXT PRIMARY KEY, slot TEXT NOT NULL)"
            )

    def _page(self, owner):
        key = digest(str(owner.journal.root))
        with self.journal.transaction() as db:
            row = db.execute(
                "SELECT slot FROM request_export_cursor WHERE owner=?", (key,)
            ).fetchone()
        after = "" if row is None else row[0]
        if after and (len(after) != 64 or any(c not in "0123456789abcdef" for c in after)):
            raise ValueError("request export cursor is invalid")
        with owner.journal.transaction() as db:
            rows = db.execute(
                "SELECT id FROM records WHERE kind='assignment' AND id>? ORDER BY id LIMIT ?",
                (after, self.batch_size),
            ).fetchall()
            if not rows and after:
                rows = db.execute(
                    "SELECT id FROM records WHERE kind='assignment' ORDER BY id LIMIT ?",
                    (self.batch_size,),
                ).fetchall()
        if rows:
            with self.journal.transaction() as db:
                db.execute(
                    "INSERT OR REPLACE INTO request_export_cursor VALUES (?,?)", (key, rows[-1][0])
                )
        return tuple(r[0] for r in rows)

    async def _export(self, owner, slot, block):
        objects = JournalEndpointObjects(owner.journal)
        retained = await run_owned_thread(owner.journal.get, "request_terminal", slot)
        if retained is None:
            # Waiting for execution/endpoint work needs no writer lock. Taking
            # that lock on every pending poll can starve the producer we await.
            evidence = await run_owned_thread(owner.evidence, slot)
            if evidence is None:
                return False
            if evidence.job.mode == "endpoint_incumbent":
                archive = await run_owned_thread(owner.journal.get, "endpoint_replay_archive", slot)
                intent = await run_owned_thread(owner.journal.get, "request_terminal_intent", slot)
                if archive is None and intent is None:
                    return False
            # Only creation needs the execution writer lock. Once sealed, the
            # immutable terminal can be exported while settlement reads the job.
            with owner.locked(slot):
                retained = await run_owned_thread(owner.journal.get, "request_terminal", slot)
                if retained is None:
                    evidence = await run_owned_thread(owner.evidence, slot)
                    if evidence is None:
                        return False
                    archive = None
                    if evidence.job.mode == "endpoint_incumbent":
                        raw = await run_owned_thread(
                            owner.journal.get, "endpoint_replay_archive", slot
                        )
                        if raw is None:
                            intent = await run_owned_thread(
                                owner.journal.get, "request_terminal_intent", slot
                            )
                            if intent is None:
                                return False
                        else:
                            archive = EndpointReplayArchive.model_validate(raw)
                    retained = await seal_request_terminal(
                        owner,
                        slot,
                        self.sign,
                        endpoint_archive=archive,
                        endpoint_objects=objects,
                    )
        terminal = SignedRequestTerminal.model_validate(retained)
        assignment = await run_owned_thread(owner.assignment, slot)
        if terminal.terminal.assignment_sha256 != digest(assignment) or identity(
            terminal.signature.hotkey
        ) != identity(owner.config.signer):
            raise ValueError("retained terminal differs from its owned assignment")
        # Delivery reads immutable originals after releasing the signing lock.
        # Slow copies must not prevent settlement from reading this job.
        if await run_owned_thread(
            partial(
                self.files.current,
                digest(terminal),
                policy_sha256=digest(owner.policy),
                opened_at_block=0,
                completed_by_block=block,
            )
        ):
            return True
        await run_owned_thread(
            partial(
                self.files.publish,
                terminal,
                objects,
                owner.policy,
                # The closure reviewer enforces the certified request interval.
                # Delivery verifies native completed steps without choosing or
                # changing that authority or asserting phase completion.
                opened_at_block=0,
                completed_by_block=block,
            )
        )
        return True

    async def poll_once(self):
        async with self.serial:
            capture = await self.provider.collect()
            considered = complete = pending = retries = 0
            last_error = ""
            last_failure = None
            ready = []
            for owner in self.executions:
                try:
                    slots = await run_owned_thread(self._page, owner)
                except (OSError, ValueError, RuntimeError, sqlite3.Error) as error:
                    retries += 1
                    last_error = type(error).__name__
                    last_failure = _failure_details(error)[0]
                    continue
                ready.extend((owner, slot) for slot in slots)

            # A slow seal or object copy must not hold up other completed work.
            # Use a bounded worker group, retaining each assignment's original
            # signing lock and immutable publication checks.
            work = iter(ready)

            async def export_ready():
                nonlocal considered, complete, pending, retries, last_error, last_failure
                for owner, slot in work:
                    considered += 1
                    try:
                        if await self._export(owner, slot, capture.snapshot.block):
                            complete += 1
                        else:
                            pending += 1
                    except (OSError, ValueError, RuntimeError, sqlite3.Error) as error:
                        retries += 1
                        last_error = type(error).__name__
                        last_failure = _failure_details(error)[0]

            tasks = [
                asyncio.create_task(export_ready())
                for _ in range(min(self.concurrency, len(ready)))
            ]
            try:
                await asyncio.gather(*tasks)
            finally:
                for task in tasks:
                    if not task.done():
                        task.cancel()

                async def drain():
                    await asyncio.gather(*tasks, return_exceptions=True)

                # Repeated cancellation cannot release the poll owner while a
                # child still owns an execution lock or a publication thread.
                await await_owned_task(asyncio.create_task(drain()))
            return {
                "status": "request_exports_pending"
                if pending or retries
                else "request_exports_current",
                "assignments_considered": considered,
                "assignments_exported": complete,
                "assignments_pending": pending,
                "retry_count": retries,
                "last_error_type": last_error,
                "last_failure": last_failure,
                "request_closure_authorized": False,
                "chain_submission_authorized": False,
            }

    async def run(self, stop, *, poll_seconds=5, report=None):
        if type(poll_seconds) not in (int, float) or not 0 < poll_seconds <= 60:
            raise ValueError("request export poll interval is outside bounds")
        while not stop.is_set():
            try:
                result = await self.poll_once()
            except (
                OSError,
                ValueError,
                RuntimeError,
                sqlite3.Error,
                asyncio.TimeoutError,
            ) as error:
                result = {"status": "request_exports_retry", "error_type": type(error).__name__}
            if report is None:
                logger.info("cohort_request_exports %s", result)
            else:
                report(result)
            with suppress(asyncio.TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=poll_seconds)
