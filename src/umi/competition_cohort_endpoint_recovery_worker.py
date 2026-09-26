"""Fair, restartable polling of retained endpoint response obligations."""

from __future__ import annotations

import asyncio
import sqlite3
from collections.abc import Callable
from contextlib import suppress

from .competition_cohort_endpoint_recovery import CohortEndpointResponseRecovery
from .concurrency import run_owned_thread
from .open_competition import digest


class CohortEndpointRecoveryWorker:
    def __init__(self, recovery: CohortEndpointResponseRecovery, *, batch_size: int = 16):
        if type(batch_size) is not int or not 1 <= batch_size <= 256:
            raise ValueError("endpoint recovery batch size is outside bounds")
        self.recovery, self.batch_size = recovery, batch_size

    async def poll_once(self) -> dict:
        journal = self.recovery.journal
        poll_slot = digest({"schema": "umi-cohort-endpoint-recovery-poll/1"})
        with journal.locked(poll_slot):

            def pending():
                with journal.journal.transaction() as db:
                    row = db.execute(
                        "SELECT obligation FROM endpoint_recovery_cursor WHERE id=1"
                    ).fetchone()
                    cursor = "" if row is None else row[0]
                    sql = (
                        "SELECT q.obligation,q.slot,q.case_id FROM endpoint_recovery_queue q "
                        "WHERE NOT EXISTS (SELECT 1 FROM records r "
                        "WHERE r.kind='endpoint_recovered_case' AND r.id=q.obligation) "
                    )
                    first = db.execute(
                        sql + "AND q.obligation>? ORDER BY q.obligation LIMIT ?",
                        (cursor, self.batch_size),
                    ).fetchall()
                    return (
                        first
                        + db.execute(
                            sql + "AND q.obligation<=? ORDER BY q.obligation LIMIT ?",
                            (cursor, self.batch_size - len(first)),
                        ).fetchall()
                    )

            rows = await run_owned_thread(pending)
            recovered = 0
            last_reason = ""
            for obligation, slot, case in rows:

                def advance(obligation):
                    with journal.journal.transaction() as db:
                        db.execute(
                            "INSERT INTO endpoint_recovery_cursor VALUES (1,?) "
                            "ON CONFLICT(id) DO UPDATE SET obligation=excluded.obligation",
                            (obligation,),
                        )

                # Advance before a potentially interrupted read. The obligation
                # remains in the queue and is revisited when the cursor wraps.
                await run_owned_thread(advance, obligation)
                try:
                    outcome = await self.recovery.recover(slot, case)
                except (ValueError, OSError, sqlite3.Error) as error:
                    last_reason = type(error).__name__
                else:
                    recovered += int(outcome.status == "recovered")
                    if outcome.status == "pending":
                        last_reason = outcome.reason
            return {
                "status": "cohort_endpoint_response_recovery",
                "considered": len(rows),
                "responses_recovered": recovered,
                "pending": len(rows) - recovered,
                "last_retry_reason": last_reason,
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
            raise ValueError("endpoint recovery poll interval is outside bounds")
        while not stop.is_set():
            task = asyncio.create_task(self.poll_once())
            stopping = asyncio.create_task(stop.wait())
            try:
                done, _ = await asyncio.wait((task, stopping), return_when=asyncio.FIRST_COMPLETED)
                if stopping in done:
                    return
                try:
                    result = task.result()
                except (ValueError, OSError, sqlite3.Error) as error:
                    result = {
                        "status": "cohort_endpoint_response_recovery_pending",
                        "last_retry_reason": type(error).__name__,
                        "chain_submission_authorized": False,
                    }
                if report is not None:
                    report(result)
            finally:
                task.cancel()
                stopping.cancel()
                with suppress(asyncio.CancelledError, ValueError, OSError, sqlite3.Error):
                    await task
                with suppress(asyncio.CancelledError):
                    await stopping
            with suppress(TimeoutError):
                await asyncio.wait_for(stop.wait(), poll_seconds)
