"""Merged recovery and retirement must not race running or uncertain sandboxes."""

from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from umi.competition_cohort_executor import CohortExecutionWorker


@pytest.mark.parametrize(
    "recovered,finished", [(False, False), (False, True), (True, False), (True, True)]
)
async def test_retirement_waits_for_recovery_and_drained_executions(recovered, finished):
    events = []
    worker = object.__new__(CohortExecutionWorker)
    active = {}

    async def recover():
        events.append("recover")
        return recovered

    async def maintenance():
        assert recovered and not active
        events.append("maintenance")

    def result():
        assert recovered
        events.append("drained")
        return "retained", "complete", ""

    class Database:
        def execute(self, query):
            assert query == "SELECT slot FROM execution_cursor LIMIT 2"
            events.append("cursor")
            return self

        def fetchall(self):
            return []

    @contextmanager
    def transaction():
        assert recovered and not active and "maintenance" in events
        yield Database()

    def assignments(**kwargs):
        assert recovered and not active and "maintenance" in events
        events.append("refill")
        return ()

    import asyncio

    worker._recover_retained = recover
    worker.maintenance = maintenance
    worker.recovery_pending = {"retained"} if not recovered else set()
    worker.concurrency = 1
    worker.batch_size = 1
    worker.source_priority_due = False
    worker._startup_resume = lambda: ()
    worker.inbox_reads = asyncio.Lock()
    worker.executor = SimpleNamespace(
        journal=SimpleNamespace(journal=SimpleNamespace(transaction=transaction))
    )
    worker.inbox = SimpleNamespace(assignments=assignments)
    active["retained"] = SimpleNamespace(done=lambda: finished, result=result)

    status = await worker._rolling_poll(active)
    if not recovered:
        assert events == ["recover"]
        assert set(active) == {"retained"}
        assert status["stage"] == "execution_retained_container_cleanup"
    elif not finished:
        assert events == ["recover"]
        assert set(active) == {"retained"}
        assert status["in_flight_operations"] == 1
    else:
        assert events == ["recover", "drained", "maintenance", "cursor", "refill"]
        assert not active
        assert status["jobs_complete"] == 1
