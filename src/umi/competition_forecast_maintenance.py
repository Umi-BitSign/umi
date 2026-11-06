"""Service-owned forecast retention, drained before its ledger is closed."""

import asyncio
import logging
from contextlib import suppress

from .concurrency import await_owned_task, run_owned_thread
from .protocol import canonical_json_bytes

logger = logging.getLogger("umi.competition.progress")


async def maintain_forecasts(ledger, stop, *, poll_seconds, report):
    if ledger is None or ledger.retention is None:
        return
    while not stop.is_set():
        error = None
        try:
            advanced = await run_owned_thread(ledger.maintain_retention)
        except Exception as caught:
            error, advanced = caught, False
        try:
            status = ledger.retention.diagnostics(error=error)
        except Exception as damaged:
            status = dict(
                stage="forecast_history_retention",
                status="repair_required",
                completed=None,
                total=None,
                eta_seconds=None,
                planning_eta_seconds=None,
                eta_basis="forecast_retention_metadata_requires_repair",
                eta_scope="forecast_retention_only_not_cohort_completion",
                stalled_or_retrying=True,
                error_type=type(damaged).__name__,
                certification_authority=False,
            )
        try:
            report(status)
        except Exception as damaged:
            logger.warning("forecast_retention_reporting_failed type=%s", type(damaged).__name__)
        if advanced:
            await asyncio.sleep(0)
        else:
            with suppress(asyncio.TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=min(30, poll_seconds))


def own_forecast_maintenance(ledger, resources, stop, *, poll_seconds, report):
    """AsyncExitStack drains publication before its earlier ledger-close callback."""
    task = asyncio.create_task(
        maintain_forecasts(ledger, stop, poll_seconds=poll_seconds, report=report)
    )

    async def close():
        task.cancel()
        with suppress(asyncio.CancelledError):
            await await_owned_task(task)

    resources.push_async_callback(close)
    return task


def log_retention(status):
    logger.info("forecast_retention %s", canonical_json_bytes(status).decode())
