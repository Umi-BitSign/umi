"""Refresh held inputs without treating elapsed blocks as certified closure."""

import asyncio
import os

import pytest

from umi.private_files import lock_private_file

from .test_competition_cohort_order_signer import source_for
from .test_competition_cohort_service_api import post
from .test_competition_cohort_service_contention import api_case as api_case
from .test_competition_cohort_service_contention import base_policy as base_policy
from .test_competition_cohort_service_contention import chain as chain
from .test_competition_cohort_service_contention import chain_config as chain_config
from .test_competition_cohort_service_contention import finality_padding as finality_padding
from .test_competition_cohort_service_contention import harness as harness
from .test_competition_cohort_service_contention import legacy_scenario as legacy_scenario
from .test_competition_cohort_service_contention import policy as policy
from .test_competition_cohort_service_contention import queue_case as queue_case
from .test_competition_cohort_service_contention import receipt_scenario as receipt_scenario
from .test_competition_cohort_service_contention import recovery as recovery
from .test_competition_cohort_service_contention import runtime as runtime
from .test_competition_cohort_service_contention import scenario as scenario
from .test_competition_cohort_service_queue import inputs
from .test_competition_historical_registration import change_block


@pytest.mark.parametrize("advance,closed", [(1, False), (20000, False), (20000, True)])
async def test_history_mutex_retry_refreshes_head_before_admission(
    api_case, chain, advance, closed
):
    s = api_case
    original = s.api.capture
    entered = asyncio.Event()
    captures = 0
    lease = None

    async def capture_and_hold():
        nonlocal captures, lease
        result = await original()
        captures += 1
        if captures == 1:
            lease = lock_private_file(s.c.queue.journal.lock_path)
            entered.set()
        return result

    s.api.capture = capture_and_hold
    task = asyncio.create_task(post(s))
    try:
        await asyncio.wait_for(entered.wait(), timeout=60)
        await asyncio.sleep(0.1)
        assert not task.done()
        if closed:
            s.source = source_for(s.c.h.batch, s.c.h.batch["history"])
        change_block(chain, s.observed.snapshot.block + advance)
        os.close(lease)
        lease = None
        response = await asyncio.wait_for(task, timeout=60)
        assert captures >= 2, "mutex retry reused a head captured before the hold"
        if not closed:
            assert response.status_code == 200, response.text
            admission = s.c.queue.lookup(inputs(s.c)[0])
            assert admission.registration.block == s.observed.snapshot.block + advance
        else:
            assert response.status_code == 503
            assert s.c.queue.entries() == ()
    finally:
        if lease is not None:
            os.close(lease)
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
