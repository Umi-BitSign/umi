"""Plan4 plus signed paid partial evidence through native closure and reward package."""

import pytest

from . import test_competition_cohort_paid_partial as paid
from .test_competition_cohort_paid_partial import base_policy as base_policy
from .test_competition_cohort_paid_partial import chain as chain
from .test_competition_cohort_paid_partial import chain_config as chain_config
from .test_competition_cohort_paid_partial import endpoint as endpoint
from .test_competition_cohort_paid_partial import execution as execution
from .test_competition_cohort_paid_partial import granted as granted
from .test_competition_cohort_paid_partial import harness as harness
from .test_competition_cohort_paid_partial import known_video_bytes as known_video_bytes
from .test_competition_cohort_paid_partial import legacy_scenario as legacy_scenario
from .test_competition_cohort_paid_partial import loop as loop
from .test_competition_cohort_paid_partial import miner_policy as miner_policy
from .test_competition_cohort_paid_partial import original_harness as original_harness
from .test_competition_cohort_paid_partial import policy as policy
from .test_competition_cohort_paid_partial import receipt_scenario as receipt_scenario
from .test_competition_cohort_paid_partial import recovery as recovery
from .test_competition_cohort_paid_partial import recovery_case as recovery_case
from .test_competition_cohort_paid_partial import relay as relay
from .test_competition_cohort_paid_partial import runtime as runtime
from .test_competition_cohort_paid_partial import scenario as scenario
from .test_competition_cohort_paid_partial import (
    service_catalog_inputs as service_catalog_inputs,
)
from .test_competition_cohort_paid_partial import service_owner as service_owner
from .test_competition_cohort_paid_partial import shared_control_group as shared_control_group

pytestmark = [
    pytest.mark.parametrize("receipt_scenario", ["standing"], indirect=True),
    pytest.mark.parametrize("recovery", ["hard12h"], indirect=True),
    pytest.mark.parametrize("service_catalog_inputs", ["equal_pools"], indirect=True),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("retirement_before_closure", [False, True])
async def test_plan4_paid_partial_package_preserves_clocks_and_credit(
    loop,
    receipt_scenario,
    runtime,
    monkeypatch,
    tmp_path,
    retirement_before_closure,
    recovery,
):
    assert recovery[0].schema_ == "umi-recoverable-cohort-plan/4"
    assert recovery[0].request_tail_rule == "original_request_12h_with_completed_miner/1"
    await paid.test_response_without_retirement_reaches_native_certified_package(
        loop,
        receipt_scenario,
        runtime,
        monkeypatch,
        tmp_path,
        retirement_before_closure,
        prepared_capture=True,
    )
