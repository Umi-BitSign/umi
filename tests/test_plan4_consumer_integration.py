"""Native plan4 settlement and reward consumer integration.

Only native synthetic fixtures construct new plan4 evidence. Existing signed
plans/evidence are never modified. No production RPC, wallets or services.
"""

import pytest

from umi.competition_cohort_recovery import cohort_request_tail_rule
from umi.competition_cohort_request_tail import (
    RequestTailObservation,
    original_request_miners,
)
from umi.competition_cohort_reward_package import replay_reward_package
from umi.open_competition import digest, identity
from umi.protocol import canonical_json_bytes

from . import test_competition_cohort_tail_settlement as tail
from .cohort_request_closure_fixture import build
from .cohort_tail_settlement_fixture import partial_original
from .test_competition_cohort_consumers import tip
from .test_competition_cohort_request_closure import put
from .test_competition_cohort_service_grants import rebuild_service_closure
from .test_competition_cohort_tail_settlement import base_policy as base_policy
from .test_competition_cohort_tail_settlement import chain as chain
from .test_competition_cohort_tail_settlement import chain_config as chain_config
from .test_competition_cohort_tail_settlement import endpoint as endpoint
from .test_competition_cohort_tail_settlement import execution as execution
from .test_competition_cohort_tail_settlement import granted as granted
from .test_competition_cohort_tail_settlement import harness as harness
from .test_competition_cohort_tail_settlement import known_video_bytes as known_video_bytes
from .test_competition_cohort_tail_settlement import legacy_scenario as legacy_scenario
from .test_competition_cohort_tail_settlement import miner_policy as miner_policy
from .test_competition_cohort_tail_settlement import policy as policy
from .test_competition_cohort_tail_settlement import receipt_scenario as receipt_scenario
from .test_competition_cohort_tail_settlement import recovery as recovery
from .test_competition_cohort_tail_settlement import recovery_case as recovery_case
from .test_competition_cohort_tail_settlement import relay as relay
from .test_competition_cohort_tail_settlement import runtime as runtime
from .test_competition_cohort_tail_settlement import scenario as scenario
from .test_competition_cohort_tail_settlement import service as service
from .test_competition_cohort_tail_settlement import (
    service_catalog_inputs as service_catalog_inputs,
)
from .test_competition_cohort_tail_settlement import service_closed as service_closed
from .test_competition_cohort_tail_settlement import service_owner as service_owner
from .test_competition_cohort_tail_settlement import (
    service_quality_inputs as service_quality_inputs,
)
from .test_competition_cohort_tail_settlement import shared_control_group as shared_control_group
from .test_competition_reward_preparation import native_package

pytestmark = [
    pytest.mark.parametrize("receipt_scenario", ["standing"], indirect=True),
    pytest.mark.parametrize("recovery", ["hard12h"], indirect=True),
    pytest.mark.parametrize("service_catalog_inputs", ["equal_pools"], indirect=True),
]


@pytest.fixture(autouse=True)
def plan4_fixture_observations(monkeypatch):
    original = tail.tail_observation

    def plan4(b, unfinished=()):
        assert b["history"].plan.schema_ == "umi-recoverable-cohort-plan/4"
        value = original(b, unfinished)
        return RequestTailObservation.model_validate_json(
            canonical_json_bytes(
                value.model_copy(update={"rule": cohort_request_tail_rule(b["history"].plan)})
            )
        )

    monkeypatch.setattr(tail, "tail_observation", plan4)


def test_plan4_paid_and_benchmark_partition_preserves_original_credit(
    service_quality_inputs,
):
    tail.test_native_tail_paid_only_and_benchmark_skips_preserve_credit(service_quality_inputs)


@pytest.mark.asyncio
async def test_plan4_settlement_proofs_and_package_replay(service_quality_inputs, tmp_path):
    await tail.test_native_tail_package_replays_exact_partition_after_independent_certification(
        service_quality_inputs, tmp_path
    )


@pytest.mark.asyncio
async def test_plan4_one_complete_miner_reaches_native_package_with_ten_skipped(
    service_quality_inputs, tmp_path
):
    b = service_quality_inputs
    old_history = b["history"]
    b["history"] = old_history.model_copy(update={"transitions": old_history.transitions[:2]})
    complete = b["service_case"].assignment.admission.submission.submission
    complete_identity = identity(complete.hotkey)
    unfinished = tuple(
        who for who in original_request_miners(b["roster"]) if who != complete_identity
    )
    assert len(unfinished) == 10
    base_tail = tail.tail_observation(b)
    selected = RequestTailObservation.model_validate_json(
        canonical_json_bytes(base_tail.model_copy(update={"unfinished_hotkeys": unfinished}))
    )
    partials = {
        digest(order.order.submission.submission): tuple(
            partial_original(b, order, who) for who in order.order.evaluators
        )
        for order in b["orders"]
        if order.order.submission.submission != complete
    }

    def terminals(order, evaluator):
        if order.order.submission.submission != complete:
            return None
        return b["terminals"].get((digest(order), identity(evaluator)))

    benchmark = build(
        b,
        tail=selected,
        observation=b["closure"].observation,
        current_block=b["closure"].observation.block,
        terminal_source=terminals,
        partial_source=lambda key: partials.get(key, ()),
    )
    assert len(benchmark.participants) == 1 and len(benchmark.skipped) == 10
    put(b, benchmark)
    closure = rebuild_service_closure(b, benchmark=benchmark)
    assert closure.catalogs[0].skipped_work == ()
    tail.recertify_reveal(b, closure)
    signable = {
        **b,
        "orders": tuple(
            order for order in b["orders"] if order.order.submission.submission == complete
        ),
    }
    prepared = await native_package.__wrapped__(signable, tmp_path / "package")
    package = prepared.package
    assert package.inputs.history.plan.schema_ == "umi-recoverable-cohort-plan/4"
    assert len(package.benchmark.participants) == 1
    assert len(package.benchmark.skipped_participants) == 10
    assert package.benchmark.skipped_participants == tuple(digest(p) for p in benchmark.skipped)
    replayed = replay_reward_package(
        package,
        b["policy"],
        prepared.store,
        package.inputs.history,
        expected_package_sha256=digest(package),
        expected_cohort_sha256=digest(package.inputs.history.plan),
        expected_tip_sha256=tip(package.inputs.history),
        current_block=2**53 - 1,
        expected_terms_sha256=prepared.requirement.terms_sha256,
        expected_catalog_sha256s=prepared.requirement.catalog_sha256s,
        maximum_promotion_bytes=1_000_000,
    )
    assert replayed == prepared.allocation
