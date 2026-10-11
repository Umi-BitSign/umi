"""Plan4 track/delivery combinations preserve explicit signed configuration."""

import pytest

from umi.competition_cohort_recovery import PHASES, RecoverableCohortPlan
from umi.protocol import canonical_json_bytes


def body(tracks, service_pool, delivery):
    value = {
        "schema": "umi-recoverable-cohort-plan/4",
        "policy_sha256": "11" * 32,
        "launch_sha256": "22" * 32,
        "sequence": 7,
        "suite_sha256": "33" * 32,
        "not_before_block": 200,
        "initial_targets": tuple(
            {"phase": phase, "target_block": 300 + index * 90} for index, phase in enumerate(PHASES)
        ),
        "eligible_tracks": tracks,
        "service_pool_bps": service_pool,
        "request_tail_rule": "original_request_12h_with_completed_miner/1",
    }
    if delivery:
        value["model_delivery"] = {
            "schema": "umi-model-delivery-profile/1",
            "mechanism": "coordinator_chunked_v1",
        }
    return value


@pytest.mark.parametrize(
    "tracks,pool,delivery",
    [
        (("endpoint",), 10000, False),
        (("model",), 0, True),
        (("endpoint", "model"), 5000, True),
    ],
)
def test_plan4_supported_layouts_roundtrip_without_clock_changes(tracks, pool, delivery):
    original = body(tracks, pool, delivery)
    raw = canonical_json_bytes(original)
    plan = RecoverableCohortPlan.model_validate_json(raw)
    assert canonical_json_bytes(plan) == raw
    assert (plan.model_delivery is not None) is delivery


@pytest.mark.parametrize(
    "tracks,pool,delivery",
    [
        (("endpoint",), 10000, True),
        (("model",), 0, False),
        (("endpoint", "model"), 5000, False),
    ],
)
def test_plan4_refuses_incompatible_delivery_profiles(tracks, pool, delivery):
    with pytest.raises(ValueError, match="model delivery"):
        RecoverableCohortPlan.model_validate_json(
            canonical_json_bytes(body(tracks, pool, delivery))
        )
