from __future__ import annotations

import pytest

from umi.config import Limits, SafetyBoundary, resolve_inference_timeout

from .test_competition_authorization import build_authorization_fixture
from .test_open_competition import policy as policy


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("netuid", 1),
        ("mechanism_id", 1),
        ("translation_weights_active", True),
        ("protocol_conformance", True),
        ("activation_evidence", True),
        ("terminal_code", "calibration_no_weight"),
    ],
)
def test_component_boundary_fails_closed(field: str, value: object) -> None:
    with pytest.raises(ValueError):
        SafetyBoundary(**{field: value})


def test_component_boundary_has_no_weight_claim() -> None:
    boundary = SafetyBoundary()
    assert boundary.netuid == 78
    assert boundary.mechanism_id == 0
    assert boundary.translation_weights_active is False
    assert boundary.protocol_conformance is False
    assert boundary.activation_evidence is False
    assert boundary.terminal_code == "component_test_no_weight"


def test_btauth_window_covers_anchor_finality_and_rejects_bad_values() -> None:
    limits = Limits()
    assert limits.btauth_max_age_seconds == 120.0
    assert limits.btauth_allowed_skew_seconds == 2.0
    with pytest.raises(ValueError, match="max_age"):
        Limits(btauth_max_age_seconds=0)
    with pytest.raises(ValueError, match="non-negative"):
        Limits(btauth_allowed_skew_seconds=-1)
    with pytest.raises(ValueError, match="less than max age"):
        Limits(btauth_max_age_seconds=2, btauth_allowed_skew_seconds=2)
    with pytest.raises(ValueError, match="maximum_request_body_bytes"):
        Limits(maximum_request_body_bytes=True)
    with pytest.raises(ValueError, match="inference_timeout_seconds"):
        Limits(inference_timeout_seconds=True)
    with pytest.raises(ValueError, match="inference_timeout_seconds"):
        Limits(inference_timeout_seconds=float("nan"))
    with pytest.raises(ValueError, match="backend_lifecycle_timeout_seconds"):
        Limits(backend_lifecycle_timeout_seconds=0)
    with pytest.raises(ValueError, match="inference_admission_timeout_seconds"):
        Limits(inference_admission_timeout_seconds=float("inf"))
    with pytest.raises(ValueError, match="video_fetch_timeout_seconds"):
        Limits(video_fetch_timeout_seconds=float("inf"))


@pytest.mark.parametrize("budget_ms", [600_000, 1_200_000])
def test_cohort_budget_is_the_default_instead_of_legacy_120_seconds(policy, budget_ms):
    case = build_authorization_fixture(
        policy.model_copy(update={"maximum_inference_ms": budget_ms})
    )
    limits = Limits.from_policy(case.legacy_policy, competition_policy=case.policy)
    assert limits.inference_timeout_seconds == budget_ms / 1000
    assert limits.inference_admission_timeout_seconds == 2 * budget_ms / 1000
    assert limits.backend_lifecycle_timeout_seconds == 3 * budget_ms / 1000
    assert limits.request_body_timeout_seconds == 30
    assert limits.video_fetch_timeout_seconds >= 120
    assert limits.maximum_hypothesis_utf8_bytes <= case.policy.maximum_output_bytes
    assert limits.maximum_active_windows == 1
    assert Limits.from_policy(case.legacy_policy).inference_timeout_seconds == 120


def test_cohort_local_overrides_do_not_change_signed_or_storage_limits(policy):
    case = build_authorization_fixture(policy)
    before = Limits.from_policy(case.legacy_policy)
    chosen = Limits.from_policy(
        case.legacy_policy,
        competition_policy=case.policy,
        backend_lifecycle_timeout_seconds=200,
        inference_admission_timeout_seconds=90,
        request_body_timeout_seconds=40,
    )
    assert chosen.backend_lifecycle_timeout_seconds == 200
    assert chosen.inference_admission_timeout_seconds == 90
    assert chosen.request_body_timeout_seconds == 40
    for key in vars(before):
        if key.startswith("maximum_") and key != "maximum_hypothesis_utf8_bytes":
            assert getattr(chosen, key) == getattr(before, key)


def test_explicit_cohort_budget_override_remains_bounded_and_visible(policy):
    policy = policy.model_copy(update={"maximum_inference_ms": 600_000})
    assert resolve_inference_timeout(policy) == 600
    assert resolve_inference_timeout(policy, requested_seconds=120) == 120
    assert resolve_inference_timeout(policy, requested_seconds=1200) == 600
    for invalid in (True, 0, -1, float("nan"), float("inf")):
        with pytest.raises(ValueError, match="inference_timeout"):
            resolve_inference_timeout(policy, requested_seconds=invalid)
