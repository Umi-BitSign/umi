from __future__ import annotations

import pytest

from umi.config import Limits, SafetyBoundary


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
