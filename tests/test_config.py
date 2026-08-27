from __future__ import annotations

import pytest

from umi.config import SafetyBoundary


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
