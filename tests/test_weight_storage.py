import json
from pathlib import Path

import pytest

from umi.weight_storage import subtensor_stored_weights


@pytest.mark.parametrize(
    "values,expected",
    [
        ([], ()),
        ([0, 0], (0, 0)),
        ([0, 1, 2], (0, 32768, 65535)),
        ([1, 3], (21845, 65535)),
        ([16384, 32768], (32768, 65535)),
        ([16385, 32770], (32767, 65535)),
        ([32767, 65534], (32767, 65535)),
        ([65535, 1, 0], (65535, 1, 0)),
    ],
)
def test_subtensor_fixed_point_rounding(values, expected):
    assert subtensor_stored_weights(values) == expected


@pytest.mark.parametrize("values", [[-1], [65536], [True], [1.0], ["1"]])
def test_storage_transform_rejects_non_u16_input(values):
    with pytest.raises(ValueError):
        subtensor_stored_weights(values)


def test_matches_both_finalized_c4_rows():
    fixture = json.loads(
        (Path(__file__).parent / "fixtures/chain_weight_storage_c4.json").read_text()
    )
    assert subtensor_stored_weights(fixture["input_weights"]) == tuple(fixture["stored_weights"])
    assert fixture["input_weights"] != fixture["stored_weights"]
