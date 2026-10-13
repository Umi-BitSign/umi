import math
import random

import pytest
import rfc8785

from umi.canonical_proof import canonical_proof_matches


@pytest.mark.parametrize(
    "value",
    [
        None,
        True,
        False,
        0,
        -(2**53 - 1),
        2**53 - 1,
        "".join(chr(number) for number in range(128)),
        {"b": "0x" + "deadbeef" * 32768, "a": [None, True, -1, {"z": []}]},
        {"\ue000": "private", "\U00010000": "supplementary", "a": "é"},
        [0.0, -0.0, 1e-7, 1e-6, 1e20, 1e21, 333333333.33333329],
        (1, 2, "ascii"),
    ],
)
def test_exact_reference_bytes_including_reference_fallback(value):
    expected = rfc8785.dumps(value)
    assert canonical_proof_matches(value, expected)
    for changed in (b"", expected[:-1], expected + b" ", b" " + expected):
        assert not canonical_proof_matches(value, changed)


@pytest.mark.parametrize(
    "bad", [2**53, -(2**53), math.nan, math.inf, -math.inf, "\ud800", {1: "bad"}]
)
def test_reference_domain_errors_remain_after_an_earlier_mismatch(bad):
    value = ["earlier", bad]
    with pytest.raises(Exception) as reference:
        rfc8785.dumps(value)
    with pytest.raises(type(reference.value)):
        canonical_proof_matches(value, b"wrong")


def test_ascii_tree_differential_against_reference():
    rng = random.Random(20261013)
    alphabet = "".join(chr(number) for number in range(128))

    def tree(depth):
        choices = [
            None,
            True,
            False,
            rng.randrange(-(2**53 - 1), 2**53),
            "".join(rng.choices(alphabet, k=rng.randrange(100))),
        ]
        if depth:
            choices.extend(
                [
                    [tree(depth - 1) for _ in range(rng.randrange(4))],
                    {
                        "".join(rng.choices(alphabet, k=3)): tree(depth - 1)
                        for _ in range(rng.randrange(4))
                    },
                ]
            )
        return rng.choice(choices)

    for _ in range(250):
        value = tree(3)
        assert canonical_proof_matches(value, rfc8785.dumps(value))


@pytest.mark.parametrize("alternate", [b'{"b":1,"a":2}', b"1.0", b"-0", b'"\\u0061"'])
def test_alternate_encoding_is_still_rejected(alternate):
    import json

    assert not canonical_proof_matches(json.loads(alternate), alternate)
