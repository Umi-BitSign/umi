import json
import math
import random

import pytest
import rfc8785
from pydantic import BaseModel, Field

from umi.canonical_stream import canonical_json_matches
from umi.protocol import is_canonical_json


@pytest.mark.parametrize(
    "value",
    [
        None,
        True,
        False,
        0,
        -(2**53 - 1),
        2**53 - 1,
        -0.0,
        1e-7,
        1e-6,
        1e20,
        1e21,
        333333333.33333329,
        "",
        '\x00\b\t\n\r\\"',
        {"\ue000": "private", "\U00010000": "supplementary", "a": "é"},
        {"items": [1, 2.5, "text", None], "nested": {"b": [], "a": {}}},
    ],
)
def test_stream_matches_reference_bytes_and_rejects_length_or_content_changes(value):
    expected = rfc8785.dumps(value)
    assert canonical_json_matches(value, expected)
    for changed in (b"", expected[:-1], expected + b" ", b" " + expected, b"!" + expected[1:]):
        assert not canonical_json_matches(value, changed)


@pytest.mark.parametrize(
    "bad", [2**53, -(2**53), math.nan, math.inf, -math.inf, "\ud800", {1: "bad"}]
)
def test_invalid_domain_is_still_checked_after_an_earlier_mismatch(bad):
    value = ["first", bad]
    with pytest.raises(Exception) as reference:
        rfc8785.dumps(value)
    with pytest.raises(type(reference.value)):
        canonical_json_matches(value, b"mismatch")


def test_model_json_mode_and_aliases_are_preserved():
    class Aliased(BaseModel):
        name: str = Field(alias="wire_name")
        values: tuple[int, ...]

    value = Aliased(wire_name="unicode é", values=(1, 2))
    assert canonical_json_matches(
        value, rfc8785.dumps(value.model_dump(mode="json", by_alias=True))
    )
    assert not canonical_json_matches(value, rfc8785.dumps(value.model_dump(mode="json")))


def test_seeded_nested_documents_match_the_reference_serializer():
    rng = random.Random(8785)

    def document(depth=0):
        choices = [None, True, False, rng.randrange(-(2**53 - 1), 2**53), rng.random(), 'a\n"é𐀀']
        if depth < 3:
            choices.extend(
                [
                    [document(depth + 1) for _ in range(rng.randrange(4))],
                    {str(i): document(depth + 1) for i in range(rng.randrange(4))},
                ]
            )
        return rng.choice(choices)

    for _ in range(150):
        value = document()
        expected = rfc8785.dumps(value)
        assert canonical_json_matches(value, expected)
        assert is_canonical_json(expected)
        assert not is_canonical_json(expected + b" ")


@pytest.mark.parametrize(
    "raw", [b'{"x":1,"x":1}', b'{"b":1,"a":2}', b"1.0", b"-0", b'"\\u0061"', b"[]\n"]
)
def test_canonical_reader_still_rejects_alternate_json_encodings(raw):
    assert json.loads(raw) is not None
    assert not is_canonical_json(raw)
