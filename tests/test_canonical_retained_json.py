"""Decoded retained bytes preserve the original RFC acceptance boundary."""

import hashlib
import json
import random

import pytest
import rfc8785

from umi import protocol
from umi.canonical_reuse import small_ascii_json_roundtrip
from umi.canonical_stream import canonical_json_matches
from umi.open_competition import digest, digest_canonical_bytes


@pytest.mark.parametrize(
    "raw",
    [
        b'{"a":1,"z":[null,true,false,-9007199254740991,9007199254740991]}',
        b'{"b":2,"a":1}',
        b'{"a":1,"a":2}',
        b'{ "a":1}',
        b'{"a":-0}',
        b'{"a":"\\u0000\\n\\t\\r\\b\\f\\"\\\\/"}',
        b'{"a":"\\u007f"}',
        b'{"a":"\\ud83d\\ude00"}',
        b'{"a":"\\u20ac"}',
        b'{"a":1.0}',
        b'{"a":1e+30}',
        b'{"a":1e-7}',
        b'{"a":9007199254740992}',
        b'{"a":NaN}',
        b'{"a":Infinity}',
        b'{"a":"\\ud800"}',
        b'\xef\xbb\xbf{"a":1}',
        '{"\ue000":1,"😀":2}'.encode(),
        b'{"a":',
        b"[] trailing",
        b"[01]",
    ],
)
def test_acceptance_and_errors_match_original_rfc_reader(raw):
    def original():
        return canonical_json_matches(json.loads(raw), raw)

    try:
        expected = original()
    except Exception as error:
        with pytest.raises(type(error)):
            protocol.is_canonical_json(raw)
    else:
        assert protocol.is_canonical_json(raw) is expected


def test_all_ascii_characters_and_safe_integer_edges_match_rfc():
    values = {chr(number): [chr(number), number, -(2**53 - 1), 2**53 - 1] for number in range(128)}
    raw = rfc8785.dumps(values)
    assert small_ascii_json_roundtrip(raw) == raw


def test_wide_decoded_trees_do_not_require_arbitrary_object_snapshotting():
    raw = rfc8785.dumps({"items": [[number, "original"] for number in range(9000)]})
    assert len(raw) <= 256 * 1024
    assert small_ascii_json_roundtrip(raw) == raw
    changed = raw.replace(b'"original"', b'"changed"', 1)
    assert small_ascii_json_roundtrip(changed) == rfc8785.dumps(json.loads(changed))


def test_random_retained_ascii_records_match_rfc():
    randomizer = random.Random(4102577)
    alphabet = "".join(chr(value) for value in range(128))
    for _ in range(300):
        value = {
            "".join(randomizer.choices(alphabet, k=6)): [
                randomizer.randrange(-(2**53 - 1), 2**53),
                "".join(randomizer.choices(alphabet, k=12)),
                {"n": None, "t": True, "f": False},
            ]
            for _ in range(12)
        }
        raw = rfc8785.dumps(value)
        assert small_ascii_json_roundtrip(raw) == raw
        assert protocol.is_canonical_json(raw)


@pytest.mark.parametrize("raw", [b"1.0", b"1e-7", b"9007199254740992", '"😀"'.encode()])
def test_other_number_and_unicode_semantics_use_original_path(raw):
    assert small_ascii_json_roundtrip(raw) is None


def test_fast_path_size_is_a_fallback_and_does_not_reject_large_records():
    raw = b'"' + b"x" * (256 * 1024) + b'"'
    assert small_ascii_json_roundtrip(raw) is None
    assert protocol.is_canonical_json(raw)


@pytest.mark.parametrize("depth", [64, 65, 100, 400])
def test_deep_trees_preserve_original_rfc_recursion_behavior(depth):
    raw = b"[" * depth + b"0" + b"]" * depth
    if depth > 64:
        assert small_ascii_json_roundtrip(raw) is None
    try:
        expected = canonical_json_matches(json.loads(raw), raw)
    except RecursionError:
        with pytest.raises(RecursionError):
            protocol.is_canonical_json(raw)
    else:
        assert protocol.is_canonical_json(raw) is expected


def test_bytes_subclasses_keep_original_reader():
    class Raw(bytes):
        def isascii(self):
            pytest.fail("caller subclass must not participate in the decoded-text fast path")

    raw = Raw(b'{"a":1}')
    assert small_ascii_json_roundtrip(raw) is None
    assert protocol.is_canonical_json(raw)


def test_validated_retained_bytes_preserve_original_digest_domain():
    value = {"original": [None, True, 123, "東京"], "schema": "retained/1"}
    raw = rfc8785.dumps(value)
    expected = hashlib.sha256(b"umi-open-competition-v1\0" + raw).hexdigest()
    assert digest(value) == digest_canonical_bytes(raw) == expected
    assert digest_canonical_bytes(raw) != hashlib.sha256(raw).hexdigest()
    with pytest.raises(TypeError):
        digest_canonical_bytes(bytearray(raw))
