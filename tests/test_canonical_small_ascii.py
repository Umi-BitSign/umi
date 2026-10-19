"""Exact RFC equivalence and fallback for the small retained-record encoder."""
import json
import random

import pytest
import rfc8785

from umi.canonical_reuse import canonical_dumps, small_ascii_json_bytes
from umi.protocol import is_canonical_json


def test_all_ascii_escapes_keys_and_safe_integer_boundaries_match_rfc():
    values = [None, True, False, -(2**53 - 1), 2**53 - 1, 0,
              ''.join(map(chr, range(128))),
              {chr(i): [i, -i, True, None, chr(127 - i)] for i in range(128)}]
    for value in values:
        expected = rfc8785.dumps(value)
        assert small_ascii_json_bytes(value) == expected
        assert canonical_dumps(value) == expected
        assert is_canonical_json(expected)


def test_seeded_nested_primitive_trees_match_existing_rfc_encoder():
    randomizer = random.Random(7100315)
    atoms = [None, True, False, -123456, 912, '', '0x0123ab', '\n\r\t"\\', '\0', '\x7f']
    def tree(depth):
        if not depth or randomizer.randrange(3) == 0:
            return randomizer.choice(atoms)
        if randomizer.randrange(2):
            return [tree(depth - 1) for _ in range(randomizer.randrange(5))]
        return {str(k) + randomizer.choice(('a', '\n', '')): tree(depth - 1)
                for k in range(randomizer.randrange(5))}
    for _ in range(1000):
        value = tree(4)
        assert small_ascii_json_bytes(value) == rfc8785.dumps(value)


@pytest.mark.parametrize('value', [1.0, -0.0, {'unicode': '東京'}, {'\U0001f600': 1},
                                  2**53, {'many': [1] * 8193}, {'large': 'x' * 262145}])
def test_unsupported_or_budget_exhausted_subset_falls_back(value):
    assert small_ascii_json_bytes(value) is None
    try:
        expected = rfc8785.dumps(value)
    except Exception as error:
        with pytest.raises(type(error)):
            canonical_dumps(value)
    else:
        assert canonical_dumps(value) == expected


def test_cycles_and_custom_types_cannot_enter_the_primitive_encoder():
    cyclic = []
    cyclic.append(cyclic)
    assert small_ascii_json_bytes(cyclic) is None
    class CustomInt(int):
        pass
    assert small_ascii_json_bytes({'a': CustomInt(1)}) is None


def test_encoder_owns_its_checked_content_before_calling_c_serializer(monkeypatch):
    import umi.canonical_reuse as reuse
    original = reuse.json.dumps
    source = {'a': [1]}
    def mutate_after_snapshot(value, **kwargs):
        source['a'][0] = '東京'
        source['\U0001f600'] = 2
        return original(value, **kwargs)
    monkeypatch.setattr(reuse.json, 'dumps', mutate_after_snapshot)
    assert small_ascii_json_bytes(source) == b'{"a":[1]}'
    assert small_ascii_json_bytes(source) is None


@pytest.mark.parametrize('raw', [b'{"b":2,"a":1}', b'{"a":1,"a":1}', b'{"a": 1}',
                                b'{"a":1.0}', b'{"a":"\\u0061"}'])
def test_noncanonical_retained_bytes_remain_rejected(raw):
    assert json.loads(raw) is not None
    assert not is_canonical_json(raw)
