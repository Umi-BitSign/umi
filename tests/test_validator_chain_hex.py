"""Large proof decoding preserves the original strict RPC hexadecimal format."""

import itertools
import re

import pytest

from umi.validator_chain import ValidatorChainError, _bytes_from_hex


@pytest.mark.parametrize("value", [None, 1, True, b"0x00", [], {}])
def test_storage_hex_rejects_non_strings(value):
    with pytest.raises(ValidatorChainError, match="fixture_hex_invalid"):
        _bytes_from_hex(value, "fixture_hex_invalid")


def test_storage_hex_matches_original_accepted_language():
    original = re.compile(r"^0x(?:[0-9a-f]{2})*$")
    values = ["", "0X00", "0x00\n", "0x00\r\n", "0x\t00", "0xé0", "0x\uff100"]
    for length in range(5):
        values.extend(
            "0x" + "".join(chars) for chars in itertools.product("09afAF x", repeat=length)
        )
    for value in values:
        if original.fullmatch(value) is None:
            with pytest.raises(ValidatorChainError, match="fixture_hex_invalid"):
                _bytes_from_hex(value, "fixture_hex_invalid")
        else:
            assert _bytes_from_hex(value, "fixture_hex_invalid") == bytes.fromhex(value[2:])


def test_runtime_sized_hex_preserves_every_byte_and_rejects_invalid_tail():
    raw = bytes(range(256)) * (8 * 1024 * 1024 // 256)
    encoded = "0x" + raw.hex()
    assert _bytes_from_hex(encoded, "fixture_hex_invalid") == raw
    for suffix in ("f", "GG", "\n", "  "):
        with pytest.raises(ValidatorChainError, match="fixture_hex_invalid"):
            _bytes_from_hex(encoded + suffix, "fixture_hex_invalid")
