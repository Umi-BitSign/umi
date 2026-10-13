"""Exact canonical comparison for large parsed proof documents.

Native proof archives mostly contain ASCII hex strings and safe integers.  In
that restricted domain CPython's C JSON encoder and RFC 8785 produce identical
bytes.  All other inputs retain the ordinary RFC serializer and its errors.
This is serialization only: no proof, schema or authority result is reused.
"""

from __future__ import annotations

import json

import rfc8785


def _ascii_integer_tree(value) -> bool:
    kind = type(value)
    if kind is str:
        return value.isascii()
    if kind is int:
        return -(2**53 - 1) <= value <= 2**53 - 1
    if kind is bool or value is None:
        return True
    if kind is list:
        return all(_ascii_integer_tree(item) for item in value)
    if kind is dict:
        return all(
            type(key) is str and key.isascii() and _ascii_integer_tree(item)
            for key, item in value.items()
        )
    return False


def canonical_proof_matches(value, expected: bytes) -> bool:
    """Compare every byte of an already parsed, privately held JSON document.

    ASCII keys have the same code-point and UTF-16 order. JSON's integer, boolean,
    null and ASCII string encodings agree with RFC 8785. Floats, Unicode, unusual
    containers and out-of-domain integers take the reference path, including
    validating the entire input after an earlier output mismatch.

    Callers must own the parsed object for this synchronous operation; this does
    not retain mutable input or create a verification receipt.
    """
    if _ascii_integer_tree(value):
        actual = json.dumps(
            value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    else:
        actual = rfc8785.dumps(value)
    return actual == expected
