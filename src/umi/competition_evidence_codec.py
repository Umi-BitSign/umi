"""Lossless bounded representation of retained bytes, without proof interpretation.

Recipes are flat concatenations: ``b`` copies bytes; ``x`` writes lowercase hex.
Only exact byte objects deduplicate. Original evidence hashes remain unchanged.
This module grants no authority to migrate or execute a signed worker release.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass

from .protocol import canonical_json_bytes

MAX_EVIDENCE_BYTES = 32 * 1024**2
MAX_METADATA_BYTES = 16 * 1024**2
MAX_RECIPE_BYTES = 4 * 1024**2
MAX_SEGMENTS = 32768
_HEX = re.compile(rb'"0x([0-9a-f]{64,})"')
_SHA = re.compile(r"[0-9a-f]{64}")
_SCHEMA = "umi-weight-evidence-recipe/1"


def checked_digest(value: str) -> str:
    if not isinstance(value, str) or _SHA.fullmatch(value) is None:
        raise ValueError("invalid evidence digest")
    return value


def checked_size(value: int, maximum: int, *, minimum: int = 1) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError("invalid evidence size or count")
    return value


def evidence_bound(kind: str) -> int:
    if kind not in {"proof", "metadata"}:
        raise ValueError("unknown evidence kind")
    return MAX_EVIDENCE_BYTES if kind == "proof" else MAX_METADATA_BYTES


@dataclass(frozen=True)
class EncodedEvidence:
    sha256: str
    expanded_bytes: int
    recipe: bytes
    objects: dict[str, bytes]


def encode_evidence(raw: bytes, *, kind: str) -> EncodedEvidence:
    if not isinstance(raw, bytes):
        raise ValueError("evidence must be bytes")
    checked_size(len(raw), evidence_bound(kind))
    identity = hashlib.sha256(raw).hexdigest()
    objects: dict[str, bytes] = {}
    segments: list[list] = []

    def append(mode: str, part: bytes):
        if not part:
            return
        key = hashlib.sha256(part).hexdigest()
        objects[key] = part
        segments.append([mode, key, len(part)])

    def recipe(parts):
        return canonical_json_bytes({"schema": _SCHEMA, "length": len(raw), "segments": parts})

    position = 0
    if kind == "proof":
        for match in _HEX.finditer(raw):
            if len(match[1]) % 2:
                continue
            # Reserve the trailing literal too; otherwise the encoder could
            # emit MAX_SEGMENTS+1 while the bounded decoder correctly refuses it.
            if len(segments) + 3 > MAX_SEGMENTS:
                break
            append("b", raw[position : match.start(1)])
            append("x", bytes.fromhex(match[1].decode("ascii")))
            position = match.end(1)
    append("b", raw[position:])
    encoded = recipe(segments)
    plain = recipe([["b", identity, len(raw)]])
    # A proof with many tiny independent objects must not inflate its payload.
    if len(encoded) > MAX_RECIPE_BYTES or len(encoded) + sum(map(len, objects.values())) >= (
        len(plain) + len(raw)
    ):
        encoded, objects = plain, {identity: raw}
    return EncodedEvidence(identity, len(raw), encoded, objects)


def inspect_recipe(raw: bytes, *, expanded_bytes: int, kind: str) -> tuple[tuple, ...]:
    """Validate all expansion bounds before consulting any object resolver."""
    checked_size(expanded_bytes, evidence_bound(kind))
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_RECIPE_BYTES:
        raise ValueError("invalid evidence recipe size")
    try:
        body = json.loads(raw)
        if canonical_json_bytes(body) != raw:
            raise ValueError("noncanonical evidence recipe")
    except (ValueError, TypeError, RecursionError, OverflowError) as exc:
        raise ValueError("invalid evidence recipe") from exc
    if not isinstance(body, dict) or set(body) != {"schema", "length", "segments"}:
        raise ValueError("invalid evidence recipe fields")
    if body["schema"] != _SCHEMA or type(body["length"]) is not int:
        raise ValueError("invalid evidence recipe version or length")
    if body["length"] != expanded_bytes:
        raise ValueError("evidence recipe length changed")
    parts = body["segments"]
    if not isinstance(parts, list) or not 0 < len(parts) <= MAX_SEGMENTS:
        raise ValueError("invalid evidence segment count")
    total = 0
    for part in parts:
        if not isinstance(part, list) or len(part) != 3 or part[0] not in ("b", "x"):
            raise ValueError("invalid evidence segment")
        checked_digest(part[1])
        checked_size(part[2], evidence_bound(kind))
        total += part[2] * (2 if part[0] == "x" else 1)
        if total > expanded_bytes:
            raise ValueError("evidence recipe expansion exceeds bound")
    if total != expanded_bytes:
        raise ValueError("evidence recipe expansion is incomplete")
    return tuple(tuple(part) for part in parts)


def decode_evidence(
    recipe: bytes,
    *,
    sha256: str,
    expanded_bytes: int,
    kind: str,
    resolve: Callable[[str, int], bytes],
) -> bytes:
    checked_digest(sha256)
    parts = inspect_recipe(recipe, expanded_bytes=expanded_bytes, kind=kind)
    result = bytearray()
    # No nested recipes, recursive object references, decompressor, or unbounded cache.
    for mode, key, size in parts:
        value = resolve(key, size)
        if not isinstance(value, bytes) or len(value) != size:
            raise ValueError("evidence object missing or wrong size")
        if hashlib.sha256(value).hexdigest() != key:
            raise ValueError("evidence object digest changed")
        result.extend(value.hex().encode("ascii") if mode == "x" else value)
    raw = bytes(result)
    if hashlib.sha256(raw).hexdigest() != sha256:
        raise ValueError("reconstructed evidence digest changed")
    return raw
