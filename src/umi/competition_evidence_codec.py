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
from dataclasses import dataclass, field

from .protocol import canonical_json_bytes

MAX_EVIDENCE_BYTES = 32 * 1024**2
MAX_PROOF_OBJECT_BYTES = 2 * MAX_EVIDENCE_BYTES + 1024
MAX_METADATA_BYTES = 16 * 1024**2
MAX_RECIPE_BYTES = 4 * 1024**2
MAX_SEGMENTS = 32768
_HEX_DIGITS = b"0123456789abcdef"
_SHA = re.compile(r"[0-9a-f]{64}")
_SCHEMA = "umi-weight-evidence-recipe/1"
_PREPARED_ISSUER = object()
# R2 request geometry, not proof semantics. Retain large shared objects and
# combine only adjacent smaller segments; the original /1 decoder is unchanged.
_MIN_REMOTE_OBJECT_BYTES = 4 * 1024


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


@dataclass(frozen=True, slots=True)
class PreparedEvidenceEncoding:
    """An immutable encoding emitted only after complete ordinary decoding.

    Retaining this operation-local representation avoids scanning/re-encoding
    those same bytes for export. It is not a proof verification receipt. Every
    object and the expanded bytes have passed the unchanged codec checks.
    """

    raw: bytes = field(repr=False)
    kind: str
    sha256: str
    recipe: bytes = field(repr=False)
    objects: tuple[tuple[str, bytes], ...] = field(repr=False)
    canonical_encoder: bool = False
    _issuer: object = field(default=None, repr=False, compare=False)
    _binding: tuple = field(default=(), repr=False, compare=False)

    def for_bytes(self, raw: bytes, *, kind: str, coalesce_small: bool = False) -> EncodedEvidence:
        if type(coalesce_small) is not bool:
            raise ValueError("evidence representation selection must be explicit")
        if (
            type(self) is not PreparedEvidenceEncoding
            or self._issuer is not _PREPARED_ISSUER
            or self._binding
            != (
                id(self.raw),
                self.kind,
                self.sha256,
                id(self.recipe),
                id(self.objects),
                self.canonical_encoder,
            )
            or type(raw) is not bytes
            or kind != self.kind
            or raw != self.raw
        ):
            raise ValueError("prepared encoding differs from its decoded original bytes")
        if coalesce_small:
            return _coalesce_prepared(self)
        return EncodedEvidence(self.sha256, len(raw), self.recipe, dict(self.objects))


def _coalesce_prepared(prepared):
    # Called only after the operation-local issuer and exact-byte binding have
    # passed. Parse already checked recipe metadata; do not rehash or re-decode
    # retained large objects or repeat the native proof verifier.
    original = dict(prepared.objects)
    segments, objects, pending = [], {}, []
    offset = start = 0

    def flush():
        if not pending:
            return
        if len(pending) == 1:
            mode, sha, size = pending[0]
            segments.append([mode, sha, size])
            objects[sha] = original[sha]
        else:
            literal = prepared.raw[start:offset]
            sha = (
                prepared.sha256
                if start == 0 and offset == len(prepared.raw)
                else hashlib.sha256(literal).hexdigest()
            )
            segments.append(["b", sha, len(literal)])
            objects[sha] = literal
        pending.clear()

    for mode, sha, size in json.loads(prepared.recipe)["segments"]:
        if size >= _MIN_REMOTE_OBJECT_BYTES:
            flush()
            segments.append([mode, sha, size])
            objects[sha] = original[sha]
        else:
            if not pending:
                start = offset
            pending.append((mode, sha, size))
        offset += size * 2 if mode == "x" else size
    flush()
    recipe = canonical_json_bytes(
        {"schema": _SCHEMA, "length": len(prepared.raw), "segments": segments}
    )
    return EncodedEvidence(prepared.sha256, len(prepared.raw), recipe, objects)


def _prepare_encoding(raw, kind, sha256, recipe, objects, *, canonical_encoder=False):
    value = PreparedEvidenceEncoding(
        bytes(raw),
        kind,
        sha256,
        bytes(recipe),
        tuple(objects.items()),
        canonical_encoder=canonical_encoder,
        _issuer=_PREPARED_ISSUER,
    )
    object.__setattr__(
        value,
        "_binding",
        (
            id(value.raw),
            value.kind,
            value.sha256,
            id(value.recipe),
            id(value.objects),
            value.canonical_encoder,
        ),
    )
    return value


def _hex_spans(raw: bytes):
    """Locate the same flat quoted hex literals without a large regex scan."""
    position = 0
    while True:
        opening = raw.find(b'"', position)
        if opening < 0:
            return
        closing = raw.find(b'"', opening + 1)
        if closing < 0:
            return
        start = opening + 1
        if raw[start : start + 2] == b"0x":
            start += 2
        if closing - start >= 64 and not raw[start:closing].translate(None, _HEX_DIGITS):
            yield start, closing
            position = closing + 1
        else:
            # A failed candidate's closing quote can start the next match.
            position = closing


def encode_evidence(raw: bytes, *, kind: str, single_object: bool = False) -> EncodedEvidence:
    if not isinstance(raw, bytes):
        raise ValueError("evidence must be bytes")
    checked_size(len(raw), evidence_bound(kind))
    if type(single_object) is not bool:
        raise ValueError("evidence representation selection must be explicit")
    identity = hashlib.sha256(raw).hexdigest()
    if single_object:
        # This is the existing /1 literal representation, also emitted by the
        # ordinary encoder's size fallback. R2 first publication avoids hundreds
        # of request-latency-bound tiny objects without changing original bytes.
        recipe = canonical_json_bytes(
            {"schema": _SCHEMA, "length": len(raw), "segments": [["b", identity, len(raw)]]}
        )
        return EncodedEvidence(identity, len(raw), recipe, {identity: raw})
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
        for start, end in _hex_spans(raw):
            if (end - start) % 2:
                continue
            # Reserve the trailing literal too; otherwise the encoder could
            # emit MAX_SEGMENTS+1 while the bounded decoder correctly refuses it.
            if len(segments) + 3 > MAX_SEGMENTS:
                break
            append("b", raw[position:start])
            append("x", bytes.fromhex(raw[start:end].decode("ascii")))
            position = end
    append("b", raw[position:])
    encoded = recipe(segments)
    plain = recipe([["b", identity, len(raw)]])
    # A proof with many tiny independent objects must not inflate its payload.
    if len(encoded) > MAX_RECIPE_BYTES or len(encoded) + sum(map(len, objects.values())) >= (
        len(plain) + len(raw)
    ):
        encoded, objects = plain, {identity: raw}
    return EncodedEvidence(identity, len(raw), encoded, objects)


def encode_evidence_for_reuse(
    raw: bytes, *, kind: str, single_object: bool = False
) -> PreparedEvidenceEncoding:
    """Retain this encoder's exact output for a second owned publication."""
    encoded = encode_evidence(raw, kind=kind, single_object=single_object)
    return _prepare_encoding(
        raw,
        kind,
        encoded.sha256,
        encoded.recipe,
        encoded.objects,
        canonical_encoder=not single_object,
    )


def prepare_evidence_with_recipe(
    raw: bytes, recipe: bytes, *, kind: str
) -> PreparedEvidenceEncoding:
    """Preserve an existing encoding using the caller's exact original bytes.

    Reconstruct each segment from the bounded input already in memory, then run
    the ordinary decoder checks. This avoids refetching unchanged remote pieces
    merely to retain their existing representation. It is transport, not proof
    acceptance, and never edits an older source record or receipt.
    """
    checked_size(len(raw), evidence_bound(kind))
    objects, offset = {}, 0
    for mode, sha, size in inspect_recipe(recipe, expanded_bytes=len(raw), kind=kind):
        length = size * 2 if mode == "x" else size
        part = raw[offset : offset + length]
        offset += length
        if mode == "x":
            try:
                value = bytes.fromhex(part.decode("ascii"))
            except (ValueError, UnicodeDecodeError) as error:
                raise ValueError("retained evidence recipe differs from original bytes") from error
            if value.hex().encode("ascii") != part:
                raise ValueError("retained evidence hex differs from original bytes")
        else:
            value = part
        if len(value) != size or hashlib.sha256(value).hexdigest() != sha:
            raise ValueError("retained evidence segment differs from original bytes")
        objects[sha] = value
    return decode_evidence_for_reuse(
        recipe,
        sha256=hashlib.sha256(raw).hexdigest(),
        expanded_bytes=len(raw),
        kind=kind,
        resolve=lambda sha, size: objects[sha],
    )


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
    return _decode_evidence(
        recipe,
        sha256=sha256,
        expanded_bytes=expanded_bytes,
        kind=kind,
        resolve=resolve,
        prepare_encoding=False,
    )


def decode_evidence_for_reuse(
    recipe: bytes,
    *,
    sha256: str,
    expanded_bytes: int,
    kind: str,
    resolve: Callable[[str, int], bytes],
) -> PreparedEvidenceEncoding:
    """Run every decoder check once and retain its exact encoding for export."""
    return _decode_evidence(
        recipe,
        sha256=sha256,
        expanded_bytes=expanded_bytes,
        kind=kind,
        resolve=resolve,
        prepare_encoding=True,
    )


def _decode_evidence(
    recipe: bytes,
    *,
    sha256: str,
    expanded_bytes: int,
    kind: str,
    resolve: Callable[[str, int], bytes],
    prepare_encoding: bool,
) -> bytes | PreparedEvidenceEncoding:
    checked_digest(sha256)
    parts = inspect_recipe(recipe, expanded_bytes=expanded_bytes, kind=kind)
    result = bytearray()
    objects = {} if prepare_encoding else None
    # No nested recipes, recursive object references, decompressor, or unbounded cache.
    for mode, key, size in parts:
        value = resolve(key, size)
        if not isinstance(value, bytes) or len(value) != size:
            raise ValueError("evidence object missing or wrong size")
        if hashlib.sha256(value).hexdigest() != key:
            raise ValueError("evidence object digest changed")
        if objects is not None:
            # Own immutable bytes even when a legacy resolver uses a bytes
            # subclass. A repeated object still receives its ordinary check.
            objects[key] = bytes(value)
        result.extend(value.hex().encode("ascii") if mode == "x" else value)
    raw = bytes(result)
    if hashlib.sha256(raw).hexdigest() != sha256:
        raise ValueError("reconstructed evidence digest changed")
    if objects is not None:
        return _prepare_encoding(raw, kind, sha256, recipe, objects)
    return raw
