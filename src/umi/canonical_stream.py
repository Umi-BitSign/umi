"""Validate, count, hash and compare RFC 8785 bytes without output buffers."""

import hashlib
import io
from typing import Any

import rfc8785
from pydantic import BaseModel

from .canonical_aggregate import AggregateStreamModel, dump_aggregate


class _ComparisonSink:
    def __init__(self, expected: bytes) -> None:
        self.expected = expected
        self.position = 0
        self.equal = True

    def write(self, chunk: bytes) -> int:
        self.equal = self.equal and self.expected.startswith(chunk, self.position)
        self.position += len(chunk)
        return len(chunk)


class _CountingSink:
    def __init__(self) -> None:
        self.size = 0

    def write(self, chunk: bytes) -> int:
        self.size += len(chunk)
        return len(chunk)


class _HashingSink(_CountingSink):
    def __init__(self, prefix: bytes) -> None:
        super().__init__()
        self.digest = hashlib.sha256(prefix)

    def write(self, chunk: bytes) -> int:
        self.digest.update(chunk)
        return super().write(chunk)


def _dump(value: BaseModel | Any, sink) -> None:
    if isinstance(value, BaseModel):
        if isinstance(value, AggregateStreamModel):
            dump_aggregate(value, sink)
            return
        value = value.model_dump(mode="json", by_alias=True)
    rfc8785.dump(value, sink)


def aggregate_json_bytes(value: BaseModel) -> bytes:
    """Buffer canonical output without first copying the entire aggregate graph."""
    sink = io.BytesIO()
    _dump(value, sink)
    return sink.getvalue()


def canonical_json_size(value: BaseModel | Any) -> int:
    """Validate every RFC 8785 input and count exact bytes without output storage."""
    sink = _CountingSink()
    _dump(value, sink)
    return sink.size


def canonical_json_sha256(value: BaseModel | Any, prefix: bytes) -> str:
    """Hash the exact domain prefix and canonical bytes without retaining output."""
    sink = _HashingSink(prefix)
    _dump(value, sink)
    return sink.digest.hexdigest()


def canonical_json_matches(value: BaseModel | Any, expected: bytes) -> bool:
    """Compare every canonical byte, continuing after mismatches to validate all input.

    No model content, schema validation or signature check is cached or skipped.
    Aggregate inventories use the same typed serialization one object at a time.
    """
    sink = _ComparisonSink(expected)
    _dump(value, sink)
    return sink.equal and sink.position == len(expected)


class _AggregateDigestComparison:
    """Compare once while hashing selected nested aggregates in bounded chunks."""

    def __init__(self, expected, selected, prefix, progress):
        self.expected, self.selected, self.prefix = expected, selected, prefix
        self.progress = progress
        self.buffer = bytearray()
        self.position = 0
        self.equal = True
        self.active = []
        self.digests = {}

    def _flush(self):
        if not self.buffer:
            return
        self._consume(self.buffer)
        self.buffer.clear()

    def _consume(self, chunk):
        self.equal = self.equal and self.expected.startswith(chunk, self.position)
        self.position += len(chunk)
        for _, hashing in self.active:
            hashing.update(chunk)

    def write(self, chunk):
        if len(chunk) >= 65536:
            self._flush()
            self._consume(chunk)
        else:
            self.buffer.extend(chunk)
            if len(self.buffer) >= 65536:
                self._flush()
        return len(chunk)

    def aggregate_enter(self, value):
        if any(value is target for target in self.selected):
            self._flush()
            if id(value) in self.digests:
                raise ValueError("canonical aggregate selection is repeated")
            self.active.append((value, hashlib.sha256(self.prefix)))

    def aggregate_leave(self, value):
        if any(value is target for target in self.selected):
            self._flush()
            actual, hashing = self.active.pop()
            if actual is not value:
                raise ValueError("canonical aggregate selection is not nested")
            self.digests[id(value)] = hashing.hexdigest()

    def aggregate_item(self, value):
        if self.progress is not None:
            self.progress(value)


def canonical_json_matches_digests(value, expected, selected, prefix, *, progress=None):
    """Validate exact canonical bytes and hash selected envelopes in that pass.

    Digests are returned only for exact selected model instances encountered by
    the canonical aggregate traversal. Unsupported/custom aggregate serializers
    cannot quietly produce a digest for an unvisited nested field. Callers must
    reject a false match before using any returned digest as authenticated input.
    """
    sink = _AggregateDigestComparison(expected, selected, prefix, progress)
    _dump(value, sink)
    sink._flush()
    if sink.active or any(id(target) not in sink.digests for target in selected):
        raise ValueError("canonical digest selection was not traversed")
    return (
        sink.equal and sink.position == len(expected),
        tuple(sink.digests[id(target)] for target in selected),
    )
