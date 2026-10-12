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
