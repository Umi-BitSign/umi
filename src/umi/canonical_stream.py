"""Compare exact RFC 8785 bytes without retaining another serialized document."""

from typing import Any

import rfc8785
from pydantic import BaseModel


class _ComparisonSink:
    def __init__(self, expected: bytes) -> None:
        self.expected = expected
        self.position = 0
        self.equal = True

    def write(self, chunk: bytes) -> int:
        self.equal = self.equal and self.expected.startswith(chunk, self.position)
        self.position += len(chunk)
        return len(chunk)


def canonical_json_matches(value: BaseModel | Any, expected: bytes) -> bool:
    """Run the same serializer and compare every byte, including the final length.

    Continue serialization after a mismatch so invalid RFC inputs still raise.
    Model dumps, schema validation and signature checks are not cached or skipped.
    This avoids the output buffer, not the parsed input or per-string encoding.
    """
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json", by_alias=True)
    sink = _ComparisonSink(expected)
    rfc8785.dump(value, sink)
    return sink.equal and sink.position == len(expected)
