"""Operation-local reuse of successful RFC 8785 serialization, never authority.

Models are dumped afresh by the caller. Keys contain exact JSON content, not
model identities or content hashes. Only serialization bytes are memoized;
schema validation, signature verification, policy decisions, receipt/conflict
reads, and finalized-head collection are never memoized.
"""

from __future__ import annotations

import json
import threading
from collections import OrderedDict
from contextlib import contextmanager
from contextvars import ContextVar

import rfc8785

# Budgets cover retained key/output bytes and entry count, not total RSS or
# transient input snapshots. Exceeding either uses ordinary serialization;
# it never rejects an input or changes any protocol/transport size limit.
_MAXIMUM_BYTES = 8 * 1024**2
_MAXIMUM_ENTRIES = 4096


class _Uncacheable(TypeError):
    pass


def _snapshot(value):
    """Own the lookup content; exclude coercions which alias invalid RFC inputs."""
    kind = type(value)
    if kind is dict:
        items = tuple(value.items())
        if any(type(k) is not str for k, _ in items):
            raise _Uncacheable
        return {k: _snapshot(v) for k, v in items}
    if kind in (list, tuple):
        return [_snapshot(v) for v in tuple(value)]
    if kind in (str, int, float, bool, type(None)):
        return value
    raise _Uncacheable


class _CanonicalCache:
    def __init__(self, maximum_bytes: int, maximum_entries: int):
        self.maximum_bytes = maximum_bytes
        self.maximum_entries = maximum_entries
        self.entries: OrderedDict[bytes, bytes] = OrderedDict()
        self.size = 0
        self.closed = False
        self.lock = threading.Lock()

    def dumps(self, value) -> bytes:
        if self.closed or not self.maximum_bytes or not self.maximum_entries:
            return rfc8785.dumps(value)
        try:
            snapshot = _snapshot(value)
        except _Uncacheable:
            return rfc8785.dumps(value)
        try:
            # This inexpensive C serializer is only a lookup key. The accepted
            # output always comes from rfc8785. Preserve non-BMP characters and
            # reject raw surrogate pairs instead of aliasing valid Unicode.
            key = json.dumps(snapshot, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        except (ValueError, UnicodeError):
            return rfc8785.dumps(snapshot)
        if len(key) > self.maximum_bytes:
            return rfc8785.dumps(snapshot)
        with self.lock:
            if not self.closed and key in self.entries:
                self.entries.move_to_end(key)
                return self.entries[key]
        # Do not hold a lock during serialization, and never retain failures.
        result = rfc8785.dumps(snapshot)
        size = len(key) + len(result)
        if size <= self.maximum_bytes:
            with self.lock:
                if not self.closed and key not in self.entries:
                    while self.entries and (
                        self.size + size > self.maximum_bytes
                        or len(self.entries) >= self.maximum_entries
                    ):
                        old_key, old_result = self.entries.popitem(last=False)
                        self.size -= len(old_key) + len(old_result)
                    self.entries[key] = result
                    self.size += size
        return result

    def close(self) -> None:
        with self.lock:
            self.closed = True
            self.entries.clear()
            self.size = 0


_ACTIVE: ContextVar[_CanonicalCache | None] = ContextVar("canonical_reuse", default=None)


@contextmanager
def canonical_json_reuse(
    *, maximum_bytes: int = _MAXIMUM_BYTES, maximum_entries: int = _MAXIMUM_ENTRIES
):
    """Share canonical bytes inside one synchronous operation, then release them.

    Nested scopes reuse the outer budget. Context copies cannot keep retained bytes
    alive after the outer scope exits: their cache is explicitly closed and cleared.
    Zero disables reuse without changing accepted inputs. This does not skip any
    Pydantic or semantic validation, including validation of identical input bytes.
    """
    if maximum_bytes < 0 or maximum_entries < 0:
        raise ValueError("canonical reuse budgets must be nonnegative")
    existing = _ACTIVE.get()
    if existing is not None and not existing.closed:
        yield
        return
    cache = _CanonicalCache(maximum_bytes, maximum_entries)
    token = _ACTIVE.set(cache)
    try:
        yield
    finally:
        cache.close()
        _ACTIVE.reset(token)


def canonical_dumps(value) -> bytes:
    cache = _ACTIVE.get()
    return rfc8785.dumps(value) if cache is None else cache.dumps(value)
