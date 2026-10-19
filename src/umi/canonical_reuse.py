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
_SMALL_JSON_BYTES = 256 * 1024
_SMALL_JSON_VALUES = 8192


class _SmallJSONFallback(Exception):
    pass


def small_ascii_json_bytes(value) -> bytes | None:
    """Byte-equivalent RFC 8785 encoding for a bounded exact primitive subset.

    ASCII keys have identical UTF-16/Python ordering; safe integers and ASCII
    strings have identical stdlib/RFC encodings. Floats, Unicode, subclasses,
    large trees and cycles retain the ordinary RFC path. These budgets only
    select an encoder: they never reject or shorten supported protocol inputs.
    """
    count = ceiling = 0

    def snapshot(item, depth=0):
        nonlocal count, ceiling
        count += 1
        if count > _SMALL_JSON_VALUES or depth > 64:
            raise _SmallJSONFallback
        kind = type(item)
        if kind is str:
            if len(item) > _SMALL_JSON_BYTES or not item.isascii():
                raise _SmallJSONFallback
            ceiling += 6 * len(item) + 3
        elif kind is int:
            if not -(2**53 - 1) <= item <= 2**53 - 1:
                raise _SmallJSONFallback
            ceiling += 18
        elif kind in (bool, type(None)):
            ceiling += 6
        elif kind is dict:
            if len(item) + count > _SMALL_JSON_VALUES:
                raise _SmallJSONFallback
            ceiling += 2
            owned = {}
            for key, child in tuple(item.items()):
                if type(key) is not str or len(key) > _SMALL_JSON_BYTES or not key.isascii():
                    raise _SmallJSONFallback
                ceiling += 6 * len(key) + 4
                if ceiling > _SMALL_JSON_BYTES:
                    raise _SmallJSONFallback
                owned[key] = snapshot(child, depth + 1)
            return owned
        elif kind in (list, tuple):
            if len(item) + count > _SMALL_JSON_VALUES:
                raise _SmallJSONFallback
            ceiling += 2
            return [snapshot(child, depth + 1) for child in tuple(item)]
        else:
            raise _SmallJSONFallback
        if ceiling > _SMALL_JSON_BYTES:
            raise _SmallJSONFallback
        return item

    try:
        owned = snapshot(value)
    except _SmallJSONFallback:
        return None
    return json.dumps(
        owned, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


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
    # Retained binary objects use this exact envelope. ASCII alphanumeric
    # strings need no JSON escaping; the sole key has no ordering ambiguity.
    # Keep this byte-equivalent shortcut narrower than JSON validation: custom
    # mappings/strings and every other value retain the ordinary RFC path.
    if type(value) is dict and len(value) == 1:
        key, raw = next(iter(value.items()))
        if (
            type(key) is str
            and key == "hex"
            and type(raw) is str
            and raw.isascii()
            and (not raw or raw.isalnum())
        ):
            return b"".join((b'{"hex":"', raw.encode("ascii"), b'"}'))
    cache = _ACTIVE.get()
    if cache is not None:
        return cache.dumps(value)
    encoded = small_ascii_json_bytes(value)
    return rfc8785.dumps(value) if encoded is None else encoded
