"""Bounded reuse of successful canonical reservation decoding, never capacity.

Callers still read every current SQL row and compare all typed allowance columns.
Only an immutable four-field fact is retained; neither limits, holds, database
contents nor a capacity/authorization decision can be borrowed from this cache.
"""

from __future__ import annotations

import os
from collections import OrderedDict
from threading import RLock

_MAXIMUM_BYTES = 32 * 1024**2
_MAXIMUM_ENTRIES = 65536
_lock = RLock()
_entries = OrderedDict()
_bytes = 0
_pid = os.getpid()


def decoded_reservation(raw, decode):
    """Decode exact bytes once; return a fresh mapping to each owned reader."""
    global _bytes, _pid
    # Only native bounded BLOBs enter reuse. Other accepted decoder inputs keep
    # their original path, with no coercion or negative-result memoization.
    if type(raw) is not bytes or not 1 <= len(raw) <= 8192:
        return decode(raw)
    with _lock:
        if _pid != os.getpid():
            _entries.clear()
            _bytes = 0
            _pid = os.getpid()
        saved = _entries.get(raw)
        if saved is not None:
            _entries.move_to_end(raw)
        if saved is None:
            return _decode_and_remember(raw, decode)
    return dict(zip(("kind", "key", "maximum_bytes", "value_sha256"), saved[0], strict=True))


def _decode_and_remember(raw, decode):
    """Called under the cache mutex so concurrent first reads share one decode."""
    global _bytes
    document = decode(raw)
    fact = tuple(document[key] for key in ("kind", "key", "maximum_bytes", "value_sha256"))
    # Charge both key bytes and decoded strings plus per-entry overhead.
    # Entry count separately bounds dictionary/tuple bookkeeping.
    size = len(raw) + 256 + sum(len(v.encode()) for v in fact if type(v) is str)
    saved = (fact, size)
    if size <= _MAXIMUM_BYTES:
        with _lock:
            prior = _entries.pop(raw, None)
            if prior is not None:
                _bytes -= prior[1]
            while _entries and (
                len(_entries) >= _MAXIMUM_ENTRIES or _bytes + size > _MAXIMUM_BYTES
            ):
                _, old = _entries.popitem(last=False)
                _bytes -= old[1]
            _entries[raw] = saved
            _bytes += size
    return dict(zip(("kind", "key", "maximum_bytes", "value_sha256"), saved[0], strict=True))
