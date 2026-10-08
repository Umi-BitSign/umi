"""Private bounded reuse of static proofs for exact retained assignments.

This stores no current authority, chain head, phase or execution decision.
Callers must read journal conflict holds and every retained input before lookup.
"""

from __future__ import annotations

import hashlib
import os
from collections import OrderedDict
from copy import deepcopy
from threading import RLock

from .open_competition import digest
from .protocol import canonical_json_bytes


def _serialized_size(value: object) -> int:
    if isinstance(value, (tuple, list)):
        return 2 + max(0, len(value) - 1) + sum(_serialized_size(item) for item in value)
    return len(canonical_json_bytes(value))


def assignment_reuse_key(journal, slot, records, config, policy, cohorts):
    stored = journal.path.stat()
    return (
        os.getpid(),
        str(journal.path),
        stored.st_dev,
        stored.st_ino,
        slot,
        digest(config),
        digest(policy),
        digest(cohorts),
        *(hashlib.sha256(raw).digest() for raw in records),
    )


class AssignmentVerificationReuse:
    """Keep private copies; changed inputs, process or materialization miss."""

    def __init__(self, maximum_bytes: int = 64 * 1024**2, maximum_entries: int = 256):
        if type(maximum_bytes) is not int or maximum_bytes < 1:
            raise ValueError("assignment reuse requires a positive byte capacity")
        if type(maximum_entries) is not int or maximum_entries < 1:
            raise ValueError("assignment reuse requires a positive entry capacity")
        self.maximum_bytes, self.maximum_entries = maximum_bytes, maximum_entries
        self._pid = os.getpid()
        self._lock = RLock()
        self._entries = OrderedDict()
        self._bytes = 0

    def lookup(self, slot, key):
        if os.getpid() != self._pid:
            return None
        with self._lock:
            entry = self._entries.get(slot)
            if entry is None:
                return None
            if entry[0] != key:
                self._bytes -= entry[2]
                del self._entries[slot]
                return None
            self._entries.move_to_end(slot)
            return deepcopy(entry[1])

    def remember(self, slot, key, value):
        if os.getpid() != self._pid:
            return
        private = deepcopy(value)
        size = _serialized_size(private)
        with self._lock:
            previous = self._entries.pop(slot, None)
            if previous is not None:
                self._bytes -= previous[2]
            if size > self.maximum_bytes:
                return
            while self._entries and (
                len(self._entries) >= self.maximum_entries
                or self._bytes + size > self.maximum_bytes
            ):
                _, old = self._entries.popitem(last=False)
                self._bytes -= old[2]
            self._entries[slot] = (key, private, size)
            self._bytes += size
