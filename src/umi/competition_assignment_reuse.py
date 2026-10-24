"""Private bounded reuse of static proofs for exact retained assignments.

This stores no current authority, chain head, phase or execution decision.
Callers must read journal conflict holds and every retained input before lookup.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from collections import OrderedDict
from contextlib import suppress
from copy import deepcopy
from threading import RLock
from weakref import WeakValueDictionary

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

    @classmethod
    def for_execution(cls, purpose):
        """Explicit host operating budgets; defaults preserve older installations."""
        if purpose not in {"execution_retained", "execution_supplied"}:
            raise ValueError("execution cache budget requires an execution purpose")
        selected = []
        for name, default, ceiling in (
            ("UMI_EXECUTION_ASSIGNMENT_CACHE_BYTES", 64 * 1024**2, 512 * 1024**2),
            ("UMI_EXECUTION_ASSIGNMENT_CACHE_ENTRIES", 256, 16384),
        ):
            raw = os.environ.get(name, str(default))
            if not raw.isascii() or not raw.isdecimal() or not 1 <= int(raw) <= ceiling:
                raise ValueError("invalid execution assignment reuse operating budget: " + name)
            selected.append(int(raw))
        return cls(*selected, purpose=purpose)

    def __init__(
        self, maximum_bytes: int = 64 * 1024**2, maximum_entries: int = 256, *, purpose="assignment"
    ):
        if type(maximum_bytes) is not int or maximum_bytes < 1:
            raise ValueError("assignment reuse requires a positive byte capacity")
        if type(maximum_entries) is not int or maximum_entries < 1:
            raise ValueError("assignment reuse requires a positive entry capacity")
        self.maximum_bytes, self.maximum_entries = maximum_bytes, maximum_entries
        if purpose not in {"assignment", "execution_retained", "execution_supplied", "order_inbox"}:
            raise ValueError("unknown assignment reuse purpose")
        self.purpose = purpose
        self._pid = os.getpid()
        self._lock = RLock()
        self._entries = OrderedDict()
        self._bytes = 0
        self._owners = WeakValueDictionary()
        self._counts = dict(
            lookups=0, hits=0, misses=0, evictions=0, oversized=0, waits=0, projections=0
        )

    def _diagnostic(self):
        with suppress(Exception):
            logging.getLogger("umi.competition.progress").info(
                json.dumps(
                    dict(
                        schema="umi-assignment-reuse-progress/1",
                        pid=os.getpid(),
                        purpose=self.purpose,
                        stage="assignment_reuse_capacity",
                        status="capacity_required"
                        if self._counts["oversized"]
                        else "capacity_pressure"
                        if self._counts["evictions"]
                        else "current",
                        **self._counts,
                        retained_bytes=self._bytes,
                        maximum_bytes=self.maximum_bytes,
                        retained_entries=len(self._entries),
                        maximum_entries=self.maximum_entries,
                        certification_authority=False,
                    ),
                    separators=(",", ":"),
                )
            )

    def resolve(self, slot, key, calculate):
        """One first verification per exact retained input, with a private result."""
        return deepcopy(self._resolve_private(slot, key, calculate))

    def _project(self, slot, key, calculate, project):
        """Run a trusted read-only projection, copying only its returned value.

        This is for owned internal consumers, never a caller-supplied callback.
        The retained graph stays private; even a projection returning a nested
        mutable model receives a defensive copy. Fresh journal/conflict reads
        remain the caller's responsibility before entering this cache.
        """
        with self._lock:
            self._counts["projections"] += 1
        return deepcopy(project(self._resolve_private(slot, key, calculate)))

    def _resolve_private(self, slot, key, calculate):
        """One first verification per exact retained input, outside journal locks."""
        from .competition_transport_verification import TransferProgress

        if os.getpid() != self._pid:
            return calculate()
        with self._lock:
            gate = self._owners.get(slot)
            if gate is None:
                gate = RLock()
                self._owners[slot] = gate
        acquired = gate.acquire(blocking=False)
        if not acquired:
            with self._lock:
                self._counts["waits"] += 1
            with TransferProgress("assignment_verification_owner", 1, unit="owners") as progress:
                progress.emit("waiting", reason="existing_local_assignment_verification")
                gate.acquire()
                progress.advance(1)
        try:
            cached = self._lookup_private(slot, key)
            if cached is not None:
                return cached
            with TransferProgress(
                "assignment_static_verification",
                1,
                unit="assignments",
                planning_unit_seconds=(0.01, 30),
            ) as progress:
                value = calculate()
                self.remember(slot, key, value)
                progress.advance(1)
                return value
        finally:
            gate.release()

    def lookup(self, slot, key):
        return deepcopy(self._lookup_private(slot, key))

    def _lookup_private(self, slot, key):
        if os.getpid() != self._pid:
            return None
        with self._lock:
            self._counts["lookups"] += 1
            entry = self._entries.get(slot)
            if entry is None:
                self._counts["misses"] += 1
                if self._counts["lookups"] % 64 == 0:
                    self._diagnostic()
                return None
            if entry[0] != key:
                self._counts["misses"] += 1
                self._bytes -= entry[2]
                del self._entries[slot]
                return None
            self._entries.move_to_end(slot)
            self._counts["hits"] += 1
            if self._counts["lookups"] % 64 == 0:
                self._diagnostic()
            private = entry[1]
        # Only owned read-only projections see this graph. Public lookup and
        # resolve still copy it, outside the cache mutex.
        return private

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
                self._counts["oversized"] += 1
                self._diagnostic()
                return
            while self._entries and (
                len(self._entries) >= self.maximum_entries
                or self._bytes + size > self.maximum_bytes
            ):
                _, old = self._entries.popitem(last=False)
                self._bytes -= old[2]
                self._counts["evictions"] += 1
            self._entries[slot] = (key, private, size)
            self._bytes += size
