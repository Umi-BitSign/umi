"""Journal-local, byte-budgeted reuse of immutable retirement validation facts.

The owner supplies exact-content keys and keeps its policy context fixed for the
lifetime of this cache. No process-global cache or durable authority is created;
callers must still reread and validate transactional journal state on every use.

Weights approximate retained Python objects, including tuple/frozen-dataclass
members, instance dictionaries/slots, keys and conservative LRU entry overhead.
Shared objects are counted once within an entry and again across entries. The
budget excludes fixed cache/lock overhead, transient sizing work and references
held by callers, so it is not an RSS limit. Too-large or mutable values simply
are not cached; they do not change which native inputs may be validated.
"""

from __future__ import annotations

import sys
import threading
from collections import OrderedDict
from dataclasses import fields, is_dataclass

DEFAULT_MAXIMUM_BYTES = 32 * 1024**2
# Account for the stored (value, weight) pair, its weight integer, OrderedDict
# links/hash-table allocation and spare table capacity without an entry cap.
_ENTRY_OVERHEAD = sys.getsizeof((None, 0)) + sys.getsizeof(0) + 256
_ATOMS = (str, bytes, int, float, bool, type(None))


def _entry_weight(key, value, maximum):
    size = _ENTRY_OVERHEAD
    seen = set()
    pending = [key, value]
    while pending:
        current = pending.pop()
        address = id(current)
        if address in seen:
            continue
        seen.add(address)
        size += sys.getsizeof(current)
        if size > maximum:
            return None
        kind = type(current)
        if kind in _ATOMS:
            continue
        if kind in (tuple, frozenset):
            pending.extend(current)
            continue
        if not is_dataclass(current) or isinstance(current, type):
            return None
        if not current.__dataclass_params__.frozen:
            return None
        pending.extend(getattr(current, f.name) for f in fields(current))
        # A frozen dataclass may use a dict, slots, inherited slots, or both.
        # Count actual storage rather than only the shallow object header.
        storage = getattr(current, "__dict__", None)
        if storage is not None and id(storage) not in seen:
            seen.add(id(storage))
            size += sys.getsizeof(storage)
            if size > maximum:
                return None
            pending.extend(storage.keys())
            pending.extend(storage.values())
        for base in kind.__mro__:
            slots = base.__dict__.get("__slots__", ())
            if isinstance(slots, str):
                slots = (slots,)
            for name in slots:
                if name in ("__dict__", "__weakref__"):
                    continue
                if name.startswith("__") and not name.endswith("__"):
                    name = "_" + base.__name__.lstrip("_") + name
                try:
                    member = getattr(current, name)
                except AttributeError:
                    continue
                pending.append(member)
    return size


class RetirementValidationCache:
    """Thread-safe weighted LRU. Use one instance per fixed-context journal.

    get(key) returns facts or None on a miss and refreshes recency. put(key,
    facts) returns whether they were cached. Replacement is atomic; an oversized
    or unsupported replacement removes any old value for that key, never other
    entries. Values must be recursively immutable primitives, tuples, frozensets
    or frozen dataclasses. Normal frozen-dataclass semantics are assumed: bypasses
    through object.__setattr__ or direct __dict__ mutation are unsupported.
    """

    def __init__(self, maximum_bytes: int = DEFAULT_MAXIMUM_BYTES):
        if type(maximum_bytes) is not int or maximum_bytes < 0:
            raise ValueError("retirement cache budget must be a nonnegative integer")
        self._maximum_bytes = maximum_bytes
        self._entries: OrderedDict[object, tuple[object, int]] = OrderedDict()
        self._retained_bytes = 0
        self._lock = threading.Lock()

    @property
    def maximum_bytes(self) -> int:
        return self._maximum_bytes

    @property
    def retained_bytes(self) -> int:
        with self._lock:
            return self._retained_bytes

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    def get(self, key):
        with self._lock:
            try:
                entry = self._entries.get(key)
            except (TypeError, RecursionError):
                return None
            if entry is None:
                return None
            self._entries.move_to_end(key)
            return entry[0]

    def put(self, key, value) -> bool:
        # Sizing does not hold the shared lock; accepted facts are immutable.
        weight = _entry_weight(key, value, self._maximum_bytes)
        try:
            hash(key)
        except (TypeError, RecursionError):
            return False
        with self._lock:
            previous = self._entries.pop(key, None)
            if previous is not None:
                self._retained_bytes -= previous[1]
            if weight is None:
                return False
            while self._entries and self._retained_bytes + weight > self._maximum_bytes:
                _, (_, removed_weight) = self._entries.popitem(last=False)
                self._retained_bytes -= removed_weight
            # Removing/reinserting also retains the exact key object we sized.
            self._entries[key] = value, weight
            self._retained_bytes += weight
            return True
