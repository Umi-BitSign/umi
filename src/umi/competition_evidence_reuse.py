"""Bounded reuse of lossless encodings of identical bytes, never proof authority."""

from __future__ import annotations

import os
from collections import OrderedDict
from dataclasses import replace
from threading import Lock

from .competition_evidence_codec import EncodedEvidence, encode_evidence


class EvidenceEncodingReuse:
    """Avoid re-encoding repeated metadata while keeping returned objects independent.

    Budgets count retained input, output and digest bytes, not total process RSS.
    An oversized entry uses the ordinary encoder without retaining its result.
    Native validation, publication and journal conflict checks remain with callers.
    """

    def __init__(self, *, maximum_bytes: int = 64 * 1024**2, maximum_entries: int = 64):
        if (
            type(maximum_bytes) is not int
            or maximum_bytes < 0
            or type(maximum_entries) is not int
            or maximum_entries < 0
        ):
            raise ValueError("evidence encoding reuse budgets must be nonnegative integers")
        self.maximum_bytes = maximum_bytes
        self.maximum_entries = maximum_entries
        self._entries: OrderedDict[tuple[str, bytes], tuple[EncodedEvidence, int]] = OrderedDict()
        self._size = 0
        self._lock = Lock()
        self._pid = os.getpid()

    def encode(self, raw: bytes, *, kind: str) -> EncodedEvidence:
        if (
            type(raw) is not bytes
            or type(kind) is not str
            or not self.maximum_entries
            or len(raw) > self.maximum_bytes
            or os.getpid() != self._pid
        ):
            return encode_evidence(raw, kind=kind)
        key = (kind, raw)
        with self._lock:
            prior = self._entries.get(key)
            if prior is not None:
                self._entries.move_to_end(key)
                return replace(prior[0], objects=dict(prior[0].objects))
        # Only successful ordinary encodings enter this cache. Exact immutable
        # bytes, including their domain, are the key; no digest-only aliasing.
        encoded = encode_evidence(raw, kind=kind)
        size = (
            len(raw)
            + len(kind)
            + len(encoded.sha256)
            + len(encoded.recipe)
            + sum(len(sha) + len(value) for sha, value in encoded.objects.items())
        )
        if size <= self.maximum_bytes:
            saved = replace(encoded, objects=dict(encoded.objects))
            with self._lock:
                if key not in self._entries:
                    while self._entries and (
                        self._size + size > self.maximum_bytes
                        or len(self._entries) >= self.maximum_entries
                    ):
                        _, (_, removed) = self._entries.popitem(last=False)
                        self._size -= removed
                    self._entries[key] = saved, size
                    self._size += size
        return encoded
