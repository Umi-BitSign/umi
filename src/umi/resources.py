"""Exact resource accounting and fail-closed protocol ceilings."""

from __future__ import annotations

import threading
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from fractions import Fraction


class ResourceLimitExceeded(RuntimeError):
    """A policy-pinned byte, attempt, capacity, or deadline ceiling was reached."""


@dataclass(frozen=True)
class ResourceSnapshot:
    window_wire_bytes: int
    assignment_wire_bytes: tuple[tuple[str, int], ...]
    attempts: tuple[tuple[str, int], ...]


class ResourceLedger:
    """Thread-safe accounting for every attempted assignment and window byte."""

    def __init__(
        self,
        *,
        maximum_assignment_wire_bytes: int,
        maximum_window_wire_bytes: int,
    ) -> None:
        if maximum_assignment_wire_bytes <= 0 or maximum_window_wire_bytes <= 0:
            raise ValueError("wire byte ceilings must be positive")
        self.maximum_assignment_wire_bytes = maximum_assignment_wire_bytes
        self.maximum_window_wire_bytes = maximum_window_wire_bytes
        self._window_bytes = 0
        self._assignment_bytes: dict[str, int] = {}
        self._attempts: dict[str, int] = {}
        self._lock = threading.Lock()

    def charge(self, byte_count: int, *, assignment_id: str | None = None) -> None:
        if isinstance(byte_count, bool) or not isinstance(byte_count, int) or byte_count < 0:
            raise ValueError("charged byte count must be a non-negative integer")
        if assignment_id is not None and not assignment_id:
            raise ValueError("assignment ID must not be empty")
        with self._lock:
            window_total = self._window_bytes + byte_count
            if window_total > self.maximum_window_wire_bytes:
                raise ResourceLimitExceeded("validator window wire-byte ceiling reached")
            if assignment_id is not None:
                assignment_total = self._assignment_bytes.get(assignment_id, 0) + byte_count
                if assignment_total > self.maximum_assignment_wire_bytes:
                    raise ResourceLimitExceeded("assignment wire-byte ceiling reached")
                self._assignment_bytes[assignment_id] = assignment_total
            self._window_bytes = window_total

    def begin_attempt(self, key: str, *, maximum_attempts: int) -> int:
        if not key:
            raise ValueError("attempt key must not be empty")
        if maximum_attempts <= 0:
            raise ValueError("maximum attempts must be positive")
        with self._lock:
            next_count = self._attempts.get(key, 0) + 1
            if next_count > maximum_attempts:
                raise ResourceLimitExceeded("attempt ceiling reached")
            self._attempts[key] = next_count
            return next_count

    def snapshot(self) -> ResourceSnapshot:
        with self._lock:
            return ResourceSnapshot(
                window_wire_bytes=self._window_bytes,
                assignment_wire_bytes=tuple(sorted(self._assignment_bytes.items())),
                attempts=tuple(sorted(self._attempts.items())),
            )


@dataclass(frozen=True)
class DeadlineStage:
    stage_id: str
    start_ms: int
    deadline_ms: int
    completion_ms: int | None

    def __post_init__(self) -> None:
        if not self.stage_id:
            raise ValueError("deadline stage ID must not be empty")
        for name in ("start_ms", "deadline_ms"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{name} must be an integer")
        if self.deadline_ms <= self.start_ms:
            raise ValueError("deadline must be later than stage start")
        if self.completion_ms is not None and (
            isinstance(self.completion_ms, bool) or not isinstance(self.completion_ms, int)
        ):
            raise TypeError("completion_ms must be an integer or null")

    @property
    def successful(self) -> bool:
        return (
            self.completion_ms is not None
            and self.start_ms <= self.completion_ms < self.deadline_ms
        )

    @property
    def utilization(self) -> Fraction:
        if not self.successful or self.completion_ms is None:
            raise ResourceLimitExceeded("capacity deadline miss")
        return Fraction(
            self.completion_ms - self.start_ms,
            self.deadline_ms - self.start_ms,
        )


def nearest_rank_percentile(values: Sequence[Fraction], percentile: Fraction) -> Fraction:
    if not values:
        raise ValueError("percentile input must not be empty")
    if not isinstance(percentile, Fraction) or not 0 < percentile <= 1:
        raise ValueError("percentile must be an exact fraction in (0, 1]")
    if any(not isinstance(value, Fraction) or value < 0 for value in values):
        raise ValueError("percentile values must be non-negative exact fractions")
    rank = max(
        1,
        (percentile.numerator * len(values) + percentile.denominator - 1) // percentile.denominator,
    )
    return sorted(values)[rank - 1]


def retained_storage_bytes(objects: Iterable[tuple[str, int]]) -> int:
    sizes: dict[str, int] = {}
    for digest, size in objects:
        if not digest:
            raise ValueError("retained object digest must not be empty")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise ValueError("retained object size must be a non-negative integer")
        previous = sizes.get(digest)
        if previous is not None and previous != size:
            raise ValueError("one retained digest has conflicting sizes")
        sizes[digest] = size
    return sum(sizes.values())


def audit_bundle_bytes(manifest_bytes: bytes, object_sizes: Mapping[str, int]) -> int:
    if not isinstance(manifest_bytes, bytes):
        raise TypeError("bundle manifest must be exact bytes")
    return len(manifest_bytes) + retained_storage_bytes(object_sizes.items())


@dataclass(frozen=True)
class PreflightBound:
    assignment_count: int
    shared_artifact_bytes: int
    retained_object_bytes: int
    audit_manifest_bytes: int
    audit_object_bytes: int
    maximum_request_transmissions: int
    maximum_response_bodies: int
    maximum_http_header_bytes: int
    maximum_request_body_bytes: int
    maximum_response_body_bytes: int

    def __post_init__(self) -> None:
        for name, value in vars(self).items():
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")
        if self.assignment_count == 0:
            raise ValueError("preflight requires at least one assignment")

    @property
    def assignment_wire_bytes(self) -> int:
        return self.maximum_request_transmissions * (
            self.maximum_http_header_bytes + self.maximum_request_body_bytes
        ) + self.maximum_response_bodies * (
            self.maximum_http_header_bytes + self.maximum_response_body_bytes
        )

    @property
    def window_wire_bytes(self) -> int:
        return self.shared_artifact_bytes + self.assignment_count * self.assignment_wire_bytes

    @property
    def audit_bundle_bytes(self) -> int:
        return self.audit_manifest_bytes + self.audit_object_bytes

    def enforce(
        self,
        *,
        maximum_assignment_wire_bytes: int,
        maximum_window_wire_bytes: int,
        retained_storage_capacity: int,
        maximum_audit_bundle_bytes: int,
    ) -> None:
        if self.assignment_wire_bytes > maximum_assignment_wire_bytes:
            raise ResourceLimitExceeded("worst-case assignment exceeds its wire ceiling")
        if self.window_wire_bytes > maximum_window_wire_bytes:
            raise ResourceLimitExceeded("worst-case window exceeds its wire ceiling")
        if self.retained_object_bytes > retained_storage_capacity:
            raise ResourceLimitExceeded("worst-case retained objects exceed declared storage")
        if self.audit_bundle_bytes > maximum_audit_bundle_bytes:
            raise ResourceLimitExceeded(
                "worst-case audit manifest and objects exceed the bundle ceiling"
            )


__all__ = [
    "DeadlineStage",
    "PreflightBound",
    "ResourceLedger",
    "ResourceLimitExceeded",
    "ResourceSnapshot",
    "audit_bundle_bytes",
    "nearest_rank_percentile",
    "retained_storage_bytes",
]
