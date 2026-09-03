"""Durable supervision and validator ports for owned GRANDPA finality.

The Rust observer verifies finality inside smoldot and emits a bounded,
hash-chained JSONL transcript.  This module keeps one observer process alive,
validates every record again in Python, and commits accepted headers to SQLite
before exposing them to validator planning or finalized-chain scanning.

An observer restart begins a new transcript at sequence zero.  A resumed
smoldot baseline can be newer than the last persisted header, so restart gaps
are recorded explicitly.  The store never invents the missing headers or
claims ancestry across such a gap.  Exact-height and adjacent-parent consumers
therefore fail closed when a required header was not observed.

These records are verifier attestations.  They are not portable GRANDPA proofs:
smoldot verifies GRANDPA internally but its public light-client API does not
export the justification or warp-proof bytes used for that decision.

The transcript and acceptance receipts are unsigned.  Their hash chains detect
alteration relative to a retained run but can be recreated offline, so direct
execution of the hash-pinned sidecar is the authority and these bytes are replay
evidence only.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import sqlite3
import stat
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from itertools import pairwise
from pathlib import Path
from typing import Any

from .chain_evidence import FinalizedSnapshotRef
from .grandpa_finality import (
    CARGO_LOCK_SHA256,
    EVIDENCE_CLASS,
    FIXTURE_SET_SHA256,
    SOURCE_REVISION,
    SOURCE_TREE_SHA256,
    FinalityAttestation,
    GrandpaFinalityLimits,
    GrandpaFinalityObserver,
    GrandpaFinalityObserverError,
)
from .policy import LiveChainObservationPin, ScoringPolicy, scoring_policy_hash
from .protocol import canonical_json_bytes
from .validator_chain_scan import (
    FinalityAttestationReplayBinding,
    VerifiedFinalizedBlockIdentity,
)
from .validator_plans import MAX_FINALITY_EVIDENCE_BYTES, VerifiedFinalizedBlock

STORE_SCHEMA = "umi-grandpa-finality-supervisor-store/1"
STORE_SCHEMA_VERSION = 2
ACCEPTANCE_RECEIPT_SCHEMA = "umi-grandpa-finality-acceptance/1"

_APPLICATION_ID = 0x554D4946  # "UMIF"
_ACCEPT_DOMAIN = b"umi-grandpa-finality-supervisor-accept-v2\0"
_ZERO_DIGEST = bytes(32)
_MAX_CANONICAL_INTEGER = (1 << 53) - 1
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_BLOCK_HASH_RE = re.compile(r"^0x[0-9a-f]{64}$")


class GrandpaFinalitySupervisorError(RuntimeError):
    """Stable fail-closed error at the durable finality boundary."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(f"GRANDPA finality supervisor failed: {reason_code}")


class GrandpaFinalityStoreCorruption(GrandpaFinalitySupervisorError):
    """Persisted rows do not reproduce under the pinned observer parser."""


class GrandpaFinalityStoreConflict(GrandpaFinalitySupervisorError):
    """A height, segment, or immutable store binding conflicts."""


@dataclass(frozen=True, slots=True)
class GrandpaFinalitySupervisorLimits:
    """Local resource ceilings for the durable observer."""

    maximum_headers: int = 1_000_000
    maximum_evidence_bytes: int = MAX_FINALITY_EVIDENCE_BYTES
    maximum_total_evidence_bytes: int = 4 * 1024 * 1024 * 1024
    maximum_database_bytes: int = 8 * 1024 * 1024 * 1024
    maximum_records_per_process: int = 100_000

    def __post_init__(self) -> None:
        for name in self.__dataclass_fields__:
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if self.maximum_evidence_bytes > MAX_FINALITY_EVIDENCE_BYTES:
            raise ValueError("finality evidence must fit the validator-plan port")
        if self.maximum_evidence_bytes > self.maximum_total_evidence_bytes:
            raise ValueError("one evidence object cannot exceed the total evidence limit")
        if self.maximum_total_evidence_bytes > self.maximum_database_bytes:
            raise ValueError("the total evidence limit cannot exceed the database limit")


@dataclass(frozen=True, slots=True)
class ObserverRunBinding:
    """Exact request values that bind one sidecar transcript segment."""

    segment_index: int
    minimum_finalized_block: int
    maximum_records: int
    startup_timeout_seconds: int

    def __post_init__(self) -> None:
        for name in (
            "segment_index",
            "minimum_finalized_block",
            "maximum_records",
            "startup_timeout_seconds",
        ):
            value = getattr(self, name)
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value < 0
                or value > _MAX_CANONICAL_INTEGER
            ):
                raise ValueError(f"{name} must be a canonical nonnegative integer")
        if self.maximum_records == 0 or self.startup_timeout_seconds == 0:
            raise ValueError("observer run limits must be positive")


@dataclass(frozen=True, slots=True)
class PersistedFinalityHead:
    """The newest full finalized header durably accepted by this store."""

    height: int
    block_hash: str
    parent_hash: str
    state_root: str
    extrinsics_root: str
    timestamp_ms: int
    accepted_at_unix_ms: int
    evidence_sha256: str
    segment_index: int
    segment_sequence: int
    restart_gap_before: bool
    acceptance_digest: str


@dataclass(frozen=True, slots=True)
class FinalityAcceptanceReceipt:
    """Canonical local-clock receipt chained to one accepted attestation."""

    height: int
    block_hash: str
    evidence_sha256: str
    segment_index: int
    segment_sequence: int
    restart_gap_before: bool
    accepted_at_unix_ms: int
    previous_acceptance_digest: str
    acceptance_digest: str
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class VerifiedFinalityScanInterval:
    """Complete verifier-owned inputs for one independently replayable scan."""

    identities: tuple[VerifiedFinalizedBlockIdentity, ...]
    attestations: tuple[bytes, ...]
    replay_bindings: tuple[FinalityAttestationReplayBinding, ...]
    acceptance_receipts: tuple[bytes, ...]

    def __post_init__(self) -> None:
        if not self.identities or not (
            len(self.identities)
            == len(self.attestations)
            == len(self.replay_bindings)
            == len(self.acceptance_receipts)
        ):
            raise ValueError("finality scan inputs must form one nonempty bijection")
        previous_receipt: FinalityAcceptanceReceipt | None = None
        for identity, attestation, encoded_receipt in zip(
            self.identities,
            self.attestations,
            self.acceptance_receipts,
            strict=True,
        ):
            if not isinstance(attestation, bytes) or not attestation:
                raise ValueError("finality scan attestation must be nonempty exact bytes")
            if hashlib.sha256(attestation).hexdigest() != identity.finality_evidence_sha256:
                raise ValueError("finality scan attestation digest disagrees with its identity")
            receipt = parse_finality_acceptance_receipt(encoded_receipt)
            if (
                receipt.height != identity.snapshot.block_number
                or receipt.block_hash != identity.snapshot.block_hash
                or receipt.evidence_sha256 != identity.finality_evidence_sha256
            ):
                raise ValueError("finality acceptance receipt disagrees with its identity")
            if (
                previous_receipt is not None
                and receipt.previous_acceptance_digest != previous_receipt.acceptance_digest
            ):
                raise ValueError("finality acceptance receipts are not hash chained")
            previous_receipt = receipt


@dataclass(frozen=True, slots=True)
class _StoredHeader:
    head: PersistedFinalityHead
    scale_header: str
    canonical_evidence: bytes
    transcript_digest: str
    previous_transcript_digest: str
    previous_finalized_hash: str | None
    ancestry_complete: bool
    previous_acceptance_digest: str


_SCHEMA_STATEMENTS = (
    """
    CREATE TABLE store_meta (
        key TEXT PRIMARY KEY,
        value BLOB NOT NULL
    ) WITHOUT ROWID
    """,
    """
    CREATE TABLE observer_segments (
        segment_index INTEGER PRIMARY KEY CHECK(segment_index >= 0),
        minimum_finalized_block INTEGER NOT NULL CHECK(minimum_finalized_block >= 0),
        maximum_records INTEGER NOT NULL CHECK(maximum_records > 0),
        startup_timeout_seconds INTEGER NOT NULL CHECK(startup_timeout_seconds > 0),
        request_id TEXT NOT NULL UNIQUE CHECK(length(request_id) = 64),
        prior_global_height INTEGER,
        prior_global_hash TEXT,
        restart_gap INTEGER NOT NULL CHECK(restart_gap IN (0, 1)),
        CHECK(
            (prior_global_height IS NULL AND prior_global_hash IS NULL) OR
            (prior_global_height >= 0 AND length(prior_global_hash) = 66)
        )
    )
    """,
    """
    CREATE TABLE finalized_headers (
        height INTEGER PRIMARY KEY CHECK(height >= 0),
        block_hash TEXT NOT NULL UNIQUE CHECK(length(block_hash) = 66),
        parent_hash TEXT NOT NULL CHECK(length(parent_hash) = 66),
        state_root TEXT NOT NULL CHECK(length(state_root) = 66),
        extrinsics_root TEXT NOT NULL CHECK(length(extrinsics_root) = 66),
        timestamp_ms INTEGER NOT NULL CHECK(timestamp_ms >= 0),
        accepted_at_unix_ms INTEGER NOT NULL CHECK(accepted_at_unix_ms > 0),
        scale_header TEXT NOT NULL CHECK(length(scale_header) >= 4),
        canonical_evidence BLOB NOT NULL CHECK(typeof(canonical_evidence) = 'blob'),
        evidence_sha256 TEXT NOT NULL UNIQUE CHECK(length(evidence_sha256) = 64),
        transcript_digest TEXT NOT NULL UNIQUE CHECK(length(transcript_digest) = 64),
        previous_transcript_digest TEXT NOT NULL CHECK(length(previous_transcript_digest) = 64),
        previous_finalized_hash TEXT,
        ancestry_complete INTEGER NOT NULL CHECK(ancestry_complete IN (0, 1)),
        segment_index INTEGER NOT NULL,
        segment_sequence INTEGER NOT NULL CHECK(segment_sequence >= 0),
        restart_gap_before INTEGER NOT NULL CHECK(restart_gap_before IN (0, 1)),
        previous_acceptance_digest TEXT NOT NULL CHECK(length(previous_acceptance_digest) = 64),
        acceptance_digest TEXT NOT NULL UNIQUE CHECK(length(acceptance_digest) = 64),
        UNIQUE(segment_index, segment_sequence),
        FOREIGN KEY(segment_index) REFERENCES observer_segments(segment_index)
            ON DELETE RESTRICT
    )
    """,
)


class DurableGrandpaFinalityPort:
    """Supervise smoldot, persist attestations, and implement validator ports."""

    def __init__(
        self,
        *,
        observer: GrandpaFinalityObserver,
        state_path: str | os.PathLike[str],
        scoring_policy_digest: str,
        chain_observation: LiveChainObservationPin,
        finality_verifier_sha256: str,
        initial_minimum_finalized_block: int,
        startup_timeout_seconds: int = 600,
        limits: GrandpaFinalitySupervisorLimits | None = None,
        busy_timeout_ms: int = 5_000,
    ) -> None:
        if not isinstance(observer, GrandpaFinalityObserver):
            raise TypeError("observer must be a GrandpaFinalityObserver")
        self._observer = observer
        self._limits = limits or GrandpaFinalitySupervisorLimits()
        self._scoring_policy_digest = _sha256(scoring_policy_digest, "scoring policy digest")
        if not isinstance(chain_observation, LiveChainObservationPin):
            raise TypeError("chain_observation must be a LiveChainObservationPin")
        self._chain_observation = chain_observation
        self._finality_verifier_sha256 = _sha256(
            finality_verifier_sha256, "finality verifier digest"
        )
        if self._finality_verifier_sha256 != observer.expected_binary_sha256:
            raise GrandpaFinalityStoreConflict("observer_binary_pin_mismatch")
        if f"0x{chain_observation.genesis_block_hash}" != observer.expected_genesis_hash:
            raise GrandpaFinalityStoreConflict("observer_genesis_pin_mismatch")
        self._initial_minimum = _canonical_uint(
            initial_minimum_finalized_block, "initial minimum finalized block"
        )
        if self._initial_minimum < observer.bootstrap_block_number:
            raise ValueError("initial minimum finalized block precedes the observer bootstrap")
        self._startup_timeout_seconds = _positive_uint(
            startup_timeout_seconds, "startup timeout seconds"
        )
        if not 1 <= self._startup_timeout_seconds <= 86_400:
            raise ValueError("startup timeout seconds must be between 1 and 86400")
        if self._limits.maximum_records_per_process > 100_000:
            raise ValueError("records per process exceeds the observer protocol maximum")
        if isinstance(busy_timeout_ms, bool) or not isinstance(busy_timeout_ms, int):
            raise TypeError("busy_timeout_ms must be an integer")
        if not 1 <= busy_timeout_ms <= 60_000:
            raise ValueError("busy_timeout_ms must be between 1 and 60000")
        self._busy_timeout_ms = busy_timeout_ms
        self._path = _prepare_database_path(state_path)
        self._run_lock = threading.Lock()
        self._initialize()

    @classmethod
    def from_policy(
        cls,
        policy: ScoringPolicy,
        *,
        target_triple: str,
        binary_path: str | os.PathLike[str],
        chain_spec_path: str | os.PathLike[str],
        state_path: str | os.PathLike[str],
        initial_minimum_finalized_block: int,
        observer_record_timeout_seconds: float = 900.0,
        observer_limits: GrandpaFinalityLimits | None = None,
        limits: GrandpaFinalitySupervisorLimits | None = None,
        startup_timeout_seconds: int = 600,
        busy_timeout_ms: int = 5_000,
    ) -> DurableGrandpaFinalityPort:
        """Build the production port from one live policy's complete pin set."""

        if not isinstance(policy, ScoringPolicy):
            raise TypeError("policy must be a ScoringPolicy")
        pins = policy.implementation_pins
        if (
            pins.pin_profile != "live_shadow_calibration"
            or pins.live_chain is None
            or pins.finality_verifier is None
        ):
            raise GrandpaFinalitySupervisorError("live_finality_policy_required")
        try:
            release_sha256 = pins.finality_verifier.release_sha256_by_target[target_triple]
        except KeyError as error:
            raise GrandpaFinalitySupervisorError("policy_target_missing") from error
        observer = GrandpaFinalityObserver.from_policy_pin(
            pins.finality_verifier,
            target_triple=target_triple,
            binary_path=binary_path,
            chain_spec_path=chain_spec_path,
            record_timeout_seconds=observer_record_timeout_seconds,
            limits=observer_limits,
        )
        return cls(
            observer=observer,
            state_path=state_path,
            scoring_policy_digest=scoring_policy_hash(policy),
            chain_observation=pins.live_chain,
            finality_verifier_sha256=release_sha256,
            initial_minimum_finalized_block=initial_minimum_finalized_block,
            startup_timeout_seconds=startup_timeout_seconds,
            limits=limits,
            busy_timeout_ms=busy_timeout_ms,
        )

    def close(self) -> None:
        """Compatibility no-op; this store opens one connection per operation."""

    def __enter__(self) -> DurableGrandpaFinalityPort:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    @property
    def scoring_policy_digest(self) -> str:
        """Return the immutable policy digest bound into this durable store."""

        return self._scoring_policy_digest

    @property
    def chain_observation(self) -> LiveChainObservationPin:
        """Return the immutable live-chain identity bound into this store."""

        return self._chain_observation

    @property
    def finality_verifier_sha256(self) -> str:
        """Return the hash-pinned smoldot observer identity for this store."""

        return self._finality_verifier_sha256

    async def finalized_head_height(self) -> int:
        """Return the newest durably accepted verifier-attested height."""

        head = await asyncio.to_thread(self.persisted_head)
        if head is None:
            raise GrandpaFinalitySupervisorError("no_verified_finalized_head")
        return head.height

    async def verified_finalized_snapshot(self) -> FinalizedSnapshotRef:
        """Return the newest state root accepted by the owned smoldot verifier."""

        head = await asyncio.to_thread(self.persisted_head)
        if head is None:
            raise GrandpaFinalitySupervisorError("no_verified_finalized_head")
        return FinalizedSnapshotRef(
            block_number=head.height,
            block_hash=head.block_hash,
            parent_hash=head.parent_hash,
            state_root=head.state_root,
        )

    async def verified_block_at(self, height: int) -> VerifiedFinalizedBlock | None:
        """Return the exact full header at ``height`` or ``None`` if it was skipped."""

        stored = await asyncio.to_thread(self._stored_header_at, height)
        if stored is None:
            return None
        return self._plan_block(stored)

    async def verified_acceptance_time_at(self, height: int) -> int | None:
        """Return the transaction-captured local acceptance time in Unix milliseconds.

        This value is append-only local conformance evidence, not a chain timestamp
        or a statement made by GRANDPA.
        """

        stored = await asyncio.to_thread(self._stored_header_at, height)
        if stored is None:
            return None
        return parse_finality_acceptance_receipt(
            _acceptance_receipt_bytes(stored)
        ).accepted_at_unix_ms

    async def verified_acceptance_receipt_at(self, height: int) -> bytes | None:
        """Return the canonical hash-chained acceptance receipt for ``height``."""

        stored = await asyncio.to_thread(self._stored_header_at, height)
        return None if stored is None else _acceptance_receipt_bytes(stored)

    async def verified_identity_at(self, height: int) -> VerifiedFinalizedBlockIdentity | None:
        """Return one adjacent parent/child identity for the chain scanner."""

        height = _canonical_uint(height, "finalized identity height")
        if height == 0:
            return None
        child, parent = await asyncio.gather(
            asyncio.to_thread(self._stored_header_at, height),
            asyncio.to_thread(self._stored_header_at, height - 1),
        )
        if child is None or parent is None or child.head.parent_hash != parent.head.block_hash:
            return None
        return VerifiedFinalizedBlockIdentity(
            snapshot=_snapshot(child),
            parent_snapshot=_snapshot(parent),
            extrinsics_root=child.head.extrinsics_root,
            finality_verifier_sha256=self._finality_verifier_sha256,
            finality_evidence_sha256=child.head.evidence_sha256,
        )

    async def verified_identities(
        self, start_height: int, end_height: int
    ) -> tuple[VerifiedFinalizedBlockIdentity, ...] | None:
        """Return a complete inclusive scan interval, or fail closed with ``None``."""

        start_height = _positive_uint(start_height, "scan start height")
        end_height = _canonical_uint(end_height, "scan end height")
        if end_height < start_height:
            raise ValueError("scan end height must not precede its start")
        rows = await asyncio.to_thread(self._stored_range, start_height - 1, end_height)
        expected_count = end_height - start_height + 2
        if len(rows) != expected_count:
            return None
        identities: list[VerifiedFinalizedBlockIdentity] = []
        for parent, child in pairwise(rows):
            if (
                child.head.height != parent.head.height + 1
                or child.head.parent_hash != parent.head.block_hash
            ):
                return None
            identities.append(
                VerifiedFinalizedBlockIdentity(
                    snapshot=_snapshot(child),
                    parent_snapshot=_snapshot(parent),
                    extrinsics_root=child.head.extrinsics_root,
                    finality_verifier_sha256=self._finality_verifier_sha256,
                    finality_evidence_sha256=child.head.evidence_sha256,
                )
            )
        return tuple(identities)

    async def verified_scan_interval(
        self,
        start_height: int,
        end_height: int,
    ) -> VerifiedFinalityScanInterval | None:
        """Return full replay inputs for a complete adjacent finalized interval.

        The replay binding is reconstructed from the immutable observer-segment
        row and the exact prior record in that segment.  Values asserted by the
        attestation itself are never used as their own expected values.
        """

        identities = await self.verified_identities(start_height, end_height)
        if identities is None:
            return None
        replay = await asyncio.to_thread(
            self._stored_replay_range,
            start_height,
            end_height,
        )
        if replay is None or len(replay) != len(identities):
            return None
        attestations: list[bytes] = []
        bindings: list[FinalityAttestationReplayBinding] = []
        acceptance_receipts: list[bytes] = []
        for identity, (stored, binding) in zip(identities, replay, strict=True):
            if (
                stored.head.height != identity.snapshot.block_number
                or stored.head.block_hash != identity.snapshot.block_hash
                or stored.head.evidence_sha256 != identity.finality_evidence_sha256
            ):
                raise GrandpaFinalityStoreCorruption("scan_replay_identity_mismatch")
            attestations.append(stored.canonical_evidence)
            bindings.append(binding)
            acceptance_receipts.append(_acceptance_receipt_bytes(stored))
        return VerifiedFinalityScanInterval(
            identities=identities,
            attestations=tuple(attestations),
            replay_bindings=tuple(bindings),
            acceptance_receipts=tuple(acceptance_receipts),
        )

    def persisted_head(self) -> PersistedFinalityHead | None:
        """Return the newest accepted header without starting the observer."""

        with self._connect(read_only=True) as connection:
            row = connection.execute(
                "SELECT * FROM finalized_headers ORDER BY height DESC LIMIT 1"
            ).fetchone()
        return None if row is None else _stored_header(row).head

    def next_run_binding(self) -> ObserverRunBinding:
        """Derive the exact next segment request from committed state."""

        with self._connect(read_only=True) as connection:
            segment = connection.execute(
                "SELECT COALESCE(MAX(segment_index), -1) + 1 FROM observer_segments"
            ).fetchone()[0]
            head = connection.execute(
                "SELECT height FROM finalized_headers ORDER BY height DESC LIMIT 1"
            ).fetchone()
        minimum = self._initial_minimum if head is None else max(self._initial_minimum, head[0] + 1)
        return ObserverRunBinding(
            segment_index=segment,
            minimum_finalized_block=minimum,
            maximum_records=self._limits.maximum_records_per_process,
            startup_timeout_seconds=self._startup_timeout_seconds,
        )

    def accept_attestation(
        self, binding: ObserverRunBinding, attestation: FinalityAttestation
    ) -> PersistedFinalityHead:
        """Atomically accept one already parsed record, with idempotent exact replay."""

        if not isinstance(binding, ObserverRunBinding):
            raise TypeError("binding must be an ObserverRunBinding")
        if not isinstance(attestation, FinalityAttestation):
            raise TypeError("attestation must be a FinalityAttestation")
        if len(attestation.canonical_bytes) > self._limits.maximum_evidence_bytes:
            raise GrandpaFinalitySupervisorError("evidence_size_limit")
        with self._connect(read_only=True) as connection:
            existing = connection.execute(
                """
                SELECT h.*, s.minimum_finalized_block, s.maximum_records,
                       s.startup_timeout_seconds, s.request_id
                FROM finalized_headers AS h
                JOIN observer_segments AS s USING(segment_index)
                WHERE h.height = ?
                """,
                (attestation.block.number,),
            ).fetchone()
        if existing is not None:
            exact_binding = (
                existing["segment_index"] == binding.segment_index
                and existing["minimum_finalized_block"] == binding.minimum_finalized_block
                and existing["maximum_records"] == binding.maximum_records
                and existing["startup_timeout_seconds"] == binding.startup_timeout_seconds
            )
            if exact_binding and existing["canonical_evidence"] == attestation.canonical_bytes:
                return _stored_header(existing).head
            raise GrandpaFinalityStoreConflict("finalized_height_conflict")
        # Reparse at the durable boundary; callers cannot bypass the observer's
        # pin, header, ancestry, or transcript checks with a forged dataclass.
        with self._connect(read_only=True) as connection:
            prior = connection.execute(
                """
                SELECT * FROM finalized_headers
                WHERE segment_index = ? ORDER BY segment_sequence DESC LIMIT 1
                """,
                (binding.segment_index,),
            ).fetchone()
        prior_attestation = None if prior is None else _stored_header(prior)
        try:
            parsed = self._observer.validate_attestation(
                attestation.canonical_bytes,
                minimum_finalized_block=binding.minimum_finalized_block,
                maximum_records=binding.maximum_records,
                startup_timeout_seconds=binding.startup_timeout_seconds,
                expected_sequence=(
                    0 if prior_attestation is None else prior_attestation.head.segment_sequence + 1
                ),
                previous_hash=(
                    None if prior_attestation is None else prior_attestation.head.block_hash
                ),
                previous_digest=(
                    "0" * 64 if prior_attestation is None else prior_attestation.transcript_digest
                ),
                previous_number=(
                    None if prior_attestation is None else prior_attestation.head.height
                ),
                previous_timestamp_ms=(
                    None if prior_attestation is None else prior_attestation.head.timestamp_ms
                ),
            )
        except GrandpaFinalityObserverError as error:
            raise GrandpaFinalitySupervisorError(f"attestation_{error.reason_code}") from error
        if parsed != attestation:
            raise GrandpaFinalityStoreConflict("attestation_dataclass_mismatch")
        return self._commit(binding, parsed)

    def run_blocking(self, stop_event: threading.Event) -> None:
        """Run the owned observer until stopped; any observer fault is terminal."""

        if not isinstance(stop_event, threading.Event):
            raise TypeError("stop_event must be a threading.Event")
        if not self._run_lock.acquire(blocking=False):
            raise GrandpaFinalitySupervisorError("observer_already_running")
        try:
            while not stop_event.is_set():
                binding = self.next_run_binding()
                try:
                    for attestation in self._observer.attestations(
                        minimum_finalized_block=binding.minimum_finalized_block,
                        maximum_records=binding.maximum_records,
                        startup_timeout_seconds=binding.startup_timeout_seconds,
                        stop_requested=stop_event.is_set,
                    ):
                        self.accept_attestation(binding, attestation)
                        if stop_event.is_set():
                            break
                except GrandpaFinalityObserverError as error:
                    raise GrandpaFinalitySupervisorError(f"observer_{error.reason_code}") from error
        finally:
            self._run_lock.release()

    async def run(self, stop_event: asyncio.Event) -> None:
        """Async service entry point around the blocking supervised observer."""

        if not isinstance(stop_event, asyncio.Event):
            raise TypeError("stop_event must be an asyncio.Event")
        thread_stop = threading.Event()

        async def bridge_stop() -> None:
            await stop_event.wait()
            thread_stop.set()

        watcher = asyncio.create_task(bridge_stop())
        try:
            await asyncio.to_thread(self.run_blocking, thread_stop)
        finally:
            thread_stop.set()
            watcher.cancel()
            with suppress(asyncio.CancelledError):
                await watcher

    def audit(self) -> None:
        """Replay every segment through the pinned parser and compare all rows."""

        try:
            with self._connect(read_only=True) as connection:
                if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                    raise GrandpaFinalityStoreCorruption("sqlite_quick_check_failed")
                if connection.execute("PRAGMA foreign_key_check").fetchall():
                    raise GrandpaFinalityStoreCorruption("sqlite_foreign_key_check_failed")
                stored_config = connection.execute(
                    "SELECT value FROM store_meta WHERE key = 'config'"
                ).fetchone()
                stored_config_hash = connection.execute(
                    "SELECT value FROM store_meta WHERE key = 'config_sha256'"
                ).fetchone()
                stored_head_digest = connection.execute(
                    "SELECT value FROM store_meta WHERE key = 'head_acceptance_digest'"
                ).fetchone()
                if (
                    stored_config is None
                    or stored_config_hash is None
                    or stored_head_digest is None
                ):
                    raise GrandpaFinalityStoreCorruption("store_meta_missing")
                expected_config = self._config_bytes()
                if stored_config[0] != expected_config:
                    raise GrandpaFinalityStoreConflict("store_binding_mismatch")
                if stored_config_hash[0] != hashlib.sha256(expected_config).digest():
                    raise GrandpaFinalityStoreCorruption("config_digest_mismatch")
                segments = connection.execute(
                    "SELECT * FROM observer_segments ORDER BY segment_index"
                ).fetchall()
                rows = connection.execute(
                    "SELECT * FROM finalized_headers ORDER BY height"
                ).fetchall()
        except sqlite3.DatabaseError as error:
            raise GrandpaFinalityStoreCorruption("sqlite_read_failed") from error

        if len(rows) > self._limits.maximum_headers:
            raise GrandpaFinalityStoreCorruption("header_count_limit")
        total_evidence = sum(len(row["canonical_evidence"]) for row in rows)
        if total_evidence > self._limits.maximum_total_evidence_bytes:
            raise GrandpaFinalityStoreCorruption("total_evidence_limit")
        by_segment: dict[int, list[sqlite3.Row]] = {}
        for row in rows:
            by_segment.setdefault(row["segment_index"], []).append(row)
        if set(by_segment) != {row["segment_index"] for row in segments}:
            raise GrandpaFinalityStoreCorruption("empty_or_orphan_segment")

        previous_global: _StoredHeader | None = None
        previous_acceptance = _ZERO_DIGEST
        previous_accepted_at_unix_ms = 0
        for expected_segment_index, segment in enumerate(segments):
            if segment["segment_index"] != expected_segment_index:
                raise GrandpaFinalityStoreCorruption("nonconsecutive_segment")
            expected_minimum = (
                self._initial_minimum
                if previous_global is None
                else max(self._initial_minimum, previous_global.head.height + 1)
            )
            if (
                segment["minimum_finalized_block"] != expected_minimum
                or segment["maximum_records"] != self._limits.maximum_records_per_process
                or segment["startup_timeout_seconds"] != self._startup_timeout_seconds
            ):
                raise GrandpaFinalityStoreCorruption("segment_run_binding_mismatch")
            segment_rows = by_segment[segment["segment_index"]]
            previous_segment: FinalityAttestation | None = None
            for expected_sequence, row in enumerate(segment_rows):
                stored = _stored_header(row)
                try:
                    parsed = self._observer.validate_attestation(
                        stored.canonical_evidence,
                        minimum_finalized_block=segment["minimum_finalized_block"],
                        maximum_records=segment["maximum_records"],
                        startup_timeout_seconds=segment["startup_timeout_seconds"],
                        expected_sequence=expected_sequence,
                        previous_hash=(
                            None if previous_segment is None else previous_segment.block.hash
                        ),
                        previous_digest=(
                            "0" * 64
                            if previous_segment is None
                            else previous_segment.transcript_digest
                        ),
                        previous_number=(
                            None if previous_segment is None else previous_segment.block.number
                        ),
                        previous_timestamp_ms=(
                            None
                            if previous_segment is None
                            else previous_segment.block.timestamp_ms
                        ),
                    )
                except (GrandpaFinalityObserverError, ValueError) as error:
                    raise GrandpaFinalityStoreCorruption(
                        f"persisted_{getattr(error, 'reason_code', 'invalid_run_binding')}"
                    ) from error
                _compare_row(stored, parsed)
                if expected_sequence == 0:
                    _audit_segment_boundary(segment, stored, previous_global)
                    request_id = json.loads(stored.canonical_evidence)["request_id"]
                    if segment["request_id"] != request_id:
                        raise GrandpaFinalityStoreCorruption("segment_request_id_mismatch")
                if previous_global is not None:
                    if stored.head.height <= previous_global.head.height:
                        raise GrandpaFinalityStoreCorruption("global_height_rollback")
                    if stored.head.timestamp_ms < previous_global.head.timestamp_ms:
                        raise GrandpaFinalityStoreCorruption("global_timestamp_rollback")
                    if (
                        stored.head.height == previous_global.head.height + 1
                        and stored.head.parent_hash != previous_global.head.block_hash
                    ):
                        raise GrandpaFinalityStoreCorruption("adjacent_parent_mismatch")
                evidence_digest = hashlib.sha256(stored.canonical_evidence).digest()
                accepted_at_unix_ms = _positive_uint(
                    stored.head.accepted_at_unix_ms,
                    "persisted finality acceptance time",
                )
                if accepted_at_unix_ms < previous_accepted_at_unix_ms:
                    raise GrandpaFinalityStoreCorruption("acceptance_clock_rollback")
                expected_acceptance = _acceptance_digest(
                    previous_acceptance,
                    height=stored.head.height,
                    block_hash=stored.head.block_hash,
                    evidence_digest=evidence_digest,
                    segment_index=stored.head.segment_index,
                    sequence=stored.head.segment_sequence,
                    restart_gap=stored.head.restart_gap_before,
                    accepted_at_unix_ms=accepted_at_unix_ms,
                )
                if (
                    row["previous_acceptance_digest"] != previous_acceptance.hex()
                    or stored.head.acceptance_digest != expected_acceptance.hex()
                ):
                    raise GrandpaFinalityStoreCorruption("acceptance_digest_mismatch")
                previous_acceptance = expected_acceptance
                previous_accepted_at_unix_ms = accepted_at_unix_ms
                previous_segment = parsed
                previous_global = stored
        if stored_head_digest[0] != previous_acceptance:
            raise GrandpaFinalityStoreCorruption("head_acceptance_digest_mismatch")
        self._assert_database_bound()

    def _initialize(self) -> None:
        try:
            with self._connect(read_only=False) as connection:
                application_id = connection.execute("PRAGMA application_id").fetchone()[0]
                user_version = connection.execute("PRAGMA user_version").fetchone()[0]
                has_tables = bool(
                    connection.execute(
                        "SELECT 1 FROM sqlite_master WHERE type = 'table' LIMIT 1"
                    ).fetchone()
                )
                if not has_tables:
                    with self._transaction(connection):
                        for statement in _SCHEMA_STATEMENTS:
                            connection.execute(statement)
                        connection.execute(f"PRAGMA application_id = {_APPLICATION_ID}")
                        connection.execute(f"PRAGMA user_version = {STORE_SCHEMA_VERSION}")
                        config = self._config_bytes()
                        connection.executemany(
                            "INSERT INTO store_meta(key, value) VALUES (?, ?)",
                            (
                                ("config", config),
                                ("config_sha256", hashlib.sha256(config).digest()),
                                ("head_acceptance_digest", _ZERO_DIGEST),
                            ),
                        )
                elif application_id != _APPLICATION_ID or user_version != STORE_SCHEMA_VERSION:
                    raise GrandpaFinalityStoreConflict("store_schema_mismatch")
        except sqlite3.DatabaseError as error:
            raise GrandpaFinalityStoreCorruption("sqlite_initialize_failed") from error
        self.audit()

    def _commit(
        self, binding: ObserverRunBinding, attestation: FinalityAttestation
    ) -> PersistedFinalityHead:
        evidence_sha = hashlib.sha256(attestation.canonical_bytes).hexdigest()
        record = json.loads(attestation.canonical_bytes)
        request_id = record["request_id"]
        try:
            with (
                self._connect(read_only=False) as connection,
                self._transaction(connection),
            ):
                existing = connection.execute(
                    "SELECT * FROM finalized_headers WHERE height = ?",
                    (attestation.block.number,),
                ).fetchone()
                if existing is not None:
                    stored = _stored_header(existing)
                    if stored.canonical_evidence != attestation.canonical_bytes:
                        raise GrandpaFinalityStoreConflict("finalized_height_conflict")
                    return stored.head
                count, total_evidence = connection.execute(
                    "SELECT COUNT(*), COALESCE(SUM(length(canonical_evidence)), 0) "
                    "FROM finalized_headers"
                ).fetchone()
                if count >= self._limits.maximum_headers:
                    raise GrandpaFinalitySupervisorError("header_count_limit")
                if (
                    total_evidence + len(attestation.canonical_bytes)
                    > self._limits.maximum_total_evidence_bytes
                ):
                    raise GrandpaFinalitySupervisorError("total_evidence_limit")
                last = connection.execute(
                    "SELECT * FROM finalized_headers ORDER BY height DESC LIMIT 1"
                ).fetchone()
                prior = None if last is None else _stored_header(last)
                if prior is not None:
                    if attestation.block.number <= prior.head.height:
                        raise GrandpaFinalityStoreConflict("global_height_rollback")
                    if attestation.block.timestamp_ms < prior.head.timestamp_ms:
                        raise GrandpaFinalityStoreConflict("global_timestamp_rollback")
                segment = connection.execute(
                    "SELECT * FROM observer_segments WHERE segment_index = ?",
                    (binding.segment_index,),
                ).fetchone()
                if segment is None:
                    next_segment = connection.execute(
                        "SELECT COALESCE(MAX(segment_index), -1) + 1 FROM observer_segments"
                    ).fetchone()[0]
                    if binding.segment_index != next_segment:
                        raise GrandpaFinalityStoreConflict("nonconsecutive_segment")
                    expected_minimum = (
                        self._initial_minimum
                        if prior is None
                        else max(self._initial_minimum, prior.head.height + 1)
                    )
                    if (
                        binding.minimum_finalized_block != expected_minimum
                        or binding.maximum_records != self._limits.maximum_records_per_process
                        or binding.startup_timeout_seconds != self._startup_timeout_seconds
                    ):
                        raise GrandpaFinalityStoreConflict("unexpected_run_binding")
                    if attestation.sequence != 0:
                        raise GrandpaFinalityStoreConflict("segment_does_not_start_at_zero")
                    gap = prior is not None and attestation.block.number != prior.head.height + 1
                    if (
                        prior is not None
                        and not gap
                        and attestation.block.parent_hash != prior.head.block_hash
                    ):
                        raise GrandpaFinalityStoreConflict("adjacent_parent_mismatch")
                    connection.execute(
                        """
                            INSERT INTO observer_segments(
                                segment_index, minimum_finalized_block, maximum_records,
                                startup_timeout_seconds, request_id, prior_global_height,
                                prior_global_hash, restart_gap
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                        (
                            binding.segment_index,
                            binding.minimum_finalized_block,
                            binding.maximum_records,
                            binding.startup_timeout_seconds,
                            request_id,
                            None if prior is None else prior.head.height,
                            None if prior is None else prior.head.block_hash,
                            int(gap),
                        ),
                    )
                    restart_gap = bool(gap)
                else:
                    if prior is not None and prior.head.segment_index != binding.segment_index:
                        raise GrandpaFinalityStoreConflict("segment_already_closed")
                    expected_segment = (
                        binding.minimum_finalized_block,
                        binding.maximum_records,
                        binding.startup_timeout_seconds,
                        request_id,
                    )
                    actual_segment = (
                        segment["minimum_finalized_block"],
                        segment["maximum_records"],
                        segment["startup_timeout_seconds"],
                        segment["request_id"],
                    )
                    if actual_segment != expected_segment:
                        raise GrandpaFinalityStoreConflict("segment_binding_conflict")
                    restart_gap = False
                previous_acceptance = connection.execute(
                    "SELECT value FROM store_meta WHERE key = 'head_acceptance_digest'"
                ).fetchone()[0]
                accepted_at_unix_ms = time.time_ns() // 1_000_000
                if prior is not None and accepted_at_unix_ms < prior.head.accepted_at_unix_ms:
                    raise GrandpaFinalitySupervisorError("acceptance_clock_rollback")
                acceptance = _acceptance_digest(
                    previous_acceptance,
                    height=attestation.block.number,
                    block_hash=attestation.block.hash,
                    evidence_digest=bytes.fromhex(evidence_sha),
                    segment_index=binding.segment_index,
                    sequence=attestation.sequence,
                    restart_gap=restart_gap,
                    accepted_at_unix_ms=accepted_at_unix_ms,
                )
                connection.execute(
                    """
                        INSERT INTO finalized_headers(
                            height, block_hash, parent_hash, state_root, extrinsics_root,
                            timestamp_ms, accepted_at_unix_ms, scale_header,
                            canonical_evidence, evidence_sha256,
                            transcript_digest, previous_transcript_digest,
                            previous_finalized_hash, ancestry_complete, segment_index,
                            segment_sequence, restart_gap_before,
                            previous_acceptance_digest, acceptance_digest
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                    (
                        attestation.block.number,
                        attestation.block.hash,
                        attestation.block.parent_hash,
                        attestation.block.state_root,
                        attestation.block.extrinsics_root,
                        attestation.block.timestamp_ms,
                        accepted_at_unix_ms,
                        attestation.block.scale_header,
                        attestation.canonical_bytes,
                        evidence_sha,
                        attestation.transcript_digest,
                        attestation.previous_transcript_digest,
                        attestation.previous_finalized_hash,
                        int(attestation.ancestry_complete_since_previous),
                        binding.segment_index,
                        attestation.sequence,
                        int(restart_gap),
                        previous_acceptance.hex(),
                        acceptance.hex(),
                    ),
                )
                connection.execute(
                    "UPDATE store_meta SET value = ? WHERE key = 'head_acceptance_digest'",
                    (acceptance,),
                )
                page_size = connection.execute("PRAGMA page_size").fetchone()[0]
                page_count = connection.execute("PRAGMA page_count").fetchone()[0]
                if page_size * page_count > self._limits.maximum_database_bytes:
                    raise GrandpaFinalitySupervisorError("database_size_limit")
        except sqlite3.IntegrityError as error:
            raise GrandpaFinalityStoreConflict("sqlite_constraint_conflict") from error
        except sqlite3.DatabaseError as error:
            raise GrandpaFinalityStoreCorruption("sqlite_write_failed") from error
        stored = self._stored_header_at(attestation.block.number)
        if stored is None:
            raise GrandpaFinalityStoreCorruption("committed_header_missing")
        return stored.head

    def _stored_header_at(self, height: int) -> _StoredHeader | None:
        height = _canonical_uint(height, "finalized block height")
        with self._connect(read_only=True) as connection:
            row = connection.execute(
                "SELECT * FROM finalized_headers WHERE height = ?", (height,)
            ).fetchone()
        return None if row is None else _stored_header(row)

    def _stored_range(self, start_height: int, end_height: int) -> tuple[_StoredHeader, ...]:
        with self._connect(read_only=True) as connection:
            rows = connection.execute(
                "SELECT * FROM finalized_headers WHERE height BETWEEN ? AND ? ORDER BY height",
                (start_height, end_height),
            ).fetchall()
        return tuple(_stored_header(row) for row in rows)

    def _stored_replay_range(
        self,
        start_height: int,
        end_height: int,
    ) -> tuple[tuple[_StoredHeader, FinalityAttestationReplayBinding], ...] | None:
        start_height = _positive_uint(start_height, "scan replay start height")
        end_height = _canonical_uint(end_height, "scan replay end height")
        if end_height < start_height:
            raise ValueError("scan replay end height must not precede its start")
        with self._connect(read_only=True) as connection:
            rows = connection.execute(
                """
                SELECT h.*, s.minimum_finalized_block, s.maximum_records,
                       s.startup_timeout_seconds
                FROM finalized_headers AS h
                JOIN observer_segments AS s USING(segment_index)
                WHERE h.height BETWEEN ? AND ?
                ORDER BY h.height
                """,
                (start_height, end_height),
            ).fetchall()
            if len(rows) != end_height - start_height + 1:
                return None
            result: list[tuple[_StoredHeader, FinalityAttestationReplayBinding]] = []
            for row in rows:
                stored = _stored_header(row)
                prior: _StoredHeader | None = None
                if stored.head.segment_sequence > 0:
                    prior_row = connection.execute(
                        """
                        SELECT * FROM finalized_headers
                        WHERE segment_index = ? AND segment_sequence = ?
                        """,
                        (
                            stored.head.segment_index,
                            stored.head.segment_sequence - 1,
                        ),
                    ).fetchone()
                    if prior_row is None:
                        raise GrandpaFinalityStoreCorruption(
                            "scan_replay_prior_attestation_missing"
                        )
                    prior = _stored_header(prior_row)
                    if (
                        stored.previous_finalized_hash != prior.head.block_hash
                        or stored.previous_transcript_digest != prior.transcript_digest
                    ):
                        raise GrandpaFinalityStoreCorruption(
                            "scan_replay_prior_attestation_mismatch"
                        )
                elif (
                    stored.previous_finalized_hash is not None
                    or stored.previous_transcript_digest != "0" * 64
                ):
                    raise GrandpaFinalityStoreCorruption("scan_replay_genesis_mismatch")
                result.append(
                    (
                        stored,
                        FinalityAttestationReplayBinding(
                            minimum_finalized_block=row["minimum_finalized_block"],
                            maximum_records=row["maximum_records"],
                            startup_timeout_seconds=row["startup_timeout_seconds"],
                            expected_sequence=stored.head.segment_sequence,
                            previous_number=(None if prior is None else prior.head.height),
                            previous_timestamp_ms=(
                                None if prior is None else prior.head.timestamp_ms
                            ),
                            previous_hash=(None if prior is None else prior.head.block_hash),
                            previous_digest=(
                                "0" * 64 if prior is None else prior.transcript_digest
                            ),
                        ),
                    )
                )
        return tuple(result)

    def _plan_block(self, stored: _StoredHeader) -> VerifiedFinalizedBlock:
        return VerifiedFinalizedBlock(
            height=stored.head.height,
            block_hash=stored.head.block_hash,
            state_root=stored.head.state_root,
            timestamp_ms=stored.head.timestamp_ms,
            scoring_policy_hash=self._scoring_policy_digest,
            chain_observation=self._chain_observation,
            finality_verifier_sha256=self._finality_verifier_sha256,
            finality_evidence=stored.canonical_evidence,
            finality_evidence_sha256=stored.head.evidence_sha256,
        )

    def _config_bytes(self) -> bytes:
        return canonical_json_bytes(
            {
                "schema": STORE_SCHEMA,
                "scoring_policy_hash": self._scoring_policy_digest,
                "chain_observation": self._chain_observation.model_dump(mode="json", by_alias=True),
                "finality_verifier_sha256": self._finality_verifier_sha256,
                "observer": {
                    "evidence_class": EVIDENCE_CLASS,
                    "offline_finality_proof": False,
                    "source_revision": SOURCE_REVISION,
                    "source_tree_sha256": SOURCE_TREE_SHA256,
                    "cargo_lock_sha256": CARGO_LOCK_SHA256,
                    "fixture_set_sha256": FIXTURE_SET_SHA256,
                    "binary_sha256": self._observer.expected_binary_sha256,
                    "chain_spec_sha256": self._observer.expected_chain_spec_sha256,
                    "genesis_hash": self._observer.expected_genesis_hash,
                    "bootstrap_block_number": self._observer.bootstrap_block_number,
                    "bootstrap_block_hash": self._observer.bootstrap_block_hash,
                },
                "initial_minimum_finalized_block": self._initial_minimum,
                "startup_timeout_seconds": self._startup_timeout_seconds,
                "limits": {
                    name: getattr(self._limits, name) for name in self._limits.__dataclass_fields__
                },
            }
        )

    @contextmanager
    def _connect(self, *, read_only: bool) -> Iterator[sqlite3.Connection]:
        try:
            if self._path.is_symlink():
                raise GrandpaFinalityStoreCorruption("unsafe_database_path")
            if read_only:
                connection = sqlite3.connect(
                    f"file:{self._path}?mode=ro",
                    uri=True,
                    timeout=self._busy_timeout_ms / 1000,
                )
            else:
                connection = sqlite3.connect(
                    self._path,
                    timeout=self._busy_timeout_ms / 1000,
                    isolation_level=None,
                )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute(f"PRAGMA busy_timeout = {self._busy_timeout_ms}")
            if not read_only:
                if connection.execute("PRAGMA journal_mode = WAL").fetchone()[0].lower() != "wal":
                    raise GrandpaFinalityStoreCorruption("wal_unavailable")
                connection.execute("PRAGMA synchronous = FULL")
                connection.execute("PRAGMA fullfsync = ON")
            yield connection
        finally:
            if "connection" in locals():
                connection.close()

    @staticmethod
    @contextmanager
    def _transaction(connection: sqlite3.Connection) -> Iterator[None]:
        connection.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            connection.rollback()
            raise
        else:
            connection.commit()

    def _assert_database_bound(self) -> None:
        total = 0
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(f"{self._path}{suffix}")
            if candidate.exists():
                if candidate.is_symlink() or not candidate.is_file():
                    raise GrandpaFinalityStoreCorruption("unsafe_database_path")
                total += candidate.stat().st_size
        if total > self._limits.maximum_database_bytes:
            raise GrandpaFinalityStoreCorruption("database_size_limit")


def _prepare_database_path(value: str | os.PathLike[str]) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise ValueError("state_path must be absolute")
    try:
        if path.parent.resolve(strict=True) != path.parent.absolute():
            raise GrandpaFinalitySupervisorError("unsafe_database_parent")
    except OSError as error:
        raise GrandpaFinalitySupervisorError("database_parent_unavailable") from error
    if path.exists() and path.is_symlink():
        raise GrandpaFinalitySupervisorError("unsafe_database_path")
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
        info = os.fstat(descriptor)
        os.close(descriptor)
    except OSError as error:
        raise GrandpaFinalitySupervisorError("database_unavailable") from error
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o077:
        raise GrandpaFinalitySupervisorError("unsafe_database_path")
    return path


def _sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be lowercase hexadecimal")
    return value


def _canonical_uint(value: object, label: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > _MAX_CANONICAL_INTEGER
    ):
        raise ValueError(f"{label} must be a canonical nonnegative integer")
    return value


def _positive_uint(value: object, label: str) -> int:
    value = _canonical_uint(value, label)
    if value == 0:
        raise ValueError(f"{label} must be positive")
    return value


def _stored_header(row: sqlite3.Row) -> _StoredHeader:
    evidence = bytes(row["canonical_evidence"])
    return _StoredHeader(
        head=PersistedFinalityHead(
            height=row["height"],
            block_hash=row["block_hash"],
            parent_hash=row["parent_hash"],
            state_root=row["state_root"],
            extrinsics_root=row["extrinsics_root"],
            timestamp_ms=row["timestamp_ms"],
            accepted_at_unix_ms=row["accepted_at_unix_ms"],
            evidence_sha256=row["evidence_sha256"],
            segment_index=row["segment_index"],
            segment_sequence=row["segment_sequence"],
            restart_gap_before=bool(row["restart_gap_before"]),
            acceptance_digest=row["acceptance_digest"],
        ),
        scale_header=row["scale_header"],
        canonical_evidence=evidence,
        transcript_digest=row["transcript_digest"],
        previous_transcript_digest=row["previous_transcript_digest"],
        previous_finalized_hash=row["previous_finalized_hash"],
        ancestry_complete=bool(row["ancestry_complete"]),
        previous_acceptance_digest=row["previous_acceptance_digest"],
    )


def _snapshot(stored: _StoredHeader) -> FinalizedSnapshotRef:
    return FinalizedSnapshotRef(
        block_number=stored.head.height,
        block_hash=stored.head.block_hash,
        parent_hash=stored.head.parent_hash,
        state_root=stored.head.state_root,
    )


def parse_finality_acceptance_receipt(payload: bytes) -> FinalityAcceptanceReceipt:
    """Parse and verify one canonical local acceptance receipt."""

    if not isinstance(payload, bytes) or not payload or len(payload) > 4_096:
        raise ValueError("finality acceptance receipt must be bounded nonempty bytes")
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("finality acceptance receipt is not JSON") from error
    expected_keys = {
        "schema",
        "height",
        "block_hash",
        "evidence_sha256",
        "segment_index",
        "segment_sequence",
        "restart_gap_before",
        "accepted_at_unix_ms",
        "previous_acceptance_digest",
        "acceptance_digest",
    }
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise ValueError("finality acceptance receipt schema is invalid")
    if canonical_json_bytes(value) != payload or value["schema"] != ACCEPTANCE_RECEIPT_SCHEMA:
        raise ValueError("finality acceptance receipt is noncanonical")
    height = _canonical_uint(value["height"], "acceptance receipt height")
    block_hash = value["block_hash"]
    evidence_sha256 = value["evidence_sha256"]
    segment_index = _canonical_uint(value["segment_index"], "acceptance segment index")
    segment_sequence = _canonical_uint(value["segment_sequence"], "acceptance segment sequence")
    restart_gap_before = value["restart_gap_before"]
    accepted_at_unix_ms = _positive_uint(value["accepted_at_unix_ms"], "acceptance receipt time")
    previous_acceptance_digest = value["previous_acceptance_digest"]
    acceptance_digest = value["acceptance_digest"]
    if not isinstance(block_hash, str) or _BLOCK_HASH_RE.fullmatch(block_hash) is None:
        raise ValueError("acceptance receipt block hash is invalid")
    _sha256(evidence_sha256, "acceptance receipt evidence digest")
    _sha256(previous_acceptance_digest, "previous acceptance digest")
    _sha256(acceptance_digest, "acceptance digest")
    if not isinstance(restart_gap_before, bool):
        raise ValueError("acceptance restart-gap marker must be boolean")
    expected = _acceptance_digest(
        bytes.fromhex(previous_acceptance_digest),
        height=height,
        block_hash=block_hash,
        evidence_digest=bytes.fromhex(evidence_sha256),
        segment_index=segment_index,
        sequence=segment_sequence,
        restart_gap=restart_gap_before,
        accepted_at_unix_ms=accepted_at_unix_ms,
    ).hex()
    if acceptance_digest != expected:
        raise ValueError("finality acceptance receipt digest is invalid")
    return FinalityAcceptanceReceipt(
        height=height,
        block_hash=block_hash,
        evidence_sha256=evidence_sha256,
        segment_index=segment_index,
        segment_sequence=segment_sequence,
        restart_gap_before=restart_gap_before,
        accepted_at_unix_ms=accepted_at_unix_ms,
        previous_acceptance_digest=previous_acceptance_digest,
        acceptance_digest=acceptance_digest,
        canonical_bytes=payload,
    )


def _acceptance_receipt_bytes(stored: _StoredHeader) -> bytes:
    payload = canonical_json_bytes(
        {
            "schema": ACCEPTANCE_RECEIPT_SCHEMA,
            "height": stored.head.height,
            "block_hash": stored.head.block_hash,
            "evidence_sha256": stored.head.evidence_sha256,
            "segment_index": stored.head.segment_index,
            "segment_sequence": stored.head.segment_sequence,
            "restart_gap_before": stored.head.restart_gap_before,
            "accepted_at_unix_ms": stored.head.accepted_at_unix_ms,
            "previous_acceptance_digest": stored.previous_acceptance_digest,
            "acceptance_digest": stored.head.acceptance_digest,
        }
    )
    parse_finality_acceptance_receipt(payload)
    return payload


def _acceptance_digest(
    previous: bytes,
    *,
    height: int,
    block_hash: str,
    evidence_digest: bytes,
    segment_index: int,
    sequence: int,
    restart_gap: bool,
    accepted_at_unix_ms: int,
) -> bytes:
    return hashlib.sha256(
        _ACCEPT_DOMAIN
        + previous
        + height.to_bytes(8, "big")
        + bytes.fromhex(block_hash[2:])
        + evidence_digest
        + segment_index.to_bytes(8, "big")
        + sequence.to_bytes(8, "big")
        + bytes([restart_gap])
        + accepted_at_unix_ms.to_bytes(8, "big")
    ).digest()


def _compare_row(stored: _StoredHeader, parsed: FinalityAttestation) -> None:
    values: tuple[tuple[Any, Any], ...] = (
        (stored.head.height, parsed.block.number),
        (stored.head.block_hash, parsed.block.hash),
        (stored.head.parent_hash, parsed.block.parent_hash),
        (stored.head.state_root, parsed.block.state_root),
        (stored.head.extrinsics_root, parsed.block.extrinsics_root),
        (stored.head.timestamp_ms, parsed.block.timestamp_ms),
        (stored.scale_header, parsed.block.scale_header),
        (stored.head.segment_sequence, parsed.sequence),
        (stored.transcript_digest, parsed.transcript_digest),
        (stored.previous_transcript_digest, parsed.previous_transcript_digest),
        (stored.previous_finalized_hash, parsed.previous_finalized_hash),
        (stored.ancestry_complete, parsed.ancestry_complete_since_previous),
        (stored.head.evidence_sha256, hashlib.sha256(parsed.canonical_bytes).hexdigest()),
    )
    if any(left != right for left, right in values):
        raise GrandpaFinalityStoreCorruption("normalized_header_mismatch")


def _audit_segment_boundary(
    segment: sqlite3.Row,
    first: _StoredHeader,
    previous: _StoredHeader | None,
) -> None:
    expected_prior_height = None if previous is None else previous.head.height
    expected_prior_hash = None if previous is None else previous.head.block_hash
    gap = previous is not None and first.head.height != previous.head.height + 1
    if (
        segment["prior_global_height"] != expected_prior_height
        or segment["prior_global_hash"] != expected_prior_hash
        or bool(segment["restart_gap"]) != gap
        or first.head.restart_gap_before != gap
    ):
        raise GrandpaFinalityStoreCorruption("segment_boundary_mismatch")
    if previous is not None and not gap and first.head.parent_hash != previous.head.block_hash:
        raise GrandpaFinalityStoreCorruption("adjacent_parent_mismatch")


__all__ = [
    "ACCEPTANCE_RECEIPT_SCHEMA",
    "STORE_SCHEMA",
    "STORE_SCHEMA_VERSION",
    "DurableGrandpaFinalityPort",
    "FinalityAcceptanceReceipt",
    "GrandpaFinalityStoreConflict",
    "GrandpaFinalityStoreCorruption",
    "GrandpaFinalitySupervisorError",
    "GrandpaFinalitySupervisorLimits",
    "ObserverRunBinding",
    "PersistedFinalityHead",
    "VerifiedFinalityScanInterval",
    "parse_finality_acceptance_receipt",
]
