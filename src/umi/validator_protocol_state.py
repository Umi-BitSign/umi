"""Crash-safe multi-window state for the live validator protocol.

The transition algorithms remain in :mod:`umi.registries` and
:mod:`umi.rolling`. This module supplies a durable transaction boundary around
those pure functions. Every scheduled window is recorded as bounded RFC 8785
input and result bytes, then current state is kept in normalized SQLite tables.
Opening the store replays the operation log from genesis and compares the
recomputed state with every current table.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import sqlite3
import stat
import threading
from collections import Counter
from contextlib import suppress
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path
from typing import Any

from .encoding import account_id32, raw_sha256, sha256_domain, u64be
from .protocol import base64url_decode, base64url_encode, canonical_json_bytes
from .registries import (
    PublisherFaultFinding,
    PublisherFaultReason,
    PublisherFaultState,
    PublisherFaultTransition,
    SpentCohortBatch,
    SpentRegistryState,
    SpentTransition,
)
from .rolling import AssignmentScore, RollingScoreState, ScoredBatch

REQUEST_SCHEMA = "umi-validator-protocol-state-window/1"
RESULT_SCHEMA = "umi-validator-protocol-state-result/1"
PROTOCOL_STATE_SNAPSHOT_SCHEMA = "umi-validator-reveal-prior-state/1"

_APPLICATION_ID = 0x554D4950  # "UMIP"
_SCHEMA_VERSION = 1
_ZERO_ROOT = bytes(32)
_JSON_SAFE_INTEGER = (1 << 53) - 1
_HEX32_RE = re.compile(r"^[0-9a-f]{64}$")
_DECIMAL_RE = re.compile(r"^(0|[1-9][0-9]*)$")
_ALLOWED_STRATA = frozenset({"fingerspelling", "short_utterance", "continuous"})


class ProtocolStateStoreError(RuntimeError):
    """A stable state-store boundary failure."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(f"validator protocol state store failed: {reason_code}")


class ProtocolStateConflict(ProtocolStateStoreError):
    """A window or idempotency key conflicts with committed history."""


class ProtocolStateCorruption(ProtocolStateStoreError):
    """Persisted bytes do not reproduce from the canonical operation log."""


class ProtocolStateLimitError(ProtocolStateStoreError):
    """A canonical input or result exceeds its local fail-closed bound."""


@dataclass(frozen=True, slots=True)
class ProtocolStatePolicyLimits:
    """Policy values that alter one or more persisted transitions."""

    rolling_batch_count: int
    score_max_age_windows: int
    publisher_fault_cooldown_windows: int

    def __post_init__(self) -> None:
        for name in (
            "rolling_batch_count",
            "score_max_age_windows",
            "publisher_fault_cooldown_windows",
        ):
            value = getattr(self, name)
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value <= 0
                or value > _JSON_SAFE_INTEGER
            ):
                raise ValueError(f"{name} must be a positive canonical JSON integer")
        if self.rolling_batch_count % 2:
            raise ValueError("rolling_batch_count must retain complete two-batch windows")


@dataclass(frozen=True, slots=True)
class ProtocolStateStoreBounds:
    """Resource ceilings for canonical state operations and normalized rows."""

    maximum_request_bytes: int = 64 * 1024 * 1024
    maximum_result_bytes: int = 4 * 1024 * 1024
    maximum_spent_batches: int = 4_096
    maximum_hashes_per_spent_batch: int = 4_096
    maximum_fault_findings: int = 4_096
    maximum_rolling_batches: int = 4_096
    maximum_assignments_per_window: int = 262_144
    maximum_issued_requests_per_window: int = 262_144
    maximum_fraction_decimal_digits: int = 256

    def __post_init__(self) -> None:
        for name in self.__dataclass_fields__:
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")


@dataclass(frozen=True, slots=True)
class ProtocolStateSnapshot:
    """The exact current state recovered from normalized tables."""

    last_window_index: int
    last_window_id: bytes | None
    spent_registry: SpentRegistryState
    publisher_faults: PublisherFaultState
    rolling_scores: RollingScoreState
    assigned_observation_counts: tuple[tuple[bytes, int], ...]
    observation_root: bytes
    state_digest: bytes

    def __post_init__(self) -> None:
        if self.last_window_index < -1:
            raise ValueError("last_window_index must be at least -1")
        if (self.last_window_index == -1) != (self.last_window_id is None):
            raise ValueError("genesis is the only state without a last window ID")
        if self.last_window_id is not None:
            raw_sha256(self.last_window_id, field="last window ID")
        raw_sha256(self.observation_root, field="observation root")
        raw_sha256(self.state_digest, field="protocol state digest")
        roots = [root for root, _ in self.assigned_observation_counts]
        if roots != sorted(roots) or len(set(roots)) != len(roots):
            raise ValueError("assigned observation counts must be unique and sorted")
        for root, count in self.assigned_observation_counts:
            account_id32(root)
            if isinstance(count, bool) or not isinstance(count, int) or count <= 0:
                raise ValueError("assigned observation counts must be positive integers")

    def assigned_observation_count(self, miner_root: str | bytes) -> int:
        """Return the cumulative request count inherited by one miner root."""

        return dict(self.assigned_observation_counts).get(account_id32(miner_root), 0)


def encode_protocol_state_snapshot(snapshot: ProtocolStateSnapshot) -> bytes:
    """Encode the complete canonical state required to replay a window.

    This is intentionally a public, store-independent evidence format.  Pool
    qualification needs the spent leaves, publisher-fault state, and miner
    observation counts that preceded selection; a root or digest alone cannot
    prove those inputs.  Reveal replay consumes the same object.
    """

    if not isinstance(snapshot, ProtocolStateSnapshot):
        raise TypeError("snapshot must be a ProtocolStateSnapshot")
    _verify_snapshot_digest(snapshot)
    return canonical_json_bytes(
        {
            "schema": PROTOCOL_STATE_SNAPSHOT_SCHEMA,
            "last_window_index": snapshot.last_window_index,
            "last_window_id": (
                None if snapshot.last_window_id is None else snapshot.last_window_id.hex()
            ),
            "spent": {
                "root": snapshot.spent_registry.root.hex(),
                "last_reveal_round": snapshot.spent_registry.last_reveal_round,
                "leaves": [item.hex() for item in sorted(snapshot.spent_registry.leaves)],
            },
            "publisher_faults": {
                "root": snapshot.publisher_faults.root.hex(),
                "last_window_index": snapshot.publisher_faults.last_window_index,
                "strikes": [
                    {"control_group_id": group.hex(), "count": count}
                    for group, count in snapshot.publisher_faults.strikes
                ],
                "cooldown_ends": [
                    {"control_group_id": group.hex(), "window_index": end}
                    for group, end in snapshot.publisher_faults.cooldown_ends
                ],
            },
            "rolling": [
                _snapshot_scored_batch_object(item) for item in snapshot.rolling_scores.batches
            ],
            "assigned_observation_counts": [
                {"miner_root": root.hex(), "count": count}
                for root, count in snapshot.assigned_observation_counts
            ],
            "observation_root": snapshot.observation_root.hex(),
            "state_digest": snapshot.state_digest.hex(),
        }
    )


def decode_protocol_state_snapshot(data: bytes) -> ProtocolStateSnapshot:
    """Parse and reauthenticate a canonical protocol-state snapshot object."""

    value = _strict_json_loads(
        data,
        maximum_bytes=ProtocolStateStoreBounds().maximum_request_bytes,
    )
    required = {
        "schema",
        "last_window_index",
        "last_window_id",
        "spent",
        "publisher_faults",
        "rolling",
        "assigned_observation_counts",
        "observation_root",
        "state_digest",
    }
    if set(value) != required or value.get("schema") != PROTOCOL_STATE_SNAPSHOT_SCHEMA:
        raise ProtocolStateCorruption("protocol_state_snapshot_invalid")
    spent = _exact_keys(value["spent"], {"root", "last_reveal_round", "leaves"})
    faults = _exact_keys(
        value["publisher_faults"],
        {"root", "last_window_index", "strikes", "cooldown_ends"},
    )
    for sequence in (
        spent["leaves"],
        faults["strikes"],
        faults["cooldown_ends"],
        value["rolling"],
        value["assigned_observation_counts"],
    ):
        if not isinstance(sequence, list):
            raise ProtocolStateCorruption("protocol_state_snapshot_invalid")
    try:
        snapshot = ProtocolStateSnapshot(
            last_window_index=_strict_int(
                value["last_window_index"], field="last window index", minimum=-1
            ),
            last_window_id=(
                None
                if value["last_window_id"] is None
                else _decode_hex32(value["last_window_id"], field="last window ID")
            ),
            spent_registry=SpentRegistryState(
                root=_decode_hex32(spent["root"], field="spent root"),
                leaves=frozenset(
                    _decode_hex32(item, field="spent leaf") for item in spent["leaves"]
                ),
                last_reveal_round=_strict_int(
                    spent["last_reveal_round"], field="last reveal round"
                ),
            ),
            publisher_faults=PublisherFaultState(
                root=_decode_hex32(faults["root"], field="publisher fault root"),
                strikes=tuple(
                    (
                        _decode_hex32(
                            _exact_keys(item, {"control_group_id", "count"})["control_group_id"],
                            field="control group ID",
                        ),
                        _strict_int(item["count"], field="publisher strike count", minimum=1),
                    )
                    for item in faults["strikes"]
                ),
                cooldown_ends=tuple(
                    (
                        _decode_hex32(
                            _exact_keys(item, {"control_group_id", "window_index"})[
                                "control_group_id"
                            ],
                            field="control group ID",
                        ),
                        _strict_int(item["window_index"], field="publisher cooldown end"),
                    )
                    for item in faults["cooldown_ends"]
                ),
                last_window_index=_strict_int(
                    faults["last_window_index"],
                    field="publisher fault last window",
                    minimum=-1,
                ),
            ),
            rolling_scores=RollingScoreState(
                tuple(_snapshot_scored_batch_from_object(item) for item in value["rolling"])
            ),
            assigned_observation_counts=tuple(
                (
                    _decode_hex32(
                        _exact_keys(item, {"miner_root", "count"})["miner_root"],
                        field="observed miner root",
                    ),
                    _strict_int(item["count"], field="observation count", minimum=1),
                )
                for item in value["assigned_observation_counts"]
            ),
            observation_root=_decode_hex32(value["observation_root"], field="observation root"),
            state_digest=_decode_hex32(value["state_digest"], field="protocol state digest"),
        )
    except (KeyError, TypeError, ValueError, ProtocolStateCorruption) as error:
        raise ProtocolStateCorruption("protocol_state_snapshot_invalid") from error
    if snapshot.last_window_index != snapshot.publisher_faults.last_window_index:
        raise ProtocolStateCorruption("protocol_state_snapshot_invalid")
    _verify_snapshot_digest(snapshot)
    if encode_protocol_state_snapshot(snapshot) != data:
        raise ProtocolStateCorruption("protocol_state_snapshot_noncanonical")
    return snapshot


@dataclass(frozen=True, slots=True)
class AppliedProtocolWindow:
    operation_id: bytes
    window_index: int
    window_id: bytes
    request_bytes: bytes
    result_bytes: bytes
    idempotent: bool
    snapshot: ProtocolStateSnapshot


@dataclass(frozen=True, slots=True)
class _WindowInput:
    operation_id: bytes
    window_index: int
    window_id: bytes
    reveal_round: int
    evidence_digest: bytes
    spent_batches: tuple[SpentCohortBatch, ...]
    fault_findings: tuple[PublisherFaultFinding, ...]
    scored_batches: tuple[ScoredBatch, ...]
    issued_miner_roots: tuple[bytes, ...]
    limits: ProtocolStatePolicyLimits


@dataclass(slots=True)
class _ReplayState:
    spent: SpentRegistryState
    faults: PublisherFaultState
    rolling: RollingScoreState
    observation_counts: dict[bytes, int]
    observation_root: bytes
    spent_first_windows: dict[bytes, int]
    last_window_id: bytes | None


@dataclass(frozen=True, slots=True)
class _Transition:
    state: _ReplayState
    spent: SpentTransition
    faults: PublisherFaultTransition
    observation_increments: tuple[tuple[bytes, int], ...]
    observation_delta_root: bytes
    result_bytes: bytes
    snapshot: ProtocolStateSnapshot


_SCHEMA_STATEMENTS = (
    """
    CREATE TABLE store_meta (
        key TEXT PRIMARY KEY,
        value BLOB NOT NULL
    ) WITHOUT ROWID
    """,
    """
    CREATE TABLE operations (
        window_index INTEGER PRIMARY KEY CHECK(window_index >= 0),
        operation_id BLOB NOT NULL UNIQUE
            CHECK(typeof(operation_id) = 'blob' AND length(operation_id) = 32),
        window_id BLOB NOT NULL UNIQUE
            CHECK(typeof(window_id) = 'blob' AND length(window_id) = 32),
        reveal_round INTEGER NOT NULL UNIQUE CHECK(reveal_round > 0),
        evidence_digest BLOB NOT NULL
            CHECK(typeof(evidence_digest) = 'blob' AND length(evidence_digest) = 32),
        request_bytes BLOB NOT NULL CHECK(typeof(request_bytes) = 'blob'),
        request_sha256 BLOB NOT NULL
            CHECK(typeof(request_sha256) = 'blob' AND length(request_sha256) = 32),
        result_bytes BLOB NOT NULL CHECK(typeof(result_bytes) = 'blob'),
        result_sha256 BLOB NOT NULL
            CHECK(typeof(result_sha256) = 'blob' AND length(result_sha256) = 32)
    )
    """,
    """
    CREATE TABLE current_head (
        singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
        last_window_index INTEGER NOT NULL CHECK(last_window_index >= -1),
        last_window_id BLOB CHECK(
            last_window_id IS NULL OR
            (typeof(last_window_id) = 'blob' AND length(last_window_id) = 32)
        ),
        spent_root BLOB NOT NULL
            CHECK(typeof(spent_root) = 'blob' AND length(spent_root) = 32),
        spent_last_reveal_round INTEGER NOT NULL CHECK(spent_last_reveal_round >= 0),
        publisher_fault_root BLOB NOT NULL
            CHECK(typeof(publisher_fault_root) = 'blob' AND length(publisher_fault_root) = 32),
        publisher_fault_last_window INTEGER NOT NULL
            CHECK(publisher_fault_last_window >= -1),
        observation_root BLOB NOT NULL
            CHECK(typeof(observation_root) = 'blob' AND length(observation_root) = 32),
        rolling_state_sha256 BLOB NOT NULL
            CHECK(typeof(rolling_state_sha256) = 'blob' AND length(rolling_state_sha256) = 32),
        state_digest BLOB NOT NULL
            CHECK(typeof(state_digest) = 'blob' AND length(state_digest) = 32),
        CHECK(
            (last_window_index = -1 AND last_window_id IS NULL) OR
            (last_window_index >= 0 AND last_window_id IS NOT NULL)
        )
    )
    """,
    """
    CREATE TABLE spent_leaves (
        leaf BLOB PRIMARY KEY CHECK(typeof(leaf) = 'blob' AND length(leaf) = 32),
        first_window_index INTEGER NOT NULL,
        FOREIGN KEY(first_window_index) REFERENCES operations(window_index) ON DELETE RESTRICT
    ) WITHOUT ROWID
    """,
    """
    CREATE TABLE publisher_fault_groups (
        control_group_id BLOB PRIMARY KEY
            CHECK(typeof(control_group_id) = 'blob' AND length(control_group_id) = 32),
        strikes INTEGER NOT NULL CHECK(strikes IN (1, 2)),
        cooldown_end INTEGER NOT NULL CHECK(cooldown_end >= 0)
    ) WITHOUT ROWID
    """,
    """
    CREATE TABLE rolling_batches (
        window_index INTEGER NOT NULL,
        ordinal INTEGER NOT NULL CHECK(ordinal IN (0, 1)),
        pool_leaf BLOB NOT NULL CHECK(typeof(pool_leaf) = 'blob' AND length(pool_leaf) = 32),
        batch_rank BLOB NOT NULL CHECK(typeof(batch_rank) = 'blob' AND length(batch_rank) = 32),
        PRIMARY KEY(window_index, pool_leaf),
        UNIQUE(window_index, ordinal),
        FOREIGN KEY(window_index) REFERENCES operations(window_index) ON DELETE RESTRICT
    ) WITHOUT ROWID
    """,
    """
    CREATE TABLE rolling_challenges (
        window_index INTEGER NOT NULL,
        pool_leaf BLOB NOT NULL,
        ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
        challenge_id BLOB NOT NULL
            CHECK(typeof(challenge_id) = 'blob' AND length(challenge_id) = 16),
        PRIMARY KEY(window_index, pool_leaf, challenge_id),
        UNIQUE(window_index, pool_leaf, ordinal),
        FOREIGN KEY(window_index, pool_leaf)
            REFERENCES rolling_batches(window_index, pool_leaf) ON DELETE CASCADE
    ) WITHOUT ROWID
    """,
    """
    CREATE TABLE rolling_miners (
        window_index INTEGER NOT NULL,
        pool_leaf BLOB NOT NULL,
        ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
        miner_root BLOB NOT NULL
            CHECK(typeof(miner_root) = 'blob' AND length(miner_root) = 32),
        PRIMARY KEY(window_index, pool_leaf, miner_root),
        UNIQUE(window_index, pool_leaf, ordinal),
        FOREIGN KEY(window_index, pool_leaf)
            REFERENCES rolling_batches(window_index, pool_leaf) ON DELETE CASCADE
    ) WITHOUT ROWID
    """,
    """
    CREATE TABLE rolling_assignments (
        window_index INTEGER NOT NULL,
        pool_leaf BLOB NOT NULL,
        miner_root BLOB NOT NULL
            CHECK(typeof(miner_root) = 'blob' AND length(miner_root) = 32),
        challenge_id BLOB NOT NULL
            CHECK(typeof(challenge_id) = 'blob' AND length(challenge_id) = 16),
        request_leaf BLOB NOT NULL UNIQUE
            CHECK(typeof(request_leaf) = 'blob' AND length(request_leaf) = 32),
        stratum TEXT NOT NULL
            CHECK(stratum IN ('fingerspelling', 'short_utterance', 'continuous')),
        canary INTEGER NOT NULL CHECK(canary IN (0, 1)),
        score_numerator TEXT,
        score_denominator TEXT,
        PRIMARY KEY(window_index, pool_leaf, miner_root, challenge_id),
        FOREIGN KEY(window_index, pool_leaf)
            REFERENCES rolling_batches(window_index, pool_leaf) ON DELETE CASCADE,
        FOREIGN KEY(window_index, pool_leaf, miner_root)
            REFERENCES rolling_miners(window_index, pool_leaf, miner_root) ON DELETE CASCADE,
        FOREIGN KEY(window_index, pool_leaf, challenge_id)
            REFERENCES rolling_challenges(window_index, pool_leaf, challenge_id)
            ON DELETE CASCADE,
        CHECK(
            (canary = 1 AND score_numerator IS NULL AND score_denominator IS NULL) OR
            (canary = 0 AND score_numerator IS NOT NULL AND score_denominator IS NOT NULL)
        )
    ) WITHOUT ROWID
    """,
    """
    CREATE TABLE assigned_observation_counts (
        miner_root BLOB PRIMARY KEY
            CHECK(typeof(miner_root) = 'blob' AND length(miner_root) = 32),
        assigned_count TEXT NOT NULL
    ) WITHOUT ROWID
    """,
)

_EXPECTED_TABLES = frozenset(
    {
        "store_meta",
        "operations",
        "current_head",
        "spent_leaves",
        "publisher_fault_groups",
        "rolling_batches",
        "rolling_challenges",
        "rolling_miners",
        "rolling_assignments",
        "assigned_observation_counts",
    }
)


def _strict_int(value: Any, *, field: str, minimum: int = 0) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < minimum
        or value > _JSON_SAFE_INTEGER
    ):
        raise ValueError(f"{field} is outside the canonical integer range")
    return value


def _hex32(value: bytes, *, field: str) -> str:
    return raw_sha256(value, field=field).hex()


def _decode_hex32(value: Any, *, field: str) -> bytes:
    if not isinstance(value, str) or _HEX32_RE.fullmatch(value) is None:
        raise ProtocolStateCorruption("canonical_request_invalid")
    return raw_sha256(value, field=field)


def _exact_keys(value: Any, expected: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise ProtocolStateCorruption("canonical_request_invalid")
    return value


def _strict_json_loads(encoded: bytes, *, maximum_bytes: int) -> dict[str, Any]:
    if not isinstance(encoded, bytes) or not encoded or len(encoded) > maximum_bytes:
        raise ProtocolStateCorruption("canonical_bytes_invalid")

    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ProtocolStateCorruption("canonical_bytes_invalid")
            result[key] = value
        return result

    def reject_constant(_value: str) -> None:
        raise ProtocolStateCorruption("canonical_bytes_invalid")

    try:
        value = json.loads(
            encoded,
            object_pairs_hook=object_pairs,
            parse_constant=reject_constant,
        )
    except ProtocolStateCorruption:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ProtocolStateCorruption("canonical_bytes_invalid") from error
    if not isinstance(value, dict) or canonical_json_bytes(value) != encoded:
        raise ProtocolStateCorruption("canonical_bytes_invalid")
    return value


def _fraction_json(value: Fraction | None, *, maximum_digits: int) -> list[str] | None:
    if value is None:
        return None
    if not isinstance(value, Fraction):
        raise TypeError("scores must use exact Fraction arithmetic")
    numerator = str(value.numerator)
    denominator = str(value.denominator)
    if len(numerator.lstrip("-")) > maximum_digits or len(denominator) > maximum_digits:
        raise ProtocolStateLimitError("fraction_decimal_limit")
    return [numerator, denominator]


def _decode_fraction(value: Any, *, maximum_digits: int) -> Fraction | None:
    if value is None:
        return None
    if (
        not isinstance(value, list)
        or len(value) != 2
        or any(not isinstance(item, str) for item in value)
    ):
        raise ProtocolStateCorruption("canonical_request_invalid")
    numerator, denominator = value
    if (
        _DECIMAL_RE.fullmatch(numerator) is None
        or _DECIMAL_RE.fullmatch(denominator) is None
        or denominator == "0"
        or len(numerator) > maximum_digits
        or len(denominator) > maximum_digits
    ):
        raise ProtocolStateCorruption("canonical_request_invalid")
    return Fraction(int(numerator), int(denominator))


def _encode_spent_batch(batch: SpentCohortBatch) -> dict[str, Any]:
    return {
        "batch_commitment": _hex32(
            raw_sha256(batch.batch_commitment, field="batch commitment"),
            field="batch commitment",
        ),
        "video_hashes": [
            _hex32(raw_sha256(value, field="video hash"), field="video hash")
            for value in batch.video_hashes
        ],
        "frame_digests": [
            _hex32(raw_sha256(value, field="frame digest"), field="frame digest")
            for value in batch.frame_digests
        ],
        "revealed_script_hashes": [
            _hex32(
                raw_sha256(value, field="normalized script hash"),
                field="normalized script hash",
            )
            for value in batch.revealed_script_hashes
        ],
    }


def _decode_spent_batch(value: Any) -> SpentCohortBatch:
    item = _exact_keys(
        value,
        {"batch_commitment", "video_hashes", "frame_digests", "revealed_script_hashes"},
    )
    for name in ("video_hashes", "frame_digests", "revealed_script_hashes"):
        if not isinstance(item[name], list):
            raise ProtocolStateCorruption("canonical_request_invalid")
    try:
        return SpentCohortBatch(
            batch_commitment=_decode_hex32(item["batch_commitment"], field="batch commitment"),
            video_hashes=tuple(
                _decode_hex32(entry, field="video hash") for entry in item["video_hashes"]
            ),
            frame_digests=tuple(
                _decode_hex32(entry, field="frame digest") for entry in item["frame_digests"]
            ),
            revealed_script_hashes=tuple(
                _decode_hex32(entry, field="normalized script hash")
                for entry in item["revealed_script_hashes"]
            ),
        )
    except (TypeError, ValueError) as error:
        raise ProtocolStateCorruption("canonical_request_invalid") from error


def _encode_fault(finding: PublisherFaultFinding) -> dict[str, Any]:
    return {
        "control_group_id": finding.control_group_id.hex(),
        "publisher_hotkey": finding.publisher_hotkey.hex(),
        "window_id": finding.window_id.hex(),
        "batch_commitment": finding.batch_commitment.hex(),
        "reason": finding.reason.value,
        "reason_code": finding.reason_code,
    }


def _decode_fault(value: Any) -> PublisherFaultFinding:
    item = _exact_keys(
        value,
        {
            "control_group_id",
            "publisher_hotkey",
            "window_id",
            "batch_commitment",
            "reason",
            "reason_code",
        },
    )
    if not isinstance(item["reason"], str):
        raise ProtocolStateCorruption("canonical_request_invalid")
    try:
        return PublisherFaultFinding(
            control_group_id=_decode_hex32(item["control_group_id"], field="control group ID"),
            publisher_hotkey=_decode_hex32(item["publisher_hotkey"], field="publisher hotkey"),
            window_id=_decode_hex32(item["window_id"], field="window ID"),
            batch_commitment=_decode_hex32(item["batch_commitment"], field="batch commitment"),
            reason=PublisherFaultReason(item["reason"]),
            reason_code=_strict_int(item["reason_code"], field="reason_code"),
        )
    except (TypeError, ValueError) as error:
        raise ProtocolStateCorruption("canonical_request_invalid") from error


def _encode_assignment(
    assignment: AssignmentScore,
    *,
    maximum_fraction_digits: int,
) -> dict[str, Any]:
    return {
        "miner_root": assignment.root.hex(),
        "challenge_id": assignment.challenge_id,
        "request_leaf": assignment.leaf.hex(),
        "stratum": assignment.stratum,
        "canary": assignment.canary,
        "score": _fraction_json(
            assignment.score,
            maximum_digits=maximum_fraction_digits,
        ),
    }


def _decode_assignment(value: Any, *, maximum_fraction_digits: int) -> AssignmentScore:
    item = _exact_keys(
        value,
        {"miner_root", "challenge_id", "request_leaf", "stratum", "canary", "score"},
    )
    if (
        not isinstance(item["challenge_id"], str)
        or not isinstance(item["stratum"], str)
        or item["stratum"] not in _ALLOWED_STRATA
        or not isinstance(item["canary"], bool)
    ):
        raise ProtocolStateCorruption("canonical_request_invalid")
    try:
        return AssignmentScore(
            miner_root=_decode_hex32(item["miner_root"], field="miner root"),
            challenge_id=item["challenge_id"],
            request_leaf=_decode_hex32(item["request_leaf"], field="request leaf"),
            stratum=item["stratum"],  # type: ignore[arg-type]
            canary=item["canary"],
            score=_decode_fraction(
                item["score"],
                maximum_digits=maximum_fraction_digits,
            ),
        )
    except (TypeError, ValueError) as error:
        raise ProtocolStateCorruption("canonical_request_invalid") from error


def _encode_scored_batch(
    batch: ScoredBatch,
    *,
    maximum_fraction_digits: int,
) -> dict[str, Any]:
    return {
        "window_index": batch.window_index,
        "batch_rank": raw_sha256(batch.batch_rank, field="batch rank").hex(),
        "pool_leaf": raw_sha256(batch.pool_leaf, field="pool leaf").hex(),
        "challenge_ids": list(batch.challenge_ids),
        "miner_roots": [account_id32(root).hex() for root in batch.miner_roots],
        "assignments": [
            _encode_assignment(
                assignment,
                maximum_fraction_digits=maximum_fraction_digits,
            )
            for assignment in batch.assignments
        ],
    }


def _decode_scored_batch(value: Any, *, maximum_fraction_digits: int) -> ScoredBatch:
    item = _exact_keys(
        value,
        {
            "window_index",
            "batch_rank",
            "pool_leaf",
            "challenge_ids",
            "miner_roots",
            "assignments",
        },
    )
    if not all(
        isinstance(item[name], list) for name in ("challenge_ids", "miner_roots", "assignments")
    ):
        raise ProtocolStateCorruption("canonical_request_invalid")
    if any(not isinstance(challenge_id, str) for challenge_id in item["challenge_ids"]):
        raise ProtocolStateCorruption("canonical_request_invalid")
    try:
        return ScoredBatch(
            window_index=_strict_int(item["window_index"], field="batch window index"),
            batch_rank=_decode_hex32(item["batch_rank"], field="batch rank"),
            pool_leaf=_decode_hex32(item["pool_leaf"], field="pool leaf"),
            challenge_ids=tuple(item["challenge_ids"]),
            miner_roots=tuple(
                _decode_hex32(root, field="miner root") for root in item["miner_roots"]
            ),
            assignments=tuple(
                _decode_assignment(
                    assignment,
                    maximum_fraction_digits=maximum_fraction_digits,
                )
                for assignment in item["assignments"]
            ),
        )
    except (TypeError, ValueError) as error:
        raise ProtocolStateCorruption("canonical_request_invalid") from error


def _snapshot_scored_batch_object(batch: ScoredBatch) -> dict[str, Any]:
    value = _encode_scored_batch(batch, maximum_fraction_digits=256)
    for assignment in value["assignments"]:
        fraction = assignment["score"]
        assignment["score"] = (
            None
            if fraction is None
            else {
                "numerator": int(fraction[0]),
                "denominator": int(fraction[1]),
            }
        )
    return value


def _snapshot_scored_batch_from_object(value: Any) -> ScoredBatch:
    if not isinstance(value, dict):
        raise ProtocolStateCorruption("protocol_state_snapshot_invalid")
    copied = json.loads(json.dumps(value))
    assignments = copied.get("assignments")
    if not isinstance(assignments, list):
        raise ProtocolStateCorruption("protocol_state_snapshot_invalid")
    for assignment in assignments:
        if not isinstance(assignment, dict) or "score" not in assignment:
            raise ProtocolStateCorruption("protocol_state_snapshot_invalid")
        fraction = assignment["score"]
        if fraction is None:
            continue
        if not isinstance(fraction, dict) or set(fraction) != {"numerator", "denominator"}:
            raise ProtocolStateCorruption("protocol_state_snapshot_invalid")
        numerator = fraction["numerator"]
        denominator = fraction["denominator"]
        if (
            isinstance(numerator, bool)
            or not isinstance(numerator, int)
            or numerator < 0
            or isinstance(denominator, bool)
            or not isinstance(denominator, int)
            or denominator <= 0
        ):
            raise ProtocolStateCorruption("protocol_state_snapshot_invalid")
        reduced = Fraction(numerator, denominator)
        if (reduced.numerator, reduced.denominator) != (numerator, denominator):
            raise ProtocolStateCorruption("protocol_state_snapshot_invalid")
        assignment["score"] = [str(numerator), str(denominator)]
    return _decode_scored_batch(copied, maximum_fraction_digits=256)


def _verify_snapshot_digest(snapshot: ProtocolStateSnapshot) -> None:
    if snapshot.last_window_index != snapshot.publisher_faults.last_window_index:
        raise ProtocolStateCorruption("protocol_state_snapshot_invalid")
    replay = _ReplayState(
        spent=snapshot.spent_registry,
        faults=snapshot.publisher_faults,
        rolling=snapshot.rolling_scores,
        observation_counts=dict(snapshot.assigned_observation_counts),
        observation_root=snapshot.observation_root,
        spent_first_windows={},
        last_window_id=snapshot.last_window_id,
    )
    expected = _state_digest(replay, bounds=ProtocolStateStoreBounds())
    if expected != snapshot.state_digest:
        raise ProtocolStateCorruption("protocol_state_snapshot_digest_mismatch")


def _encode_limits(limits: ProtocolStatePolicyLimits) -> dict[str, int]:
    return {
        "rolling_batch_count": limits.rolling_batch_count,
        "score_max_age_windows": limits.score_max_age_windows,
        "publisher_fault_cooldown_windows": limits.publisher_fault_cooldown_windows,
    }


def _decode_limits(value: Any) -> ProtocolStatePolicyLimits:
    item = _exact_keys(
        value,
        {
            "rolling_batch_count",
            "score_max_age_windows",
            "publisher_fault_cooldown_windows",
        },
    )
    try:
        return ProtocolStatePolicyLimits(
            rolling_batch_count=_strict_int(
                item["rolling_batch_count"],
                field="rolling_batch_count",
                minimum=1,
            ),
            score_max_age_windows=_strict_int(
                item["score_max_age_windows"],
                field="score_max_age_windows",
                minimum=1,
            ),
            publisher_fault_cooldown_windows=_strict_int(
                item["publisher_fault_cooldown_windows"],
                field="publisher_fault_cooldown_windows",
                minimum=1,
            ),
        )
    except (TypeError, ValueError) as error:
        raise ProtocolStateCorruption("canonical_request_invalid") from error


def _canonical_request(value: _WindowInput, bounds: ProtocolStateStoreBounds) -> bytes:
    encoded = canonical_json_bytes(
        {
            "schema": REQUEST_SCHEMA,
            "operation_id": value.operation_id.hex(),
            "window_index": value.window_index,
            "window_id": value.window_id.hex(),
            "reveal_round": value.reveal_round,
            "evidence_digest": value.evidence_digest.hex(),
            "spent_cohort_batches": [_encode_spent_batch(batch) for batch in value.spent_batches],
            "objective_fault_findings": [
                _encode_fault(finding) for finding in value.fault_findings
            ],
            "scored_batches": [
                _encode_scored_batch(
                    batch,
                    maximum_fraction_digits=bounds.maximum_fraction_decimal_digits,
                )
                for batch in value.scored_batches
            ],
            "issued_miner_roots": [root.hex() for root in value.issued_miner_roots],
            "policy_limits": _encode_limits(value.limits),
        }
    )
    if len(encoded) > bounds.maximum_request_bytes:
        raise ProtocolStateLimitError("canonical_request_size_limit")
    return encoded


def _parse_request(encoded: bytes, bounds: ProtocolStateStoreBounds) -> _WindowInput:
    value = _exact_keys(
        _strict_json_loads(encoded, maximum_bytes=bounds.maximum_request_bytes),
        {
            "schema",
            "operation_id",
            "window_index",
            "window_id",
            "reveal_round",
            "evidence_digest",
            "spent_cohort_batches",
            "objective_fault_findings",
            "scored_batches",
            "issued_miner_roots",
            "policy_limits",
        },
    )
    if value["schema"] != REQUEST_SCHEMA:
        raise ProtocolStateCorruption("canonical_request_invalid")
    for name in (
        "spent_cohort_batches",
        "objective_fault_findings",
        "scored_batches",
        "issued_miner_roots",
    ):
        if not isinstance(value[name], list):
            raise ProtocolStateCorruption("canonical_request_invalid")
    try:
        parsed = _WindowInput(
            operation_id=_decode_hex32(value["operation_id"], field="operation ID"),
            window_index=_strict_int(value["window_index"], field="window index"),
            window_id=_decode_hex32(value["window_id"], field="window ID"),
            reveal_round=_strict_int(value["reveal_round"], field="reveal round", minimum=1),
            evidence_digest=_decode_hex32(value["evidence_digest"], field="evidence digest"),
            spent_batches=tuple(
                _decode_spent_batch(batch) for batch in value["spent_cohort_batches"]
            ),
            fault_findings=tuple(
                _decode_fault(finding) for finding in value["objective_fault_findings"]
            ),
            scored_batches=tuple(
                _decode_scored_batch(
                    batch,
                    maximum_fraction_digits=bounds.maximum_fraction_decimal_digits,
                )
                for batch in value["scored_batches"]
            ),
            issued_miner_roots=tuple(
                _decode_hex32(root, field="issued miner root")
                for root in value["issued_miner_roots"]
            ),
            limits=_decode_limits(value["policy_limits"]),
        )
        _validate_window_input(parsed, bounds)
        return parsed
    except ProtocolStateCorruption:
        raise
    except (TypeError, ValueError, ProtocolStateLimitError) as error:
        raise ProtocolStateCorruption("canonical_request_invalid") from error


def _validate_window_input(value: _WindowInput, bounds: ProtocolStateStoreBounds) -> None:
    _strict_int(value.window_index, field="window index")
    _strict_int(value.reveal_round, field="reveal round", minimum=1)
    raw_sha256(value.operation_id, field="operation ID")
    raw_sha256(value.window_id, field="window ID")
    raw_sha256(value.evidence_digest, field="evidence digest")
    if not isinstance(value.limits, ProtocolStatePolicyLimits):
        raise TypeError("limits must be ProtocolStatePolicyLimits")
    if value.limits.rolling_batch_count > bounds.maximum_rolling_batches:
        raise ProtocolStateLimitError("rolling_batch_count_limit")

    if not isinstance(value.spent_batches, tuple) or any(
        not isinstance(batch, SpentCohortBatch) for batch in value.spent_batches
    ):
        raise TypeError("spent cohort batches must be a tuple of SpentCohortBatch values")
    if len(value.spent_batches) > bounds.maximum_spent_batches:
        raise ProtocolStateLimitError("spent_batch_count_limit")
    commitments = tuple(
        raw_sha256(batch.batch_commitment, field="batch commitment")
        for batch in value.spent_batches
    )
    if commitments != tuple(sorted(commitments)):
        raise ValueError("spent cohort batches must be sorted by batch commitment")
    for batch in value.spent_batches:
        if (
            len(batch.video_hashes) > bounds.maximum_hashes_per_spent_batch
            or len(batch.frame_digests) > bounds.maximum_hashes_per_spent_batch
            or len(batch.revealed_script_hashes) > bounds.maximum_hashes_per_spent_batch
        ):
            raise ProtocolStateLimitError("spent_batch_hash_count_limit")

    if not isinstance(value.fault_findings, tuple) or any(
        not isinstance(finding, PublisherFaultFinding) for finding in value.fault_findings
    ):
        raise TypeError("fault findings must be a tuple of PublisherFaultFinding values")
    if len(value.fault_findings) > bounds.maximum_fault_findings:
        raise ProtocolStateLimitError("fault_finding_count_limit")
    fault_leaves = tuple(finding.leaf for finding in value.fault_findings)
    if fault_leaves != tuple(sorted(fault_leaves)) or len(set(fault_leaves)) != len(fault_leaves):
        raise ValueError("fault findings must be unique and sorted by fault leaf")
    if any(finding.window_id != value.window_id for finding in value.fault_findings):
        raise ValueError("fault findings must name the applied window ID")

    if not isinstance(value.scored_batches, tuple) or any(
        not isinstance(batch, ScoredBatch) for batch in value.scored_batches
    ):
        raise TypeError("scored batches must be a tuple of ScoredBatch values")
    if len(value.scored_batches) not in {0, 2}:
        raise ValueError("a scheduled window must carry zero or exactly two scored batches")
    if len(value.scored_batches) > bounds.maximum_rolling_batches:
        raise ProtocolStateLimitError("scored_batch_count_limit")
    if value.scored_batches:
        if any(batch.window_index != value.window_index for batch in value.scored_batches):
            raise ValueError("scored batches must belong to the applied window")
        if tuple(sorted(value.scored_batches, key=lambda batch: batch.order_key)) != (
            value.scored_batches
        ):
            raise ValueError("scored batches must use canonical rank order")
    assignment_count = sum(len(batch.assignments) for batch in value.scored_batches)
    if assignment_count > bounds.maximum_assignments_per_window:
        raise ProtocolStateLimitError("scored_assignment_count_limit")

    if not isinstance(value.issued_miner_roots, tuple) or any(
        not isinstance(root, bytes) for root in value.issued_miner_roots
    ):
        raise TypeError("issued miner roots must be a tuple of AccountId32 bytes")
    if len(value.issued_miner_roots) > bounds.maximum_issued_requests_per_window:
        raise ProtocolStateLimitError("issued_request_count_limit")
    if value.issued_miner_roots != tuple(sorted(value.issued_miner_roots)):
        raise ValueError("issued miner roots must be sorted; duplicate requests remain present")
    for root in value.issued_miner_roots:
        account_id32(root)
    if value.scored_batches:
        scored_roots = tuple(
            sorted(
                assignment.root
                for batch in value.scored_batches
                for assignment in batch.assignments
            )
        )
        if scored_roots != value.issued_miner_roots:
            raise ValueError("issued miner roots must match every scored assignment exactly")


def _normalize_window_input(
    *,
    operation_id: str | bytes,
    window_index: int,
    window_id: str | bytes,
    reveal_round: int,
    evidence_digest: str | bytes,
    spent_cohort_batches: tuple[SpentCohortBatch, ...],
    objective_fault_findings: tuple[PublisherFaultFinding, ...],
    scored_batches: tuple[ScoredBatch, ...],
    issued_miner_roots: tuple[str | bytes, ...],
    policy_limits: ProtocolStatePolicyLimits,
    bounds: ProtocolStateStoreBounds,
) -> _WindowInput:
    if not isinstance(issued_miner_roots, tuple):
        raise TypeError("issued_miner_roots must be a tuple")
    value = _WindowInput(
        operation_id=raw_sha256(operation_id, field="operation ID"),
        window_index=window_index,
        window_id=raw_sha256(window_id, field="window ID"),
        reveal_round=reveal_round,
        evidence_digest=raw_sha256(evidence_digest, field="evidence digest"),
        spent_batches=spent_cohort_batches,
        fault_findings=objective_fault_findings,
        scored_batches=scored_batches,
        issued_miner_roots=tuple(account_id32(root) for root in issued_miner_roots),
        limits=policy_limits,
    )
    _validate_window_input(value, bounds)
    return value


def _encode_fault_state(state: PublisherFaultState) -> dict[str, Any]:
    return {
        "root": state.root.hex(),
        "last_window_index": state.last_window_index,
        "strikes": [[group.hex(), count] for group, count in state.strikes],
        "cooldown_ends": [[group.hex(), end] for group, end in state.cooldown_ends],
    }


def _encode_rolling_state(
    state: RollingScoreState,
    *,
    maximum_fraction_digits: int,
) -> dict[str, Any]:
    return {
        "batches": [
            _encode_scored_batch(
                batch,
                maximum_fraction_digits=maximum_fraction_digits,
            )
            for batch in state.batches
        ]
    }


def _rolling_digest(state: RollingScoreState, bounds: ProtocolStateStoreBounds) -> bytes:
    return hashlib.sha256(
        canonical_json_bytes(
            _encode_rolling_state(
                state,
                maximum_fraction_digits=bounds.maximum_fraction_decimal_digits,
            )
        )
    ).digest()


def _fault_digest(state: PublisherFaultState) -> bytes:
    return hashlib.sha256(canonical_json_bytes(_encode_fault_state(state))).digest()


def _state_digest(
    state: _ReplayState,
    *,
    bounds: ProtocolStateStoreBounds,
) -> bytes:
    summary = {
        "last_window_index": state.faults.last_window_index,
        "last_window_id": None if state.last_window_id is None else state.last_window_id.hex(),
        "spent_root": state.spent.root.hex(),
        "spent_last_reveal_round": state.spent.last_reveal_round,
        "spent_leaf_count": len(state.spent.leaves),
        "publisher_fault_root": state.faults.root.hex(),
        "publisher_fault_state_sha256": _fault_digest(state.faults).hex(),
        "rolling_state_sha256": _rolling_digest(state.rolling, bounds).hex(),
        "observation_root": state.observation_root.hex(),
        "observed_miner_count": len(state.observation_counts),
    }
    return sha256_domain(
        b"umi-validator-protocol-state-v1\0",
        canonical_json_bytes(summary),
    )


def _snapshot(state: _ReplayState, bounds: ProtocolStateStoreBounds) -> ProtocolStateSnapshot:
    return ProtocolStateSnapshot(
        last_window_index=state.faults.last_window_index,
        last_window_id=state.last_window_id,
        spent_registry=state.spent,
        publisher_faults=state.faults,
        rolling_scores=state.rolling,
        assigned_observation_counts=tuple(sorted(state.observation_counts.items())),
        observation_root=state.observation_root,
        state_digest=_state_digest(state, bounds=bounds),
    )


def _genesis(bounds: ProtocolStateStoreBounds) -> tuple[_ReplayState, ProtocolStateSnapshot]:
    state = _ReplayState(
        spent=SpentRegistryState(),
        faults=PublisherFaultState(),
        rolling=RollingScoreState(),
        observation_counts={},
        observation_root=_ZERO_ROOT,
        spent_first_windows={},
        last_window_id=None,
    )
    return state, _snapshot(state, bounds)


def _transition(
    current: _ReplayState,
    value: _WindowInput,
    *,
    request_bytes: bytes,
    bounds: ProtocolStateStoreBounds,
) -> _Transition:
    if value.window_index != current.faults.last_window_index + 1:
        raise ValueError("protocol state updates must cover consecutive scheduled windows")
    if value.reveal_round <= current.spent.last_reveal_round:
        raise ValueError("reveal rounds must advance across scheduled windows")

    spent, spent_transition = current.spent.apply(value.reveal_round, value.spent_batches)
    faults, fault_transition = current.faults.advance_window(
        value.window_index,
        value.fault_findings,
        cooldown_windows=value.limits.publisher_fault_cooldown_windows,
    )
    rolling = current.rolling.advance(
        value.window_index,
        new_batches=value.scored_batches,
        rolling_batch_count=value.limits.rolling_batch_count,
        score_max_age_windows=value.limits.score_max_age_windows,
    )

    counts = dict(current.observation_counts)
    observation_increments = tuple(sorted(Counter(value.issued_miner_roots).items()))
    for root, increment in observation_increments:
        counts[root] = counts.get(root, 0) + increment
    delta_root = sha256_domain(
        b"umi-assigned-observation-delta-v1\0",
        u64be(len(value.issued_miner_roots)),
        b"".join(value.issued_miner_roots),
    )
    observation_root = sha256_domain(
        b"umi-assigned-observation-root-v1\0",
        current.observation_root,
        u64be(value.window_index),
        delta_root,
    )
    first_windows = dict(current.spent_first_windows)
    for leaf in spent_transition.delta_leaves:
        first_windows[leaf] = value.window_index

    next_state = _ReplayState(
        spent=spent,
        faults=faults,
        rolling=rolling,
        observation_counts=counts,
        observation_root=observation_root,
        spent_first_windows=first_windows,
        last_window_id=value.window_id,
    )
    next_snapshot = _snapshot(next_state, bounds)
    result = canonical_json_bytes(
        {
            "schema": RESULT_SCHEMA,
            "operation_id": value.operation_id.hex(),
            "window_index": value.window_index,
            "window_id": value.window_id.hex(),
            "evidence_digest": value.evidence_digest.hex(),
            "request_sha256": hashlib.sha256(request_bytes).hexdigest(),
            "spent": {
                "previous_root": spent_transition.previous_root.hex(),
                "delta_leaves": [leaf.hex() for leaf in spent_transition.delta_leaves],
                "delta_root": spent_transition.delta_root.hex(),
                "resulting_root": spent_transition.resulting_root.hex(),
                "prior_collisions": [leaf.hex() for leaf in spent_transition.prior_collisions],
                "duplicate_video_hashes": [
                    value.hex() for value in spent_transition.duplicate_video_hashes
                ],
                "duplicate_frame_digests": [
                    value.hex() for value in spent_transition.duplicate_frame_digests
                ],
                "has_eligibility_fault": spent_transition.has_eligibility_fault,
            },
            "publisher_fault": {
                "previous_root": fault_transition.previous_root.hex(),
                "fault_leaves": [leaf.hex() for leaf in fault_transition.fault_leaves],
                "resulting_root": fault_transition.resulting_root.hex(),
                "struck_groups": [group.hex() for group in fault_transition.struck_groups],
            },
            "rolling": {
                "batch_identities": [
                    {
                        "window_index": batch.window_index,
                        "pool_leaf": raw_sha256(batch.pool_leaf, field="pool leaf").hex(),
                    }
                    for batch in rolling.batches
                ],
                "state_sha256": _rolling_digest(rolling, bounds).hex(),
            },
            "assigned_observations": {
                "issued_request_count": len(value.issued_miner_roots),
                "delta_root": delta_root.hex(),
                "resulting_root": observation_root.hex(),
                "observed_miner_count": len(counts),
            },
            "state": {
                "spent_leaf_count": len(spent.leaves),
                "publisher_fault_group_count": len(faults.strikes),
                "rolling_batch_count": len(rolling.batches),
                "state_digest": next_snapshot.state_digest.hex(),
            },
        }
    )
    if len(result) > bounds.maximum_result_bytes:
        raise ProtocolStateLimitError("canonical_result_size_limit")
    return _Transition(
        state=next_state,
        spent=spent_transition,
        faults=fault_transition,
        observation_increments=observation_increments,
        observation_delta_root=delta_root,
        result_bytes=result,
        snapshot=next_snapshot,
    )


class ValidatorProtocolStateStore:
    """SQLite-backed atomic state for consecutive validator windows."""

    def __init__(
        self,
        database_path: str | os.PathLike[str],
        *,
        bounds: ProtocolStateStoreBounds | None = None,
        busy_timeout_seconds: float = 10.0,
    ) -> None:
        if bounds is not None and not isinstance(bounds, ProtocolStateStoreBounds):
            raise TypeError("bounds must be ProtocolStateStoreBounds or None")
        if (
            isinstance(busy_timeout_seconds, bool)
            or not isinstance(busy_timeout_seconds, (int, float))
            or not math.isfinite(busy_timeout_seconds)
            or busy_timeout_seconds <= 0
        ):
            raise ValueError("busy_timeout_seconds must be a positive finite number")
        self._bounds = bounds or ProtocolStateStoreBounds()
        self._path = self._prepare_database_path(Path(database_path))
        self._lock = threading.RLock()
        self._closed = False
        try:
            self._connection = sqlite3.connect(
                os.fspath(self._path),
                timeout=float(busy_timeout_seconds),
                isolation_level=None,
                check_same_thread=False,
            )
            self._connection.row_factory = sqlite3.Row
            self._configure_connection(int(busy_timeout_seconds * 1_000))
            with self._lock:
                self._begin_immediate()
                try:
                    self._initialize_or_verify_schema_locked()
                    self._replay = self._audit_locked()
                    self._connection.commit()
                except Exception:
                    self._connection.rollback()
                    raise
            self._assert_safe_database_files()
        except ProtocolStateStoreError:
            self._close_after_failed_init()
            raise
        except (OSError, sqlite3.Error, TypeError, ValueError) as error:
            self._close_after_failed_init()
            raise ProtocolStateStoreError("database_open_failed") from error

    @property
    def database_path(self) -> Path:
        return self._path

    @property
    def snapshot(self) -> ProtocolStateSnapshot:
        with self._lock:
            self._require_open()
            return _snapshot(self._replay, self._bounds)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._connection.close()
            self._closed = True

    def __enter__(self) -> ValidatorProtocolStateStore:
        self._require_open()
        return self

    def __exit__(self, _type: Any, _value: Any, _traceback: Any) -> None:
        self.close()

    def apply_window(
        self,
        *,
        operation_id: str | bytes,
        window_index: int,
        window_id: str | bytes,
        reveal_round: int,
        evidence_digest: str | bytes,
        spent_cohort_batches: tuple[SpentCohortBatch, ...],
        objective_fault_findings: tuple[PublisherFaultFinding, ...],
        scored_batches: tuple[ScoredBatch, ...],
        issued_miner_roots: tuple[str | bytes, ...],
        policy_limits: ProtocolStatePolicyLimits,
    ) -> AppliedProtocolWindow:
        """Atomically apply or idempotently return one canonical scheduled window."""

        value = _normalize_window_input(
            operation_id=operation_id,
            window_index=window_index,
            window_id=window_id,
            reveal_round=reveal_round,
            evidence_digest=evidence_digest,
            spent_cohort_batches=spent_cohort_batches,
            objective_fault_findings=objective_fault_findings,
            scored_batches=scored_batches,
            issued_miner_roots=issued_miner_roots,
            policy_limits=policy_limits,
            bounds=self._bounds,
        )
        request_bytes = _canonical_request(value, self._bounds)

        with self._lock:
            self._require_open()
            self._begin_immediate()
            prior_replay = self._replay
            try:
                self._synchronize_locked()
                # Synchronization may have adopted another process's committed
                # head. Rollback must preserve that audited state, not the stale
                # value held before BEGIN IMMEDIATE acquired the writer lock.
                prior_replay = self._replay
                existing = self._connection.execute(
                    "SELECT window_index, window_id, request_bytes, result_bytes "
                    "FROM operations WHERE operation_id = ?",
                    (value.operation_id,),
                ).fetchone()
                if existing is not None:
                    if bytes(existing["request_bytes"]) != request_bytes:
                        raise ProtocolStateConflict("operation_id_conflict")
                    self._connection.commit()
                    return AppliedProtocolWindow(
                        operation_id=value.operation_id,
                        window_index=int(existing["window_index"]),
                        window_id=bytes(existing["window_id"]),
                        request_bytes=request_bytes,
                        result_bytes=bytes(existing["result_bytes"]),
                        idempotent=True,
                        snapshot=_snapshot(self._replay, self._bounds),
                    )

                collision = self._connection.execute(
                    "SELECT operation_id FROM operations WHERE window_index = ? OR window_id = ?",
                    (value.window_index, value.window_id),
                ).fetchone()
                if collision is not None:
                    raise ProtocolStateConflict("window_replay_conflict")
                transition = _transition(
                    self._replay,
                    value,
                    request_bytes=request_bytes,
                    bounds=self._bounds,
                )
                self._connection.execute(
                    "INSERT INTO operations ("
                    "window_index, operation_id, window_id, reveal_round, evidence_digest, "
                    "request_bytes, request_sha256, result_bytes, result_sha256"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        value.window_index,
                        value.operation_id,
                        value.window_id,
                        value.reveal_round,
                        value.evidence_digest,
                        request_bytes,
                        hashlib.sha256(request_bytes).digest(),
                        transition.result_bytes,
                        hashlib.sha256(transition.result_bytes).digest(),
                    ),
                )
                self._write_current_state_locked(transition)
                self._assert_safe_database_files()
                self._connection.commit()
                self._replay = transition.state
                return AppliedProtocolWindow(
                    operation_id=value.operation_id,
                    window_index=value.window_index,
                    window_id=value.window_id,
                    request_bytes=request_bytes,
                    result_bytes=transition.result_bytes,
                    idempotent=False,
                    snapshot=transition.snapshot,
                )
            except Exception as error:
                self._connection.rollback()
                self._replay = prior_replay
                if isinstance(
                    error,
                    (
                        ProtocolStateStoreError,
                        TypeError,
                        ValueError,
                    ),
                ):
                    raise
                if isinstance(error, sqlite3.OperationalError) and "locked" in str(error).lower():
                    raise ProtocolStateStoreError("database_busy") from error
                if isinstance(error, sqlite3.Error):
                    raise ProtocolStateStoreError("database_write_failed") from error
                raise

    def audit(self) -> ProtocolStateSnapshot:
        """Replay every persisted checkpoint and refresh the in-memory state."""

        with self._lock:
            self._require_open()
            self._begin_immediate()
            try:
                self._replay = self._audit_locked()
                snapshot = _snapshot(self._replay, self._bounds)
                self._connection.commit()
                return snapshot
            except Exception:
                self._connection.rollback()
                raise

    def _close_after_failed_init(self) -> None:
        connection = getattr(self, "_connection", None)
        if connection is not None:
            with suppress(sqlite3.Error):
                connection.close()
        self._closed = True

    def _require_open(self) -> None:
        if self._closed:
            raise ProtocolStateStoreError("store_closed")

    def _begin_immediate(self) -> None:
        try:
            self._connection.execute("BEGIN IMMEDIATE")
        except sqlite3.OperationalError as error:
            if "locked" in str(error).lower():
                raise ProtocolStateStoreError("database_busy") from error
            raise

    def _configure_connection(self, busy_timeout_ms: int) -> None:
        journal_mode = self._connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]
        if str(journal_mode).lower() != "wal":
            raise ProtocolStateStoreError("wal_unavailable")
        self._connection.execute("PRAGMA synchronous = FULL")
        if int(self._connection.execute("PRAGMA synchronous").fetchone()[0]) != 2:
            raise ProtocolStateStoreError("synchronous_full_unavailable")
        self._connection.execute("PRAGMA foreign_keys = ON")
        if int(self._connection.execute("PRAGMA foreign_keys").fetchone()[0]) != 1:
            raise ProtocolStateStoreError("foreign_keys_unavailable")
        self._connection.execute(f"PRAGMA busy_timeout = {busy_timeout_ms}")
        self._connection.execute("PRAGMA trusted_schema = OFF")

    def _initialize_or_verify_schema_locked(self) -> None:
        version = int(self._connection.execute("PRAGMA user_version").fetchone()[0])
        application_id = int(self._connection.execute("PRAGMA application_id").fetchone()[0])
        objects = {
            row[0]
            for row in self._connection.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type IN ('table', 'view', 'trigger') AND name NOT LIKE 'sqlite_%'"
            )
        }
        if version == 0 and application_id == 0 and not objects:
            for statement in _SCHEMA_STATEMENTS:
                self._connection.execute(statement)
            schema_digest = hashlib.sha256(
                "\n".join(statement.strip() for statement in _SCHEMA_STATEMENTS).encode("utf-8")
            ).digest()
            self._connection.execute(
                "INSERT INTO store_meta (key, value) VALUES (?, ?)",
                ("schema_sha256", schema_digest),
            )
            self._connection.execute(f"PRAGMA application_id = {_APPLICATION_ID}")
            self._connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
            _state, snapshot = _genesis(self._bounds)
            self._connection.execute(
                "INSERT INTO current_head ("
                "singleton, last_window_index, last_window_id, spent_root, "
                "spent_last_reveal_round, publisher_fault_root, "
                "publisher_fault_last_window, observation_root, rolling_state_sha256, state_digest"
                ") VALUES (1, -1, NULL, ?, 0, ?, -1, ?, ?, ?)",
                (
                    snapshot.spent_registry.root,
                    snapshot.publisher_faults.root,
                    snapshot.observation_root,
                    _rolling_digest(snapshot.rolling_scores, self._bounds),
                    snapshot.state_digest,
                ),
            )
            return
        if version != _SCHEMA_VERSION or application_id != _APPLICATION_ID:
            raise ProtocolStateCorruption("schema_identity_mismatch")
        if objects != _EXPECTED_TABLES:
            raise ProtocolStateCorruption("schema_object_mismatch")
        expected_digest = hashlib.sha256(
            "\n".join(statement.strip() for statement in _SCHEMA_STATEMENTS).encode("utf-8")
        ).digest()
        meta_rows = self._connection.execute(
            "SELECT key, value FROM store_meta ORDER BY key"
        ).fetchall()
        if (
            len(meta_rows) != 1
            or meta_rows[0]["key"] != "schema_sha256"
            or bytes(meta_rows[0]["value"]) != expected_digest
        ):
            raise ProtocolStateCorruption("schema_digest_mismatch")

    def _synchronize_locked(self) -> None:
        row = self._connection.execute(
            "SELECT last_window_index, state_digest FROM current_head WHERE singleton = 1"
        ).fetchone()
        if row is None:
            raise ProtocolStateCorruption("current_head_missing")
        local = _snapshot(self._replay, self._bounds)
        if (
            int(row["last_window_index"]) != local.last_window_index
            or bytes(row["state_digest"]) != local.state_digest
        ):
            self._replay = self._audit_locked()

    def _write_current_state_locked(self, transition: _Transition) -> None:
        state = transition.state
        snapshot = transition.snapshot
        for leaf in transition.spent.delta_leaves:
            self._connection.execute(
                "INSERT INTO spent_leaves (leaf, first_window_index) VALUES (?, ?)",
                (leaf, snapshot.last_window_index),
            )

        self._connection.execute("DELETE FROM publisher_fault_groups")
        cooldowns = dict(state.faults.cooldown_ends)
        for group, strikes in state.faults.strikes:
            self._connection.execute(
                "INSERT INTO publisher_fault_groups "
                "(control_group_id, strikes, cooldown_end) VALUES (?, ?, ?)",
                (group, strikes, cooldowns[group]),
            )

        self._connection.execute("DELETE FROM rolling_batches")
        ordinal_by_window: dict[int, int] = {}
        for batch in state.rolling.batches:
            window_ordinal = ordinal_by_window.get(batch.window_index, 0)
            ordinal_by_window[batch.window_index] = window_ordinal + 1
            pool_leaf = raw_sha256(batch.pool_leaf, field="pool leaf")
            self._connection.execute(
                "INSERT INTO rolling_batches "
                "(window_index, ordinal, pool_leaf, batch_rank) VALUES (?, ?, ?, ?)",
                (
                    batch.window_index,
                    window_ordinal,
                    pool_leaf,
                    raw_sha256(batch.batch_rank, field="batch rank"),
                ),
            )
            for ordinal, challenge_id in enumerate(batch.challenge_ids):
                self._connection.execute(
                    "INSERT INTO rolling_challenges "
                    "(window_index, pool_leaf, ordinal, challenge_id) VALUES (?, ?, ?, ?)",
                    (
                        batch.window_index,
                        pool_leaf,
                        ordinal,
                        base64url_decode(challenge_id),
                    ),
                )
            for ordinal, root in enumerate(batch.miner_roots):
                self._connection.execute(
                    "INSERT INTO rolling_miners "
                    "(window_index, pool_leaf, ordinal, miner_root) VALUES (?, ?, ?, ?)",
                    (batch.window_index, pool_leaf, ordinal, account_id32(root)),
                )
            for assignment in batch.assignments:
                numerator = None if assignment.score is None else str(assignment.score.numerator)
                denominator = (
                    None if assignment.score is None else str(assignment.score.denominator)
                )
                self._connection.execute(
                    "INSERT INTO rolling_assignments ("
                    "window_index, pool_leaf, miner_root, challenge_id, request_leaf, "
                    "stratum, canary, score_numerator, score_denominator"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        batch.window_index,
                        pool_leaf,
                        assignment.root,
                        base64url_decode(assignment.challenge_id),
                        assignment.leaf,
                        assignment.stratum,
                        int(assignment.canary),
                        numerator,
                        denominator,
                    ),
                )

        # Only roots issued in this window change. Keeping one normalized total
        # per root avoids copying the complete cumulative map into every
        # checkpoint and makes the common update proportional to this window.
        for root, _increment in transition.observation_increments:
            count = state.observation_counts[root]
            self._connection.execute(
                "INSERT INTO assigned_observation_counts (miner_root, assigned_count) "
                "VALUES (?, ?) ON CONFLICT(miner_root) DO UPDATE SET "
                "assigned_count = excluded.assigned_count",
                (root, str(count)),
            )

        self._connection.execute(
            "UPDATE current_head SET "
            "last_window_index = ?, last_window_id = ?, spent_root = ?, "
            "spent_last_reveal_round = ?, publisher_fault_root = ?, "
            "publisher_fault_last_window = ?, observation_root = ?, "
            "rolling_state_sha256 = ?, state_digest = ? WHERE singleton = 1",
            (
                snapshot.last_window_index,
                snapshot.last_window_id,
                snapshot.spent_registry.root,
                snapshot.spent_registry.last_reveal_round,
                snapshot.publisher_faults.root,
                snapshot.publisher_faults.last_window_index,
                snapshot.observation_root,
                _rolling_digest(snapshot.rolling_scores, self._bounds),
                snapshot.state_digest,
            ),
        )

    def _audit_locked(self) -> _ReplayState:
        try:
            return self._audit_impl_locked()
        except ProtocolStateStoreError:
            raise
        except (OverflowError, TypeError, ValueError, sqlite3.Error) as error:
            raise ProtocolStateCorruption("operation_log_decode_failed") from error

    def _audit_impl_locked(self) -> _ReplayState:
        quick_check = self._connection.execute("PRAGMA quick_check").fetchall()
        if [row[0] for row in quick_check] != ["ok"]:
            raise ProtocolStateCorruption("sqlite_quick_check_failed")
        if self._connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise ProtocolStateCorruption("foreign_key_check_failed")

        state, _genesis_snapshot = _genesis(self._bounds)
        rows = self._connection.execute(
            "SELECT window_index, operation_id, window_id, reveal_round, evidence_digest, "
            "request_bytes, request_sha256, result_bytes, result_sha256 "
            "FROM operations ORDER BY window_index"
        ).fetchall()
        for expected_index, row in enumerate(rows):
            if int(row["window_index"]) != expected_index:
                raise ProtocolStateCorruption("operation_sequence_gap")
            request_bytes = bytes(row["request_bytes"])
            if hashlib.sha256(request_bytes).digest() != bytes(row["request_sha256"]):
                raise ProtocolStateCorruption("request_digest_mismatch")
            value = _parse_request(request_bytes, self._bounds)
            if (
                value.window_index != expected_index
                or value.operation_id != bytes(row["operation_id"])
                or value.window_id != bytes(row["window_id"])
                or value.reveal_round != int(row["reveal_round"])
                or value.evidence_digest != bytes(row["evidence_digest"])
            ):
                raise ProtocolStateCorruption("operation_metadata_mismatch")
            try:
                transition = _transition(
                    state,
                    value,
                    request_bytes=request_bytes,
                    bounds=self._bounds,
                )
            except (TypeError, ValueError, ProtocolStateStoreError) as error:
                raise ProtocolStateCorruption("operation_replay_failed") from error
            result_bytes = bytes(row["result_bytes"])
            if (
                len(result_bytes) > self._bounds.maximum_result_bytes
                or hashlib.sha256(result_bytes).digest() != bytes(row["result_sha256"])
                or result_bytes != transition.result_bytes
            ):
                raise ProtocolStateCorruption("result_checkpoint_mismatch")
            state = transition.state

        self._compare_current_tables_locked(state)
        return state

    def _compare_current_tables_locked(self, expected: _ReplayState) -> None:
        snapshot = _snapshot(expected, self._bounds)
        head_rows = self._connection.execute("SELECT * FROM current_head").fetchall()
        if len(head_rows) != 1:
            raise ProtocolStateCorruption("current_head_invalid")
        head = head_rows[0]
        expected_head = (
            1,
            snapshot.last_window_index,
            snapshot.last_window_id,
            snapshot.spent_registry.root,
            snapshot.spent_registry.last_reveal_round,
            snapshot.publisher_faults.root,
            snapshot.publisher_faults.last_window_index,
            snapshot.observation_root,
            _rolling_digest(snapshot.rolling_scores, self._bounds),
            snapshot.state_digest,
        )
        actual_head = tuple(head)
        if actual_head != expected_head:
            raise ProtocolStateCorruption("current_head_mismatch")

        spent_rows = tuple(
            (bytes(row["leaf"]), int(row["first_window_index"]))
            for row in self._connection.execute(
                "SELECT leaf, first_window_index FROM spent_leaves ORDER BY leaf"
            )
        )
        if spent_rows != tuple(sorted(expected.spent_first_windows.items())):
            raise ProtocolStateCorruption("spent_leaf_table_mismatch")
        if frozenset(leaf for leaf, _ in spent_rows) != expected.spent.leaves:
            raise ProtocolStateCorruption("spent_leaf_state_mismatch")

        cooldowns = dict(expected.faults.cooldown_ends)
        fault_rows = tuple(
            (
                bytes(row["control_group_id"]),
                int(row["strikes"]),
                int(row["cooldown_end"]),
            )
            for row in self._connection.execute(
                "SELECT control_group_id, strikes, cooldown_end "
                "FROM publisher_fault_groups ORDER BY control_group_id"
            )
        )
        expected_fault_rows = tuple(
            (group, strikes, cooldowns[group]) for group, strikes in expected.faults.strikes
        )
        if fault_rows != expected_fault_rows:
            raise ProtocolStateCorruption("publisher_fault_table_mismatch")

        rolling = self._read_rolling_state_locked()
        if rolling != expected.rolling:
            raise ProtocolStateCorruption("rolling_state_table_mismatch")

        observation_rows: list[tuple[bytes, int]] = []
        for row in self._connection.execute(
            "SELECT miner_root, assigned_count FROM assigned_observation_counts ORDER BY miner_root"
        ):
            encoded = row["assigned_count"]
            if (
                not isinstance(encoded, str)
                or _DECIMAL_RE.fullmatch(encoded) is None
                or encoded == "0"
            ):
                raise ProtocolStateCorruption("observation_count_invalid")
            observation_rows.append((bytes(row["miner_root"]), int(encoded)))
        if tuple(observation_rows) != tuple(sorted(expected.observation_counts.items())):
            raise ProtocolStateCorruption("observation_count_table_mismatch")

    def _read_rolling_state_locked(self) -> RollingScoreState:
        batches: list[ScoredBatch] = []
        rows = self._connection.execute(
            "SELECT window_index, ordinal, pool_leaf, batch_rank FROM rolling_batches "
            "ORDER BY window_index, ordinal"
        ).fetchall()
        try:
            for row in rows:
                window_index = int(row["window_index"])
                pool_leaf = bytes(row["pool_leaf"])
                challenge_rows = self._connection.execute(
                    "SELECT challenge_id FROM rolling_challenges "
                    "WHERE window_index = ? AND pool_leaf = ? ORDER BY ordinal",
                    (window_index, pool_leaf),
                ).fetchall()
                miner_rows = self._connection.execute(
                    "SELECT miner_root FROM rolling_miners "
                    "WHERE window_index = ? AND pool_leaf = ? ORDER BY ordinal",
                    (window_index, pool_leaf),
                ).fetchall()
                assignment_rows = self._connection.execute(
                    "SELECT miner_root, challenge_id, request_leaf, stratum, canary, "
                    "score_numerator, score_denominator FROM rolling_assignments "
                    "WHERE window_index = ? AND pool_leaf = ? "
                    "ORDER BY miner_root, challenge_id",
                    (window_index, pool_leaf),
                ).fetchall()
                assignments: list[AssignmentScore] = []
                for assignment in assignment_rows:
                    numerator = assignment["score_numerator"]
                    denominator = assignment["score_denominator"]
                    score: Fraction | None
                    if numerator is None and denominator is None:
                        score = None
                    elif isinstance(numerator, str) and isinstance(denominator, str):
                        if (
                            _DECIMAL_RE.fullmatch(numerator) is None
                            or _DECIMAL_RE.fullmatch(denominator) is None
                            or denominator == "0"
                            or len(numerator) > self._bounds.maximum_fraction_decimal_digits
                            or len(denominator) > self._bounds.maximum_fraction_decimal_digits
                        ):
                            raise ProtocolStateCorruption("rolling_fraction_invalid")
                        score = Fraction(int(numerator), int(denominator))
                    else:
                        raise ProtocolStateCorruption("rolling_fraction_invalid")
                    assignments.append(
                        AssignmentScore(
                            miner_root=bytes(assignment["miner_root"]),
                            challenge_id=base64url_encode(bytes(assignment["challenge_id"])),
                            request_leaf=bytes(assignment["request_leaf"]),
                            stratum=str(assignment["stratum"]),  # type: ignore[arg-type]
                            canary=bool(assignment["canary"]),
                            score=score,
                        )
                    )
                batches.append(
                    ScoredBatch(
                        window_index=window_index,
                        batch_rank=bytes(row["batch_rank"]),
                        pool_leaf=pool_leaf,
                        challenge_ids=tuple(
                            base64url_encode(bytes(challenge["challenge_id"]))
                            for challenge in challenge_rows
                        ),
                        miner_roots=tuple(bytes(miner["miner_root"]) for miner in miner_rows),
                        assignments=tuple(assignments),
                    )
                )
            return RollingScoreState(tuple(batches))
        except ProtocolStateCorruption:
            raise
        except (TypeError, ValueError) as error:
            raise ProtocolStateCorruption("rolling_state_decode_failed") from error

    @classmethod
    def _prepare_database_path(cls, path: Path) -> Path:
        if not path.is_absolute():
            raise ValueError("database_path must be absolute")
        parent = path.parent
        try:
            unresolved_parent = parent.lstat()
            if stat.S_ISLNK(unresolved_parent.st_mode):
                raise ProtocolStateStoreError("unsafe_database_parent")
            resolved_parent = parent.resolve(strict=True)
            parent_stat = resolved_parent.stat()
        except ProtocolStateStoreError:
            raise
        except OSError as error:
            raise ProtocolStateStoreError("database_parent_unavailable") from error
        if not stat.S_ISDIR(parent_stat.st_mode) or parent_stat.st_mode & 0o022:
            raise ProtocolStateStoreError("unsafe_database_parent")
        if hasattr(os, "getuid") and parent_stat.st_uid != os.getuid():
            raise ProtocolStateStoreError("unsafe_database_parent")

        path = resolved_parent / path.name
        cls._assert_path_entry_safe(path, allow_missing=True)
        for suffix in ("-wal", "-shm", "-journal"):
            cls._assert_path_entry_safe(Path(os.fspath(path) + suffix), allow_missing=True)
        if not path.exists():
            flags = os.O_CREAT | os.O_EXCL | os.O_RDWR
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                descriptor = os.open(path, flags, 0o600)
                os.close(descriptor)
            except OSError as error:
                raise ProtocolStateStoreError("database_create_failed") from error
        cls._assert_path_entry_safe(path, allow_missing=False)
        return path

    @classmethod
    def _assert_path_entry_safe(cls, path: Path, *, allow_missing: bool) -> None:
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            if allow_missing:
                return
            raise ProtocolStateStoreError("database_file_missing") from None
        except OSError as error:
            raise ProtocolStateStoreError("database_file_unavailable") from error
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_mode & 0o022
            or metadata.st_nlink != 1
        ):
            raise ProtocolStateStoreError("unsafe_database_file")
        if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
            raise ProtocolStateStoreError("unsafe_database_file")

    def _assert_safe_database_files(self) -> None:
        self._assert_path_entry_safe(self._path, allow_missing=False)
        for suffix in ("-wal", "-shm"):
            self._assert_path_entry_safe(
                Path(os.fspath(self._path) + suffix),
                allow_missing=True,
            )


__all__ = [
    "PROTOCOL_STATE_SNAPSHOT_SCHEMA",
    "REQUEST_SCHEMA",
    "RESULT_SCHEMA",
    "AppliedProtocolWindow",
    "ProtocolStateConflict",
    "ProtocolStateCorruption",
    "ProtocolStateLimitError",
    "ProtocolStatePolicyLimits",
    "ProtocolStateSnapshot",
    "ProtocolStateStoreBounds",
    "ProtocolStateStoreError",
    "ValidatorProtocolStateStore",
    "decode_protocol_state_snapshot",
    "encode_protocol_state_snapshot",
]
