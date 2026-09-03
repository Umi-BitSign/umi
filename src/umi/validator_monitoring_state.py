"""Crash-safe bounded state for source-conditioned validator monitoring.

Only complete, valid two-batch scoring windows belong in this store.  Skipped
and void windows advance other protocol state, but they must not enter the
``publisher_monitoring_batches`` queue described by the whitepaper.  The store
keeps canonical operation bytes for the retained queue and independently
materializes every observation in normalized SQLite rows.  On open and before
each write it replays those bytes and compares the normalized tables and head
digest, failing closed on any disagreement.

The module deliberately does not decide whether a window is protocol-valid.
Its caller must obtain that fact from the reveal/score state machine and bind
the corresponding evidence digest.  Requiring the literal ``True`` at this
boundary prevents a skipped or void result from being inserted accidentally.
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
from contextlib import suppress
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path
from typing import Any

from .encoding import account_id32, raw_sha256, u32be, u64be
from .monitoring import (
    BOOTSTRAP_REPLICATES,
    MAX_MONITORED_SOURCES_PER_KIND,
    MAX_MONITORING_OBSERVATIONS,
    SourceMonitoringReport,
    SourceObservation,
    compute_source_monitoring,
)
from .protocol import canonical_json_bytes
from .rolling import ScoredBatch

MONITORING_WINDOW_SCHEMA = "umi-validator-monitoring-window/1"
MONITORING_POLICY_SCHEMA = "umi-validator-monitoring-policy/1"

_APPLICATION_ID = 0x554D494D  # "UMIM"
_SCHEMA_VERSION = 1
_STATE_DOMAIN = b"umi-validator-monitoring-state-v1\0"
_JSON_SAFE_INTEGER = (1 << 53) - 1
_DECIMAL_RE = re.compile(r"^(0|-?[1-9][0-9]*)$")
_POSITIVE_DECIMAL_RE = re.compile(r"^[1-9][0-9]*$")
_HEX32_RE = re.compile(r"^[0-9a-f]{64}$")
_STRATA = ("fingerspelling", "short_utterance", "continuous")


class MonitoringStateStoreError(RuntimeError):
    """Stable failure at the durable source-monitoring boundary."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(f"validator monitoring state failed: {reason_code}")


class MonitoringStateConflict(MonitoringStateStoreError):
    """A submitted operation conflicts with retained or later history."""


class MonitoringStateCorruption(MonitoringStateStoreError):
    """Persisted bytes do not reproduce the materialized monitoring state."""


class MonitoringStateLimitError(MonitoringStateStoreError):
    """A policy or operation exceeds a fail-closed local resource bound."""


class MonitoringStateEmpty(MonitoringStateStoreError):
    """No valid scoring cohort is available for a monitoring report."""


@dataclass(frozen=True, slots=True)
class MonitoringBatchSource:
    """Policy source identity for one selected scored batch."""

    pool_leaf: str | bytes
    publisher_hotkey: str | bytes
    control_group_id: str | bytes

    def __post_init__(self) -> None:
        raw_sha256(self.pool_leaf, field="pool leaf")
        account_id32(self.publisher_hotkey)
        raw_sha256(self.control_group_id, field="control group ID")

    @property
    def pool(self) -> bytes:
        return raw_sha256(self.pool_leaf, field="pool leaf")

    @property
    def publisher(self) -> bytes:
        return account_id32(self.publisher_hotkey)

    @property
    def group(self) -> bytes:
        return raw_sha256(self.control_group_id, field="control group ID")


@dataclass(frozen=True, slots=True)
class MonitoringSignerCluster:
    """Signer-cluster identity bound to one emission-bearing request leaf."""

    request_leaf: str | bytes
    signer_cluster_id: str | bytes

    def __post_init__(self) -> None:
        raw_sha256(self.request_leaf, field="request leaf")
        raw_sha256(self.signer_cluster_id, field="signer cluster ID")

    @property
    def leaf(self) -> bytes:
        return raw_sha256(self.request_leaf, field="request leaf")

    @property
    def cluster(self) -> bytes:
        return raw_sha256(self.signer_cluster_id, field="signer cluster ID")


@dataclass(frozen=True, slots=True)
class MonitoringStatePolicy:
    """Policy values and registries that define one monitoring database."""

    validator_account_id32: bytes
    scoring_policy_hash: bytes
    maximum_batches: int
    minimum_clips_per_side_and_stratum: int
    alert_threshold: Fraction
    publisher_sources: tuple[bytes, ...]
    control_group_sources: tuple[bytes, ...]
    publisher_control_groups: tuple[tuple[bytes, bytes], ...]
    bootstrap_replicates: int = BOOTSTRAP_REPLICATES

    def __post_init__(self) -> None:
        account_id32(self.validator_account_id32)
        raw_sha256(self.scoring_policy_hash, field="scoring policy hash")
        for name in (
            "maximum_batches",
            "minimum_clips_per_side_and_stratum",
            "bootstrap_replicates",
        ):
            value = getattr(self, name)
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value <= 0
                or value > _JSON_SAFE_INTEGER
            ):
                raise ValueError(f"{name} must be a positive canonical JSON integer")
        if self.maximum_batches % 2:
            raise ValueError("maximum_batches must retain complete two-batch windows")
        if self.bootstrap_replicates > 65_536:
            raise ValueError("bootstrap_replicates exceeds its hard ceiling")
        if not isinstance(self.alert_threshold, Fraction):
            raise TypeError("alert_threshold must be Fraction")
        if not 0 <= self.alert_threshold <= 1:
            raise ValueError("alert_threshold must be in the unit interval")
        _validate_registry(self.publisher_sources, label="publisher", accounts=True)
        _validate_registry(self.control_group_sources, label="control-group", accounts=False)
        if not isinstance(self.publisher_control_groups, tuple):
            raise TypeError("publisher_control_groups must be a tuple")
        try:
            mappings = tuple(
                (account_id32(publisher), raw_sha256(group, field="control group ID"))
                for publisher, group in self.publisher_control_groups
            )
        except (TypeError, ValueError) as error:
            raise ValueError("publisher control-group mapping is invalid") from error
        if mappings != tuple(sorted(set(mappings))):
            raise ValueError("publisher control-group mapping must be sorted and unique")
        if tuple(publisher for publisher, _group in mappings) != self.publisher_sources:
            raise ValueError("publisher control-group mapping must cover every publisher once")
        if {group for _publisher, group in mappings} != set(self.control_group_sources):
            raise ValueError("publisher control-group mapping must cover every control group")


@dataclass(frozen=True, slots=True)
class MonitoringStateBounds:
    """Hard local limits independent of the active scoring policy."""

    maximum_request_bytes: int = 64 * 1024 * 1024
    maximum_observations: int = MAX_MONITORING_OBSERVATIONS
    maximum_observations_per_window: int = 65_536
    maximum_fraction_decimal_digits: int = 256

    def __post_init__(self) -> None:
        for name in self.__dataclass_fields__:
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if self.maximum_observations > MAX_MONITORING_OBSERVATIONS:
            raise ValueError("maximum_observations exceeds the monitoring implementation ceiling")
        if self.maximum_observations_per_window > self.maximum_observations:
            raise ValueError("per-window observation limit exceeds the retained-state limit")


@dataclass(frozen=True, slots=True)
class MonitoringStateSnapshot:
    """Reproduced head of the bounded valid-batch queue."""

    first_window_index: int | None
    last_window_index: int | None
    last_window_id: bytes | None
    valid_window_count: int
    batch_count: int
    observation_count: int
    state_digest: bytes

    def __post_init__(self) -> None:
        if self.valid_window_count < 0 or self.batch_count < 0 or self.observation_count < 0:
            raise ValueError("monitoring snapshot counts cannot be negative")
        empty = self.valid_window_count == 0
        if empty != (self.first_window_index is None):
            raise ValueError("empty monitoring state has no first window")
        if empty != (self.last_window_index is None):
            raise ValueError("empty monitoring state has no last window")
        if empty != (self.last_window_id is None):
            raise ValueError("empty monitoring state has no last window ID")
        if not empty:
            if self.first_window_index is None or self.last_window_index is None:
                raise ValueError("nonempty monitoring state needs a window range")
            if self.first_window_index < 0 or self.last_window_index < self.first_window_index:
                raise ValueError("monitoring snapshot window range is invalid")
            raw_sha256(self.last_window_id, field="last window ID")
        if self.batch_count != 2 * self.valid_window_count:
            raise ValueError("monitoring state must retain complete two-batch windows")
        raw_sha256(self.state_digest, field="monitoring state digest")


@dataclass(frozen=True, slots=True)
class MonitoringComputationInput:
    """Exact arguments supplied to :func:`compute_source_monitoring`."""

    observations: tuple[SourceObservation, ...]
    validator_account_id32: bytes
    scoring_policy_hash: bytes
    first_window_index: int
    last_window_index: int
    minimum_clips_per_side_and_stratum: int
    alert_threshold: Fraction
    maximum_batches: int
    publisher_sources: tuple[bytes, ...]
    control_group_sources: tuple[bytes, ...]
    bootstrap_replicates: int

    def compute(self) -> SourceMonitoringReport:
        """Produce the deterministic alert-only report from this exact input."""

        return compute_source_monitoring(
            self.observations,
            validator_hotkey=self.validator_account_id32,
            scoring_policy_hash=self.scoring_policy_hash,
            first_window_index=self.first_window_index,
            last_window_index=self.last_window_index,
            minimum_clips_per_side_and_stratum=self.minimum_clips_per_side_and_stratum,
            alert_threshold=self.alert_threshold,
            maximum_batches=self.maximum_batches,
            publisher_sources=self.publisher_sources,
            control_group_sources=self.control_group_sources,
            bootstrap_replicates=self.bootstrap_replicates,
        )


@dataclass(frozen=True, slots=True)
class AppliedMonitoringWindow:
    operation_id: bytes
    window_index: int
    window_id: bytes
    evidence_digest: bytes
    request_bytes: bytes
    idempotent: bool
    snapshot: MonitoringStateSnapshot


@dataclass(frozen=True, slots=True)
class _Window:
    operation_id: bytes
    window_index: int
    window_id: bytes
    evidence_digest: bytes
    observations: tuple[SourceObservation, ...]
    request_bytes: bytes


_SCHEMA_STATEMENTS = (
    """
    CREATE TABLE store_meta (
        key TEXT PRIMARY KEY,
        value BLOB NOT NULL
    ) WITHOUT ROWID
    """,
    """
    CREATE TABLE valid_windows (
        window_index INTEGER PRIMARY KEY CHECK(window_index >= 0),
        operation_id BLOB NOT NULL UNIQUE
            CHECK(typeof(operation_id) = 'blob' AND length(operation_id) = 32),
        window_id BLOB NOT NULL UNIQUE
            CHECK(typeof(window_id) = 'blob' AND length(window_id) = 32),
        evidence_digest BLOB NOT NULL
            CHECK(typeof(evidence_digest) = 'blob' AND length(evidence_digest) = 32),
        request_bytes BLOB NOT NULL CHECK(typeof(request_bytes) = 'blob'),
        request_sha256 BLOB NOT NULL
            CHECK(typeof(request_sha256) = 'blob' AND length(request_sha256) = 32),
        observation_count INTEGER NOT NULL CHECK(observation_count > 0)
    )
    """,
    """
    CREATE TABLE monitoring_observations (
        request_leaf BLOB PRIMARY KEY
            CHECK(typeof(request_leaf) = 'blob' AND length(request_leaf) = 32),
        window_index INTEGER NOT NULL,
        pool_leaf BLOB NOT NULL
            CHECK(typeof(pool_leaf) = 'blob' AND length(pool_leaf) = 32),
        miner_root BLOB NOT NULL
            CHECK(typeof(miner_root) = 'blob' AND length(miner_root) = 32),
        publisher_hotkey BLOB NOT NULL
            CHECK(typeof(publisher_hotkey) = 'blob' AND length(publisher_hotkey) = 32),
        control_group_id BLOB NOT NULL
            CHECK(typeof(control_group_id) = 'blob' AND length(control_group_id) = 32),
        signer_cluster_id BLOB NOT NULL
            CHECK(typeof(signer_cluster_id) = 'blob' AND length(signer_cluster_id) = 32),
        stratum TEXT NOT NULL CHECK(
            stratum IN ('fingerspelling', 'short_utterance', 'continuous')
        ),
        score_numerator TEXT NOT NULL,
        score_denominator TEXT NOT NULL,
        FOREIGN KEY(window_index) REFERENCES valid_windows(window_index) ON DELETE CASCADE
    ) WITHOUT ROWID
    """,
    """
    CREATE TABLE current_head (
        singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
        first_window_index INTEGER,
        last_window_index INTEGER,
        last_window_id BLOB CHECK(
            last_window_id IS NULL OR
            (typeof(last_window_id) = 'blob' AND length(last_window_id) = 32)
        ),
        valid_window_count INTEGER NOT NULL CHECK(valid_window_count >= 0),
        batch_count INTEGER NOT NULL CHECK(batch_count >= 0),
        observation_count INTEGER NOT NULL CHECK(observation_count >= 0),
        state_digest BLOB NOT NULL
            CHECK(typeof(state_digest) = 'blob' AND length(state_digest) = 32),
        CHECK(
            (valid_window_count = 0 AND first_window_index IS NULL
                AND last_window_index IS NULL AND last_window_id IS NULL) OR
            (valid_window_count > 0 AND first_window_index IS NOT NULL
                AND last_window_index IS NOT NULL AND last_window_id IS NOT NULL)
        )
    )
    """,
)

_EXPECTED_TABLES = frozenset(
    {"store_meta", "valid_windows", "monitoring_observations", "current_head"}
)


def _validate_registry(
    values: tuple[bytes, ...],
    *,
    label: str,
    accounts: bool,
) -> None:
    if not isinstance(values, tuple) or not values:
        raise ValueError(f"{label} source registry must be a nonempty tuple")
    converter = account_id32 if accounts else raw_sha256
    normalized = tuple(converter(value) for value in values)
    if normalized != tuple(sorted(set(normalized))):
        raise ValueError(f"{label} source registry must be sorted and unique")
    if len(normalized) > MAX_MONITORED_SOURCES_PER_KIND:
        raise ValueError(f"{label} source registry exceeds its hard count ceiling")


def _fraction_object(value: Fraction, *, maximum_digits: int) -> dict[str, str]:
    if not isinstance(value, Fraction):
        raise TypeError("monitoring scores must use exact Fraction arithmetic")
    numerator = str(value.numerator)
    denominator = str(value.denominator)
    if len(numerator.lstrip("-")) > maximum_digits or len(denominator) > maximum_digits:
        raise MonitoringStateLimitError("fraction_decimal_limit")
    return {"numerator": numerator, "denominator": denominator}


def _decode_fraction(value: Any, *, maximum_digits: int) -> Fraction:
    if not isinstance(value, dict) or set(value) != {"numerator", "denominator"}:
        raise MonitoringStateCorruption("canonical_request_invalid")
    numerator = value["numerator"]
    denominator = value["denominator"]
    if (
        not isinstance(numerator, str)
        or not isinstance(denominator, str)
        or _DECIMAL_RE.fullmatch(numerator) is None
        or _POSITIVE_DECIMAL_RE.fullmatch(denominator) is None
        or len(numerator.lstrip("-")) > maximum_digits
        or len(denominator) > maximum_digits
    ):
        raise MonitoringStateCorruption("canonical_request_invalid")
    result = Fraction(int(numerator), int(denominator))
    if str(result.numerator) != numerator or str(result.denominator) != denominator:
        raise MonitoringStateCorruption("canonical_fraction_not_reduced")
    return result


def _hex32(value: bytes, *, field: str) -> str:
    return raw_sha256(value, field=field).hex()


def _decode_hex32(value: Any, *, field: str) -> bytes:
    if not isinstance(value, str) or _HEX32_RE.fullmatch(value) is None:
        raise MonitoringStateCorruption("canonical_request_invalid")
    return raw_sha256(value, field=field)


def _strict_int(value: Any, *, field: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > _JSON_SAFE_INTEGER
    ):
        raise MonitoringStateCorruption("canonical_request_invalid")
    return value


def _observation_key(value: SourceObservation) -> tuple[bytes, ...]:
    return (
        value.miner_root,
        value.publisher_hotkey,
        value.control_group_id,
        value.pool_leaf,
        value.request_leaf,
    )


def source_observations_from_scored_batches(
    scored_batches: tuple[ScoredBatch, ScoredBatch],
    *,
    batch_sources: tuple[MonitoringBatchSource, MonitoringBatchSource],
    signer_clusters: tuple[MonitoringSignerCluster, ...],
) -> tuple[SourceObservation, ...]:
    """Build a complete non-canary monitoring cohort from scored assignments.

    ``ScoredBatch`` already proves that assignments are the complete
    miner-by-challenge cross product.  This adapter additionally requires an
    exact signer-cluster record for every non-canary request leaf and rejects
    records for canaries or omitted assignments.  All miners assigned the same
    clip must resolve to the same signer cluster.
    """

    if (
        not isinstance(scored_batches, tuple)
        or len(scored_batches) != 2
        or any(not isinstance(batch, ScoredBatch) for batch in scored_batches)
    ):
        raise ValueError("monitoring requires exactly two ScoredBatch values")
    if tuple(sorted(scored_batches, key=lambda batch: batch.order_key)) != scored_batches:
        raise ValueError("monitoring scored batches must preserve canonical batch order")
    if scored_batches[0].window_index != scored_batches[1].window_index:
        raise ValueError("monitoring scored batches must belong to one window")
    if scored_batches[0].miner_roots != scored_batches[1].miner_roots:
        raise ValueError("monitoring scored batches must use the same miner panel")
    if (
        not isinstance(batch_sources, tuple)
        or len(batch_sources) != 2
        or any(not isinstance(source, MonitoringBatchSource) for source in batch_sources)
    ):
        raise ValueError("batch_sources must contain exactly two source records")
    source_pools = tuple(source.pool for source in batch_sources)
    if source_pools != tuple(sorted(set(source_pools))):
        raise ValueError("batch source records must be unique and sorted by pool leaf")
    expected_pools = {raw_sha256(batch.pool_leaf, field="pool leaf") for batch in scored_batches}
    if set(source_pools) != expected_pools:
        raise ValueError("batch source records do not match the scored batches")
    if not isinstance(signer_clusters, tuple) or any(
        not isinstance(value, MonitoringSignerCluster) for value in signer_clusters
    ):
        raise TypeError("signer_clusters must be a tuple of MonitoringSignerCluster values")
    cluster_leaves = tuple(value.leaf for value in signer_clusters)
    if cluster_leaves != tuple(sorted(set(cluster_leaves))):
        raise ValueError("signer-cluster records must be unique and sorted by request leaf")

    source_by_pool = {source.pool: (source.publisher, source.group) for source in batch_sources}
    cluster_by_leaf = {value.leaf: value.cluster for value in signer_clusters}
    assignments = tuple(
        (batch, assignment)
        for batch in scored_batches
        for assignment in batch.assignments
        if not assignment.canary
    )
    expected_leaves = tuple(sorted(assignment.leaf for _batch, assignment in assignments))
    if len(set(expected_leaves)) != len(expected_leaves):
        raise ValueError("scored monitoring batches reuse a request leaf")
    if cluster_leaves != expected_leaves:
        raise ValueError("signer-cluster records must match every non-canary assignment exactly")

    clip_clusters: dict[tuple[bytes, str], bytes] = {}
    observations: list[SourceObservation] = []
    for batch, assignment in assignments:
        if assignment.score is None:
            raise ValueError("non-canary scored assignment is missing its exact score")
        pool = raw_sha256(batch.pool_leaf, field="pool leaf")
        cluster = cluster_by_leaf[assignment.leaf]
        clip_key = (pool, assignment.challenge_id)
        prior_cluster = clip_clusters.setdefault(clip_key, cluster)
        if prior_cluster != cluster:
            raise ValueError("one scored clip resolves to inconsistent signer clusters")
        publisher, group = source_by_pool[pool]
        observations.append(
            SourceObservation(
                request_leaf=assignment.leaf,
                pool_leaf=pool,
                miner_root=assignment.root,
                publisher_hotkey=publisher,
                control_group_id=group,
                signer_cluster_id=cluster,
                stratum=assignment.stratum,
                score=assignment.score,
            )
        )
    return tuple(sorted(observations, key=_observation_key))


def _observation_object(
    value: SourceObservation,
    *,
    maximum_fraction_digits: int,
) -> dict[str, Any]:
    return {
        "request_leaf": value.request_leaf.hex(),
        "pool_leaf": value.pool_leaf.hex(),
        "miner_root": value.miner_root.hex(),
        "publisher_hotkey": value.publisher_hotkey.hex(),
        "control_group_id": value.control_group_id.hex(),
        "signer_cluster_id": value.signer_cluster_id.hex(),
        "stratum": value.stratum,
        "score": _fraction_object(
            value.score,
            maximum_digits=maximum_fraction_digits,
        ),
    }


def _decode_observation(value: Any, *, maximum_fraction_digits: int) -> SourceObservation:
    expected = {
        "request_leaf",
        "pool_leaf",
        "miner_root",
        "publisher_hotkey",
        "control_group_id",
        "signer_cluster_id",
        "stratum",
        "score",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise MonitoringStateCorruption("canonical_request_invalid")
    if not isinstance(value["stratum"], str) or value["stratum"] not in _STRATA:
        raise MonitoringStateCorruption("canonical_request_invalid")
    try:
        return SourceObservation(
            request_leaf=_decode_hex32(value["request_leaf"], field="request leaf"),
            pool_leaf=_decode_hex32(value["pool_leaf"], field="pool leaf"),
            miner_root=_decode_hex32(value["miner_root"], field="miner root"),
            publisher_hotkey=_decode_hex32(value["publisher_hotkey"], field="publisher hotkey"),
            control_group_id=_decode_hex32(value["control_group_id"], field="control group ID"),
            signer_cluster_id=_decode_hex32(value["signer_cluster_id"], field="signer cluster ID"),
            stratum=value["stratum"],  # type: ignore[arg-type]
            score=_decode_fraction(value["score"], maximum_digits=maximum_fraction_digits),
        )
    except MonitoringStateStoreError:
        raise
    except (TypeError, ValueError) as error:
        raise MonitoringStateCorruption("canonical_request_invalid") from error


def _policy_bytes(policy: MonitoringStatePolicy) -> bytes:
    return canonical_json_bytes(
        {
            "schema": MONITORING_POLICY_SCHEMA,
            "validator_account_id32": policy.validator_account_id32.hex(),
            "scoring_policy_hash": policy.scoring_policy_hash.hex(),
            "maximum_batches": policy.maximum_batches,
            "minimum_clips_per_side_and_stratum": (policy.minimum_clips_per_side_and_stratum),
            "alert_threshold": {
                "numerator": str(policy.alert_threshold.numerator),
                "denominator": str(policy.alert_threshold.denominator),
            },
            "publisher_sources": [value.hex() for value in policy.publisher_sources],
            "control_group_sources": [value.hex() for value in policy.control_group_sources],
            "publisher_control_groups": [
                {
                    "publisher_hotkey": publisher.hex(),
                    "control_group_id": group.hex(),
                }
                for publisher, group in policy.publisher_control_groups
            ],
            "bootstrap_replicates": policy.bootstrap_replicates,
        }
    )


def _canonical_request(
    *,
    operation_id: bytes,
    window_index: int,
    window_id: bytes,
    evidence_digest: bytes,
    observations: tuple[SourceObservation, ...],
    bounds: MonitoringStateBounds,
) -> bytes:
    encoded = canonical_json_bytes(
        {
            "schema": MONITORING_WINDOW_SCHEMA,
            "operation_id": operation_id.hex(),
            "window_index": window_index,
            "window_id": window_id.hex(),
            "evidence_digest": evidence_digest.hex(),
            "valid_window": True,
            "observations": [
                _observation_object(
                    observation,
                    maximum_fraction_digits=bounds.maximum_fraction_decimal_digits,
                )
                for observation in observations
            ],
        }
    )
    if len(encoded) > bounds.maximum_request_bytes:
        raise MonitoringStateLimitError("canonical_request_size_limit")
    return encoded


def _strict_json_loads(encoded: bytes, *, maximum_bytes: int) -> dict[str, Any]:
    if not isinstance(encoded, bytes) or not encoded or len(encoded) > maximum_bytes:
        raise MonitoringStateCorruption("canonical_bytes_invalid")

    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise MonitoringStateCorruption("canonical_bytes_invalid")
            result[key] = value
        return result

    def reject_constant(_value: str) -> None:
        raise MonitoringStateCorruption("canonical_bytes_invalid")

    try:
        value = json.loads(
            encoded,
            object_pairs_hook=object_pairs,
            parse_constant=reject_constant,
        )
    except MonitoringStateStoreError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise MonitoringStateCorruption("canonical_bytes_invalid") from error
    if not isinstance(value, dict) or canonical_json_bytes(value) != encoded:
        raise MonitoringStateCorruption("canonical_bytes_invalid")
    return value


def _parse_request(encoded: bytes, *, bounds: MonitoringStateBounds) -> _Window:
    value = _strict_json_loads(encoded, maximum_bytes=bounds.maximum_request_bytes)
    expected = {
        "schema",
        "operation_id",
        "window_index",
        "window_id",
        "evidence_digest",
        "valid_window",
        "observations",
    }
    if (
        set(value) != expected
        or value["schema"] != MONITORING_WINDOW_SCHEMA
        or value["valid_window"] is not True
        or not isinstance(value["observations"], list)
    ):
        raise MonitoringStateCorruption("canonical_request_invalid")
    if len(value["observations"]) > bounds.maximum_observations_per_window:
        raise MonitoringStateCorruption("canonical_request_invalid")
    observations = tuple(
        _decode_observation(
            observation,
            maximum_fraction_digits=bounds.maximum_fraction_decimal_digits,
        )
        for observation in value["observations"]
    )
    window = _Window(
        operation_id=_decode_hex32(value["operation_id"], field="operation ID"),
        window_index=_strict_int(value["window_index"], field="window index"),
        window_id=_decode_hex32(value["window_id"], field="window ID"),
        evidence_digest=_decode_hex32(value["evidence_digest"], field="evidence digest"),
        observations=observations,
        request_bytes=encoded,
    )
    return window


def _normalize_observations(
    observations: tuple[SourceObservation, ...],
    *,
    policy: MonitoringStatePolicy,
    bounds: MonitoringStateBounds,
) -> tuple[SourceObservation, ...]:
    if not isinstance(observations, tuple) or not observations:
        raise ValueError("observations must be a nonempty tuple")
    if len(observations) > bounds.maximum_observations_per_window:
        raise MonitoringStateLimitError("window_observation_count_limit")
    if any(not isinstance(value, SourceObservation) for value in observations):
        raise TypeError("observations must contain SourceObservation values")
    ordered = tuple(sorted(observations, key=_observation_key))
    if len({value.request_leaf for value in ordered}) != len(ordered):
        raise ValueError("monitoring window contains a duplicate request leaf")
    pools = tuple(sorted({value.pool_leaf for value in ordered}))
    if len(pools) != 2:
        raise ValueError("a valid monitoring window must contain exactly two batches")
    publishers = frozenset(policy.publisher_sources)
    groups = frozenset(policy.control_group_sources)
    publisher_groups = dict(policy.publisher_control_groups)
    if any(value.publisher_hotkey not in publishers for value in ordered):
        raise ValueError("monitoring observation references an undeclared publisher")
    if any(value.control_group_id not in groups for value in ordered):
        raise ValueError("monitoring observation references an undeclared control group")
    if any(publisher_groups[value.publisher_hotkey] != value.control_group_id for value in ordered):
        raise ValueError("monitoring publisher does not match its policy control group")
    miner_panels: list[frozenset[bytes]] = []
    batch_sources: list[tuple[bytes, bytes]] = []
    for pool in pools:
        pool_values = tuple(value for value in ordered if value.pool_leaf == pool)
        sources = {(value.publisher_hotkey, value.control_group_id) for value in pool_values}
        if len(sources) != 1:
            raise ValueError("one monitoring batch must have exactly one publisher and group")
        batch_sources.append(next(iter(sources)))
        panel = frozenset(value.miner_root for value in pool_values)
        miner_panels.append(panel)
        for miner in panel:
            strata = {value.stratum for value in pool_values if value.miner_root == miner}
            if strata != set(_STRATA):
                raise ValueError("monitoring evidence contains a partial miner batch")
    if miner_panels[0] != miner_panels[1]:
        raise ValueError("selected monitoring batches must use the same miner panel")
    if batch_sources[0][1] == batch_sources[1][1]:
        raise ValueError("selected monitoring batches must use distinct control groups")
    return ordered


def _state_digest(policy_bytes: bytes, windows: tuple[_Window, ...]) -> bytes:
    return hashlib.sha256(
        _STATE_DOMAIN
        + hashlib.sha256(policy_bytes).digest()
        + u32be(len(windows))
        + b"".join(
            u64be(window.window_index) + hashlib.sha256(window.request_bytes).digest()
            for window in windows
        )
    ).digest()


def _snapshot(policy_bytes: bytes, windows: tuple[_Window, ...]) -> MonitoringStateSnapshot:
    observations = sum((len(window.observations) for window in windows), start=0)
    if not windows:
        return MonitoringStateSnapshot(
            first_window_index=None,
            last_window_index=None,
            last_window_id=None,
            valid_window_count=0,
            batch_count=0,
            observation_count=0,
            state_digest=_state_digest(policy_bytes, windows),
        )
    return MonitoringStateSnapshot(
        first_window_index=windows[0].window_index,
        last_window_index=windows[-1].window_index,
        last_window_id=windows[-1].window_id,
        valid_window_count=len(windows),
        batch_count=2 * len(windows),
        observation_count=observations,
        state_digest=_state_digest(policy_bytes, windows),
    )


class ValidatorMonitoringStateStore:
    """SQLite-backed queue of the latest policy-sized valid batch cohort."""

    def __init__(
        self,
        database_path: str | os.PathLike[str],
        *,
        policy: MonitoringStatePolicy,
        bounds: MonitoringStateBounds | None = None,
        busy_timeout_seconds: float = 10.0,
    ) -> None:
        if not isinstance(policy, MonitoringStatePolicy):
            raise TypeError("policy must be MonitoringStatePolicy")
        if bounds is not None and not isinstance(bounds, MonitoringStateBounds):
            raise TypeError("bounds must be MonitoringStateBounds or None")
        if (
            isinstance(busy_timeout_seconds, bool)
            or not isinstance(busy_timeout_seconds, (int, float))
            or not math.isfinite(busy_timeout_seconds)
            or busy_timeout_seconds <= 0
        ):
            raise ValueError("busy_timeout_seconds must be a positive finite number")
        self._policy = policy
        self._policy_bytes = _policy_bytes(policy)
        self._bounds = bounds or MonitoringStateBounds()
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
                    self._windows = self._audit_locked()
                    self._connection.commit()
                except Exception:
                    self._connection.rollback()
                    raise
            self._assert_safe_database_files()
        except MonitoringStateStoreError:
            self._close_after_failed_init()
            raise
        except (OSError, sqlite3.Error, TypeError, ValueError) as error:
            self._close_after_failed_init()
            raise MonitoringStateStoreError("database_open_failed") from error

    @property
    def database_path(self) -> Path:
        return self._path

    @property
    def policy(self) -> MonitoringStatePolicy:
        return self._policy

    @property
    def snapshot(self) -> MonitoringStateSnapshot:
        with self._lock:
            self._require_open()
            return _snapshot(self._policy_bytes, self._windows)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._connection.close()
            self._closed = True

    def __enter__(self) -> ValidatorMonitoringStateStore:
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
        evidence_digest: str | bytes,
        valid_window: bool,
        observations: tuple[SourceObservation, ...],
    ) -> AppliedMonitoringWindow:
        """Insert one complete valid cohort and atomically evict the oldest pair."""

        if valid_window is not True:
            raise ValueError("only a protocol-valid window may enter monitoring state")
        if (
            isinstance(window_index, bool)
            or not isinstance(window_index, int)
            or not 0 <= window_index <= _JSON_SAFE_INTEGER
        ):
            raise ValueError("window_index is outside the canonical integer range")
        operation = raw_sha256(operation_id, field="operation ID")
        identifier = raw_sha256(window_id, field="window ID")
        evidence = raw_sha256(evidence_digest, field="evidence digest")
        ordered = _normalize_observations(
            observations,
            policy=self._policy,
            bounds=self._bounds,
        )
        request_bytes = _canonical_request(
            operation_id=operation,
            window_index=window_index,
            window_id=identifier,
            evidence_digest=evidence,
            observations=ordered,
            bounds=self._bounds,
        )

        with self._lock:
            self._require_open()
            self._begin_immediate()
            prior = self._windows
            try:
                self._windows = self._audit_locked()
                # BEGIN IMMEDIATE may have waited for another process.  Once
                # that process's head has been audited, a later rollback must
                # retain the adopted state rather than restore our stale head.
                prior = self._windows
                existing = self._connection.execute(
                    "SELECT window_index, window_id, evidence_digest, request_bytes "
                    "FROM valid_windows WHERE operation_id = ?",
                    (operation,),
                ).fetchone()
                if existing is not None:
                    if bytes(existing["request_bytes"]) != request_bytes:
                        raise MonitoringStateConflict("operation_id_conflict")
                    snapshot = _snapshot(self._policy_bytes, self._windows)
                    self._connection.commit()
                    return AppliedMonitoringWindow(
                        operation_id=operation,
                        window_index=int(existing["window_index"]),
                        window_id=bytes(existing["window_id"]),
                        evidence_digest=bytes(existing["evidence_digest"]),
                        request_bytes=request_bytes,
                        idempotent=True,
                        snapshot=snapshot,
                    )
                last = self._windows[-1] if self._windows else None
                if last is not None and window_index <= last.window_index:
                    raise MonitoringStateConflict("stale_or_conflicting_window")
                collision = self._connection.execute(
                    "SELECT 1 FROM valid_windows WHERE window_id = ?",
                    (identifier,),
                ).fetchone()
                if collision is not None:
                    raise MonitoringStateConflict("window_id_conflict")
                retained_pools = {
                    observation.pool_leaf
                    for retained in self._windows
                    for observation in retained.observations
                }
                if any(observation.pool_leaf in retained_pools for observation in ordered):
                    raise MonitoringStateConflict("pool_leaf_reuse")

                self._connection.execute(
                    "INSERT INTO valid_windows ("
                    "window_index, operation_id, window_id, evidence_digest, request_bytes, "
                    "request_sha256, observation_count) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        window_index,
                        operation,
                        identifier,
                        evidence,
                        request_bytes,
                        hashlib.sha256(request_bytes).digest(),
                        len(ordered),
                    ),
                )
                for value in ordered:
                    self._connection.execute(
                        "INSERT INTO monitoring_observations ("
                        "request_leaf, window_index, pool_leaf, miner_root, publisher_hotkey, "
                        "control_group_id, signer_cluster_id, stratum, score_numerator, "
                        "score_denominator) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            value.request_leaf,
                            window_index,
                            value.pool_leaf,
                            value.miner_root,
                            value.publisher_hotkey,
                            value.control_group_id,
                            value.signer_cluster_id,
                            value.stratum,
                            str(value.score.numerator),
                            str(value.score.denominator),
                        ),
                    )
                maximum_windows = self._policy.maximum_batches // 2
                retained_indices = [
                    int(row["window_index"])
                    for row in self._connection.execute(
                        "SELECT window_index FROM valid_windows ORDER BY window_index"
                    )
                ]
                for evicted in retained_indices[:-maximum_windows]:
                    self._connection.execute(
                        "DELETE FROM valid_windows WHERE window_index = ?", (evicted,)
                    )
                windows = self._read_windows_locked()
                if (
                    sum(len(item.observations) for item in windows)
                    > self._bounds.maximum_observations
                ):
                    raise MonitoringStateLimitError("retained_observation_count_limit")
                snapshot = _snapshot(self._policy_bytes, windows)
                self._write_head_locked(snapshot)
                self._assert_safe_database_files()
                self._connection.commit()
                self._windows = windows
                return AppliedMonitoringWindow(
                    operation_id=operation,
                    window_index=window_index,
                    window_id=identifier,
                    evidence_digest=evidence,
                    request_bytes=request_bytes,
                    idempotent=False,
                    snapshot=snapshot,
                )
            except Exception as error:
                self._connection.rollback()
                self._windows = prior
                if isinstance(error, (MonitoringStateStoreError, TypeError, ValueError)):
                    raise
                if isinstance(error, sqlite3.OperationalError) and "locked" in str(error).lower():
                    raise MonitoringStateStoreError("database_busy") from error
                if isinstance(error, sqlite3.Error):
                    raise MonitoringStateStoreError("database_write_failed") from error
                raise

    def computation_input(self) -> MonitoringComputationInput:
        """Return the canonical pure-function input for the retained valid batches."""

        with self._lock:
            self._require_open()
            if not self._windows:
                raise MonitoringStateEmpty("no_valid_monitoring_windows")
            observations = tuple(
                sorted(
                    (
                        observation
                        for window in self._windows
                        for observation in window.observations
                    ),
                    key=_observation_key,
                )
            )
            return MonitoringComputationInput(
                observations=observations,
                validator_account_id32=self._policy.validator_account_id32,
                scoring_policy_hash=self._policy.scoring_policy_hash,
                first_window_index=self._windows[0].window_index,
                last_window_index=self._windows[-1].window_index,
                minimum_clips_per_side_and_stratum=(
                    self._policy.minimum_clips_per_side_and_stratum
                ),
                alert_threshold=self._policy.alert_threshold,
                maximum_batches=self._policy.maximum_batches,
                publisher_sources=self._policy.publisher_sources,
                control_group_sources=self._policy.control_group_sources,
                bootstrap_replicates=self._policy.bootstrap_replicates,
            )

    def report(self) -> SourceMonitoringReport:
        """Compute the reproducible per-validator publisher/group report."""

        return self.computation_input().compute()

    def audit(self) -> MonitoringStateSnapshot:
        """Replay retained canonical windows and verify every materialized row."""

        with self._lock:
            self._require_open()
            self._begin_immediate()
            try:
                self._windows = self._audit_locked()
                snapshot = _snapshot(self._policy_bytes, self._windows)
                self._connection.commit()
                return snapshot
            except Exception:
                self._connection.rollback()
                raise

    def _configure_connection(self, busy_timeout_ms: int) -> None:
        journal_mode = self._connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]
        if str(journal_mode).lower() != "wal":
            raise MonitoringStateStoreError("wal_unavailable")
        self._connection.execute("PRAGMA synchronous = FULL")
        if int(self._connection.execute("PRAGMA synchronous").fetchone()[0]) != 2:
            raise MonitoringStateStoreError("synchronous_full_unavailable")
        self._connection.execute("PRAGMA foreign_keys = ON")
        if int(self._connection.execute("PRAGMA foreign_keys").fetchone()[0]) != 1:
            raise MonitoringStateStoreError("foreign_keys_unavailable")
        self._connection.execute(f"PRAGMA busy_timeout = {busy_timeout_ms}")
        self._connection.execute("PRAGMA trusted_schema = OFF")
        self._connection.execute("PRAGMA wal_autocheckpoint = 256")

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
        schema_digest = hashlib.sha256(
            "\n".join(statement.strip() for statement in _SCHEMA_STATEMENTS).encode("utf-8")
        ).digest()
        if version == 0 and application_id == 0 and not objects:
            for statement in _SCHEMA_STATEMENTS:
                self._connection.execute(statement)
            self._connection.executemany(
                "INSERT INTO store_meta (key, value) VALUES (?, ?)",
                (
                    ("schema_sha256", schema_digest),
                    ("policy_bytes", self._policy_bytes),
                    ("policy_sha256", hashlib.sha256(self._policy_bytes).digest()),
                ),
            )
            self._connection.execute(f"PRAGMA application_id = {_APPLICATION_ID}")
            self._connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
            self._write_head_locked(_snapshot(self._policy_bytes, ()), insert=True)
            return
        if version != _SCHEMA_VERSION or application_id != _APPLICATION_ID:
            raise MonitoringStateCorruption("schema_identity_mismatch")
        if objects != _EXPECTED_TABLES:
            raise MonitoringStateCorruption("schema_object_mismatch")
        meta = {
            str(row["key"]): bytes(row["value"])
            for row in self._connection.execute("SELECT key, value FROM store_meta ORDER BY key")
        }
        expected_meta = {
            "schema_sha256": schema_digest,
            "policy_bytes": self._policy_bytes,
            "policy_sha256": hashlib.sha256(self._policy_bytes).digest(),
        }
        if set(meta) != set(expected_meta):
            raise MonitoringStateCorruption("store_meta_mismatch")
        if meta["schema_sha256"] != schema_digest:
            raise MonitoringStateCorruption("schema_digest_mismatch")
        if (
            hashlib.sha256(meta["policy_bytes"]).digest() != meta["policy_sha256"]
            or meta["policy_bytes"] != self._policy_bytes
        ):
            raise MonitoringStateConflict("policy_mismatch")

    def _read_windows_locked(self) -> tuple[_Window, ...]:
        windows: list[_Window] = []
        rows = self._connection.execute(
            "SELECT window_index, operation_id, window_id, evidence_digest, request_bytes, "
            "request_sha256, observation_count FROM valid_windows ORDER BY window_index"
        ).fetchall()
        if len(rows) > self._policy.maximum_batches // 2:
            raise MonitoringStateCorruption("retained_window_count_limit")
        prior_index = -1
        for row in rows:
            window_index = int(row["window_index"])
            if window_index <= prior_index:
                raise MonitoringStateCorruption("valid_window_order_invalid")
            prior_index = window_index
            encoded = bytes(row["request_bytes"])
            if hashlib.sha256(encoded).digest() != bytes(row["request_sha256"]):
                raise MonitoringStateCorruption("request_digest_mismatch")
            window = _parse_request(encoded, bounds=self._bounds)
            normalized = _normalize_observations(
                window.observations,
                policy=self._policy,
                bounds=self._bounds,
            )
            if normalized != window.observations:
                raise MonitoringStateCorruption("observation_order_mismatch")
            if (
                window.window_index != window_index
                or window.operation_id != bytes(row["operation_id"])
                or window.window_id != bytes(row["window_id"])
                or window.evidence_digest != bytes(row["evidence_digest"])
                or len(window.observations) != int(row["observation_count"])
            ):
                raise MonitoringStateCorruption("window_metadata_mismatch")
            windows.append(window)
        result = tuple(windows)
        if sum(len(item.observations) for item in result) > self._bounds.maximum_observations:
            raise MonitoringStateCorruption("retained_observation_count_limit")
        return result

    def _audit_locked(self) -> tuple[_Window, ...]:
        try:
            quick_check = self._connection.execute("PRAGMA quick_check").fetchall()
            if [row[0] for row in quick_check] != ["ok"]:
                raise MonitoringStateCorruption("sqlite_quick_check_failed")
            if self._connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
                raise MonitoringStateCorruption("foreign_key_check_failed")
            windows = self._read_windows_locked()
            expected_observations = tuple(
                sorted(
                    (
                        (window.window_index, observation)
                        for window in windows
                        for observation in window.observations
                    ),
                    key=lambda item: (item[1].request_leaf, item[0]),
                )
            )
            actual_observations: list[tuple[int, SourceObservation]] = []
            for row in self._connection.execute(
                "SELECT request_leaf, window_index, pool_leaf, miner_root, publisher_hotkey, "
                "control_group_id, signer_cluster_id, stratum, score_numerator, "
                "score_denominator FROM monitoring_observations ORDER BY request_leaf"
            ):
                numerator = row["score_numerator"]
                denominator = row["score_denominator"]
                if (
                    not isinstance(numerator, str)
                    or not isinstance(denominator, str)
                    or _DECIMAL_RE.fullmatch(numerator) is None
                    or _POSITIVE_DECIMAL_RE.fullmatch(denominator) is None
                    or len(numerator.lstrip("-")) > self._bounds.maximum_fraction_decimal_digits
                    or len(denominator) > self._bounds.maximum_fraction_decimal_digits
                ):
                    raise MonitoringStateCorruption("materialized_fraction_invalid")
                score = Fraction(int(numerator), int(denominator))
                if str(score.numerator) != numerator or str(score.denominator) != denominator:
                    raise MonitoringStateCorruption("materialized_fraction_not_reduced")
                actual_observations.append(
                    (
                        int(row["window_index"]),
                        SourceObservation(
                            request_leaf=bytes(row["request_leaf"]),
                            pool_leaf=bytes(row["pool_leaf"]),
                            miner_root=bytes(row["miner_root"]),
                            publisher_hotkey=bytes(row["publisher_hotkey"]),
                            control_group_id=bytes(row["control_group_id"]),
                            signer_cluster_id=bytes(row["signer_cluster_id"]),
                            stratum=str(row["stratum"]),  # type: ignore[arg-type]
                            score=score,
                        ),
                    )
                )
            if tuple(actual_observations) != expected_observations:
                raise MonitoringStateCorruption("materialized_observations_mismatch")
            snapshot = _snapshot(self._policy_bytes, windows)
            rows = self._connection.execute("SELECT * FROM current_head").fetchall()
            if len(rows) != 1:
                raise MonitoringStateCorruption("current_head_invalid")
            head = rows[0]
            expected_head = (
                1,
                snapshot.first_window_index,
                snapshot.last_window_index,
                snapshot.last_window_id,
                snapshot.valid_window_count,
                snapshot.batch_count,
                snapshot.observation_count,
                snapshot.state_digest,
            )
            if tuple(head) != expected_head:
                raise MonitoringStateCorruption("current_head_mismatch")
            return windows
        except MonitoringStateStoreError:
            raise
        except (OverflowError, TypeError, ValueError, sqlite3.Error) as error:
            raise MonitoringStateCorruption("operation_log_decode_failed") from error

    def _write_head_locked(
        self,
        snapshot: MonitoringStateSnapshot,
        *,
        insert: bool = False,
    ) -> None:
        values = (
            snapshot.first_window_index,
            snapshot.last_window_index,
            snapshot.last_window_id,
            snapshot.valid_window_count,
            snapshot.batch_count,
            snapshot.observation_count,
            snapshot.state_digest,
        )
        if insert:
            self._connection.execute(
                "INSERT INTO current_head ("
                "singleton, first_window_index, last_window_index, last_window_id, "
                "valid_window_count, batch_count, observation_count, state_digest"
                ") VALUES (1, ?, ?, ?, ?, ?, ?, ?)",
                values,
            )
        else:
            self._connection.execute(
                "UPDATE current_head SET first_window_index = ?, last_window_index = ?, "
                "last_window_id = ?, valid_window_count = ?, batch_count = ?, "
                "observation_count = ?, state_digest = ? WHERE singleton = 1",
                values,
            )

    def _begin_immediate(self) -> None:
        try:
            self._connection.execute("BEGIN IMMEDIATE")
        except sqlite3.OperationalError as error:
            if "locked" in str(error).lower():
                raise MonitoringStateStoreError("database_busy") from error
            raise

    def _require_open(self) -> None:
        if self._closed:
            raise MonitoringStateStoreError("store_closed")

    def _close_after_failed_init(self) -> None:
        connection = getattr(self, "_connection", None)
        if connection is not None:
            with suppress(sqlite3.Error):
                connection.close()
        self._closed = True

    @classmethod
    def _prepare_database_path(cls, path: Path) -> Path:
        if not path.is_absolute():
            raise ValueError("database_path must be absolute")
        try:
            parent_metadata = path.parent.lstat()
            if stat.S_ISLNK(parent_metadata.st_mode):
                raise MonitoringStateStoreError("unsafe_database_parent")
            parent = path.parent.resolve(strict=True)
            parent_metadata = parent.stat()
        except MonitoringStateStoreError:
            raise
        except OSError as error:
            raise MonitoringStateStoreError("database_parent_unavailable") from error
        if not stat.S_ISDIR(parent_metadata.st_mode) or parent_metadata.st_mode & 0o022:
            raise MonitoringStateStoreError("unsafe_database_parent")
        if hasattr(os, "getuid") and parent_metadata.st_uid != os.getuid():
            raise MonitoringStateStoreError("unsafe_database_parent")
        resolved = parent / path.name
        cls._assert_path_safe(resolved, allow_missing=True)
        for suffix in ("-wal", "-shm", "-journal"):
            cls._assert_path_safe(Path(os.fspath(resolved) + suffix), allow_missing=True)
        if not resolved.exists():
            flags = os.O_CREAT | os.O_EXCL | os.O_RDWR
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                descriptor = os.open(resolved, flags, 0o600)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                parent_flags = os.O_RDONLY
                if hasattr(os, "O_DIRECTORY"):
                    parent_flags |= os.O_DIRECTORY
                parent_descriptor = os.open(parent, parent_flags)
                try:
                    os.fsync(parent_descriptor)
                finally:
                    os.close(parent_descriptor)
            except OSError as error:
                raise MonitoringStateStoreError("database_create_failed") from error
        cls._assert_path_safe(resolved, allow_missing=False)
        return resolved

    @classmethod
    def _assert_path_safe(cls, path: Path, *, allow_missing: bool) -> None:
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            if allow_missing:
                return
            raise MonitoringStateStoreError("database_file_missing") from None
        except OSError as error:
            raise MonitoringStateStoreError("database_file_unavailable") from error
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_mode & 0o022
            or metadata.st_nlink != 1
        ):
            raise MonitoringStateStoreError("unsafe_database_file")
        if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
            raise MonitoringStateStoreError("unsafe_database_file")

    def _assert_safe_database_files(self) -> None:
        self._assert_path_safe(self._path, allow_missing=False)
        for suffix in ("-wal", "-shm"):
            self._assert_path_safe(Path(os.fspath(self._path) + suffix), allow_missing=True)


__all__ = [
    "MONITORING_POLICY_SCHEMA",
    "MONITORING_WINDOW_SCHEMA",
    "AppliedMonitoringWindow",
    "MonitoringBatchSource",
    "MonitoringComputationInput",
    "MonitoringSignerCluster",
    "MonitoringStateBounds",
    "MonitoringStateConflict",
    "MonitoringStateCorruption",
    "MonitoringStateEmpty",
    "MonitoringStateLimitError",
    "MonitoringStatePolicy",
    "MonitoringStateSnapshot",
    "MonitoringStateStoreError",
    "ValidatorMonitoringStateStore",
    "source_observations_from_scored_batches",
]
