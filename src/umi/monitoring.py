"""Deterministic source-conditioned shadow monitoring.

The launch metric never changes a score, denominator, registry, or weight.  It
only measures whether a miner performs unusually well on clips from one
publisher or control group.  All arithmetic is exact and the signer-cluster
bootstrap is driven by a domain-separated SHA-256 stream, so an auditor can
reproduce the interval without a platform PRNG.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from fractions import Fraction
from typing import Literal

from .encoding import account_id32, raw_sha256, u32be, u64be
from .protocol import canonical_json_bytes

SourceKind = Literal["publisher", "control_group"]
Stratum = Literal["fingerspelling", "short_utterance", "continuous"]

SOURCE_MONITORING_SCHEMA = "umi-source-monitoring/1"
BOOTSTRAP_PROFILE = "umi-signer-cluster-bootstrap-sha256/1"
BOOTSTRAP_REPLICATES = 4_096
CONFIDENCE_LEVEL = Fraction(95, 100)
MAX_MONITORING_OBSERVATIONS = 262_144
MAX_MONITORED_MINERS = 4_096
MAX_MONITORED_SOURCES_PER_KIND = 256

_STRATA: tuple[Stratum, ...] = (
    "fingerspelling",
    "short_utterance",
    "continuous",
)
_STRATUM_WEIGHTS: Mapping[Stratum, Fraction] = {
    "fingerspelling": Fraction(3, 20),
    "short_utterance": Fraction(7, 20),
    "continuous": Fraction(1, 2),
}
_BOOTSTRAP_DOMAIN = b"umi-source-bootstrap-v1\0"
_SEED_DOMAIN = b"umi-source-bootstrap-seed-v1\0"


def _unit_fraction(value: Fraction, *, label: str) -> Fraction:
    if not isinstance(value, Fraction):
        raise TypeError(f"{label} must be Fraction")
    if not 0 <= value <= 1:
        raise ValueError(f"{label} must be in the unit interval")
    return value


@dataclass(frozen=True, slots=True)
class SourceObservation:
    """One emission-bearing assignment used only by shadow monitoring."""

    request_leaf: bytes
    pool_leaf: bytes
    miner_root: bytes
    publisher_hotkey: bytes
    control_group_id: bytes
    signer_cluster_id: bytes
    stratum: Stratum
    score: Fraction

    def __post_init__(self) -> None:
        for name in ("request_leaf", "pool_leaf", "control_group_id", "signer_cluster_id"):
            raw_sha256(getattr(self, name), field=name.replace("_", " "))
        account_id32(self.miner_root)
        account_id32(self.publisher_hotkey)
        if self.stratum not in _STRATA:
            raise ValueError("source observation has an unsupported stratum")
        _unit_fraction(self.score, label="source observation score")


@dataclass(frozen=True, slots=True)
class ComponentEffect:
    stratum: Stratum
    source_count: int
    outside_count: int
    source_signer_clusters: int
    outside_signer_clusters: int
    source_mean: Fraction | None
    outside_mean: Fraction | None
    difference: Fraction | None


@dataclass(frozen=True, slots=True)
class SourceEffect:
    source_kind: SourceKind
    source_id: bytes
    miner_root: bytes
    eligible: bool
    components: tuple[ComponentEffect, ...]
    aggregate_effect: Fraction | None
    interval_lower: Fraction | None
    interval_upper: Fraction | None
    alert: bool

    def __post_init__(self) -> None:
        if self.source_kind not in {"publisher", "control_group"}:
            raise ValueError("source kind is unsupported")
        raw_sha256(self.source_id, field="source ID")
        account_id32(self.miner_root)
        if tuple(component.stratum for component in self.components) != _STRATA:
            raise ValueError("source-effect components are not in canonical stratum order")
        values = (self.aggregate_effect, self.interval_lower, self.interval_upper)
        if self.eligible != all(value is not None for value in values):
            raise ValueError("source-effect eligibility and aggregate fields disagree")
        if not self.eligible and self.alert:
            raise ValueError("an ineligible source effect cannot alert")
        if self.eligible and not self.interval_lower <= self.interval_upper:  # type: ignore[operator]
            raise ValueError("source-effect bootstrap interval is reversed")


@dataclass(frozen=True, slots=True)
class SourceMonitoringReport:
    validator_account_id32: bytes
    scoring_policy_hash: bytes
    first_window_index: int
    last_window_index: int
    minimum_clips_per_side_and_stratum: int
    alert_threshold: Fraction
    observation_count: int
    batch_count: int
    publisher_sources: tuple[bytes, ...]
    control_group_sources: tuple[bytes, ...]
    observation_sha256: bytes
    effects: tuple[SourceEffect, ...]
    report_bytes: bytes
    report_sha256: bytes

    def __post_init__(self) -> None:
        account_id32(self.validator_account_id32)
        raw_sha256(self.scoring_policy_hash, field="scoring policy hash")
        raw_sha256(self.observation_sha256, field="observation digest")
        raw_sha256(self.report_sha256, field="report digest")
        if self.first_window_index < 0 or self.last_window_index < self.first_window_index:
            raise ValueError("source-monitoring window range is invalid")
        if self.minimum_clips_per_side_and_stratum <= 0:
            raise ValueError("source-monitoring minimum sample must be positive")
        _unit_fraction(self.alert_threshold, label="source divergence alert threshold")
        if self.observation_count <= 0 or self.batch_count <= 0:
            raise ValueError("source monitoring requires observations and batches")
        for label, sources in (
            ("publisher", self.publisher_sources),
            ("control-group", self.control_group_sources),
        ):
            if not sources or sources != tuple(sorted(set(sources))):
                raise ValueError(f"{label} source registry must be nonempty, sorted, and unique")
            for source in sources:
                raw_sha256(source, field=f"{label} source")
        if hashlib.sha256(self.report_bytes).digest() != self.report_sha256:
            raise ValueError("source-monitoring report digest does not reproduce")


def compute_source_monitoring(
    observations: Sequence[SourceObservation],
    *,
    validator_hotkey: str | bytes,
    scoring_policy_hash: str | bytes,
    first_window_index: int,
    last_window_index: int,
    minimum_clips_per_side_and_stratum: int,
    alert_threshold: Fraction,
    maximum_batches: int,
    publisher_sources: Sequence[str | bytes],
    control_group_sources: Sequence[str | bytes],
    bootstrap_replicates: int = BOOTSTRAP_REPLICATES,
) -> SourceMonitoringReport:
    """Compute every publisher- and group-conditioned local validator effect."""

    if isinstance(observations, (bytes, bytearray, str)) or not isinstance(observations, Sequence):
        raise TypeError("source observations must be a sequence")
    values = tuple(observations)
    if not values or any(not isinstance(item, SourceObservation) for item in values):
        raise ValueError("source observations must contain SourceObservation values")
    if len(values) > MAX_MONITORING_OBSERVATIONS:
        raise ValueError("source observations exceed the hard count ceiling")
    if first_window_index < 0 or last_window_index < first_window_index:
        raise ValueError("source-monitoring window range is invalid")
    for name, value in (
        ("minimum_clips_per_side_and_stratum", minimum_clips_per_side_and_stratum),
        ("maximum_batches", maximum_batches),
        ("bootstrap_replicates", bootstrap_replicates),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError(f"{name} must be a positive integer")
    if bootstrap_replicates > 65_536:
        raise ValueError("bootstrap replicate count exceeds its hard ceiling")
    threshold = _unit_fraction(alert_threshold, label="source divergence alert threshold")
    validator = account_id32(validator_hotkey)
    policy_hash = raw_sha256(scoring_policy_hash, field="scoring policy hash")
    publishers = _source_registry(
        publisher_sources,
        label="publisher",
        account_sources=True,
    )
    control_groups = _source_registry(
        control_group_sources,
        label="control-group",
        account_sources=False,
    )

    ordered = tuple(sorted(values, key=_observation_key))
    request_leaves = tuple(item.request_leaf for item in ordered)
    if len(set(request_leaves)) != len(request_leaves):
        raise ValueError("source observations contain a duplicate request leaf")
    batch_count = len({item.pool_leaf for item in ordered})
    if batch_count > maximum_batches:
        raise ValueError("source observations exceed the monitoring batch window")
    encoded_observations = canonical_json_bytes([_observation_object(item) for item in ordered])
    observation_digest = hashlib.sha256(encoded_observations).digest()
    if any(item.publisher_hotkey not in publishers for item in ordered):
        raise ValueError("source observation references an undeclared publisher")
    if any(item.control_group_id not in control_groups for item in ordered):
        raise ValueError("source observation references an undeclared control group")

    effects: list[SourceEffect] = []
    miners = sorted({item.miner_root for item in ordered})
    if len(miners) > MAX_MONITORED_MINERS:
        raise ValueError("source observations exceed the monitored-miner ceiling")
    sources: tuple[tuple[SourceKind, bytes], ...] = tuple(
        [("publisher", value) for value in publishers]
        + [("control_group", value) for value in control_groups]
    )
    for source_kind, source_id in sources:
        for miner_root in miners:
            miner_observations = tuple(item for item in ordered if item.miner_root == miner_root)
            effects.append(
                _source_effect(
                    miner_observations,
                    source_kind=source_kind,
                    source_id=source_id,
                    miner_root=miner_root,
                    policy_hash=policy_hash,
                    validator=validator,
                    observation_digest=observation_digest,
                    minimum=minimum_clips_per_side_and_stratum,
                    alert_threshold=threshold,
                    bootstrap_replicates=bootstrap_replicates,
                )
            )
    effect_tuple = tuple(effects)
    body = {
        "schema": SOURCE_MONITORING_SCHEMA,
        "validator_account_id32": validator.hex(),
        "scoring_policy_hash": policy_hash.hex(),
        "first_window_index": first_window_index,
        "last_window_index": last_window_index,
        "minimum_clips_per_side_and_stratum": minimum_clips_per_side_and_stratum,
        "alert_threshold": _fraction_object(threshold),
        "bootstrap": {
            "profile": BOOTSTRAP_PROFILE,
            "replicates": bootstrap_replicates,
            "confidence_level": _fraction_object(CONFIDENCE_LEVEL),
        },
        "observation_count": len(ordered),
        "batch_count": batch_count,
        "publisher_sources": [source.hex() for source in publishers],
        "control_group_sources": [source.hex() for source in control_groups],
        "observation_sha256": observation_digest.hex(),
        "effects": [_effect_object(effect) for effect in effect_tuple],
    }
    report_bytes = canonical_json_bytes(body)
    return SourceMonitoringReport(
        validator_account_id32=validator,
        scoring_policy_hash=policy_hash,
        first_window_index=first_window_index,
        last_window_index=last_window_index,
        minimum_clips_per_side_and_stratum=minimum_clips_per_side_and_stratum,
        alert_threshold=threshold,
        observation_count=len(ordered),
        batch_count=batch_count,
        publisher_sources=publishers,
        control_group_sources=control_groups,
        observation_sha256=observation_digest,
        effects=effect_tuple,
        report_bytes=report_bytes,
        report_sha256=hashlib.sha256(report_bytes).digest(),
    )


def _source_effect(
    observations: tuple[SourceObservation, ...],
    *,
    source_kind: SourceKind,
    source_id: bytes,
    miner_root: bytes,
    policy_hash: bytes,
    validator: bytes,
    observation_digest: bytes,
    minimum: int,
    alert_threshold: Fraction,
    bootstrap_replicates: int,
) -> SourceEffect:
    components: list[ComponentEffect] = []
    groups: dict[tuple[Stratum, bool], tuple[SourceObservation, ...]] = {}
    for stratum in _STRATA:
        inside = tuple(
            item
            for item in observations
            if item.stratum == stratum and _matches_source(item, source_kind, source_id)
        )
        outside = tuple(
            item
            for item in observations
            if item.stratum == stratum and not _matches_source(item, source_kind, source_id)
        )
        groups[(stratum, True)] = inside
        groups[(stratum, False)] = outside
        eligible = len(inside) >= minimum and len(outside) >= minimum
        source_mean = _mean(item.score for item in inside) if eligible else None
        outside_mean = _mean(item.score for item in outside) if eligible else None
        components.append(
            ComponentEffect(
                stratum=stratum,
                source_count=len(inside),
                outside_count=len(outside),
                source_signer_clusters=len({item.signer_cluster_id for item in inside}),
                outside_signer_clusters=len({item.signer_cluster_id for item in outside}),
                source_mean=source_mean,
                outside_mean=outside_mean,
                difference=(
                    source_mean - outside_mean
                    if source_mean is not None and outside_mean is not None
                    else None
                ),
            )
        )
    component_tuple = tuple(components)
    eligible = all(component.difference is not None for component in component_tuple)
    if not eligible:
        return SourceEffect(
            source_kind=source_kind,
            source_id=source_id,
            miner_root=miner_root,
            eligible=False,
            components=component_tuple,
            aggregate_effect=None,
            interval_lower=None,
            interval_upper=None,
            alert=False,
        )

    aggregate = sum(
        (_STRATUM_WEIGHTS[item.stratum] * item.difference for item in component_tuple),
        start=Fraction(0),
    )
    seed = hashlib.sha256(
        _SEED_DOMAIN
        + policy_hash
        + validator
        + source_kind.encode("ascii")
        + source_id
        + miner_root
        + observation_digest
    ).digest()
    replicates = [
        _bootstrap_effect(groups, seed=seed, replicate=index)
        for index in range(bootstrap_replicates)
    ]
    replicates.sort()
    tail = (Fraction(1) - CONFIDENCE_LEVEL) / 2
    lower = _nearest_rank(replicates, tail)
    upper = _nearest_rank(replicates, Fraction(1) - tail)
    return SourceEffect(
        source_kind=source_kind,
        source_id=source_id,
        miner_root=miner_root,
        eligible=True,
        components=component_tuple,
        aggregate_effect=aggregate,
        interval_lower=lower,
        interval_upper=upper,
        alert=lower > alert_threshold,
    )


def _bootstrap_effect(
    groups: Mapping[tuple[Stratum, bool], tuple[SourceObservation, ...]],
    *,
    seed: bytes,
    replicate: int,
) -> Fraction:
    aggregate = Fraction(0)
    for stratum_index, stratum in enumerate(_STRATA):
        means: list[Fraction] = []
        for side_index, inside in enumerate((True, False)):
            by_cluster: dict[bytes, list[Fraction]] = defaultdict(list)
            for item in groups[(stratum, inside)]:
                by_cluster[item.signer_cluster_id].append(item.score)
            cluster_ids = sorted(by_cluster)
            sampled: list[Fraction] = []
            for draw in range(len(cluster_ids)):
                index = _uniform_index(
                    len(cluster_ids),
                    seed=seed,
                    replicate=replicate,
                    stratum_index=stratum_index,
                    side_index=side_index,
                    draw=draw,
                )
                sampled.extend(by_cluster[cluster_ids[index]])
            means.append(_mean(sampled))
        aggregate += _STRATUM_WEIGHTS[stratum] * (means[0] - means[1])
    return aggregate


def _uniform_index(
    size: int,
    *,
    seed: bytes,
    replicate: int,
    stratum_index: int,
    side_index: int,
    draw: int,
) -> int:
    if size <= 0:
        raise ValueError("bootstrap source side has no signer clusters")
    ceiling = (1 << 256) - ((1 << 256) % size)
    counter = 0
    while True:
        candidate = int.from_bytes(
            hashlib.sha256(
                _BOOTSTRAP_DOMAIN
                + seed
                + u64be(replicate)
                + u32be(stratum_index)
                + u32be(side_index)
                + u64be(draw)
                + u32be(counter)
            ).digest(),
            "big",
        )
        if candidate < ceiling:
            return candidate % size
        counter += 1


def _nearest_rank(values: Sequence[Fraction], percentile: Fraction) -> Fraction:
    if not values:
        raise ValueError("nearest-rank percentile requires values")
    if not 0 < percentile <= 1:
        raise ValueError("nearest-rank percentile must be in (0, 1]")
    rank = max(
        1,
        (percentile.numerator * len(values) + percentile.denominator - 1) // percentile.denominator,
    )
    return values[rank - 1]


def _source_registry(
    values: Sequence[str | bytes],
    *,
    label: str,
    account_sources: bool,
) -> tuple[bytes, ...]:
    if isinstance(values, (str, bytes, bytearray)) or not isinstance(values, Sequence):
        raise TypeError(f"{label} source registry must be a sequence")
    converter = account_id32 if account_sources else raw_sha256
    sources = tuple(converter(value) for value in values)
    if not sources or sources != tuple(sorted(set(sources))):
        raise ValueError(f"{label} source registry must be nonempty, sorted, and unique")
    if len(sources) > MAX_MONITORED_SOURCES_PER_KIND:
        raise ValueError(f"{label} source registry exceeds its hard count ceiling")
    return sources


def _mean(values: Iterable[Fraction]) -> Fraction:
    material = tuple(values)
    if not material:
        raise ValueError("mean requires at least one value")
    return sum(material, start=Fraction(0)) / len(material)


def _matches_source(
    observation: SourceObservation,
    source_kind: SourceKind,
    source_id: bytes,
) -> bool:
    return (
        observation.publisher_hotkey == source_id
        if source_kind == "publisher"
        else observation.control_group_id == source_id
    )


def _observation_key(value: SourceObservation) -> tuple[bytes, ...]:
    return (
        value.miner_root,
        value.publisher_hotkey,
        value.control_group_id,
        value.pool_leaf,
        value.request_leaf,
    )


def _fraction_object(value: Fraction | None) -> dict[str, str] | None:
    if value is None:
        return None
    return {"numerator": str(value.numerator), "denominator": str(value.denominator)}


def _observation_object(value: SourceObservation) -> dict[str, object]:
    return {
        "request_leaf": value.request_leaf.hex(),
        "pool_leaf": value.pool_leaf.hex(),
        "miner_root": value.miner_root.hex(),
        "publisher_hotkey": value.publisher_hotkey.hex(),
        "control_group_id": value.control_group_id.hex(),
        "signer_cluster_id": value.signer_cluster_id.hex(),
        "stratum": value.stratum,
        "score": _fraction_object(value.score),
    }


def _component_object(value: ComponentEffect) -> dict[str, object]:
    return {
        "stratum": value.stratum,
        "source_count": value.source_count,
        "outside_count": value.outside_count,
        "source_signer_clusters": value.source_signer_clusters,
        "outside_signer_clusters": value.outside_signer_clusters,
        "source_mean": _fraction_object(value.source_mean),
        "outside_mean": _fraction_object(value.outside_mean),
        "difference": _fraction_object(value.difference),
    }


def _effect_object(value: SourceEffect) -> dict[str, object]:
    return {
        "source_kind": value.source_kind,
        "source_id": value.source_id.hex(),
        "miner_root": value.miner_root.hex(),
        "eligible": value.eligible,
        "components": [_component_object(item) for item in value.components],
        "aggregate_effect": _fraction_object(value.aggregate_effect),
        "interval_lower": _fraction_object(value.interval_lower),
        "interval_upper": _fraction_object(value.interval_upper),
        "alert": value.alert,
    }


__all__ = [
    "BOOTSTRAP_PROFILE",
    "BOOTSTRAP_REPLICATES",
    "CONFIDENCE_LEVEL",
    "MAX_MONITORED_MINERS",
    "MAX_MONITORED_SOURCES_PER_KIND",
    "MAX_MONITORING_OBSERVATIONS",
    "SOURCE_MONITORING_SCHEMA",
    "ComponentEffect",
    "SourceEffect",
    "SourceMonitoringReport",
    "SourceObservation",
    "compute_source_monitoring",
]
