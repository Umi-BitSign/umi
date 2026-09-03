from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import replace
from fractions import Fraction
from pathlib import Path

import pytest

from umi.monitoring import SourceObservation, compute_source_monitoring
from umi.protocol import base64url_encode
from umi.rolling import AssignmentScore, ScoredBatch
from umi.validator_monitoring_state import (
    MonitoringBatchSource,
    MonitoringSignerCluster,
    MonitoringStateBounds,
    MonitoringStateConflict,
    MonitoringStateCorruption,
    MonitoringStateEmpty,
    MonitoringStateLimitError,
    MonitoringStatePolicy,
    MonitoringStateStoreError,
    ValidatorMonitoringStateStore,
    source_observations_from_scored_batches,
)


def _hash(label: str) -> bytes:
    return hashlib.sha256(label.encode()).digest()


PUBLISHERS = tuple(sorted((_hash("publisher-a"), _hash("publisher-b"), _hash("publisher-c"))))
GROUPS = tuple(sorted((_hash("group-a"), _hash("group-b"), _hash("group-c"))))
VALIDATOR = _hash("validator")
POLICY_HASH = _hash("policy")
MINER_A = _hash("miner-a")
MINER_B = _hash("miner-b")
STRATA = ("fingerspelling", "short_utterance", "continuous")


def _policy(*, maximum_batches: int = 4) -> MonitoringStatePolicy:
    return MonitoringStatePolicy(
        validator_account_id32=VALIDATOR,
        scoring_policy_hash=POLICY_HASH,
        maximum_batches=maximum_batches,
        minimum_clips_per_side_and_stratum=1,
        alert_threshold=Fraction(3, 20),
        publisher_sources=PUBLISHERS,
        control_group_sources=GROUPS,
        publisher_control_groups=tuple(zip(PUBLISHERS, GROUPS, strict=True)),
        bootstrap_replicates=32,
    )


def _source_pair() -> tuple[tuple[bytes, bytes], tuple[bytes, bytes]]:
    return ((PUBLISHERS[0], GROUPS[0]), (PUBLISHERS[1], GROUPS[1]))


def _observations(
    window_index: int,
    *,
    miners: tuple[bytes, ...] = (MINER_A,),
    sources: tuple[tuple[bytes, bytes], tuple[bytes, bytes]] | None = None,
    pool_suffix: str = "",
) -> tuple[SourceObservation, ...]:
    values: list[SourceObservation] = []
    source_values = sources or _source_pair()
    for pool_ordinal, (publisher, group) in enumerate(source_values):
        pool = _hash(f"pool-{window_index}-{pool_ordinal}{pool_suffix}")
        score = Fraction(1) if pool_ordinal == 0 else Fraction(0)
        for miner in miners:
            for stratum_ordinal, stratum in enumerate(STRATA):
                values.append(
                    SourceObservation(
                        request_leaf=_hash(
                            f"request-{window_index}-{pool_ordinal}-"
                            f"{miner.hex()}-{stratum_ordinal}{pool_suffix}"
                        ),
                        pool_leaf=pool,
                        miner_root=miner,
                        publisher_hotkey=publisher,
                        control_group_id=group,
                        signer_cluster_id=_hash(f"signer-{pool_ordinal}-{stratum_ordinal}"),
                        stratum=stratum,  # type: ignore[arg-type]
                        score=score,
                    )
                )
    return tuple(reversed(values))


def _kwargs(window_index: int, **overrides: object) -> dict[str, object]:
    result: dict[str, object] = {
        "operation_id": _hash(f"operation-{window_index}"),
        "window_index": window_index,
        "window_id": _hash(f"window-{window_index}"),
        "evidence_digest": _hash(f"evidence-{window_index}"),
        "valid_window": True,
        "observations": _observations(window_index),
    }
    result.update(overrides)
    return result


def _database_path(tmp_path: Path, name: str = "monitoring.sqlite3") -> Path:
    return (tmp_path / name).resolve()


def _scored_batches(window_index: int = 0) -> tuple[ScoredBatch, ScoredBatch]:
    miners = tuple(sorted((MINER_A, MINER_B)))
    results: list[ScoredBatch] = []
    for pool_ordinal in range(2):
        challenge_bytes = tuple(
            window_index.to_bytes(8, "big")
            + pool_ordinal.to_bytes(4, "big")
            + ordinal.to_bytes(4, "big")
            for ordinal in range(4)
        )
        challenge_ids = tuple(base64url_encode(value) for value in challenge_bytes)
        assignments = tuple(
            AssignmentScore(
                miner_root=miner,
                challenge_id=challenge_ids[ordinal],
                request_leaf=hashlib.sha256(
                    b"scored-request\0" + miner + challenge_bytes[ordinal]
                ).digest(),
                stratum=(STRATA[ordinal] if ordinal < 3 else "continuous"),  # type: ignore[arg-type]
                canary=ordinal == 3,
                score=(None if ordinal == 3 else Fraction(1 if pool_ordinal == 0 else 0)),
            )
            for miner in miners
            for ordinal in range(4)
        )
        results.append(
            ScoredBatch(
                window_index=window_index,
                batch_rank=bytes([pool_ordinal + 1]) * 32,
                pool_leaf=_hash(f"scored-pool-{window_index}-{pool_ordinal}"),
                challenge_ids=challenge_ids,
                miner_roots=miners,
                assignments=assignments,
            )
        )
    return results[0], results[1]


def _scored_metadata(
    batches: tuple[ScoredBatch, ScoredBatch],
) -> tuple[
    tuple[MonitoringBatchSource, MonitoringBatchSource],
    tuple[MonitoringSignerCluster, ...],
]:
    source_pair = _source_pair()
    sources = tuple(
        sorted(
            (
                MonitoringBatchSource(
                    pool_leaf=batch.pool_leaf,
                    publisher_hotkey=source_pair[ordinal][0],
                    control_group_id=source_pair[ordinal][1],
                )
                for ordinal, batch in enumerate(batches)
            ),
            key=lambda value: value.pool,
        )
    )
    clusters = tuple(
        sorted(
            (
                MonitoringSignerCluster(
                    request_leaf=assignment.leaf,
                    signer_cluster_id=_hash(f"cluster-{pool_ordinal}-{assignment.challenge_id}"),
                )
                for pool_ordinal, batch in enumerate(batches)
                for assignment in batch.assignments
                if not assignment.canary
            ),
            key=lambda value: value.leaf,
        )
    )
    return sources, clusters  # type: ignore[return-value]


def test_scored_batch_adapter_is_complete_and_excludes_canaries() -> None:
    batches = _scored_batches()
    sources, clusters = _scored_metadata(batches)
    observations = source_observations_from_scored_batches(
        batches,
        batch_sources=sources,
        signer_clusters=clusters,
    )
    assert len(observations) == 12
    assert {item.score for item in observations} == {Fraction(0), Fraction(1)}
    canary_leaves = {
        assignment.leaf
        for batch in batches
        for assignment in batch.assignments
        if assignment.canary
    }
    assert not canary_leaves.intersection(item.request_leaf for item in observations)

    with pytest.raises(ValueError, match="every non-canary assignment exactly"):
        source_observations_from_scored_batches(
            batches,
            batch_sources=sources,
            signer_clusters=clusters[:-1],
        )

    first_challenge = batches[0].challenge_ids[0]
    leaves = {
        assignment.leaf
        for assignment in batches[0].assignments
        if assignment.challenge_id == first_challenge
    }
    changed_leaf = max(leaves)
    inconsistent = tuple(
        replace(value, signer_cluster_id=_hash("wrong-cluster"))
        if value.leaf == changed_leaf
        else value
        for value in clusters
    )
    with pytest.raises(ValueError, match="inconsistent signer clusters"):
        source_observations_from_scored_batches(
            batches,
            batch_sources=sources,
            signer_clusters=inconsistent,
        )


def test_valid_windows_report_exactly_and_survive_restart(tmp_path: Path) -> None:
    path = _database_path(tmp_path)
    with ValidatorMonitoringStateStore(path, policy=_policy()) as store:
        assert store.snapshot.valid_window_count == 0
        with pytest.raises(MonitoringStateEmpty) as empty:
            store.report()
        assert empty.value.reason_code == "no_valid_monitoring_windows"

        applied = store.apply_window(**_kwargs(0))
        assert applied.idempotent is False
        assert applied.snapshot.first_window_index == 0
        assert applied.snapshot.last_window_index == 0
        assert applied.snapshot.batch_count == 2
        assert applied.snapshot.observation_count == 6

        computation = store.computation_input()
        report = store.report()
        direct = compute_source_monitoring(
            computation.observations,
            validator_hotkey=VALIDATOR,
            scoring_policy_hash=POLICY_HASH,
            first_window_index=0,
            last_window_index=0,
            minimum_clips_per_side_and_stratum=1,
            alert_threshold=Fraction(3, 20),
            maximum_batches=4,
            publisher_sources=PUBLISHERS,
            control_group_sources=GROUPS,
            bootstrap_replicates=32,
        )
        assert report.report_bytes == direct.report_bytes
        high = next(
            effect
            for effect in report.effects
            if effect.source_kind == "publisher" and effect.source_id == PUBLISHERS[0]
        )
        assert high.aggregate_effect == 1
        assert high.interval_lower == 1
        assert high.alert is True
        first_digest = store.snapshot.state_digest

    with ValidatorMonitoringStateStore(path, policy=_policy()) as recovered:
        assert recovered.audit().state_digest == first_digest
        assert recovered.report().report_bytes == report.report_bytes


def test_only_literal_valid_window_can_mutate_state(tmp_path: Path) -> None:
    with ValidatorMonitoringStateStore(_database_path(tmp_path), policy=_policy()) as store:
        for value in (False, 1, None):
            kwargs = _kwargs(0, valid_window=value)
            with pytest.raises(ValueError, match="protocol-valid"):
                store.apply_window(**kwargs)  # type: ignore[arg-type]
        assert store.snapshot.valid_window_count == 0


def test_idempotency_conflicts_and_monotonic_valid_indices(tmp_path: Path) -> None:
    with ValidatorMonitoringStateStore(_database_path(tmp_path), policy=_policy()) as store:
        first = store.apply_window(**_kwargs(0))
        replay = store.apply_window(**_kwargs(0))
        assert replay.idempotent is True
        assert replay.request_bytes == first.request_bytes

        conflicting = _kwargs(0, window_id=_hash("different-window"))
        with pytest.raises(MonitoringStateConflict) as operation_conflict:
            store.apply_window(**conflicting)
        assert operation_conflict.value.reason_code == "operation_id_conflict"

        store.apply_window(**_kwargs(2))
        with pytest.raises(MonitoringStateConflict) as stale:
            store.apply_window(**_kwargs(1))
        assert stale.value.reason_code == "stale_or_conflicting_window"


def test_queue_retains_exact_latest_policy_batch_count(tmp_path: Path) -> None:
    path = _database_path(tmp_path)
    with ValidatorMonitoringStateStore(path, policy=_policy(maximum_batches=4)) as store:
        store.apply_window(**_kwargs(0))
        store.apply_window(**_kwargs(3))
        result = store.apply_window(**_kwargs(9))
        assert result.snapshot.first_window_index == 3
        assert result.snapshot.last_window_index == 9
        assert result.snapshot.valid_window_count == 2
        assert result.snapshot.batch_count == 4
        assert result.snapshot.observation_count == 12
        assert store.report().first_window_index == 3
        assert store.report().last_window_index == 9

    connection = sqlite3.connect(path)
    try:
        assert connection.execute("SELECT COUNT(*) FROM valid_windows").fetchone()[0] == 2
        assert (
            connection.execute("SELECT COUNT(*) FROM monitoring_observations").fetchone()[0] == 12
        )
    finally:
        connection.close()


def test_launch_window_retains_exactly_twelve_latest_valid_batches(tmp_path: Path) -> None:
    path = _database_path(tmp_path)
    with ValidatorMonitoringStateStore(path, policy=_policy(maximum_batches=12)) as store:
        for index in range(7):
            store.apply_window(**_kwargs(index))
        snapshot = store.snapshot
        assert snapshot.first_window_index == 1
        assert snapshot.last_window_index == 6
        assert snapshot.valid_window_count == 6
        assert snapshot.batch_count == 12
        assert snapshot.observation_count == 36
        assert store.computation_input().maximum_batches == 12


def test_window_validation_rejects_partial_or_inconsistent_evidence(tmp_path: Path) -> None:
    with ValidatorMonitoringStateStore(_database_path(tmp_path), policy=_policy()) as store:
        values = _observations(0)
        with pytest.raises(ValueError, match="partial miner batch"):
            store.apply_window(**_kwargs(0, observations=values[:-1]))

        uneven_panel = _observations(0) + tuple(
            item
            for item in _observations(0, miners=(MINER_B,), pool_suffix="-other")
            if item.pool_leaf == _hash("pool-0-0-other")
        )
        with pytest.raises(ValueError, match="exactly two batches"):
            store.apply_window(**_kwargs(0, observations=uneven_panel))

        same_group_sources = (
            (PUBLISHERS[0], GROUPS[0]),
            (PUBLISHERS[1], GROUPS[0]),
        )
        with pytest.raises(ValueError, match="policy control group"):
            store.apply_window(
                **_kwargs(0, observations=_observations(0, sources=same_group_sources))
            )

        undeclared = replace(values[0], publisher_hotkey=PUBLISHERS[2][::-1])
        with pytest.raises(ValueError, match="undeclared publisher"):
            store.apply_window(**_kwargs(0, observations=(undeclared, *values[1:])))
        assert store.snapshot.valid_window_count == 0


def test_same_panel_is_required_across_selected_batches(tmp_path: Path) -> None:
    values = list(_observations(0, miners=(MINER_A, MINER_B)))
    second_pool = _hash("pool-0-1")
    values = [
        item
        for item in values
        if not (item.pool_leaf == second_pool and item.miner_root == MINER_B)
    ]
    with (
        ValidatorMonitoringStateStore(_database_path(tmp_path), policy=_policy()) as store,
        pytest.raises(ValueError, match="same miner panel"),
    ):
        store.apply_window(**_kwargs(0, observations=tuple(values)))


def test_duplicate_request_and_retained_pool_reuse_fail_closed(tmp_path: Path) -> None:
    with ValidatorMonitoringStateStore(_database_path(tmp_path), policy=_policy()) as store:
        values = _observations(0)
        with pytest.raises(ValueError, match="duplicate request leaf"):
            store.apply_window(**_kwargs(0, observations=(*values, values[0])))
        store.apply_window(**_kwargs(0))
        reused = tuple(
            replace(
                item,
                request_leaf=_hash(f"reused-{index}"),
            )
            for index, item in enumerate(_observations(0))
        )
        with pytest.raises(MonitoringStateConflict) as conflict:
            store.apply_window(**_kwargs(1, observations=reused))
        assert conflict.value.reason_code == "pool_leaf_reuse"


def test_exact_fraction_and_resource_bounds_are_enforced(tmp_path: Path) -> None:
    with pytest.raises(TypeError, match="Fraction"):
        SourceObservation(
            request_leaf=_hash("request"),
            pool_leaf=_hash("pool"),
            miner_root=MINER_A,
            publisher_hotkey=PUBLISHERS[0],
            control_group_id=GROUPS[0],
            signer_cluster_id=_hash("signer"),
            stratum="continuous",
            score=0.5,  # type: ignore[arg-type]
        )

    bounds = MonitoringStateBounds(
        maximum_request_bytes=128,
        maximum_observations=100,
        maximum_observations_per_window=50,
    )
    with ValidatorMonitoringStateStore(
        _database_path(tmp_path), policy=_policy(), bounds=bounds
    ) as store:
        with pytest.raises(MonitoringStateLimitError) as limited:
            store.apply_window(**_kwargs(0))
        assert limited.value.reason_code == "canonical_request_size_limit"
        assert store.snapshot.valid_window_count == 0


def test_restart_rejects_canonical_operation_corruption(tmp_path: Path) -> None:
    path = _database_path(tmp_path)
    with ValidatorMonitoringStateStore(path, policy=_policy()) as store:
        store.apply_window(**_kwargs(0))

    connection = sqlite3.connect(path)
    try:
        connection.execute(
            "UPDATE valid_windows SET request_bytes = ? WHERE window_index = 0",
            (b"{}",),
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(MonitoringStateCorruption) as corrupted:
        ValidatorMonitoringStateStore(path, policy=_policy())
    assert corrupted.value.reason_code == "request_digest_mismatch"


def test_restart_rejects_materialized_row_corruption(tmp_path: Path) -> None:
    path = _database_path(tmp_path)
    with ValidatorMonitoringStateStore(path, policy=_policy()) as store:
        store.apply_window(**_kwargs(0))

    connection = sqlite3.connect(path)
    try:
        leaf = _observations(0)[0].request_leaf
        connection.execute(
            "UPDATE monitoring_observations SET score_numerator = '1' WHERE request_leaf = ?",
            (leaf,),
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(MonitoringStateCorruption) as corrupted:
        ValidatorMonitoringStateStore(path, policy=_policy())
    assert corrupted.value.reason_code == "materialized_observations_mismatch"


def test_database_is_bound_to_exact_validator_policy(tmp_path: Path) -> None:
    path = _database_path(tmp_path)
    with ValidatorMonitoringStateStore(path, policy=_policy()):
        pass
    changed = replace(_policy(), alert_threshold=Fraction(1, 10))
    with pytest.raises(MonitoringStateConflict) as mismatch:
        ValidatorMonitoringStateStore(path, policy=changed)
    assert mismatch.value.reason_code == "policy_mismatch"


def test_two_store_instances_synchronize_before_writing(tmp_path: Path) -> None:
    path = _database_path(tmp_path)
    first = ValidatorMonitoringStateStore(path, policy=_policy())
    second = ValidatorMonitoringStateStore(path, policy=_policy())
    try:
        first.apply_window(**_kwargs(0))
        result = second.apply_window(**_kwargs(1))
        assert result.snapshot.valid_window_count == 2
        assert first.audit().state_digest == second.audit().state_digest
    finally:
        first.close()
        second.close()


def test_failed_concurrent_write_keeps_newly_audited_head(tmp_path: Path) -> None:
    path = _database_path(tmp_path)
    first = ValidatorMonitoringStateStore(path, policy=_policy())
    second = ValidatorMonitoringStateStore(path, policy=_policy())
    try:
        committed = first.apply_window(**_kwargs(2))
        with pytest.raises(MonitoringStateConflict):
            second.apply_window(**_kwargs(1))
        assert second.snapshot.state_digest == committed.snapshot.state_digest
        assert second.snapshot.last_window_index == 2
    finally:
        first.close()
        second.close()


def test_store_requires_absolute_safe_path_and_closes_idempotently(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="absolute"):
        ValidatorMonitoringStateStore(Path("relative.sqlite3"), policy=_policy())
    store = ValidatorMonitoringStateStore(_database_path(tmp_path), policy=_policy())
    store.close()
    store.close()
    with pytest.raises(MonitoringStateStoreError) as closed:
        _ = store.snapshot
    assert closed.value.reason_code == "store_closed"


def test_policy_requires_complete_batch_window_and_canonical_registries() -> None:
    with pytest.raises(ValueError, match="complete two-batch"):
        _policy(maximum_batches=3)
    with pytest.raises(ValueError, match="sorted and unique"):
        replace(_policy(), publisher_sources=tuple(reversed(PUBLISHERS)))
    with pytest.raises(ValueError, match="cover every publisher"):
        replace(_policy(), publisher_control_groups=((PUBLISHERS[0], GROUPS[0]),))
