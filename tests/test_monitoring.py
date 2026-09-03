from __future__ import annotations

import hashlib
from fractions import Fraction

import bittensor as bt
import pytest

from umi.encoding import account_id32
from umi.monitoring import SourceObservation, compute_source_monitoring


def _id(value: int) -> bytes:
    return bytes([value]) * 32


def _observations(*, second_miner: bool = False) -> tuple[SourceObservation, ...]:
    values: list[SourceObservation] = []
    request = 1
    strata = ("fingerspelling", "short_utterance", "continuous")
    for stratum_index, stratum in enumerate(strata):
        for source_index, (publisher, group, score) in enumerate(
            ((_id(20), _id(30), Fraction(1)), (_id(21), _id(31), Fraction(0)))
        ):
            for clip in range(3):
                values.append(
                    SourceObservation(
                        request_leaf=hashlib.sha256(f"request-{request}".encode()).digest(),
                        pool_leaf=_id(40 + stratum_index * 2 + source_index),
                        miner_root=_id(10),
                        publisher_hotkey=publisher,
                        control_group_id=group,
                        signer_cluster_id=_id(50 + source_index * 3 + clip),
                        stratum=stratum,  # type: ignore[arg-type]
                        score=score,
                    )
                )
                request += 1
    if second_miner:
        values.append(
            SourceObservation(
                request_leaf=hashlib.sha256(b"second-miner").digest(),
                pool_leaf=_id(40),
                miner_root=_id(11),
                publisher_hotkey=_id(20),
                control_group_id=_id(30),
                signer_cluster_id=_id(50),
                stratum="fingerspelling",
                score=Fraction(1),
            )
        )
    return tuple(values)


def _report(values: tuple[SourceObservation, ...], *, minimum: int = 2):
    return compute_source_monitoring(
        values,
        validator_hotkey=_id(9),
        scoring_policy_hash=_id(8),
        first_window_index=0,
        last_window_index=3,
        minimum_clips_per_side_and_stratum=minimum,
        alert_threshold=Fraction(3, 20),
        maximum_batches=12,
        publisher_sources=(_id(20), _id(21), _id(22)),
        control_group_sources=(_id(30), _id(31), _id(32)),
        bootstrap_replicates=64,
    )


def test_source_monitoring_is_exact_deterministic_and_alert_only() -> None:
    values = _observations()
    report = _report(values)
    replay = _report(tuple(reversed(values)))

    assert report.report_bytes == replay.report_bytes
    assert report.report_sha256 == hashlib.sha256(report.report_bytes).digest()
    assert report.observation_count == 18
    assert report.batch_count == 6

    publisher_high = next(
        item
        for item in report.effects
        if item.source_kind == "publisher" and item.source_id == _id(20)
    )
    assert publisher_high.eligible is True
    assert publisher_high.aggregate_effect == 1
    assert publisher_high.interval_lower == 1
    assert publisher_high.interval_upper == 1
    assert publisher_high.alert is True
    assert all(component.difference == 1 for component in publisher_high.components)

    publisher_low = next(
        item
        for item in report.effects
        if item.source_kind == "publisher" and item.source_id == _id(21)
    )
    assert publisher_low.aggregate_effect == -1
    assert publisher_low.alert is False

    group_high = next(
        item
        for item in report.effects
        if item.source_kind == "control_group" and item.source_id == _id(30)
    )
    assert group_high.aggregate_effect == 1
    assert group_high.alert is True


def test_every_miner_source_pair_is_reported_even_when_ineligible() -> None:
    report = _report(_observations(second_miner=True))
    second_miner = [item for item in report.effects if item.miner_root == _id(11)]
    assert len(second_miner) == 6
    assert all(item.eligible is False for item in second_miner)
    assert all(item.aggregate_effect is None and not item.alert for item in second_miner)


def test_signer_cluster_bootstrap_is_reproducible_with_unequal_clusters() -> None:
    values = list(_observations())
    # Collapse two high-source clips in every stratum into one signer cluster.
    values = [
        SourceObservation(
            request_leaf=item.request_leaf,
            pool_leaf=item.pool_leaf,
            miner_root=item.miner_root,
            publisher_hotkey=item.publisher_hotkey,
            control_group_id=item.control_group_id,
            signer_cluster_id=(
                _id(99)
                if item.publisher_hotkey == _id(20) and item.signer_cluster_id in {_id(50), _id(51)}
                else item.signer_cluster_id
            ),
            stratum=item.stratum,
            score=(
                Fraction(1, 2)
                if item.publisher_hotkey == _id(20) and item.signer_cluster_id == _id(51)
                else item.score
            ),
        )
        for item in values
    ]
    first = _report(tuple(values))
    second = _report(tuple(values))
    assert first.report_bytes == second.report_bytes
    effect = next(
        item
        for item in first.effects
        if item.source_kind == "publisher" and item.source_id == _id(20)
    )
    assert effect.eligible
    assert effect.interval_lower <= effect.interval_upper  # type: ignore[operator]


@pytest.mark.parametrize(
    ("mutator", "message"),
    [
        (lambda values: (*values, values[0]), "duplicate request leaf"),
        (lambda values: values, "monitoring batch window"),
    ],
)
def test_monitoring_fails_closed_on_duplicate_or_batch_limit(mutator, message: str) -> None:
    values = mutator(_observations())
    maximum_batches = 12 if "duplicate" in message else 1
    with pytest.raises(ValueError, match=message):
        compute_source_monitoring(
            values,
            validator_hotkey=_id(9),
            scoring_policy_hash=_id(8),
            first_window_index=0,
            last_window_index=3,
            minimum_clips_per_side_and_stratum=2,
            alert_threshold=Fraction(3, 20),
            maximum_batches=maximum_batches,
            publisher_sources=(_id(20), _id(21)),
            control_group_sources=(_id(30), _id(31)),
            bootstrap_replicates=8,
        )


def test_monitoring_validates_bounds_and_observation_shape() -> None:
    values = _observations()
    with pytest.raises(ValueError, match="positive integer"):
        compute_source_monitoring(
            values,
            validator_hotkey=_id(9),
            scoring_policy_hash=_id(8),
            first_window_index=0,
            last_window_index=3,
            minimum_clips_per_side_and_stratum=0,
            alert_threshold=Fraction(3, 20),
            maximum_batches=12,
            publisher_sources=(_id(20), _id(21)),
            control_group_sources=(_id(30), _id(31)),
        )
    with pytest.raises(ValueError, match="unit interval"):
        SourceObservation(
            request_leaf=_id(1),
            pool_leaf=_id(2),
            miner_root=_id(3),
            publisher_hotkey=_id(4),
            control_group_id=_id(5),
            signer_cluster_id=_id(6),
            stratum="continuous",
            score=Fraction(2),
        )


def test_monitoring_reports_declared_sources_with_no_observations() -> None:
    report = _report(_observations())
    unused = [item for item in report.effects if item.source_id in {_id(22), _id(32)}]
    assert len(unused) == 2
    assert all(not item.eligible and not item.alert for item in unused)


def test_monitoring_rejects_undeclared_or_noncanonical_source_registries() -> None:
    values = _observations()
    with pytest.raises(ValueError, match="undeclared publisher"):
        compute_source_monitoring(
            values,
            validator_hotkey=_id(9),
            scoring_policy_hash=_id(8),
            first_window_index=0,
            last_window_index=3,
            minimum_clips_per_side_and_stratum=2,
            alert_threshold=Fraction(3, 20),
            maximum_batches=12,
            publisher_sources=(_id(20),),
            control_group_sources=(_id(30), _id(31)),
            bootstrap_replicates=8,
        )


def test_publisher_registry_accepts_ss58_accounts_not_hex_digest_text() -> None:
    publisher_one = bt.sp_core.Keypair.create_from_uri("//PublisherOne").ss58_address
    publisher_two = bt.sp_core.Keypair.create_from_uri("//PublisherTwo").ss58_address
    publisher_one_raw = account_id32(publisher_one)
    publisher_two_raw = account_id32(publisher_two)
    values = tuple(
        SourceObservation(
            request_leaf=item.request_leaf,
            pool_leaf=item.pool_leaf,
            miner_root=item.miner_root,
            publisher_hotkey=(
                publisher_one_raw if item.publisher_hotkey == _id(20) else publisher_two_raw
            ),
            control_group_id=item.control_group_id,
            signer_cluster_id=item.signer_cluster_id,
            stratum=item.stratum,
            score=item.score,
        )
        for item in _observations()
    )
    report = compute_source_monitoring(
        values,
        validator_hotkey=_id(9),
        scoring_policy_hash=_id(8),
        first_window_index=0,
        last_window_index=3,
        minimum_clips_per_side_and_stratum=2,
        alert_threshold=Fraction(3, 20),
        maximum_batches=12,
        publisher_sources=(publisher_one, publisher_two),
        control_group_sources=(_id(30), _id(31)),
        bootstrap_replicates=8,
    )
    assert report.publisher_sources == tuple(sorted((publisher_one_raw, publisher_two_raw)))
    with pytest.raises(ValueError, match="sorted, and unique"):
        compute_source_monitoring(
            values,
            validator_hotkey=_id(9),
            scoring_policy_hash=_id(8),
            first_window_index=0,
            last_window_index=3,
            minimum_clips_per_side_and_stratum=2,
            alert_threshold=Fraction(3, 20),
            maximum_batches=12,
            publisher_sources=(_id(21), _id(20)),
            control_group_sources=(_id(30), _id(31)),
            bootstrap_replicates=8,
        )
