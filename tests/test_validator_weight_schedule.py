from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest

from umi.chain_evidence import FinalizedSnapshotRef, StorageEvidence
from umi.validator_chain import FinalizedRuntimePin, PinnedRuntimeContext, VerifiedStorageRead
from umi.validator_chain_scan import VerifiedFinalizedBlockIdentity
from umi.validator_weight_schedule import (
    VerifiedWeightScheduleObservation,
    WeightCommitSchedule,
    WeightCommitSchedulePending,
    WeightScheduleError,
    WeightScheduleIdentity,
    WeightScheduleLimits,
    derive_weight_commit_schedule,
)

GENESIS_HASH = (b"g" * 32).hex()
FINALITY_VERIFIER = (b"f" * 32).hex()
METADATA = b"weight-schedule-runtime-metadata"
PIN = FinalizedRuntimePin(
    metadata_sha256=hashlib.sha256(METADATA).hexdigest(),
    spec_version=449,
    transaction_version=1,
)


def block_hash(value: int) -> str:
    return "0x" + value.to_bytes(32, "big").hex()


def snapshot(height: int) -> FinalizedSnapshotRef:
    return FinalizedSnapshotRef(
        block_number=height,
        block_hash=block_hash(10_000 + height),
        parent_hash=block_hash(9_999 + height),
        state_root=block_hash(20_000 + height),
    )


class Entry:
    modifier = "Default"
    default_bytes = (0).to_bytes(8, "little")
    value_type = "u64"


class EpochRuntime:
    def storage_key(self, pallet, item, params):
        return f"{pallet}.{item}:{params[0]}".encode()

    def storage_entry(self, _pallet, _item):
        return Entry()

    def decode(self, _type_name, value, *, strict):
        assert strict is True
        if not isinstance(value, bytes) or len(value) != 8:
            raise ValueError("invalid epoch encoding")
        return int.from_bytes(value, "little")


def observation(
    height: int,
    epoch: int,
    *,
    timestamp_ms: int | None = None,
    runtime_pin: FinalizedRuntimePin = PIN,
    genesis_hash: str = GENESIS_HASH,
    finality_verifier: str = FINALITY_VERIFIER,
) -> VerifiedWeightScheduleObservation:
    ref = snapshot(height)
    evidence_bytes = f"owned-finality-{height}".encode()
    identity = VerifiedFinalizedBlockIdentity(
        snapshot=ref,
        parent_snapshot=snapshot(height - 1),
        extrinsics_root=block_hash(30_000 + height),
        finality_verifier_sha256=finality_verifier,
        finality_evidence_sha256=hashlib.sha256(evidence_bytes).hexdigest(),
    )
    runtime = PinnedRuntimeContext(
        snapshot=ref,
        pin=runtime_pin,
        metadata_bytes=METADATA,
        runtime_version_bytes=b'{"specVersion":449,"transactionVersion":1}',
        _runtime=EpochRuntime(),
    )
    raw_epoch = epoch.to_bytes(8, "little")
    storage = StorageEvidence(
        snapshot=ref,
        storage_key=b"SubtensorModule.SubnetEpochIndex:78",
        value=raw_epoch,
        proof=(f"proof-{height}".encode(),),
        verifier=lambda **_kwargs: True,
    )
    read = VerifiedStorageRead(
        runtime=runtime,
        pallet="SubtensorModule",
        item="SubnetEpochIndex",
        params=(78,),
        evidence=storage,
        decoded_value=epoch,
    )
    return VerifiedWeightScheduleObservation(
        identity=identity,
        timestamp_ms=height * 1_000 if timestamp_ms is None else timestamp_ms,
        chain_genesis_hash=genesis_hash,
        finality_attestation=evidence_bytes,
        subnet_epoch_index_read=read,
    )


def interval(first: int, epochs: list[int]) -> tuple[VerifiedWeightScheduleObservation, ...]:
    return tuple(observation(first + offset, epoch) for offset, epoch in enumerate(epochs))


def schedule_identity(*, runtime_pin: FinalizedRuntimePin = PIN) -> WeightScheduleIdentity:
    return WeightScheduleIdentity(
        chain_genesis_hash=GENESIS_HASH,
        finality_verifier_sha256=FINALITY_VERIFIER,
        runtime_pin=runtime_pin,
    )


def derive(
    values: tuple[VerifiedWeightScheduleObservation, ...],
    *,
    reveal_time_ms: int = 101_500,
    buffer_blocks: int = 2,
    submission_blocks: int = 3,
):
    return derive_weight_commit_schedule(
        values,
        identity=schedule_identity(),
        reveal_time_ms=reveal_time_ms,
        weight_commit_buffer_blocks=buffer_blocks,
        weight_commit_submission_blocks=submission_blocks,
    )


def test_ordinary_observed_transition_derives_complete_schedule() -> None:
    result = derive(interval(100, [7, 7, 7, 7, 8, 8, 8, 8, 8]))

    assert isinstance(result, WeightCommitSchedule)
    assert result.reveal_observation_block.snapshot.block_number == 102
    assert result.weight_commit_ready_height == 104
    assert result.base_epoch_block.snapshot.block_number == 103
    assert result.base_epoch_index == 7
    assert result.weight_commit_open_block.snapshot.block_number == 104
    assert result.weight_commit_epoch_index == 8
    assert result.weight_commit_close_block.snapshot.block_number == 108


def test_pull_forward_before_ready_becomes_base_and_is_not_used_as_open() -> None:
    result = derive(interval(100, [7, 7, 7, 8, 8, 8, 9, 9, 9, 9, 9]))

    assert isinstance(result, WeightCommitSchedule)
    assert result.base_epoch_block.snapshot.block_number == 103
    assert result.base_epoch_index == 8
    assert result.weight_commit_open_block.snapshot.block_number == 106
    assert result.weight_commit_epoch_index == 9


def test_pull_forward_transition_at_ready_opens_at_ready() -> None:
    result = derive(interval(100, [7, 7, 7, 7, 9, 9, 9, 9, 9]))

    assert isinstance(result, WeightCommitSchedule)
    assert result.weight_commit_open_block.snapshot.block_number == 104
    assert result.weight_commit_epoch_index == 9


def test_deferred_transition_waits_for_first_observed_greater_epoch() -> None:
    result = derive(interval(100, [7, 7, 7, 7, 7, 7, 7, 8, 8, 8, 8, 8]))

    assert isinstance(result, WeightCommitSchedule)
    assert result.weight_commit_open_block.snapshot.block_number == 107
    assert result.weight_commit_epoch_index == 8


def test_epoch_change_closes_before_height_limit() -> None:
    result = derive(
        interval(100, [7, 7, 7, 7, 8, 8, 9]),
        submission_blocks=5,
    )

    assert isinstance(result, WeightCommitSchedule)
    assert result.weight_commit_open_block.snapshot.block_number == 104
    assert result.weight_commit_close_block.snapshot.block_number == 106
    assert result.weight_commit_close_block.subnet_epoch_index == 9


def test_close_height_is_strictly_greater_than_open_plus_allowance() -> None:
    result = derive(interval(100, [7, 7, 7, 7, 8, 8, 8, 8, 8]))

    assert isinstance(result, WeightCommitSchedule)
    assert result.weight_commit_open_block.snapshot.block_number == 104
    # 107 == open + 3 remains eligible. The first height-only close is 108.
    assert result.weight_commit_close_block.snapshot.block_number == 108


def test_epoch_change_at_exact_height_boundary_closes_on_that_block() -> None:
    result = derive(interval(100, [7, 7, 7, 7, 8, 8, 8, 9]))

    assert isinstance(result, WeightCommitSchedule)
    assert result.weight_commit_open_block.snapshot.block_number == 104
    assert result.weight_commit_close_block.snapshot.block_number == 107


@pytest.mark.parametrize(
    ("values", "reason", "next_height"),
    [
        (interval(99, [7, 7, 7]), "reveal_observation_pending", 102),
        (interval(100, [7, 7, 7]), "base_epoch_observation_pending", 103),
        (interval(100, [7, 7, 7, 7, 7]), "epoch_transition_pending", 105),
        (interval(100, [7, 7, 7, 7, 8, 8]), "close_observation_pending", 106),
    ],
)
def test_missing_future_observations_return_precise_pending_state(
    values, reason, next_height
) -> None:
    result = derive(values)

    assert isinstance(result, WeightCommitSchedulePending)
    assert result.reason_code == reason
    assert result.next_required_height == next_height


def test_empty_observation_set_is_pending_without_inventing_a_height() -> None:
    result = derive(())

    assert result == WeightCommitSchedulePending(
        reason_code="reveal_observation_pending",
        next_required_height=None,
    )


def test_interval_starting_at_reveal_fails_closed_without_boundary_history() -> None:
    with pytest.raises(WeightScheduleError, match="reveal_boundary_history_missing"):
        derive(interval(102, [7, 8, 8, 8, 8, 8, 8]))


def test_finalized_height_gap_fails_closed() -> None:
    values = (observation(100, 7), observation(101, 7), observation(103, 7))

    with pytest.raises(WeightScheduleError, match="finalized_observation_gap"):
        derive(values)


def test_parent_identity_mismatch_fails_closed() -> None:
    second = observation(101, 7)
    fork_parent = FinalizedSnapshotRef(
        block_number=100,
        block_hash=block_hash(99_999),
        parent_hash=block_hash(99_998),
        state_root=block_hash(99_997),
    )
    fork_snapshot = replace(second.snapshot, parent_hash=fork_parent.block_hash)
    wrong_parent = replace(
        second.identity,
        snapshot=fork_snapshot,
        parent_snapshot=fork_parent,
    )
    fork_runtime = replace(second.runtime, snapshot=fork_snapshot)
    fork_evidence = StorageEvidence(
        snapshot=fork_snapshot,
        storage_key=second.subnet_epoch_index_read.evidence.storage_key,
        value=second.subnet_epoch_index_read.evidence.value,
        proof=second.subnet_epoch_index_read.evidence.proof,
        verifier=lambda **_kwargs: True,
    )
    fork_read = replace(
        second.subnet_epoch_index_read,
        runtime=fork_runtime,
        evidence=fork_evidence,
    )
    values = (
        observation(100, 7),
        replace(
            second,
            identity=wrong_parent,
            subnet_epoch_index_read=fork_read,
        ),
    )

    with pytest.raises(WeightScheduleError, match="finalized_parent_identity_mismatch"):
        derive(values, reveal_time_ms=200_000)


def test_epoch_regression_fails_closed() -> None:
    with pytest.raises(WeightScheduleError, match="subnet_epoch_index_regression"):
        derive(interval(100, [7, 8, 7]), reveal_time_ms=200_000)


def test_inconsistent_chain_finality_and_runtime_identity_fail_closed() -> None:
    values = interval(100, [7, 7, 7])
    wrong_genesis = replace(values[1], chain_genesis_hash=(b"x" * 32).hex())
    with pytest.raises(WeightScheduleError, match="chain_identity_mismatch"):
        derive((values[0], wrong_genesis, values[2]), reveal_time_ms=200_000)

    wrong_finality = schedule_identity()
    wrong_finality = replace(wrong_finality, finality_verifier_sha256=(b"x" * 32).hex())
    with pytest.raises(WeightScheduleError, match="finality_verifier_mismatch"):
        derive_weight_commit_schedule(
            values,
            identity=wrong_finality,
            reveal_time_ms=200_000,
            weight_commit_buffer_blocks=2,
            weight_commit_submission_blocks=3,
        )

    wrong_pin = FinalizedRuntimePin(
        metadata_sha256=PIN.metadata_sha256,
        spec_version=450,
        transaction_version=1,
    )
    with pytest.raises(WeightScheduleError, match="runtime_identity_mismatch"):
        derive_weight_commit_schedule(
            values,
            identity=schedule_identity(runtime_pin=wrong_pin),
            reveal_time_ms=200_000,
            weight_commit_buffer_blocks=2,
            weight_commit_submission_blocks=3,
        )


def test_epoch_read_must_be_exact_proof_backed_runtime_decode() -> None:
    valid = observation(100, 7)
    forged_read = replace(valid.subnet_epoch_index_read, decoded_value=8)

    with pytest.raises(ValueError, match="semantic decode disagrees"):
        replace(valid, subnet_epoch_index_read=forged_read)

    wrong_evidence = StorageEvidence(
        snapshot=valid.snapshot,
        storage_key=b"SubtensorModule.Tempo:78",
        value=valid.subnet_epoch_index_read.evidence.value,
        proof=(b"wrong-item-proof",),
        verifier=lambda **_kwargs: True,
    )
    wrong_item = replace(
        valid.subnet_epoch_index_read,
        item="Tempo",
        evidence=wrong_evidence,
    )
    with pytest.raises(ValueError, match="wrong runtime storage item"):
        replace(valid, subnet_epoch_index_read=wrong_item)


@pytest.mark.parametrize(
    ("buffer_blocks", "submission_blocks"),
    [(0, 3), (2, 0), (-1, 3), (2, -1), (True, 3)],
)
def test_invalid_schedule_parameters_fail_closed(buffer_blocks, submission_blocks) -> None:
    with pytest.raises(ValueError):
        derive(
            interval(100, [7, 7]),
            buffer_blocks=buffer_blocks,
            submission_blocks=submission_blocks,
        )


def test_observation_count_and_evidence_are_bounded() -> None:
    values = interval(100, [7, 7, 7])
    with pytest.raises(WeightScheduleError, match="observation_count_limit"):
        derive_weight_commit_schedule(
            values,
            identity=schedule_identity(),
            reveal_time_ms=200_000,
            weight_commit_buffer_blocks=2,
            weight_commit_submission_blocks=3,
            limits=WeightScheduleLimits(maximum_observations=2),
        )

    limits = WeightScheduleLimits(maximum_finality_evidence_bytes=4)
    with pytest.raises(WeightScheduleError, match="finality_evidence_size_limit"):
        derive_weight_commit_schedule(
            values,
            identity=schedule_identity(),
            reveal_time_ms=200_000,
            weight_commit_buffer_blocks=2,
            weight_commit_submission_blocks=3,
            limits=limits,
        )
