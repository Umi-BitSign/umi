from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi.policy import scoring_policy_hash
from umi.protocol import canonical_json_bytes
from umi.validator_chain import (
    DecodedStorageClaim,
    MultiStorageEvidence,
    StorageClaim,
    VerifiedStorageBatch,
)
from umi.validator_plans import VerifiedFinalizedBlock
from umi.validator_state import StagePending, WindowStage
from umi.validator_weight_ports import (
    LiveWeightBuildSnapshotPort,
    LiveWeightPortError,
    LiveWeightSchedulePort,
)
from umi.validator_weight_schedule import WeightCommitSchedule, derive_weight_commit_schedule
from umi.window import QUICKNET_GENESIS_MS, QUICKNET_PERIOD_MS

from .test_shadow import _fixture as _shadow_fixture
from .test_validator_weight_build_effect import _fixture, _snapshot


class _Finality:
    def __init__(self, fixture, observations) -> None:
        self._policy = fixture.policy
        self._observations = {item.snapshot.block_number: item for item in observations}
        live = fixture.policy.implementation_pins.live_chain
        assert live is not None
        self.chain_observation = live
        self.finality_verifier_sha256 = next(
            iter(
                fixture.policy.implementation_pins.finality_verifier.release_sha256_by_target.values()
            )
        )
        self.head_error: Exception | None = None
        self.interval_missing = False
        self.block_overrides: dict[int, VerifiedFinalizedBlock | None] = {}

    async def finalized_head_height(self) -> int:
        if self.head_error is not None:
            raise self.head_error
        return max(self._observations)

    async def verified_scan_interval(self, start_height: int, end_height: int):
        if self.interval_missing:
            return None
        values = tuple(self._observations[height] for height in range(start_height, end_height + 1))
        return SimpleNamespace(
            identities=tuple(item.identity for item in values),
            attestations=tuple(item.finality_attestation for item in values),
            replay_bindings=tuple(SimpleNamespace() for _item in values),
        )

    async def verified_block_at(self, height: int):
        if height in self.block_overrides:
            return self.block_overrides[height]
        item = self._observations.get(height)
        if item is None:
            return None
        return VerifiedFinalizedBlock(
            height=height,
            block_hash=item.snapshot.block_hash,
            state_root=item.snapshot.state_root,
            timestamp_ms=item.timestamp_ms,
            scoring_policy_hash=scoring_policy_hash(self._policy),
            chain_observation=self.chain_observation,
            finality_verifier_sha256=item.identity.finality_verifier_sha256,
            finality_evidence=item.finality_attestation,
            finality_evidence_sha256=item.identity.finality_evidence_sha256,
        )


class _Proofs:
    def __init__(self, observations, values=None) -> None:
        self._observations = {item.snapshot.block_number: item for item in observations}
        self._values = values or {}
        self.storage_batches: list[tuple] = []

    async def pinned_runtime(self, snapshot, pin):
        item = self._observations[snapshot.block_number]
        assert item.snapshot == snapshot
        assert item.runtime.pin == pin
        return item.runtime

    async def storage_read(self, runtime, pallet, item, params=()):
        observation = self._observations[runtime.snapshot.block_number]
        assert (pallet, item, tuple(params)) == (
            "SubtensorModule",
            "SubnetEpochIndex",
            (78,),
        )
        return observation.subnet_epoch_index_read

    async def storage_reads(self, runtime, specs):
        exact_specs = tuple(specs)
        self.storage_batches.append(exact_specs)
        keyed = sorted(
            (
                runtime.storage_key(spec.pallet, spec.item, spec.params),
                spec,
                self._values[(spec.pallet, spec.item, spec.params)],
            )
            for spec in exact_specs
        )
        claims: list[StorageClaim] = []
        reads: list[DecodedStorageClaim] = []
        for key, spec, value in keyed:
            raw = None if value is None else canonical_json_bytes(value)
            claims.append(StorageClaim(storage_key=key, value=raw))
            reads.append(
                DecodedStorageClaim(
                    spec=spec,
                    storage_key=key,
                    raw_value=raw,
                    decoded_value=value,
                )
            )
        evidence = MultiStorageEvidence(
            snapshot=runtime.snapshot,
            claims=tuple(claims),
            proof=(b"live-weight-port-proof\0" + len(self.storage_batches).to_bytes(2, "big"),),
            verifier=lambda **_kwargs: True,
        )
        return VerifiedStorageBatch(runtime=runtime, evidence=evidence, reads=tuple(reads))


class _NoHead(RuntimeError):
    reason_code = "no_verified_finalized_head"


def _port_work(fixture):
    plan = replace(
        fixture.work.window.plan,
        announcement_block=99,
        proposal_close_block=100,
        closing_block=101,
    )
    return replace(fixture.work, window=replace(fixture.work.window, plan=plan))


def _complete_schedule(fixture) -> WeightCommitSchedule:
    reveal_time = (
        QUICKNET_GENESIS_MS + (fixture.work.window.plan.reveal_round - 1) * QUICKNET_PERIOD_MS
    )
    result = derive_weight_commit_schedule(
        fixture.capture.observations,
        identity=fixture.capture.identity,
        reveal_time_ms=reveal_time,
        weight_commit_buffer_blocks=fixture.policy.clock.weight_commit_buffer_blocks,
        weight_commit_submission_blocks=fixture.policy.clock.weight_commit_submission_blocks,
    )
    assert isinstance(result, WeightCommitSchedule)
    return result


def _snapshot_values(snapshot) -> dict[tuple[str, str, tuple[object, ...]], object]:
    return {
        (read.spec.pallet, read.spec.item, read.spec.params): read.decoded_value
        for batch in snapshot.storage_batches
        for read in batch.reads
    }


@pytest.mark.asyncio
async def test_live_schedule_collects_complete_proof_backed_finalized_interval(tmp_path) -> None:
    fixture = _fixture(tmp_path)
    work = _port_work(fixture)
    finality = _Finality(fixture, fixture.capture.observations)
    proofs = _Proofs(fixture.capture.observations)
    port = LiveWeightSchedulePort(policy=fixture.policy, finality=finality, proofs=proofs)

    capture = await port(work)

    assert capture == fixture.capture
    assert capture.observations[0].snapshot.block_number == work.window.plan.announcement_block
    assert capture.observations[-1].snapshot.block_number == await finality.finalized_head_height()


@pytest.mark.asyncio
async def test_live_schedule_is_shared_by_transcript_reveal_and_weight_stages(tmp_path) -> None:
    fixture = _fixture(tmp_path)
    work = _port_work(fixture)
    finality = _Finality(fixture, fixture.capture.observations)
    port = LiveWeightSchedulePort(
        policy=fixture.policy,
        finality=finality,
        proofs=_Proofs(fixture.capture.observations),
    )

    for stage in (
        WindowStage.ASSIGNMENT,
        WindowStage.REQUEST_TRANSCRIPT,
        WindowStage.SEALED_RESPONSE,
        WindowStage.REVEAL_AND_SCORE,
        WindowStage.WEIGHT_BUILD,
    ):
        staged = replace(work, window=replace(work.window, stage=stage))
        assert await port(staged) == fixture.capture


@pytest.mark.asyncio
async def test_live_schedule_distinguishes_pending_head_from_finality_failure(tmp_path) -> None:
    fixture = _fixture(tmp_path)
    work = _port_work(fixture)
    finality = _Finality(fixture, fixture.capture.observations)
    port = LiveWeightSchedulePort(
        policy=fixture.policy,
        finality=finality,
        proofs=_Proofs(fixture.capture.observations),
    )

    finality.head_error = _NoHead()
    with pytest.raises(StagePending, match="weight_schedule_finalized_head_pending"):
        await port(work)

    finality.head_error = RuntimeError("observer store corrupt")
    with pytest.raises(LiveWeightPortError, match="weight_schedule_finalized_head_failed"):
        await port(work)


@pytest.mark.asyncio
async def test_live_schedule_waits_for_a_complete_finality_interval(tmp_path) -> None:
    fixture = _fixture(tmp_path)
    finality = _Finality(fixture, fixture.capture.observations)
    finality.interval_missing = True
    port = LiveWeightSchedulePort(
        policy=fixture.policy,
        finality=finality,
        proofs=_Proofs(fixture.capture.observations),
    )

    with pytest.raises(StagePending, match="weight_schedule_finality_interval_pending"):
        await port(_port_work(fixture))


@pytest.mark.asyncio
async def test_live_snapshot_collects_exact_mapping_graph_and_rechecks_finality(tmp_path) -> None:
    fixture = _fixture(tmp_path)
    roots = (b"A" * 32, b"B" * 32)
    schedule = _complete_schedule(fixture)
    expected = _snapshot(fixture.policy, fixture.capture, roots)
    proofs = _Proofs(
        fixture.capture.observations,
        _snapshot_values(expected),
    )
    finality = _Finality(fixture, fixture.capture.observations)
    port = LiveWeightBuildSnapshotPort(
        policy=fixture.policy,
        finality=finality,
        proofs=proofs,
        validator_hotkey=fixture.validator,
        maximum_storage_keys_per_proof=4,
    )

    actual = await port(fixture.work, roots, schedule)

    actual_values = _snapshot_values(actual)
    assert actual.identity == expected.identity
    assert actual.timestamp_ms == expected.timestamp_ms
    assert actual.requested_roots == roots
    assert actual_values == _snapshot_values(expected)
    assert all(len(batch) <= 4 for batch in proofs.storage_batches)
    assert len(actual_values) == len(
        {read.storage_key for batch in actual.storage_batches for read in batch.reads}
    )


@pytest.mark.asyncio
async def test_live_snapshot_omits_inverse_reads_only_for_unresolved_destination(tmp_path) -> None:
    fixture = _fixture(tmp_path)
    roots = (b"A" * 32, b"B" * 32)
    expected = _snapshot(
        fixture.policy,
        fixture.capture,
        roots,
        unresolved_root=roots[1],
    )
    port = LiveWeightBuildSnapshotPort(
        policy=fixture.policy,
        finality=_Finality(fixture, fixture.capture.observations),
        proofs=_Proofs(fixture.capture.observations, _snapshot_values(expected)),
        validator_hotkey=fixture.validator,
    )

    actual = await port(fixture.work, roots, _complete_schedule(fixture))

    reads = _snapshot_values(actual)
    assert ("SubtensorModule", "Uids", (78, roots[1])) in reads
    assert ("SubtensorModule", "Keys", (78, 2)) not in reads
    assert ("SubtensorModule", "HotkeyRoot", (78, roots[1])) not in reads


@pytest.mark.asyncio
async def test_live_snapshot_rejects_commit_open_finality_substitution(tmp_path) -> None:
    fixture = _fixture(tmp_path)
    schedule = _complete_schedule(fixture)
    roots = (b"A" * 32, b"B" * 32)
    expected = _snapshot(fixture.policy, fixture.capture, roots)
    finality = _Finality(fixture, fixture.capture.observations)
    height = schedule.weight_commit_open_block.snapshot.block_number
    genuine = await finality.verified_block_at(height)
    assert genuine is not None
    finality.block_overrides[height] = replace(genuine, timestamp_ms=genuine.timestamp_ms + 1)
    port = LiveWeightBuildSnapshotPort(
        policy=fixture.policy,
        finality=finality,
        proofs=_Proofs(fixture.capture.observations, _snapshot_values(expected)),
        validator_hotkey=fixture.validator,
    )

    with pytest.raises(LiveWeightPortError, match="weight_snapshot_finalized_block_mismatch"):
        await port(fixture.work, roots, schedule)


def test_live_weight_ports_reject_rehearsal_policy(tmp_path) -> None:
    fixture = _fixture(tmp_path)
    policy, _wallets = _shadow_fixture()

    with pytest.raises(ValueError, match="complete production pins"):
        LiveWeightSchedulePort(
            policy=policy.policy,
            finality=_Finality(fixture, fixture.capture.observations),
            proofs=_Proofs(fixture.capture.observations),
        )
