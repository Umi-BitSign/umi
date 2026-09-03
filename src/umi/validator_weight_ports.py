"""Concrete read-only production ports for shadow weight construction.

The schedule port walks a complete verifier-owned finalized interval and proves
``SubnetEpochIndex`` at every block.  The snapshot port then multiproves exactly
the live SN78 topology, validator row, and root-to-successor-to-UID values consumed
by :class:`ShadowWeightBuildEffect`.  Neither class accepts a wallet, signer, call
builder, submission method, or best-head client.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from .encoding import account_id32
from .policy import ScoringPolicy, scoring_policy_hash
from .validator_chain import (
    FinalizedProofCollector,
    FinalizedRuntimePin,
    StorageReadSpec,
    VerifiedStorageBatch,
)
from .validator_state import StagePending, StageWorkItem, WindowStage
from .validator_weight_build_effect import (
    VerifiedWeightBuildSnapshot,
    WeightScheduleCapture,
)
from .validator_weight_schedule import (
    SUBNET_EPOCH_PALLET,
    SUBNET_EPOCH_STORAGE_ITEM,
    VerifiedWeightScheduleObservation,
    WeightCommitSchedule,
    WeightScheduleIdentity,
    WeightScheduleLimits,
)

_PALLET = "SubtensorModule"
_BASE_ITEMS = (
    "NetworksAdded",
    "MechanismCountCurrent",
    "SubnetworkN",
    "MinAllowedWeights",
    "MaxWeightsLimit",
    "WeightsVersionKey",
    "ValidatorPermit",
    "LastUpdate",
    "ActivityCutoffFactorMilli",
    "Tempo",
)


class LiveWeightPortError(RuntimeError):
    """Stable fail-closed error from concrete live weight evidence collection."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@runtime_checkable
class WeightFinalityPort(Protocol):
    @property
    def chain_observation(self): ...

    @property
    def finality_verifier_sha256(self) -> str: ...

    async def finalized_head_height(self) -> int: ...

    async def verified_scan_interval(self, start_height: int, end_height: int): ...

    async def verified_block_at(self, height: int): ...


@runtime_checkable
class WeightProofPort(Protocol):
    async def pinned_runtime(self, snapshot, pin): ...

    async def storage_read(self, runtime, pallet: str, item: str, params=()): ...

    async def storage_reads(self, runtime, specs: Sequence[StorageReadSpec]): ...


@dataclass(frozen=True, slots=True)
class LiveWeightSchedulePort:
    """Build the complete proof-backed schedule prefix from persisted finality."""

    policy: ScoringPolicy
    finality: WeightFinalityPort
    proofs: WeightProofPort
    limits: WeightScheduleLimits = field(default_factory=WeightScheduleLimits)

    def __post_init__(self) -> None:
        _validate_common(self.policy, self.finality, self.proofs)
        if not isinstance(self.limits, WeightScheduleLimits):
            raise TypeError("limits must be WeightScheduleLimits")

    async def __call__(self, work: StageWorkItem) -> WeightScheduleCapture:
        _validate_schedule_work(work, self.policy)
        identity = _schedule_identity(self.policy, self.finality)
        start = work.window.plan.announcement_block
        try:
            head = await self.finality.finalized_head_height()
        except Exception as error:
            if getattr(error, "reason_code", None) == "no_verified_finalized_head":
                raise StagePending("weight_schedule_finalized_head_pending") from error
            raise LiveWeightPortError("weight_schedule_finalized_head_failed") from error
        if isinstance(head, bool) or not isinstance(head, int) or head < 0:
            raise LiveWeightPortError("weight_schedule_finalized_head_invalid")
        if head < start:
            return WeightScheduleCapture(observations=(), identity=identity)
        if head - start + 1 > self.limits.maximum_observations:
            raise LiveWeightPortError("weight_schedule_observation_count_limit")
        try:
            interval = await self.finality.verified_scan_interval(start, head)
        except Exception as error:
            raise LiveWeightPortError("weight_schedule_finality_interval_failed") from error
        if interval is None:
            raise StagePending("weight_schedule_finality_interval_pending")
        identities = getattr(interval, "identities", None)
        attestations = getattr(interval, "attestations", None)
        if (
            not isinstance(identities, tuple)
            or not isinstance(attestations, tuple)
            or len(identities) != head - start + 1
            or len(attestations) != len(identities)
        ):
            raise LiveWeightPortError("weight_schedule_finality_interval_invalid")

        observations: list[VerifiedWeightScheduleObservation] = []
        runtime_pin = identity.runtime_pin
        for expected_height, finalized_identity, attestation in zip(
            range(start, head + 1), identities, attestations, strict=True
        ):
            if finalized_identity.snapshot.block_number != expected_height:
                raise LiveWeightPortError("weight_schedule_finality_height_mismatch")
            try:
                block = await self.finality.verified_block_at(expected_height)
            except Exception as error:
                raise LiveWeightPortError("weight_schedule_finalized_block_failed") from error
            if block is None:
                raise StagePending("weight_schedule_finalized_block_pending")
            if (
                block.height != expected_height
                or block.block_hash != finalized_identity.snapshot.block_hash
                or block.state_root != finalized_identity.snapshot.state_root
                or block.finality_evidence != attestation
                or block.finality_evidence_sha256 != finalized_identity.finality_evidence_sha256
                or block.finality_verifier_sha256 != finalized_identity.finality_verifier_sha256
            ):
                raise LiveWeightPortError("weight_schedule_finalized_block_mismatch")
            try:
                runtime = await self.proofs.pinned_runtime(
                    finalized_identity.snapshot,
                    runtime_pin,
                )
                epoch_read = await self.proofs.storage_read(
                    runtime,
                    SUBNET_EPOCH_PALLET,
                    SUBNET_EPOCH_STORAGE_ITEM,
                    (78,),
                )
            except Exception as error:
                raise LiveWeightPortError("weight_schedule_epoch_proof_failed") from error
            observations.append(
                VerifiedWeightScheduleObservation(
                    identity=finalized_identity,
                    timestamp_ms=block.timestamp_ms,
                    chain_genesis_hash=identity.chain_genesis_hash,
                    finality_attestation=attestation,
                    subnet_epoch_index_read=epoch_read,
                )
            )
        return WeightScheduleCapture(observations=tuple(observations), identity=identity)


@dataclass(frozen=True, slots=True)
class LiveWeightBuildSnapshotPort:
    """Collect exactly the proof-backed storage graph consumed by weight replay."""

    policy: ScoringPolicy
    finality: WeightFinalityPort
    proofs: WeightProofPort
    validator_hotkey: str | bytes
    maximum_storage_keys_per_proof: int = 1_024

    def __post_init__(self) -> None:
        _validate_common(self.policy, self.finality, self.proofs)
        validator = account_id32(self.validator_hotkey)
        if validator not in {
            account_id32(item.validator_hotkey) for item in self.policy.validator_registry
        }:
            raise ValueError("weight snapshot validator is absent from the policy registry")
        object.__setattr__(self, "validator_hotkey", validator)
        if (
            isinstance(self.maximum_storage_keys_per_proof, bool)
            or not isinstance(self.maximum_storage_keys_per_proof, int)
            or not 1 <= self.maximum_storage_keys_per_proof <= 4_096
        ):
            raise ValueError("maximum storage keys per proof must be between 1 and 4096")

    async def __call__(
        self,
        work: StageWorkItem,
        positive_roots: tuple[bytes, ...],
        schedule: WeightCommitSchedule,
    ) -> VerifiedWeightBuildSnapshot:
        _validate_work(work, self.policy)
        if not isinstance(schedule, WeightCommitSchedule):
            raise TypeError("schedule must be WeightCommitSchedule")
        roots = tuple(account_id32(root) for root in positive_roots)
        if roots != tuple(sorted(set(roots))):
            raise ValueError("positive roots must be unique and sorted")
        validator = account_id32(self.validator_hotkey)
        if validator in roots:
            raise LiveWeightPortError("weight_snapshot_validator_is_positive_root")
        observation = schedule.weight_commit_open_block
        expected_identity = _schedule_identity(self.policy, self.finality)
        if (
            observation.chain_genesis_hash != expected_identity.chain_genesis_hash
            or observation.identity.finality_verifier_sha256
            != expected_identity.finality_verifier_sha256
            or observation.runtime.pin != expected_identity.runtime_pin
        ):
            raise LiveWeightPortError("weight_snapshot_schedule_identity_mismatch")
        await _verify_finalized_open_observation(
            self.finality,
            observation,
            policy_hash=scoring_policy_hash(self.policy),
            chain_observation=self.policy.implementation_pins.live_chain,
        )
        runtime = observation.runtime
        batches: list[VerifiedStorageBatch] = []
        seen_keys: set[bytes] = set()

        base_specs = (
            *(StorageReadSpec(_PALLET, item, (78,)) for item in _BASE_ITEMS),
            StorageReadSpec(_PALLET, "Uids", (78, validator)),
        )
        base_batches = await self._read_batches(runtime, base_specs, seen_keys)
        batches.extend(base_batches)
        base_values = _decoded_values(base_batches)
        validator_uid = _optional_uint(
            _required(base_values, _PALLET, "Uids", (78, validator)),
            "weight_snapshot_validator_uid_invalid",
        )
        if validator_uid is None:
            raise LiveWeightPortError("weight_snapshot_validator_uid_unresolved")

        validator_specs = (
            StorageReadSpec(_PALLET, "Keys", (78, validator_uid)),
            StorageReadSpec(_PALLET, "Weights", (78, 0, validator_uid)),
        )
        validator_batches = await self._read_batches(runtime, validator_specs, seen_keys)
        batches.extend(validator_batches)

        successor_specs = tuple(
            StorageReadSpec(_PALLET, "HotkeySuccessor", (78, root)) for root in roots
        )
        successor_batches = await self._read_batches(runtime, successor_specs, seen_keys)
        batches.extend(successor_batches)
        successor_values = _decoded_values(successor_batches)
        successor_by_root: dict[bytes, bytes] = {}
        for root in roots:
            raw = _required(successor_values, _PALLET, "HotkeySuccessor", (78, root))
            successor_by_root[root] = root if raw is None else account_id32(raw)

        successors = tuple(sorted(set(successor_by_root.values())))
        uid_specs = tuple(StorageReadSpec(_PALLET, "Uids", (78, item)) for item in successors)
        uid_batches = await self._read_batches(runtime, uid_specs, seen_keys)
        batches.extend(uid_batches)
        uid_values = _decoded_values(uid_batches)
        uid_by_successor = {
            successor: _optional_uint(
                _required(uid_values, _PALLET, "Uids", (78, successor)),
                "weight_snapshot_miner_uid_invalid",
            )
            for successor in successors
        }

        resolved_specs: list[StorageReadSpec] = []
        for successor in successors:
            uid = uid_by_successor[successor]
            if uid is None:
                continue
            resolved_specs.extend(
                (
                    StorageReadSpec(_PALLET, "Keys", (78, uid)),
                    StorageReadSpec(_PALLET, "HotkeyRoot", (78, successor)),
                )
            )
        resolved_batches = await self._read_batches(
            runtime,
            tuple(resolved_specs),
            seen_keys,
        )
        batches.extend(resolved_batches)
        if not batches:
            raise LiveWeightPortError("weight_snapshot_storage_batches_empty")
        return VerifiedWeightBuildSnapshot(
            identity=observation.identity,
            timestamp_ms=observation.timestamp_ms,
            chain_genesis_hash=observation.chain_genesis_hash,
            finality_attestation=observation.finality_attestation,
            storage_batches=tuple(batches),
            requested_roots=roots,
        )

    async def _read_batches(
        self,
        runtime,
        specs: Sequence[StorageReadSpec],
        seen_keys: set[bytes],
    ) -> tuple[VerifiedStorageBatch, ...]:
        unique: dict[bytes, StorageReadSpec] = {}
        for spec in specs:
            key = runtime.storage_key(spec.pallet, spec.item, spec.params)
            previous = unique.setdefault(key, spec)
            if previous != spec:
                raise LiveWeightPortError("weight_snapshot_storage_key_alias")
            if key in seen_keys:
                raise LiveWeightPortError("weight_snapshot_duplicate_storage_key")
        ordered = tuple(spec for _key, spec in sorted(unique.items()))
        result: list[VerifiedStorageBatch] = []
        for offset in range(0, len(ordered), self.maximum_storage_keys_per_proof):
            chunk = ordered[offset : offset + self.maximum_storage_keys_per_proof]
            if not chunk:
                continue
            try:
                batch = await self.proofs.storage_reads(runtime, chunk)
            except Exception as error:
                raise LiveWeightPortError("weight_snapshot_storage_proof_failed") from error
            if not isinstance(batch, VerifiedStorageBatch) or batch.runtime != runtime:
                raise LiveWeightPortError("weight_snapshot_storage_batch_invalid")
            result.append(batch)
            seen_keys.update(read.storage_key for read in batch.reads)
        return tuple(result)


def build_live_weight_ports(
    *,
    policy: ScoringPolicy,
    finality: WeightFinalityPort,
    proofs: FinalizedProofCollector,
    validator_hotkey: str | bytes,
    schedule_limits: WeightScheduleLimits | None = None,
    maximum_storage_keys_per_proof: int = 1_024,
):
    """Return the two concrete ports expected by ``WeightBuildEffectPorts``."""

    from .validator_weight_build_effect import WeightBuildEffectPorts

    return WeightBuildEffectPorts(
        schedule=LiveWeightSchedulePort(
            policy=policy,
            finality=finality,
            proofs=proofs,
            limits=schedule_limits or WeightScheduleLimits(),
        ),
        snapshot=LiveWeightBuildSnapshotPort(
            policy=policy,
            finality=finality,
            proofs=proofs,
            validator_hotkey=validator_hotkey,
            maximum_storage_keys_per_proof=maximum_storage_keys_per_proof,
        ),
    )


def _validate_common(
    policy: ScoringPolicy,
    finality: WeightFinalityPort,
    proofs: WeightProofPort,
) -> None:
    if not isinstance(policy, ScoringPolicy) or policy.translation_weights_active:
        raise ValueError("live weight evidence ports require an inactive scoring policy")
    pins = policy.implementation_pins
    if (
        pins.pin_profile != "live_shadow_calibration"
        or pins.live_chain is None
        or pins.finality_verifier is None
        or pins.storage_proof_verifier is None
    ):
        raise ValueError("live weight evidence ports require complete production pins")
    required_finality = (
        "finalized_head_height",
        "verified_scan_interval",
        "verified_block_at",
    )
    if any(not callable(getattr(finality, name, None)) for name in required_finality):
        raise TypeError("finality port lacks a required verified-finality method")
    required_proofs = ("pinned_runtime", "storage_read", "storage_reads")
    if any(not callable(getattr(proofs, name, None)) for name in required_proofs):
        raise TypeError("proof port lacks a required proof-collection method")
    if getattr(finality, "chain_observation", None) != pins.live_chain:
        raise ValueError("weight finality port names another live chain")


def _validate_work(work: StageWorkItem, policy: ScoringPolicy) -> None:
    if not isinstance(work, StageWorkItem) or work.stage is not WindowStage.WEIGHT_BUILD:
        raise LiveWeightPortError("weight_port_received_wrong_stage")
    if work.window.plan.scoring_policy_hash != scoring_policy_hash(policy):
        raise LiveWeightPortError("weight_port_policy_hash_mismatch")


def _validate_schedule_work(work: StageWorkItem, policy: ScoringPolicy) -> None:
    """Allow the common schedule to settle any stage of the same window.

    Transcript incidents and reveal-time voids share the exact Section 10.3
    commit-close boundary with the later weight-build stage.  The schedule is
    read-only and consumes only the window plan, so restricting it to
    ``WEIGHT_BUILD`` would make those earlier terminal paths impossible to
    settle under the production composition.
    """

    if not isinstance(work, StageWorkItem):
        raise LiveWeightPortError("weight_schedule_received_invalid_work")
    if work.window.plan.scoring_policy_hash != scoring_policy_hash(policy):
        raise LiveWeightPortError("weight_port_policy_hash_mismatch")


def _schedule_identity(
    policy: ScoringPolicy,
    finality: WeightFinalityPort,
) -> WeightScheduleIdentity:
    live = policy.implementation_pins.live_chain
    pin = policy.implementation_pins.finality_verifier
    if live is None or pin is None:
        raise LiveWeightPortError("weight_schedule_policy_pins_missing")
    finality_digest = getattr(finality, "finality_verifier_sha256", None)
    if finality_digest not in pin.release_sha256_by_target.values():
        raise LiveWeightPortError("weight_schedule_finality_verifier_mismatch")
    return WeightScheduleIdentity(
        chain_genesis_hash=live.genesis_block_hash,
        finality_verifier_sha256=finality_digest,
        runtime_pin=FinalizedRuntimePin(
            metadata_sha256=live.metadata_sha256,
            spec_version=live.runtime_spec_version,
            transaction_version=live.transaction_version,
            state_version=live.state_version,
            ss58_prefix=42,
        ),
    )


def _decoded_values(
    batches: Sequence[VerifiedStorageBatch],
) -> dict[tuple[str, str, tuple[Any, ...]], Any]:
    result: dict[tuple[str, str, tuple[Any, ...]], Any] = {}
    for batch in batches:
        for read in batch.reads:
            key = (read.spec.pallet, read.spec.item, read.spec.params)
            if key in result:
                raise LiveWeightPortError("weight_snapshot_duplicate_decoded_read")
            result[key] = read.decoded_value
    return result


async def _verify_finalized_open_observation(
    finality: WeightFinalityPort,
    observation: VerifiedWeightScheduleObservation,
    *,
    policy_hash: str,
    chain_observation: object,
) -> None:
    height = observation.snapshot.block_number
    try:
        block = await finality.verified_block_at(height)
    except Exception as error:
        raise LiveWeightPortError("weight_snapshot_finalized_block_failed") from error
    if block is None:
        raise StagePending("weight_snapshot_finalized_block_pending")
    identity = observation.identity
    if (
        block.height != height
        or block.block_hash != identity.snapshot.block_hash
        or block.state_root != identity.snapshot.state_root
        or block.timestamp_ms != observation.timestamp_ms
        or block.scoring_policy_hash != policy_hash
        or block.chain_observation != chain_observation
        or block.finality_verifier_sha256 != identity.finality_verifier_sha256
        or block.finality_evidence != observation.finality_attestation
        or block.finality_evidence_sha256 != identity.finality_evidence_sha256
    ):
        raise LiveWeightPortError("weight_snapshot_finalized_block_mismatch")


def _required(
    values: Mapping[tuple[str, str, tuple[Any, ...]], Any],
    pallet: str,
    item: str,
    params: tuple[Any, ...],
) -> Any:
    key = (pallet, item, params)
    if key not in values:
        raise LiveWeightPortError("weight_snapshot_required_read_missing")
    return values[key]


def _optional_uint(value: Any, reason_code: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 65_535:
        raise LiveWeightPortError(reason_code)
    return value


__all__ = [
    "LiveWeightBuildSnapshotPort",
    "LiveWeightPortError",
    "LiveWeightSchedulePort",
    "WeightFinalityPort",
    "WeightProofPort",
    "build_live_weight_ports",
]
