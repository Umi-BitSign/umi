from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from fractions import Fraction
from types import SimpleNamespace

import pytest

from umi.chain_evidence import FinalizedSnapshotRef, StorageEvidence
from umi.encoding import account_id32
from umi.policy import SCORING_POLICY_MEDIA_TYPE, ScoringPolicy, scoring_policy_hash
from umi.protocol import PROTOCOL_VERSION, base64url_encode, canonical_json_bytes
from umi.rolling import AssignmentScore, ScoredBatch
from umi.validator_adapters import CompleteStageEffect, TerminalStageEffect
from umi.validator_chain import (
    DecodedStorageClaim,
    FinalizedRuntimePin,
    MultiStorageEvidence,
    PinnedRuntimeContext,
    StorageClaim,
    StorageReadSpec,
    VerifiedStorageBatch,
    VerifiedStorageRead,
)
from umi.validator_chain_scan import VerifiedFinalizedBlockIdentity
from umi.validator_journal import StageObjectInput, ValidatorStageJournal
from umi.validator_protocol_state import (
    ProtocolStatePolicyLimits,
    ValidatorProtocolStateStore,
)
from umi.validator_reveal_effect import (
    REVEAL_STAGE_SCHEMA,
    RevealObjectRef,
    RevealStageManifest,
)
from umi.validator_state import StageEvidence, StageWorkItem, WindowStage
from umi.validator_weight_build_effect import (
    ProofBackedWeightBuildCloseResolver,
    ProofBackedWeightBuildReplayHook,
    ShadowWeightBuildEffect,
    VerifiedWeightBuildSnapshot,
    WeightBuildBindingError,
    WeightBuildEffectPorts,
    WeightBuildPending,
    WeightBuildResultEvidence,
    WeightBuildSnapshotEvidence,
    WeightScheduleCapture,
    replay_weight_build_stage_receipt,
)
from umi.validator_weight_schedule import (
    VerifiedWeightScheduleObservation,
    WeightScheduleIdentity,
)
from umi.window import QUICKNET_GENESIS_MS, QUICKNET_PERIOD_MS

from .test_validator_closing_snapshot import FINALITY_VERIFIER, METADATA, _live_policy, _work
from .test_validator_protocol_state import _issued_roots

RUNTIME_VERSION = canonical_json_bytes(
    {"specVersion": 452, "stateVersion": 1, "transactionVersion": 1}
)


def _synthetic_reveal_resolved(policy, receipt, objects):
    manifests = []
    for reference in receipt.objects:
        data = objects[reference.sha256]
        try:
            value = json.loads(data)
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if isinstance(value, dict) and value.get("schema") == REVEAL_STAGE_SCHEMA:
            manifests.append(RevealStageManifest.model_validate(value))
    assert len(manifests) == 1
    manifest = manifests[0]
    transition = json.loads(objects[manifest.protocol_transition_result.sha256])
    return SimpleNamespace(
        manifest=manifest,
        policy=policy,
        result=SimpleNamespace(
            window_id=manifest.window_id,
            window_index=manifest.window_index,
            scoring_policy_hash=manifest.scoring_policy_hash,
            void_reason_codes=[],
        ),
        resulting_protocol_state_digest=transition["state"]["state_digest"],
    )


@pytest.fixture(autouse=True)
def _stub_full_reveal_replay(monkeypatch: pytest.MonkeyPatch):
    def from_record(record, journal):
        objects = {item.sha256: journal.read_object(item) for item in record.receipt.objects}
        policies = [
            ScoringPolicy.model_validate(json.loads(data))
            for data in objects.values()
            if isinstance((value := json.loads(data)), dict)
            and value.get("schema") == "umi-scoring-policy/1"
        ]
        assert len(policies) == 1
        return _synthetic_reveal_resolved(policies[0], record.receipt, objects)

    monkeypatch.setattr(
        "umi.validator_weight_build_effect.resolve_reveal_stage_record",
        from_record,
    )
    monkeypatch.setattr(
        "umi.validator_weight_build_effect.resolve_reveal_receipt",
        _synthetic_reveal_resolved,
    )


class _FakeRuntime:
    def storage_key(self, pallet: str, item: str, params: list[object]) -> bytes:
        normalized: list[object] = []
        for index, value in enumerate(params):
            if item in {"Uids", "HotkeySuccessor", "HotkeyRoot"} and index == 1:
                normalized.append(account_id32(value).hex())  # type: ignore[arg-type]
            else:
                normalized.append(value)
        return hashlib.sha256(
            b"weight-build-test-key-v1\0"
            + canonical_json_bytes({"item": item, "pallet": pallet, "params": normalized})
        ).digest()

    def storage_entry(self, _pallet: str, item: str):
        return SimpleNamespace(
            modifier=(
                "Optional" if item in {"Uids", "HotkeySuccessor", "HotkeyRoot"} else "Default"
            ),
            default_bytes=canonical_json_bytes(False),
            value_type=item,
        )

    def decode(self, _value_type: str, encoded: bytes, *, strict: bool) -> object:
        assert strict
        return json.loads(encoded)

    def constant(self, pallet: str, name: str) -> int:
        assert (pallet, name) == ("System", "SS58Prefix")
        return 42


def _policy() -> ScoringPolicy:
    return _live_policy()


def _scored_window(window_index: int) -> tuple[ScoredBatch, ScoredBatch]:
    roots = (b"A" * 32, b"B" * 32)
    result: list[ScoredBatch] = []
    for pool_ordinal in (1, 2):
        raw_ids = tuple(
            window_index.to_bytes(8, "big")
            + pool_ordinal.to_bytes(4, "big")
            + ordinal.to_bytes(4, "big")
            for ordinal in range(7)
        )
        challenge_ids = tuple(base64url_encode(value) for value in raw_ids)
        strata = (
            "fingerspelling",
            "fingerspelling",
            "short_utterance",
            "short_utterance",
            "continuous",
            "continuous",
            "continuous",
        )
        assignments = tuple(
            AssignmentScore(
                miner_root=root,
                challenge_id=challenge_ids[ordinal],
                request_leaf=hashlib.sha256(b"weight-request\0" + root + raw_ids[ordinal]).digest(),
                stratum=strata[ordinal],  # type: ignore[arg-type]
                canary=ordinal == 6,
                score=None if ordinal == 6 else Fraction(3, 4),
            )
            for root in roots
            for ordinal in range(7)
        )
        result.append(
            ScoredBatch(
                window_index=window_index,
                batch_rank=bytes([pool_ordinal]) * 32,
                pool_leaf=hashlib.sha256(
                    f"weight-pool-{window_index}-{pool_ordinal}".encode()
                ).digest(),
                challenge_ids=challenge_ids,
                miner_roots=roots,
                assignments=assignments,
            )
        )
    return result[0], result[1]


def _runtime_pin(policy: ScoringPolicy) -> FinalizedRuntimePin:
    live = policy.implementation_pins.live_chain
    assert live is not None
    return FinalizedRuntimePin(
        metadata_sha256=live.metadata_sha256,
        spec_version=live.runtime_spec_version,
        transaction_version=live.transaction_version,
        state_version=live.state_version,
        ss58_prefix=42,
    )


def _block(height: int) -> FinalizedSnapshotRef:
    return FinalizedSnapshotRef(
        block_number=height,
        block_hash="0x" + hashlib.sha256(f"block-{height}".encode()).hexdigest(),
        parent_hash="0x" + hashlib.sha256(f"block-{height - 1}".encode()).hexdigest(),
        state_root="0x" + hashlib.sha256(f"state-{height}".encode()).hexdigest(),
    )


def _identity(height: int, attestation: bytes) -> VerifiedFinalizedBlockIdentity:
    return VerifiedFinalizedBlockIdentity(
        snapshot=_block(height),
        parent_snapshot=_block(height - 1),
        extrinsics_root="0x" + hashlib.sha256(f"extrinsics-{height}".encode()).hexdigest(),
        finality_verifier_sha256=FINALITY_VERIFIER,
        finality_evidence_sha256=hashlib.sha256(attestation).hexdigest(),
    )


def _runtime(policy: ScoringPolicy, snapshot: FinalizedSnapshotRef) -> PinnedRuntimeContext:
    return PinnedRuntimeContext(
        snapshot=snapshot,
        pin=_runtime_pin(policy),
        metadata_bytes=METADATA,
        runtime_version_bytes=RUNTIME_VERSION,
        _runtime=_FakeRuntime(),
    )


def _schedule(policy: ScoringPolicy, work: StageWorkItem) -> WeightScheduleCapture:
    reveal_time = QUICKNET_GENESIS_MS + (work.window.plan.reveal_round - 1) * QUICKNET_PERIOD_MS
    observations: list[VerifiedWeightScheduleObservation] = []
    for height in range(99, 164):
        attestation = canonical_json_bytes({"height": height})
        identity = _identity(height, attestation)
        runtime = _runtime(policy, identity.snapshot)
        epoch = 5 if height < 132 else 6
        key = runtime.storage_key("SubtensorModule", "SubnetEpochIndex", (78,))
        raw = canonical_json_bytes(epoch)
        evidence = StorageEvidence(
            snapshot=identity.snapshot,
            storage_key=key,
            value=raw,
            proof=(f"epoch-proof-{height}".encode(),),
            verifier=lambda **_kwargs: True,
        )
        read = VerifiedStorageRead(
            runtime=runtime,
            pallet="SubtensorModule",
            item="SubnetEpochIndex",
            params=(78,),
            evidence=evidence,
            decoded_value=epoch,
        )
        observations.append(
            VerifiedWeightScheduleObservation(
                identity=identity,
                timestamp_ms=reveal_time + (height - 100) * 1_000,
                chain_genesis_hash=policy.implementation_pins.live_chain.genesis_block_hash,  # type: ignore[union-attr]
                finality_attestation=attestation,
                subnet_epoch_index_read=read,
            )
        )
    return WeightScheduleCapture(
        observations=tuple(observations),
        identity=WeightScheduleIdentity(
            chain_genesis_hash=policy.implementation_pins.live_chain.genesis_block_hash,  # type: ignore[union-attr]
            finality_verifier_sha256=FINALITY_VERIFIER,
            runtime_pin=_runtime_pin(policy),
        ),
    )


def _batch(
    policy: ScoringPolicy,
    identity: VerifiedFinalizedBlockIdentity,
    specs_and_values: list[tuple[StorageReadSpec, object]],
) -> VerifiedStorageBatch:
    runtime = _runtime(policy, identity.snapshot)
    keyed = sorted(
        (
            runtime.storage_key(spec.pallet, spec.item, spec.params),
            spec,
            value,
        )
        for spec, value in specs_and_values
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
        snapshot=identity.snapshot,
        claims=tuple(claims),
        proof=(b"weight-build-proof",),
        verifier=lambda **_kwargs: True,
    )
    return VerifiedStorageBatch(runtime=runtime, evidence=evidence, reads=tuple(reads))


def _snapshot(
    policy: ScoringPolicy,
    capture: WeightScheduleCapture,
    roots: tuple[bytes, ...],
    *,
    minimum: int = 2,
    existing_row: list[list[int]] | None = None,
    last_update: int = 120,
    unresolved_root: bytes | None = None,
) -> VerifiedWeightBuildSnapshot:
    observation = next(item for item in capture.observations if item.snapshot.block_number == 132)
    validator = account_id32(policy.validator_registry[0].validator_hotkey)
    permits = [True, False, False, False, False, False]
    updates = [last_update, 0, 0, 0, 0, 0]
    values: list[tuple[StorageReadSpec, object]] = [
        (StorageReadSpec("SubtensorModule", "NetworksAdded", (78,)), True),
        (StorageReadSpec("SubtensorModule", "MechanismCountCurrent", (78,)), 1),
        (StorageReadSpec("SubtensorModule", "SubnetworkN", (78,)), 6),
        (StorageReadSpec("SubtensorModule", "MinAllowedWeights", (78,)), minimum),
        (StorageReadSpec("SubtensorModule", "MaxWeightsLimit", (78,)), 65_535),
        (StorageReadSpec("SubtensorModule", "WeightsVersionKey", (78,)), 7),
        (StorageReadSpec("SubtensorModule", "ValidatorPermit", (78,)), permits),
        (StorageReadSpec("SubtensorModule", "LastUpdate", (78,)), updates),
        (StorageReadSpec("SubtensorModule", "ActivityCutoffFactorMilli", (78,)), 100),
        (StorageReadSpec("SubtensorModule", "Tempo", (78,)), 360),
        (StorageReadSpec("SubtensorModule", "Uids", (78, validator)), 0),
        (
            StorageReadSpec("SubtensorModule", "Keys", (78, 0)),
            policy.validator_registry[0].validator_hotkey,
        ),
        (
            StorageReadSpec("SubtensorModule", "Weights", (78, 0, 0)),
            existing_row or [],
        ),
    ]
    for uid, root in enumerate(roots, start=1):
        values.extend(
            (
                (
                    StorageReadSpec("SubtensorModule", "HotkeySuccessor", (78, root)),
                    None,
                ),
                (
                    StorageReadSpec("SubtensorModule", "Uids", (78, root)),
                    None if root == unresolved_root else uid,
                ),
            )
        )
        if root != unresolved_root:
            values.extend(
                (
                    (
                        StorageReadSpec("SubtensorModule", "Keys", (78, uid)),
                        __import__("bittensor").sp_core.ss58_encode(root),
                    ),
                    (
                        StorageReadSpec("SubtensorModule", "HotkeyRoot", (78, root)),
                        None,
                    ),
                )
            )
    batch = _batch(policy, observation.identity, values)
    return VerifiedWeightBuildSnapshot(
        identity=observation.identity,
        timestamp_ms=observation.timestamp_ms,
        chain_genesis_hash=observation.chain_genesis_hash,
        finality_attestation=observation.finality_attestation,
        storage_batches=(batch,),
        requested_roots=roots,
    )


def _ref(data: bytes, media_type: str = "application/json") -> RevealObjectRef:
    return RevealObjectRef(
        sha256=hashlib.sha256(data).hexdigest(),
        media_type=media_type,
        size_bytes=len(data),
    )


@dataclass
class _Fixture:
    policy: ScoringPolicy
    work: StageWorkItem
    store: ValidatorProtocolStateStore
    journal: ValidatorStageJournal
    capture: WeightScheduleCapture
    validator: bytes


def _fixture(tmp_path, *, minimum: int = 2) -> _Fixture:
    policy = _policy()
    initial = _work(policy)
    plan = initial.window.plan
    batches = _scored_window(plan.window_index)
    store = ValidatorProtocolStateStore(tmp_path / "protocol.sqlite3")
    transition_operation = b"T" * 32
    transition_evidence = b"E" * 32
    applied = store.apply_window(
        operation_id=transition_operation,
        window_index=plan.window_index,
        window_id=bytes.fromhex(plan.window_id),
        reveal_round=plan.reveal_round,
        evidence_digest=transition_evidence,
        spent_cohort_batches=(),
        objective_fault_findings=(),
        scored_batches=batches,
        issued_miner_roots=_issued_roots(batches),
        policy_limits=ProtocolStatePolicyLimits(
            rolling_batch_count=policy.limits.rolling_batch_count,
            score_max_age_windows=policy.limits.score_max_age_windows,
            publisher_fault_cooldown_windows=policy.limits.publisher_fault_cooldown_windows,
        ),
    )
    journal = ValidatorStageJournal(tmp_path / "journal")
    records = []
    for stage in (
        WindowStage.POOL_AND_SELECTION,
        WindowStage.ASSIGNMENT,
        WindowStage.REQUEST_TRANSCRIPT,
        WindowStage.SEALED_RESPONSE,
    ):
        records.append(
            journal.record(
                window_id=plan.window_id,
                stage=stage,
                operation_id=f"test-{stage.value}",
                objects=(
                    StageObjectInput(
                        canonical_json_bytes({"stage": stage.value}),
                        "application/json",
                    ),
                ),
            )
        )

    dummy = canonical_json_bytes({"dummy": True})
    reveal_result = canonical_json_bytes(
        {
            "schema": "umi-validator-reveal-result/1",
            "scoring_policy_hash": scoring_policy_hash(policy),
            "void_reason_codes": [],
            "window_id": plan.window_id,
            "window_index": plan.window_index,
        }
    )
    policy_bytes = canonical_json_bytes(policy)
    reference = _ref(dummy)
    manifest = RevealStageManifest(
        schema=REVEAL_STAGE_SCHEMA,
        protocol=PROTOCOL_VERSION,
        operation_id="test-reveal",
        transition_operation_id=transition_operation.hex(),
        transition_evidence_sha256=transition_evidence.hex(),
        window_id=plan.window_id,
        window_index=plan.window_index,
        scoring_policy_hash=scoring_policy_hash(policy),
        pool_stage_receipt=reference,
        response_stage_receipt=reference,
        pool_selection_evidence=reference,
        reveal_pulse=reference,
        policy_object=_ref(policy_bytes, SCORING_POLICY_MEDIA_TYPE),
        prior_protocol_state=reference,
        reveal_result=_ref(reveal_result),
        protocol_transition_request=_ref(applied.request_bytes),
        protocol_transition_result=_ref(applied.result_bytes),
        monitoring_transition_request=None,
        monitoring_report=None,
        audit_release_fact=None,
        audit_release_evidence=None,
        decryption_records=[reference],
        plaintext_objects=[],
        source_objects=[reference],
    )
    manifest_bytes = canonical_json_bytes(manifest)
    reveal = journal.record(
        window_id=plan.window_id,
        stage=WindowStage.REVEAL_AND_SCORE,
        operation_id="test-reveal",
        objects=tuple(
            StageObjectInput(
                data,
                SCORING_POLICY_MEDIA_TYPE if data == policy_bytes else "application/json",
            )
            for data in {
                hashlib.sha256(item).hexdigest(): item
                for item in (
                    dummy,
                    policy_bytes,
                    reveal_result,
                    applied.request_bytes,
                    applied.result_bytes,
                    manifest_bytes,
                )
            }.values()
        ),
    )
    records.append(reveal)
    work = replace(
        initial,
        window=replace(initial.window, stage=WindowStage.WEIGHT_BUILD),
        completed_evidence=tuple(
            StageEvidence(
                window_id=plan.window_id,
                stage=WindowStage(record.receipt.stage),
                evidence_sha256=record.evidence_sha256,
                recorded_at_unix_ns=index + 1,
            )
            for index, record in enumerate(records)
        ),
    )
    del minimum
    return _Fixture(
        policy=policy,
        work=work,
        store=store,
        journal=journal,
        capture=_schedule(policy, work),
        validator=account_id32(policy.validator_registry[0].validator_hotkey),
    )


async def _run(
    fixture: _Fixture,
    *,
    minimum: int = 2,
    existing_row: list[list[int]] | None = None,
    last_update: int = 120,
    unresolved_root: bytes | None = None,
):
    async def schedule(_work):
        return fixture.capture

    async def snapshot(_work, roots, _schedule_value):
        return _snapshot(
            fixture.policy,
            fixture.capture,
            roots,
            minimum=minimum,
            existing_row=existing_row,
            last_update=last_update,
            unresolved_root=unresolved_root,
        )

    effect = ShadowWeightBuildEffect(
        policy=fixture.policy,
        journal=fixture.journal,
        protocol_state=fixture.store,
        ports=WeightBuildEffectPorts(schedule=schedule, snapshot=snapshot),
        validator_hotkey=fixture.validator,
    )
    return await effect.perform(operation_id="test-weight-build", work=fixture.work)


def _record(fixture: _Fixture, result):
    return fixture.journal.record(
        window_id=fixture.work.window.plan.window_id,
        stage=WindowStage.WEIGHT_BUILD,
        operation_id=result.operation_id,
        objects=result.objects,
        metadata=result.receipt_metadata(),
    )


@pytest.mark.asyncio
async def test_shadow_weight_build_recomputes_and_receipt_replays(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _fixture(tmp_path)
    result = await _run(fixture, existing_row=[[3, 100]])
    assert isinstance(result.decision, CompleteStageEffect)
    record = _record(fixture, result)
    payloads = {item.sha256: fixture.journal.read_object(item) for item in record.receipt.objects}
    monkeypatch.setattr(
        "umi.validator_weight_build_effect.bittensor_core.Runtime",
        lambda *_a, **_k: _FakeRuntime(),
    )
    replay = replay_weight_build_stage_receipt(
        record.receipt, payloads, verifier=lambda **_kwargs: True
    )
    assert replay.weight_build is not None
    assert len(replay.result.quantized_row) == 2
    assert replay.snapshot.prior_row_classification == "previous_row_active"
    close = ProofBackedWeightBuildCloseResolver(lambda **_kwargs: True)(
        policy=fixture.policy, receipt=record, objects=payloads
    )
    assert close.block_number == 163
    evidence = SimpleNamespace(
        stage_id=WindowStage.WEIGHT_BUILD.value,
        window_id=record.receipt.window_id,
    )
    assert ProofBackedWeightBuildReplayHook(lambda **_kwargs: True)(
        policy=fixture.policy,
        evidence=evidence,
        receipt=record.receipt,
        objects=payloads,
    )


@pytest.mark.asyncio
async def test_under_floor_skips_without_uniform_fallback(tmp_path) -> None:
    fixture = _fixture(tmp_path)
    result = await _run(fixture, minimum=3)
    assert isinstance(result.decision, TerminalStageEffect)
    assert result.decision.reason_code == "positive_utilities_below_min_allowed_weights"
    result_object = next(
        item.data
        for item in result.objects
        if json.loads(item.data).get("schema") == "umi-validator-weight-build-result/1"
    )
    parsed = WeightBuildResultEvidence.model_validate_json(result_object)
    assert parsed.quantized_row == []
    assert parsed.uid_vector == []


@pytest.mark.asyncio
async def test_unresolved_destination_is_dropped_then_fails_live_floor(tmp_path) -> None:
    fixture = _fixture(tmp_path)
    result = await _run(fixture, unresolved_root=b"B" * 32)
    assert isinstance(result.decision, TerminalStageEffect)
    assert result.decision.reason_code == "resolved_destinations_below_min_allowed_weights"


@pytest.mark.asyncio
async def test_prior_row_inactive_classification_is_evidenced(tmp_path) -> None:
    fixture = _fixture(tmp_path)
    result = await _run(fixture, existing_row=[[3, 100]], last_update=1)
    snapshot_object = next(
        item.data
        for item in result.objects
        if json.loads(item.data).get("schema") == "umi-validator-weight-build-snapshot/1"
    )
    parsed = WeightBuildSnapshotEvidence.model_validate_json(snapshot_object)
    assert parsed.prior_row_classification == "previous_row_inactive"


@pytest.mark.asyncio
async def test_receipt_replay_rejects_missing_tampered_and_unverified_objects(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _fixture(tmp_path)
    record = _record(fixture, await _run(fixture))
    payloads = {item.sha256: fixture.journal.read_object(item) for item in record.receipt.objects}
    monkeypatch.setattr(
        "umi.validator_weight_build_effect.bittensor_core.Runtime",
        lambda *_a, **_k: _FakeRuntime(),
    )
    missing = dict(payloads)
    missing.pop(next(iter(missing)))
    with pytest.raises(WeightBuildBindingError, match="object_graph_incomplete"):
        replay_weight_build_stage_receipt(record.receipt, missing, verifier=lambda **_kwargs: True)
    tampered = dict(payloads)
    digest = next(iter(tampered))
    tampered[digest] += b"x"
    with pytest.raises(WeightBuildBindingError, match="object_metadata_mismatch"):
        replay_weight_build_stage_receipt(record.receipt, tampered, verifier=lambda **_kwargs: True)
    with pytest.raises(WeightBuildBindingError, match="proof"):
        replay_weight_build_stage_receipt(
            record.receipt, payloads, verifier=lambda **_kwargs: False
        )


@pytest.mark.asyncio
async def test_future_schedule_observations_are_pending(tmp_path) -> None:
    fixture = _fixture(tmp_path)
    fixture.capture = replace(fixture.capture, observations=fixture.capture.observations[:20])
    with pytest.raises(WeightBuildPending, match="base_epoch_observation_pending"):
        await _run(fixture)
