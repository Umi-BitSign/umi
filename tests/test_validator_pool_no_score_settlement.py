from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi.calibration_bundle import (
    CALIBRATION_RECEIPT_MEDIA_TYPE,
    CALIBRATION_STAGE_SCHEMA,
    CalibrationObject,
    CalibrationStageEvidence,
    calibration_stage_replay_hook_id,
)
from umi.policy import ScoringPolicy, scoring_policy_hash
from umi.protocol import PROTOCOL_VERSION, GroundTruthPayload, canonical_json_bytes
from umi.registries import spent_batch_leaf, spent_frame_leaf, spent_script_leaf, spent_video_leaf
from umi.validator_adapters import (
    JournalStageAdapter,
    TerminalStageEffect,
    stage_operation_id,
    stage_result_from_receipt,
)
from umi.validator_assignments import ValidatorAssignmentStore
from umi.validator_bundle_ports import TranscriptStageReplayHook
from umi.validator_extrinsics import ValidatorExtrinsicJournal
from umi.validator_journal import ValidatorStageJournal
from umi.validator_plans import VerifiedFinalizedBlock
from umi.validator_pool_no_score import PoolNoScoreEvidence, PoolNoScoreReplay
from umi.validator_pool_replay import resolve_pool_stage
from umi.validator_protocol_state import ValidatorProtocolStateStore
from umi.validator_readiness import ProofBackedPriorWindowReadiness, VerifiedPublishedBundle
from umi.validator_reveal_effect import (
    POOL_NO_SCORE_REVEAL_RESULT_SCHEMA,
    REVEAL_AUDIT_RELEASE_SCHEMA,
    PoolNoScoreRevealResult,
    RevealAuditRelease,
    RevealEffectPorts,
    RevealTransitionCoordinator,
    ValidatorRevealEffect,
    VerifiedRevealAuditRelease,
    resolve_reveal_stage_record,
)
from umi.validator_state import (
    StageCompletion,
    StageEvidence,
    TerminalDecision,
    TerminalOutcome,
    WindowStage,
)
from umi.validator_transcript_abort import DurableTranscriptAbortRegistry
from umi.validator_transcript_effects import (
    AssignmentTranscriptEffect,
    RequestTranscriptEffect,
    SealedResponseTranscriptEffect,
    TranscriptEffectPorts,
    replay_transcript_stage_record,
)
from umi.validator_window_material import ValidatorWindowMaterialStore

from . import test_shadow as shadow_test_support
from .test_policy import _live_shadow_policy_data
from .test_validator_reveal_effect import Harness, _stage_evidence, _work
from .test_validator_transcript_abort_settlement import _BundleVerifier, _Finality

_TRANSCRIPT_STAGES = (
    WindowStage.ASSIGNMENT,
    WindowStage.REQUEST_TRANSCRIPT,
    WindowStage.SEALED_RESPONSE,
)


def _configure_reason(harness: Harness, reason: str) -> None:
    closing = harness.fixture.closing.snapshot
    if reason == "candidate_pool_empty":
        publishers = [row.model_copy(update={"registered": False}) for row in closing.publishers]
        closing = closing.model_copy(update={"publishers": publishers})
    elif reason == "candidate_control_group_count_insufficient":
        publishers = [
            row if index == 0 else row.model_copy(update={"registered": False})
            for index, row in enumerate(closing.publishers)
        ]
        closing = closing.model_copy(update={"publishers": publishers})
    elif reason == "eligible_miner_set_empty":
        neurons = [row.model_copy(update={"validator_permit": True}) for row in closing.neurons]
        closing = closing.model_copy(update={"neurons": neurons})
    else:  # pragma: no cover - test helper contract
        raise ValueError(reason)
    harness.fixture.closing = replace(
        harness.fixture.closing,
        snapshot=closing,
        snapshot_bytes=canonical_json_bytes(closing),
    )


def _unused(*_args, **_kwargs):  # pragma: no cover - propagation must bypass ports
    raise AssertionError("pool no-score propagation called an external transcript port")


async def _unused_transport(*_args, **_kwargs):  # pragma: no cover
    raise AssertionError("pool no-score propagation attempted miner transport")


def _transcript_effect(stage: WindowStage, root: Path, registry: DurableTranscriptAbortRegistry):
    ports = TranscriptEffectPorts(
        plan=_unused,
        observe=_unused,
        anchor_ports=_unused,
        verify_anchor=_unused,
        audit_release_block=_unused,
        transport=_unused_transport,
    )
    common = {
        "assignments": ValidatorAssignmentStore(root / "assignments"),
        "extrinsics": ValidatorExtrinsicJournal(root / "extrinsics"),
        "ports": ports,
        "abort_registry": registry,
        "maximum_anchor_advances": 4,
    }
    if stage is WindowStage.ASSIGNMENT:
        return AssignmentTranscriptEffect(**common)
    if stage is WindowStage.REQUEST_TRANSCRIPT:
        return RequestTranscriptEffect(
            **common,
            maximum_transport_concurrency=4,
            transport_timeout_seconds=1,
        )
    return SealedResponseTranscriptEffect(**common)


async def _pool_no_score_prefix(
    root: Path,
    harness: Harness,
    *,
    reason: str,
):
    _configure_reason(harness, reason)
    registry_path = root / "assignments" / "abort-registry"
    registry = DurableTranscriptAbortRegistry(registry_path)
    pool_effect = harness.fixture.effect(abort_registry=registry)
    operation = stage_operation_id(
        harness.fixture.window.window_id,
        WindowStage.POOL_AND_SELECTION,
    )
    pool_result = await pool_effect.perform(operation_id=operation, work=harness.fixture.work)
    pool_record = harness.journal.record(
        window_id=harness.fixture.window.window_id,
        stage=WindowStage.POOL_AND_SELECTION,
        operation_id=operation,
        objects=pool_result.objects,
        metadata=pool_result.receipt_metadata(),
    )
    # Restart after the receipt write. The recovered adapter must bind the durable
    # origin without rerunning pool collection or assignment preparation.
    recovered_pool = JournalStageAdapter(
        stage=WindowStage.POOL_AND_SELECTION,
        journal=harness.journal,
        effect=harness.fixture.effect(abort_registry=DurableTranscriptAbortRegistry(registry_path)),
    )
    completion = await recovered_pool.execute(harness.fixture.work)
    assert completion.evidence_sha256 == pool_record.evidence_sha256
    assert harness.fixture.prepared_calls == 0

    evidence: list[StageEvidence] = [_stage_evidence(harness.fixture.window.window_id, pool_record)]
    origin: PoolNoScoreEvidence | None = None
    for stage in _TRANSCRIPT_STAGES:
        work = _work(harness.fixture.window, stage, tuple(evidence))
        effect = _transcript_effect(
            stage,
            root,
            DurableTranscriptAbortRegistry(registry_path),
        )
        result = await effect.perform(
            operation_id=stage_operation_id(harness.fixture.window.window_id, stage),
            work=work,
        )
        record = harness.journal.record(
            window_id=harness.fixture.window.window_id,
            stage=stage,
            operation_id=result.operation_id,
            objects=result.objects,
            metadata=result.receipt_metadata(),
        )
        # Restart after every propagation receipt, exercising the idempotent hook.
        recovered = JournalStageAdapter(
            stage=stage,
            journal=harness.journal,
            effect=_transcript_effect(
                stage,
                root,
                DurableTranscriptAbortRegistry(registry_path),
            ),
        )
        stage_completion = await recovered.execute(work)
        assert isinstance(stage_completion, StageCompletion)
        replay = replay_transcript_stage_record(record, harness.journal)
        assert isinstance(replay, PoolNoScoreReplay)
        assert replay.origin.reason_code == reason
        origin = replay.origin
        evidence.append(_stage_evidence(harness.fixture.window.window_id, record))
    assert origin is not None
    return _work(
        harness.fixture.window,
        WindowStage.REVEAL_AND_SCORE,
        tuple(evidence),
    ), origin


def _replay_pool_stage(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
):
    record = harness.journal.load(
        harness.fixture.window.window_id,
        WindowStage.POOL_AND_SELECTION,
    )
    objects = {item.sha256: harness.journal.read_object(item) for item in record.receipt.objects}
    evidence = CalibrationStageEvidence(
        schema=CALIBRATION_STAGE_SCHEMA,
        protocol=PROTOCOL_VERSION,
        window_id=record.receipt.window_id,
        scoring_policy_hash=harness.fixture.window.scoring_policy_hash,
        stage_id=WindowStage.POOL_AND_SELECTION.value,
        replay_hook_id=calibration_stage_replay_hook_id(
            harness.fixture.policy,
            WindowStage.POOL_AND_SELECTION.value,
        ),
        previous_stage_evidence_sha256=None,
        receipt_object=CalibrationObject.from_bytes(
            record.receipt_bytes,
            CALIBRATION_RECEIPT_MEDIA_TYPE,
        ),
        payload_objects=[
            CalibrationObject(
                sha256=item.sha256,
                media_type=item.media_type,
                size_bytes=item.size_bytes,
            )
            for item in record.receipt.objects
        ],
    )
    monkeypatch.setattr(
        "umi.validator_pool_replay.replay_announcement_validator_storage",
        lambda proof, *, verifier: SimpleNamespace(evidence=object()),
    )
    monkeypatch.setattr(
        "umi.validator_pool_replay.validate_replayed_announcement_validator_snapshot",
        lambda snapshot, replayed, *, policy: harness.fixture.closing.announcement_snapshot,
    )
    monkeypatch.setattr(
        "umi.validator_pool_replay.replay_closing_snapshot_storage",
        lambda proof, *, verifier: SimpleNamespace(evidence=object()),
    )
    monkeypatch.setattr(
        "umi.validator_pool_replay.validate_replayed_closing_snapshot",
        lambda snapshot, replayed, *, policy: harness.fixture.closing.snapshot,
    )
    monkeypatch.setattr(
        "umi.validator_pool_replay.verify_snapshot_finality",
        lambda proof, **values: None,
    )
    return resolve_pool_stage(
        policy=harness.fixture.policy,
        evidence=evidence,
        receipt=record.receipt,
        objects=objects,
        verifier=lambda **_values: True,
        finality_verifier=lambda **_values: True,
        finality_verifier_sha256="7b" * 32,
    )


def _assert_transcript_hooks(harness: Harness) -> None:
    pool_record = harness.journal.load(
        harness.fixture.window.window_id,
        WindowStage.POOL_AND_SELECTION,
    )
    previous = pool_record.evidence_sha256
    for stage in _TRANSCRIPT_STAGES:
        record = harness.journal.load(harness.fixture.window.window_id, stage)
        objects = {
            item.sha256: harness.journal.read_object(item) for item in record.receipt.objects
        }
        evidence = CalibrationStageEvidence(
            schema=CALIBRATION_STAGE_SCHEMA,
            protocol=PROTOCOL_VERSION,
            window_id=record.receipt.window_id,
            scoring_policy_hash=harness.fixture.window.scoring_policy_hash,
            stage_id=stage.value,
            replay_hook_id=calibration_stage_replay_hook_id(
                harness.fixture.policy,
                stage.value,
            ),
            previous_stage_evidence_sha256=previous,
            receipt_object=CalibrationObject.from_bytes(
                record.receipt_bytes,
                CALIBRATION_RECEIPT_MEDIA_TYPE,
            ),
            payload_objects=[
                CalibrationObject(
                    sha256=item.sha256,
                    media_type=item.media_type,
                    size_bytes=item.size_bytes,
                )
                for item in record.receipt.objects
            ],
        )
        assert TranscriptStageReplayHook(stage.value)(
            policy=harness.fixture.policy,
            evidence=evidence,
            receipt=record.receipt,
            objects=objects,
        )
        previous = record.evidence_sha256


def _restarted_reveal_effect(root: Path, harness: Harness) -> ValidatorRevealEffect:
    async def decrypt(sealed, _pulse):
        return harness.ground_truth_by_ciphertext[sealed.sha256_hex]

    async def audit_release(work, reason):
        evidence = canonical_json_bytes({"kind": "pool-no-score-release", "reason": reason})
        return VerifiedRevealAuditRelease(
            fact=RevealAuditRelease(
                schema=REVEAL_AUDIT_RELEASE_SCHEMA,
                window_id=work.window.plan.window_id,
                reason_code=reason,
                audit_release_block=1_600,
                evidence_sha256=hashlib.sha256(evidence).hexdigest(),
            ),
            evidence_bytes=evidence,
        )

    protocol_state = ValidatorProtocolStateStore(root / "protocol.sqlite3")
    harness.fixture.protocol_state = protocol_state
    return ValidatorRevealEffect(
        policy=harness.fixture.policy,
        validator_hotkey=harness.fixture.validator_wallet.hotkey.ss58_address,
        journal=ValidatorStageJournal(root / "journal"),
        material_store=ValidatorWindowMaterialStore(root / "materials"),
        protocol_state=protocol_state,
        monitoring_state=harness.monitoring,
        coordinator=RevealTransitionCoordinator(root / "reveal.sqlite3"),
        ports=RevealEffectPorts(
            reveal_pulse=lambda _work: harness.reveal_pulse,
            decrypt=decrypt,
            audit_release=audit_release,
        ),
    )


def _expected_spent(harness: Harness, result: PoolNoScoreRevealResult) -> set[bytes]:
    by_batch = {item["batch_id"]: item for item in result.candidate_reveals}
    expected: set[bytes] = set()
    for source in harness.fixture.batch_sources:
        candidate = by_batch.get(source.batch_id)
        if candidate is None:
            continue
        public = json.loads(source.public_manifest_bytes)
        expected.add(spent_batch_leaf(candidate["batch_commitment"]))
        expected.update(spent_video_leaf(item["media"]["sha256"]) for item in public["items"])
        expected.update(spent_frame_leaf(item["media"]["frame_digest"]) for item in public["items"])
        plaintext = harness.ground_truth_by_ciphertext[
            hashlib.sha256(source.ground_truth_envelope_bytes).hexdigest()
        ]
        ground = GroundTruthPayload.model_validate_json(plaintext)
        expected.update(
            spent_script_leaf(script)
            for item in ground.items
            for script in item.retirement_script_sha256s
        )
    return expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("reason", "outcome", "candidate_count"),
    [
        ("candidate_pool_empty", TerminalOutcome.SKIPPED, 0),
        ("candidate_control_group_count_insufficient", TerminalOutcome.VOID, 1),
        ("eligible_miner_set_empty", TerminalOutcome.SKIPPED, 3),
    ],
)
async def test_pool_no_score_settles_after_restart_and_retires_known_candidates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reason: str,
    outcome: TerminalOutcome,
    candidate_count: int,
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    work, origin = await _pool_no_score_prefix(tmp_path, harness, reason=reason)
    assert len(origin.candidates) == candidate_count
    pool_replay = _replay_pool_stage(harness, monkeypatch)
    assert isinstance(pool_replay.selection, PoolNoScoreEvidence)
    assert pool_replay.selection.reason_code == reason
    assert pool_replay.assignment_ids == ()
    _assert_transcript_hooks(harness)
    operation = stage_operation_id(harness.fixture.window.window_id, work.stage)
    first = await _restarted_reveal_effect(tmp_path, harness).perform(
        operation_id=operation,
        work=work,
    )
    assert isinstance(first.decision, TerminalStageEffect)
    assert first.decision.outcome is outcome
    assert first.decision.reason_code == reason
    assert first.decision.audit_release_block == 1_600
    assert first.metadata["pool_no_score_reason_code"] == reason
    assert first.metadata["issued_request_count"] == 0
    assert first.metadata["scored_batch_count"] == 0

    snapshot = harness.fixture.protocol_state.snapshot
    assert snapshot.last_window_index == harness.fixture.window.window_index
    assert snapshot.rolling_scores.batches == ()
    assert snapshot.assigned_observation_counts == ()
    assert snapshot.spent_registry.last_reveal_round == harness.fixture.window.reveal_round

    # Restart after the atomic state transition but before writing the reveal receipt.
    recovered = await _restarted_reveal_effect(tmp_path, harness).perform(
        operation_id=operation,
        work=work,
    )
    assert recovered.objects == first.objects
    assert recovered.metadata == first.metadata
    assert recovered.decision == first.decision

    journal = ValidatorStageJournal(tmp_path / "journal")
    record = journal.record(
        window_id=recovered.window_id,
        stage=recovered.stage,
        operation_id=recovered.operation_id,
        objects=recovered.objects,
        metadata=recovered.receipt_metadata(),
    )
    terminal = stage_result_from_receipt(record)
    assert isinstance(terminal, TerminalDecision)
    assert terminal.outcome is outcome
    resolved = resolve_reveal_stage_record(record, journal)
    assert isinstance(resolved.result, PoolNoScoreRevealResult)
    assert resolved.result.schema_ == POOL_NO_SCORE_REVEAL_RESULT_SCHEMA
    assert resolved.result.pool_no_score.reason_code == reason
    assert resolved.result.scored_batches == []
    assert resolved.result.monitoring_observations == []
    assert resolved.result.issued_request_count == 0
    assert set(snapshot.spent_registry.leaves) == _expected_spent(harness, resolved.result)


@pytest.mark.asyncio
async def test_pool_no_score_applies_objective_fault_and_allows_next_window_readiness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    live_policy = ScoringPolicy.model_validate(_live_shadow_policy_data())
    monkeypatch.setattr(shadow_test_support, "_policy", lambda *_args: live_policy)
    harness = Harness(tmp_path, monkeypatch)
    first_ciphertext = next(iter(harness.ground_truth_by_ciphertext))
    harness.ground_truth_by_ciphertext[first_ciphertext] = b"{}"
    work, _origin = await _pool_no_score_prefix(
        tmp_path,
        harness,
        reason="eligible_miner_set_empty",
    )
    operation = stage_operation_id(harness.fixture.window.window_id, work.stage)
    result = await _restarted_reveal_effect(tmp_path, harness).perform(
        operation_id=operation,
        work=work,
    )
    assert result.metadata["objective_fault_count"] == 1
    snapshot = harness.fixture.protocol_state.snapshot
    assert len(snapshot.publisher_faults.strikes) == 1
    assert snapshot.rolling_scores.batches == ()

    journal = ValidatorStageJournal(tmp_path / "journal")
    record = journal.record(
        window_id=result.window_id,
        stage=result.stage,
        operation_id=result.operation_id,
        objects=result.objects,
        metadata=result.receipt_metadata(),
    )
    resolved = resolve_reveal_stage_record(record, journal)
    assert isinstance(resolved.result, PoolNoScoreRevealResult)
    assert resolved.result.objective_fault_findings[0]["reason"] == "ground_truth_schema_invalid"

    terminal = stage_result_from_receipt(record)
    assert isinstance(terminal, TerminalDecision)
    previous = replace(
        work.window,
        stage=WindowStage.REVEAL_AND_SCORE,
        terminal_outcome=terminal.outcome,
        terminal_reason_code=terminal.reason_code,
        terminal_evidence_sha256=terminal.evidence_sha256,
        audit_release_block=terminal.audit_release_block,
        revision=work.window.revision + 1,
    )
    release_evidence = b"pool-no-score-release-finality"
    pin = harness.fixture.policy.implementation_pins.finality_verifier
    assert pin is not None
    finality_sha256 = next(iter(pin.release_sha256_by_target.values()))
    block = VerifiedFinalizedBlock(
        height=1_600,
        block_hash="0x" + "ab" * 32,
        state_root="0x" + "cd" * 32,
        timestamp_ms=1_800_000_000_000,
        scoring_policy_hash=scoring_policy_hash(harness.fixture.policy),
        chain_observation=harness.fixture.policy.implementation_pins.live_chain,
        finality_verifier_sha256=finality_sha256,
        finality_evidence=release_evidence,
        finality_evidence_sha256=hashlib.sha256(release_evidence).hexdigest(),
    )
    binding = VerifiedPublishedBundle(
        manifest_sha256="ef" * 32,
        window_id=previous.plan.window_id,
        window_index=previous.plan.window_index,
        scoring_policy_hash=previous.plan.scoring_policy_hash,
        terminal_classification="skipped",
        highest_stage=WindowStage.REVEAL_AND_SCORE.value,
        audit_release_block=1_600,
        audit_release_block_hash=block.block_hash,
        reason_codes=("eligible_miner_set_empty",),
    )
    bundle_root = tmp_path / "bundles"
    (bundle_root / previous.plan.window_id).mkdir(parents=True)
    readiness = ProofBackedPriorWindowReadiness(
        policy=harness.fixture.policy,
        protocol_state=harness.fixture.protocol_state,
        journal=journal,
        bundle_root=bundle_root,
        bundle_verifier=_BundleVerifier(binding),
        finality=_Finality(harness.fixture.policy, block),
    )
    checkpoint = await readiness.verified_reveal_and_spent(previous)
    assert checkpoint is not None
    assert checkpoint.spent_root == snapshot.spent_registry.root.hex()


@pytest.mark.asyncio
async def test_pool_no_score_corrupted_response_receipt_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    work, _origin = await _pool_no_score_prefix(
        tmp_path,
        harness,
        reason="eligible_miner_set_empty",
    )
    response_record = harness.journal.load(
        harness.fixture.window.window_id,
        WindowStage.SEALED_RESPONSE,
    )
    payloads = {
        item.sha256: harness.journal.read_object(item) for item in response_record.receipt.objects
    }
    first_digest = next(iter(payloads))
    payloads[first_digest] = b"{}"
    from umi.validator_transcript_effects import (
        TranscriptReplayError,
        replay_transcript_stage_receipt,
    )

    with pytest.raises(TranscriptReplayError):
        replay_transcript_stage_receipt(response_record.receipt, payloads)

    operation = stage_operation_id(harness.fixture.window.window_id, work.stage)
    result = await _restarted_reveal_effect(tmp_path, harness).perform(
        operation_id=operation,
        work=work,
    )
    journal = ValidatorStageJournal(tmp_path / "journal")
    record = journal.record(
        window_id=result.window_id,
        stage=result.stage,
        operation_id=result.operation_id,
        objects=result.objects,
        metadata=result.receipt_metadata(),
    )
    object_path = journal.root / "objects" / record.receipt.objects[0].sha256
    original = object_path.read_bytes()
    object_path.write_bytes(b"corrupt")
    try:
        with pytest.raises(ValueError, match=r"wrong byte length|SHA-256"):
            resolve_reveal_stage_record(record, journal)
    finally:
        object_path.write_bytes(original)


@pytest.mark.asyncio
async def test_true_empty_source_bypasses_mirror_and_settles_after_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    closing = harness.fixture.closing.snapshot
    publishers = [
        row.model_copy(
            update={
                "pool_manifest_sha256": None,
                "anchor_inclusion_block": None,
            }
        )
        for row in closing.publishers
    ]
    closing = closing.model_copy(update={"publishers": publishers})
    harness.fixture.closing = replace(
        harness.fixture.closing,
        snapshot=closing,
        snapshot_bytes=canonical_json_bytes(closing),
    )
    source_calls = 0

    async def missing_index(_work):
        nonlocal source_calls
        source_calls += 1
        raise AssertionError("zero-anchor settlement must not request a mirror index")

    harness.fixture.source_port = missing_index
    work, origin = await _pool_no_score_prefix(
        tmp_path,
        harness,
        reason="candidate_pool_empty",
    )
    assert source_calls == 0
    assert origin.artifact_retrieval_evidence is None
    assert origin.empty_source_evidence is not None
    assert origin.candidates == []

    pool_replay = _replay_pool_stage(harness, monkeypatch)
    assert isinstance(pool_replay.selection, PoolNoScoreEvidence)
    assert pool_replay.selection.empty_source_evidence is not None

    operation = stage_operation_id(harness.fixture.window.window_id, work.stage)
    result = await _restarted_reveal_effect(tmp_path, harness).perform(
        operation_id=operation,
        work=work,
    )
    assert isinstance(result.decision, TerminalStageEffect)
    assert result.decision.outcome is TerminalOutcome.SKIPPED
    assert result.decision.reason_code == "candidate_pool_empty"
    assert result.metadata["issued_request_count"] == 0
    assert result.metadata["scored_batch_count"] == 0
    assert harness.fixture.protocol_state.snapshot.last_window_index == (
        harness.fixture.window.window_index
    )
    assert harness.fixture.protocol_state.snapshot.spent_registry.leaves == frozenset()
