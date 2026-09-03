from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from umi.artifacts import PublicBatchManifest
from umi.calibration_bundle import (
    CALIBRATION_RECEIPT_MEDIA_TYPE,
    CALIBRATION_STAGE_SCHEMA,
    CalibrationObject,
    CalibrationStageEvidence,
    calibration_stage_replay_hook_id,
)
from umi.policy import ScoringPolicy, scoring_policy_hash
from umi.protocol import (
    PROTOCOL_VERSION,
    GroundTruthPayload,
    canonical_json_bytes,
)
from umi.registries import (
    spent_batch_leaf,
    spent_frame_leaf,
    spent_script_leaf,
    spent_video_leaf,
)
from umi.validator import QueryOutcome
from umi.validator_adapters import (
    JournalStageAdapter,
    TerminalStageEffect,
    stage_operation_id,
    stage_result_from_receipt,
)
from umi.validator_assignments import ValidatorAssignmentStore
from umi.validator_extrinsics import ValidatorExtrinsicJournal
from umi.validator_journal import (
    STAGE_RECEIPT_MEDIA_TYPE,
    StageReceipt,
    ValidatorStageJournal,
)
from umi.validator_plans import VerifiedFinalizedBlock
from umi.validator_protocol_state import ValidatorProtocolStateStore
from umi.validator_readiness import (
    ProofBackedPriorWindowReadiness,
    VerifiedPublishedBundle,
)
from umi.validator_reveal_effect import (
    REVEAL_ABORT_RESULT_SCHEMA,
    RevealBindingError,
    RevealEffectPorts,
    RevealTransitionCoordinator,
    TranscriptAbortRevealResult,
    ValidatorRevealEffect,
    replay_reveal_stage,
    resolve_reveal_stage_record,
)
from umi.validator_state import (
    StageCompletion,
    StageEvidence,
    TerminalDecision,
    TerminalOutcome,
    WindowStage,
)
from umi.validator_transcript_effects import (
    AssignmentTranscriptEffect,
    RequestTranscriptEffect,
    SealedResponseTranscriptEffect,
    TranscriptAbortReplay,
    TranscriptEffectPending,
    TranscriptEffectPorts,
    TranscriptStageReplay,
    replay_transcript_stage_record,
)
from umi.validator_window_material import ValidatorWindowMaterialStore

from . import test_shadow as shadow_test_support
from .test_policy import _live_shadow_policy_data
from .test_validator_reveal_effect import Harness, _stage_evidence, _work
from .test_validator_transcript_effects import AnchorChain, FactPort

_TRANSCRIPT_STAGES = (
    WindowStage.ASSIGNMENT,
    WindowStage.REQUEST_TRANSCRIPT,
    WindowStage.SEALED_RESPONSE,
)


class _BundleVerifier:
    def __init__(self, binding: VerifiedPublishedBundle) -> None:
        self.binding = binding

    async def verify(self, _root: Path) -> VerifiedPublishedBundle:
        return self.binding


class _Finality:
    def __init__(self, policy, block: VerifiedFinalizedBlock) -> None:
        self.chain_observation = policy.implementation_pins.live_chain
        pin = policy.implementation_pins.finality_verifier
        assert pin is not None
        self.finality_verifier_sha256 = next(iter(pin.release_sha256_by_target.values()))
        self.block = block

    async def verified_block_at(self, height: int):
        return self.block if height == self.block.height else None


def _effect_for_stage(
    *,
    stage: WindowStage,
    root: Path,
    ports: TranscriptEffectPorts,
):
    assignments = ValidatorAssignmentStore(root / "assignments")
    extrinsics = ValidatorExtrinsicJournal(root / "extrinsics")
    if stage is WindowStage.ASSIGNMENT:
        return AssignmentTranscriptEffect(
            assignments=assignments,
            extrinsics=extrinsics,
            ports=ports,
            maximum_anchor_advances=4,
        )
    if stage is WindowStage.REQUEST_TRANSCRIPT:
        return RequestTranscriptEffect(
            assignments=assignments,
            extrinsics=extrinsics,
            ports=ports,
            maximum_transport_concurrency=16,
            transport_timeout_seconds=2,
            maximum_anchor_advances=4,
        )
    assert stage is WindowStage.SEALED_RESPONSE
    return SealedResponseTranscriptEffect(
        assignments=assignments,
        extrinsics=extrinsics,
        ports=ports,
        maximum_anchor_advances=4,
    )


async def _abort_prefix(
    root: Path,
    harness: Harness,
    *,
    origin_stage: WindowStage,
) -> tuple[object, tuple[StageEvidence, ...], str]:
    pool_completion = await harness.pool_adapter.execute(harness.fixture.work)
    pool_record = harness.journal.load(
        harness.fixture.window.window_id,
        WindowStage.POOL_AND_SELECTION,
    )
    assert pool_completion.evidence_sha256 == pool_record.evidence_sha256
    evidence = [_stage_evidence(harness.fixture.window.window_id, pool_record)]

    plan = harness.fixture.material_store.load(harness.fixture.window.window_id).plan
    facts = FactPort(plan)
    if origin_stage is WindowStage.ASSIGNMENT:
        facts.overrides["assignment_freeze"] = plan.spec.issue_close_round
        reason = "assignment_freeze_deadline_missed"
    elif origin_stage is WindowStage.REQUEST_TRANSCRIPT:
        facts.overrides["request_freeze"] = plan.spec.response_close_round
        reason = "request_freeze_deadline_missed"
    else:
        facts.overrides["response_freeze"] = plan.spec.reveal_round
        reason = "response_freeze_deadline_missed"
    chain = AnchorChain(plan)

    async def transport(prepared, *_args):
        return QueryOutcome(
            request=prepared.request,
            auth_headers=dict(prepared.auth_headers),
            received_at_unix_ns=None,
            envelope_bytes=None,
            envelope=None,
            response_signature=None,
            sealed_response=None,
            failure_code="transport_error",
        )

    async def release(_work_item, _reason):
        return 1_500

    ports = TranscriptEffectPorts(
        plan=harness.fixture.material_store.load_for_work,
        observe=facts,
        anchor_ports=chain.ports,
        verify_anchor=chain.verify_finality,
        audit_release_block=release,
        transport=transport,
    )

    for stage in _TRANSCRIPT_STAGES:
        # Reopen every durable transcript component between stages.  Propagation
        # must depend on receipt-bound state, not an in-memory exception/value.
        effect = _effect_for_stage(stage=stage, root=root, ports=ports)
        adapter = JournalStageAdapter(stage=stage, journal=harness.journal, effect=effect)
        work = _work(harness.fixture.window, stage, tuple(evidence))
        if stage is origin_stage:
            # Crash exactly after the authoritative receipt lands but before the
            # effect's secondary abort registry is updated.  A fresh adapter must
            # recover the receipt, run the idempotent hook, and never repeat the
            # stage's chain/transport work.
            effect_result = await effect.perform(
                operation_id=stage_operation_id(harness.fixture.window.window_id, stage),
                work=work,
            )
            harness.journal.record(
                window_id=harness.fixture.window.window_id,
                stage=stage,
                operation_id=effect_result.operation_id,
                objects=effect_result.objects,
                metadata=effect_result.receipt_metadata(),
            )
            recovered_effect = _effect_for_stage(stage=stage, root=root, ports=ports)
            recovered_adapter = JournalStageAdapter(
                stage=stage,
                journal=harness.journal,
                effect=recovered_effect,
            )
            completion = await recovered_adapter.execute(work)
        else:
            for _attempt in range(8):
                try:
                    completion = await adapter.execute(work)
                except TranscriptEffectPending:
                    continue
                break
            else:  # pragma: no cover - bounded fake chain must settle
                raise AssertionError(f"{stage.value} did not settle")
        assert isinstance(completion, StageCompletion)
        record = harness.journal.load(harness.fixture.window.window_id, stage)
        evidence.append(_stage_evidence(harness.fixture.window.window_id, record))

        replay = replay_transcript_stage_record(record, harness.journal)
        if _TRANSCRIPT_STAGES.index(stage) < _TRANSCRIPT_STAGES.index(origin_stage):
            assert isinstance(replay, TranscriptStageReplay)
        else:
            assert isinstance(replay, TranscriptAbortReplay)
            assert replay.origin.origin_stage == origin_stage.value
            assert replay.origin.reason_code == reason
            assert replay.origin.audit_release_block == 1_500

    return (
        _work(
            harness.fixture.window,
            WindowStage.REVEAL_AND_SCORE,
            tuple(evidence),
        ),
        tuple(evidence),
        reason,
    )


def _restarted_reveal_effect(root: Path, harness: Harness) -> ValidatorRevealEffect:
    async def decrypt(sealed, _pulse):
        try:
            return harness.ground_truth_by_ciphertext[sealed.sha256_hex]
        except KeyError:
            return harness.response_plaintexts[sealed.sha256_hex]

    async def unused_audit_release(*_args):  # pragma: no cover - abort owns release
        raise AssertionError("an abort settlement must preserve its original release block")

    return ValidatorRevealEffect(
        policy=harness.fixture.policy,
        validator_hotkey=harness.fixture.validator_wallet.hotkey.ss58_address,
        journal=ValidatorStageJournal(root / "journal"),
        material_store=ValidatorWindowMaterialStore(root / "materials"),
        protocol_state=ValidatorProtocolStateStore(root / "protocol.sqlite3"),
        monitoring_state=harness.monitoring,
        coordinator=RevealTransitionCoordinator(root / "reveal.sqlite3"),
        ports=RevealEffectPorts(
            reveal_pulse=lambda _work_item: harness.reveal_pulse,
            decrypt=decrypt,
            audit_release=unused_audit_release,
        ),
    )


def _expected_spent_leaves(harness: Harness, result: TranscriptAbortRevealResult) -> set[bytes]:
    candidate_by_batch = {item["batch_id"]: item for item in result.candidate_reveals}
    expected: set[bytes] = set()
    for source in harness.fixture.batch_sources:
        public = PublicBatchManifest.model_validate_json(source.public_manifest_bytes)
        candidate = candidate_by_batch[public.batch_id]
        expected.add(spent_batch_leaf(candidate["batch_commitment"]))
        expected.update(spent_video_leaf(item.media.sha256) for item in public.items)
        expected.update(spent_frame_leaf(item.media.frame_digest) for item in public.items)
        plaintext = harness.ground_truth_by_ciphertext[
            hashlib.sha256(source.ground_truth_envelope_bytes).hexdigest()
        ]
        ground_truth = GroundTruthPayload.model_validate_json(plaintext)
        expected.update(
            spent_script_leaf(script)
            for item in ground_truth.items
            for script in item.retirement_script_sha256s
        )
    assert set(candidate_by_batch) == {source.batch_id for source in harness.fixture.batch_sources}
    return expected


def _record_reveal(root: Path, result) -> tuple[ValidatorStageJournal, object]:
    journal = ValidatorStageJournal(root / "journal")
    record = journal.record(
        window_id=result.window_id,
        stage=result.stage,
        operation_id=result.operation_id,
        objects=result.objects,
        metadata=result.receipt_metadata(),
    )
    return journal, record


def _is_response_receipt(data: bytes) -> bool:
    try:
        decoded = json.loads(data)
        receipt = StageReceipt.model_validate(decoded)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError):
        return False
    return (
        isinstance(decoded, dict)
        and decoded.get("schema") == "umi-validator-stage-receipt/1"
        and canonical_json_bytes(receipt) == data
        and receipt.stage == WindowStage.SEALED_RESPONSE.value
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("origin_stage", "expected_issued"),
    [
        (WindowStage.ASSIGNMENT, 0),
        (WindowStage.REQUEST_TRANSCRIPT, 0),
        (WindowStage.SEALED_RESPONSE, 56),
    ],
)
async def test_abort_settles_at_reveal_retires_candidates_and_survives_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    origin_stage: WindowStage,
    expected_issued: int,
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    work, prefix_evidence, reason = await _abort_prefix(
        tmp_path,
        harness,
        origin_stage=origin_stage,
    )
    assert harness.fixture.protocol_state.snapshot.last_window_index == -1

    operation = stage_operation_id(harness.fixture.window.window_id, work.stage)
    first = await harness.reveal_effect().perform(operation_id=operation, work=work)
    assert isinstance(first.decision, TerminalStageEffect)
    assert first.decision.outcome is TerminalOutcome.SKIPPED
    assert first.decision.reason_code == reason
    assert first.decision.audit_release_block == 1_500
    assert first.metadata["transcript_abort_origin_stage"] == origin_stage.value
    assert first.metadata["issued_request_count"] == expected_issued
    assert first.metadata["scored_batch_count"] == 0

    snapshot = harness.fixture.protocol_state.snapshot
    assert snapshot.last_window_index == harness.fixture.window.window_index
    assert snapshot.last_window_id == bytes.fromhex(harness.fixture.window.window_id)
    assert snapshot.spent_registry.last_reveal_round == harness.fixture.window.reveal_round
    assert snapshot.spent_registry.leaves
    assert snapshot.rolling_scores.batches == ()
    assert sum(count for _root, count in snapshot.assigned_observation_counts) == expected_issued

    # Simulate process death after the coordinator and protocol-state commit,
    # but before the reveal StageReceipt.  Fresh journal, material, protocol,
    # coordinator, and effect instances must reproduce byte-for-byte.
    recovered = await _restarted_reveal_effect(tmp_path, harness).perform(
        operation_id=operation,
        work=work,
    )
    assert recovered.objects == first.objects
    assert recovered.metadata == first.metadata
    assert recovered.decision == first.decision

    journal, record = _record_reveal(tmp_path, recovered)
    terminal = stage_result_from_receipt(record)
    assert isinstance(terminal, TerminalDecision)
    assert terminal.outcome is TerminalOutcome.SKIPPED
    assert terminal.reason_code == reason
    assert terminal.audit_release_block == 1_500
    resolved = resolve_reveal_stage_record(record, journal)
    assert isinstance(resolved.result, TranscriptAbortRevealResult)
    assert resolved.result.schema_ == REVEAL_ABORT_RESULT_SCHEMA
    assert resolved.result.abort_origin.origin_stage == origin_stage.value
    assert resolved.result.abort_origin.reason_code == reason
    assert resolved.result.scored_batches == []
    assert resolved.result.monitoring_observations == []
    assert resolved.result.issued_request_count == expected_issued
    assert resolved.resulting_protocol_state_digest == snapshot.state_digest.hex()
    assert {
        bytes.fromhex(value) for value in resolved.result.spent_transition_preview["delta_leaves"]
    } == set(snapshot.spent_registry.leaves)
    assert set(snapshot.spent_registry.leaves) == _expected_spent_leaves(
        harness,
        resolved.result,
    )

    payloads = {item.sha256: journal.read_object(item) for item in record.receipt.objects}
    evidence = CalibrationStageEvidence(
        schema=CALIBRATION_STAGE_SCHEMA,
        protocol=PROTOCOL_VERSION,
        window_id=record.receipt.window_id,
        scoring_policy_hash=harness.fixture.window.scoring_policy_hash,
        stage_id=WindowStage.REVEAL_AND_SCORE.value,
        replay_hook_id=calibration_stage_replay_hook_id(
            harness.fixture.policy,
            WindowStage.REVEAL_AND_SCORE.value,
        ),
        previous_stage_evidence_sha256=prefix_evidence[-1].evidence_sha256,
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
    assert replay_reveal_stage(
        policy=harness.fixture.policy,
        evidence=evidence,
        receipt=record.receipt,
        objects=payloads,
    )

    missing = dict(payloads)
    embedded_response = next(
        item.sha256
        for item in record.receipt.objects
        if item.media_type == STAGE_RECEIPT_MEDIA_TYPE
        and _is_response_receipt(payloads[item.sha256])
    )
    del missing[embedded_response]
    with pytest.raises(RevealBindingError, match="object graph is not exact"):
        replay_reveal_stage(
            policy=harness.fixture.policy,
            evidence=evidence,
            receipt=record.receipt,
            objects=missing,
        )

    changed = dict(payloads)
    changed[embedded_response] = b"{}"
    with pytest.raises(RevealBindingError, match="metadata does not reproduce"):
        replay_reveal_stage(
            policy=harness.fixture.policy,
            evidence=evidence,
            receipt=record.receipt,
            objects=changed,
        )


@pytest.mark.asyncio
async def test_abort_reveal_applies_objective_publisher_fault_and_enables_readiness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    live_policy = ScoringPolicy.model_validate(_live_shadow_policy_data())
    monkeypatch.setattr(shadow_test_support, "_policy", lambda *_args: live_policy)
    harness = Harness(tmp_path, monkeypatch)
    # One committed publisher payload becomes objectively malformed at reveal.
    # The transcript abort must not suppress this independently reproducible strike.
    first_ciphertext = next(iter(harness.ground_truth_by_ciphertext))
    harness.ground_truth_by_ciphertext[first_ciphertext] = b"{}"
    work, _evidence, reason = await _abort_prefix(
        tmp_path,
        harness,
        origin_stage=WindowStage.ASSIGNMENT,
    )
    operation = stage_operation_id(harness.fixture.window.window_id, work.stage)
    result = await harness.reveal_effect().perform(operation_id=operation, work=work)
    assert result.metadata["objective_fault_count"] >= 1
    snapshot = harness.fixture.protocol_state.snapshot
    assert snapshot.publisher_faults.strikes
    assert snapshot.rolling_scores.batches == ()

    journal, record = _record_reveal(tmp_path, result)
    resolved = resolve_reveal_stage_record(record, journal)
    assert isinstance(resolved.result, TranscriptAbortRevealResult)
    assert resolved.result.scored_batches == []
    assert resolved.result.monitoring_observations == []
    assert len(resolved.result.objective_fault_findings) == 1
    assert resolved.result.objective_fault_findings[0]["reason"] == ("ground_truth_schema_invalid")
    assert len(snapshot.publisher_faults.strikes) == 1
    assert snapshot.publisher_faults.strikes[0][1] == 1
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
    release_evidence = b"abort-settlement-release-finality"
    pin = harness.fixture.policy.implementation_pins.finality_verifier
    assert pin is not None
    finality_sha256 = next(iter(pin.release_sha256_by_target.values()))
    block = VerifiedFinalizedBlock(
        height=1_500,
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
        audit_release_block=1_500,
        audit_release_block_hash=block.block_hash,
        reason_codes=(reason,),
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
    assert checkpoint.window_id == previous.plan.window_id
    assert checkpoint.spent_root == snapshot.spent_registry.root.hex()
    assert checkpoint.reveal_round == previous.plan.reveal_round
