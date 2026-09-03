from __future__ import annotations

import hashlib
from dataclasses import replace
from types import SimpleNamespace

import pytest

import umi.mirror_readiness as mirror_readiness
from umi.calibration_bundle import (
    CALIBRATION_RECEIPT_MEDIA_TYPE,
    CalibrationObject,
    CalibrationStageEvidence,
    FinalityReplayBindingObject,
    calibration_stage_replay_hook_id,
)
from umi.chain_evidence import FinalizedSnapshotRef
from umi.protocol import PROTOCOL_VERSION, canonical_json_bytes
from umi.validator_adapters import JournalStageAdapter
from umi.validator_assignment_preparation import (
    ASSIGNMENT_ISSUANCE_FINALITY_SCHEMA,
    AssignmentIssuanceFinalityEvidence,
    issuance_identity_object,
)
from umi.validator_chain_scan import (
    FinalityAttestationReplayBinding,
    VerifiedFinalizedBlockIdentity,
)
from umi.validator_journal import ValidatorStageJournal
from umi.validator_pool_replay import PoolStageReplayError, resolve_pool_stage
from umi.validator_state import WindowStage
from umi.window import QUICKNET_GENESIS_MS, QUICKNET_PERIOD_MS

from .test_validator_pool_effect import _Fixture


def _valid_issuance(fixture: _Fixture):
    original = fixture.prepared

    def prepared(context, work):
        value = original(context, work)
        attestation = b"issuance-finality-attestation"
        parent = FinalizedSnapshotRef(
            block_number=value.issuance_block - 1,
            block_hash=fixture.closing.snapshot.closing_block_hash,
            parent_hash="0x" + "77" * 32,
            state_root="0x" + "78" * 32,
        )
        snapshot = FinalizedSnapshotRef(
            block_number=value.issuance_block,
            block_hash=value.issuance_block_hash,
            parent_hash=parent.block_hash,
            state_root="0x" + "79" * 32,
        )
        identity = VerifiedFinalizedBlockIdentity(
            snapshot=snapshot,
            parent_snapshot=parent,
            extrinsics_root="0x" + "7a" * 32,
            finality_verifier_sha256="7b" * 32,
            finality_evidence_sha256=hashlib.sha256(attestation).hexdigest(),
        )
        binding = FinalityAttestationReplayBinding(
            minimum_finalized_block=value.issuance_block,
            maximum_records=10,
            startup_timeout_seconds=60,
            expected_sequence=0,
            previous_number=None,
            previous_timestamp_ms=None,
        )
        finality = AssignmentIssuanceFinalityEvidence(
            schema=ASSIGNMENT_ISSUANCE_FINALITY_SCHEMA,
            protocol=PROTOCOL_VERSION,
            window_id=fixture.window.window_id,
            timestamp_ms=value.issuance_block_timestamp_ms,
            identity=issuance_identity_object(identity),
            replay_binding=FinalityReplayBindingObject.from_evidence(binding),
            attestation_hex=attestation.hex(),
        )
        return replace(value, finality_evidence_bytes=canonical_json_bytes(finality))

    fixture.prepared = prepared


async def _stage(tmp_path):
    fixture = _Fixture(tmp_path)
    _valid_issuance(fixture)
    journal = ValidatorStageJournal(tmp_path / "journal")
    await JournalStageAdapter(
        stage=WindowStage.POOL_AND_SELECTION,
        journal=journal,
        effect=fixture.effect(),
    ).execute(fixture.work)
    record = journal.load(fixture.window.window_id, WindowStage.POOL_AND_SELECTION)
    objects = {item.sha256: journal.read_object(item) for item in record.receipt.objects}
    evidence = CalibrationStageEvidence(
        schema="umi-calibration-stage-evidence/2",
        protocol=PROTOCOL_VERSION,
        window_id=fixture.window.window_id,
        scoring_policy_hash=fixture.window.scoring_policy_hash,
        stage_id=WindowStage.POOL_AND_SELECTION.value,
        replay_hook_id=calibration_stage_replay_hook_id(
            fixture.policy, WindowStage.POOL_AND_SELECTION.value
        ),
        previous_stage_evidence_sha256=None,
        receipt_object=CalibrationObject.from_bytes(
            record.receipt_bytes, CALIBRATION_RECEIPT_MEDIA_TYPE
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
    return fixture, record.receipt, evidence, objects


@pytest.mark.asyncio
async def test_pool_stage_replays_selection_panel_and_all_signed_assignments(
    tmp_path, monkeypatch
) -> None:
    fixture, receipt, evidence, objects = await _stage(tmp_path)
    readiness_calls = []
    real_verify_readiness = mirror_readiness.verify_live_mirror_readiness

    def verify_readiness(**values):
        readiness_calls.append(values)
        return real_verify_readiness(**values)

    monkeypatch.setattr(mirror_readiness, "verify_live_mirror_readiness", verify_readiness)
    snapshot_finality_calls = []
    monkeypatch.setattr(
        "umi.validator_pool_replay.replay_announcement_validator_storage",
        lambda proof, *, verifier: SimpleNamespace(evidence=object()),
    )
    monkeypatch.setattr(
        "umi.validator_pool_replay.validate_replayed_announcement_validator_snapshot",
        lambda snapshot, replayed, *, policy: fixture.closing.announcement_snapshot,
    )
    monkeypatch.setattr(
        "umi.validator_pool_replay.replay_closing_snapshot_storage",
        lambda proof, *, verifier: SimpleNamespace(evidence=object()),
    )
    monkeypatch.setattr(
        "umi.validator_pool_replay.validate_replayed_closing_snapshot",
        lambda snapshot, replayed, *, policy: fixture.closing.snapshot,
    )
    monkeypatch.setattr(
        "umi.validator_pool_replay.verify_snapshot_finality",
        lambda proof, *, label, policy, finality_verifier, finality_verifier_sha256: (
            snapshot_finality_calls.append((label, proof))
        ),
    )
    finality_calls = []

    def finality(**values):
        finality_calls.append(values)
        return True

    replay = resolve_pool_stage(
        policy=fixture.policy,
        evidence=evidence,
        receipt=receipt,
        objects=objects,
        verifier=lambda **_values: True,
        finality_verifier=finality,
        finality_verifier_sha256="7b" * 32,
    )
    assert replay.window == fixture.window
    assert replay.assignment_ids == tuple(replay.selection.assignment_ids)
    assert len(replay.assignment_ids) == 56
    assert len(replay.selection.candidates) == 3
    assert len(replay.selection.selected_panel) == 2
    assert [item[0] for item in snapshot_finality_calls] == ["announcement", "closing"]
    assert len(finality_calls) == 1
    assert len(readiness_calls) == 1
    assert readiness_calls[0]["discovery_rule_bytes"] == fixture.discovery_bytes
    assert readiness_calls[0]["readiness_set_bytes"] == fixture.readiness_bytes
    assert finality_calls[0]["identities"][0].snapshot.block_number == (
        replay.selection.issuance_block
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation", ["missing", "tampered"])
async def test_pool_stage_rejects_missing_or_tampered_mirror_readiness(
    tmp_path,
    mutation: str,
) -> None:
    fixture, receipt, evidence, objects = await _stage(tmp_path)
    readiness_digest = hashlib.sha256(fixture.readiness_bytes).hexdigest()
    assert objects[readiness_digest] == fixture.readiness_bytes
    changed = dict(objects)
    if mutation == "missing":
        del changed[readiness_digest]
    else:
        changed[readiness_digest] = fixture.readiness_bytes + b"\n"

    with pytest.raises(PoolStageReplayError, match="pool payload"):
        resolve_pool_stage(
            policy=fixture.policy,
            evidence=evidence,
            receipt=receipt,
            objects=changed,
            verifier=lambda **_values: True,
            finality_verifier=lambda **_values: True,
            finality_verifier_sha256="7b" * 32,
        )


@pytest.mark.asyncio
async def test_pool_stage_rejects_extra_object_and_failed_issuance_finality(
    tmp_path, monkeypatch
) -> None:
    fixture, receipt, evidence, objects = await _stage(tmp_path)
    monkeypatch.setattr(
        "umi.validator_pool_replay.replay_announcement_validator_storage",
        lambda proof, *, verifier: SimpleNamespace(evidence=object()),
    )
    monkeypatch.setattr(
        "umi.validator_pool_replay.validate_replayed_announcement_validator_snapshot",
        lambda snapshot, replayed, *, policy: fixture.closing.announcement_snapshot,
    )
    monkeypatch.setattr(
        "umi.validator_pool_replay.replay_closing_snapshot_storage",
        lambda proof, *, verifier: SimpleNamespace(evidence=object()),
    )
    monkeypatch.setattr(
        "umi.validator_pool_replay.validate_replayed_closing_snapshot",
        lambda snapshot, replayed, *, policy: fixture.closing.snapshot,
    )
    monkeypatch.setattr(
        "umi.validator_pool_replay.verify_snapshot_finality",
        lambda proof, *, label, policy, finality_verifier, finality_verifier_sha256: None,
    )
    with pytest.raises(PoolStageReplayError, match="payload table"):
        resolve_pool_stage(
            policy=fixture.policy,
            evidence=evidence,
            receipt=receipt,
            objects={**objects, "00" * 32: b"extra"},
            verifier=lambda **_values: True,
            finality_verifier=lambda **_values: True,
            finality_verifier_sha256="7b" * 32,
        )
    with pytest.raises(PoolStageReplayError, match="issuance finality replay failed"):
        resolve_pool_stage(
            policy=fixture.policy,
            evidence=evidence,
            receipt=receipt,
            objects=objects,
            verifier=lambda **_values: True,
            finality_verifier=lambda **_values: False,
            finality_verifier_sha256="7b" * 32,
        )


@pytest.mark.asyncio
async def test_pool_stage_replay_rejects_late_closing_acceptance(
    tmp_path,
    monkeypatch,
) -> None:
    fixture, receipt, evidence, objects = await _stage(tmp_path)
    publication_ms = QUICKNET_GENESIS_MS + (fixture.window.selection_round - 1) * QUICKNET_PERIOD_MS
    late = fixture.closing.snapshot.model_copy(update={"accepted_at_unix_ms": publication_ms})
    monkeypatch.setattr(
        "umi.validator_pool_replay.replay_announcement_validator_storage",
        lambda proof, *, verifier: SimpleNamespace(evidence=object()),
    )
    monkeypatch.setattr(
        "umi.validator_pool_replay.validate_replayed_announcement_validator_snapshot",
        lambda snapshot, replayed, *, policy: fixture.closing.announcement_snapshot,
    )
    monkeypatch.setattr(
        "umi.validator_pool_replay.replay_closing_snapshot_storage",
        lambda proof, *, verifier: SimpleNamespace(evidence=object()),
    )
    monkeypatch.setattr(
        "umi.validator_pool_replay.validate_replayed_closing_snapshot",
        lambda snapshot, replayed, *, policy: late,
    )
    monkeypatch.setattr(
        "umi.validator_pool_replay.verify_snapshot_finality",
        lambda proof, **values: None,
    )

    with pytest.raises(PoolStageReplayError, match="closing snapshot"):
        resolve_pool_stage(
            policy=fixture.policy,
            evidence=evidence,
            receipt=receipt,
            objects=objects,
            verifier=lambda **_values: True,
            finality_verifier=lambda **_values: True,
            finality_verifier_sha256="7b" * 32,
        )
