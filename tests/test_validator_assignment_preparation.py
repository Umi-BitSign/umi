from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest

from umi.calibration_bundle import FinalityReplayBindingObject
from umi.chain_evidence import FinalizedSnapshotRef
from umi.grandpa_finality_supervisor import (
    ACCEPTANCE_RECEIPT_SCHEMA,
    VerifiedFinalityScanInterval,
    _acceptance_digest,
)
from umi.policy import scoring_policy_hash
from umi.pool import CandidateBatch
from umi.protocol import base64url_encode, canonical_json_bytes
from umi.validator_assignment_preparation import (
    AssignmentIssuanceFinalityEvidence,
    AssignmentPreparationError,
    FinalizedPreparedAssignmentsAdapter,
)
from umi.validator_assignments import deterministic_assignment_id
from umi.validator_chain_scan import (
    FinalityAttestationReplayBinding,
    VerifiedFinalizedBlockIdentity,
)
from umi.validator_delivery import IssuedVideoDelivery
from umi.validator_plans import VerifiedFinalizedBlock
from umi.validator_pool_effect import (
    ClosingNeuron,
    PoolSelectionContext,
)
from umi.validator_state import (
    ControlState,
    PauseScope,
    StageWorkItem,
    WindowPlan,
    WindowRecord,
    WindowStage,
)
from umi.validator_transcript_ports import (
    DurableBtauthNonceStore,
    LiveBtauthAttemptPort,
)
from umi.validator_window_material import ValidatorWindowMaterialStore
from umi.window import QUICKNET_GENESIS_MS, QUICKNET_PERIOD_MS

from .factories import dev_wallet
from .test_shadow import _fixture as shadow_fixture
from .test_validator_weight_build_effect import _policy


class _Finality:
    def __init__(self, policy, block: VerifiedFinalizedBlock) -> None:
        self.chain_observation = policy.implementation_pins.live_chain
        self.finality_verifier_sha256 = block.finality_verifier_sha256
        self.block = block

    async def finalized_head_height(self) -> int:
        return self.block.height

    async def verified_block_at(self, height: int):
        return self.block if height == self.block.height else None

    async def verified_scan_interval(self, start_height: int, end_height: int):
        if (start_height, end_height) != (self.block.height, self.block.height):
            return None
        snapshot = FinalizedSnapshotRef(
            block_number=self.block.height,
            block_hash=self.block.block_hash,
            parent_hash="0x" + "44" * 32,
            state_root=self.block.state_root,
        )
        parent = FinalizedSnapshotRef(
            block_number=self.block.height - 1,
            block_hash=snapshot.parent_hash,
            parent_hash="0x" + "55" * 32,
            state_root="0x" + "66" * 32,
        )
        identity = VerifiedFinalizedBlockIdentity(
            snapshot=snapshot,
            parent_snapshot=parent,
            extrinsics_root="0x" + "77" * 32,
            finality_verifier_sha256=self.block.finality_verifier_sha256,
            finality_evidence_sha256=self.block.finality_evidence_sha256,
        )
        binding = FinalityAttestationReplayBinding(
            minimum_finalized_block=self.block.height,
            maximum_records=1,
            startup_timeout_seconds=10,
            expected_sequence=0,
            previous_number=None,
            previous_timestamp_ms=None,
        )
        accepted_at_unix_ms = 2_000_000_000_000
        acceptance_digest = _acceptance_digest(
            bytes(32),
            height=self.block.height,
            block_hash=self.block.block_hash,
            evidence_digest=hashlib.sha256(self.block.finality_evidence).digest(),
            segment_index=0,
            sequence=0,
            restart_gap=False,
            accepted_at_unix_ms=accepted_at_unix_ms,
        ).hex()
        acceptance_receipt = canonical_json_bytes(
            {
                "schema": ACCEPTANCE_RECEIPT_SCHEMA,
                "height": self.block.height,
                "block_hash": self.block.block_hash,
                "evidence_sha256": self.block.finality_evidence_sha256,
                "segment_index": 0,
                "segment_sequence": 0,
                "restart_gap_before": False,
                "accepted_at_unix_ms": accepted_at_unix_ms,
                "previous_acceptance_digest": "00" * 32,
                "acceptance_digest": acceptance_digest,
            }
        )
        return VerifiedFinalityScanInterval(
            identities=(identity,),
            attestations=(self.block.finality_evidence,),
            replay_bindings=(binding,),
            acceptance_receipts=(acceptance_receipt,),
        )


def _case(tmp_path):
    policy = _policy()
    policy_hash = scoring_policy_hash(policy)
    validator_wallet = dev_wallet("//Validator0")
    assert validator_wallet.hotkey.ss58_address in {
        item.validator_hotkey for item in policy.validator_registry
    }
    rehearsal, _signers = shadow_fixture()
    manifest = rehearsal.batch_artifacts[0].public_manifest
    selection_round = 100_000
    selection_ms = QUICKNET_GENESIS_MS + (selection_round - 1) * QUICKNET_PERIOD_MS
    window = WindowPlan(
        window_id=manifest.window_id,
        window_index=0,
        scoring_policy_hash=policy_hash,
        announcement_block=10_000,
        proposal_close_block=10_030,
        closing_block=10_045,
        selection_round=selection_round,
        issue_close_round=selection_round + 20,
        response_close_round=selection_round + 40,
        reveal_round=selection_round + 140,
    )
    work = StageWorkItem(
        window=WindowRecord(
            plan=window,
            stage=WindowStage.POOL_AND_SELECTION,
            terminal_outcome=None,
            terminal_reason_code=None,
            terminal_evidence_sha256=None,
            audit_release_block=None,
            created_at_unix_ns=1,
            updated_at_unix_ns=1,
            revision=0,
        ),
        completed_evidence=(),
        controls=tuple(ControlState(scope, ()) for scope in PauseScope),
    )
    miner = dev_wallet("//Bob").hotkey.ss58_address
    panel = (
        ClosingNeuron(
            uid=1,
            hotkey=miner,
            root=miner,
            registered=True,
            validator_permit=False,
            serving_url="https://miner.example",
        ),
    )
    deliveries = tuple(
        sorted(
            (
                IssuedVideoDelivery(
                    batch_id=manifest.batch_id,
                    challenge_id=item.challenge_id,
                    url=(
                        "https://objects.example/v1/umi/deliveries/"
                        + base64url_encode(
                            hashlib.sha256(
                                manifest.batch_id.encode() + item.challenge_id.encode()
                            ).digest()[:24]
                        )
                    ),
                    sha256=item.media.sha256,
                    size_bytes=item.media.size_bytes,
                    expires_at_unix_ms=10**15,
                )
                for item in manifest.items
            ),
            key=lambda item: (item.batch_id, item.challenge_id),
        )
    )
    publisher = policy.publisher_registry[0]
    context = PoolSelectionContext(
        window=window,
        selected_batches=(
            CandidateBatch(
                publisher_hotkey=publisher.publisher_hotkey,
                control_group_id=publisher.control_group_id,
                batch_id=manifest.batch_id,
                batch_commitment="11" * 32,
            ),
        ),
        selected_manifests=(manifest,),
        selected_video_deliveries=deliveries,
        selected_panel=panel,
        selection_seed=b"s" * 32,
        response_deadline_blocks=10,
    )
    finality_evidence = b"verified-finality"
    pin = policy.implementation_pins.finality_verifier
    assert pin is not None
    block = VerifiedFinalizedBlock(
        height=window.closing_block + 1,
        block_hash="0x" + "22" * 32,
        state_root="0x" + "33" * 32,
        timestamp_ms=selection_ms + 1_000,
        scoring_policy_hash=policy_hash,
        chain_observation=policy.implementation_pins.live_chain,
        finality_verifier_sha256=next(iter(pin.release_sha256_by_target.values())),
        finality_evidence=finality_evidence,
        finality_evidence_sha256=hashlib.sha256(finality_evidence).hexdigest(),
    )
    btauth = LiveBtauthAttemptPort(
        policy=policy,
        validator_hotkey=validator_wallet.hotkey.ss58_address,
        wallet=validator_wallet,
        material_store=ValidatorWindowMaterialStore(tmp_path / "material"),
        nonces=DurableBtauthNonceStore(tmp_path / "nonces"),
    )
    finality = _Finality(policy, block)
    return policy, context, work, block, btauth, finality


@pytest.mark.asyncio
async def test_prepares_complete_signed_cartesian_set_at_one_finalized_block(tmp_path) -> None:
    policy, context, work, block, btauth, finality = _case(tmp_path)
    adapter = FinalizedPreparedAssignmentsAdapter(
        policy=policy,
        validator_hotkey=btauth.validator_hotkey,
        finality=finality,
        btauth=btauth,
    )

    prepared = await adapter(context, work)

    assert len(prepared.assignments) == len(context.selected_manifests[0].items)
    assert prepared.issuance_block == block.height
    issuance = AssignmentIssuanceFinalityEvidence.model_validate_json(
        prepared.finality_evidence_bytes
    )
    assert canonical_json_bytes(issuance) == prepared.finality_evidence_bytes
    assert bytes.fromhex(issuance.attestation_hex) == block.finality_evidence
    assert issuance.replay_binding == FinalityReplayBindingObject.from_evidence(
        (await finality.verified_scan_interval(block.height, block.height)).replay_bindings[0]
    )
    assert [item.assignment_id for item in prepared.assignments] == sorted(
        deterministic_assignment_id(item.initial_attempt) for item in prepared.assignments
    )
    for assignment in prepared.assignments:
        request = assignment.initial_attempt.request
        assert request.issued_block_hash == block.block_hash
        assert request.deadline_block == block.height + context.response_deadline_blocks
        assert assignment.initial_attempt.validator_hotkey == btauth.validator_hotkey
        assert assignment.miner_url == context.selected_panel[0].serving_url


@pytest.mark.asyncio
async def test_rejects_finalized_block_outside_issue_interval(tmp_path) -> None:
    policy, context, work, block, btauth, finality = _case(tmp_path)
    finality.block = replace(
        block,
        timestamp_ms=QUICKNET_GENESIS_MS
        + (context.window.issue_close_round - 1) * QUICKNET_PERIOD_MS,
    )
    adapter = FinalizedPreparedAssignmentsAdapter(
        policy=policy,
        validator_hotkey=btauth.validator_hotkey,
        finality=finality,
        btauth=btauth,
    )

    with pytest.raises(AssignmentPreparationError, match="assignment_issuance_block_mismatch"):
        await adapter(context, work)
