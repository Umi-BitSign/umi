"""Production composition for independently replaying validator bundles.

Construction verifies the pinned local sidecar and chain-spec artifacts but does
not start a process, read chain state, access a wallet, or perform network I/O.
Every stage hook is a pure replay over the objects named by the signed bundle.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from os import PathLike
from typing import Literal

import bittensor as bt

from .calibration_bundle import (
    CALIBRATION_RECEIPT_MEDIA_TYPE,
    STAGE_IDS,
    CalibrationStageEvidence,
    CalibrationVerificationPorts,
    GrandpaFinalityReplayVerifier,
    build_bittensor_runtime_context,
    calibration_stage_replay_hook_id,
)
from .crypto import verify_response_signature
from .grandpa_finality import GrandpaFinalityObserver
from .policy import ScoringPolicy, scoring_policy_hash
from .protocol import canonical_json_bytes
from .substrate_proof import SubprocessStorageProofVerifier
from .validator_journal import StageReceipt
from .validator_pool_no_score import PoolNoScoreReplay
from .validator_pool_replay import ProofBackedPoolStageReplayHook
from .validator_reveal_effect import replay_reveal_stage
from .validator_state import WindowStage
from .validator_terminal_effect import (
    ReplayCalibrationBundleVerifier,
    replay_terminal_stage_receipt,
)
from .validator_transcript_effects import (
    TranscriptAbortReplay,
    TranscriptStageReplay,
    replay_transcript_stage_receipt,
)
from .validator_weight_build_effect import ProofBackedWeightBuildReplayHook


class BundlePortCompositionError(RuntimeError):
    """Production replay ports do not match the active policy pins."""


@dataclass(frozen=True, slots=True)
class BittensorManifestSignatureVerifier:
    """Verify the one explicitly declared validator hotkey signature scheme."""

    def __call__(
        self,
        *,
        account_id32: bytes,
        scheme: str,
        digest: bytes,
        signature: bytes,
    ) -> bool:
        if (
            not isinstance(account_id32, bytes)
            or len(account_id32) != 32
            or scheme not in {"sr25519", "ed25519"}
            or not isinstance(digest, bytes)
            or len(digest) != 32
            or not isinstance(signature, bytes)
            or len(signature) != 64
        ):
            return False
        try:
            hotkey = bt.sp_core.ss58_encode(account_id32)
        except Exception:
            return False
        return verify_response_signature(
            digest,
            hotkey_ss58=hotkey,
            scheme=scheme,
            signature="0x" + signature.hex(),
        )


@dataclass(frozen=True, slots=True)
class TranscriptStageReplayHook:
    """Policy-bind the existing exact transcript receipt replay."""

    stage: Literal["assignment", "request_transcript", "sealed_response"]

    def __post_init__(self) -> None:
        if self.stage not in {
            WindowStage.ASSIGNMENT.value,
            WindowStage.REQUEST_TRANSCRIPT.value,
            WindowStage.SEALED_RESPONSE.value,
        }:
            raise ValueError("transcript replay hook has another stage")

    def __call__(
        self,
        *,
        policy: ScoringPolicy,
        evidence: CalibrationStageEvidence,
        receipt: StageReceipt,
        objects: Mapping[str, bytes],
    ) -> bool:
        if (
            not isinstance(policy, ScoringPolicy)
            or policy.translation_weights_active
            or not isinstance(evidence, CalibrationStageEvidence)
            or not isinstance(receipt, StageReceipt)
            or evidence.stage_id != self.stage
            or receipt.stage != self.stage
            or evidence.window_id != receipt.window_id
            or evidence.scoring_policy_hash != scoring_policy_hash(policy)
            or evidence.replay_hook_id != calibration_stage_replay_hook_id(policy, self.stage)
            or receipt.operation_id != f"umi-stage-v1/{receipt.window_id}/{self.stage}"
        ):
            return False
        receipt_bytes = canonical_json_bytes(receipt)
        if (
            evidence.receipt_object.sha256 != hashlib.sha256(receipt_bytes).hexdigest()
            or evidence.receipt_object.media_type != CALIBRATION_RECEIPT_MEDIA_TYPE
            or evidence.receipt_object.size_bytes != len(receipt_bytes)
        ):
            return False
        receipt_refs = {item.sha256: item for item in receipt.objects}
        evidence_refs = {item.sha256: item for item in evidence.payload_objects}
        if (
            len(receipt_refs) != len(receipt.objects)
            or len(evidence_refs) != len(evidence.payload_objects)
            or set(objects) != set(receipt_refs)
            or set(evidence_refs) != set(receipt_refs)
        ):
            return False
        for digest, reference in receipt_refs.items():
            retained = evidence_refs[digest]
            data = objects[digest]
            if (
                retained.media_type != reference.media_type
                or retained.size_bytes != reference.size_bytes
                or not isinstance(data, bytes)
                or len(data) != reference.size_bytes
                or hashlib.sha256(data).hexdigest() != digest
            ):
                return False
        try:
            replay = replay_transcript_stage_receipt(receipt, objects)
        except Exception:
            return False
        expected_stage = WindowStage(self.stage)
        if isinstance(replay, TranscriptStageReplay):
            return bool(
                replay.window_id == receipt.window_id
                and replay.stage is expected_stage
                and replay.scoring_policy_hash == scoring_policy_hash(policy)
            )
        if isinstance(replay, TranscriptAbortReplay):
            return bool(
                replay.window_id == receipt.window_id
                and replay.stage is expected_stage
                and replay.operation_id == receipt.operation_id
                and replay.origin.scoring_policy_hash == scoring_policy_hash(policy)
            )
        if isinstance(replay, PoolNoScoreReplay):
            return bool(
                replay.window_id == receipt.window_id
                and replay.stage is expected_stage
                and replay.operation_id == receipt.operation_id
                and replay.origin.scoring_policy_hash == scoring_policy_hash(policy)
            )
        return False


def build_production_calibration_bundle_verifier(
    *,
    policy: ScoringPolicy,
    target_triple: str,
    finality_verifier_binary: str | PathLike[str],
    finality_chain_spec: str | PathLike[str],
    storage_proof_verifier: SubprocessStorageProofVerifier,
) -> ReplayCalibrationBundleVerifier:
    """Build the complete seven-stage production replay surface.

    The two paths are checked against the policy by
    :meth:`GrandpaFinalityObserver.from_policy_pin`; the proof verifier has
    already authenticated its own executable and is additionally matched to the
    target-specific policy digest here.
    """

    if not isinstance(policy, ScoringPolicy):
        raise TypeError("bundle replay policy must be ScoringPolicy")
    if policy.translation_weights_active:
        raise BundlePortCompositionError("bundle replay builder requires a shadow policy")
    if not isinstance(target_triple, str) or not target_triple:
        raise ValueError("bundle replay target triple must be nonempty")
    if not isinstance(storage_proof_verifier, SubprocessStorageProofVerifier):
        raise TypeError("storage_proof_verifier must be SubprocessStorageProofVerifier")
    pins = policy.implementation_pins
    proof_pin = pins.storage_proof_verifier
    finality_pin = pins.finality_verifier
    if (
        pins.pin_profile != "live_shadow_calibration"
        or pins.live_chain is None
        or proof_pin is None
        or finality_pin is None
    ):
        raise BundlePortCompositionError("bundle replay policy lacks live production pins")
    try:
        expected_proof = proof_pin.release_sha256_by_target[target_triple]
        expected_finality = finality_pin.release_sha256_by_target[target_triple]
    except KeyError as error:
        raise BundlePortCompositionError("bundle replay target is absent from policy") from error
    if storage_proof_verifier.expected_sha256 != expected_proof:
        raise BundlePortCompositionError("bundle replay proof verifier pin mismatch")

    observer = GrandpaFinalityObserver.from_policy_pin(
        finality_pin,
        target_triple=target_triple,
        binary_path=finality_verifier_binary,
        chain_spec_path=finality_chain_spec,
    )
    if observer.expected_binary_sha256 != expected_finality:
        raise BundlePortCompositionError("bundle replay finality verifier pin mismatch")
    finality_replay = GrandpaFinalityReplayVerifier(observer)
    hooks = {
        calibration_stage_replay_hook_id(policy, WindowStage.POOL_AND_SELECTION.value): (
            ProofBackedPoolStageReplayHook(
                verifier=storage_proof_verifier,
                finality_verifier=finality_replay,
                finality_verifier_sha256=expected_finality,
            )
        ),
        calibration_stage_replay_hook_id(policy, WindowStage.ASSIGNMENT.value): (
            TranscriptStageReplayHook(WindowStage.ASSIGNMENT.value)
        ),
        calibration_stage_replay_hook_id(policy, WindowStage.REQUEST_TRANSCRIPT.value): (
            TranscriptStageReplayHook(WindowStage.REQUEST_TRANSCRIPT.value)
        ),
        calibration_stage_replay_hook_id(policy, WindowStage.SEALED_RESPONSE.value): (
            TranscriptStageReplayHook(WindowStage.SEALED_RESPONSE.value)
        ),
        calibration_stage_replay_hook_id(policy, WindowStage.REVEAL_AND_SCORE.value): (
            replay_reveal_stage
        ),
        calibration_stage_replay_hook_id(policy, WindowStage.WEIGHT_BUILD.value): (
            ProofBackedWeightBuildReplayHook(storage_proof_verifier)
        ),
        calibration_stage_replay_hook_id(
            policy, WindowStage.COMMIT_AND_TERMINAL_STATE.value
        ): replay_terminal_stage_receipt,
    }
    if len(hooks) != len(STAGE_IDS):
        raise RuntimeError("bundle replay hook table is not the complete stage set")
    ports = CalibrationVerificationPorts(
        finality_verifier=finality_replay,
        extrinsics_root_verifier=storage_proof_verifier.verify_extrinsics_root,
        event_proof_verifier=storage_proof_verifier,
        runtime_factory=build_bittensor_runtime_context,
        signature_verifier=BittensorManifestSignatureVerifier(),
        stage_replay_hooks=hooks,
        target_triple=target_triple,
        storage_proof_verifier_sha256=expected_proof,
        finality_verifier_sha256=expected_finality,
    )
    return ReplayCalibrationBundleVerifier(ports)


__all__ = [
    "BittensorManifestSignatureVerifier",
    "BundlePortCompositionError",
    "TranscriptStageReplayHook",
    "build_production_calibration_bundle_verifier",
]
