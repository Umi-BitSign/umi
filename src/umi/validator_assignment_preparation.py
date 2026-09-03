"""Finality-bound construction of the initial signed miner assignment set.

The pool stage has already fixed the selected batches, exact delivery URLs, and
miner panel.  This adapter adds only one independently finalized issuance block
and validator-hotkey authentication.  It cannot transmit requests or write to
chain state.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Annotated, Literal

from pydantic import Field, model_validator
from typing_extensions import Self

from .calibration_bundle import FinalityReplayBindingObject, FinalizedSnapshotObject
from .encoding import account_id32
from .policy import ScoringPolicy, scoring_policy_hash
from .protocol import (
    PROTOCOL_VERSION,
    StrictProtocolModel,
    TranslationRequest,
    canonical_json_bytes,
)
from .validator_chain_scan import VerifiedFinalizedBlockIdentity
from .validator_plans import VerifiedFinalizedBlock
from .validator_pool_effect import (
    PoolSelectionContext,
    PreparedAssignmentSet,
)
from .validator_state import StagePending, StageWorkItem, WindowStage
from .validator_transcript_effects import TranscriptAssignment
from .validator_transcript_ports import LiveBtauthAttemptPort
from .window import QUICKNET_GENESIS_MS, QUICKNET_PERIOD_MS

ASSIGNMENT_ISSUANCE_FINALITY_SCHEMA = "umi-validator-assignment-issuance-finality/1"


class AssignmentIssuanceFinalityEvidence(StrictProtocolModel):
    """Complete pinned inputs for offline replay of the issuance block."""

    schema_: Literal[ASSIGNMENT_ISSUANCE_FINALITY_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    window_id: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    timestamp_ms: Annotated[int, Field(ge=0)]
    identity: dict
    replay_binding: FinalityReplayBindingObject
    attestation_hex: Annotated[str, Field(pattern=r"^[0-9a-f]+$")]

    @model_validator(mode="after")
    def validate_identity(self) -> Self:
        identity = issuance_identity_from_object(self.identity)
        attestation = bytes.fromhex(self.attestation_hex)
        if (
            not attestation
            or hashlib.sha256(attestation).hexdigest() != identity.finality_evidence_sha256
        ):
            raise ValueError("issuance attestation does not reproduce its identity")
        return self


def issuance_identity_object(identity: VerifiedFinalizedBlockIdentity) -> dict:
    if not isinstance(identity, VerifiedFinalizedBlockIdentity):
        raise TypeError("issuance identity must be VerifiedFinalizedBlockIdentity")
    return {
        "snapshot": FinalizedSnapshotObject.from_evidence(identity.snapshot).model_dump(
            mode="json"
        ),
        "parent_snapshot": FinalizedSnapshotObject.from_evidence(
            identity.parent_snapshot
        ).model_dump(mode="json"),
        "extrinsics_root": identity.extrinsics_root,
        "finality_verifier_sha256": identity.finality_verifier_sha256,
        "finality_evidence_sha256": identity.finality_evidence_sha256,
    }


def issuance_identity_from_object(value: object) -> VerifiedFinalizedBlockIdentity:
    if not isinstance(value, dict) or set(value) != {
        "snapshot",
        "parent_snapshot",
        "extrinsics_root",
        "finality_verifier_sha256",
        "finality_evidence_sha256",
    }:
        raise ValueError("issuance finality identity has another shape")
    return VerifiedFinalizedBlockIdentity(
        snapshot=FinalizedSnapshotObject.model_validate(value["snapshot"]).to_evidence(),
        parent_snapshot=FinalizedSnapshotObject.model_validate(
            value["parent_snapshot"]
        ).to_evidence(),
        extrinsics_root=value["extrinsics_root"],
        finality_verifier_sha256=value["finality_verifier_sha256"],
        finality_evidence_sha256=value["finality_evidence_sha256"],
    )


class AssignmentPreparationError(RuntimeError):
    """A selected assignment set cannot be bound to finalized issuance state."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True, slots=True)
class FinalizedPreparedAssignmentsAdapter:
    """Build every initial signed request at one verified finalized block."""

    policy: ScoringPolicy
    validator_hotkey: str
    finality: object
    btauth: LiveBtauthAttemptPort

    def __post_init__(self) -> None:
        if not isinstance(self.policy, ScoringPolicy):
            raise TypeError("assignment preparation policy must be ScoringPolicy")
        if self.policy.translation_weights_active:
            raise ValueError("assignment preparation is available only in shadow mode")
        validator = account_id32(self.validator_hotkey)
        if validator not in {
            account_id32(item.validator_hotkey) for item in self.policy.validator_registry
        }:
            raise ValueError("assignment validator is absent from the policy registry")
        if not isinstance(self.btauth, LiveBtauthAttemptPort):
            raise TypeError("assignment preparation requires LiveBtauthAttemptPort")
        if self.btauth.policy != self.policy or self.btauth.validator_account_id32 != validator:
            raise ValueError("assignment btauth adapter has another policy or validator")
        for name in (
            "finalized_head_height",
            "verified_block_at",
            "verified_scan_interval",
        ):
            if not callable(getattr(self.finality, name, None)):
                raise TypeError("assignment finality port lacks required methods")
        pins = self.policy.implementation_pins
        if (
            pins.live_chain is None
            or pins.finality_verifier is None
            or getattr(self.finality, "chain_observation", None) != pins.live_chain
            or getattr(self.finality, "finality_verifier_sha256", None)
            not in pins.finality_verifier.release_sha256_by_target.values()
        ):
            raise ValueError("assignment finality adapter disagrees with policy pins")

    async def __call__(
        self,
        context: PoolSelectionContext,
        work: StageWorkItem,
    ) -> PreparedAssignmentSet:
        self._validate_context(context, work)
        try:
            height = await self.finality.finalized_head_height()
        except Exception as error:
            raise StagePending("assignment_issuance_finality_pending") from error
        try:
            block = await self.finality.verified_block_at(height)
        except Exception as error:
            raise AssignmentPreparationError("assignment_issuance_block_read_failed") from error
        if block is None:
            raise StagePending("assignment_issuance_finality_pending")
        self._validate_block(block, context)
        try:
            interval = await self.finality.verified_scan_interval(height, height)
        except Exception as error:
            raise AssignmentPreparationError("assignment_issuance_finality_read_failed") from error
        finality_evidence = self._issuance_finality_evidence(
            interval,
            block=block,
            window_id=context.window.window_id,
        )

        deliveries = {
            (item.batch_id, item.challenge_id): item for item in context.selected_video_deliveries
        }
        assignments: list[TranscriptAssignment] = []
        for manifest in context.selected_manifests:
            for item in manifest.items:
                delivery = deliveries[(manifest.batch_id, item.challenge_id)]
                for miner in context.selected_panel:
                    request = TranslationRequest.model_validate(
                        {
                            "protocol": PROTOCOL_VERSION,
                            "window_id": context.window.window_id,
                            "batch_id": manifest.batch_id,
                            "challenge_id": item.challenge_id,
                            "issued_block": block.height,
                            "issued_block_hash": block.block_hash,
                            "deadline_block": (block.height + context.response_deadline_blocks),
                            "response_close_round": context.window.response_close_round,
                            "reveal_round": context.window.reveal_round,
                            "video": {
                                "url": delivery.url,
                                "sha256": delivery.sha256,
                                "size_bytes": delivery.size_bytes,
                                "media_type": item.media.media_type,
                            },
                            "task": {
                                "source_language": "ase",
                                "target_language": "en",
                                "stratum": item.stratum,
                            },
                            "scoring_policy_hash": context.window.scoring_policy_hash,
                        }
                    )
                    prepared = self.btauth.prepare_initial(
                        request,
                        miner_hotkey=miner.hotkey,
                    )
                    assignments.append(
                        TranscriptAssignment(
                            initial_attempt=prepared,
                            miner_url=miner.serving_url or "",
                        )
                    )
        canonical = tuple(sorted(assignments, key=lambda item: item.assignment_id))
        return PreparedAssignmentSet(
            assignments=canonical,
            issuance_block=block.height,
            issuance_block_hash=block.block_hash,
            issuance_block_timestamp_ms=block.timestamp_ms,
            finality_evidence_bytes=finality_evidence,
        )

    def _issuance_finality_evidence(
        self,
        interval: object,
        *,
        block: VerifiedFinalizedBlock,
        window_id: str,
    ) -> bytes:
        identities = getattr(interval, "identities", None)
        attestations = getattr(interval, "attestations", None)
        bindings = getattr(interval, "replay_bindings", None)
        if (
            not isinstance(identities, tuple)
            or not isinstance(attestations, tuple)
            or not isinstance(bindings, tuple)
            or len(identities) != 1
            or len(attestations) != 1
            or len(bindings) != 1
        ):
            raise AssignmentPreparationError("assignment_issuance_finality_invalid")
        identity = identities[0]
        attestation = attestations[0]
        binding = bindings[0]
        if (
            not isinstance(identity, VerifiedFinalizedBlockIdentity)
            or not isinstance(attestation, bytes)
            or identity.snapshot.block_number != block.height
            or identity.snapshot.block_hash != block.block_hash
            or identity.snapshot.state_root != block.state_root
            or identity.finality_verifier_sha256 != block.finality_verifier_sha256
            or identity.finality_evidence_sha256 != block.finality_evidence_sha256
            or attestation != block.finality_evidence
        ):
            raise AssignmentPreparationError("assignment_issuance_finality_mismatch")
        try:
            evidence = AssignmentIssuanceFinalityEvidence(
                schema=ASSIGNMENT_ISSUANCE_FINALITY_SCHEMA,
                protocol=PROTOCOL_VERSION,
                window_id=window_id,
                timestamp_ms=block.timestamp_ms,
                identity=issuance_identity_object(identity),
                replay_binding=FinalityReplayBindingObject.from_evidence(binding),
                attestation_hex=attestation.hex(),
            )
        except (TypeError, ValueError) as error:
            raise AssignmentPreparationError("assignment_issuance_finality_invalid") from error
        return canonical_json_bytes(evidence)

    def _validate_context(
        self,
        context: PoolSelectionContext,
        work: StageWorkItem,
    ) -> None:
        if not isinstance(context, PoolSelectionContext):
            raise TypeError("assignment preparation requires PoolSelectionContext")
        if not isinstance(work, StageWorkItem) or work.stage is not WindowStage.POOL_AND_SELECTION:
            raise AssignmentPreparationError("assignment_preparation_wrong_stage")
        if work.window.plan != context.window:
            raise AssignmentPreparationError("assignment_context_window_mismatch")
        if context.window.scoring_policy_hash != scoring_policy_hash(self.policy):
            raise AssignmentPreparationError("assignment_context_policy_mismatch")
        if any(item.serving_url is None for item in context.selected_panel):
            raise AssignmentPreparationError("assignment_panel_serving_url_missing")

    def _validate_block(
        self,
        block: object,
        context: PoolSelectionContext,
    ) -> None:
        if not isinstance(block, VerifiedFinalizedBlock):
            raise AssignmentPreparationError("assignment_issuance_block_invalid")
        pins = self.policy.implementation_pins
        selection_ms = (
            QUICKNET_GENESIS_MS + (context.window.selection_round - 1) * QUICKNET_PERIOD_MS
        )
        issue_close_ms = (
            QUICKNET_GENESIS_MS + (context.window.issue_close_round - 1) * QUICKNET_PERIOD_MS
        )
        if (
            block.height <= context.window.closing_block
            or not selection_ms <= block.timestamp_ms < issue_close_ms
            or block.scoring_policy_hash != context.window.scoring_policy_hash
            or block.chain_observation != pins.live_chain
            or block.finality_verifier_sha256
            != getattr(self.finality, "finality_verifier_sha256", None)
        ):
            raise AssignmentPreparationError("assignment_issuance_block_mismatch")


__all__ = [
    "ASSIGNMENT_ISSUANCE_FINALITY_SCHEMA",
    "AssignmentIssuanceFinalityEvidence",
    "AssignmentPreparationError",
    "FinalizedPreparedAssignmentsAdapter",
    "issuance_identity_from_object",
    "issuance_identity_object",
]
