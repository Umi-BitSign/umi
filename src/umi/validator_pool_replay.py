"""Pure, proof-backed replay for the pool-and-selection stage.

The live pool effect deliberately accepts narrow collectors and persists all of
their proof material.  This module is the inverse boundary: it accepts only the
objects named by a signed stage receipt and independently reconstructs the
closing snapshot, eligible pool, Quicknet selection, miner panel, and complete
signed assignment Cartesian product.  It owns no store, wallet, network client,
or mutable cache.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .anchors import VerifiedAuthEvidence
from .artifacts import PublicBatchManifest, validate_public_batch_manifest
from .calibration_bundle import (
    CALIBRATION_RECEIPT_MEDIA_TYPE,
    CalibrationStageEvidence,
    FinalityReplayVerifier,
    calibration_stage_replay_hook_id,
)
from .chain_evidence import FinalizedSnapshotRef
from .drand import DrandPulse
from .encoding import account_id32
from .policy import ScoringPolicy, scoring_policy_hash
from .pool import (
    CandidateBatch,
    MinerCandidate,
    PoolManifest,
    batch_rank,
    candidate_pool_root,
    miner_rank,
    parse_pool_manifest_bytes,
    select_batches,
    select_miner_panel,
    selection_seed,
    verify_availability_certificate_member,
    verify_pool_artifacts,
)
from .protocol import (
    PROTOCOL_VERSION,
    TranslationRequest,
    base64url_decode,
    canonical_json_bytes,
)
from .registries import SpentCohortBatch
from .validator import PreparedRequestAttempt
from .validator_adapters import ADAPTER_RESULT_SCHEMA, stage_operation_id
from .validator_assignment_preparation import (
    ASSIGNMENT_ISSUANCE_FINALITY_SCHEMA,
    AssignmentIssuanceFinalityEvidence,
    issuance_identity_from_object,
)
from .validator_assignments import (
    MAX_ASSIGNMENTS_PER_WINDOW,
    MAX_REQUEST_BODY_BYTES,
    MAX_RESPONSE_BODY_BYTES,
    MAX_RETAINED_PREFIX_BYTES,
    WINDOW_SCHEMA,
    TranscriptWindowSpec,
    deterministic_assignment_id,
)
from .validator_chain import MultiStorageProofVerifier
from .validator_chain_scan import (
    FinalityAttestationReplayBinding,
    VerifiedFinalizedBlockIdentity,
)
from .validator_closing_snapshot import (
    AnnouncementValidatorProofEvidence,
    ClosingSnapshot,
    ClosingSnapshotProofEvidence,
    replay_announcement_validator_storage,
    replay_closing_snapshot_storage,
    validate_replayed_announcement_validator_snapshot,
    validate_replayed_closing_snapshot,
)
from .validator_delivery import (
    IssuedVideoDelivery,
    IssuedVideoDeliverySet,
    MirrorDiscoveryRule,
    VideoDeliveryCommitment,
    VideoDeliveryIssuanceEvidence,
    validate_delivery_issuance,
)
from .validator_journal import StageReceipt
from .validator_pool_effect import (
    POOL_CERTIFICATE_BREACH_SCHEMA,
    POOL_SELECTION_EVIDENCE_SCHEMA,
    AnnouncementValidatorSnapshot,
    ClosingNeuron,
    PoolAnchorRetrievalEvidence,
    PoolCertificateBreachEvidence,
    PoolEvidenceObjectRef,
    PoolSelectionEvidence,
    SelectedMinerEvidence,
    pool_certificate_breach_metadata,
)
from .validator_pool_no_score import (
    POOL_EMPTY_SOURCE_SCHEMA,
    POOL_NO_SCORE_SCHEMA,
    PoolEmptySourceEvidence,
    PoolNoScoreEvidence,
    PoolNoScoreObjectRef,
    pool_no_score_metadata,
)
from .validator_protocol_state import (
    ProtocolStateSnapshot,
    decode_protocol_state_snapshot,
)
from .validator_state import WindowPlan, WindowStage
from .validator_window_material import (
    WINDOW_MATERIAL_RECEIPT_SCHEMA,
    WINDOW_MATERIAL_SCHEMA,
    WindowMaterial,
    WindowMaterialReceipt,
)
from .window import QUICKNET_GENESIS_MS, QUICKNET_PERIOD_MS, ceil_div


class PoolStageReplayError(RuntimeError):
    """A pool receipt cannot be reproduced from its exact retained objects."""


@dataclass(frozen=True, slots=True)
class PoolStageReplay:
    """The independently reconstructed immutable outputs of the pool stage."""

    selection: PoolSelectionEvidence | PoolNoScoreEvidence | PoolCertificateBreachEvidence
    announcement_validator_snapshot: AnnouncementValidatorSnapshot
    closing_snapshot: ClosingSnapshot
    prior_protocol_state: ProtocolStateSnapshot
    window: WindowPlan
    assignment_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ProofBackedPoolStageReplayHook:
    """Calibration hook using the policy-pinned storage and finality verifiers."""

    verifier: MultiStorageProofVerifier
    finality_verifier: FinalityReplayVerifier
    finality_verifier_sha256: str

    def __post_init__(self) -> None:
        if not callable(self.verifier):
            raise TypeError("pool replay storage verifier must be callable")
        if not callable(self.finality_verifier):
            raise TypeError("pool replay finality verifier must be callable")
        try:
            raw_digest = bytes.fromhex(self.finality_verifier_sha256)
        except (TypeError, ValueError) as error:
            raise ValueError(
                "pool replay finality verifier digest must be lowercase SHA-256 hexadecimal"
            ) from error
        if len(raw_digest) != 32 or self.finality_verifier_sha256 != raw_digest.hex():
            raise ValueError(
                "pool replay finality verifier digest must be lowercase SHA-256 hexadecimal"
            )

    def __call__(
        self,
        *,
        policy: ScoringPolicy,
        evidence: CalibrationStageEvidence,
        receipt: StageReceipt,
        objects: Mapping[str, bytes],
    ) -> bool:
        resolve_pool_stage(
            policy=policy,
            evidence=evidence,
            receipt=receipt,
            objects=objects,
            verifier=self.verifier,
            finality_verifier=self.finality_verifier,
            finality_verifier_sha256=self.finality_verifier_sha256,
        )
        return True


@dataclass(frozen=True, slots=True)
class _QualifiedPool:
    raw: bytes
    manifest: PoolManifest
    public_by_batch: Mapping[str, PublicBatchManifest]
    public_ref_by_batch: Mapping[str, PoolEvidenceObjectRef | PoolNoScoreObjectRef]
    envelope_ref_by_batch: Mapping[str, PoolEvidenceObjectRef | PoolNoScoreObjectRef]


def resolve_pool_stage(
    *,
    policy: ScoringPolicy,
    evidence: CalibrationStageEvidence,
    receipt: StageReceipt,
    objects: Mapping[str, bytes],
    verifier: MultiStorageProofVerifier,
    finality_verifier: FinalityReplayVerifier,
    finality_verifier_sha256: str,
) -> PoolStageReplay:
    """Reproduce one pool receipt without consulting live or local mutable state."""

    if not isinstance(policy, ScoringPolicy):
        raise TypeError("pool replay policy must be ScoringPolicy")
    if policy.translation_weights_active:
        raise PoolStageReplayError("pool replay requires an inactive shadow policy")
    if not isinstance(evidence, CalibrationStageEvidence):
        raise TypeError("pool replay evidence must be CalibrationStageEvidence")
    if not isinstance(receipt, StageReceipt):
        raise TypeError("pool replay receipt must be StageReceipt")
    if not isinstance(objects, Mapping):
        raise TypeError("pool replay objects must be a digest mapping")
    if not callable(verifier) or not callable(finality_verifier):
        raise TypeError("pool replay verifiers must be callable")

    policy_hash = scoring_policy_hash(policy)
    receipt_bytes = canonical_json_bytes(receipt)
    if (
        evidence.stage_id != WindowStage.POOL_AND_SELECTION.value
        or receipt.stage != WindowStage.POOL_AND_SELECTION.value
        or evidence.window_id != receipt.window_id
        or evidence.scoring_policy_hash != policy_hash
        or evidence.replay_hook_id
        != calibration_stage_replay_hook_id(policy, WindowStage.POOL_AND_SELECTION.value)
        or receipt.operation_id
        != stage_operation_id(receipt.window_id, WindowStage.POOL_AND_SELECTION)
        or evidence.receipt_object.sha256 != hashlib.sha256(receipt_bytes).hexdigest()
        or evidence.receipt_object.media_type != CALIBRATION_RECEIPT_MEDIA_TYPE
        or evidence.receipt_object.size_bytes != len(receipt_bytes)
    ):
        raise PoolStageReplayError("pool calibration evidence binding is invalid")
    _validate_payload_table(evidence, receipt, objects)
    has_selection = _receipt_has_schema(
        receipt,
        objects,
        POOL_SELECTION_EVIDENCE_SCHEMA,
    )
    has_no_score = _receipt_has_schema(receipt, objects, POOL_NO_SCORE_SCHEMA)
    has_certificate_breach = _receipt_has_schema(
        receipt,
        objects,
        POOL_CERTIFICATE_BREACH_SCHEMA,
    )
    if sum((has_selection, has_no_score, has_certificate_breach)) != 1:
        raise PoolStageReplayError("pool receipt must contain exactly one decision schema")
    if has_certificate_breach:
        effect_metadata, terminal = _certificate_breach_receipt_metadata(receipt)
        return _resolve_pool_certificate_breach_stage(
            policy=policy,
            receipt=receipt,
            objects=objects,
            effect_metadata=effect_metadata,
            terminal=terminal,
            verifier=verifier,
            finality_verifier=finality_verifier,
            finality_verifier_sha256=finality_verifier_sha256,
        )
    effect_metadata = _completion_metadata(receipt)
    if has_no_score:
        return _resolve_pool_no_score_stage(
            policy=policy,
            receipt=receipt,
            objects=objects,
            effect_metadata=effect_metadata,
            verifier=verifier,
            finality_verifier=finality_verifier,
            finality_verifier_sha256=finality_verifier_sha256,
        )

    selection, selection_bytes = _find_schema_object(
        receipt,
        objects,
        POOL_SELECTION_EVIDENCE_SCHEMA,
        PoolSelectionEvidence,
        "pool selection evidence",
    )
    material, material_bytes = _find_schema_object(
        receipt,
        objects,
        WINDOW_MATERIAL_SCHEMA,
        WindowMaterial,
        "window material",
    )
    material_receipt, material_receipt_bytes = _find_schema_object(
        receipt,
        objects,
        WINDOW_MATERIAL_RECEIPT_SCHEMA,
        WindowMaterialReceipt,
        "window material receipt",
    )
    selection_digest = hashlib.sha256(selection_bytes).hexdigest()
    material_digest = hashlib.sha256(material_bytes).hexdigest()
    material_receipt_digest = hashlib.sha256(material_receipt_bytes).hexdigest()

    source_refs = {item.sha256: item for item in selection.source_objects}
    primary = {selection_digest, material_digest, material_receipt_digest}
    if set(objects) != set(source_refs) | primary or primary & set(source_refs):
        raise PoolStageReplayError("pool receipt object graph is not exact")
    for digest, reference in source_refs.items():
        receipted = next((item for item in receipt.objects if item.sha256 == digest), None)
        if receipted is None or receipted.model_dump() != reference.model_dump():
            raise PoolStageReplayError("pool source reference differs from its receipt")

    if (
        selection.window_id != receipt.window_id
        or selection.scoring_policy_hash != policy_hash
        or selection.protocol != PROTOCOL_VERSION
        or material.source_evidence_sha256 != selection_digest
        or material.window.window_id != receipt.window_id
        or material.window.scoring_policy_hash != policy_hash
    ):
        raise PoolStageReplayError("pool selection, material, and policy bindings disagree")
    expected_material_receipt = WindowMaterialReceipt(
        schema=WINDOW_MATERIAL_RECEIPT_SCHEMA,
        protocol=PROTOCOL_VERSION,
        window_id=material.window.window_id,
        window_index=material.window.window_index,
        scoring_policy_hash=material.window.scoring_policy_hash,
        source_evidence_sha256=selection_digest,
        material_sha256=material_digest,
        material_size_bytes=len(material_bytes),
        assignment_count=len(material.assignments),
    )
    if material_receipt != expected_material_receipt:
        raise PoolStageReplayError("window material receipt does not reproduce")

    source_bytes = {digest: objects[digest] for digest in source_refs}
    retained_policy = _canonical_explicit(
        source_bytes,
        selection.policy_object,
        ScoringPolicy,
        "pool policy",
    )
    if (
        retained_policy != policy
        or canonical_json_bytes(policy) != source_bytes[selection.policy_object.sha256]
    ):
        raise PoolStageReplayError("pool retained policy differs from bundle policy")
    prior_state = decode_protocol_state_snapshot(
        _resolve_ref(source_bytes, selection.prior_protocol_state)
    )
    if (
        prior_state.state_digest.hex() != selection.protocol_state_digest
        or prior_state.spent_registry.root.hex() != selection.prior_spent_root
        or prior_state.publisher_faults.root.hex() != selection.prior_publisher_fault_root
        or prior_state.last_window_index != selection.window_index - 1
    ):
        raise PoolStageReplayError("prior protocol state does not reproduce")

    window = material.window.to_plan()
    _validate_window(policy, selection, window)
    if material_receipt.window_index != window.window_index:
        raise PoolStageReplayError("window material receipt has another window index")

    announcement_bytes = _resolve_ref(
        source_bytes,
        selection.announcement_validator_snapshot,
    )
    announcement_proof = _resolve_ref(
        source_bytes,
        selection.announcement_validator_proof_evidence,
    )
    replayed_announcement = replay_announcement_validator_storage(
        announcement_proof,
        verifier=verifier,
    )
    announcement = validate_replayed_announcement_validator_snapshot(
        announcement_bytes,
        replayed_announcement,
        policy=policy,
    )
    verify_snapshot_finality(
        replayed_announcement.evidence,
        label="announcement",
        policy=policy,
        finality_verifier=finality_verifier,
        finality_verifier_sha256=finality_verifier_sha256,
    )
    _validate_announcement_window(announcement, window)

    closing_bytes = _resolve_ref(source_bytes, selection.closing_snapshot)
    closing_proof = _resolve_ref(source_bytes, selection.closing_proof_evidence)
    replayed_closing = replay_closing_snapshot_storage(closing_proof, verifier=verifier)
    closing = validate_replayed_closing_snapshot(
        closing_bytes,
        replayed_closing,
        policy=policy,
    )
    verify_snapshot_finality(
        replayed_closing.evidence,
        label="closing",
        policy=policy,
        finality_verifier=finality_verifier,
        finality_verifier_sha256=finality_verifier_sha256,
    )
    _validate_closing_window(
        closing,
        window,
        validator_hotkey=selection.validator_hotkey,
    )

    pools, explained, retrieval_evidence = _reconstruct_pools(
        policy=policy,
        source_refs=source_refs,
        source_bytes=source_bytes,
        selection=selection,
        announcement=announcement,
        closing=closing,
        window=window,
    )
    pulse_bytes = _resolve_ref(source_bytes, selection.selection_pulse)
    pulse = _parse_pulse(pulse_bytes, expected_round=window.selection_round)
    if pulse.evidence_digest != selection.selection_pulse_evidence_digest:
        raise PoolStageReplayError("selection pulse evidence digest does not reproduce")

    candidates = _eligible_candidates(
        policy=policy,
        pools=pools,
        closing=closing,
        prior_state=prior_state,
        window=window,
    )
    pool_root = candidate_pool_root(candidates)
    seed = selection_seed(pulse.signature_bytes, pool_root)
    if pool_root.hex() != selection.candidate_pool_root or seed.hex() != selection.selection_seed:
        raise PoolStageReplayError("candidate root or selection seed does not reproduce")
    selected = select_batches(
        candidates,
        seed,
        count=policy.limits.batches_selected_per_window,
    )
    _validate_candidate_evidence(selection, candidates, selected, pools, seed)

    selected_neurons = _validate_panel(
        policy=policy,
        selection=selection,
        closing=closing,
        prior_state=prior_state,
        seed=seed,
    )
    selected_manifests = tuple(
        _public_manifest(candidate.batch_id, pools) for candidate in selected
    )
    commitments = tuple(
        sorted(
            (
                VideoDeliveryCommitment(
                    batch_id=manifest.batch_id,
                    challenge_id=item.challenge_id,
                    sha256=item.media.sha256,
                    size_bytes=item.media.size_bytes,
                )
                for manifest in selected_manifests
                for item in manifest.items
            ),
            key=lambda item: (
                base64url_decode(item.batch_id),
                base64url_decode(item.challenge_id),
            ),
        )
    )
    delivery_result = IssuedVideoDeliverySet(
        deliveries=tuple(
            IssuedVideoDelivery.model_validate(item.model_dump(mode="json"))
            for item in selection.selected_video_deliveries
        ),
        discovery_rule_bytes=_resolve_ref(source_bytes, selection.mirror_discovery_rule),
        request_bytes=_resolve_ref(source_bytes, selection.delivery_issuance_request),
        response_bytes=_resolve_ref(source_bytes, selection.delivery_issuance_response),
        evidence_bytes=_resolve_ref(source_bytes, selection.delivery_issuance_evidence),
    )
    try:
        deliveries_tuple = validate_delivery_issuance(
            policy=policy,
            window=window,
            expected_commitments=commitments,
            result=delivery_result,
        )
        delivery_evidence = _parse_canonical(
            delivery_result.evidence_bytes,
            VideoDeliveryIssuanceEvidence,
            "video delivery issuance evidence",
        )
        if (
            delivery_evidence.observed_window_wire_bytes
            != retrieval_evidence.artifact_observed_wire_bytes
            + delivery_evidence.delivery_observed_wire_bytes
            or delivery_evidence.accounted_window_wire_bytes
            != retrieval_evidence.artifact_accounted_wire_bytes
            + delivery_evidence.delivery_accounted_wire_bytes
            or delivery_evidence.accounted_window_wire_bytes
            > policy.limits.maximum_validator_window_wire_bytes
        ):
            raise ValueError("delivery evidence does not reconcile window accounting")
    except (TypeError, ValueError) as error:
        raise PoolStageReplayError("video delivery issuance does not reproduce") from error
    deliveries = {(item.batch_id, item.challenge_id): item for item in deliveries_tuple}

    issuance_bytes = _resolve_ref(source_bytes, selection.issuance_finality_evidence)
    issuance = _parse_canonical(
        issuance_bytes,
        AssignmentIssuanceFinalityEvidence,
        "assignment issuance finality",
    )
    _verify_issuance_finality(
        issuance,
        policy=policy,
        selection=selection,
        window=window,
        finality_verifier=finality_verifier,
        finality_verifier_sha256=finality_verifier_sha256,
    )
    assignment_ids = _validate_material_assignments(
        policy=policy,
        selection=selection,
        material=material,
        window=window,
        selected_manifests=selected_manifests,
        selected_neurons=selected_neurons,
        deliveries=deliveries,
        issuance=issuance,
    )

    explained.update(
        {
            selection.policy_object.sha256,
            selection.prior_protocol_state.sha256,
            selection.announcement_validator_snapshot.sha256,
            selection.announcement_validator_proof_evidence.sha256,
            selection.closing_snapshot.sha256,
            selection.closing_proof_evidence.sha256,
            selection.artifact_retrieval_evidence.sha256,
            selection.mirror_discovery_rule.sha256,
            selection.delivery_issuance_request.sha256,
            selection.delivery_issuance_response.sha256,
            selection.delivery_issuance_evidence.sha256,
            selection.mirror_readiness_set.sha256,
            selection.selection_pulse.sha256,
            selection.issuance_finality_evidence.sha256,
        }
    )
    if set(source_refs) != explained:
        raise PoolStageReplayError("pool source index contains an unexplained object")

    expected_effect_metadata = {
        "pool_selection_evidence_sha256": selection_digest,
        "window_material_sha256": material_digest,
        "window_material_receipt_sha256": material_receipt_digest,
        "candidate_pool_root": pool_root.hex(),
        "selection_seed": seed.hex(),
        "selected_batch_ids": [item.batch_id for item in selected],
        "selected_miner_hotkeys": [item.hotkey for item in selected_neurons],
        "assignment_count": len(assignment_ids),
        "announcement_validator_proof_evidence_sha256": (announcement.proof_evidence_sha256),
        "closing_proof_evidence_sha256": closing.proof_evidence_sha256,
    }
    if effect_metadata != expected_effect_metadata:
        raise PoolStageReplayError("pool receipt metadata does not reproduce")

    return PoolStageReplay(
        selection=selection,
        announcement_validator_snapshot=announcement,
        closing_snapshot=closing,
        prior_protocol_state=prior_state,
        window=window,
        assignment_ids=assignment_ids,
    )


def _resolve_pool_certificate_breach_stage(
    *,
    policy: ScoringPolicy,
    receipt: StageReceipt,
    objects: Mapping[str, bytes],
    effect_metadata: Mapping[str, Any],
    terminal: Mapping[str, Any],
    verifier: MultiStorageProofVerifier,
    finality_verifier: FinalityReplayVerifier,
    finality_verifier_sha256: str,
) -> PoolStageReplay:
    breach, breach_bytes = _find_schema_object(
        receipt,
        objects,
        POOL_CERTIFICATE_BREACH_SCHEMA,
        PoolCertificateBreachEvidence,
        "pool certificate-breach evidence",
    )
    breach_digest = hashlib.sha256(breach_bytes).hexdigest()
    source_refs = {item.sha256: item for item in breach.source_objects}
    if set(objects) != set(source_refs) | {breach_digest} or breach_digest in source_refs:
        raise PoolStageReplayError("certificate-breach receipt object graph is not exact")
    receipt_refs = {item.sha256: item for item in receipt.objects}
    for digest, reference in source_refs.items():
        receipted = receipt_refs.get(digest)
        if receipted is None or receipted.model_dump() != reference.model_dump():
            raise PoolStageReplayError("certificate-breach source differs from its receipt")

    policy_hash = scoring_policy_hash(policy)
    window = breach.window.to_plan()
    if (
        breach.window_id != receipt.window_id
        or breach.scoring_policy_hash != policy_hash
        or breach.protocol != PROTOCOL_VERSION
        or breach.operation_id != receipt.operation_id
    ):
        raise PoolStageReplayError("certificate-breach decision changes its receipt binding")
    _validate_window(policy, breach, window)
    source_bytes = {digest: objects[digest] for digest in source_refs}
    retained_policy = _canonical_explicit(
        source_bytes,
        breach.policy_object,
        ScoringPolicy,
        "pool policy",
    )
    if (
        retained_policy != policy
        or canonical_json_bytes(policy) != source_bytes[breach.policy_object.sha256]
    ):
        raise PoolStageReplayError("certificate-breach policy differs from the active policy")
    prior_state = decode_protocol_state_snapshot(
        _resolve_ref(source_bytes, breach.prior_protocol_state)
    )
    if (
        prior_state.state_digest.hex() != breach.protocol_state_digest
        or prior_state.spent_registry.root.hex() != breach.prior_spent_root
        or prior_state.publisher_faults.root.hex() != breach.prior_publisher_fault_root
        or prior_state.last_window_index != breach.window_index - 1
    ):
        raise PoolStageReplayError("certificate-breach prior protocol state does not reproduce")

    announcement_bytes = _resolve_ref(
        source_bytes,
        breach.announcement_validator_snapshot,
    )
    replayed_announcement = replay_announcement_validator_storage(
        _resolve_ref(source_bytes, breach.announcement_validator_proof_evidence),
        verifier=verifier,
    )
    announcement = validate_replayed_announcement_validator_snapshot(
        announcement_bytes,
        replayed_announcement,
        policy=policy,
    )
    verify_snapshot_finality(
        replayed_announcement.evidence,
        label="announcement",
        policy=policy,
        finality_verifier=finality_verifier,
        finality_verifier_sha256=finality_verifier_sha256,
    )
    _validate_announcement_window(announcement, window)

    closing_bytes = _resolve_ref(source_bytes, breach.closing_snapshot)
    replayed_closing = replay_closing_snapshot_storage(
        _resolve_ref(source_bytes, breach.closing_proof_evidence),
        verifier=verifier,
    )
    closing = validate_replayed_closing_snapshot(
        closing_bytes,
        replayed_closing,
        policy=policy,
    )
    verify_snapshot_finality(
        replayed_closing.evidence,
        label="closing",
        policy=policy,
        finality_verifier=finality_verifier,
        finality_verifier_sha256=finality_verifier_sha256,
    )
    _validate_closing_window(closing, window, validator_hotkey=breach.validator_hotkey)

    pulse_bytes = _resolve_ref(source_bytes, breach.selection_pulse)
    pulse = _parse_pulse(pulse_bytes, expected_round=window.selection_round)
    if pulse.evidence_digest != breach.selection_pulse_evidence_digest:
        raise PoolStageReplayError("certificate-breach selection pulse digest changed")
    discovery = _canonical_explicit(
        source_bytes,
        breach.mirror_discovery_rule,
        MirrorDiscoveryRule,
        "mirror discovery rule",
    )
    if (
        breach.mirror_discovery_rule.sha256
        != policy.implementation_pins.rules.mirror_discovery_rule_sha256
        or discovery.authentication_profile
        != policy.implementation_pins.rules.mirror_authentication_profile
    ):
        raise PoolStageReplayError("certificate-breach mirror discovery differs from policy")

    try:
        manifest = parse_pool_manifest_bytes(
            _resolve_ref(source_bytes, breach.final_pool_manifest),
            policy=policy,
        )
    except (TypeError, ValueError) as error:
        raise PoolStageReplayError("certificate-breach pool manifest is invalid") from error
    publisher = account_id32(manifest.publisher_hotkey)
    if (
        account_id32(breach.publisher_hotkey) != publisher
        or manifest.window_id != window.window_id
        or manifest.scoring_policy_hash != policy_hash
    ):
        raise PoolStageReplayError("certificate-breach pool manifest changes publisher or window")
    active_validators = tuple(
        item.validator_hotkey for item in announcement.validators if item.validator_permit
    )
    if len(active_validators) < 4:
        raise PoolStageReplayError("certificate-breach validator set lacks quorum authority")
    try:
        verify_availability_certificate_member(
            manifest.availability_certificate,
            manifest.body(),
            active_validator_hotkeys=active_validators,
            policy=policy,
        )
    except (TypeError, ValueError) as error:
        raise PoolStageReplayError("certificate-breach quorum membership is invalid") from error

    policy_publishers = {
        account_id32(item.publisher_hotkey): item for item in policy.publisher_registry
    }
    closing_publishers = {account_id32(item.publisher_hotkey): item for item in closing.publishers}
    policy_row = policy_publishers.get(publisher)
    closing_row = closing_publishers.get(publisher)
    manifest_digest = hashlib.sha256(
        _resolve_ref(source_bytes, breach.final_pool_manifest)
    ).hexdigest()
    from .mirror_readiness import MirrorReadinessError, verify_live_mirror_readiness

    try:
        readiness = verify_live_mirror_readiness(
            policy=policy,
            discovery_rule_bytes=_resolve_ref(source_bytes, breach.mirror_discovery_rule),
            readiness_set_bytes=_resolve_ref(source_bytes, breach.mirror_readiness_set),
        )
    except MirrorReadinessError as error:
        raise PoolStageReplayError("certificate-breach mirror readiness does not verify") from error
    certificate_signers = {
        account_id32(item.validator_hotkey) for item in manifest.availability_certificate.signatures
    }
    if (
        policy_row is None
        or closing_row is None
        or not closing_row.registered
        or account_id32(closing_row.owner_coldkey) != account_id32(policy_row.owner_coldkey)
        or closing_row.control_group_id != policy_row.control_group_id
        or closing_row.locked_collateral_alpha_rao < policy.minimum_publisher_collateral_alpha_rao
        or closing_row.minimum_locked_collateral_alpha_rao
        < policy.minimum_publisher_collateral_alpha_rao
        or closing_row.pool_manifest_sha256 != manifest_digest
        or closing_row.anchor_inclusion_block is None
        or closing_row.anchor_inclusion_block > window.closing_block
        or readiness.readiness.window_id != window.window_id
        or readiness.readiness.window_index != window.window_index
        or readiness.expected_pool_manifest_sha256_by_publisher_account.get(publisher)
        != manifest_digest
        or certificate_signers != set(readiness.signer_accounts)
        or not prior_state.publisher_faults.is_eligible(
            policy_row.control_group_id,
            window.window_index,
        )
    ):
        raise PoolStageReplayError("certificate-breach publisher was not chain-eligible")

    entries = [item for item in manifest.batches if item.batch_id == breach.batch_id]
    if len(entries) != 1:
        raise PoolStageReplayError("certificate-breach batch is absent or duplicated")
    entry = entries[0]
    challenge_id: str | None = None
    expected_size: int | None = None
    if breach.artifact_kind == "public_manifest":
        expected_sha256 = entry.public_manifest_sha256
        resource_key = f"public:{entry.batch_id}:{entry.public_manifest_sha256}"
    elif breach.artifact_kind == "ground_truth_envelope":
        expected_sha256 = entry.ciphertext_sha256
        resource_key = f"envelope:{entry.batch_id}:{entry.ciphertext_sha256}"
    else:
        if breach.parent_public_manifest is None:
            raise PoolStageReplayError("certificate-breach video lacks its public manifest")
        parent_bytes = _resolve_ref(source_bytes, breach.parent_public_manifest)
        if hashlib.sha256(parent_bytes).hexdigest() != entry.public_manifest_sha256:
            raise PoolStageReplayError("certificate-breach public-manifest digest changed")
        parent = _parse_canonical(
            parent_bytes,
            PublicBatchManifest,
            "certificate-breach public manifest",
        )
        try:
            validate_public_batch_manifest(parent, policy)
        except (TypeError, ValueError) as error:
            raise PoolStageReplayError(
                "certificate-breach public manifest is ineligible"
            ) from error
        if (
            parent.window_id != window.window_id
            or account_id32(parent.publisher_hotkey) != publisher
            or parent.batch_id != entry.batch_id
            or parent.scoring_policy_hash != policy_hash
        ):
            raise PoolStageReplayError("certificate-breach public manifest is misbound")
        items = [item for item in parent.items if item.challenge_id == breach.challenge_id]
        if len(items) != 1:
            raise PoolStageReplayError("certificate-breach video is absent or duplicated")
        item = items[0]
        challenge_id = item.challenge_id
        expected_sha256 = item.media.sha256
        expected_size = item.media.size_bytes
        resource_key = f"video:{entry.batch_id}:{item.challenge_id}:{item.media.sha256}"
    if (
        breach.expected_sha256 != expected_sha256
        or breach.challenge_id != challenge_id
        or breach.expected_size_bytes != expected_size
        or breach.resource_key_sha256 != hashlib.sha256(resource_key.encode("utf-8")).hexdigest()
    ):
        raise PoolStageReplayError("certificate-breach target no longer reproduces")

    retrieval = _parse_canonical(
        _resolve_ref(source_bytes, breach.artifact_retrieval_evidence),
        PoolAnchorRetrievalEvidence,
        "certificate-breach retrieval evidence",
    )
    if (
        retrieval.window_id != window.window_id
        or retrieval.window_index != window.window_index
        or retrieval.scoring_policy_hash != policy_hash
        or retrieval.discovery_rule_sha256 != breach.mirror_discovery_rule.sha256
    ):
        raise PoolStageReplayError("certificate-breach retrieval evidence is misbound")
    timely = {
        account_id32(item.publisher_hotkey): item.pool_manifest_sha256
        for item in closing.publishers
        if item.pool_manifest_sha256 is not None
        and item.anchor_inclusion_block is not None
        and item.anchor_inclusion_block <= window.closing_block
    }
    outcomes = {account_id32(item.publisher_hotkey): item for item in retrieval.anchor_outcomes}
    if (
        set(outcomes) != set(timely)
        or any(item.sha256 != timely[account] for account, item in outcomes.items())
        or any(
            item.status not in {"qualified", "ignored_unavailable", "ignored_invalid"}
            for item in outcomes.values()
        )
        or outcomes[publisher].status != "qualified"
    ):
        raise PoolStageReplayError("certificate-breach anchor outcomes do not reproduce")
    target_attempts = [
        item
        for item in retrieval.attempts
        if item.resource_key_sha256 == breach.resource_key_sha256
    ]
    expected_urls = [
        hashlib.sha256((origin + f"/v1/umi/objects/{expected_sha256}").encode("utf-8")).hexdigest()
        for origin in discovery.origins[: policy.limits.maximum_video_fetch_attempts_per_actor]
    ]
    if (
        len(target_attempts) != len(expected_urls)
        or [item.attempt_index for item in target_attempts] != list(range(len(expected_urls)))
        or [item.url_sha256 for item in target_attempts] != expected_urls
        or any(item.status == "success" for item in target_attempts)
    ):
        raise PoolStageReplayError("certificate-breach mirror exhaustion does not reproduce")

    expected_effect_metadata = pool_certificate_breach_metadata(
        breach,
        evidence_sha256=breach_digest,
    )
    expected_incident = {
        "incident_id": f"umi-certificate-breach/{window.window_id}",
        "reason_code": "certificate_breach",
        "metadata": {
            "certificate_breach_evidence_sha256": breach_digest,
            "publisher_hotkey": breach.publisher_hotkey,
            "artifact_kind": breach.artifact_kind,
            "batch_id": breach.batch_id,
            "challenge_id": breach.challenge_id,
            "expected_sha256": breach.expected_sha256,
        },
    }
    if (
        effect_metadata != expected_effect_metadata
        or terminal.get("outcome") != "skipped"
        or terminal.get("reason_code") != "certificate_breach"
        or terminal.get("incident") != expected_incident
        or terminal.get("pause_scopes") != ["window_intake"]
        or not isinstance(terminal.get("audit_release_block"), int)
        or isinstance(terminal.get("audit_release_block"), bool)
        or terminal["audit_release_block"] <= window.announcement_block
    ):
        raise PoolStageReplayError("certificate-breach terminal decision does not reproduce")
    return PoolStageReplay(
        selection=breach,
        announcement_validator_snapshot=announcement,
        closing_snapshot=closing,
        prior_protocol_state=prior_state,
        window=window,
        assignment_ids=(),
    )


def _resolve_pool_no_score_stage(
    *,
    policy: ScoringPolicy,
    receipt: StageReceipt,
    objects: Mapping[str, bytes],
    effect_metadata: Mapping[str, Any],
    verifier: MultiStorageProofVerifier,
    finality_verifier: FinalityReplayVerifier,
    finality_verifier_sha256: str,
) -> PoolStageReplay:
    no_score, no_score_bytes = _find_schema_object(
        receipt,
        objects,
        POOL_NO_SCORE_SCHEMA,
        PoolNoScoreEvidence,
        "pool no-score evidence",
    )
    no_score_digest = hashlib.sha256(no_score_bytes).hexdigest()
    source_refs = {item.sha256: item for item in no_score.source_objects}
    if set(objects) != set(source_refs) | {no_score_digest} or no_score_digest in source_refs:
        raise PoolStageReplayError("pool no-score receipt object graph is not exact")
    receipt_refs = {item.sha256: item for item in receipt.objects}
    for digest, reference in source_refs.items():
        receipted = receipt_refs.get(digest)
        if receipted is None or receipted.model_dump() != reference.model_dump():
            raise PoolStageReplayError("pool no-score source differs from its receipt")

    policy_hash = scoring_policy_hash(policy)
    window = no_score.window.to_plan()
    if (
        no_score.window_id != receipt.window_id
        or no_score.scoring_policy_hash != policy_hash
        or no_score.protocol != PROTOCOL_VERSION
        or no_score.operation_id != receipt.operation_id
    ):
        raise PoolStageReplayError("pool no-score decision changes its receipt binding")
    _validate_window(policy, no_score, window)

    source_bytes = {digest: objects[digest] for digest in source_refs}
    retained_policy = _canonical_explicit(
        source_bytes,
        no_score.policy_object,
        ScoringPolicy,
        "pool policy",
    )
    if (
        retained_policy != policy
        or canonical_json_bytes(policy) != source_bytes[no_score.policy_object.sha256]
    ):
        raise PoolStageReplayError("pool retained policy differs from bundle policy")
    prior_state = decode_protocol_state_snapshot(
        _resolve_ref(source_bytes, no_score.prior_protocol_state)
    )
    if (
        prior_state.state_digest.hex() != no_score.protocol_state_digest
        or prior_state.spent_registry.root.hex() != no_score.prior_spent_root
        or prior_state.publisher_faults.root.hex() != no_score.prior_publisher_fault_root
        or prior_state.last_window_index != no_score.window_index - 1
    ):
        raise PoolStageReplayError("prior protocol state does not reproduce")

    announcement_bytes = _resolve_ref(
        source_bytes,
        no_score.announcement_validator_snapshot,
    )
    announcement_proof = _resolve_ref(
        source_bytes,
        no_score.announcement_validator_proof_evidence,
    )
    replayed_announcement = replay_announcement_validator_storage(
        announcement_proof,
        verifier=verifier,
    )
    announcement = validate_replayed_announcement_validator_snapshot(
        announcement_bytes,
        replayed_announcement,
        policy=policy,
    )
    verify_snapshot_finality(
        replayed_announcement.evidence,
        label="announcement",
        policy=policy,
        finality_verifier=finality_verifier,
        finality_verifier_sha256=finality_verifier_sha256,
    )
    _validate_announcement_window(announcement, window)

    closing_bytes = _resolve_ref(source_bytes, no_score.closing_snapshot)
    closing_proof = _resolve_ref(source_bytes, no_score.closing_proof_evidence)
    replayed_closing = replay_closing_snapshot_storage(
        closing_proof,
        verifier=verifier,
    )
    closing = validate_replayed_closing_snapshot(
        closing_bytes,
        replayed_closing,
        policy=policy,
    )
    verify_snapshot_finality(
        replayed_closing.evidence,
        label="closing",
        policy=policy,
        finality_verifier=finality_verifier,
        finality_verifier_sha256=finality_verifier_sha256,
    )
    _validate_closing_window(
        closing,
        window,
        validator_hotkey=no_score.validator_hotkey,
    )

    empty_source = _pool_empty_source_evidence(
        no_score=no_score,
        source_bytes=source_bytes,
        closing=closing,
        window=window,
        policy=policy,
    )
    if empty_source is None:
        pools, explained, _retrieval_evidence = _reconstruct_pools(
            policy=policy,
            source_refs=source_refs,
            source_bytes=source_bytes,
            selection=no_score,
            announcement=announcement,
            closing=closing,
            window=window,
        )
    else:
        pools = ()
        explained = {no_score.empty_source_evidence.sha256}
    pulse_bytes = _resolve_ref(source_bytes, no_score.selection_pulse)
    pulse = _parse_pulse(pulse_bytes, expected_round=window.selection_round)
    if pulse.evidence_digest != no_score.selection_pulse_evidence_digest:
        raise PoolStageReplayError("selection pulse evidence digest does not reproduce")

    candidates = _eligible_candidates(
        policy=policy,
        pools=pools,
        closing=closing,
        prior_state=prior_state,
        window=window,
        allow_empty=True,
    )
    selected: tuple[CandidateBatch, ...] = ()
    if no_score.reason_code == "candidate_pool_empty":
        if candidates or no_score.candidate_pool_root is not None:
            raise PoolStageReplayError("empty candidate pool no longer reproduces")
        if no_score.selection_seed is not None or no_score.candidates:
            raise PoolStageReplayError("empty candidate pool carries ranked evidence")
    else:
        if not candidates:
            raise PoolStageReplayError("nonempty pool no-score outcome has no candidates")
        pool_root = candidate_pool_root(candidates)
        seed = selection_seed(pulse.signature_bytes, pool_root)
        if no_score.candidate_pool_root != pool_root.hex() or no_score.selection_seed != seed.hex():
            raise PoolStageReplayError("pool no-score root or seed does not reproduce")
        if no_score.reason_code == "candidate_control_group_count_insufficient":
            try:
                select_batches(
                    candidates,
                    seed,
                    count=policy.limits.batches_selected_per_window,
                )
            except ValueError:
                pass
            else:
                raise PoolStageReplayError(
                    "candidate control-group insufficiency no longer reproduces"
                )
        else:
            selected = select_batches(
                candidates,
                seed,
                count=policy.limits.batches_selected_per_window,
            )
            panel = _validate_panel(
                policy=policy,
                selection=no_score,
                closing=closing,
                prior_state=prior_state,
                seed=seed,
                allow_empty=True,
            )
            if panel:
                raise PoolStageReplayError("eligible miner set is no longer empty")
        _validate_candidate_evidence(no_score, candidates, selected, pools, seed)

    explained.update(
        {
            no_score.policy_object.sha256,
            no_score.prior_protocol_state.sha256,
            no_score.announcement_validator_snapshot.sha256,
            no_score.announcement_validator_proof_evidence.sha256,
            no_score.closing_snapshot.sha256,
            no_score.closing_proof_evidence.sha256,
            no_score.selection_pulse.sha256,
        }
    )
    if no_score.artifact_retrieval_evidence is not None:
        explained.add(no_score.artifact_retrieval_evidence.sha256)
    if no_score.empty_source_evidence is not None:
        explained.add(no_score.empty_source_evidence.sha256)
    if set(source_refs) != explained:
        raise PoolStageReplayError("pool no-score source index has an unexplained object")
    expected_metadata = pool_no_score_metadata(
        no_score,
        origin_sha256=no_score_digest,
    )
    if effect_metadata != expected_metadata:
        raise PoolStageReplayError("pool no-score receipt metadata does not reproduce")
    return PoolStageReplay(
        selection=no_score,
        announcement_validator_snapshot=announcement,
        closing_snapshot=closing,
        prior_protocol_state=prior_state,
        window=window,
        assignment_ids=(),
    )


def _pool_empty_source_evidence(
    *,
    no_score: PoolNoScoreEvidence,
    source_bytes: Mapping[str, bytes],
    closing: ClosingSnapshot,
    window: WindowPlan,
    policy: ScoringPolicy,
) -> PoolEmptySourceEvidence | None:
    reference = no_score.empty_source_evidence
    if reference is None:
        return None
    if reference.media_type != "application/json":
        raise PoolStageReplayError("empty-source evidence has the wrong media type")
    evidence = _canonical_explicit(
        source_bytes,
        reference,
        PoolEmptySourceEvidence,
        "empty pool source evidence",
    )
    snapshot_sha256 = hashlib.sha256(source_bytes[no_score.closing_snapshot.sha256]).hexdigest()
    proof_sha256 = hashlib.sha256(source_bytes[no_score.closing_proof_evidence.sha256]).hexdigest()
    if (
        evidence.schema_ != POOL_EMPTY_SOURCE_SCHEMA
        or evidence.window_id != window.window_id
        or evidence.window_index != window.window_index
        or evidence.scoring_policy_hash != scoring_policy_hash(policy)
        or evidence.closing_block != window.closing_block
        or evidence.closing_block_hash != closing.closing_block_hash
        or evidence.closing_snapshot_sha256 != snapshot_sha256
        or evidence.closing_proof_evidence_sha256 != proof_sha256
        or evidence.publisher_registry_count != len(closing.publishers)
        or len(closing.publishers) != len(policy.publisher_registry)
    ):
        raise PoolStageReplayError("empty-source evidence changes its closing snapshot binding")
    if any(
        row.pool_manifest_sha256 is not None
        and row.anchor_inclusion_block is not None
        and row.anchor_inclusion_block <= window.closing_block
        for row in closing.publishers
    ):
        raise PoolStageReplayError("empty-source evidence conflicts with a timely pool anchor")
    return evidence


def _validate_payload_table(
    evidence: CalibrationStageEvidence,
    receipt: StageReceipt,
    objects: Mapping[str, bytes],
) -> None:
    receipt_refs = {item.sha256: item for item in receipt.objects}
    evidence_refs = {item.sha256: item for item in evidence.payload_objects}
    if len(receipt_refs) != len(receipt.objects) or len(evidence_refs) != len(
        evidence.payload_objects
    ):
        raise PoolStageReplayError("pool payload table contains duplicate digests")
    if set(objects) != set(receipt_refs) or set(evidence_refs) != set(receipt_refs):
        raise PoolStageReplayError("pool payload table is incomplete or contains extras")
    for digest, reference in receipt_refs.items():
        supplied = evidence_refs[digest]
        data = objects[digest]
        if (
            supplied.sha256 != reference.sha256
            or supplied.media_type != reference.media_type
            or supplied.size_bytes != reference.size_bytes
            or not isinstance(data, bytes)
            or len(data) != reference.size_bytes
            or hashlib.sha256(data).hexdigest() != digest
        ):
            raise PoolStageReplayError("pool payload bytes or metadata do not reproduce")


def _completion_metadata(receipt: StageReceipt) -> dict[str, Any]:
    value = receipt.metadata
    if (
        set(value) != {"schema", "kind", "metadata", "terminal"}
        or value.get("schema") != ADAPTER_RESULT_SCHEMA
        or value.get("kind") != "completion"
        or value.get("terminal") is not None
        or not isinstance(value.get("metadata"), dict)
    ):
        raise PoolStageReplayError("pool receipt is not one canonical completion")
    return dict(value["metadata"])


def _certificate_breach_receipt_metadata(
    receipt: StageReceipt,
) -> tuple[dict[str, Any], dict[str, Any]]:
    value = receipt.metadata
    if (
        set(value) != {"schema", "kind", "metadata", "terminal"}
        or value.get("schema") != ADAPTER_RESULT_SCHEMA
        or value.get("kind") != "terminal"
        or not isinstance(value.get("metadata"), dict)
        or not isinstance(value.get("terminal"), dict)
    ):
        raise PoolStageReplayError(
            "certificate-breach receipt is not one canonical terminal decision"
        )
    terminal = dict(value["terminal"])
    if set(terminal) != {
        "outcome",
        "reason_code",
        "audit_release_block",
        "incident",
        "pause_scopes",
    }:
        raise PoolStageReplayError("certificate-breach terminal metadata has extra fields")
    return dict(value["metadata"]), terminal


def _find_schema_object(
    receipt: StageReceipt,
    objects: Mapping[str, bytes],
    schema: str,
    model: type[Any],
    label: str,
) -> tuple[Any, bytes]:
    matches: list[bytes] = []
    for reference in receipt.objects:
        if reference.media_type != "application/json":
            continue
        data = objects[reference.sha256]
        try:
            value = json.loads(data)
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if isinstance(value, dict) and value.get("schema") == schema:
            matches.append(data)
    if len(matches) != 1:
        raise PoolStageReplayError(f"{label} cardinality is not one")
    data = matches[0]
    return _parse_canonical(data, model, label), data


def _receipt_has_schema(
    receipt: StageReceipt,
    objects: Mapping[str, bytes],
    schema: str,
) -> bool:
    matches = 0
    for reference in receipt.objects:
        if reference.media_type != "application/json":
            continue
        data = objects[reference.sha256]
        try:
            value = json.loads(data)
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if isinstance(value, dict) and value.get("schema") == schema:
            matches += 1
    if matches > 1:
        raise PoolStageReplayError(f"{schema} cardinality exceeds one")
    return matches == 1


def _parse_canonical(data: bytes, model: type[Any], label: str) -> Any:
    try:
        value = model.model_validate_json(data)
    except Exception as error:
        raise PoolStageReplayError(f"{label} is invalid") from error
    if canonical_json_bytes(value) != data:
        raise PoolStageReplayError(f"{label} is not canonical JSON")
    return value


def _canonical_explicit(
    objects: Mapping[str, bytes],
    reference: PoolEvidenceObjectRef | PoolNoScoreObjectRef,
    model: type[Any],
    label: str,
) -> Any:
    return _parse_canonical(_resolve_ref(objects, reference), model, label)


def _resolve_ref(
    objects: Mapping[str, bytes],
    reference: PoolEvidenceObjectRef | PoolNoScoreObjectRef,
) -> bytes:
    try:
        data = objects[reference.sha256]
    except KeyError as error:
        raise PoolStageReplayError("pool evidence reference is missing") from error
    if (
        not isinstance(data, bytes)
        or len(data) != reference.size_bytes
        or hashlib.sha256(data).hexdigest() != reference.sha256
    ):
        raise PoolStageReplayError("pool evidence reference does not reproduce")
    return data


def _validate_window(
    policy: ScoringPolicy,
    selection: PoolSelectionEvidence | PoolNoScoreEvidence | PoolCertificateBreachEvidence,
    window: WindowPlan,
) -> None:
    expected_announcement = (
        policy.activation_block + window.window_index * policy.clock.window_stride_blocks
    )
    if (
        window.window_id != selection.window_id
        or window.window_index != selection.window_index
        or window.scoring_policy_hash != selection.scoring_policy_hash
        or window.announcement_block != expected_announcement
        or window.proposal_close_block != expected_announcement + policy.clock.proposal_blocks
        or window.closing_block != expected_announcement + policy.clock.anchor_blocks
        or window.issue_close_round - window.selection_round
        != ceil_div(policy.clock.issue_allowance_seconds, 3)
        or window.response_close_round - window.issue_close_round
        != ceil_div(policy.clock.response_window_seconds, 3)
        or window.reveal_round - window.response_close_round
        != ceil_div(policy.clock.reveal_margin_seconds, 3)
    ):
        raise PoolStageReplayError("pool window schedule does not reproduce from policy")


def verify_snapshot_finality(
    proof: AnnouncementValidatorProofEvidence | ClosingSnapshotProofEvidence,
    *,
    label: str,
    policy: ScoringPolicy,
    finality_verifier: FinalityReplayVerifier,
    finality_verifier_sha256: str,
) -> None:
    """Replay one retained smoldot finality attestation against policy pins."""
    finality = proof.finality
    if finality.finality_verifier_sha256 != finality_verifier_sha256:
        raise PoolStageReplayError(f"{label} finality verifier is not policy-pinned")
    attestation = bytes.fromhex(finality.finality_attestation[2:])
    identity = VerifiedFinalizedBlockIdentity(
        snapshot=FinalizedSnapshotRef(
            block_number=finality.block_number,
            block_hash=finality.block_hash,
            parent_hash=finality.parent_block_hash,
            state_root=finality.state_root,
        ),
        parent_snapshot=FinalizedSnapshotRef(
            block_number=finality.parent_block_number,
            block_hash=finality.parent_block_hash,
            parent_hash=finality.parent_parent_hash,
            state_root=finality.parent_state_root,
        ),
        extrinsics_root=finality.extrinsics_root,
        finality_verifier_sha256=finality.finality_verifier_sha256,
        finality_evidence_sha256=finality.finality_attestation_sha256,
    )
    try:
        binding = FinalityAttestationReplayBinding(**finality.replay_binding)
        accepted = finality_verifier(
            identities=(identity,),
            attestations=(attestation,),
            replay_bindings=(binding,),
            policy=policy,
        )
    except Exception as error:
        raise PoolStageReplayError(f"{label} finality replay failed") from error
    if accepted is not True:
        raise PoolStageReplayError(f"{label} finality replay failed")


def _validate_announcement_window(
    announcement: AnnouncementValidatorSnapshot,
    window: WindowPlan,
) -> None:
    if (
        announcement.window_id != window.window_id
        or announcement.window_index != window.window_index
        or announcement.scoring_policy_hash != window.scoring_policy_hash
        or announcement.announcement_block != window.announcement_block
    ):
        raise PoolStageReplayError(
            "announcement validator snapshot does not bind the selection window"
        )


def _validate_closing_window(
    closing: ClosingSnapshot,
    window: WindowPlan,
    *,
    validator_hotkey: str,
) -> None:
    selection_publication_ms = (
        QUICKNET_GENESIS_MS + (window.selection_round - 1) * QUICKNET_PERIOD_MS
    )
    if (
        closing.window_id != window.window_id
        or closing.window_index != window.window_index
        or closing.scoring_policy_hash != window.scoring_policy_hash
        or closing.closing_block != window.closing_block
        or closing.accepted_at_unix_ms >= selection_publication_ms
    ):
        raise PoolStageReplayError("closing snapshot does not bind the selection window")
    closing_validators = {account_id32(item.validator_hotkey): item for item in closing.validators}
    issuer = closing_validators.get(account_id32(validator_hotkey))
    if issuer is None or not issuer.validator_permit:
        raise PoolStageReplayError("issuing validator had no closing-block permit")


def _reconstruct_pools(
    *,
    policy: ScoringPolicy,
    source_refs: Mapping[str, PoolEvidenceObjectRef | PoolNoScoreObjectRef],
    source_bytes: Mapping[str, bytes],
    selection: PoolSelectionEvidence | PoolNoScoreEvidence,
    announcement: AnnouncementValidatorSnapshot,
    closing: ClosingSnapshot,
    window: WindowPlan,
) -> tuple[tuple[_QualifiedPool, ...], set[str], PoolAnchorRetrievalEvidence]:
    special = {
        selection.policy_object.sha256,
        selection.prior_protocol_state.sha256,
        selection.announcement_validator_snapshot.sha256,
        selection.announcement_validator_proof_evidence.sha256,
        selection.closing_snapshot.sha256,
        selection.closing_proof_evidence.sha256,
        selection.artifact_retrieval_evidence.sha256,
        selection.selection_pulse.sha256,
    }
    mirror_discovery_ref = selection.mirror_discovery_rule
    mirror_readiness_ref = selection.mirror_readiness_set
    if mirror_discovery_ref is None or mirror_readiness_ref is None:
        raise PoolStageReplayError("anchor-backed pool evidence lacks mirror readiness")
    special.update({mirror_discovery_ref.sha256, mirror_readiness_ref.sha256})
    if isinstance(selection, PoolSelectionEvidence):
        special.update(
            {
                selection.delivery_issuance_request.sha256,
                selection.delivery_issuance_response.sha256,
                selection.delivery_issuance_evidence.sha256,
                selection.issuance_finality_evidence.sha256,
            }
        )
    pool_rows: list[tuple[PoolEvidenceObjectRef | PoolNoScoreObjectRef, bytes, PoolManifest]] = []
    for digest, reference in source_refs.items():
        if digest in special or reference.media_type != "application/json":
            continue
        data = source_bytes[digest]
        try:
            decoded = json.loads(data)
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if isinstance(decoded, dict) and decoded.get("schema") == "umi-pool-manifest/1":
            pool_rows.append((reference, data, parse_pool_manifest_bytes(data, policy=policy)))
    pool_rows.sort(key=lambda item: account_id32(item[2].publisher_hotkey))
    accounts = [account_id32(item[2].publisher_hotkey) for item in pool_rows]
    if accounts != sorted(set(accounts)):
        raise PoolStageReplayError("final pool manifests are missing or duplicated")
    if len(pool_rows) > policy.limits.max_active_publishers:
        raise PoolStageReplayError("final pool set exceeds active-publisher limit")
    if sum(len(item[2].batches) for item in pool_rows) > policy.limits.max_candidate_batches_total:
        raise PoolStageReplayError("final pool set exceeds global candidate limit")
    if any(
        item[2].window_id != window.window_id
        or item[2].scoring_policy_hash != scoring_policy_hash(policy)
        for item in pool_rows
    ):
        raise PoolStageReplayError("final pool manifest binds another window")

    certificates = [canonical_json_bytes(item[2].availability_certificate) for item in pool_rows]
    if certificates and len(set(certificates)) != 1:
        raise PoolStageReplayError("final pools do not carry one common certificate")
    active_validators = tuple(
        item.validator_hotkey for item in announcement.validators if item.validator_permit
    )
    if len(active_validators) < 4:
        raise PoolStageReplayError("announcement validator set has fewer than four permits")
    for _reference, _data, manifest in pool_rows:
        verify_availability_certificate_member(
            manifest.availability_certificate,
            manifest.body(),
            active_validator_hotkeys=active_validators,
            policy=policy,
        )

    timely = {
        account_id32(item.publisher_hotkey): item.pool_manifest_sha256
        for item in closing.publishers
        if item.pool_manifest_sha256 is not None
        and item.anchor_inclusion_block is not None
        and item.anchor_inclusion_block <= window.closing_block
    }
    actual = {
        account_id32(manifest.publisher_hotkey): reference.sha256
        for reference, _data, manifest in pool_rows
    }
    if any(timely.get(account) != digest for account, digest in actual.items()):
        raise PoolStageReplayError("final pool set contains a non-anchored manifest")

    # Re-run the public readiness verifier from the exact receipt-bound bytes,
    # then reproduce the live source's publisher/digest and signer decisions.
    from .mirror_readiness import MirrorReadinessError, verify_live_mirror_readiness

    try:
        readiness = verify_live_mirror_readiness(
            policy=policy,
            discovery_rule_bytes=_resolve_ref(source_bytes, mirror_discovery_ref),
            readiness_set_bytes=_resolve_ref(source_bytes, mirror_readiness_ref),
        )
    except MirrorReadinessError as error:
        raise PoolStageReplayError("pool mirror readiness does not verify") from error
    if (
        readiness.readiness.window_id != window.window_id
        or readiness.readiness.window_index != window.window_index
        or readiness.readiness.scoring_policy_sha256 != scoring_policy_hash(policy)
    ):
        raise PoolStageReplayError("pool mirror readiness anchor set does not reproduce")
    readiness_timely = {
        account: digest
        for account, digest in timely.items()
        if readiness.expected_pool_manifest_sha256_by_publisher_account.get(account) == digest
    }
    if actual != readiness_timely:
        raise PoolStageReplayError("pool mirror readiness anchor set does not reproduce")
    if pool_rows:
        certificate_signers = {
            account_id32(item.validator_hotkey)
            for item in pool_rows[0][2].availability_certificate.signatures
        }
        if certificate_signers != set(readiness.signer_accounts):
            raise PoolStageReplayError("pool mirror readiness signer set does not reproduce")

    retrieval = _parse_canonical(
        source_bytes[selection.artifact_retrieval_evidence.sha256],
        PoolAnchorRetrievalEvidence,
        "pool anchor retrieval evidence",
    )
    if (
        retrieval.window_id != window.window_id
        or retrieval.window_index != window.window_index
        or retrieval.scoring_policy_hash != scoring_policy_hash(policy)
        or retrieval.discovery_rule_sha256
        != policy.implementation_pins.rules.mirror_discovery_rule_sha256
    ):
        raise PoolStageReplayError("pool anchor retrieval evidence is misbound")

    outcomes = {account_id32(item.publisher_hotkey): item for item in retrieval.anchor_outcomes}
    if (
        set(outcomes) != set(timely)
        or any(item.sha256 != timely[account] for account, item in outcomes.items())
        or any(
            (account in actual) != (item.status == "qualified")
            for account, item in outcomes.items()
        )
    ):
        raise PoolStageReplayError("pool anchor retrieval outcomes do not reproduce")

    entries = [entry for _ref, _raw, manifest in pool_rows for entry in manifest.batches]
    if len({item.batch_id for item in entries}) != len(entries) or len(
        {item.batch_commitment for item in entries}
    ) != len(entries):
        raise PoolStageReplayError("certified pools contain a cross-publisher duplicate")

    explained = {
        *(item[0].sha256 for item in pool_rows),
        mirror_discovery_ref.sha256,
        mirror_readiness_ref.sha256,
    }
    qualified: list[_QualifiedPool] = []
    for _pool_ref, raw, manifest in pool_rows:
        publics: dict[str, PublicBatchManifest] = {}
        public_refs: dict[str, PoolEvidenceObjectRef | PoolNoScoreObjectRef] = {}
        envelope_refs: dict[str, PoolEvidenceObjectRef | PoolNoScoreObjectRef] = {}
        for entry in manifest.batches:
            public_ref = source_refs.get(entry.public_manifest_sha256)
            envelope_ref = source_refs.get(entry.ciphertext_sha256)
            if (
                public_ref is None
                or public_ref.media_type != "application/json"
                or envelope_ref is None
                or envelope_ref.media_type != "application/octet-stream"
            ):
                raise PoolStageReplayError("pool artifact reference is missing or mistyped")
            public = _parse_canonical(
                source_bytes[public_ref.sha256],
                PublicBatchManifest,
                "public batch manifest",
            )
            publics[entry.batch_id] = public
            public_refs[entry.batch_id] = public_ref
            envelope_refs[entry.batch_id] = envelope_ref
            explained.update({public_ref.sha256, envelope_ref.sha256})
        verify_pool_artifacts(
            manifest.body(),
            public_manifests=publics,
            ciphertexts={
                batch_id: source_bytes[reference.sha256]
                for batch_id, reference in envelope_refs.items()
            },
            policy=policy,
        )
        qualified.append(
            _QualifiedPool(
                raw=raw,
                manifest=manifest,
                public_by_batch=publics,
                public_ref_by_batch=public_refs,
                envelope_ref_by_batch=envelope_refs,
            )
        )
    return tuple(qualified), explained, retrieval


def _eligible_candidates(
    *,
    policy: ScoringPolicy,
    pools: Sequence[_QualifiedPool],
    closing: ClosingSnapshot,
    prior_state: ProtocolStateSnapshot,
    window: WindowPlan,
    allow_empty: bool = False,
) -> tuple[CandidateBatch, ...]:
    registry = {account_id32(item.publisher_hotkey): item for item in policy.publisher_registry}
    closing_publishers = {account_id32(item.publisher_hotkey): item for item in closing.publishers}
    if set(closing_publishers) != set(registry):
        raise PoolStageReplayError("closing publisher registry is incomplete")
    eligible: set[bytes] = set()
    for account, policy_row in registry.items():
        row = closing_publishers[account]
        owner_ok = account_id32(row.owner_coldkey) == account_id32(policy_row.owner_coldkey)
        if row.control_group_id != policy_row.control_group_id:
            raise PoolStageReplayError("closing publisher changes its control group")
        if (
            row.registered
            and owner_ok
            and row.locked_collateral_alpha_rao >= policy.minimum_publisher_collateral_alpha_rao
            and row.minimum_locked_collateral_alpha_rao
            >= policy.minimum_publisher_collateral_alpha_rao
            and row.pool_manifest_sha256 is not None
            and row.anchor_inclusion_block is not None
            and row.anchor_inclusion_block <= window.closing_block
            and prior_state.publisher_faults.is_eligible(
                policy_row.control_group_id, window.window_index
            )
        ):
            eligible.add(account)

    group_counts: dict[str, int] = {}
    candidates: list[CandidateBatch] = []
    spent: list[SpentCohortBatch] = []
    for pool in pools:
        publisher = account_id32(pool.manifest.publisher_hotkey)
        if publisher not in eligible:
            continue
        policy_row = registry[publisher]
        group_counts[policy_row.control_group_id] = group_counts.get(
            policy_row.control_group_id, 0
        ) + len(pool.manifest.batches)
        for entry in pool.manifest.batches:
            public = pool.public_by_batch[entry.batch_id]
            candidates.append(
                CandidateBatch(
                    publisher_hotkey=pool.manifest.publisher_hotkey,
                    control_group_id=policy_row.control_group_id,
                    batch_id=entry.batch_id,
                    batch_commitment=entry.batch_commitment,
                )
            )
            spent.append(
                SpentCohortBatch(
                    batch_commitment=entry.batch_commitment,
                    video_hashes=tuple(item.media.sha256 for item in public.items),
                    frame_digests=tuple(item.media.frame_digest for item in public.items),
                )
            )
    if not candidates and not allow_empty:
        raise PoolStageReplayError("eligible candidate pool is empty")
    if (
        any(
            count > policy.limits.max_candidate_batches_per_group for count in group_counts.values()
        )
        or len(group_counts) > policy.limits.max_active_control_groups
    ):
        raise PoolStageReplayError("eligible candidate pool exceeds group limits")
    _next, transition = prior_state.spent_registry.apply(window.reveal_round, tuple(spent))
    if transition.has_eligibility_fault:
        raise PoolStageReplayError("candidate pool conflicts with spent state")
    return tuple(candidates)


def _validate_candidate_evidence(
    selection: PoolSelectionEvidence | PoolNoScoreEvidence,
    candidates: Sequence[CandidateBatch],
    selected: Sequence[CandidateBatch],
    pools: Sequence[_QualifiedPool],
    seed: bytes,
) -> None:
    selected_ordinals = {item.pool_leaf: ordinal for ordinal, item in enumerate(selected)}
    expected: list[dict[str, Any]] = []
    for candidate in sorted(candidates, key=lambda item: (batch_rank(seed, item), item.pool_leaf)):
        pool = next(
            value
            for value in pools
            if account_id32(value.manifest.publisher_hotkey)
            == account_id32(candidate.publisher_hotkey)
        )
        expected.append(
            {
                "publisher_hotkey": str(candidate.publisher_hotkey),
                "control_group_id": (
                    candidate.control_group_id
                    if isinstance(candidate.control_group_id, str)
                    else candidate.control_group_id.hex()
                ),
                "batch_id": candidate.batch_id,
                "batch_commitment": (
                    candidate.batch_commitment
                    if isinstance(candidate.batch_commitment, str)
                    else candidate.batch_commitment.hex()
                ),
                "pool_leaf": candidate.pool_leaf.hex(),
                "batch_rank": batch_rank(seed, candidate).hex(),
                "selection_ordinal": selected_ordinals.get(candidate.pool_leaf),
                "final_pool_manifest": {
                    "sha256": hashlib.sha256(pool.raw).hexdigest(),
                    "media_type": "application/json",
                    "size_bytes": len(pool.raw),
                },
                "public_manifest": pool.public_ref_by_batch[candidate.batch_id].model_dump(
                    mode="json", by_alias=True
                ),
                "ground_truth_envelope": pool.envelope_ref_by_batch[candidate.batch_id].model_dump(
                    mode="json", by_alias=True
                ),
            }
        )
    actual = [item.model_dump(mode="json", by_alias=True) for item in selection.candidates]
    if actual != expected:
        raise PoolStageReplayError("candidate eligibility or batch selection does not reproduce")


def _validate_panel(
    *,
    policy: ScoringPolicy,
    selection: PoolSelectionEvidence | PoolNoScoreEvidence,
    closing: ClosingSnapshot,
    prior_state: ProtocolStateSnapshot,
    seed: bytes,
    allow_empty: bool = False,
) -> tuple[ClosingNeuron, ...]:
    validator_rows = {account_id32(item.validator_hotkey): item for item in closing.validators}
    policy_validators = {account_id32(item.validator_hotkey) for item in policy.validator_registry}
    if (
        set(validator_rows) != policy_validators
        or len([item for item in validator_rows.values() if item.validator_permit]) < 4
    ):
        raise PoolStageReplayError("closing validator registry or permit set is invalid")
    if not validator_rows[account_id32(selection.validator_hotkey)].validator_permit:
        raise PoolStageReplayError("issuing validator lacks its closing permit")

    publisher_accounts = {account_id32(item.publisher_hotkey) for item in policy.publisher_registry}
    candidates: list[MinerCandidate] = []
    by_account: dict[bytes, ClosingNeuron] = {}
    roots: set[bytes] = set()
    for neuron in closing.neurons:
        account = account_id32(neuron.hotkey)
        if neuron.validator_permit or account in publisher_accounts or neuron.serving_url is None:
            continue
        root = account_id32(neuron.root)
        if root in roots:
            raise PoolStageReplayError("eligible miner snapshot contains duplicate roots")
        roots.add(root)
        candidates.append(
            MinerCandidate(
                hotkey=neuron.hotkey,
                root=neuron.root,
                assigned_observation_count=prior_state.assigned_observation_count(root),
            )
        )
        by_account[account] = neuron
    panel = select_miner_panel(
        tuple(candidates),
        seed,
        validator_hotkey=selection.validator_hotkey,
        panel_size=policy.limits.miner_panel_size,
    )
    neurons = tuple(by_account[account_id32(item.hotkey)] for item in panel)
    expected = [
        SelectedMinerEvidence(
            panel_ordinal=index,
            uid=neuron.uid,
            hotkey=neuron.hotkey,
            root=neuron.root,
            serving_url=neuron.serving_url or "",
            assigned_observation_count=miner.assigned_observation_count,
            miner_rank=miner_rank(seed, selection.validator_hotkey, neuron.hotkey).hex(),
        )
        for index, (miner, neuron) in enumerate(zip(panel, neurons, strict=True))
    ]
    if isinstance(selection, PoolNoScoreEvidence):
        if not allow_empty or expected:
            raise PoolStageReplayError("selected miner panel does not reproduce")
    elif not expected or selection.selected_panel != expected:
        raise PoolStageReplayError("selected miner panel does not reproduce")
    return neurons


def _public_manifest(batch_id: str, pools: Sequence[_QualifiedPool]) -> PublicBatchManifest:
    matches = [pool.public_by_batch[batch_id] for pool in pools if batch_id in pool.public_by_batch]
    if len(matches) != 1:
        raise PoolStageReplayError("selected batch public manifest cardinality is not one")
    return matches[0]


def _verify_issuance_finality(
    issuance: AssignmentIssuanceFinalityEvidence,
    *,
    policy: ScoringPolicy,
    selection: PoolSelectionEvidence,
    window: WindowPlan,
    finality_verifier: FinalityReplayVerifier,
    finality_verifier_sha256: str,
) -> None:
    identity = issuance_identity_from_object(issuance.identity)
    attestation = bytes.fromhex(issuance.attestation_hex)
    selection_ms = QUICKNET_GENESIS_MS + (window.selection_round - 1) * QUICKNET_PERIOD_MS
    issue_close_ms = QUICKNET_GENESIS_MS + (window.issue_close_round - 1) * QUICKNET_PERIOD_MS
    if (
        issuance.schema_ != ASSIGNMENT_ISSUANCE_FINALITY_SCHEMA
        or issuance.window_id != window.window_id
        or identity.snapshot.block_number != selection.issuance_block
        or identity.snapshot.block_hash != selection.issuance_block_hash
        or identity.finality_verifier_sha256 != finality_verifier_sha256
        or identity.snapshot.block_number <= window.closing_block
        or not selection_ms <= issuance.timestamp_ms < issue_close_ms
    ):
        raise PoolStageReplayError("assignment issuance finality binding is invalid")
    try:
        accepted = finality_verifier(
            identities=(identity,),
            attestations=(attestation,),
            replay_bindings=(issuance.replay_binding.to_evidence(),),
            policy=policy,
        )
    except Exception as error:
        raise PoolStageReplayError("assignment issuance finality replay failed") from error
    if accepted is not True:
        raise PoolStageReplayError("assignment issuance finality replay failed")


def _validate_material_assignments(
    *,
    policy: ScoringPolicy,
    selection: PoolSelectionEvidence,
    material: WindowMaterial,
    window: WindowPlan,
    selected_manifests: Sequence[PublicBatchManifest],
    selected_neurons: Sequence[ClosingNeuron],
    deliveries: Mapping[tuple[str, str], IssuedVideoDelivery],
    issuance: AssignmentIssuanceFinalityEvidence,
) -> tuple[str, ...]:
    response_deadline_blocks = ceil_div(
        policy.clock.issue_allowance_seconds + policy.clock.response_window_seconds,
        policy.clock.target_block_interval_seconds,
    )
    expected_count = sum(len(item.items) for item in selected_manifests) * len(selected_neurons)
    expected_spec = TranscriptWindowSpec(
        schema=WINDOW_SCHEMA,
        protocol=PROTOCOL_VERSION,
        window_id=window.window_id,
        validator_hotkey=selection.validator_hotkey,
        expected_assignment_count=expected_count,
        maximum_request_transmissions_per_assignment=(
            policy.limits.maximum_request_transmissions_per_assignment
        ),
        issue_close_round=window.issue_close_round,
        response_close_round=window.response_close_round,
        reveal_round=window.reveal_round,
        maximum_request_body_bytes=min(
            policy.limits.maximum_request_body_bytes, MAX_REQUEST_BODY_BYTES
        ),
        maximum_response_body_bytes=min(
            policy.limits.maximum_response_body_bytes, MAX_RESPONSE_BODY_BYTES
        ),
        maximum_retained_prefix_bytes=min(
            policy.limits.maximum_response_body_bytes, MAX_RETAINED_PREFIX_BYTES
        ),
    )
    if material.transcript_spec != expected_spec or expected_count > MAX_ASSIGNMENTS_PER_WINDOW:
        raise PoolStageReplayError("window transcript specification does not reproduce")

    manifests = {item.batch_id: item for item in selected_manifests}
    miners = {account_id32(item.hotkey): item for item in selected_neurons}
    expected_keys = {
        (manifest.batch_id, item.challenge_id, account)
        for manifest in selected_manifests
        for item in manifest.items
        for account in miners
    }
    seen: set[tuple[str, str, bytes]] = set()
    assignment_ids: list[str] = []
    for item in material.assignments:
        request_bytes = base64url_decode(item.request_bytes_base64url)
        request = _parse_canonical(request_bytes, TranslationRequest, "initial request")
        headers = tuple((header.name, header.value) for header in item.auth_headers)
        try:
            auth = VerifiedAuthEvidence.from_headers(
                dict(headers),
                request=request,
                expected_validator_hotkey=item.validator_hotkey,
                expected_miner_hotkey=item.miner_hotkey,
            )
        except Exception as error:
            raise PoolStageReplayError("initial request authentication does not verify") from error
        if (
            auth.auth_record != item.auth_record
            or auth.request_digest_bytes.hex() != item.request_digest
            or auth.validator_account_id32.hex() != item.validator_account_id32
            or auth.miner_account_id32.hex() != item.miner_account_id32
        ):
            raise PoolStageReplayError("initial request authentication evidence differs")
        prepared = PreparedRequestAttempt(
            request=request,
            request_bytes=request_bytes,
            validator_hotkey=item.validator_hotkey,
            miner_hotkey=item.miner_hotkey,
            auth_headers=headers,
            auth_evidence=auth,
        )
        assignment_id = deterministic_assignment_id(prepared)
        if assignment_id != item.assignment_id:
            raise PoolStageReplayError("assignment ID does not reproduce")

        account = account_id32(item.miner_hotkey)
        key = (request.batch_id, request.challenge_id, account)
        if key not in expected_keys or key in seen:
            raise PoolStageReplayError("assignments are not the selected Cartesian product")
        seen.add(key)
        manifest = manifests[request.batch_id]
        public_item = next(
            value for value in manifest.items if value.challenge_id == request.challenge_id
        )
        delivery = deliveries[(request.batch_id, request.challenge_id)]
        neuron = miners[account]
        if (
            item.validator_hotkey != selection.validator_hotkey
            or account_id32(item.validator_hotkey) != account_id32(selection.validator_hotkey)
            or account_id32(item.miner_hotkey) != account_id32(neuron.hotkey)
            or item.miner_url != neuron.serving_url
            or request.window_id != window.window_id
            or request.scoring_policy_hash != window.scoring_policy_hash
            or request.response_close_round != window.response_close_round
            or request.reveal_round != window.reveal_round
            or request.issued_block != selection.issuance_block
            or request.issued_block_hash != selection.issuance_block_hash
            or request.issued_block
            != issuance_identity_from_object(issuance.identity).snapshot.block_number
            or request.deadline_block != selection.issuance_block + response_deadline_blocks
            or request.video.url != delivery.url
            or request.video.sha256 != public_item.media.sha256
            or request.video.size_bytes != public_item.media.size_bytes
            or request.video.media_type != public_item.media.media_type
            or request.task.source_language != "ase"
            or request.task.target_language != "en"
            or request.task.stratum != public_item.stratum
            or len(request_bytes)
            > min(policy.limits.maximum_request_body_bytes, MAX_REQUEST_BODY_BYTES)
        ):
            raise PoolStageReplayError("prepared request changes selected source material")
        assignment_ids.append(assignment_id)
    if seen != expected_keys:
        raise PoolStageReplayError("assignments omit selected work")
    result = tuple(sorted(assignment_ids))
    if (
        tuple(item.assignment_id for item in material.assignments) != result
        or tuple(selection.assignment_ids) != result
    ):
        raise PoolStageReplayError("assignment ordering or selection index does not reproduce")
    return result


def _parse_pulse(raw: bytes, *, expected_round: int) -> DrandPulse:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PoolStageReplayError("selection pulse is invalid JSON") from error
    if canonical_json_bytes(value) != raw:
        raise PoolStageReplayError("selection pulse is not canonical JSON")
    try:
        return DrandPulse.from_json(value, expected_round=expected_round)
    except Exception as error:
        raise PoolStageReplayError("selection pulse does not verify") from error


__all__ = [
    "PoolStageReplay",
    "PoolStageReplayError",
    "ProofBackedPoolStageReplayHook",
    "resolve_pool_stage",
    "verify_snapshot_finality",
]
