"""Offline replay of one UMI shadow window without chain authority.

This module deliberately stops after a projected weight build.  Its input and
output schemas describe a rehearsal, not a live calibration result, protocol
conformance evidence, or an activation gate.  It has no signing or chain-write
entry points.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from fractions import Fraction
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import Field, model_validator
from typing_extensions import Self

from .anchors import (
    AssignmentAnchorRecord,
    CanonicalNonce,
    RequestAnchorRecord,
    ResponseAnchorRecord,
    SealedResponseRecord,
    VerifiedAuthEvidence,
    assignment_set_root,
    request_set_root,
    response_set_root,
)
from .artifacts import (
    PublicBatchManifest,
    validate_public_batch_manifest,
    validate_revealed_batch_shape,
)
from .audit_bundle import (
    SHADOW_INCIDENT_TERMINAL,
    SHADOW_TERMINAL,
    STAGE_IDS,
    AuditBundleManifest,
    BundleObjectInput,
    StageInput,
    verify_audit_bundle,
    write_audit_bundle,
)
from .canary import evaluate_canary
from .crypto import verify_response_signature
from .drand import DrandPulse
from .encoding import account_id32, sha256_domain
from .policy import (
    ScoringPolicy,
    scoring_policy_hash,
    umi_source_tree_sha256,
    validate_rehearsal_runtime,
)
from .pool import (
    AvailabilityCertificate,
    CandidateBatch,
    MinerCandidate,
    PoolBody,
    batch_rank,
    candidate_pool_root,
    select_batches,
    select_miner_panel,
    selection_seed,
    verify_availability_certificate,
    verify_pool_artifacts,
)
from .protocol import (
    BlockHash,
    GroundTruthPayload,
    Hex32,
    NonEmptyText,
    OpaqueId,
    StrictProtocolModel,
    TranslationRequest,
    base64url_decode,
    canonical_json_bytes,
    normalized_grapheme_count,
    normalized_token_count,
    request_digest,
)
from .registries import PublisherFaultState, SpentCohortBatch, SpentRegistryState
from .rolling import (
    AssignmentScore,
    RollingScoreState,
    ScoredBatch,
    WeightBuild,
)
from .scoring import score_cer_with_trace, score_wer_with_trace, scoring_environment
from .window import WindowClock, WindowSchedule

SHADOW_REHEARSAL_SCHEMA = "umi-shadow-rehearsal/1"
SHADOW_RESPONSE_SCHEMA = "umi-shadow-response/1"
SHADOW_REPORT_SCHEMA = "umi-shadow-rehearsal-report/2"
MAX_SHADOW_EVIDENCE_BYTES = 16 * 1024 * 1024
NO_CHAIN_REASON = "offline_rehearsal_has_no_finalized_chain_terminal_state"
CANARY_HIT_REASON = "canary_hit"
SOURCE_EVIDENCE_MEDIA_TYPE = "application/vnd.umi.shadow-rehearsal-evidence+json"

SignatureHex = Annotated[str, Field(pattern=r"^0x[0-9a-f]{128}$")]


class RehearsalPulse(StrictProtocolModel):
    round: Annotated[int, Field(gt=0)]
    randomness: Hex32
    signature: Annotated[str, Field(pattern=r"^[0-9a-f]{96}$")]

    def verified(self, *, expected_round: int) -> DrandPulse:
        return DrandPulse.from_json(
            self.model_dump(mode="json"),
            expected_round=expected_round,
        )


class RehearsalBatchArtifact(StrictProtocolModel):
    batch_id: OpaqueId
    public_manifest: PublicBatchManifest
    ciphertext_b64: str
    revealed_ground_truth: GroundTruthPayload

    @model_validator(mode="after")
    def validate_bindings(self) -> Self:
        ciphertext = self.ciphertext_bytes
        if not ciphertext:
            raise ValueError("rehearsal ciphertext must not be empty")
        if self.batch_id != self.public_manifest.batch_id:
            raise ValueError("artifact batch ID does not bind its public manifest")
        if self.batch_id != self.revealed_ground_truth.batch_id:
            raise ValueError("artifact batch ID does not bind its revealed ground truth")
        if hashlib.sha256(ciphertext).hexdigest() != self.public_manifest.ciphertext_sha256:
            raise ValueError("artifact ciphertext does not match its public manifest")
        return self

    @property
    def ciphertext_bytes(self) -> bytes:
        from .protocol import base64url_decode

        return base64url_decode(self.ciphertext_b64)


class RehearsalMiner(StrictProtocolModel):
    hotkey: NonEmptyText
    root: NonEmptyText
    assigned_observation_count: Annotated[int, Field(ge=0)]
    uid: Annotated[int, Field(ge=0, le=65_535)]

    @model_validator(mode="after")
    def validate_accounts(self) -> Self:
        account_id32(self.hotkey)
        account_id32(self.root)
        return self


class RehearsalAuthRecord(StrictProtocolModel):
    version: Literal["btauth/1"]
    scheme: Literal["sr25519", "ed25519"]
    method: Literal["POST"]
    wire_request_target: Literal["/v1/translate"]
    raw_body_sha256: Hex32
    nonce: CanonicalNonce
    sender: NonEmptyText
    receiver: NonEmptyText
    signature: SignatureHex

    @property
    def nonce_int(self) -> int:
        return int(self.nonce)

    @model_validator(mode="after")
    def validate_accounts(self) -> Self:
        account_id32(self.sender)
        account_id32(self.receiver)
        return self

    def headers(self) -> dict[str, str]:
        return {
            "X-Bittensor-Version": "1",
            "X-Bittensor-Crypto": self.scheme,
            "X-Bittensor-Hotkey": self.sender,
            "X-Bittensor-Nonce": self.nonce,
            "X-Bittensor-Receiver": self.receiver,
            "X-Bittensor-Signature": self.signature,
        }

    def anchor_record(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class RehearsalResponsePayload(StrictProtocolModel):
    schema_: Literal[SHADOW_RESPONSE_SCHEMA] = Field(alias="schema")
    request_digest: Hex32
    validator_hotkey: NonEmptyText
    serving_hotkey: NonEmptyText
    status: Literal["ok", "error"]
    received_video_sha256: Hex32 | None
    hypothesis: str | None
    error_code: NonEmptyText | None

    @model_validator(mode="after")
    def validate_status(self) -> Self:
        account_id32(self.validator_hotkey)
        account_id32(self.serving_hotkey)
        if self.status == "ok":
            if self.received_video_sha256 is None or self.hypothesis is None:
                raise ValueError("ok rehearsal response requires video digest and hypothesis")
            if self.error_code is not None:
                raise ValueError("ok rehearsal response cannot carry an error code")
        else:
            if self.hypothesis is not None or self.error_code is None:
                raise ValueError("error rehearsal response requires only an error code")
        return self


class RehearsalResponse(StrictProtocolModel):
    payload: RehearsalResponsePayload
    signature_scheme: Literal["sr25519", "ed25519"]
    signature: SignatureHex
    received_block: Annotated[int, Field(ge=0)]


class RehearsalAssignment(StrictProtocolModel):
    miner_hotkey: NonEmptyText
    miner_root: NonEmptyText
    batch_id: OpaqueId
    challenge_id: OpaqueId
    request: TranslationRequest
    auth_records: Annotated[list[RehearsalAuthRecord], Field(min_length=1, max_length=2)]
    response: RehearsalResponse

    @model_validator(mode="after")
    def validate_local_bindings(self) -> Self:
        account_id32(self.miner_hotkey)
        account_id32(self.miner_root)
        if self.request.batch_id != self.batch_id:
            raise ValueError("assignment batch ID does not bind its request")
        if self.request.challenge_id != self.challenge_id:
            raise ValueError("assignment challenge ID does not bind its request")
        nonces = [record.nonce_int for record in self.auth_records]
        if nonces != sorted(nonces) or len(set(nonces)) != len(nonces):
            raise ValueError("assignment authentication records must be ordered by nonce")
        return self


class ShadowRehearsalEvidence(StrictProtocolModel):
    schema_: Literal[SHADOW_REHEARSAL_SCHEMA] = Field(alias="schema")
    translation_weights_active: Literal[False]
    protocol_conformance: Literal[False]
    activation_evidence: Literal[False]
    chain_operations_authorized: Literal[False]
    policy: ScoringPolicy
    window_index: Literal[0]
    announcement_block_hash: BlockHash
    announcement_timestamp_ms: Annotated[int, Field(gt=0)]
    pulse: RehearsalPulse
    validator_hotkey: NonEmptyText
    active_validator_hotkeys: Annotated[list[NonEmptyText], Field(min_length=4)]
    pool_bodies: Annotated[list[PoolBody], Field(min_length=3, max_length=3)]
    availability_certificate: AvailabilityCertificate
    batch_artifacts: Annotated[
        list[RehearsalBatchArtifact],
        Field(min_length=3, max_length=3),
    ]
    miners: Annotated[list[RehearsalMiner], Field(min_length=2)]
    assignments: Annotated[list[RehearsalAssignment], Field(min_length=1)]
    minimum_positive_weights: Annotated[int, Field(gt=0)]
    maximum_weight_limit_u16: Annotated[int, Field(gt=0, le=65_535)] = 65_535

    @model_validator(mode="after")
    def validate_canonical_sets(self) -> Self:
        if self.policy.translation_weights_active:
            raise ValueError("offline rehearsal requires an inactive weight policy")
        validator = account_id32(self.validator_hotkey)
        active = [account_id32(value) for value in self.active_validator_hotkeys]
        if active != sorted(active) or len(set(active)) != len(active):
            raise ValueError("active validators must be unique and sorted by account")
        if validator not in active:
            raise ValueError("rehearsal validator must be in the active validator set")
        policy_validators = [
            account_id32(item.validator_hotkey) for item in self.policy.validator_registry
        ]
        if active != policy_validators:
            raise ValueError("active validators must exactly match the offline policy registry")

        publisher_accounts = [account_id32(body.publisher_hotkey) for body in self.pool_bodies]
        if publisher_accounts != sorted(publisher_accounts):
            raise ValueError("pool bodies must be sorted by publisher account")
        if len(set(publisher_accounts)) != len(publisher_accounts):
            raise ValueError("pool bodies must contain one entry per publisher")

        artifact_ids = [base64url_decode(item.batch_id) for item in self.batch_artifacts]
        if artifact_ids != sorted(artifact_ids) or len(set(artifact_ids)) != len(artifact_ids):
            raise ValueError("batch artifacts must be unique and sorted by decoded batch ID")

        miner_accounts = [account_id32(item.hotkey) for item in self.miners]
        miner_roots = [account_id32(item.root) for item in self.miners]
        miner_uids = [item.uid for item in self.miners]
        if miner_accounts != sorted(miner_accounts) or len(set(miner_accounts)) != len(
            miner_accounts
        ):
            raise ValueError("miners must be unique and sorted by hotkey account")
        if len(set(miner_roots)) != len(miner_roots):
            raise ValueError("miner roots must be unique")
        if len(set(miner_uids)) != len(miner_uids):
            raise ValueError("miner UIDs must be unique")
        policy_publishers = {
            account_id32(item.publisher_hotkey) for item in self.policy.publisher_registry
        }
        if set(miner_accounts).intersection(policy_publishers):
            raise ValueError("rehearsal miner set includes an active publisher hotkey")
        if set(miner_accounts).intersection(active):
            raise ValueError("rehearsal miner set includes an active validator hotkey")
        if self.minimum_positive_weights > len(self.miners):
            raise ValueError("minimum positive weights exceeds the rehearsal miner set")

        assignment_keys = [_assignment_order_key(item) for item in self.assignments]
        if assignment_keys != sorted(assignment_keys) or len(set(assignment_keys)) != len(
            assignment_keys
        ):
            raise ValueError("assignments must be unique and in canonical order")
        return self


class QuantizedWeightRecord(StrictProtocolModel):
    uid: Annotated[int, Field(ge=0, le=65_535)]
    value: Annotated[int, Field(ge=0, le=65_535)]


class ShadowRehearsalReport(StrictProtocolModel):
    schema_: Literal[SHADOW_REPORT_SCHEMA] = Field(alias="schema")
    terminal_classification: Literal[SHADOW_TERMINAL, SHADOW_INCIDENT_TERMINAL]
    window_valid: bool
    translation_weights_active: Literal[False]
    protocol_conformance: Literal[False]
    activation_evidence: Literal[False]
    chain_writes_performed: Literal[False]
    runner_signing_performed: Literal[False]
    weight_submission_performed: Literal[False]
    ground_truth_timelock_verified: Literal[False]
    response_timelocks_verified: Literal[False]
    scoring_policy_hash: Hex32
    window_id: Hex32
    selected_batch_ids: Annotated[list[OpaqueId], Field(min_length=2, max_length=2)]
    selected_miner_hotkeys: Annotated[list[NonEmptyText], Field(min_length=1)]
    assignment_count: Annotated[int, Field(gt=0)]
    scored_assignment_count: Annotated[int, Field(gt=0)]
    canary_check_count: Annotated[int, Field(gt=0)]
    assignment_set_root: Hex32
    request_set_root: Hex32
    response_set_root: Hex32
    spent_previous_root: Hex32
    spent_resulting_root: Hex32
    publisher_fault_previous_root: Hex32
    publisher_fault_resulting_root: Hex32
    quantized_row: list[QuantizedWeightRecord]
    limitations: list[NonEmptyText]

    @model_validator(mode="after")
    def validate_report(self) -> Self:
        if not self.limitations:
            raise ValueError("offline rehearsal report must state its limitations")
        if self.window_valid != (self.terminal_classification == SHADOW_TERMINAL):
            raise ValueError("rehearsal validity and terminal classification disagree")
        if self.window_valid != bool(self.quantized_row):
            raise ValueError("only a valid rehearsal window can carry a projected row")
        uids = [item.uid for item in self.quantized_row]
        if uids != sorted(uids) or len(set(uids)) != len(uids):
            raise ValueError("quantized row must be unique and sorted by UID")
        return self


@dataclass(frozen=True)
class ShadowRehearsalRun:
    report: ShadowRehearsalReport
    audit_manifest: AuditBundleManifest
    manifest_path: Path


def parse_shadow_rehearsal_evidence(data: bytes) -> ShadowRehearsalEvidence:
    """Parse only exact RFC 8785 bytes into the strict rehearsal schema."""

    if not isinstance(data, bytes):
        raise TypeError("shadow rehearsal evidence must be exact bytes")
    if not data or len(data) > MAX_SHADOW_EVIDENCE_BYTES:
        raise ValueError("shadow rehearsal evidence is empty or exceeds its byte ceiling")
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("shadow rehearsal evidence is not valid JSON") from error
    evidence = ShadowRehearsalEvidence.model_validate(value)
    if canonical_json_bytes(evidence) != data:
        raise ValueError("shadow rehearsal evidence is not exact RFC 8785 canonical JSON")
    return evidence


def rehearsal_response_digest(payload: RehearsalResponsePayload) -> bytes:
    """Return the custom digest used only to authenticate rehearsal hypotheses."""

    if not isinstance(payload, RehearsalResponsePayload):
        raise TypeError("payload must be RehearsalResponsePayload")
    return sha256_domain(
        b"umi-shadow-response-v1\0",
        canonical_json_bytes(payload),
    )


def run_shadow_rehearsal(data: bytes, output_directory: Path) -> ShadowRehearsalRun:
    """Replay one deterministic offline window and write a bounded audit bundle."""

    evidence = parse_shadow_rehearsal_evidence(data)
    policy = evidence.policy
    validate_shadow_runtime(policy)
    policy_hash = scoring_policy_hash(policy)
    schedule = _derive_and_validate_schedule(evidence, policy_hash)
    pulse = evidence.pulse.verified(expected_round=schedule.selection_round)

    artifact_by_id = {item.batch_id: item for item in evidence.batch_artifacts}
    _validate_pool_and_artifacts(evidence, schedule, policy_hash, artifact_by_id)
    verify_availability_certificate(
        evidence.availability_certificate,
        evidence.pool_bodies,
        active_validator_hotkeys=evidence.active_validator_hotkeys,
        policy=policy,
    )

    candidates = _candidate_batches(evidence)
    pool_root = candidate_pool_root(candidates)
    seed = selection_seed(pulse.signature_bytes, pool_root)
    selected = select_batches(
        candidates,
        seed,
        count=policy.limits.batches_selected_per_window,
    )
    _validate_selected_script_uniqueness(selected, artifact_by_id)
    panel = _select_panel(evidence, seed)

    replay = _replay_assignments(
        evidence,
        schedule,
        policy_hash,
        selected,
        panel,
        artifact_by_id,
        seed,
    )
    spent_state, spent_transition = _replay_spent_registry(
        evidence,
        schedule,
        artifact_by_id,
    )
    if spent_transition.has_eligibility_fault:
        raise ValueError("rehearsal cohort has a spent-registry eligibility fault")
    fault_state, fault_transition = PublisherFaultState().advance_empty_window(
        evidence.window_index
    )

    window_valid = replay.weight_build is not None
    terminal_classification = SHADOW_TERMINAL if window_valid else SHADOW_INCIDENT_TERMINAL
    limitations = [
        "no finalized chain storage or event proofs",
        "ground-truth ciphertext is hash-bound but not timelock-decrypted",
        "response hypotheses use rehearsal signatures instead of response timelocks",
        "committed media metadata is replayed but video bytes are not decoded",
        "HTTP wire accounting and resource preflight are not integrated",
        "missing, late, and outer-invalid response dispositions are not replayed",
        "nonempty publisher-fault classification requires finalized chain evidence",
        "rolling and registry state starts from the version genesis zero state",
        "no weight call is built, signed, or submitted",
        "the bundle is not activation evidence",
    ]
    if not window_valid:
        limitations.append("the canary hit made this rehearsal window void before weight build")
    report = ShadowRehearsalReport.model_validate(
        {
            "schema": SHADOW_REPORT_SCHEMA,
            "terminal_classification": terminal_classification,
            "window_valid": window_valid,
            "translation_weights_active": False,
            "protocol_conformance": False,
            "activation_evidence": False,
            "chain_writes_performed": False,
            "runner_signing_performed": False,
            "weight_submission_performed": False,
            "ground_truth_timelock_verified": False,
            "response_timelocks_verified": False,
            "scoring_policy_hash": policy_hash,
            "window_id": schedule.window_id,
            "selected_batch_ids": [item.batch_id for item in selected],
            "selected_miner_hotkeys": [str(item.hotkey) for item in panel],
            "assignment_count": len(evidence.assignments),
            "scored_assignment_count": replay.scored_assignment_count,
            "canary_check_count": replay.canary_check_count,
            "assignment_set_root": replay.assignment_root.hex(),
            "request_set_root": replay.request_root.hex(),
            "response_set_root": replay.response_root.hex(),
            "spent_previous_root": spent_transition.previous_root.hex(),
            "spent_resulting_root": spent_state.root.hex(),
            "publisher_fault_previous_root": fault_transition.previous_root.hex(),
            "publisher_fault_resulting_root": fault_state.root.hex(),
            "quantized_row": [
                {"uid": uid, "value": value}
                for uid, value in (
                    replay.weight_build.quantized_row if replay.weight_build is not None else ()
                )
            ],
            "limitations": limitations,
        }
    )
    stages = _audit_stages(
        evidence,
        schedule,
        pulse,
        selected,
        panel,
        replay,
        spent_transition,
        fault_transition,
        report,
        canonical_json_bytes(evidence),
    )
    manifest_path = write_audit_bundle(
        output_directory,
        scoring_policy_hash=policy_hash,
        software_revisions=_software_revisions(),
        window_id=schedule.window_id,
        terminal_classification=terminal_classification,
        audit_release_block=0,
        reason_codes=list(replay.void_reason_codes or (NO_CHAIN_REASON,)),
        stages=stages,
        maximum_bundle_bytes=policy.limits.maximum_audit_bundle_bytes,
    )
    manifest = verify_audit_bundle(
        output_directory,
        maximum_bundle_bytes=policy.limits.maximum_audit_bundle_bytes,
    )
    if (
        manifest.translation_weights_active
        or manifest.protocol_conformance
        or manifest.activation_evidence
    ):
        raise RuntimeError("offline audit bundle asserted a forbidden readiness flag")
    return ShadowRehearsalRun(
        report=report,
        audit_manifest=manifest,
        manifest_path=manifest_path,
    )


def validate_shadow_runtime(policy: ScoringPolicy) -> None:
    """Validate every policy-pinned runtime dependency used by the rehearsal."""

    validate_rehearsal_runtime(policy)


@dataclass(frozen=True)
class _ReplayResult:
    assignment_root: bytes
    request_root: bytes
    response_root: bytes
    score_records: tuple[dict[str, Any], ...]
    canary_records: tuple[dict[str, Any], ...]
    scored_assignment_count: int
    canary_check_count: int
    rolling_state: RollingScoreState | None
    weight_build: WeightBuild | None
    void_reason_codes: tuple[str, ...]
    assignment_anchor_records: tuple[AssignmentAnchorRecord, ...]
    request_anchor_records: tuple[RequestAnchorRecord, ...]
    response_anchor_records: tuple[ResponseAnchorRecord, ...]
    sealed_records: tuple[SealedResponseRecord, ...]


@dataclass(frozen=True)
class _ValidatedRehearsalResponse:
    sealed_record: SealedResponseRecord
    hypothesis: str | None
    zero_score_reason: str | None


def _derive_and_validate_schedule(
    evidence: ShadowRehearsalEvidence,
    policy_hash: str,
) -> WindowSchedule:
    clock_policy = evidence.policy.clock
    clock = WindowClock(
        activation_block=evidence.policy.activation_block,
        window_stride_blocks=clock_policy.window_stride_blocks,
        proposal_blocks=clock_policy.proposal_blocks,
        anchor_blocks=clock_policy.anchor_blocks,
        target_block_interval_seconds=clock_policy.target_block_interval_seconds,
        selection_finality_buffer_seconds=clock_policy.selection_finality_buffer_seconds,
        issue_allowance_seconds=clock_policy.issue_allowance_seconds,
        response_window_seconds=clock_policy.response_window_seconds,
        delivery_grace_seconds=clock_policy.delivery_grace_seconds,
        reveal_margin_seconds=clock_policy.reveal_margin_seconds,
    )
    return clock.derive(
        evidence.window_index,
        netuid=evidence.policy.netuid,
        announcement_block_hash=evidence.announcement_block_hash,
        announcement_timestamp_ms=evidence.announcement_timestamp_ms,
        scoring_policy_hash=policy_hash,
    )


def _validate_pool_and_artifacts(
    evidence: ShadowRehearsalEvidence,
    schedule: WindowSchedule,
    policy_hash: str,
    artifact_by_id: dict[str, RehearsalBatchArtifact],
) -> None:
    policy = evidence.policy
    if len(evidence.pool_bodies) != policy.limits.max_candidate_batches_total:
        raise ValueError("rehearsal pool does not contain the full launch candidate count")
    expected_batch_ids = {entry.batch_id for body in evidence.pool_bodies for entry in body.batches}
    if len(expected_batch_ids) != policy.limits.max_candidate_batches_total:
        raise ValueError("rehearsal pool must carry exactly one unique batch per publisher")
    if set(artifact_by_id) != expected_batch_ids:
        raise ValueError("rehearsal artifacts are not a bijection with pool entries")

    registry_by_publisher = {
        account_id32(entry.publisher_hotkey): entry for entry in policy.publisher_registry
    }
    groups_seen: set[str] = set()
    for body in evidence.pool_bodies:
        registry = registry_by_publisher.get(account_id32(body.publisher_hotkey))
        if registry is None:
            raise ValueError("pool publisher is absent from the policy registry")
        if registry.control_group_id in groups_seen:
            raise ValueError("rehearsal pool contains two publishers from one control group")
        groups_seen.add(registry.control_group_id)
        if body.window_id != schedule.window_id or body.scoring_policy_hash != policy_hash:
            raise ValueError("pool body does not bind the derived window and policy")
        if len(body.batches) != policy.limits.max_candidate_batches_per_publisher:
            raise ValueError("publisher pool exceeds the launch batch limit")
        public_manifests = {
            entry.batch_id: artifact_by_id[entry.batch_id].public_manifest for entry in body.batches
        }
        ciphertexts = {
            entry.batch_id: artifact_by_id[entry.batch_id].ciphertext_bytes
            for entry in body.batches
        }
        verify_pool_artifacts(
            body,
            public_manifests=public_manifests,
            ciphertexts=ciphertexts,
            policy=policy,
        )
        for entry in body.batches:
            artifact = artifact_by_id[entry.batch_id]
            manifest = artifact.public_manifest
            if manifest.publisher_hotkey != body.publisher_hotkey:
                raise ValueError("public manifest publisher disagrees with its pool")
            if (
                manifest.window_id != schedule.window_id
                or manifest.scoring_policy_hash != policy_hash
                or manifest.response_close_round != schedule.response_close_round
                or manifest.reveal_round != schedule.reveal_round
                or entry.reveal_round != schedule.reveal_round
            ):
                raise ValueError("batch artifact does not bind the derived schedule")
            validate_public_batch_manifest(manifest, policy)
            validate_revealed_batch_shape(
                manifest,
                artifact.revealed_ground_truth,
                policy,
            )


def _candidate_batches(evidence: ShadowRehearsalEvidence) -> tuple[CandidateBatch, ...]:
    group_by_publisher = {
        account_id32(entry.publisher_hotkey): entry.control_group_id
        for entry in evidence.policy.publisher_registry
    }
    return tuple(
        CandidateBatch(
            publisher_hotkey=body.publisher_hotkey,
            control_group_id=group_by_publisher[account_id32(body.publisher_hotkey)],
            batch_id=entry.batch_id,
            batch_commitment=entry.batch_commitment,
        )
        for body in evidence.pool_bodies
        for entry in body.batches
    )


def _select_panel(
    evidence: ShadowRehearsalEvidence,
    seed: bytes,
) -> tuple[MinerCandidate, ...]:
    panel = select_miner_panel(
        tuple(
            MinerCandidate(
                hotkey=item.hotkey,
                root=item.root,
                assigned_observation_count=item.assigned_observation_count,
            )
            for item in evidence.miners
        ),
        seed,
        validator_hotkey=evidence.validator_hotkey,
        panel_size=evidence.policy.limits.miner_panel_size,
    )
    if not panel:
        raise ValueError("rehearsal miner panel is empty")
    return panel


def _replay_assignments(
    evidence: ShadowRehearsalEvidence,
    schedule: WindowSchedule,
    policy_hash: str,
    selected: tuple[CandidateBatch, ...],
    panel: tuple[MinerCandidate, ...],
    artifacts: dict[str, RehearsalBatchArtifact],
    seed: bytes,
) -> _ReplayResult:
    assignments_by_key = {
        _assignment_order_key(assignment): assignment for assignment in evidence.assignments
    }
    expected_keys = {
        (
            base64url_decode(candidate.batch_id),
            base64url_decode(item.challenge_id),
            account_id32(miner.hotkey),
        )
        for candidate in selected
        for item in artifacts[candidate.batch_id].public_manifest.items
        for miner in panel
    }
    if set(assignments_by_key) != expected_keys:
        raise ValueError("assignments are not the exact selected-batch and panel cross product")

    assignment_anchors: list[AssignmentAnchorRecord] = []
    request_anchors: list[RequestAnchorRecord] = []
    response_anchors: list[ResponseAnchorRecord] = []
    sealed_records: list[SealedResponseRecord] = []
    scores_by_batch: dict[str, list[AssignmentScore]] = {
        candidate.batch_id: [] for candidate in selected
    }
    score_records: list[dict[str, Any]] = []
    canary_records: list[dict[str, Any]] = []
    canary_hit = False
    miner_root_by_hotkey = {
        account_id32(item.hotkey): account_id32(item.root) for item in evidence.miners
    }

    for key in sorted(expected_keys):
        assignment = assignments_by_key[key]
        artifact = artifacts[assignment.batch_id]
        manifest_item = next(
            item
            for item in artifact.public_manifest.items
            if item.challenge_id == assignment.challenge_id
        )
        ground_item = next(
            item
            for item in artifact.revealed_ground_truth.items
            if item.challenge_id == assignment.challenge_id
        )
        expected_root = miner_root_by_hotkey[account_id32(assignment.miner_hotkey)]
        if account_id32(assignment.miner_root) != expected_root:
            raise ValueError("assignment miner root disagrees with the candidate snapshot")
        digest = request_digest(assignment.request)
        verified_auth = _validate_request(
            assignment,
            manifest_item,
            schedule,
            policy_hash,
            evidence.validator_hotkey,
            evidence.policy,
        )
        assignment_anchor = AssignmentAnchorRecord(
            initial_auth_evidence=verified_auth[0],
        )
        request_anchor = RequestAnchorRecord(
            auth_evidence=verified_auth,
        )
        validated_response = _validate_rehearsal_response(
            assignment,
            digest,
            expected_validator_hotkey=evidence.validator_hotkey,
            policy=evidence.policy,
        )
        response_anchor = ResponseAnchorRecord(
            request_leaf=request_anchor.leaf,
            sealed_response_record=validated_response.sealed_record,
        )
        assignment_anchors.append(assignment_anchor)
        request_anchors.append(request_anchor)
        response_anchors.append(response_anchor)
        sealed_records.append(validated_response.sealed_record)

        hypothesis = validated_response.hypothesis
        if ground_item.canary:
            canary = evaluate_canary(
                ground_item,
                hypothesis,
                cer_threshold=evidence.policy.thresholds.canary_cer_hit_threshold.fraction,
                wer_threshold=evidence.policy.thresholds.canary_wer_hit_threshold.fraction,
            )
            record = {
                "batch_id": assignment.batch_id,
                "challenge_id": assignment.challenge_id,
                "miner_root": assignment.miner_root,
                "metric": canary.metric,
                "score": _fraction_record(canary.score),
                "threshold": _fraction_record(canary.threshold),
                "hit": canary.hit,
                "zero_score_reason": validated_response.zero_score_reason,
                "trace": canary.trace.to_record() if canary.trace is not None else None,
            }
            canary_records.append(record)
            if canary.hit:
                canary_hit = True
            scores_by_batch[assignment.batch_id].append(
                AssignmentScore(
                    miner_root=assignment.miner_root,
                    challenge_id=assignment.challenge_id,
                    request_leaf=request_anchor.leaf,
                    stratum=manifest_item.stratum,
                    canary=True,
                    score=None,
                )
            )
            continue

        if hypothesis is None:
            score = Fraction(0, 1)
            trace_record = None
        else:
            trace = (
                score_cer_with_trace(hypothesis, ground_item.references)
                if ground_item.metric == "cer"
                else score_wer_with_trace(hypothesis, ground_item.references)
            )
            score = trace.score
            trace_record = trace.to_record()
        scores_by_batch[assignment.batch_id].append(
            AssignmentScore(
                miner_root=assignment.miner_root,
                challenge_id=assignment.challenge_id,
                request_leaf=request_anchor.leaf,
                stratum=manifest_item.stratum,
                canary=False,
                score=score,
            )
        )
        score_records.append(
            {
                "batch_id": assignment.batch_id,
                "challenge_id": assignment.challenge_id,
                "miner_root": assignment.miner_root,
                "stratum": manifest_item.stratum,
                "metric": ground_item.metric,
                "score": _fraction_record(score),
                "zero_score_reason": validated_response.zero_score_reason,
                "trace": trace_record,
            }
        )

    assignment_tuple = tuple(assignment_anchors)
    request_tuple = tuple(request_anchors)
    response_tuple = tuple(response_anchors)
    assignment_root = assignment_set_root(
        assignment_tuple,
        window_id=schedule.window_id,
        validator_hotkey=evidence.validator_hotkey,
    )
    request_root = request_set_root(
        request_tuple,
        assignments=assignment_tuple,
        window_id=schedule.window_id,
        validator_hotkey=evidence.validator_hotkey,
    )
    response_root = response_set_root(
        response_tuple,
        request_records=request_tuple,
        window_id=schedule.window_id,
        validator_hotkey=evidence.validator_hotkey,
    )

    rolling: RollingScoreState | None = None
    weights: WeightBuild | None = None
    void_reason_codes: tuple[str, ...] = ()
    if canary_hit:
        void_reason_codes = (CANARY_HIT_REASON,)
    else:
        scored_batches = tuple(
            ScoredBatch(
                window_index=evidence.window_index,
                batch_rank=batch_rank(seed, candidate),
                pool_leaf=candidate.pool_leaf,
                challenge_ids=tuple(
                    item.challenge_id
                    for item in artifacts[candidate.batch_id].public_manifest.items
                ),
                miner_roots=tuple(
                    sorted(
                        (item.root for item in panel),
                        key=account_id32,
                    )
                ),
                assignments=tuple(
                    sorted(
                        scores_by_batch[candidate.batch_id],
                        key=lambda item: item.key,
                    )
                ),
            )
            for candidate in selected
        )
        rolling = RollingScoreState().advance(
            evidence.window_index,
            new_batches=scored_batches,
            rolling_batch_count=evidence.policy.limits.rolling_batch_count,
            score_max_age_windows=evidence.policy.limits.score_max_age_windows,
        )
        uid_by_root = {account_id32(item.root): item.uid for item in evidence.miners}
        weights = rolling.build_weights(
            minimum_assigned_clips=evidence.policy.limits.minimum_assigned_clips,
            minimum_clips_per_stratum=evidence.policy.limits.minimum_clips_per_stratum,
            quality_floor=evidence.policy.thresholds.quality_floor.fraction,
            uid_by_root=uid_by_root,
            minimum_positive_weights=evidence.minimum_positive_weights,
            maximum_weight_limit_u16=evidence.maximum_weight_limit_u16,
        )
    return _ReplayResult(
        assignment_root=assignment_root,
        request_root=request_root,
        response_root=response_root,
        score_records=tuple(score_records),
        canary_records=tuple(canary_records),
        scored_assignment_count=len(score_records),
        canary_check_count=len(canary_records),
        rolling_state=rolling,
        weight_build=weights,
        void_reason_codes=void_reason_codes,
        assignment_anchor_records=assignment_tuple,
        request_anchor_records=request_tuple,
        response_anchor_records=response_tuple,
        sealed_records=tuple(sealed_records),
    )


def _validate_request(
    assignment: RehearsalAssignment,
    manifest_item: Any,
    schedule: WindowSchedule,
    policy_hash: str,
    validator_hotkey: str,
    policy: ScoringPolicy,
) -> tuple[VerifiedAuthEvidence, ...]:
    request = assignment.request
    if (
        request.window_id != schedule.window_id
        or request.response_close_round != schedule.response_close_round
        or request.reveal_round != schedule.reveal_round
        or request.scoring_policy_hash != policy_hash
    ):
        raise ValueError("assignment request does not bind the derived window")
    if request.deadline_block != request.issued_block + schedule.response_deadline_blocks:
        raise ValueError("assignment request deadline does not reproduce")
    if (
        request.video.sha256 != manifest_item.media.sha256
        or request.video.size_bytes != manifest_item.media.size_bytes
        or request.video.media_type != manifest_item.media.media_type
        or request.task.stratum != manifest_item.stratum
    ):
        raise ValueError("assignment request does not bind the committed public item")
    body = canonical_json_bytes(request)
    if len(body) > policy.limits.maximum_request_body_bytes:
        raise ValueError("assignment request exceeds the policy byte ceiling")
    if len(assignment.auth_records) > policy.limits.maximum_request_transmissions_per_assignment:
        raise ValueError("assignment exceeds its transmission attempt ceiling")
    verified_records: list[VerifiedAuthEvidence] = []
    for record in assignment.auth_records:
        if (
            record.raw_body_sha256 != hashlib.sha256(body).hexdigest()
            or account_id32(record.sender) != account_id32(validator_hotkey)
            or account_id32(record.receiver) != account_id32(assignment.miner_hotkey)
        ):
            raise ValueError("authentication record does not bind the assignment request")
        verified = VerifiedAuthEvidence.from_headers(
            record.headers(),
            request=request,
            expected_validator_hotkey=validator_hotkey,
            expected_miner_hotkey=assignment.miner_hotkey,
        )
        if canonical_json_bytes(verified.auth_record) != canonical_json_bytes(
            record.anchor_record()
        ):
            raise ValueError("historical authentication result does not reproduce")
        verified_records.append(verified)
    return tuple(verified_records)


def _validate_rehearsal_response(
    assignment: RehearsalAssignment,
    digest: str,
    *,
    expected_validator_hotkey: str,
    policy: ScoringPolicy,
) -> _ValidatedRehearsalResponse:
    response = assignment.response
    payload = response.payload
    if payload.request_digest != digest:
        raise ValueError("rehearsal response binds a different request digest")
    if account_id32(payload.validator_hotkey) != account_id32(expected_validator_hotkey):
        raise ValueError("rehearsal response binds a different validator hotkey")
    if account_id32(payload.serving_hotkey) != account_id32(assignment.miner_hotkey):
        raise ValueError("rehearsal response serving hotkey disagrees with its assignment")
    if (
        not assignment.request.issued_block
        <= response.received_block
        <= (assignment.request.deadline_block)
    ):
        raise ValueError("rehearsal response was recorded outside its block interval")
    signature_digest = rehearsal_response_digest(payload)
    if not verify_response_signature(
        signature_digest,
        hotkey_ss58=payload.serving_hotkey,
        scheme=response.signature_scheme,
        signature=response.signature,
    ):
        raise ValueError("rehearsal response signature does not verify")
    payload_bytes = canonical_json_bytes(payload)
    sealed_record = SealedResponseRecord.model_validate(
        {
            "disposition": "sealed",
            "receipt_metadata": {
                "evidence_mode": "offline_shadow_rehearsal",
                "received_block": response.received_block,
            },
            "wire_envelope_sha256": hashlib.sha256(payload_bytes).hexdigest(),
            "signature_scheme": response.signature_scheme,
            "serving_hotkey": payload.serving_hotkey,
            "signature": response.signature,
            "received_bytes_sha256": None,
        }
    )
    hypothesis: str | None = None
    zero_score_reason: str | None = None
    if payload.status == "ok":
        candidate = payload.hypothesis
        if candidate is None:
            raise RuntimeError("strict rehearsal response lost its ok hypothesis")
        if payload.received_video_sha256 != assignment.request.video.sha256:
            zero_score_reason = "received_video_digest_mismatch"
        elif len(candidate.encode("utf-8")) > policy.limits.maximum_hypothesis_utf8_bytes:
            zero_score_reason = "hypothesis_utf8_limit"
        elif normalized_token_count(candidate) > policy.limits.maximum_hypothesis_tokens:
            zero_score_reason = "hypothesis_token_limit"
        elif normalized_grapheme_count(candidate) > policy.limits.maximum_hypothesis_graphemes:
            zero_score_reason = "hypothesis_grapheme_limit"
        else:
            hypothesis = candidate
    elif payload.error_code not in policy.implementation_pins.rules.miner_error_codes:
        zero_score_reason = "miner_error_code_unpinned"
    elif payload.received_video_sha256 not in {None, assignment.request.video.sha256}:
        zero_score_reason = "received_video_digest_mismatch"
    else:
        zero_score_reason = payload.error_code
    return _ValidatedRehearsalResponse(
        sealed_record=sealed_record,
        hypothesis=hypothesis,
        zero_score_reason=zero_score_reason,
    )


def _replay_spent_registry(
    evidence: ShadowRehearsalEvidence,
    schedule: WindowSchedule,
    artifacts: dict[str, RehearsalBatchArtifact],
):
    commitment_by_id = {
        entry.batch_id: entry.batch_commitment
        for body in evidence.pool_bodies
        for entry in body.batches
    }
    batches = tuple(
        SpentCohortBatch(
            batch_commitment=commitment_by_id[artifact.batch_id],
            video_hashes=tuple(item.media.sha256 for item in artifact.public_manifest.items),
            frame_digests=tuple(item.media.frame_digest for item in artifact.public_manifest.items),
            revealed_script_hashes=tuple(
                script_hash
                for item in artifact.revealed_ground_truth.items
                for script_hash in item.retirement_script_sha256s
            ),
        )
        for artifact in evidence.batch_artifacts
    )
    return SpentRegistryState().apply(schedule.reveal_round, batches)


def _validate_selected_script_uniqueness(
    selected: tuple[CandidateBatch, ...],
    artifacts: dict[str, RehearsalBatchArtifact],
) -> None:
    script_hashes = [
        script_hash
        for candidate in selected
        for item in artifacts[candidate.batch_id].revealed_ground_truth.items
        for script_hash in item.retirement_script_sha256s
    ]
    if len(script_hashes) != len(set(script_hashes)):
        raise ValueError("selected batches contain more than one variant of a script")


def _audit_stages(
    evidence: ShadowRehearsalEvidence,
    schedule: WindowSchedule,
    pulse: DrandPulse,
    selected: tuple[CandidateBatch, ...],
    panel: tuple[MinerCandidate, ...],
    replay: _ReplayResult,
    spent_transition: Any,
    fault_transition: Any,
    report: ShadowRehearsalReport,
    source_evidence: bytes,
) -> tuple[StageInput, ...]:
    public_artifacts = [
        {
            "batch_id": item.batch_id,
            "public_manifest": item.public_manifest.model_dump(mode="json", by_alias=True),
            "ciphertext_b64": item.ciphertext_b64,
        }
        for item in evidence.batch_artifacts
    ]
    stage_records = (
        {
            "schema": "umi-shadow-stage-pool/1",
            "policy": evidence.policy.model_dump(mode="json", by_alias=True),
            "schedule": asdict(schedule),
            "pulse": {
                "round": pulse.round,
                "randomness": pulse.randomness,
                "signature": pulse.signature,
                "evidence_digest": pulse.evidence_digest,
            },
            "pool_bodies": [
                body.model_dump(mode="json", by_alias=True) for body in evidence.pool_bodies
            ],
            "availability_certificate": evidence.availability_certificate.model_dump(
                mode="json", by_alias=True
            ),
            "public_artifacts": public_artifacts,
            "selected_batch_ids": [item.batch_id for item in selected],
            "selected_miner_hotkeys": [str(item.hotkey) for item in panel],
        },
        {
            "schema": "umi-shadow-stage-assignment/1",
            "assignments": [
                {
                    "miner_hotkey": item.miner_hotkey,
                    "request": item.request.model_dump(mode="json", by_alias=True),
                    "initial_auth_record": item.auth_records[0].anchor_record(),
                }
                for item in evidence.assignments
            ],
            "assignment_leaves": [record.leaf.hex() for record in replay.assignment_anchor_records],
            "assignment_set_root": replay.assignment_root.hex(),
        },
        {
            "schema": "umi-shadow-stage-request/1",
            "transcripts": [
                {
                    "miner_hotkey": item.miner_hotkey,
                    "request_digest": request_digest(item.request),
                    "auth_records": [record.anchor_record() for record in item.auth_records],
                }
                for item in evidence.assignments
            ],
            "request_leaves": [record.leaf.hex() for record in replay.request_anchor_records],
            "request_set_root": replay.request_root.hex(),
        },
        {
            "schema": "umi-shadow-stage-response/1",
            "responses": [
                item.response.model_dump(mode="json", by_alias=True)
                for item in evidence.assignments
            ],
            "sealed_response_records": [
                record.model_dump(mode="json", by_alias=True) for record in replay.sealed_records
            ],
            "response_leaves": [record.leaf.hex() for record in replay.response_anchor_records],
            "response_set_root": replay.response_root.hex(),
        },
        {
            "schema": "umi-shadow-stage-reveal-score/1",
            "ground_truth": [
                item.revealed_ground_truth.model_dump(mode="json", by_alias=True)
                for item in evidence.batch_artifacts
            ],
            "scores": list(replay.score_records),
            "canaries": list(replay.canary_records),
            "spent_transition": _spent_transition_record(spent_transition),
            "publisher_fault_transition": _fault_transition_record(fault_transition),
        },
    )
    stages: list[StageInput] = []
    for index, (stage_id, record) in enumerate(zip(STAGE_IDS[:5], stage_records, strict=True)):
        objects = [
            BundleObjectInput(
                data=canonical_json_bytes(record),
                media_type="application/json",
            )
        ]
        if index == 0:
            objects.append(
                BundleObjectInput(
                    data=source_evidence,
                    media_type=SOURCE_EVIDENCE_MEDIA_TYPE,
                )
            )
        if index == 4 and replay.weight_build is None:
            objects.append(
                BundleObjectInput(
                    data=canonical_json_bytes(report),
                    media_type="application/json",
                )
            )
        stages.append(StageInput(stage_id=stage_id, objects=tuple(objects)))

    if replay.weight_build is not None and replay.rolling_state is not None:
        weight_record = {
            "schema": "umi-shadow-stage-weight/1",
            "rolling_queue": [_scored_batch_record(item) for item in replay.rolling_state.batches],
            "weight_build": _weight_build_record(replay.weight_build),
            "report": report.model_dump(mode="json", by_alias=True),
        }
        stages.append(
            StageInput(
                stage_id=STAGE_IDS[5],
                objects=(
                    BundleObjectInput(
                        data=canonical_json_bytes(weight_record),
                        media_type="application/json",
                    ),
                ),
            )
        )
        terminal_reason = NO_CHAIN_REASON
    else:
        if len(replay.void_reason_codes) != 1:
            raise RuntimeError("a void rehearsal must have exactly one canonical reason")
        terminal_reason = replay.void_reason_codes[0]
        stages.append(
            StageInput(
                stage_id=STAGE_IDS[5],
                not_reached_reason=terminal_reason,
            )
        )
    stages.append(
        StageInput(
            stage_id=STAGE_IDS[6],
            not_reached_reason=terminal_reason,
        )
    )
    return tuple(stages)


def _assignment_order_key(
    assignment: RehearsalAssignment,
) -> tuple[bytes, bytes, bytes]:
    return (
        base64url_decode(assignment.batch_id),
        base64url_decode(assignment.challenge_id),
        account_id32(assignment.miner_hotkey),
    )


def _fraction_record(value: Fraction) -> dict[str, int]:
    return {"numerator": value.numerator, "denominator": value.denominator}


def _scored_batch_record(batch: ScoredBatch) -> dict[str, Any]:
    return {
        "window_index": batch.window_index,
        "batch_rank": bytes.fromhex(batch.batch_rank).hex()
        if isinstance(batch.batch_rank, str)
        else batch.batch_rank.hex(),
        "pool_leaf": bytes.fromhex(batch.pool_leaf).hex()
        if isinstance(batch.pool_leaf, str)
        else batch.pool_leaf.hex(),
        "assignments": [
            {
                "miner_root": assignment.root.hex(),
                "stratum": assignment.stratum,
                "canary": assignment.canary,
                "score": (
                    _fraction_record(assignment.score) if assignment.score is not None else None
                ),
            }
            for assignment in batch.assignments
        ],
    }


def _weight_build_record(weights: WeightBuild) -> dict[str, Any]:
    return {
        "root_vector": [
            {"miner_root": root.hex(), "weight": _fraction_record(weight)}
            for root, weight in weights.root_vector
        ],
        "uid_vector": [
            {"uid": uid, "weight": _fraction_record(weight)} for uid, weight in weights.uid_vector
        ],
        "quantized_row": [{"uid": uid, "value": value} for uid, value in weights.quantized_row],
    }


def _spent_transition_record(transition: Any) -> dict[str, Any]:
    return {
        "reveal_round": transition.reveal_round,
        "previous_root": transition.previous_root.hex(),
        "delta_leaves": [leaf.hex() for leaf in transition.delta_leaves],
        "delta_root": transition.delta_root.hex(),
        "resulting_root": transition.resulting_root.hex(),
        "prior_collisions": [leaf.hex() for leaf in transition.prior_collisions],
        "duplicate_video_hashes": [value.hex() for value in transition.duplicate_video_hashes],
        "duplicate_frame_digests": [value.hex() for value in transition.duplicate_frame_digests],
    }


def _fault_transition_record(transition: Any) -> dict[str, Any]:
    return {
        "window_index": transition.window_index,
        "previous_root": transition.previous_root.hex(),
        "fault_leaves": [leaf.hex() for leaf in transition.fault_leaves],
        "resulting_root": transition.resulting_root.hex(),
        "struck_groups": [group.hex() for group in transition.struck_groups],
    }


def _software_revisions() -> dict[str, str]:
    environment = scoring_environment()
    return {
        "scoring_source_sha256": environment["scoring_source_sha256"],
        "shadow_runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "umi_source_tree_sha256": umi_source_tree_sha256(),
    }


__all__ = [
    "CANARY_HIT_REASON",
    "MAX_SHADOW_EVIDENCE_BYTES",
    "NO_CHAIN_REASON",
    "SHADOW_REHEARSAL_SCHEMA",
    "SHADOW_REPORT_SCHEMA",
    "SHADOW_RESPONSE_SCHEMA",
    "SOURCE_EVIDENCE_MEDIA_TYPE",
    "QuantizedWeightRecord",
    "RehearsalAssignment",
    "RehearsalAuthRecord",
    "RehearsalBatchArtifact",
    "RehearsalMiner",
    "RehearsalPulse",
    "RehearsalResponse",
    "RehearsalResponsePayload",
    "ShadowRehearsalEvidence",
    "ShadowRehearsalReport",
    "ShadowRehearsalRun",
    "parse_shadow_rehearsal_evidence",
    "rehearsal_response_digest",
    "run_shadow_rehearsal",
    "validate_shadow_runtime",
]
