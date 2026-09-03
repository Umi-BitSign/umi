"""Installed operator CLI for publisher assembly and availability certification."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import os
import re
import stat
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Annotated, Literal

import bittensor as bt
from pydantic import Field, ValidationError, model_validator
from typing_extensions import Self

from .artifacts import PublicBatchManifest
from .calibration_bundle import GrandpaFinalityReplayVerifier
from .encoding import account_id32
from .grandpa_finality import GrandpaFinalityObserver
from .grandpa_finality_supervisor import DurableGrandpaFinalityPort
from .mirror_readiness import (
    MAX_MIRROR_READINESS_BYTES,
    MirrorReadinessError,
    build_mirror_readiness_set,
    check_readiness_input,
    parse_mirror_readiness_statement,
    sign_mirror_readiness,
)
from .mirror_service import MirrorServiceError, check_mirror_service
from .policy import ScoringPolicy, scoring_policy_hash, validate_live_shadow_runtime
from .pool import parse_pool_body_bytes
from .protocol import PROTOCOL_VERSION, StrictProtocolModel, base64url_decode, canonical_json_bytes
from .publisher_availability import (
    MAX_RECEIPT_BYTES,
    AvailabilityQualificationStore,
    AvailabilityWorkflowError,
    LoadedCandidateBundle,
    build_candidate_set,
    build_certified_release,
    load_candidate_bundle,
    parse_qualification_receipt_bytes,
    validate_candidate_bundle,
    write_candidate_bundle,
    write_certified_release,
)
from .publisher_availability_authority import (
    VerifiedQualificationObservation,
    authorize_candidate_qualification,
    protocol_state_genesis_evidence,
    sign_authorized_candidate_qualification,
)
from .substrate_proof import SubprocessStorageProofVerifier
from .validator_bundle_ports import build_production_calibration_bundle_verifier
from .validator_chain import BittensorRawJsonRpc, FinalizedProofCollector
from .validator_closing_snapshot import (
    MAX_CLOSING_PROOF_BYTES,
    AnnouncementValidatorProofEvidence,
    ProofBackedClosingSnapshotCollector,
)
from .validator_journal import ValidatorStageJournal
from .validator_live import LiveValidatorPaths
from .validator_plans import DeterministicWindowPlanSource
from .validator_pool_effect import MAX_CLOSING_SNAPSHOT_BYTES
from .validator_protocol_state import (
    ProtocolStateStoreError,
    ValidatorProtocolStateStore,
    encode_protocol_state_snapshot,
)
from .validator_readiness import (
    ProofBackedPriorWindowReadiness,
    ReplayPublishedBundleVerifier,
)
from .validator_state import ValidatorControlPlane, WindowPlan, WindowStage

ASSEMBLY_CONFIG_SCHEMA = "umi-availability-assembly-config/1"
QUALIFICATION_AUTHORITY_CONFIG_SCHEMA = "umi-availability-qualification-authority-config/1"
AUTHORITY_COLLECTION_SCHEMA = "umi-availability-authority-collection/1"
AUTHORITY_COLLECTION_FILENAME = "authority-collection.json"
ANNOUNCEMENT_SET_FILENAME = "announcement-set.json"
ANNOUNCEMENT_PROOF_FILENAME = "announcement-proof.json"
COLLECTION_OBSERVATION_BEFORE_FILENAME = "collection-observation-before.json"
COLLECTION_OBSERVATION_AFTER_FILENAME = "collection-observation-after.json"
MAX_ASSEMBLY_CONFIG_BYTES = 4 * 1024 * 1024
MAX_POLICY_BYTES = 4 * 1024 * 1024
_MAX_PATH_BYTES = 4_096
_READ_CHUNK_BYTES = 1024 * 1024
_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")


class BatchArtifactPath(StrictProtocolModel):
    batch_id: Annotated[str, Field(min_length=1, max_length=64)]
    path: Annotated[str, Field(min_length=1, max_length=_MAX_PATH_BYTES)]

    @model_validator(mode="after")
    def validate_path(self) -> Self:
        _opaque_id(self.batch_id, "batch artifact ID")
        _absolute_normal_path(self.path, "batch artifact")
        return self


class VideoArtifactPath(BatchArtifactPath):
    challenge_id: Annotated[str, Field(min_length=1, max_length=64)]

    @model_validator(mode="after")
    def validate_video_path(self) -> Self:
        _opaque_id(self.challenge_id, "video challenge ID")
        return self


class AvailabilityAssemblyConfig(StrictProtocolModel):
    """Explicit local source paths for one publisher candidate-set build."""

    schema_: Literal[ASSEMBLY_CONFIG_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    window: dict
    pool_body_paths: Annotated[list[str], Field(min_length=1, max_length=256)]
    public_manifest_paths: Annotated[list[str], Field(min_length=1, max_length=256)]
    ground_truth_envelopes: Annotated[list[BatchArtifactPath], Field(min_length=1, max_length=256)]
    videos: Annotated[list[VideoArtifactPath], Field(min_length=1, max_length=65_536)]

    @model_validator(mode="after")
    def validate_ordering(self) -> Self:
        # Parsing the WindowPlan here keeps this operator config strict without
        # introducing a second protocol schema for the same fields.
        WindowPlan(**self.window)
        for value in (*self.pool_body_paths, *self.public_manifest_paths):
            _absolute_normal_path(value, "assembly artifact")
        if self.pool_body_paths != sorted(set(self.pool_body_paths)):
            raise ValueError("pool-body paths must be unique and sorted")
        if self.public_manifest_paths != sorted(set(self.public_manifest_paths)):
            raise ValueError("public-manifest paths must be unique and sorted")
        envelope_keys = [base64url_decode(item.batch_id) for item in self.ground_truth_envelopes]
        if envelope_keys != sorted(envelope_keys) or len(set(envelope_keys)) != len(envelope_keys):
            raise ValueError("ground-truth envelope paths must be unique and batch-sorted")
        video_keys = [
            (base64url_decode(item.batch_id), base64url_decode(item.challenge_id))
            for item in self.videos
        ]
        if video_keys != sorted(video_keys) or len(set(video_keys)) != len(video_keys):
            raise ValueError("video paths must be unique and identity-sorted")
        all_paths = [
            *self.pool_body_paths,
            *self.public_manifest_paths,
            *(item.path for item in self.ground_truth_envelopes),
            *(item.path for item in self.videos),
        ]
        if len(set(all_paths)) != len(all_paths):
            raise ValueError("assembly artifact paths must be distinct")
        return self


class QualificationAuthorityConfig(StrictProtocolModel):
    """Pinned executables and the validator-owned state used for qualification."""

    schema_: Literal[QUALIFICATION_AUTHORITY_CONFIG_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    network: Literal["finney"]
    target_triple: Annotated[str, Field(min_length=1, max_length=256)]
    storage_proof_verifier_binary: Annotated[str, Field(min_length=1, max_length=_MAX_PATH_BYTES)]
    finality_verifier_binary: Annotated[str, Field(min_length=1, max_length=_MAX_PATH_BYTES)]
    finality_chain_spec_path: Annotated[str, Field(min_length=1, max_length=_MAX_PATH_BYTES)]
    validator_state_root: Annotated[str, Field(min_length=1, max_length=_MAX_PATH_BYTES)]
    finality_startup_timeout_seconds: Annotated[int, Field(ge=1, le=900)] = 120

    @model_validator(mode="after")
    def validate_paths(self) -> Self:
        paths = (
            ("storage proof verifier", self.storage_proof_verifier_binary),
            ("finality verifier", self.finality_verifier_binary),
            ("finality chain spec", self.finality_chain_spec_path),
            ("validator state root", self.validator_state_root),
        )
        for label, value in paths:
            _absolute_normal_path(value, label)
        if len({value for _label, value in paths}) != len(paths):
            raise ValueError("qualification authority paths must be distinct")
        return self


class AuthorityCollectionManifest(StrictProtocolModel):
    """Digest index proving one announcement collection finished before close."""

    schema_: Literal[AUTHORITY_COLLECTION_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    window_id: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    window_index: Annotated[int, Field(ge=0)]
    scoring_policy_hash: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    announcement_block: Annotated[int, Field(ge=0)]
    proposal_close_block: Annotated[int, Field(gt=0)]
    announcement_snapshot_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    announcement_proof_evidence_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    observation_before_block: Annotated[int, Field(ge=0)]
    observation_before_block_hash: Annotated[str, Field(pattern=r"^0x[0-9a-f]{64}$")]
    observation_before_evidence_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    observation_after_block: Annotated[int, Field(ge=0)]
    observation_after_block_hash: Annotated[str, Field(pattern=r"^0x[0-9a-f]{64}$")]
    observation_after_evidence_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]

    @model_validator(mode="after")
    def validate_interval(self) -> Self:
        if not (
            self.announcement_block
            <= self.observation_before_block
            <= self.observation_after_block
            < self.proposal_close_block
        ):
            raise ValueError("authority collection observations fall outside proposal interval")
        if (
            self.observation_before_block == self.observation_after_block
            and self.observation_before_block_hash != self.observation_after_block_hash
        ):
            raise ValueError("authority collection observations conflict at one height")
        return self


def _load_policy(path: Path) -> ScoringPolicy:
    raw = _read_stable_file(path, MAX_POLICY_BYTES, "policy")
    try:
        policy = ScoringPolicy.model_validate_json(raw)
    except (ValidationError, ValueError) as error:
        raise AvailabilityWorkflowError("policy_invalid") from error
    if canonical_json_bytes(policy) != raw:
        raise AvailabilityWorkflowError("policy_noncanonical")
    if policy.translation_weights_active is not False:
        raise AvailabilityWorkflowError("availability_requires_shadow_policy")
    return policy


def _load_assembly(path: Path) -> AvailabilityAssemblyConfig:
    raw = _read_stable_file(path, MAX_ASSEMBLY_CONFIG_BYTES, "assembly_config")
    try:
        config = AvailabilityAssemblyConfig.model_validate_json(raw)
    except (ValidationError, ValueError) as error:
        raise AvailabilityWorkflowError("assembly_config_invalid") from error
    if canonical_json_bytes(config) != raw:
        raise AvailabilityWorkflowError("assembly_config_noncanonical")
    return config


def _load_authority_config(path: Path) -> QualificationAuthorityConfig:
    raw = _read_stable_file(path, MAX_ASSEMBLY_CONFIG_BYTES, "qualification_authority_config")
    try:
        config = QualificationAuthorityConfig.model_validate_json(raw)
    except (ValidationError, ValueError) as error:
        raise AvailabilityWorkflowError("qualification_authority_config_invalid") from error
    if canonical_json_bytes(config) != raw:
        raise AvailabilityWorkflowError("qualification_authority_config_noncanonical")
    return config


def _assemble(args: argparse.Namespace) -> dict:
    policy = _load_policy(args.policy)
    config = _load_assembly(args.assembly)
    window = WindowPlan(**config.window)
    bodies = [
        _read_stable_file(Path(path), policy.limits.maximum_manifest_bytes, "pool_body")
        for path in config.pool_body_paths
    ]
    public: dict[str, bytes] = {}
    source_paths: dict[str, Path] = {}
    for path_text in config.public_manifest_paths:
        path = Path(path_text)
        raw = _read_stable_file(path, policy.limits.maximum_manifest_bytes, "public_manifest")
        try:
            manifest = PublicBatchManifest.model_validate_json(raw)
        except (ValidationError, ValueError) as error:
            raise AvailabilityWorkflowError("public_manifest_invalid") from error
        if canonical_json_bytes(manifest) != raw:
            raise AvailabilityWorkflowError("public_manifest_noncanonical")
        if manifest.batch_id in public:
            raise AvailabilityWorkflowError("public_manifest_batch_duplicate")
        public[manifest.batch_id] = raw
        source_paths[hashlib.sha256(raw).hexdigest()] = path
    envelopes: dict[str, bytes] = {}
    for item in config.ground_truth_envelopes:
        raw = _read_stable_file(
            Path(item.path),
            policy.limits.maximum_ground_truth_envelope_bytes,
            "ground_truth_envelope",
        )
        envelopes[item.batch_id] = raw
        source_paths[hashlib.sha256(raw).hexdigest()] = Path(item.path)
    videos: dict[tuple[str, str], bytes] = {}
    for item in config.videos:
        raw = _read_stable_file(Path(item.path), policy.limits.maximum_clip_size_bytes, "video")
        videos[(item.batch_id, item.challenge_id)] = raw
        source_paths[hashlib.sha256(raw).hexdigest()] = Path(item.path)
    for path, raw in zip(config.pool_body_paths, bodies, strict=True):
        source_paths[hashlib.sha256(raw).hexdigest()] = Path(path)
        parse_pool_body_bytes(raw, policy=policy)
    manifest, objects = build_candidate_set(
        policy=policy,
        window=window,
        pool_body_bytes=bodies,
        public_manifest_bytes=public,
        ground_truth_envelopes=envelopes,
        videos=videos,
    )
    loaded = LoadedCandidateBundle(
        root=args.assembly.parent,
        manifest=manifest,
        manifest_bytes=canonical_json_bytes(manifest),
        objects=objects,
        object_paths=source_paths,
    )
    validated = validate_candidate_bundle(loaded, policy=policy)
    if not args.check:
        if args.output is None:
            raise AvailabilityWorkflowError("assembly_output_required")
        write_candidate_bundle(args.output, manifest, objects)
    return {
        "schema": "umi-availability-assembly-result/1",
        "candidate_set_sha256": loaded.sha256,
        "object_count": len(manifest.objects),
        "pool_count": len(validated.pool_bodies),
        "scoring_policy_sha256": scoring_policy_hash(policy),
        "status": "checked" if args.check else "assembled",
        "state_mutated": not args.check,
        "translation_weights_active": False,
        "weight_submission_capability": False,
    }


def _capture_qualification_observation(
    observer: GrandpaFinalityObserver,
    *,
    minimum_finalized_block: int,
    startup_timeout_seconds: int,
) -> VerifiedQualificationObservation:
    try:
        records = tuple(
            observer.attestations(
                minimum_finalized_block=minimum_finalized_block,
                maximum_records=1,
                startup_timeout_seconds=startup_timeout_seconds,
            )
        )
    except Exception as error:
        raise AvailabilityWorkflowError("qualification_live_finality_unavailable") from error
    if len(records) != 1:
        raise AvailabilityWorkflowError("qualification_live_finality_record_count")
    record = records[0]
    return VerifiedQualificationObservation(
        block_number=record.block.number,
        block_hash=record.block.hash,
        finality_evidence_bytes=record.canonical_bytes,
    )


def _build_authority_verifiers(
    policy: ScoringPolicy,
    config: QualificationAuthorityConfig,
):
    try:
        validate_live_shadow_runtime(
            policy,
            target_triple=config.target_triple,
            storage_proof_verifier_binary=config.storage_proof_verifier_binary,
            finality_verifier_binary=config.finality_verifier_binary,
            finality_chain_spec_path=config.finality_chain_spec_path,
        )
    except Exception as error:
        raise AvailabilityWorkflowError("qualification_runtime_pin_mismatch") from error
    proof_pin = policy.implementation_pins.storage_proof_verifier
    finality_pin = policy.implementation_pins.finality_verifier
    if proof_pin is None or finality_pin is None:
        raise AvailabilityWorkflowError("qualification_policy_pins_missing")
    proof_digest = proof_pin.release_sha256_by_target.get(config.target_triple)
    finality_digest = finality_pin.release_sha256_by_target.get(config.target_triple)
    if proof_digest is None or finality_digest is None:
        raise AvailabilityWorkflowError("qualification_policy_target_missing")
    try:
        storage_verifier = SubprocessStorageProofVerifier(
            binary_path=config.storage_proof_verifier_binary,
            expected_sha256=proof_digest,
        )
        observer = GrandpaFinalityObserver.from_policy_pin(
            finality_pin,
            target_triple=config.target_triple,
            binary_path=config.finality_verifier_binary,
            chain_spec_path=config.finality_chain_spec_path,
            record_timeout_seconds=config.finality_startup_timeout_seconds,
        )
    except Exception as error:
        raise AvailabilityWorkflowError("qualification_verifier_initialization_failed") from error
    return storage_verifier, observer, finality_digest


def _require_existing_validator_state(
    config: QualificationAuthorityConfig,
    *,
    window_index: int,
) -> LiveValidatorPaths:
    """Resolve one already-running validator state tree without creating it."""

    root = Path(config.validator_state_root)
    paths = LiveValidatorPaths.below(root)
    try:
        root_stat = root.lstat()
    except OSError as error:
        raise AvailabilityWorkflowError("qualification_validator_state_missing") from error
    if (
        stat.S_ISLNK(root_stat.st_mode)
        or not stat.S_ISDIR(root_stat.st_mode)
        or root_stat.st_uid != os.getuid()
        or root_stat.st_mode & 0o077
    ):
        raise AvailabilityWorkflowError("qualification_validator_state_unsafe")
    required_files = (
        paths.control_plane,
        paths.protocol_state,
        paths.plan_observations,
        paths.finality_state,
    )
    required_directories = (paths.stage_journal,)
    for path in required_files:
        try:
            details = path.lstat()
        except OSError as error:
            raise AvailabilityWorkflowError("qualification_validator_state_incomplete") from error
        if (
            stat.S_ISLNK(details.st_mode)
            or not stat.S_ISREG(details.st_mode)
            or details.st_uid != os.getuid()
            or details.st_mode & 0o022
        ):
            raise AvailabilityWorkflowError("qualification_validator_state_unsafe")
    for path in required_directories:
        try:
            details = path.lstat()
        except OSError as error:
            raise AvailabilityWorkflowError("qualification_validator_state_incomplete") from error
        if (
            stat.S_ISLNK(details.st_mode)
            or not stat.S_ISDIR(details.st_mode)
            or details.st_uid != os.getuid()
            or details.st_mode & 0o022
        ):
            raise AvailabilityWorkflowError("qualification_validator_state_unsafe")
    if window_index > 0:
        bundle_roots = []
        for path in (paths.bundles, paths.incident_bundles):
            if not os.path.lexists(path):
                continue
            details = path.lstat()
            if (
                stat.S_ISLNK(details.st_mode)
                or not stat.S_ISDIR(details.st_mode)
                or details.st_uid != os.getuid()
                or details.st_mode & 0o022
            ):
                raise AvailabilityWorkflowError("qualification_validator_state_unsafe")
            bundle_roots.append(path)
        if not bundle_roots:
            raise AvailabilityWorkflowError("qualification_prior_bundle_missing")
    return paths


async def _replay_protocol_state_authority(
    *,
    policy: ScoringPolicy,
    config: QualificationAuthorityConfig,
    paths: LiveValidatorPaths,
    window: WindowPlan,
    storage_verifier: SubprocessStorageProofVerifier,
) -> tuple[bytes, bytes]:
    """Rebuild state continuity from the live validator's full durable history."""

    protocol_store: ValidatorProtocolStateStore | None = None
    finality: DurableGrandpaFinalityPort | None = None
    try:
        protocol_store = ValidatorProtocolStateStore(paths.protocol_state)
        state = protocol_store.audit()
        state_bytes = encode_protocol_state_snapshot(state)
        control = ValidatorControlPlane(paths.control_plane)
        journal = ValidatorStageJournal(paths.stage_journal)
        finality = DurableGrandpaFinalityPort.from_policy(
            policy,
            target_triple=config.target_triple,
            binary_path=config.finality_verifier_binary,
            chain_spec_path=config.finality_chain_spec_path,
            state_path=paths.finality_state,
            initial_minimum_finalized_block=policy.activation_block - 1,
            startup_timeout_seconds=config.finality_startup_timeout_seconds,
        )
        finality.audit()
        bundle_verifier = build_production_calibration_bundle_verifier(
            policy=policy,
            target_triple=config.target_triple,
            finality_verifier_binary=config.finality_verifier_binary,
            finality_chain_spec=config.finality_chain_spec_path,
            storage_proof_verifier=storage_verifier,
        )
        readiness = ProofBackedPriorWindowReadiness(
            policy=policy,
            protocol_state=protocol_store,
            journal=journal,
            bundle_root=paths.bundles,
            incident_bundle_root=paths.incident_bundles,
            bundle_verifier=ReplayPublishedBundleVerifier(bundle_verifier.ports),
            finality=finality,
        )
        # Construction audits the complete cached announcement prefix against
        # the control-plane plans without advancing either store.
        DeterministicWindowPlanSource(
            policy=policy,
            control_plane=control,
            finalized_blocks=finality,
            prior_readiness=readiness,
            observation_cache_path=paths.plan_observations,
        )
        windows = control.list_windows()
        if len(windows) != window.window_index + 1 or [
            item.plan.window_index for item in windows
        ] != list(range(len(windows))):
            raise AvailabilityWorkflowError("qualification_window_history_not_reconciled")
        current = windows[-1]
        if (
            current.plan != window
            or not current.is_active
            or current.stage is not WindowStage.POOL_AND_SELECTION
        ):
            raise AvailabilityWorkflowError("qualification_current_window_state_mismatch")

        if window.window_index == 0:
            continuity = protocol_state_genesis_evidence(
                protocol_state_bytes=state_bytes,
                protocol_state=state,
                window_id=window.window_id,
                policy_hash=scoring_policy_hash(policy),
            )
        else:
            previous = windows[-2]
            checkpoint = await readiness.verified_reveal_and_spent(previous)
            if checkpoint is None:
                raise AvailabilityWorkflowError("qualification_prior_window_not_ready")
            if (
                checkpoint.window_index != window.window_index - 1
                or checkpoint.window_id != previous.plan.window_id
                or checkpoint.reveal_round != previous.plan.reveal_round
                or checkpoint.spent_root != state.spent_registry.root.hex()
                or state.last_window_index != previous.plan.window_index
                or state.last_window_id != bytes.fromhex(previous.plan.window_id)
                or state.spent_registry.last_reveal_round != previous.plan.reveal_round
            ):
                raise AvailabilityWorkflowError("qualification_prior_checkpoint_mismatch")
            continuity = checkpoint.evidence

        final_state_bytes = encode_protocol_state_snapshot(protocol_store.audit())
        if final_state_bytes != state_bytes or control.list_windows() != windows:
            raise AvailabilityWorkflowError("qualification_validator_state_changed")
        return state_bytes, continuity
    except AvailabilityWorkflowError:
        raise
    except (ProtocolStateStoreError, OSError, ValueError) as error:
        raise AvailabilityWorkflowError("qualification_protocol_state_unavailable") from error
    except Exception as error:
        raise AvailabilityWorkflowError("qualification_protocol_state_replay_failed") from error
    finally:
        if protocol_store is not None:
            protocol_store.close()
        if finality is not None:
            finality.close()


def _require_collection_observation(
    observation: VerifiedQualificationObservation,
    *,
    window: WindowPlan,
    prior: VerifiedQualificationObservation | None = None,
) -> None:
    if not (window.announcement_block <= observation.block_number < window.proposal_close_block):
        raise AvailabilityWorkflowError("authority_collection_outside_proposal_interval")
    if prior is not None and (
        observation.block_number < prior.block_number
        or (
            observation.block_number == prior.block_number
            and observation.block_hash != prior.block_hash
        )
    ):
        raise AvailabilityWorkflowError("authority_collection_finality_regressed")


async def _collect_authority(
    args: argparse.Namespace,
    *,
    client_factory,
) -> dict:
    policy = _load_policy(args.policy)
    loaded = load_candidate_bundle(args.candidate_bundle)
    config = _load_authority_config(args.authority_config)
    window = loaded.manifest.window.to_plan()
    validator_paths = _require_existing_validator_state(config, window_index=window.window_index)
    if not args.check:
        if args.output is None:
            raise AvailabilityWorkflowError("authority_collection_output_required")
        _absolute_normal_path(str(args.output), "authority collection output")
        if _paths_overlap(
            args.output,
            (
                args.policy,
                args.candidate_bundle,
                args.authority_config,
                Path(config.storage_proof_verifier_binary),
                Path(config.finality_verifier_binary),
                Path(config.finality_chain_spec_path),
                validator_paths.root,
            ),
        ):
            raise AvailabilityWorkflowError("authority_collection_output_overlap")
    storage_verifier, observer, _finality_digest = _build_authority_verifiers(policy, config)

    before = _capture_qualification_observation(
        observer,
        minimum_finalized_block=window.announcement_block,
        startup_timeout_seconds=config.finality_startup_timeout_seconds,
    )
    _require_collection_observation(before, window=window)

    finality_database = validator_paths.finality_state
    finality = None
    client = None
    try:
        try:
            finality = DurableGrandpaFinalityPort.from_policy(
                policy,
                target_triple=config.target_triple,
                binary_path=config.finality_verifier_binary,
                chain_spec_path=config.finality_chain_spec_path,
                state_path=finality_database,
                initial_minimum_finalized_block=policy.activation_block - 1,
            )
            finality.audit()
            persisted_before = finality.persisted_head()
        except Exception as error:
            raise AvailabilityWorkflowError("authority_finality_state_unavailable") from error
        if (
            persisted_before is None
            or persisted_before.height < window.announcement_block
            or persisted_before.height >= window.proposal_close_block
        ):
            raise AvailabilityWorkflowError("authority_finality_state_outside_proposal_interval")

        try:
            client = client_factory(config.network)
            if await client.connect() is not client:
                raise AvailabilityWorkflowError("authority_chain_client_connection_invalid")
            proofs = FinalizedProofCollector(
                BittensorRawJsonRpc(client),
                finality=finality,
                verifier=storage_verifier,
            )
            collector = ProofBackedClosingSnapshotCollector(
                policy=policy,
                finality=finality,
                proofs=proofs,
            )
            snapshot, snapshot_bytes, proof_bytes = await collector.collect_announcement_validators(
                window
            )
        except AvailabilityWorkflowError:
            raise
        except Exception as error:
            raise AvailabilityWorkflowError("authority_announcement_collection_failed") from error

        after = _capture_qualification_observation(
            observer,
            minimum_finalized_block=max(window.announcement_block, before.block_number),
            startup_timeout_seconds=config.finality_startup_timeout_seconds,
        )
        _require_collection_observation(after, window=window, prior=before)
        persisted_after = finality.persisted_head()
        if (
            persisted_after is None
            or persisted_after.height < persisted_before.height
            or persisted_after.height >= window.proposal_close_block
        ):
            raise AvailabilityWorkflowError("authority_finality_state_outside_proposal_interval")
        for observation in (before, after):
            if (
                observation.block_number == window.announcement_block
                and observation.block_hash != snapshot.announcement_block_hash
            ):
                raise AvailabilityWorkflowError("authority_collection_observation_hash_mismatch")

        manifest = AuthorityCollectionManifest(
            schema=AUTHORITY_COLLECTION_SCHEMA,
            protocol=PROTOCOL_VERSION,
            window_id=window.window_id,
            window_index=window.window_index,
            scoring_policy_hash=scoring_policy_hash(policy),
            announcement_block=window.announcement_block,
            proposal_close_block=window.proposal_close_block,
            announcement_snapshot_sha256=hashlib.sha256(snapshot_bytes).hexdigest(),
            announcement_proof_evidence_sha256=hashlib.sha256(proof_bytes).hexdigest(),
            observation_before_block=before.block_number,
            observation_before_block_hash=before.block_hash,
            observation_before_evidence_sha256=hashlib.sha256(
                before.finality_evidence_bytes
            ).hexdigest(),
            observation_after_block=after.block_number,
            observation_after_block_hash=after.block_hash,
            observation_after_evidence_sha256=hashlib.sha256(
                after.finality_evidence_bytes
            ).hexdigest(),
        )
        manifest_bytes = canonical_json_bytes(manifest)
        if not args.check:
            _write_authority_collection(
                args.output,
                manifest_bytes=manifest_bytes,
                snapshot_bytes=snapshot_bytes,
                proof_bytes=proof_bytes,
                before_bytes=before.finality_evidence_bytes,
                after_bytes=after.finality_evidence_bytes,
            )
        return {
            "schema": "umi-availability-authority-collection-result/1",
            "announcement_proof_evidence_sha256": (manifest.announcement_proof_evidence_sha256),
            "announcement_snapshot_sha256": manifest.announcement_snapshot_sha256,
            "collection_manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "observation_after_block": after.block_number,
            "scoring_policy_sha256": scoring_policy_hash(policy),
            "status": "checked" if args.check else "collected",
            "state_mutated": not args.check,
            "broadcast_performed": False,
            "translation_weights_active": False,
            "weight_submission_capability": False,
        }
    finally:
        if finality is not None:
            finality.close()
        if client is not None:
            await client.close()


async def _qualification_authority(
    args: argparse.Namespace,
    *,
    policy: ScoringPolicy,
    loaded: LoadedCandidateBundle,
    capture_live_observation: bool,
):
    config = _load_authority_config(args.authority_config)
    storage_verifier, observer, finality_digest = _build_authority_verifiers(policy, config)
    window = loaded.manifest.window.to_plan()
    validator_paths = _require_existing_validator_state(config, window_index=window.window_index)
    announcement_snapshot_bytes = _read_stable_file(
        args.announcement_snapshot,
        MAX_CLOSING_SNAPSHOT_BYTES,
        "announcement_snapshot",
    )
    announcement_proof_bytes = _read_stable_file(
        args.announcement_proof,
        MAX_CLOSING_PROOF_BYTES,
        "announcement_proof",
    )
    protocol_state_bytes, continuity_evidence_bytes = await _replay_protocol_state_authority(
        policy=policy,
        config=config,
        paths=validator_paths,
        window=window,
        storage_verifier=storage_verifier,
    )

    if capture_live_observation:
        observation = _capture_qualification_observation(
            observer,
            minimum_finalized_block=loaded.manifest.window.announcement_block,
            startup_timeout_seconds=config.finality_startup_timeout_seconds,
        )
    else:
        try:
            proof = AnnouncementValidatorProofEvidence.model_validate_json(announcement_proof_bytes)
            observation = VerifiedQualificationObservation(
                block_number=proof.finality.block_number,
                block_hash=proof.finality.block_hash,
                finality_evidence_bytes=bytes.fromhex(
                    proof.finality.finality_attestation.removeprefix("0x")
                ),
            )
        except Exception as error:
            raise AvailabilityWorkflowError("qualification_announcement_proof_invalid") from error
    authorized = authorize_candidate_qualification(
        loaded=loaded,
        policy=policy,
        validator_hotkey=args.validator_hotkey,
        announcement_snapshot_bytes=announcement_snapshot_bytes,
        announcement_proof_evidence_bytes=announcement_proof_bytes,
        protocol_state_bytes=protocol_state_bytes,
        protocol_state_continuity_evidence_bytes=continuity_evidence_bytes,
        observation=observation,
        storage_proof_verifier=storage_verifier,
        finality_verifier=GrandpaFinalityReplayVerifier(observer),
        finality_verifier_sha256=finality_digest,
    )
    return authorized, observer, config


async def _qualify(args: argparse.Namespace) -> dict:
    policy = _load_policy(args.policy)
    loaded = load_candidate_bundle(args.candidate_bundle)
    authorized, observer, authority_config = await _qualification_authority(
        args,
        policy=policy,
        loaded=loaded,
        capture_live_observation=not args.check,
    )
    validated = authorized.validated
    if args.check:
        return {
            "schema": "umi-availability-qualification-check/1",
            "availability_set_root": validated.set_root,
            "candidate_set_sha256": loaded.sha256,
            "qualified_pool_leaves": list(validated.leaves),
            "scoring_policy_sha256": scoring_policy_hash(policy),
            "status": "proof_authority_checked_unsigned",
            "state_mutated": False,
            "signature_created": False,
            "translation_weights_active": False,
            "weight_submission_capability": False,
        }
    required = {
        "state_root": args.state_root,
        "receipt_output": args.receipt_output,
        "wallet_name": args.wallet_name,
        "wallet_hotkey_name": args.wallet_hotkey_name,
        "wallet_path": args.wallet_path,
    }
    if any(value is None for value in required.values()):
        raise AvailabilityWorkflowError("qualification_signing_arguments_missing")
    if (
        _NAME_RE.fullmatch(args.wallet_name) is None
        or _NAME_RE.fullmatch(args.wallet_hotkey_name) is None
    ):
        raise AvailabilityWorkflowError("wallet_name_invalid")
    for label, path in (
        ("state_root", args.state_root),
        ("receipt_output", args.receipt_output),
        ("wallet_path", args.wallet_path),
    ):
        _absolute_normal_path(str(path), label)
    if _paths_overlap(
        Path(args.state_root),
        (
            args.policy,
            args.candidate_bundle,
            args.announcement_snapshot,
            args.announcement_proof,
            args.authority_config,
            Path(authority_config.validator_state_root),
            Path(args.receipt_output),
            Path(args.wallet_path),
        ),
    ):
        raise AvailabilityWorkflowError("qualification_state_input_overlap")
    wallet = bt.Wallet(
        name=args.wallet_name,
        hotkey=args.wallet_hotkey_name,
        path=args.wallet_path,
    )
    state = AvailabilityQualificationStore(
        args.state_root,
        policy_hash=scoring_policy_hash(policy),
        validator_hotkey=args.validator_hotkey,
    )
    window = loaded.manifest.window

    def require_still_open() -> None:
        observation = _capture_qualification_observation(
            observer,
            minimum_finalized_block=window.announcement_block,
            startup_timeout_seconds=authority_config.finality_startup_timeout_seconds,
        )
        if observation.block_number >= window.proposal_close_block:
            raise AvailabilityWorkflowError("qualification_outside_proposal_interval")

    receipt = sign_authorized_candidate_qualification(
        authorized,
        policy=policy,
        state=state,
        wallet=wallet,
        before_sign=require_still_open,
    )
    receipt_bytes = canonical_json_bytes(receipt)
    _write_idempotent_receipt(args.receipt_output, receipt_bytes)
    return {
        "schema": "umi-availability-qualification-result/1",
        "availability_set_root": receipt.availability_set_root,
        "candidate_set_sha256": receipt.candidate_set_sha256,
        "receipt_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
        "scoring_policy_sha256": scoring_policy_hash(policy),
        "status": "signed_and_retained",
        "state_mutated": True,
        "signature_created": True,
        "translation_weights_active": False,
        "weight_submission_capability": False,
    }


def _aggregate(args: argparse.Namespace) -> dict:
    policy = _load_policy(args.policy)
    loaded = load_candidate_bundle(args.candidate_bundle)
    validated = validate_candidate_bundle(loaded, policy=policy)
    receipts = [
        parse_qualification_receipt_bytes(
            _read_stable_file(path, MAX_RECEIPT_BYTES, "qualification_receipt")
        )
        for path in args.receipt
    ]
    material = build_certified_release(validated, receipts, policy=policy)
    if not args.check:
        if args.output is None:
            raise AvailabilityWorkflowError("certified_release_output_required")
        write_certified_release(args.output, material)
    return {
        "schema": "umi-certified-pool-release-result/1",
        "availability_set_root": material.release.availability_set_root,
        "candidate_set_sha256": loaded.sha256,
        "mirror_index_sha256": material.release.mirror_index_sha256,
        "pool_manifest_sha256s": [item.sha256 for item in material.release.pool_manifests],
        "scoring_policy_sha256": scoring_policy_hash(policy),
        "signer_count": len(material.certificate.signatures),
        "status": "checked" if args.check else "materialized",
        "state_mutated": not args.check,
        "broadcast_performed": False,
        "translation_weights_active": False,
        "weight_submission_capability": False,
    }


def _attest_mirror(args: argparse.Namespace) -> dict:
    try:
        checked_service = check_mirror_service(args.service_config)
        receipt_bytes = _read_stable_file(
            args.qualification_receipt,
            MAX_RECEIPT_BYTES,
            "qualification_receipt",
        )
        checked = check_readiness_input(checked_service, receipt_bytes)
    except MirrorServiceError as error:
        raise AvailabilityWorkflowError(error.reason_code) from error
    except MirrorReadinessError as error:
        raise AvailabilityWorkflowError(error.reason_code) from error
    if args.check:
        return {
            "schema": "umi-mirror-readiness-attestation-result/1",
            "certified_release_sha256": checked_service.certified_release_sha256,
            "delivery_origin": checked_service.delivery_origin,
            "retrieval_origin": checked_service.retrieval_origin,
            "status": "checked",
            "signature_created": False,
            "state_mutated": False,
            "broadcast_performed": False,
            "translation_weights_active": False,
            "weight_submission_capability": False,
        }
    required = (
        args.output,
        args.wallet_name,
        args.wallet_hotkey_name,
        args.wallet_path,
    )
    if any(value is None for value in required):
        raise AvailabilityWorkflowError("mirror_readiness_signing_arguments_missing")
    wallet = bt.Wallet(
        name=args.wallet_name,
        hotkey=args.wallet_hotkey_name,
        path=str(args.wallet_path),
    )
    try:
        signer = bt.resolve_signer(wallet, role="hotkey")
        scheme = bt.wallets.format_crypto_type(signer.crypto_type)
    except Exception as error:
        raise AvailabilityWorkflowError("mirror_readiness_signer_unavailable") from error
    if account_id32(signer.ss58_address) != account_id32(checked.receipt.validator_hotkey):
        raise AvailabilityWorkflowError("mirror_readiness_signer_mismatch")
    if scheme not in {"sr25519", "ed25519"}:
        raise AvailabilityWorkflowError("mirror_readiness_signature_scheme_invalid")
    try:
        statement = sign_mirror_readiness(
            checked,
            signature_scheme=scheme,
            sign_digest=lambda digest: bytes(signer.sign(digest)),
        )
    except MirrorReadinessError as error:
        raise AvailabilityWorkflowError(error.reason_code) from error
    statement_bytes = canonical_json_bytes(statement)
    _write_idempotent_receipt(args.output, statement_bytes)
    return {
        "schema": "umi-mirror-readiness-attestation-result/1",
        "certified_release_sha256": checked_service.certified_release_sha256,
        "delivery_origin": checked_service.delivery_origin,
        "retrieval_origin": checked_service.retrieval_origin,
        "statement_sha256": hashlib.sha256(statement_bytes).hexdigest(),
        "status": "signed",
        "signature_created": True,
        "state_mutated": True,
        "broadcast_performed": False,
        "translation_weights_active": False,
        "weight_submission_capability": False,
    }


def _verify_mirrors(args: argparse.Namespace) -> dict:
    policy = _load_policy(args.policy)
    root = args.certified_tree.expanduser().absolute()
    try:
        release_bytes = _read_stable_file(
            root / "certified-release.json",
            MAX_MIRROR_READINESS_BYTES,
            "certified_release",
        )
        anchor_bytes = _read_stable_file(
            root / "anchor-intents.json",
            MAX_MIRROR_READINESS_BYTES,
            "anchor_intents",
        )
        discovery_bytes = _read_stable_file(
            args.mirror_discovery_rule,
            MAX_MIRROR_READINESS_BYTES,
            "mirror_discovery_rule",
        )
        receipts = [
            _read_stable_file(path, MAX_RECEIPT_BYTES, "qualification_receipt")
            for path in args.qualification_receipt
        ]
        statements = [
            parse_mirror_readiness_statement(
                _read_stable_file(path, MAX_MIRROR_READINESS_BYTES, "mirror_readiness_statement")
            )
            for path in args.statement
        ]
        readiness = build_mirror_readiness_set(
            policy=policy,
            certified_release_bytes=release_bytes,
            anchor_intents_bytes=anchor_bytes,
            discovery_rule_bytes=discovery_bytes,
            qualification_receipt_bytes=receipts,
            statements=statements,
        )
    except MirrorReadinessError as error:
        raise AvailabilityWorkflowError(error.reason_code) from error
    readiness_bytes = canonical_json_bytes(readiness)
    if not args.check:
        if args.output is None:
            raise AvailabilityWorkflowError("mirror_readiness_set_output_required")
        if args.output.expanduser().absolute().is_relative_to(root):
            raise AvailabilityWorkflowError("mirror_readiness_output_inside_certified_tree")
        _write_idempotent_receipt(args.output, readiness_bytes)
    return {
        "schema": "umi-mirror-readiness-set-result/1",
        "certified_release_sha256": readiness.certified_release_sha256,
        "mirror_readiness_set_sha256": hashlib.sha256(readiness_bytes).hexdigest(),
        "signer_count": len(readiness.statements),
        "status": "checked" if args.check else "anchor_ready",
        "state_mutated": not args.check,
        "broadcast_performed": False,
        "translation_weights_active": False,
        "weight_submission_capability": False,
    }


def run(argv: Sequence[str] | None = None, *, client_factory=bt.Client) -> int:
    """Run one explicit workflow step and emit one canonical machine-readable result."""

    args = _parser().parse_args(argv)
    try:
        if args.command == "collect-authority":
            result = asyncio.run(args.handler(args, client_factory=client_factory))
        elif args.command == "qualify":
            result = asyncio.run(args.handler(args))
        else:
            result = args.handler(args)
        print(canonical_json_bytes(result).decode("utf-8"))
        return 0
    except AvailabilityWorkflowError as error:
        _print_error(error.reason_code, check=args.check)
        return 2
    except Exception:
        _print_error("availability_operator_failed", check=args.check)
        return 2


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Assemble, certify, and materialize UMI shadow publisher pools"
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    assemble = subcommands.add_parser("assemble", help="build a candidate-set bundle")
    assemble.add_argument("--policy", type=Path, required=True)
    assemble.add_argument("--assembly", type=Path, required=True)
    assemble.add_argument("--output", type=Path)
    assemble.add_argument("--check", action="store_true")
    assemble.set_defaults(handler=_assemble)

    collect_authority = subcommands.add_parser(
        "collect-authority",
        help="collect proof-backed announcement authority before proposal close",
    )
    collect_authority.add_argument("--policy", type=Path, required=True)
    collect_authority.add_argument("--candidate-bundle", type=Path, required=True)
    collect_authority.add_argument(
        "--authority-config",
        type=Path,
        required=True,
        help="pinned verifier paths plus one existing live-validator state root",
    )
    collect_authority.add_argument("--output", type=Path)
    collect_authority.add_argument(
        "--check",
        action="store_true",
        help="perform read-only finality and proof RPC checks without writing output",
    )
    collect_authority.set_defaults(handler=_collect_authority)

    qualify = subcommands.add_parser(
        "qualify",
        help="replay proof authority, retain, and sign one complete candidate set",
    )
    qualify.add_argument("--policy", type=Path, required=True)
    qualify.add_argument("--candidate-bundle", type=Path, required=True)
    qualify.add_argument(
        "--announcement-snapshot",
        type=Path,
        required=True,
        help="exact canonical umi-validator-announcement-set/1 JSON",
    )
    qualify.add_argument(
        "--announcement-proof",
        type=Path,
        required=True,
        help="exact canonical umi-announcement-validator-evidence/1 JSON",
    )
    qualify.add_argument(
        "--authority-config",
        type=Path,
        required=True,
        help="pinned verifier paths and one existing live-validator state root",
    )
    qualify.add_argument("--validator-hotkey", required=True)
    qualify.add_argument("--state-root", type=Path)
    qualify.add_argument("--receipt-output", type=Path)
    qualify.add_argument("--wallet-name")
    qualify.add_argument("--wallet-hotkey-name")
    qualify.add_argument("--wallet-path", type=Path)
    qualify.add_argument("--check", action="store_true")
    qualify.set_defaults(handler=_qualify)

    aggregate = subcommands.add_parser(
        "aggregate",
        help="verify a quorum and build final pool manifests plus mirror tree",
    )
    aggregate.add_argument("--policy", type=Path, required=True)
    aggregate.add_argument("--candidate-bundle", type=Path, required=True)
    aggregate.add_argument("--receipt", type=Path, required=True, action="append")
    aggregate.add_argument("--output", type=Path)
    aggregate.add_argument("--check", action="store_true")
    aggregate.set_defaults(handler=_aggregate)

    attest_mirror = subcommands.add_parser(
        "attest-mirror",
        help="check one exact mirror definition and sign its pre-anchor readiness",
    )
    attest_mirror.add_argument("--service-config", type=Path, required=True)
    attest_mirror.add_argument("--qualification-receipt", type=Path, required=True)
    attest_mirror.add_argument("--output", type=Path)
    attest_mirror.add_argument("--wallet-name")
    attest_mirror.add_argument("--wallet-hotkey-name")
    attest_mirror.add_argument("--wallet-path", type=Path)
    attest_mirror.add_argument("--check", action="store_true")
    attest_mirror.set_defaults(handler=_attest_mirror)

    verify_mirrors = subcommands.add_parser(
        "verify-mirrors",
        help="require a unique checked mirror pair from every availability signer",
    )
    verify_mirrors.add_argument("--policy", type=Path, required=True)
    verify_mirrors.add_argument("--certified-tree", type=Path, required=True)
    verify_mirrors.add_argument("--mirror-discovery-rule", type=Path, required=True)
    verify_mirrors.add_argument(
        "--qualification-receipt", type=Path, required=True, action="append"
    )
    verify_mirrors.add_argument("--statement", type=Path, required=True, action="append")
    verify_mirrors.add_argument("--output", type=Path)
    verify_mirrors.add_argument("--check", action="store_true")
    verify_mirrors.set_defaults(handler=_verify_mirrors)
    return parser


def _read_stable_file(path: Path, maximum_bytes: int, label: str) -> bytes:
    absolute = path.expanduser().absolute()
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(absolute, flags)
    except OSError as error:
        raise AvailabilityWorkflowError(f"{label}_unavailable") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_mode & 0o022
            or before.st_size <= 0
            or before.st_size > maximum_bytes
        ):
            raise AvailabilityWorkflowError(f"{label}_unsafe")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(_READ_CHUNK_BYTES, maximum_bytes - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > maximum_bytes:
                raise AvailabilityWorkflowError(f"{label}_size_limit")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        before_identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        if before_identity != after_identity or total != before.st_size:
            raise AvailabilityWorkflowError(f"{label}_changed")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _write_idempotent_receipt(path: Path, data: bytes) -> None:
    absolute = path.expanduser().absolute()
    absolute.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if absolute.exists():
        existing = _read_stable_file(absolute, MAX_RECEIPT_BYTES, "receipt_output")
        if existing != data:
            raise AvailabilityWorkflowError("receipt_output_conflict")
        return
    descriptor = os.open(absolute, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("receipt write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _fsync_directory(absolute.parent)


def _write_authority_collection(
    output: Path,
    *,
    manifest_bytes: bytes,
    snapshot_bytes: bytes,
    proof_bytes: bytes,
    before_bytes: bytes,
    after_bytes: bytes,
) -> None:
    root = output.expanduser().absolute()
    if root.exists() or root.is_symlink():
        raise AvailabilityWorkflowError("authority_collection_output_exists")
    root.mkdir(parents=True, mode=0o700)
    os.chmod(root, 0o700)
    _fsync_directory(root.parent)
    objects = (
        (ANNOUNCEMENT_PROOF_FILENAME, proof_bytes, MAX_CLOSING_PROOF_BYTES),
        (ANNOUNCEMENT_SET_FILENAME, snapshot_bytes, MAX_CLOSING_SNAPSHOT_BYTES),
        (
            COLLECTION_OBSERVATION_BEFORE_FILENAME,
            before_bytes,
            MAX_CLOSING_PROOF_BYTES,
        ),
        (
            COLLECTION_OBSERVATION_AFTER_FILENAME,
            after_bytes,
            MAX_CLOSING_PROOF_BYTES,
        ),
        (AUTHORITY_COLLECTION_FILENAME, manifest_bytes, MAX_ASSEMBLY_CONFIG_BYTES),
    )
    for name, data, maximum_bytes in objects:
        if not data or len(data) > maximum_bytes:
            raise AvailabilityWorkflowError("authority_collection_object_size_limit")
        _write_new_private_file(root / name, data)
    _fsync_directory(root)


def _write_new_private_file(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("authority evidence write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _paths_overlap(state: Path, inputs: Sequence[Path]) -> bool:
    state = state.expanduser().absolute()
    for item in inputs:
        value = item.expanduser().absolute()
        if state == value or state in value.parents or value in state.parents:
            return True
    return False


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _absolute_normal_path(value: str, label: str) -> Path:
    path = Path(value)
    if not path.is_absolute() or path != Path(os.path.normpath(path)):
        raise ValueError(f"{label} path must be absolute and lexically normalized")
    return path


def _opaque_id(value: str, label: str) -> None:
    if len(base64url_decode(value)) != 16:
        raise ValueError(f"{label} must encode exactly 16 bytes")


def _print_error(reason_code: str, *, check: bool) -> None:
    print(
        canonical_json_bytes(
            {
                "reason_code": reason_code,
                "status": "blocked",
                "state_mutated": False if check else None,
                "state_mutation_possible": not check,
                "broadcast_performed": False,
                "translation_weights_active": False,
                "weight_submission_capability": False,
            }
        ).decode("utf-8"),
        file=sys.stderr,
    )


def main() -> None:
    raise SystemExit(run())


__all__ = [
    "ANNOUNCEMENT_PROOF_FILENAME",
    "ANNOUNCEMENT_SET_FILENAME",
    "ASSEMBLY_CONFIG_SCHEMA",
    "AUTHORITY_COLLECTION_FILENAME",
    "AUTHORITY_COLLECTION_SCHEMA",
    "COLLECTION_OBSERVATION_AFTER_FILENAME",
    "COLLECTION_OBSERVATION_BEFORE_FILENAME",
    "QUALIFICATION_AUTHORITY_CONFIG_SCHEMA",
    "AuthorityCollectionManifest",
    "AvailabilityAssemblyConfig",
    "BatchArtifactPath",
    "QualificationAuthorityConfig",
    "VideoArtifactPath",
    "main",
    "run",
]


if __name__ == "__main__":  # pragma: no cover - exercised through the installed entry point
    main()
