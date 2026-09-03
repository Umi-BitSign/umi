from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass, replace
from pathlib import Path
from types import SimpleNamespace

import bittensor as bt
import httpx
import pytest

from umi.chain_evidence import FinalizedSnapshotRef
from umi.config import Limits
from umi.crypto import seal_response, sign_response_digest
from umi.encoding import account_id32
from umi.miner import RESPONSE_SIGNATURE_HEADER
from umi.policy import ScoringPolicy, scoring_policy_hash
from umi.protocol import (
    PROTOCOL_VERSION,
    RESPONSE_ENVELOPE_SCHEMA,
    RESPONSE_TLE_PROFILE,
    ResponseEnvelope,
    TranslationRequest,
    canonical_json_bytes,
    request_digest,
)
from umi.resources import ResourceLimitExceeded
from umi.validator import prepare_request_attempt
from umi.validator_assignments import (
    WINDOW_SCHEMA,
    AttemptOutcomeInput,
    TranscriptWindowSpec,
    ValidatorAssignmentStore,
)
from umi.validator_journal import StageObjectInput, ValidatorStageJournal
from umi.validator_pool_effect import (
    POOL_SELECTION_EVIDENCE_SCHEMA,
    PoolEvidenceObjectRef,
    PoolSelectionEvidence,
    SelectedCandidateEvidence,
    SelectedMinerEvidence,
    SelectedVideoDeliveryEvidence,
)
from umi.validator_state import (
    ControlState,
    PauseScope,
    StageEvidence,
    StageWorkItem,
    WindowPlan,
    WindowRecord,
    WindowStage,
)
from umi.validator_transcript_effects import (
    TranscriptAssignment,
    TranscriptEffectPending,
    TranscriptExecutionPlan,
)
from umi.validator_transcript_ports import (
    BoundedHttpTranscriptTransport,
    DurableBtauthNonceStore,
    DurableTranscriptResourceStore,
    FinalizedTranscriptObservationPort,
    LiveBtauthAttemptPort,
    ObservedScheduleAuditReleasePort,
    ReceiptReplayTranscriptResourceBaseline,
    SignedValidatorCapacityStatement,
    TranscriptPortBindingError,
    TranscriptPreflightPlanPort,
    TranscriptResourceBaseline,
    TranscriptResourceDerivationEvidence,
    TranscriptResourceStoreError,
    ValidatorCapacitySetEvidence,
    ValidatorCapacityStatement,
    ValidatorResourceCapacities,
    VerifiedTranscriptResourceBaseline,
    VerifiedValidatorCapacitySet,
    validator_capacity_set_root,
)
from umi.validator_weight_build_effect import WeightScheduleCapture
from umi.validator_weight_schedule import WeightScheduleIdentity
from umi.validator_window_material import ValidatorWindowMaterialStore
from umi.window import quicknet_round_at_ms

from .factories import challenge_request, dev_wallet
from .test_shadow import _fixture
from .test_validator_anchor_composition import _attested_block, _rounds
from .test_validator_assignments import _outer_invalid
from .test_validator_weight_build_effect import _policy, _schedule

VALIDATOR_WALLET = dev_wallet("//Validator0")
VALIDATOR = VALIDATOR_WALLET.hotkey.ss58_address
MINER_WALLET = dev_wallet("//Bob")
MINER = MINER_WALLET.hotkey.ss58_address
SOURCE = b"proof-bound-pool-selection-evidence"
METER = b"signed-policy-pinned-pool-resource-meter"


def _capacity_policy_and_set() -> tuple[ScoringPolicy, VerifiedValidatorCapacitySet]:
    policy = _policy()
    wallets = [dev_wallet(f"//Validator{index}") for index in range(4)]
    wallet_by_account = {wallet.hotkey.ss58_address: wallet for wallet in wallets}
    signed = []
    for entry in policy.validator_registry:
        statement = ValidatorCapacityStatement(
            schema="umi-validator-capacity/1",
            validator_hotkey=entry.validator_hotkey,
            hardware_class="mac-studio-m4-ultra",
            region_class="operator-premises-us-east",
            meter_adapter_version="umi-resource-meter-test@sha256:" + "11" * 32,
            capacities=ValidatorResourceCapacities(
                cpu_core_milliseconds_per_window=100_000_000,
                accelerator_milliseconds_per_window=0,
                peak_host_memory_bytes=256 * 1024 * 1024 * 1024,
                peak_accelerator_memory_bytes=0,
                retained_storage_bytes=8 * 1024 * 1024 * 1024,
            ),
        )
        digest = hashlib.sha256(
            b"umi-validator-capacity-v1\0" + canonical_json_bytes(statement)
        ).digest()
        signature = bytes(wallet_by_account[entry.validator_hotkey].hotkey.sign(digest))
        signed.append(
            SignedValidatorCapacityStatement(
                statement=statement,
                signature_scheme="sr25519",
                signature="0x" + signature.hex(),
            )
        )
    signed.sort(key=lambda item: account_id32(item.statement.validator_hotkey))
    evidence = ValidatorCapacitySetEvidence(
        schema="umi-validator-capacity-set-evidence/1",
        protocol=PROTOCOL_VERSION,
        statements=signed,
    )
    policy = policy.model_copy(
        update={"validator_capacity_set_root": validator_capacity_set_root(evidence)}
    )
    return policy, VerifiedValidatorCapacitySet(policy, canonical_json_bytes(evidence))


@dataclass(frozen=True)
class TranscriptEnvironment:
    policy: ScoringPolicy
    material_store: ValidatorWindowMaterialStore
    journal: ValidatorStageJournal
    plan: TranscriptExecutionPlan
    work: StageWorkItem
    stored: object
    pool_object_bytes: int


def _request(policy_hash: str, reveal_round: int) -> TranslationRequest:
    value = challenge_request(1, reveal_round=reveal_round).model_dump(
        mode="json",
        by_alias=True,
    )
    value["scoring_policy_hash"] = policy_hash
    return TranslationRequest.model_validate(value)


def _environment(
    root: Path,
    *,
    stage: WindowStage = WindowStage.ASSIGNMENT,
    reveal_round: int | None = None,
) -> TranscriptEnvironment:
    policy = _policy()
    policy_hash = scoring_policy_hash(policy)
    reveal = reveal_round or bt.timelock.current_round() + 100
    prepared = prepare_request_attempt(
        _request(policy_hash, reveal),
        wallet=VALIDATOR_WALLET,
        miner_hotkey=MINER,
        nonce_ns=10_000,
    )
    assignment = TranscriptAssignment(prepared, "https://miner.example")
    limits = policy.limits
    plan = TranscriptExecutionPlan(
        spec=TranscriptWindowSpec(
            schema=WINDOW_SCHEMA,
            protocol=PROTOCOL_VERSION,
            window_id=prepared.request.window_id,
            validator_hotkey=VALIDATOR,
            expected_assignment_count=1,
            maximum_request_transmissions_per_assignment=(
                limits.maximum_request_transmissions_per_assignment
            ),
            issue_close_round=reveal - 3,
            response_close_round=reveal - 2,
            reveal_round=reveal,
            maximum_request_body_bytes=limits.maximum_request_body_bytes,
            maximum_response_body_bytes=limits.maximum_response_body_bytes,
            maximum_retained_prefix_bytes=limits.maximum_response_body_bytes,
        ),
        assignments=(assignment,),
    )
    window = WindowPlan(
        window_id=plan.spec.window_id,
        window_index=7,
        scoring_policy_hash=policy_hash,
        announcement_block=1_000,
        proposal_close_block=1_030,
        closing_block=1_045,
        selection_round=reveal - 10,
        issue_close_round=plan.spec.issue_close_round,
        response_close_round=plan.spec.response_close_round,
        reveal_round=plan.spec.reveal_round,
    )
    material_store = ValidatorWindowMaterialStore(root / "material")
    stored = material_store.put(
        window,
        plan,
        source_evidence_sha256=hashlib.sha256(SOURCE).hexdigest(),
    )
    journal = ValidatorStageJournal(root / "journal")
    pool_record = journal.record(
        window_id=window.window_id,
        stage=WindowStage.POOL_AND_SELECTION,
        operation_id=f"umi-stage-v1/{window.window_id}/pool_and_selection",
        objects=(
            StageObjectInput(SOURCE, "application/octet-stream"),
            StageObjectInput(stored.material_bytes, "application/json"),
            StageObjectInput(stored.receipt_bytes, "application/json"),
        ),
        metadata={"source": "test-proof-bound-pool"},
    )
    material_store.attach_pool_stage_receipt(window.window_id, pool_record.receipt_bytes)
    work = StageWorkItem(
        window=WindowRecord(
            plan=window,
            stage=stage,
            terminal_outcome=None,
            terminal_reason_code=None,
            terminal_evidence_sha256=None,
            audit_release_block=None,
            created_at_unix_ns=1,
            updated_at_unix_ns=1,
            revision=1,
        ),
        completed_evidence=(
            StageEvidence(
                window_id=window.window_id,
                stage=WindowStage.POOL_AND_SELECTION,
                evidence_sha256=pool_record.evidence_sha256,
                recorded_at_unix_ns=1,
            ),
        ),
        controls=(
            ControlState(PauseScope.WINDOW_INTAKE, ()),
            ControlState(PauseScope.WEIGHT_SUBMISSION, ()),
        ),
    )
    return TranscriptEnvironment(
        policy=policy,
        material_store=material_store,
        journal=journal,
        plan=plan,
        work=work,
        stored=material_store.load_for_work(work),
        pool_object_bytes=sum(item.size_bytes for item in pool_record.receipt.objects),
    )


def _object_ref(data: bytes, media_type: str) -> PoolEvidenceObjectRef:
    return PoolEvidenceObjectRef(
        sha256=hashlib.sha256(data).hexdigest(),
        media_type=media_type,
        size_bytes=len(data),
    )


def _receipt_resource_environment(
    root: Path,
    policy: ScoringPolicy,
) -> TranscriptEnvironment:
    rehearsal, _signers = _fixture()
    template = rehearsal.batch_artifacts[0].public_manifest
    policy_hash = scoring_policy_hash(policy)
    publisher = policy.publisher_registry[0]
    manifest = template.model_copy(
        update={
            "publisher_hotkey": publisher.publisher_hotkey,
            "scoring_policy_hash": policy_hash,
        }
    )
    manifest_bytes = canonical_json_bytes(manifest)
    request = TranslationRequest.model_validate(
        {
            "protocol": PROTOCOL_VERSION,
            "window_id": manifest.window_id,
            "batch_id": manifest.batch_id,
            "challenge_id": manifest.items[0].challenge_id,
            "issued_block": 1_046,
            "issued_block_hash": "0x" + "31" * 32,
            "deadline_block": 1_056,
            "response_close_round": manifest.response_close_round,
            "reveal_round": manifest.reveal_round,
            "video": {
                "url": "https://objects.example/selected-video",
                "sha256": manifest.items[0].media.sha256,
                "size_bytes": manifest.items[0].media.size_bytes,
                "media_type": "video/mp4",
            },
            "task": {
                "source_language": "ase",
                "target_language": "en",
                "stratum": manifest.items[0].stratum,
            },
            "scoring_policy_hash": policy_hash,
        }
    )
    prepared = prepare_request_attempt(
        request,
        wallet=VALIDATOR_WALLET,
        miner_hotkey=MINER,
        nonce_ns=10_000,
    )
    assignment = TranscriptAssignment(prepared, "https://miner.example")
    limits = policy.limits
    plan = TranscriptExecutionPlan(
        spec=TranscriptWindowSpec(
            schema=WINDOW_SCHEMA,
            protocol=PROTOCOL_VERSION,
            window_id=request.window_id,
            validator_hotkey=VALIDATOR,
            expected_assignment_count=1,
            maximum_request_transmissions_per_assignment=(
                limits.maximum_request_transmissions_per_assignment
            ),
            issue_close_round=request.response_close_round - 1,
            response_close_round=request.response_close_round,
            reveal_round=request.reveal_round,
            maximum_request_body_bytes=limits.maximum_request_body_bytes,
            maximum_response_body_bytes=limits.maximum_response_body_bytes,
            maximum_retained_prefix_bytes=limits.maximum_response_body_bytes,
        ),
        assignments=(assignment,),
    )
    window = WindowPlan(
        window_id=request.window_id,
        window_index=7,
        scoring_policy_hash=policy_hash,
        announcement_block=1_000,
        proposal_close_block=1_030,
        closing_block=1_045,
        selection_round=request.response_close_round - 10,
        issue_close_round=request.response_close_round - 1,
        response_close_round=request.response_close_round,
        reveal_round=request.reveal_round,
    )
    source_values = (
        (canonical_json_bytes({"kind": "announcement-validator-snapshot"}), "application/json"),
        (canonical_json_bytes({"kind": "announcement-validator-proof"}), "application/json"),
        (canonical_json_bytes({"kind": "closing-snapshot"}), "application/json"),
        (b"closing-proof", "application/octet-stream"),
        (b"artifact-retrieval-proof", "application/octet-stream"),
        (canonical_json_bytes({"kind": "mirror-discovery"}), "application/json"),
        (canonical_json_bytes({"kind": "mirror-readiness-set"}), "application/json"),
        (canonical_json_bytes({"kind": "delivery-request"}), "application/json"),
        (canonical_json_bytes({"kind": "delivery-response"}), "application/json"),
        (canonical_json_bytes({"kind": "delivery-evidence"}), "application/json"),
        (canonical_json_bytes({"kind": "selection-pulse"}), "application/json"),
        (canonical_json_bytes(policy), "application/json"),
        (canonical_json_bytes({"kind": "prior-protocol-state"}), "application/json"),
        (b"issuance-finality", "application/octet-stream"),
        (canonical_json_bytes({"kind": "final-pool"}), "application/json"),
        (manifest_bytes, "application/json"),
        (b"ground-truth-envelope", "application/octet-stream"),
    )
    refs = tuple(_object_ref(data, media_type) for data, media_type in source_values)
    (
        announcement_validator_ref,
        announcement_validator_proof_ref,
        closing_ref,
        closing_proof_ref,
        retrieval_ref,
        discovery_ref,
        readiness_ref,
        delivery_request_ref,
        delivery_response_ref,
        delivery_evidence_ref,
        pulse_ref,
        policy_ref,
        prior_state_ref,
        issuance_ref,
        final_pool_ref,
        public_ref,
        ground_truth_ref,
    ) = refs
    selection = PoolSelectionEvidence(
        schema=POOL_SELECTION_EVIDENCE_SCHEMA,
        protocol=PROTOCOL_VERSION,
        window_id=window.window_id,
        window_index=window.window_index,
        scoring_policy_hash=policy_hash,
        validator_hotkey=VALIDATOR,
        announcement_validator_snapshot=announcement_validator_ref,
        announcement_validator_proof_evidence=announcement_validator_proof_ref,
        closing_snapshot=closing_ref,
        closing_proof_evidence=closing_proof_ref,
        artifact_retrieval_evidence=retrieval_ref,
        mirror_discovery_rule=discovery_ref,
        mirror_readiness_set=readiness_ref,
        delivery_issuance_request=delivery_request_ref,
        delivery_issuance_response=delivery_response_ref,
        delivery_issuance_evidence=delivery_evidence_ref,
        selection_pulse=pulse_ref,
        selection_pulse_evidence_digest="41" * 32,
        policy_object=policy_ref,
        prior_protocol_state=prior_state_ref,
        protocol_state_digest="42" * 32,
        prior_spent_root="43" * 32,
        prior_publisher_fault_root="44" * 32,
        candidate_pool_root="45" * 32,
        selection_seed="46" * 32,
        candidates=[
            SelectedCandidateEvidence(
                publisher_hotkey=publisher.publisher_hotkey,
                control_group_id=publisher.control_group_id,
                batch_id=manifest.batch_id,
                batch_commitment="47" * 32,
                pool_leaf="48" * 32,
                batch_rank="49" * 32,
                selection_ordinal=0,
                final_pool_manifest=final_pool_ref,
                public_manifest=public_ref,
                ground_truth_envelope=ground_truth_ref,
            )
        ],
        selected_panel=[
            SelectedMinerEvidence(
                panel_ordinal=0,
                uid=1,
                hotkey=MINER,
                root=MINER,
                serving_url="https://miner.example",
                assigned_observation_count=0,
                miner_rank="50" * 32,
            )
        ],
        selected_video_deliveries=[
            SelectedVideoDeliveryEvidence(
                batch_id=manifest.batch_id,
                challenge_id=manifest.items[0].challenge_id,
                url="https://objects.example/selected-video",
                sha256=manifest.items[0].media.sha256,
                size_bytes=manifest.items[0].media.size_bytes,
                expires_at_unix_ms=10**15,
            )
        ],
        issuance_block=1_046,
        issuance_block_hash="0x" + "31" * 32,
        issuance_finality_evidence=issuance_ref,
        assignment_ids=[assignment.assignment_id],
        source_objects=sorted(refs, key=lambda item: bytes.fromhex(item.sha256)),
    )
    selection_bytes = canonical_json_bytes(selection)
    material_store = ValidatorWindowMaterialStore(root / "material")
    stored = material_store.put(
        window,
        plan,
        source_evidence_sha256=hashlib.sha256(selection_bytes).hexdigest(),
    )
    journal = ValidatorStageJournal(root / "journal")
    pool_record = journal.record(
        window_id=window.window_id,
        stage=WindowStage.POOL_AND_SELECTION,
        operation_id=f"umi-stage-v1/{window.window_id}/pool_and_selection",
        objects=(
            StageObjectInput(selection_bytes, "application/json"),
            StageObjectInput(stored.material_bytes, "application/json"),
            StageObjectInput(stored.receipt_bytes, "application/json"),
            *(StageObjectInput(data, media_type) for data, media_type in source_values),
        ),
        metadata={"source": "receipt-resource-test"},
    )
    material_store.attach_pool_stage_receipt(window.window_id, pool_record.receipt_bytes)
    work = StageWorkItem(
        window=WindowRecord(
            plan=window,
            stage=WindowStage.ASSIGNMENT,
            terminal_outcome=None,
            terminal_reason_code=None,
            terminal_evidence_sha256=None,
            audit_release_block=None,
            created_at_unix_ns=1,
            updated_at_unix_ns=1,
            revision=1,
        ),
        completed_evidence=(
            StageEvidence(
                window_id=window.window_id,
                stage=WindowStage.POOL_AND_SELECTION,
                evidence_sha256=pool_record.evidence_sha256,
                recorded_at_unix_ns=1,
            ),
        ),
        controls=(
            ControlState(PauseScope.WINDOW_INTAKE, ()),
            ControlState(PauseScope.WEIGHT_SUBMISSION, ()),
        ),
    )
    return TranscriptEnvironment(
        policy=policy,
        material_store=material_store,
        journal=journal,
        plan=plan,
        work=work,
        stored=material_store.load_for_work(work),
        pool_object_bytes=sum(item.size_bytes for item in pool_record.receipt.objects),
    )


def _baseline(
    environment: TranscriptEnvironment,
    *,
    retained_capacity: int = 1024 * 1024 * 1024,
    material_sha256: str | None = None,
) -> VerifiedTranscriptResourceBaseline:
    stored = environment.stored
    baseline = TranscriptResourceBaseline(
        schema="umi-validator-transcript-resource-baseline/1",
        protocol=PROTOCOL_VERSION,
        window_id=environment.plan.spec.window_id,
        scoring_policy_hash=scoring_policy_hash(environment.policy),
        window_material_sha256=material_sha256 or stored.receipt.material_sha256,
        window_material_receipt_sha256=stored.receipt_sha256,
        pool_stage_evidence_sha256=stored.pool_stage_evidence_sha256,
        shared_artifact_wire_bytes=environment.pool_object_bytes,
        retained_object_bytes=environment.pool_object_bytes,
        audit_manifest_bytes=4_096,
        audit_object_bytes=environment.pool_object_bytes,
        retained_storage_capacity=retained_capacity,
        signed_meter_evidence_sha256=hashlib.sha256(METER).hexdigest(),
    )
    return VerifiedTranscriptResourceBaseline(
        baseline=baseline,
        baseline_bytes=canonical_json_bytes(baseline),
        signed_meter_evidence_bytes=METER,
    )


async def _preflight(
    environment: TranscriptEnvironment,
    root: Path,
    *,
    baseline: VerifiedTranscriptResourceBaseline | None = None,
) -> DurableTranscriptResourceStore:
    resources = DurableTranscriptResourceStore(root)
    expected = baseline or _baseline(environment)

    async def load_baseline(_work, _material):
        return expected

    port = TranscriptPreflightPlanPort(
        policy=environment.policy,
        material_store=environment.material_store,
        journal=environment.journal,
        baseline=load_baseline,
        resources=resources,
    )
    loaded = await port(environment.work)
    assert loaded.plan == environment.plan
    return resources


async def test_resource_preflight_and_ledger_are_restart_stable(tmp_path: Path) -> None:
    environment = _environment(tmp_path / "environment")
    root = tmp_path / "resources"
    resources = await _preflight(environment, root)
    ledger = resources.ledger(environment.plan.spec.window_id)
    assignment_id = environment.plan.assignments[0].assignment_id
    initial = environment.pool_object_bytes

    assert ledger.snapshot().window_wire_bytes == initial
    assert ledger.begin_attempt(f"request:{assignment_id}", maximum_attempts=2) == 1
    ledger.charge(123, assignment_id=assignment_id)

    restarted = DurableTranscriptResourceStore(root)
    snapshot = restarted.ledger(environment.plan.spec.window_id).snapshot()
    assert snapshot.window_wire_bytes == initial + 123
    assert snapshot.assignment_wire_bytes == ((assignment_id, 123),)
    assert snapshot.attempts == ((f"request:{assignment_id}", 1),)

    # Preflight replay after bytes have been charged validates immutable inputs
    # without resetting or conflicting with the durable counter.
    await _preflight(environment, root)
    assert (
        DurableTranscriptResourceStore(root).ledger(environment.plan.spec.window_id).snapshot()
        == snapshot
    )


async def test_preflight_rejects_capacity_and_binding_tamper(tmp_path: Path) -> None:
    environment = _environment(tmp_path / "environment")
    with pytest.raises(ResourceLimitExceeded, match="retained"):
        await _preflight(
            environment,
            tmp_path / "small",
            baseline=_baseline(
                environment,
                retained_capacity=environment.pool_object_bytes,
            ),
        )
    with pytest.raises(TranscriptPortBindingError, match="resource_baseline_binding_mismatch"):
        await _preflight(
            environment,
            tmp_path / "wrong-binding",
            baseline=_baseline(environment, material_sha256="ff" * 32),
        )


def test_validator_capacity_set_verifies_registry_signatures_and_policy_root() -> None:
    policy, capacity_set = _capacity_policy_and_set()

    assert capacity_set.policy_hash == scoring_policy_hash(policy)
    assert validator_capacity_set_root(capacity_set.evidence) == (
        policy.validator_capacity_set_root
    )
    assert capacity_set.statement_for(VALIDATOR).validator_hotkey == VALIDATOR

    values = capacity_set.evidence.model_dump(mode="json", by_alias=True)
    values["statements"][0]["signature"] = "0x" + "00" * 64
    with pytest.raises(
        TranscriptPortBindingError,
        match="validator_capacity_signature_invalid",
    ):
        VerifiedValidatorCapacitySet(
            policy,
            canonical_json_bytes(ValidatorCapacitySetEvidence.model_validate(values)),
        )

    wrong_root = policy.model_copy(update={"validator_capacity_set_root": "ff" * 32})
    with pytest.raises(
        TranscriptPortBindingError,
        match="validator_capacity_set_root_mismatch",
    ):
        VerifiedValidatorCapacitySet(wrong_root, capacity_set.evidence_bytes)


async def test_receipt_resource_baseline_is_exact_restart_replay(
    tmp_path: Path,
) -> None:
    policy, capacity_set = _capacity_policy_and_set()
    environment = _receipt_resource_environment(tmp_path / "environment", policy)
    baseline_port = ReceiptReplayTranscriptResourceBaseline(
        policy=policy,
        validator_hotkey=VALIDATOR,
        material_store=environment.material_store,
        journal=environment.journal,
        capacity_set=capacity_set,
    )

    first = baseline_port(environment.work, environment.stored)
    derivation = TranscriptResourceDerivationEvidence.model_validate_json(
        first.signed_meter_evidence_bytes
    )
    manifest = _fixture()[0].batch_artifacts[0].public_manifest
    expected_video_bytes = sum(item.media.size_bytes for item in manifest.items)
    assert derivation.capacity_set_sha256 == capacity_set.evidence_sha256
    assert derivation.raw_video_count == len(manifest.items)
    assert derivation.raw_video_bytes == expected_video_bytes
    assert derivation.pool_object_bytes == environment.pool_object_bytes
    assert derivation.retained_object_bytes >= derivation.pool_object_bytes
    assert derivation.shared_artifact_wire_bytes > derivation.pool_object_bytes
    assert first.baseline.retained_storage_capacity == (
        capacity_set.statement_for(VALIDATOR).capacities.retained_storage_bytes
    )

    restarted_material = ValidatorWindowMaterialStore(environment.material_store.root)
    restarted_journal = ValidatorStageJournal(environment.journal.root)
    restarted = ReceiptReplayTranscriptResourceBaseline(
        policy=policy,
        validator_hotkey=VALIDATOR,
        material_store=restarted_material,
        journal=restarted_journal,
        capacity_set=VerifiedValidatorCapacitySet(
            policy,
            capacity_set.evidence_bytes,
        ),
    )
    restarted_stored = restarted_material.load_for_work(environment.work)
    second = restarted(environment.work, restarted_stored)
    assert second.baseline_bytes == first.baseline_bytes
    assert second.signed_meter_evidence_bytes == first.signed_meter_evidence_bytes

    resources = DurableTranscriptResourceStore(tmp_path / "resources")
    preflight = TranscriptPreflightPlanPort(
        policy=policy,
        material_store=restarted_material,
        journal=restarted_journal,
        baseline=restarted,
        resources=resources,
    )
    loaded = await preflight(environment.work)
    assert loaded.plan == environment.plan
    receipt = resources.preflight_receipt(environment.plan.spec.window_id)
    assert receipt.signed_meter_evidence_sha256 == (first.baseline.signed_meter_evidence_sha256)


def test_receipt_resource_baseline_rejects_argument_and_pool_object_tamper(
    tmp_path: Path,
) -> None:
    policy, capacity_set = _capacity_policy_and_set()
    environment = _receipt_resource_environment(tmp_path / "environment", policy)
    baseline_port = ReceiptReplayTranscriptResourceBaseline(
        policy=policy,
        validator_hotkey=VALIDATOR,
        material_store=environment.material_store,
        journal=environment.journal,
        capacity_set=capacity_set,
    )

    foreign = _environment(tmp_path / "foreign").stored
    with pytest.raises(
        TranscriptPortBindingError,
        match="resource_material_argument_mismatch",
    ):
        baseline_port(environment.work, foreign)

    record = environment.journal.load(
        environment.plan.spec.window_id,
        WindowStage.POOL_AND_SELECTION,
    )
    public_ref = next(
        reference
        for reference in record.receipt.objects
        if environment.journal.read_object(reference).startswith(b'{"batch_id"')
    )
    object_path = environment.journal.root / "objects" / public_ref.sha256
    object_path.write_bytes(b"tampered")
    with pytest.raises(ValueError, match="wrong byte length"):
        baseline_port(environment.work, environment.stored)


async def test_resource_database_tamper_fails_closed(tmp_path: Path) -> None:
    environment = _environment(tmp_path / "environment")
    root = tmp_path / "resources"
    resources = await _preflight(environment, root)
    with sqlite3.connect(resources.database_path) as connection:
        connection.execute(
            "UPDATE windows SET baseline_bytes = ? WHERE window_id = ?",
            (b"{}", environment.plan.spec.window_id),
        )
    with pytest.raises(TranscriptResourceStoreError, match="resource_baseline_invalid"):
        DurableTranscriptResourceStore(root)


async def test_attempt_ceiling_remains_enforced_after_restart(tmp_path: Path) -> None:
    environment = _environment(tmp_path / "environment")
    root = tmp_path / "resources"
    resources = await _preflight(environment, root)
    assignment_id = environment.plan.assignments[0].assignment_id
    key = f"request:{assignment_id}"
    assert (
        resources.ledger(environment.plan.spec.window_id).begin_attempt(
            key,
            maximum_attempts=2,
        )
        == 1
    )
    assert (
        DurableTranscriptResourceStore(root)
        .ledger(environment.plan.spec.window_id)
        .begin_attempt(key, maximum_attempts=2)
        == 2
    )
    with pytest.raises(ResourceLimitExceeded, match="attempt ceiling"):
        DurableTranscriptResourceStore(root).ledger(environment.plan.spec.window_id).begin_attempt(
            key, maximum_attempts=2
        )


async def test_http_transport_retains_oversize_receipt_and_rejects_origin_drift(
    tmp_path: Path,
) -> None:
    environment = _environment(tmp_path / "environment")
    resources = await _preflight(environment, tmp_path / "resources")
    prepared = environment.plan.assignments[0].initial_attempt
    assignment_id = environment.plan.assignments[0].assignment_id
    maximum = environment.policy.limits.maximum_response_body_bytes

    async def respond(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-length": str(maximum + 1)},
            content=b"",
        )

    port = BoundedHttpTranscriptTransport(
        policy=environment.policy,
        material_store=environment.material_store,
        resources=resources,
        timeout_seconds=1.0,
        transport=httpx.MockTransport(respond),
        allow_in_process_transport=True,
    )
    outcome = await port(
        prepared,
        assignment_id,
        "https://miner.example",
        environment.work,
    )
    assert outcome.failure_code == "resource_limit"
    assert outcome.envelope_bytes is None
    assert outcome.received_body_prefix == b""
    assert outcome.received_bytes_sha256 == hashlib.sha256(b"").hexdigest()
    attempts = dict(resources.ledger(environment.plan.spec.window_id).snapshot().attempts)
    assert attempts[f"request:{assignment_id}"] == 1
    assert attempts[f"response:{assignment_id}"] == 1

    with pytest.raises(TranscriptPortBindingError, match="http_transport_material_mismatch"):
        await port(
            prepared,
            assignment_id,
            "https://changed-origin.example",
            environment.work,
        )


def test_http_transport_derives_every_protocol_limit_from_policy(tmp_path: Path) -> None:
    environment = _environment(tmp_path / "environment")
    custom_limits = environment.policy.limits.model_copy(
        update={
            "maximum_hypothesis_tokens": 257,
            "maximum_hypothesis_graphemes": 1_025,
            "maximum_request_transmissions_per_assignment": 3,
            "maximum_response_bodies_per_assignment": 4,
            "maximum_video_fetch_attempts_per_actor": 5,
            "maximum_assignment_wire_bytes": 35 * 1024 * 1024,
        }
    )
    custom_policy = environment.policy.model_copy(update={"limits": custom_limits})

    port = BoundedHttpTranscriptTransport(
        policy=custom_policy,
        material_store=environment.material_store,
        resources=DurableTranscriptResourceStore(tmp_path / "resources"),
        timeout_seconds=1.0,
    )

    assert port.limits == Limits.from_policy(custom_policy)
    assert port.limits.maximum_hypothesis_tokens == 257
    assert port.limits.maximum_hypothesis_graphemes == 1_025
    assert port.limits.maximum_request_transmissions_per_assignment == 3
    assert port.limits.maximum_response_bodies_per_assignment == 4
    assert port.limits.maximum_video_fetch_attempts_per_actor == 5
    assert port.limits.maximum_assignment_wire_bytes == 35 * 1024 * 1024


async def test_http_transport_preserves_validator_bound_encrypted_response(
    tmp_path: Path,
) -> None:
    environment = _environment(tmp_path / "environment")
    resources = await _preflight(environment, tmp_path / "resources")
    prepared = environment.plan.assignments[0].initial_attempt
    sealed = seal_response(b'{"status":"ok"}', reveal_round=prepared.request.reveal_round)
    envelope = ResponseEnvelope.model_validate(
        {
            "schema": RESPONSE_ENVELOPE_SCHEMA,
            "protocol": PROTOCOL_VERSION,
            "window_id": prepared.request.window_id,
            "batch_id": prepared.request.batch_id,
            "challenge_id": prepared.request.challenge_id,
            "request_digest": request_digest(prepared.request),
            "issued_block_hash": prepared.request.issued_block_hash,
            "validator_hotkey": prepared.validator_hotkey,
            "serving_hotkey": prepared.miner_hotkey,
            "response_tle_profile": RESPONSE_TLE_PROFILE,
            "response_reveal_round": prepared.request.reveal_round,
            "encrypted_response": sealed.portable_b64,
            "encrypted_response_sha256": sealed.sha256_hex,
            "signature_scheme": "sr25519",
        }
    )
    scheme, signature = sign_response_digest(MINER_WALLET, envelope)
    assert scheme == "sr25519"
    body = canonical_json_bytes(envelope)

    class ResponseStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield body

    async def respond(request: httpx.Request) -> httpx.Response:
        assert await request.aread() == prepared.request_bytes
        return httpx.Response(
            200,
            headers={
                "Content-Length": str(len(body)),
                RESPONSE_SIGNATURE_HEADER: signature,
            },
            stream=ResponseStream(),
        )

    port = BoundedHttpTranscriptTransport(
        policy=environment.policy,
        material_store=environment.material_store,
        resources=resources,
        timeout_seconds=1.0,
        transport=httpx.MockTransport(respond),
        allow_in_process_transport=True,
    )
    outcome = await port(
        prepared,
        environment.plan.assignments[0].assignment_id,
        "https://miner.example",
        environment.work,
    )
    assert outcome.failure_code is None
    assert outcome.envelope == envelope
    assert outcome.envelope_bytes == body
    assert outcome.sealed_response == sealed
    assert outcome.request == prepared.request


async def test_http_transport_closed_window_returns_bounded_late_without_sending(
    tmp_path: Path,
) -> None:
    environment = _environment(
        tmp_path / "environment",
        reveal_round=bt.timelock.current_round(),
    )
    resources = await _preflight(environment, tmp_path / "resources")
    calls = 0

    async def should_not_send(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(500)

    port = BoundedHttpTranscriptTransport(
        policy=environment.policy,
        material_store=environment.material_store,
        resources=resources,
        timeout_seconds=1.0,
        transport=httpx.MockTransport(should_not_send),
        allow_in_process_transport=True,
    )
    assignment = environment.plan.assignments[0]
    outcome = await port(
        assignment.initial_attempt,
        assignment.assignment_id,
        assignment.miner_url,
        environment.work,
    )
    assert calls == 0
    assert outcome.failure_code == "late"
    assert outcome.envelope_bytes is None
    assert outcome.received_body_prefix is None


async def test_btauth_retry_uses_durable_monotonic_nonce_and_exact_request(tmp_path: Path) -> None:
    environment = _environment(
        tmp_path / "environment",
        stage=WindowStage.REQUEST_TRANSCRIPT,
    )
    nonce_root = tmp_path / "nonces"
    nonces = DurableBtauthNonceStore(nonce_root, now_ns=lambda: 100)
    port = LiveBtauthAttemptPort(
        policy=environment.policy,
        validator_hotkey=VALIDATOR,
        wallet=VALIDATOR_WALLET,
        material_store=environment.material_store,
        nonces=nonces,
    )
    assignment = environment.plan.assignments[0]
    store = ValidatorAssignmentStore(tmp_path / "assignments")
    store.create_window(environment.plan.spec)
    first = store.add_assignment(
        environment.plan.spec.window_id,
        assignment.initial_attempt,
        observed_round=environment.plan.spec.issue_close_round - 1,
    )
    store.freeze_assignments(
        environment.plan.spec.window_id,
        observed_round=environment.plan.spec.issue_close_round - 1,
    )
    store.claim_for_send(
        first.assignment_id,
        0,
        operation_id="transcript.test.send.0",
        observed_round=environment.plan.spec.issue_close_round - 1,
    )
    failure = _outer_invalid(
        b"bad",
        recorded_round=environment.plan.spec.response_close_round - 1,
    )
    store.record_outcome(
        first.assignment_id,
        0,
        AttemptOutcomeInput(
            sealed_response_record=failure.sealed_response_record,
            recorded_at_round=environment.plan.spec.response_close_round - 1,
            received_block=105,
            received_round=environment.plan.spec.response_close_round - 1,
            body_or_prefix=b"bad",
        ),
    )
    previous = store.list_attempts(first.assignment_id)[0]

    retry = await port(assignment, previous, 1, environment.work)
    assert retry.request_bytes == assignment.initial_attempt.request_bytes
    assert retry.request == assignment.initial_attempt.request
    assert retry.auth_evidence.auth_record.nonce_int > (
        assignment.initial_attempt.auth_evidence.auth_record.nonce_int
    )
    restarted = DurableBtauthNonceStore(nonce_root, now_ns=lambda: 100)
    assert (
        restarted.next_nonce(
            port.validator_account_id32,
            floor=retry.auth_evidence.auth_record.nonce_int,
        )
        == retry.auth_evidence.auth_record.nonce_int + 1
    )


class _FinalityPort:
    def __init__(self, policy: ScoringPolicy, block) -> None:
        self.scoring_policy_digest = scoring_policy_hash(policy)
        self.chain_observation = policy.implementation_pins.live_chain
        finality = policy.implementation_pins.finality_verifier
        assert finality is not None
        self.finality_verifier_sha256 = finality.release_sha256_by_target["aarch64-apple-darwin"]
        self.block = block
        self.snapshot = FinalizedSnapshotRef(
            block_number=block.height,
            block_hash=block.block_hash,
            parent_hash="0x" + "91" * 32,
            state_root=block.state_root,
        )

    async def verified_finalized_snapshot(self) -> FinalizedSnapshotRef:
        return self.snapshot

    async def verified_block_at(self, height: int):
        return self.block if height == self.block.height else None


async def test_finalized_boundary_observation_is_exact_and_tamper_fails(tmp_path: Path) -> None:
    environment = _environment(tmp_path / "environment")
    block = _attested_block(environment.policy)
    finality = _FinalityPort(environment.policy, block)
    port = FinalizedTranscriptObservationPort(
        policy=environment.policy,
        finality=finality,
        rounds=_rounds(environment.policy, finality),
    )
    result = await port("request_send", environment.work)
    assert result.finalized_block == block.height
    assert result.finalized_block_hash == block.block_hash
    assert result.quicknet_round == quicknet_round_at_ms(block.timestamp_ms)

    finality.snapshot = replace(finality.snapshot, state_root="0x" + "92" * 32)
    with pytest.raises(TranscriptPortBindingError, match="finalized_observation_binding_mismatch"):
        await port("request_send", environment.work)


async def test_audit_release_uses_observed_schedule_and_returns_pending_without_close(
    tmp_path: Path,
) -> None:
    environment = _environment(
        tmp_path / "environment",
        stage=WindowStage.SEALED_RESPONSE,
    )
    capture = _schedule(environment.policy, environment.work)

    async def complete_schedule(_work):
        return capture

    port = ObservedScheduleAuditReleasePort(
        policy=environment.policy,
        schedule=complete_schedule,
    )
    assert await port(environment.work, "transport_timeout") == 163

    async def incomplete_schedule(_work):
        return WeightScheduleCapture(capture.observations[:-1], capture.identity)

    pending = ObservedScheduleAuditReleasePort(
        policy=environment.policy,
        schedule=incomplete_schedule,
    )
    with pytest.raises(TranscriptEffectPending, match="audit_release_"):
        await pending(environment.work, "transport_timeout")

    identity = WeightScheduleIdentity(
        chain_genesis_hash=capture.identity.chain_genesis_hash,
        finality_verifier_sha256="ee" * 32,
        runtime_pin=capture.identity.runtime_pin,
    )

    async def wrong_identity(_work):
        return WeightScheduleCapture(capture.observations, identity)

    with pytest.raises(TranscriptPortBindingError, match="audit_schedule_identity_mismatch"):
        await ObservedScheduleAuditReleasePort(
            policy=environment.policy,
            schedule=wrong_identity,
        )(environment.work, "transport_timeout")


def test_custom_sync_transport_and_shared_state_root_are_rejected(tmp_path: Path) -> None:
    environment = _environment(tmp_path / "environment")
    resources = DurableTranscriptResourceStore(tmp_path / "resources")
    with pytest.raises(TypeError, match="async httpx transport"):
        BoundedHttpTranscriptTransport(
            policy=environment.policy,
            material_store=environment.material_store,
            resources=resources,
            timeout_seconds=1.0,
            transport=SimpleNamespace(),
            allow_in_process_transport=True,
        )
