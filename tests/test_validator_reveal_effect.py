from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import bittensor as bt
import bittensor_core
import pytest

from umi.artifacts import PublicBatchManifest, validate_revealed_batch_shape
from umi.calibration_bundle import (
    CALIBRATION_RECEIPT_MEDIA_TYPE,
    CALIBRATION_STAGE_SCHEMA,
    CalibrationObject,
    CalibrationStageEvidence,
    calibration_stage_replay_hook_id,
)
from umi.crypto import seal_response, sign_response_digest
from umi.drand import DrandPulse
from umi.encoding import account_id32, sha256_domain
from umi.policy import scoring_policy_hash
from umi.protocol import (
    GROUND_TRUTH_SCHEMA,
    PROTOCOL_VERSION,
    RESPONSE_ENVELOPE_SCHEMA,
    RESPONSE_PLAINTEXT_SCHEMA,
    RESPONSE_TLE_PROFILE,
    GroundTruthPayload,
    ResponseEnvelope,
    ResponsePlaintext,
    canonical_json_bytes,
    request_digest,
)
from umi.validator import QueryOutcome
from umi.validator_adapters import (
    CompleteStageEffect,
    JournalStageAdapter,
    TerminalStageEffect,
    stage_operation_id,
)
from umi.validator_assignments import ValidatorAssignmentStore
from umi.validator_extrinsics import ValidatorExtrinsicJournal
from umi.validator_journal import StageObject, StageReceipt, ValidatorStageJournal
from umi.validator_monitoring_state import (
    MonitoringStatePolicy,
    ValidatorMonitoringStateStore,
)
from umi.validator_reveal_effect import (
    REVEAL_AUDIT_RELEASE_SCHEMA,
    REVEAL_RESULT_SCHEMA,
    RevealAuditRelease,
    RevealBindingError,
    RevealEffectPorts,
    RevealTransitionCoordinator,
    ValidatorRevealEffect,
    VerifiedRevealAuditRelease,
    replay_reveal_stage,
    resolve_reveal_receipt,
    resolve_reveal_stage_record,
)
from umi.validator_state import (
    ControlState,
    PauseScope,
    StageEvidence,
    StageWorkItem,
    TerminalOutcome,
    WindowPlan,
    WindowRecord,
    WindowStage,
)
from umi.validator_transcript_effects import (
    AssignmentTranscriptEffect,
    RequestTranscriptEffect,
    SealedResponseTranscriptEffect,
    TranscriptEffectPending,
    TranscriptEffectPorts,
    VerifiedProtocolObservation,
)

from . import test_validator_transcript_effects as transcript_test_support
from .test_shadow import RANDOMNESS, SIGNATURE
from .test_shadow import _fixture as shadow_fixture
from .test_validator_pool_effect import _Fixture as PoolFixture
from .test_validator_transcript_effects import AnchorChain, FactPort


def _controls() -> tuple[ControlState, ...]:
    return tuple(ControlState(scope=scope, active_holds=()) for scope in PauseScope)


def _work(
    window: WindowPlan,
    stage: WindowStage,
    evidence: tuple[StageEvidence, ...],
) -> StageWorkItem:
    return StageWorkItem(
        window=WindowRecord(
            plan=window,
            stage=stage,
            terminal_outcome=None,
            terminal_reason_code=None,
            terminal_evidence_sha256=None,
            audit_release_block=None,
            created_at_unix_ns=1,
            updated_at_unix_ns=1,
            revision=len(evidence),
        ),
        completed_evidence=evidence,
        controls=_controls(),
    )


def _stage_evidence(window_id: str, record) -> StageEvidence:
    return StageEvidence(
        window_id=window_id,
        stage=WindowStage(record.receipt.stage),
        evidence_sha256=record.evidence_sha256,
        recorded_at_unix_ns=1,
    )


class RevealFactPort(FactPort):
    async def __call__(self, boundary, work):
        observed = await super().__call__(boundary, work)
        return VerifiedProtocolObservation(
            finalized_block=work.window.plan.closing_block + 2,
            finalized_block_hash=observed.finalized_block_hash,
            quicknet_round=observed.quicknet_round,
            evidence_bytes=observed.evidence_bytes,
        )


def _ground_truth(public: PublicBatchManifest, policy) -> GroundTruthPayload:
    items = []
    canary_start = len(public.items) - 2
    for index, item in enumerate(public.items):
        script = hashlib.sha256(
            b"reveal-test-script\0"
            + public.batch_id.encode("ascii")
            + item.challenge_id.encode("ascii")
        ).hexdigest()
        canary = index >= canary_start
        if canary:
            reserved = hashlib.sha256(bytes.fromhex(script) + b"reserved").hexdigest()
            if item.stratum == "fingerspelling":
                actual = ["aaaaaaaa", "aaaaaaaaa", "aaaaaaa"]
                mismatch = ["zzzzzzzz", "zzzzzzzzz", "zzzzzzz"]
            else:
                actual = ["hello world", "greetings earth", "good morning"]
                mismatch = ["purple chairs", "zebra quantum", "distant ocean"]
            references = mismatch
            canary_evidence = {
                "actual_references": actual,
                "actual_script_sha256": script,
                "reserved_script_sha256": reserved,
                "mismatched_references": mismatch,
            }
            retirement = sorted((script, reserved))
        else:
            references = ["hello world", "hello, world", "hi world"]
            canary_evidence = None
            retirement = [script]
        items.append(
            {
                "challenge_id": item.challenge_id,
                "metric": "cer" if item.stratum == "fingerspelling" else "wer",
                "canary": canary,
                "references": references,
                "canary_evidence": canary_evidence,
                "normalized_script_sha256": script,
                "retirement_script_sha256s": retirement,
                "consent_manifest_sha256": item.consent_manifest_sha256,
            }
        )
    result = GroundTruthPayload.model_validate(
        {
            "schema": GROUND_TRUTH_SCHEMA,
            "window_id": public.window_id,
            "batch_id": public.batch_id,
            "scoring_policy_hash": public.scoring_policy_hash,
            "tle_profile": "umi-tle/1",
            "response_close_round": public.response_close_round,
            "reveal_round": public.reveal_round,
            "items": items,
        }
    )
    validate_revealed_batch_shape(public, result, policy)
    return result


class Harness:
    def __init__(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self.fixture = PoolFixture(tmp_path)
        monkeypatch.setattr(
            transcript_test_support,
            "VALIDATOR",
            self.fixture.validator_wallet.hotkey.ss58_address,
        )
        self.journal = ValidatorStageJournal(tmp_path / "journal")
        self.evidence: list[StageEvidence] = []
        self.response_plaintexts: dict[str, bytes] = {}
        self.canary_assignment: tuple[str, str, bytes] | None = None
        self.canary_outcome: QueryOutcome | None = None
        self.canary_outcome_assignment_id: str | None = None

        pool_adapter = JournalStageAdapter(
            stage=WindowStage.POOL_AND_SELECTION,
            journal=self.journal,
            effect=self.fixture.effect(),
        )
        self.pool_adapter = pool_adapter
        self.assignments = ValidatorAssignmentStore(tmp_path / "assignments")
        self.extrinsics = ValidatorExtrinsicJournal(tmp_path / "extrinsics")
        self.coordinator = RevealTransitionCoordinator(tmp_path / "reveal.sqlite3")

        publishers = tuple(
            sorted(
                account_id32(item.publisher_hotkey)
                for item in self.fixture.policy.publisher_registry
            )
        )
        groups = tuple(
            sorted(
                bytes.fromhex(item.control_group_id)
                for item in self.fixture.policy.control_group_registry
            )
        )
        mappings = tuple(
            sorted(
                (
                    account_id32(item.publisher_hotkey),
                    bytes.fromhex(item.control_group_id),
                )
                for item in self.fixture.policy.publisher_registry
            )
        )
        monitoring_policy = MonitoringStatePolicy(
            validator_account_id32=account_id32(self.fixture.validator_wallet.hotkey.ss58_address),
            scoring_policy_hash=bytes.fromhex(self.fixture.window.scoring_policy_hash),
            maximum_batches=self.fixture.policy.limits.publisher_monitoring_batches,
            minimum_clips_per_side_and_stratum=(
                self.fixture.policy.limits.divergence_minimum_clips_per_side_and_stratum
            ),
            alert_threshold=(
                self.fixture.policy.thresholds.source_divergence_alert_threshold.fraction
            ),
            publisher_sources=publishers,
            control_group_sources=groups,
            publisher_control_groups=mappings,
        )
        self.monitoring = ValidatorMonitoringStateStore(
            tmp_path / "monitoring.sqlite3",
            policy=monitoring_policy,
        )

        # The fixture carries a real verified selection pulse.  The later test
        # pulse has the same strict wire shape but no test-only Quicknet secret.
        monkeypatch.setattr(DrandPulse, "verify", lambda _self: None)
        monkeypatch.setattr(bt.timelock, "current_round", lambda: 1)
        self.reveal_pulse = canonical_json_bytes(
            {
                "round": self.fixture.window.reveal_round,
                "randomness": RANDOMNESS,
                "signature": SIGNATURE,
            }
        )

        self.ground_truth_by_ciphertext: dict[str, bytes] = {}
        self.ground_truth_by_challenge: dict[tuple[str, str], object] = {}
        for source in self.fixture.batch_sources:
            public = PublicBatchManifest.model_validate_json(source.public_manifest_bytes)
            ground = _ground_truth(public, self.fixture.policy)
            self.ground_truth_by_ciphertext[
                hashlib.sha256(source.ground_truth_envelope_bytes).hexdigest()
            ] = canonical_json_bytes(ground)
            for item in ground.items:
                self.ground_truth_by_challenge[(ground.batch_id, item.challenge_id)] = item

        def replay_decrypt(portable_bytes, _signature):
            digest = hashlib.sha256(portable_bytes).hexdigest()
            try:
                return self.ground_truth_by_ciphertext[digest]
            except KeyError:
                return self.response_plaintexts[digest]

        monkeypatch.setattr(bittensor_core, "decrypt_with_signature", replay_decrypt)

        _rehearsal, signers = shadow_fixture()
        self.miner_wallets = {
            address: wallet
            for address, wallet in signers.items()
            if address in {item.hotkey for item in self.fixture.closing.snapshot.neurons}
        }

    async def build_prefix(self, *, sealed_canary: bool = False) -> StageWorkItem:
        pool_completion = await self.pool_adapter.execute(self.fixture.work)
        pool_record = self.journal.load(
            self.fixture.window.window_id,
            WindowStage.POOL_AND_SELECTION,
        )
        assert pool_completion.evidence_sha256 == pool_record.evidence_sha256
        self.evidence.append(_stage_evidence(self.fixture.window.window_id, pool_record))

        plan = self.fixture.material_store.load(self.fixture.window.window_id).plan
        facts = RevealFactPort(plan)
        chain = AnchorChain(plan)

        async def transport(prepared, assignment_id, _miner_url, _work_item):
            if assignment_id == self.canary_outcome_assignment_id:
                assert self.canary_outcome is not None
                return self.canary_outcome
            if sealed_canary:
                ground = self.ground_truth_by_challenge[
                    (prepared.request.batch_id, prepared.request.challenge_id)
                ]
                if ground.canary and self.canary_assignment is None:
                    plaintext = ResponsePlaintext.model_validate(
                        {
                            "schema": RESPONSE_PLAINTEXT_SCHEMA,
                            "protocol": PROTOCOL_VERSION,
                            "window_id": prepared.request.window_id,
                            "batch_id": prepared.request.batch_id,
                            "challenge_id": prepared.request.challenge_id,
                            "request_digest": request_digest(prepared.request),
                            "issued_block_hash": prepared.request.issued_block_hash,
                            "validator_hotkey": prepared.validator_hotkey,
                            "serving_hotkey": prepared.miner_hotkey,
                            "status": "ok",
                            "received_video_sha256": prepared.request.video.sha256,
                            "hypothesis": ground.references[0],
                            "model_revision": None,
                            "error_code": None,
                        }
                    )
                    plaintext_bytes = canonical_json_bytes(plaintext)
                    sealed = seal_response(
                        plaintext_bytes,
                        reveal_round=prepared.request.reveal_round,
                    )
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
                    scheme, signature = sign_response_digest(
                        self.miner_wallets[prepared.miner_hotkey],
                        envelope,
                    )
                    assert scheme == envelope.signature_scheme
                    envelope_bytes = canonical_json_bytes(envelope)
                    self.response_plaintexts[sealed.sha256_hex] = plaintext_bytes
                    self.canary_assignment = (
                        prepared.request.batch_id,
                        prepared.request.challenge_id,
                        account_id32(prepared.miner_hotkey),
                    )
                    outcome = QueryOutcome(
                        request=prepared.request,
                        auth_headers=dict(prepared.auth_headers),
                        received_at_unix_ns="123",
                        envelope_bytes=envelope_bytes,
                        envelope=envelope,
                        response_signature=signature,
                        sealed_response=sealed,
                        received_bytes_sha256=hashlib.sha256(envelope_bytes).hexdigest(),
                    )
                    self.canary_outcome = outcome
                    self.canary_outcome_assignment_id = assignment_id
                    return outcome
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
            plan=self.fixture.material_store.load_for_work,
            observe=facts,
            anchor_ports=chain.ports,
            verify_anchor=chain.verify_finality,
            audit_release_block=release,
            transport=transport,
        )
        effects = {
            WindowStage.ASSIGNMENT: AssignmentTranscriptEffect(
                assignments=self.assignments,
                extrinsics=self.extrinsics,
                ports=ports,
                maximum_anchor_advances=4,
            ),
            WindowStage.REQUEST_TRANSCRIPT: RequestTranscriptEffect(
                assignments=self.assignments,
                extrinsics=self.extrinsics,
                ports=ports,
                maximum_transport_concurrency=16,
                transport_timeout_seconds=2,
                maximum_anchor_advances=4,
            ),
            WindowStage.SEALED_RESPONSE: SealedResponseTranscriptEffect(
                assignments=self.assignments,
                extrinsics=self.extrinsics,
                ports=ports,
                maximum_anchor_advances=4,
            ),
        }
        for stage in (
            WindowStage.ASSIGNMENT,
            WindowStage.REQUEST_TRANSCRIPT,
            WindowStage.SEALED_RESPONSE,
        ):
            work = _work(self.fixture.window, stage, tuple(self.evidence))
            operation = stage_operation_id(self.fixture.window.window_id, stage)
            for _attempt in range(8):
                try:
                    result = await effects[stage].perform(
                        operation_id=operation,
                        work=work,
                    )
                except TranscriptEffectPending:
                    continue
                break
            else:
                raise AssertionError(f"{stage.value} did not settle")
            assert isinstance(result.decision, CompleteStageEffect)
            record = self.journal.record(
                window_id=self.fixture.window.window_id,
                stage=stage,
                operation_id=operation,
                objects=result.objects,
                metadata=result.receipt_metadata(),
            )
            self.evidence.append(_stage_evidence(self.fixture.window.window_id, record))
        return _work(
            self.fixture.window,
            WindowStage.REVEAL_AND_SCORE,
            tuple(self.evidence),
        )

    def reveal_effect(self) -> ValidatorRevealEffect:
        async def decrypt(sealed, _pulse):
            try:
                return self.ground_truth_by_ciphertext[sealed.sha256_hex]
            except KeyError:
                return self.response_plaintexts[sealed.sha256_hex]

        async def audit_release(work, reason):
            evidence = canonical_json_bytes({"kind": "finalized-audit-release", "reason": reason})
            fact = RevealAuditRelease(
                schema=REVEAL_AUDIT_RELEASE_SCHEMA,
                window_id=work.window.plan.window_id,
                reason_code=reason,
                audit_release_block=1_600,
                evidence_sha256=hashlib.sha256(evidence).hexdigest(),
            )
            return VerifiedRevealAuditRelease(fact=fact, evidence_bytes=evidence)

        return ValidatorRevealEffect(
            policy=self.fixture.policy,
            validator_hotkey=self.fixture.validator_wallet.hotkey.ss58_address,
            journal=self.journal,
            material_store=self.fixture.material_store,
            protocol_state=self.fixture.protocol_state,
            monitoring_state=self.monitoring,
            coordinator=self.coordinator,
            ports=RevealEffectPorts(
                reveal_pulse=lambda _work_item: self.reveal_pulse,
                decrypt=decrypt,
                audit_release=audit_release,
            ),
        )


def _calibration_evidence(record, policy) -> CalibrationStageEvidence:
    return CalibrationStageEvidence(
        schema=CALIBRATION_STAGE_SCHEMA,
        protocol=PROTOCOL_VERSION,
        window_id=record.receipt.window_id,
        scoring_policy_hash=scoring_policy_hash(policy),
        stage_id=WindowStage.REVEAL_AND_SCORE.value,
        replay_hook_id=calibration_stage_replay_hook_id(
            policy,
            WindowStage.REVEAL_AND_SCORE.value,
        ),
        previous_stage_evidence_sha256="11" * 32,
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


def _rewrite_reveal_result(record, journal, mutate):
    """Rehash a forged reveal result through every pre-existing shallow binding."""

    objects = {item.sha256: journal.read_object(item) for item in record.receipt.objects}
    media_types = {item.sha256: item.media_type for item in record.receipt.objects}
    manifest_digest, manifest = next(
        (digest, json.loads(data))
        for digest, data in objects.items()
        if data.startswith(b"{")
        and json.loads(data).get("schema") == "umi-validator-reveal-stage/1"
    )
    old_result_digest = manifest["reveal_result"]["sha256"]
    result = json.loads(objects[old_result_digest])
    mutate(result)
    result_bytes = canonical_json_bytes(result)

    pool_receipt_bytes = objects[manifest["pool_stage_receipt"]["sha256"]]
    response_receipt_bytes = objects[manifest["response_stage_receipt"]["sha256"]]
    pulse = DrandPulse.from_json(
        json.loads(objects[manifest["reveal_pulse"]["sha256"]]),
        expected_round=result["reveal_round"],
    )
    transition_evidence = sha256_domain(
        b"umi-validator-reveal-evidence-v1\0",
        hashlib.sha256(pool_receipt_bytes).digest(),
        hashlib.sha256(response_receipt_bytes).digest(),
        bytes.fromhex(pulse.evidence_digest),
        hashlib.sha256(result_bytes).digest(),
        bytes.fromhex(result["prior_protocol_state_digest"]),
    ).hex()

    old_request_digest = manifest["protocol_transition_request"]["sha256"]
    transition_request = json.loads(objects[old_request_digest])
    transition_request.update(
        {
            "evidence_digest": transition_evidence,
            "monitoring_observations_sha256": hashlib.sha256(
                canonical_json_bytes(result["monitoring_observations"])
            ).hexdigest(),
            "reveal_result_sha256": hashlib.sha256(result_bytes).hexdigest(),
            "scored_batches_sha256": hashlib.sha256(
                canonical_json_bytes(result["scored_batches"])
            ).hexdigest(),
            "valid_scoring_window": not result["void_reason_codes"],
            "void_reason_codes": result["void_reason_codes"],
        }
    )
    transition_request_bytes = canonical_json_bytes(transition_request)

    old_transition_result_digest = manifest["protocol_transition_result"]["sha256"]
    transition_result = json.loads(objects[old_transition_result_digest])
    transition_result["request_sha256"] = hashlib.sha256(transition_request_bytes).hexdigest()
    transition_result_bytes = canonical_json_bytes(transition_result)

    replacements = {
        old_result_digest: (result_bytes, "application/json"),
        old_request_digest: (transition_request_bytes, "application/json"),
        old_transition_result_digest: (transition_result_bytes, "application/json"),
    }
    for old_digest, (data, media_type) in replacements.items():
        objects.pop(old_digest)
        media_types.pop(old_digest)
        digest = hashlib.sha256(data).hexdigest()
        objects[digest] = data
        media_types[digest] = media_type

    def object_ref(data, media_type):
        return {
            "sha256": hashlib.sha256(data).hexdigest(),
            "media_type": media_type,
            "size_bytes": len(data),
        }

    manifest.update(
        {
            "transition_evidence_sha256": transition_evidence,
            "reveal_result": object_ref(result_bytes, "application/json"),
            "protocol_transition_request": object_ref(
                transition_request_bytes,
                "application/json",
            ),
            "protocol_transition_result": object_ref(
                transition_result_bytes,
                "application/json",
            ),
        }
    )
    objects.pop(manifest_digest)
    media_types.pop(manifest_digest)
    manifest["source_objects"] = sorted(
        (object_ref(data, media_types[digest]) for digest, data in objects.items()),
        key=lambda item: bytes.fromhex(item["sha256"]),
    )
    manifest_bytes = canonical_json_bytes(manifest)
    new_manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()
    objects[new_manifest_digest] = manifest_bytes
    media_types[new_manifest_digest] = "application/json"

    receipt_value = record.receipt.model_dump(mode="json", by_alias=True)
    metadata = dict(receipt_value["metadata"])
    effect_metadata = dict(metadata.get("metadata", {}))
    effect_metadata.update(
        {
            "reveal_manifest_sha256": new_manifest_digest,
            "reveal_result_sha256": hashlib.sha256(result_bytes).hexdigest(),
            "transition_evidence_sha256": transition_evidence,
        }
    )
    metadata["metadata"] = effect_metadata
    receipt_value["metadata"] = metadata
    receipt_value["objects"] = sorted(
        (
            StageObject(
                sha256=digest,
                media_type=media_types[digest],
                size_bytes=len(data),
            ).model_dump(mode="json")
            for digest, data in objects.items()
        ),
        key=lambda item: bytes.fromhex(item["sha256"]),
    )
    receipt = StageReceipt.model_validate(receipt_value)
    receipt_bytes = canonical_json_bytes(receipt)
    return receipt, receipt_bytes, objects


@pytest.mark.asyncio
async def test_reveal_scores_zero_rows_commits_state_and_replays_after_crash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    work = await harness.build_prefix()
    effect = harness.reveal_effect()
    operation = stage_operation_id(harness.fixture.window.window_id, work.stage)

    first = await effect.perform(operation_id=operation, work=work)
    assert isinstance(first.decision, CompleteStageEffect)
    assert harness.fixture.protocol_state.snapshot.last_window_index == 0
    assert len(harness.fixture.protocol_state.snapshot.rolling_scores.batches) == 2
    assert (
        sum(
            count
            for _root, count in harness.fixture.protocol_state.snapshot.assigned_observation_counts
        )
        == 56
    )

    # Simulate a crash after both state stores committed but before StageReceipt.
    recovered = await effect.perform(operation_id=operation, work=work)
    assert recovered.objects == first.objects
    assert recovered.metadata == first.metadata
    assert recovered.decision == first.decision

    record = harness.journal.record(
        window_id=harness.fixture.window.window_id,
        stage=WindowStage.REVEAL_AND_SCORE,
        operation_id=operation,
        objects=recovered.objects,
        metadata=recovered.receipt_metadata(),
    )
    resolved = resolve_reveal_stage_record(record, harness.journal)
    assert resolved.result.schema_ == REVEAL_RESULT_SCHEMA
    assert resolved.result.void_reason_codes == []
    assert len(resolved.result.scored_batches) == 2
    assert resolved.resulting_protocol_state_digest == (
        harness.fixture.protocol_state.snapshot.state_digest.hex()
    )
    payloads = {item.sha256: harness.journal.read_object(item) for item in record.receipt.objects}
    calibration_evidence = CalibrationStageEvidence(
        schema=CALIBRATION_STAGE_SCHEMA,
        protocol=PROTOCOL_VERSION,
        window_id=record.receipt.window_id,
        scoring_policy_hash=harness.fixture.window.scoring_policy_hash,
        stage_id=WindowStage.REVEAL_AND_SCORE.value,
        replay_hook_id=calibration_stage_replay_hook_id(
            harness.fixture.policy,
            WindowStage.REVEAL_AND_SCORE.value,
        ),
        previous_stage_evidence_sha256="11" * 32,
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
        evidence=calibration_evidence,
        receipt=record.receipt,
        objects=payloads,
    )
    receipt_resolved = resolve_reveal_receipt(
        harness.fixture.policy,
        record.receipt,
        payloads,
    )
    assert (
        receipt_resolved.resulting_protocol_state_digest == resolved.resulting_protocol_state_digest
    )


@pytest.mark.asyncio
async def test_public_replay_rejects_plaintext_not_decrypted_from_committed_ciphertext(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    work = await harness.build_prefix()
    operation = stage_operation_id(harness.fixture.window.window_id, work.stage)
    output = await harness.reveal_effect().perform(operation_id=operation, work=work)
    record = harness.journal.record(
        window_id=harness.fixture.window.window_id,
        stage=WindowStage.REVEAL_AND_SCORE,
        operation_id=operation,
        objects=output.objects,
        metadata=output.receipt_metadata(),
    )
    payloads = {item.sha256: harness.journal.read_object(item) for item in record.receipt.objects}
    evidence = _calibration_evidence(record, harness.fixture.policy)

    monkeypatch.setattr(
        bittensor_core,
        "decrypt_with_signature",
        lambda _portable, _signature: b'{"forged":"plaintext"}',
    )
    with pytest.raises(RevealBindingError, match="committed ciphertexts"):
        replay_reveal_stage(
            policy=harness.fixture.policy,
            evidence=evidence,
            receipt=record.receipt,
            objects=payloads,
        )


@pytest.mark.asyncio
async def test_public_replay_recomputes_scores_canaries_and_ground_truth_shape(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    work = await harness.build_prefix()
    operation = stage_operation_id(harness.fixture.window.window_id, work.stage)
    output = await harness.reveal_effect().perform(operation_id=operation, work=work)
    record = harness.journal.record(
        window_id=harness.fixture.window.window_id,
        stage=WindowStage.REVEAL_AND_SCORE,
        operation_id=operation,
        objects=output.objects,
        metadata=output.receipt_metadata(),
    )

    def change_response_score(result):
        response = next(item for item in result["responses"] if item["score"] is not None)
        response["score"] = {"denominator": 1, "numerator": 1}

    def change_score_trace(result):
        response = next(item for item in result["responses"] if item["score"] is not None)
        response["score_trace"] = {"forged": True}

    def change_zero_reason(result):
        result["responses"][0]["zero_score_reason"] = "forged_zero_reason"

    def change_canary(result):
        response = next(item for item in result["responses"] if item["canary_result"] is not None)
        response["canary_result"]["hit"] = True

    def change_global_canary_hit(result):
        result["canary_hit"] = True
        result["void_reason_codes"] = ["canary_hit"]
        result["scored_batches"] = []
        result["monitoring_observations"] = []

    def change_ground_truth_shape(result):
        result["candidate_reveals"][0]["ground_truth_shape_valid"] = False

    def change_scored_batch(result):
        assignment = next(
            item for item in result["scored_batches"][0]["assignments"] if not item["canary"]
        )
        assignment["score"] = {"denominator": 1, "numerator": 1}

    for mutate in (
        change_response_score,
        change_score_trace,
        change_zero_reason,
        change_canary,
        change_global_canary_hit,
        change_ground_truth_shape,
        change_scored_batch,
    ):
        receipt, receipt_bytes, payloads = _rewrite_reveal_result(
            record,
            harness.journal,
            mutate,
        )
        rewritten = SimpleNamespace(receipt=receipt, receipt_bytes=receipt_bytes)
        evidence = _calibration_evidence(rewritten, harness.fixture.policy)
        with pytest.raises(RevealBindingError, match="committed ciphertexts"):
            replay_reveal_stage(
                policy=harness.fixture.policy,
                evidence=evidence,
                receipt=receipt,
                objects=payloads,
            )


@pytest.mark.asyncio
async def test_canary_hit_voids_without_publisher_strike_and_preserves_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = Harness(tmp_path, monkeypatch)
    work = await harness.build_prefix(sealed_canary=True)
    assert harness.canary_assignment is not None
    effect = harness.reveal_effect()
    operation = stage_operation_id(harness.fixture.window.window_id, work.stage)

    result = await effect.perform(operation_id=operation, work=work)
    assert isinstance(result.decision, TerminalStageEffect)
    assert result.decision.outcome is TerminalOutcome.VOID
    assert result.decision.reason_code == "canary_hit"
    assert set(result.decision.pause_scopes) == {
        PauseScope.WINDOW_INTAKE,
        PauseScope.WEIGHT_SUBMISSION,
    }
    snapshot = harness.fixture.protocol_state.snapshot
    assert snapshot.publisher_faults.strikes == ()
    assert snapshot.rolling_scores.batches == ()
    assert sum(count for _root, count in snapshot.assigned_observation_counts) == 56

    reveal_objects = [item.data for item in result.objects]
    decoded = [
        GroundTruthPayload.model_validate_json(item)
        for item in reveal_objects
        if b'"schema":"umi-ground-truth/1"' in item
    ]
    assert decoded
    assert any(b'"canary_hit"' in item for item in reveal_objects)


def test_coordinator_rejects_symlink_path(tmp_path: Path) -> None:
    target = tmp_path / "target.sqlite3"
    target.write_bytes(b"")
    link = tmp_path / "coordinator.sqlite3"
    link.symlink_to(target)
    with pytest.raises(Exception, match="symlink"):
        RevealTransitionCoordinator(link)


def test_coordinator_rejects_traversable_parent(tmp_path: Path) -> None:
    parent = tmp_path / "shared"
    parent.mkdir(mode=0o755)
    parent.chmod(0o755)
    with pytest.raises(Exception, match="private real directory"):
        RevealTransitionCoordinator(parent / "coordinator.sqlite3")


def test_coordinator_files_are_owner_private_under_permissive_umask(tmp_path: Path) -> None:
    parent = tmp_path / "private"
    parent.mkdir(mode=0o700)
    prior = os.umask(0o022)
    try:
        coordinator = RevealTransitionCoordinator(parent / "coordinator.sqlite3")
    finally:
        os.umask(prior)
    try:
        for suffix in ("", "-wal", "-shm"):
            path = Path(os.fspath(coordinator.database_path) + suffix)
            if path.exists():
                assert path.stat().st_mode & 0o077 == 0
    finally:
        coordinator.close()
