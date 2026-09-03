from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import bittensor as bt
import httpx
import pytest
from fastapi.testclient import TestClient

from umi.artifacts import PublicBatchManifest
from umi.audit_publication import AuditBundlePublisher, PublicOriginVerifier
from umi.calibration_bundle import (
    CalibrationVerificationPorts,
    calibration_stage_replay_hook_id,
)
from umi.chain_evidence import FinalizedSnapshotRef
from umi.crypto import seal_response, sign_response_digest
from umi.drand import DrandPulse
from umi.encoding import account_id32
from umi.grandpa_finality import EVIDENCE_CLASS, RECORD_SCHEMA
from umi.observer import create_observer_app
from umi.observer_bundle_feed import (
    BoundedHTTPSFetcher,
    ObserverBundleFeed,
    ObserverFeedTarget,
)
from umi.policy import ScoringPolicy, scoring_policy_hash
from umi.protocol import (
    PROTOCOL_VERSION,
    RESPONSE_ENVELOPE_SCHEMA,
    RESPONSE_PLAINTEXT_SCHEMA,
    RESPONSE_TLE_PROFILE,
    ResponseEnvelope,
    ResponsePlaintext,
    canonical_json_bytes,
    request_digest,
)
from umi.validator import QueryOutcome
from umi.validator_assignment_preparation import (
    ASSIGNMENT_ISSUANCE_FINALITY_SCHEMA,
    AssignmentIssuanceFinalityEvidence,
    issuance_identity_object,
)
from umi.validator_bundle_ports import (
    BittensorManifestSignatureVerifier,
    TranscriptStageReplayHook,
)
from umi.validator_chain import PinnedRuntimeContext
from umi.validator_chain_scan import (
    DecodedNoWeightInterval,
    FinalityAttestationReplayBinding,
    FinalizedBlockScanner,
    RawFinalizedBlockBody,
    RawFinalizedEventStorage,
    VerifiedFinalizedBlockIdentity,
    finalized_block_body_sha256,
)
from umi.validator_delivery import (
    DEFAULT_DELIVERY_ISSUANCE_PATH,
    DEFAULT_MIRROR_INDEX_PATH,
    MIRROR_DISCOVERY_SCHEMA,
    MirrorDiscoveryRule,
)
from umi.validator_incident_observer import ReplayIncidentBundleVerifier
from umi.validator_live import (
    FORBIDDEN_WEIGHT_CAPABILITY_NAMES,
    LiveValidatorPorts,
    PrivateValidatorManifestSigner,
    build_live_validator,
)
from umi.validator_plans import VerifiedFinalizedBlock
from umi.validator_pool_replay import ProofBackedPoolStageReplayHook
from umi.validator_readiness import ReplayPublishedBundleVerifier
from umi.validator_reveal_effect import (
    REVEAL_AUDIT_RELEASE_SCHEMA,
    RevealAuditRelease,
    VerifiedRevealAuditRelease,
    replay_reveal_stage,
)
from umi.validator_state import STAGE_ORDER, TerminalOutcome, WindowStage
from umi.validator_terminal_effect import (
    ReplayCalibrationBundleVerifier,
    replay_terminal_stage_receipt,
)
from umi.validator_transcript_effects import VerifiedProtocolObservation
from umi.validator_weight_build_effect import (
    ProofBackedWeightBuildCloseResolver,
    ProofBackedWeightBuildReplayHook,
)

from . import test_shadow as shadow_support
from . import test_validator_pool_replay as pool_replay_support
from . import test_validator_transcript_effects as transcript_support
from . import test_validator_weight_build_effect as weight_support
from .test_observer import SequenceCollector, _cache, _snapshot
from .test_validator_closing_snapshot import _live_policy
from .test_validator_live import _config, _runtime_validation
from .test_validator_pool_effect import _Fixture as PoolFixture
from .test_validator_reveal_effect import _ground_truth


def _pin_rehearsal_mirror_rule(policy_data: dict) -> None:
    rules = policy_data["implementation_pins"]["rules"]
    discovery = MirrorDiscoveryRule(
        schema=MIRROR_DISCOVERY_SCHEMA,
        protocol=PROTOCOL_VERSION,
        authentication_profile=rules["mirror_authentication_profile"],
        index_path_template=DEFAULT_MIRROR_INDEX_PATH,
        delivery_issuance_path=DEFAULT_DELIVERY_ISSUANCE_PATH,
        origins=[
            "https://mirror.example",
            "https://mirror1.example",
            "https://mirror2.example",
        ],
        delivery_origins=[
            "https://delivery.example",
            "https://delivery1.example",
            "https://delivery2.example",
        ],
    )
    rules["mirror_discovery_rule_sha256"] = hashlib.sha256(
        canonical_json_bytes(discovery)
    ).hexdigest()


class _StaticPublicTree:
    def __init__(self, root: Path) -> None:
        self.root = root

    def __call__(self, request: httpx.Request) -> httpx.Response:
        target = self.root / request.url.path.lstrip("/")
        if not target.is_file():
            return httpx.Response(404, request=request)
        body = target.read_bytes()
        return httpx.Response(
            200,
            headers={"Content-Encoding": "identity", "Content-Length": str(len(body))},
            stream=httpx.ByteStream(body),
            request=request,
        )


class _PlanningFinality:
    def __init__(self, policy: ScoringPolicy, timestamp_ms: int) -> None:
        self.policy = policy
        self.timestamp_ms = timestamp_ms
        self.calls: list[str] = []

    async def finalized_head_height(self) -> int:
        self.calls.append("finalized_head_height")
        return self.policy.activation_block

    async def verified_block_at(self, height: int) -> VerifiedFinalizedBlock | None:
        self.calls.append(f"verified_block_at:{height}")
        if height != self.policy.activation_block:
            return None
        evidence = canonical_json_bytes({"height": height, "kind": "fake-finality"})
        finality = self.policy.implementation_pins.finality_verifier
        live = self.policy.implementation_pins.live_chain
        assert finality is not None and live is not None
        return VerifiedFinalizedBlock(
            height=height,
            block_hash="0x" + "33" * 32,
            state_root="0x" + "32" * 32,
            timestamp_ms=self.timestamp_ms,
            scoring_policy_hash=scoring_policy_hash(self.policy),
            chain_observation=live,
            finality_verifier_sha256=finality.release_sha256_by_target["aarch64-apple-darwin"],
            finality_evidence=evidence,
            finality_evidence_sha256=hashlib.sha256(evidence).hexdigest(),
        )

    def close(self) -> None:
        return None


class _PriorReadiness:
    async def verified_reveal_and_spent(self, _previous):
        return None


class _Observations:
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def __call__(self, boundary: str, work) -> VerifiedProtocolObservation:
        self.calls.append(boundary)
        plan = work.window.plan
        if boundary in {"response_freeze", "response_set_anchor_submit"}:
            round_number = plan.response_close_round
        elif boundary in {"retry_prepare", "response_receipt"}:
            round_number = plan.response_close_round - 1
        else:
            round_number = plan.issue_close_round - 1
        sequence = len(self.calls)
        evidence = f"observation:{boundary}:{sequence}".encode()
        return VerifiedProtocolObservation(
            finalized_block=plan.closing_block + 2,
            finalized_block_hash="0x" + f"{sequence:064x}",
            quicknet_round=round_number,
            evidence_bytes=evidence,
        )


class _LazyAnchorChain:
    """Retain one external fake-chain ledger across a validator process restart."""

    def __init__(self) -> None:
        self.chain: transcript_support.AnchorChain | None = None

    def _bound(self, work) -> transcript_support.AnchorChain:
        if self.chain is None:
            material = self.material_store.load_for_work(work)
            self.chain = transcript_support.AnchorChain(material.plan)
        return self.chain

    def bind(self, material_store) -> None:
        self.material_store = material_store

    def __call__(self, operation, work):
        return self._bound(work).ports(operation, work)

    async def verify_anchor(self, operation, frozen, entry, work):
        return await self._bound(work).verify_finality(operation, frozen, entry, work)

    @property
    def submit_calls(self) -> tuple[str, ...]:
        if self.chain is None:
            return ()
        return tuple(self.chain.submit_calls)


class _ScanRuntime(weight_support._FakeRuntime):
    def decode_extrinsic(self, _raw: bytes, _strict: bool = True):
        raise AssertionError("the no-weight fixture has no extrinsics")


class _NoWeightScanPort:
    """Expose a complete local finalized interval only after its shared close."""

    def __init__(self, policy: ScoringPolicy, validator_hotkey: str) -> None:
        self.policy = policy
        self.validator_account_id32 = account_id32(validator_hotkey)
        self.close_finalized = False
        self.calls: list[tuple[int, int]] = []
        self.weight_calls = 0
        self._cached: DecodedNoWeightInterval | None = None

    async def capture(self, *, start_block: int, end_block: int):
        self.calls.append((start_block, end_block))
        if not self.close_finalized:
            return None
        if self._cached is None:
            self._cached = await _no_weight_interval(
                self.policy,
                self.validator_account_id32,
                start_block,
                end_block,
            )
        return self._cached


class _ScanPort:
    def __init__(
        self,
        policy: ScoringPolicy,
        identities: tuple[VerifiedFinalizedBlockIdentity, ...],
    ) -> None:
        self.policy = policy
        self.bodies: dict[int, RawFinalizedBlockBody] = {}
        self.events: dict[int, RawFinalizedEventStorage] = {}
        self.runtimes: dict[int, PinnedRuntimeContext] = {}
        event_value = canonical_json_bytes([])
        for identity in identities:
            height = identity.snapshot.block_number
            self.bodies[height] = RawFinalizedBlockBody(
                block_hash=identity.snapshot.block_hash,
                parent_hash=identity.snapshot.parent_hash,
                state_root=identity.snapshot.state_root,
                extrinsics_root=identity.extrinsics_root,
                extrinsics=(),
                body_sha256=finalized_block_body_sha256(()),
            )
            runtime = _scan_runtime(policy, identity.parent_snapshot)
            key = runtime.storage_key("System", "Events")
            self.events[height] = RawFinalizedEventStorage(
                block_hash=identity.snapshot.block_hash,
                state_root=identity.snapshot.state_root,
                storage_key=key,
                value=event_value,
                proof=(f"events-proof:{height}".encode(),),
                value_sha256=hashlib.sha256(event_value).hexdigest(),
            )
            self.runtimes[height] = runtime

    async def block_body_at(self, identity):
        return self.bodies[identity.snapshot.block_number]

    async def event_storage_at(self, identity, storage_key):
        value = self.events[identity.snapshot.block_number]
        assert value.storage_key == storage_key
        return value

    async def execution_runtime_at(self, identity):
        return self.runtimes[identity.snapshot.block_number]


def _scan_runtime(
    policy: ScoringPolicy,
    snapshot: FinalizedSnapshotRef,
) -> PinnedRuntimeContext:
    return PinnedRuntimeContext(
        snapshot=snapshot,
        pin=weight_support._runtime_pin(policy),
        metadata_bytes=weight_support.METADATA,
        runtime_version_bytes=weight_support.RUNTIME_VERSION,
        _runtime=_ScanRuntime(),
    )


async def _no_weight_interval(
    policy: ScoringPolicy,
    validator: bytes,
    start: int,
    end: int,
) -> DecodedNoWeightInterval:
    pairs = []
    for height in range(start, end + 1):
        template = weight_support._identity(height, b"template")
        attestation = canonical_json_bytes(
            {
                "schema": RECORD_SCHEMA,
                "evidence_class": EVIDENCE_CLASS,
                "offline_finality_proof": False,
                "sequence": 0,
                "previous_finalized_hash": None,
                "previous_transcript_digest": "0" * 64,
                "block": {
                    "number": template.snapshot.block_number,
                    "hash": template.snapshot.block_hash,
                    "parent_hash": template.snapshot.parent_hash,
                    "state_root": template.snapshot.state_root,
                    "extrinsics_root": template.extrinsics_root,
                    "scale_header": "0x00",
                    "timestamp_ms": height * 12_000,
                },
            }
        )
        pairs.append((weight_support._identity(height, attestation), attestation))
    pairs = tuple(pairs)
    identities = tuple(item[0] for item in pairs)
    scanner = FinalizedBlockScanner(
        _ScanPort(policy, identities),
        extrinsics_root_verifier=lambda **_values: True,
        event_proof_verifier=lambda **_values: True,
        supported_runtime_pins=(weight_support._runtime_pin(policy),),
    )
    return await scanner.capture_no_weight_interval(
        identities,
        finality_attestations=tuple(item[1] for item in pairs),
        finality_replay_bindings=tuple(
            FinalityAttestationReplayBinding(
                minimum_finalized_block=height,
                maximum_records=1,
                startup_timeout_seconds=60,
                expected_sequence=0,
                previous_number=None,
                previous_timestamp_ms=None,
            )
            for height in range(start, end + 1)
        ),
        start_block=start,
        end_block=end,
        validator_account=validator,
    )


def _verification_ports(policy: ScoringPolicy) -> CalibrationVerificationPorts:
    finality_pin = policy.implementation_pins.finality_verifier
    proof_pin = policy.implementation_pins.storage_proof_verifier
    assert finality_pin is not None and proof_pin is not None
    target = "aarch64-apple-darwin"
    finality_digest = finality_pin.release_sha256_by_target[target]

    def finality_verifier(*, identities, attestations, replay_bindings, policy):
        return bool(
            not policy.translation_weights_active
            and len(identities) == len(attestations) == len(replay_bindings)
            and all(
                identity.finality_verifier_sha256 == finality_digest
                and hashlib.sha256(attestation).hexdigest() == identity.finality_evidence_sha256
                for identity, attestation in zip(identities, attestations, strict=True)
            )
        )

    hooks = {
        calibration_stage_replay_hook_id(policy, WindowStage.POOL_AND_SELECTION.value): (
            ProofBackedPoolStageReplayHook(
                verifier=lambda **_values: True,
                finality_verifier=finality_verifier,
                finality_verifier_sha256=finality_digest,
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
            ProofBackedWeightBuildReplayHook(lambda **_values: True)
        ),
        calibration_stage_replay_hook_id(
            policy, WindowStage.COMMIT_AND_TERMINAL_STATE.value
        ): replay_terminal_stage_receipt,
    }

    def runtime_factory(*, snapshot, pin, metadata_bytes, runtime_version_bytes):
        assert pin == weight_support._runtime_pin(policy)
        assert metadata_bytes == weight_support.METADATA
        assert runtime_version_bytes == weight_support.RUNTIME_VERSION
        return _scan_runtime(policy, snapshot)

    return CalibrationVerificationPorts(
        finality_verifier=finality_verifier,
        extrinsics_root_verifier=lambda **_values: True,
        event_proof_verifier=lambda **_values: True,
        runtime_factory=runtime_factory,
        signature_verifier=BittensorManifestSignatureVerifier(),
        stage_replay_hooks=hooks,
        target_triple=target,
        storage_proof_verifier_sha256=proof_pin.release_sha256_by_target[target],
        finality_verifier_sha256=finality_digest,
    )


def _with_replayable_issuance(fixture: PoolFixture, policy: ScoringPolicy) -> None:
    original = fixture.prepared
    finality = policy.implementation_pins.finality_verifier
    assert finality is not None
    digest = finality.release_sha256_by_target["aarch64-apple-darwin"]

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
            finality_verifier_sha256=digest,
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
        evidence = AssignmentIssuanceFinalityEvidence(
            schema=ASSIGNMENT_ISSUANCE_FINALITY_SCHEMA,
            protocol=PROTOCOL_VERSION,
            window_id=fixture.window.window_id,
            timestamp_ms=value.issuance_block_timestamp_ms,
            identity=issuance_identity_object(identity),
            replay_binding=pool_replay_support.FinalityReplayBindingObject.from_evidence(binding),
            attestation_hex=attestation.hex(),
        )
        return replace(value, finality_evidence_bytes=canonical_json_bytes(evidence))

    fixture.prepared = prepared


@pytest.mark.asyncio
async def test_full_live_shadow_rehearsal_executes_restarts_and_replays(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy_data = _live_policy().model_dump(mode="json", by_alias=True)
    policy_data["activation_block"] = 99
    policy_data["soak_start_window_index"] = 0
    _pin_rehearsal_mirror_rule(policy_data)
    policy = ScoringPolicy.model_validate(policy_data)

    # Generate real signed pool/request fixtures against the exact live policy.
    monkeypatch.setattr(shadow_support, "_policy", lambda _publishers, _validators: policy)
    fixture = PoolFixture(tmp_path / "external-fixture")
    _with_replayable_issuance(fixture, policy)
    assert fixture.policy == policy

    monkeypatch.setattr(
        transcript_support,
        "VALIDATOR",
        fixture.validator_wallet.hotkey.ss58_address,
    )
    monkeypatch.setattr(DrandPulse, "verify", lambda _self: None)
    monkeypatch.setattr(bt.timelock, "current_round", lambda: 1)
    monkeypatch.setattr(
        "umi.validator_pool_replay.replay_announcement_validator_storage",
        lambda _proof, *, verifier: SimpleNamespace(evidence=object()),
    )
    monkeypatch.setattr(
        "umi.validator_pool_replay.validate_replayed_announcement_validator_snapshot",
        lambda _snapshot, _replayed, *, policy: fixture.closing.announcement_snapshot,
    )
    monkeypatch.setattr(
        "umi.validator_pool_replay.replay_closing_snapshot_storage",
        lambda _proof, *, verifier: SimpleNamespace(evidence=object()),
    )
    monkeypatch.setattr(
        "umi.validator_pool_replay.validate_replayed_closing_snapshot",
        lambda _snapshot, _replayed, *, policy: fixture.closing.snapshot,
    )
    monkeypatch.setattr(
        "umi.validator_pool_replay.verify_snapshot_finality",
        lambda _proof, **_values: None,
    )
    monkeypatch.setattr(
        "umi.validator_weight_build_effect.bittensor_core.Runtime",
        lambda *_args, **_kwargs: weight_support._FakeRuntime(),
    )

    announcement_timestamp, _schedule = shadow_support._schedule(policy)
    planning = _PlanningFinality(policy, announcement_timestamp)
    observations = _Observations()
    anchors = _LazyAnchorChain()
    no_weight = _NoWeightScanPort(policy, fixture.validator_wallet.hotkey.ss58_address)
    signer = PrivateValidatorManifestSigner(
        fixture.validator_wallet,
        validator_hotkey=fixture.validator_wallet.hotkey.ss58_address,
        signature_scheme="sr25519",
    )

    ground_truth_by_ciphertext: dict[str, bytes] = {}
    ground_truth_by_challenge = {}
    for source in fixture.batch_sources:
        public = PublicBatchManifest.model_validate_json(source.public_manifest_bytes)
        ground = _ground_truth(public, policy)
        ground_truth_by_ciphertext[
            hashlib.sha256(source.ground_truth_envelope_bytes).hexdigest()
        ] = canonical_json_bytes(ground)
        for item in ground.items:
            ground_truth_by_challenge[(ground.batch_id, item.challenge_id)] = item

    miners = {
        wallet.hotkey.ss58_address: wallet
        for wallet in (
            shadow_support._wallet("//MinerA"),
            shadow_support._wallet("//MinerB"),
        )
    }
    response_plaintexts: dict[str, bytes] = {}
    answered_strata: set[tuple[str, str]] = set()
    invalid_canary_plaintext_sent = False
    transport_calls: list[str] = []

    async def transport(prepared, assignment_id, _miner_url, _work):
        nonlocal invalid_canary_plaintext_sent
        transport_calls.append(assignment_id)
        ground = ground_truth_by_challenge[
            (prepared.request.batch_id, prepared.request.challenge_id)
        ]
        answer_key = (prepared.miner_hotkey, prepared.request.task.stratum)
        send_invalid_canary = ground.canary and not invalid_canary_plaintext_sent
        if (ground.canary and not send_invalid_canary) or (
            not ground.canary and answer_key in answered_strata
        ):
            return QueryOutcome(
                request=prepared.request,
                auth_headers=dict(prepared.auth_headers),
                received_at_unix_ns=None,
                envelope_bytes=None,
                envelope=None,
                response_signature=None,
                sealed_response=None,
                failure_code="resource_limit",
            )
        if send_invalid_canary:
            invalid_canary_plaintext_sent = True
        else:
            answered_strata.add(answer_key)
        plaintext = ResponsePlaintext.model_validate(
            {
                "schema": RESPONSE_PLAINTEXT_SCHEMA,
                "protocol": PROTOCOL_VERSION,
                "window_id": prepared.request.window_id,
                "batch_id": prepared.request.batch_id,
                "challenge_id": (
                    "AwMDAwMDAwMDAwMDAwMDAw"
                    if send_invalid_canary
                    else prepared.request.challenge_id
                ),
                "request_digest": request_digest(prepared.request),
                "issued_block_hash": prepared.request.issued_block_hash,
                "validator_hotkey": prepared.validator_hotkey,
                "serving_hotkey": prepared.miner_hotkey,
                "status": "ok",
                "received_video_sha256": prepared.request.video.sha256,
                "hypothesis": "hello world",
                "model_revision": "11" * 32,
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
        scheme, signature = sign_response_digest(miners[prepared.miner_hotkey], envelope)
        assert scheme == envelope.signature_scheme
        envelope_bytes = canonical_json_bytes(envelope)
        response_plaintexts[sealed.sha256_hex] = plaintext_bytes
        return QueryOutcome(
            request=prepared.request,
            auth_headers=dict(prepared.auth_headers),
            received_at_unix_ns="123",
            envelope_bytes=envelope_bytes,
            envelope=envelope,
            response_signature=signature,
            sealed_response=sealed,
            received_bytes_sha256=hashlib.sha256(envelope_bytes).hexdigest(),
        )

    async def prepare_retry(_assignment, _previous, _attempt_index, _work):
        # The deterministic fake miner returns a terminal local resource receipt;
        # there is no useful transport retry for those assignments.
        return None

    reveal_pulse = canonical_json_bytes(
        {
            "round": fixture.window.reveal_round,
            "randomness": shadow_support.RANDOMNESS,
            "signature": shadow_support.SIGNATURE,
        }
    )

    async def decrypt(sealed, _pulse):
        if sealed.sha256_hex in ground_truth_by_ciphertext:
            return ground_truth_by_ciphertext[sealed.sha256_hex]
        return response_plaintexts[sealed.sha256_hex]

    def replay_decrypt(portable_bytes, _signature):
        digest = hashlib.sha256(portable_bytes).hexdigest()
        if digest in ground_truth_by_ciphertext:
            return ground_truth_by_ciphertext[digest]
        return response_plaintexts[digest]

    monkeypatch.setattr("bittensor_core.decrypt_with_signature", replay_decrypt)

    async def reveal_release(work, reason):
        evidence = canonical_json_bytes({"kind": "release", "reason": reason})
        fact = RevealAuditRelease(
            schema=REVEAL_AUDIT_RELEASE_SCHEMA,
            window_id=work.window.plan.window_id,
            reason_code=reason,
            audit_release_block=163,
            evidence_sha256=hashlib.sha256(evidence).hexdigest(),
        )
        return VerifiedRevealAuditRelease(fact=fact, evidence_bytes=evidence)

    async def transcript_release(_work, _reason):
        return 163

    captured_weight_schedule = None

    async def weight_schedule(work):
        nonlocal captured_weight_schedule
        captured_weight_schedule = weight_support._schedule(policy, work)
        return captured_weight_schedule

    async def weight_snapshot(_work, roots, _schedule):
        assert captured_weight_schedule is not None
        return weight_support._snapshot(
            policy,
            captured_weight_schedule,
            roots,
            minimum=2,
            last_update=0,
        )

    async def manifest_verify(root: Path):
        return await ReplayCalibrationBundleVerifier(_verification_ports(policy)).verify(root)

    class _Verifier:
        async def verify(self, root: Path):
            return await manifest_verify(root)

    def ports(context) -> LiveValidatorPorts:
        anchors.bind(context.window_material)
        return LiveValidatorPorts(
            finalized_blocks=planning,
            prior_readiness=_PriorReadiness(),
            pool_source=lambda _work: fixture.source,
            closing_snapshot=lambda _work: fixture.closing,
            selection_pulse=lambda _work: fixture.pulse_bytes,
            delivery_issuance=fixture.delivery_issuance,
            prepared_assignments=fixture.prepared,
            transcript_plan=context.window_material.load_for_work,
            observe=observations,
            anchor_ports=anchors,
            transcript_audit_release=transcript_release,
            transport=transport,
            prepare_retry=prepare_retry,
            reveal_pulse=lambda _work: reveal_pulse,
            decrypt=decrypt,
            reveal_audit_release=reveal_release,
            weight_schedule=weight_schedule,
            weight_snapshot=weight_snapshot,
            no_weight_capture=no_weight,
            weight_close_resolver=ProofBackedWeightBuildCloseResolver(lambda **_values: True),
            bundle_verifier=_Verifier(),
            incident_bundle_verifier=_Verifier(),
            manifest_signer=signer,
        )

    config = _config(tmp_path, policy)
    runtime = build_live_validator(
        config=config,
        policy=policy,
        runtime_validation=_runtime_validation(policy),
        port_factory=ports,
    )
    try:
        first = await runtime.service.tick()
        assert first.started
        assert first.step is not None
        assert first.step.work is not None
        assert first.step.work.stage is WindowStage.POOL_AND_SELECTION

        # Restart on the durable assignment boundary.  The recovered process must
        # advance to request transport without resubmitting this anchor.
        assignment = await runtime.service.tick()
        assert assignment.step is not None
        assert assignment.step.work is not None
        assert assignment.step.work.stage is WindowStage.ASSIGNMENT
        assert len(anchors.submit_calls) == 1
    finally:
        runtime.close()

    runtime = build_live_validator(
        config=config,
        policy=policy,
        runtime_validation=_runtime_validation(policy),
        port_factory=ports,
    )
    try:
        waiting_for_close = False
        for _ in range(24):
            tick = await runtime.service.tick()
            if (
                tick.step is not None
                and tick.step.pending_reason_code == "weight_commit_close_finality_pending"
            ):
                waiting_for_close = True
                break
        assert waiting_for_close
        assert len(anchors.submit_calls) == 3
        assert len(set(anchors.submit_calls)) == 3
        bundle_root = runtime.paths.bundles / fixture.window.window_id
        assert not bundle_root.exists()
        assert no_weight.weight_calls == 0

        no_weight.close_finalized = True
        terminal = await runtime.service.tick()
        assert terminal.step is not None and terminal.step.terminal
        recovery = runtime.recovery_state()
        assert recovery.active_window is None
        assert terminal.step.window is not None
        assert terminal.step.window.terminal_outcome is TerminalOutcome.CALIBRATION_NO_WEIGHT
        assert bundle_root.exists()
        assert len(transport_calls) == 56
        assert len(answered_strata) == 6
        assert no_weight.weight_calls == 0
        assert FORBIDDEN_WEIGHT_CAPABILITY_NAMES.isdisjoint(LiveValidatorPorts.__dataclass_fields__)

        # A fresh verifier uses only the signed bundle and its explicit replay ports.
        verified = await ReplayCalibrationBundleVerifier(_verification_ports(policy)).verify(
            bundle_root
        )
        assert verified.terminal_classification == "calibration_no_weight"
        assert [stage.stage_id for stage in verified.stages] == [
            stage.value for stage in STAGE_ORDER
        ]
        assert verified.weight_commit_close_block == 163
        assert all(
            call[0] == fixture.window.announcement_block and call[1] == 163
            for call in no_weight.calls
        )

        public_root = (tmp_path / "published-audits").resolve()
        staging_root = (tmp_path / "publication-staging").resolve()
        incident_root = (tmp_path / "incident-bundles").resolve()
        publisher_state = (tmp_path / "publication-state").resolve()
        for path, mode in (
            (public_root, 0o755),
            (staging_root, 0o700),
            (incident_root, 0o700),
            (publisher_state, 0o700),
        ):
            path.mkdir(mode=mode)
            path.chmod(mode)
        static = _StaticPublicTree(public_root)
        transport_mock = httpx.MockTransport(static)
        release_manifest_sha256 = "ab" * 32
        public_verifier = ReplayPublishedBundleVerifier(_verification_ports(policy))
        publisher = AuditBundlePublisher(
            policy_hash=scoring_policy_hash(policy),
            validator_account_id32=account_id32(fixture.validator_wallet.hotkey.ss58_address),
            release_manifest_sha256=release_manifest_sha256,
            calibration_root=runtime.paths.bundles.resolve(),
            incident_root=incident_root,
            public_docroot=public_root,
            private_staging_root=staging_root,
            state_database_path=publisher_state / "publication.sqlite3",
            bundle_verifier=public_verifier,
            origin_verifier=PublicOriginVerifier(
                "https://audit.example",
                timeout_seconds=2,
                maximum_concurrency=4,
                transport=transport_mock,
            ),
        )
        publication = await publisher.run_once()
        assert publication.completed == 1

        def feed_fetcher(origin: str, timeout: float) -> BoundedHTTPSFetcher:
            return BoundedHTTPSFetcher(
                origin,
                timeout_seconds=timeout,
                transport=transport_mock,
            )

        feed_target = ObserverFeedTarget(
            validator_account_id32=account_id32(fixture.validator_wallet.hotkey.ss58_address).hex(),
            scoring_policy_hash=scoring_policy_hash(policy),
            release_manifest_sha256=release_manifest_sha256,
            public_origin="https://audit.example",
            verifier=public_verifier,
        )
        feed_state_path = (tmp_path / "observer-feed" / "state.sqlite3").resolve()
        feed_temporary_root = (tmp_path / "observer-temporary").resolve()
        monkeypatch.setattr(
            "umi.observer_bundle_feed.decrypt_with_signature",
            lambda encrypted, _signature: response_plaintexts[
                hashlib.sha256(encrypted).hexdigest()
            ],
        )
        feed = ObserverBundleFeed(
            targets=(feed_target,),
            state_database_path=feed_state_path,
            temporary_root=feed_temporary_root,
            maximum_stale_seconds=300,
            timeout_seconds=2,
            fetcher_factory=feed_fetcher,
            clock=lambda: 100,
        )
        assert await feed.refresh(200)
        feed_window = feed.snapshot().windows[0]
        assert feed_window.solutions == ()
        assert feed_window.solution_count == 56
        total, materialized_solutions = feed.solution_page(
            feed_window.validator_account_id32,
            feed_window.window_id,
            offset=0,
            limit=100,
        )
        assert total == 56
        assert sum(item.response_plaintext_valid for item in materialized_solutions) == 6
        assert (
            sum(item.outer_disposition == "resource_limit" for item in materialized_solutions) == 49
        )
        binding_invalid = next(
            item
            for item in materialized_solutions
            if item.zero_score_reason == "plaintext_binding_mismatch"
        )
        assert binding_invalid.outer_disposition == "sealed"
        assert binding_invalid.response_plaintext_valid is False
        assert binding_invalid.response_status is None
        assert binding_invalid.hypothesis is None
        assert binding_invalid.evidence.response_plaintext is not None

        restarted_feed = ObserverBundleFeed(
            targets=(feed_target,),
            state_database_path=feed_state_path,
            temporary_root=feed_temporary_root,
            maximum_stale_seconds=300,
            timeout_seconds=2,
            fetcher_factory=feed_fetcher,
            clock=lambda: 100,
        )
        assert restarted_feed.snapshot().windows == feed.snapshot().windows

        app = create_observer_app(
            _cache(SequenceCollector([_snapshot(block_number=200)])),
            bundle_feed=restarted_feed,
        )
        with TestClient(app) as client:
            api_response = client.get(
                f"/api/v1/windows/{fixture.window.window_id}/solutions"
                f"?validator={feed_window.validator_account_id32}&limit=50"
            )
            api_next_response = client.get(
                f"/api/v1/windows/{fixture.window.window_id}/solutions"
                f"?validator={feed_window.validator_account_id32}&limit=50"
                f"&cursor={api_response.json()['page']['next_cursor']}"
            )
        assert api_response.status_code == 200
        assert api_next_response.status_code == 200
        api = api_response.json()
        assert api["score_scope"] == "validator_local"
        assert api["page"] == {
            "limit": 50,
            "total": 56,
            "returned": 50,
            "next_cursor": api["page"]["next_cursor"],
        }
        assert api["page"]["next_cursor"] is not None
        api_solutions = api["solutions"] + api_next_response.json()["solutions"]
        assert len(api_solutions) == 56
        assert any(item["hypothesis"] == "hello world" for item in api_solutions)
        assert all(item["references"] for item in api_solutions)
        assert all(item["evidence"]["request"]["url"] for item in api_solutions)
        projected_binding_invalid = next(
            item
            for item in api_solutions
            if item["zero_score_reason"] == "plaintext_binding_mismatch"
        )
        assert projected_binding_invalid["response_plaintext_valid"] is False
        assert projected_binding_invalid["response_status"] is None
        assert projected_binding_invalid["hypothesis"] is None
        assert projected_binding_invalid["evidence"]["response_plaintext"] is not None
    finally:
        runtime.close()
        fixture.protocol_state.close()


@pytest.mark.asyncio
async def test_live_service_settles_zero_anchor_window_without_mirror_index(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy_data = _live_policy().model_dump(mode="json", by_alias=True)
    policy_data["activation_block"] = 99
    policy_data["soak_start_window_index"] = 0
    _pin_rehearsal_mirror_rule(policy_data)
    policy = ScoringPolicy.model_validate(policy_data)
    monkeypatch.setattr(shadow_support, "_policy", lambda _publishers, _validators: policy)
    fixture = PoolFixture(tmp_path / "external-empty-fixture")
    assert fixture.policy == policy
    closing = fixture.closing.snapshot
    closing = closing.model_copy(
        update={
            "publishers": [
                row.model_copy(
                    update={
                        "pool_manifest_sha256": None,
                        "anchor_inclusion_block": None,
                    }
                )
                for row in closing.publishers
            ]
        }
    )
    fixture.closing = replace(
        fixture.closing,
        snapshot=closing,
        snapshot_bytes=canonical_json_bytes(closing),
    )

    monkeypatch.setattr(DrandPulse, "verify", lambda _self: None)
    monkeypatch.setattr(
        "umi.validator_pool_replay.replay_announcement_validator_storage",
        lambda _proof, *, verifier: SimpleNamespace(evidence=object()),
    )
    monkeypatch.setattr(
        "umi.validator_pool_replay.validate_replayed_announcement_validator_snapshot",
        lambda _snapshot, _replayed, *, policy: fixture.closing.announcement_snapshot,
    )
    monkeypatch.setattr(
        "umi.validator_pool_replay.replay_closing_snapshot_storage",
        lambda _proof, *, verifier: SimpleNamespace(evidence=object()),
    )
    monkeypatch.setattr(
        "umi.validator_pool_replay.validate_replayed_closing_snapshot",
        lambda _snapshot, _replayed, *, policy: fixture.closing.snapshot,
    )
    monkeypatch.setattr(
        "umi.validator_pool_replay.verify_snapshot_finality",
        lambda _proof, **_values: None,
    )

    announcement_timestamp, _schedule = shadow_support._schedule(policy)
    planning = _PlanningFinality(policy, announcement_timestamp)
    observations = _Observations()
    anchors = _LazyAnchorChain()
    no_weight = _NoWeightScanPort(policy, fixture.validator_wallet.hotkey.ss58_address)
    signer = PrivateValidatorManifestSigner(
        fixture.validator_wallet,
        validator_hotkey=fixture.validator_wallet.hotkey.ss58_address,
        signature_scheme="sr25519",
    )
    source_calls = 0

    async def missing_index(_work):
        nonlocal source_calls
        source_calls += 1
        raise AssertionError("zero-anchor live window requested a mirror index")

    async def unused(*_args, **_kwargs):
        raise AssertionError("zero-anchor live window invoked an unused port")

    async def reveal_release(work, reason):
        assert reason == "candidate_pool_empty"
        evidence = canonical_json_bytes({"kind": "release", "reason": reason})
        return VerifiedRevealAuditRelease(
            fact=RevealAuditRelease(
                schema=REVEAL_AUDIT_RELEASE_SCHEMA,
                window_id=work.window.plan.window_id,
                reason_code=reason,
                audit_release_block=163,
                evidence_sha256=hashlib.sha256(evidence).hexdigest(),
            ),
            evidence_bytes=evidence,
        )

    class _Verifier:
        async def verify(self, root: Path):
            return await ReplayCalibrationBundleVerifier(_verification_ports(policy)).verify(root)

    def ports(context) -> LiveValidatorPorts:
        anchors.bind(context.window_material)
        return LiveValidatorPorts(
            finalized_blocks=planning,
            prior_readiness=_PriorReadiness(),
            pool_source=missing_index,
            closing_snapshot=lambda _work: fixture.closing,
            selection_pulse=lambda _work: fixture.pulse_bytes,
            delivery_issuance=unused,
            prepared_assignments=unused,
            transcript_plan=context.window_material.load_for_work,
            observe=observations,
            anchor_ports=anchors,
            transcript_audit_release=unused,
            transport=unused,
            prepare_retry=unused,
            reveal_pulse=lambda _work: canonical_json_bytes(
                {
                    "round": fixture.window.reveal_round,
                    "randomness": shadow_support.RANDOMNESS,
                    "signature": shadow_support.SIGNATURE,
                }
            ),
            decrypt=unused,
            reveal_audit_release=reveal_release,
            weight_schedule=unused,
            weight_snapshot=unused,
            no_weight_capture=no_weight,
            weight_close_resolver=unused,
            bundle_verifier=_Verifier(),
            incident_bundle_verifier=ReplayIncidentBundleVerifier(_verification_ports(policy)),
            manifest_signer=signer,
        )

    config = _config(tmp_path, policy)
    runtime = build_live_validator(
        config=config,
        policy=policy,
        runtime_validation=_runtime_validation(policy),
        port_factory=ports,
    )
    try:
        waiting_for_release = False
        for _ in range(12):
            tick = await runtime.service.tick()
            if (
                tick.step is not None
                and tick.step.pending_reason_code == "incident_audit_release_finality_pending"
            ):
                waiting_for_release = True
                break
        assert waiting_for_release
        assert runtime.recovery_state().active_window is not None
        no_weight.close_finalized = True
        terminal = await runtime.service.tick()
        assert terminal.step is not None and terminal.step.terminal
        assert terminal.step is not None
        assert terminal.step.window is not None
        assert terminal.step.window.terminal_outcome is TerminalOutcome.SKIPPED
        assert terminal.step.window.terminal_reason_code == "candidate_pool_empty"
        assert runtime.recovery_state().active_window is None
        assert source_calls == 0
        assert anchors.submit_calls == ()
        assert no_weight.calls
        assert no_weight.weight_calls == 0
        bundle_root = runtime.paths.incident_bundles / fixture.window.window_id
        assert bundle_root.exists()
        verified = await ReplayIncidentBundleVerifier(_verification_ports(policy)).verify(
            bundle_root
        )
        assert verified.terminal_classification == "skipped"
        assert verified.highest_stage == WindowStage.REVEAL_AND_SCORE.value
    finally:
        runtime.close()
        fixture.protocol_state.close()
