from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import bittensor as bt
import pytest

from umi.calibration_bundle import (
    CALIBRATION_BUNDLE_SCHEMA,
    CALIBRATION_POLICY_MEDIA_TYPE,
    STAGE_IDS,
    CalibrationObjectInput,
    CalibrationStageInput,
    CalibrationVerificationPorts,
    _PayloadTable,
    calibration_stage_replay_hook_id,
    verify_calibration_bundle,
    write_calibration_bundle,
)
from umi.chain_evidence import FinalizedSnapshotRef
from umi.encoding import account_id32
from umi.grandpa_finality import EVIDENCE_CLASS, RECORD_SCHEMA
from umi.policy import (
    PolicyImplementationPins,
    PublisherControlGroup,
    PublisherRegistryEntry,
    ScoringPolicy,
    ValidatorRegistryEntry,
    scoring_policy_hash,
)
from umi.protocol import PROTOCOL_VERSION, canonical_json_bytes
from umi.validator_chain import FinalizedRuntimePin, PinnedRuntimeContext
from umi.validator_chain_scan import (
    DecodedNoWeightInterval,
    FinalityAttestationReplayBinding,
    FinalizedBlockScanner,
    RawFinalizedBlockBody,
    RawFinalizedEventStorage,
    VerifiedFinalizedBlockIdentity,
    finalized_block_body_sha256,
)
from umi.validator_incident_bundle import (
    INCIDENT_BUNDLE_SCHEMA,
    verify_incident_bundle,
    write_incident_bundle,
)
from umi.validator_journal import STAGE_RECEIPT_SCHEMA, StageObject, StageReceipt
from umi.validator_terminal_effect import (
    TERMINAL_STAGE_MEDIA_TYPE,
    TerminalEffectError,
    build_terminal_stage_document,
)

VALIDATOR = b"v" * 32
WINDOW_ID = "11" * 32
SECRET = b"manifest-test-key"
METADATA = b"test-runtime-metadata"
FINALITY_VERIFIER_SHA256 = "fa" * 32
PROOF_VERIFIER_SHA256 = "fb" * 32
CHAIN_SPEC_SHA256 = "fc" * 32
TARGET_TRIPLE = "aarch64-apple-darwin"
PIN = FinalizedRuntimePin(
    metadata_sha256=hashlib.sha256(METADATA).hexdigest(),
    spec_version=449,
    transaction_version=1,
)
RUNTIME_VERSION = canonical_json_bytes(
    {"specVersion": 449, "stateVersion": 1, "transactionVersion": 1}
)


def test_payload_table_deduplicates_one_media_type_and_rejects_media_aliases() -> None:
    payloads = _PayloadTable(maximum_object_bytes=1024, values={})
    data = b'{"schema":"umi-scoring-policy/1"}'

    first = payloads.add(data, CALIBRATION_POLICY_MEDIA_TYPE)
    assert payloads.add(data, CALIBRATION_POLICY_MEDIA_TYPE) == first
    assert list(payloads.values) == [first.sha256]

    with pytest.raises(RuntimeError, match="conflicting bytes or media type"):
        payloads.add(data, "application/json")


def _address(uri: str) -> str:
    return bt.sp_core.Keypair.create_from_uri(uri).ss58_address


def _policy() -> ScoringPolicy:
    rows = [(f"{index:064x}", _address(f"//BundleGroup{index}")) for index in range(1, 4)]
    groups = [
        PublisherControlGroup(control_group_id=group_id, administrator=administrator)
        for group_id, administrator in rows
    ]
    publishers = [
        PublisherRegistryEntry(
            publisher_hotkey=_address(f"//BundlePublisher{index}"),
            owner_coldkey=administrator,
            control_group_id=group_id,
        )
        for index, (group_id, administrator) in enumerate(rows, start=1)
    ]
    publishers.sort(key=lambda item: account_id32(item.publisher_hotkey))
    validators = [
        ValidatorRegistryEntry(
            validator_hotkey=_address(f"//BundleValidator{index}"),
            administrator_id=f"{100 + index:064x}",
        )
        for index in range(4)
    ]
    validators.sort(key=lambda item: account_id32(item.validator_hotkey))
    policy = ScoringPolicy.launch(
        translation_weights_active=False,
        activation_block=1_000,
        minimum_publisher_collateral_alpha_rao=1_000_000_000,
        soak_start_window_index=7,
        validator_capacity_set_root="aa" * 32,
        validator_cost_schedule_hash="bb" * 32,
        implementation_pins=PolicyImplementationPins.local_rehearsal(),
        validator_registry=validators,
        control_group_registry=groups,
        publisher_registry=publishers,
    )
    data = policy.model_dump(mode="json", by_alias=True)
    pins = data["implementation_pins"]
    pins["pin_profile"] = "live_shadow_calibration"
    pins["conformance_fixtures_verified"] = True
    pins["conformance_execution_report_sha256"] = "0f" * 32
    pins["scoring"]["normalization_fixture_set_sha256"] = "10" * 32
    pins["media"]["frame_digest_fixture_set_sha256"] = "11" * 32
    pins["timelock"]["portable_envelope_fixture_set_sha256"] = "12" * 32
    pins["chain"]["chain_fixture_set_sha256"] = "13" * 32
    pins["rules"]["mirror_discovery_rule_sha256"] = "14" * 32
    pins["live_chain"] = {
        "network": "finney",
        "genesis_block_hash": "15" * 32,
        "runtime_spec_version": PIN.spec_version,
        "transaction_version": PIN.transaction_version,
        "state_version": PIN.state_version,
        "metadata_sha256": PIN.metadata_sha256,
        "subtensor_revision": "da06f033663896ef2fdbbfc3ecc68ca908fba0f5",
        "live_chain_fixture_set_sha256": "17" * 32,
    }
    pins["storage_proof_verifier"] = {
        "protocol": "umi-substrate-proof-verifier/1",
        "polkadot_sdk_revision": "cacb4310f20c7cac83eb3ccd8ed5a5ad4212608a",
        "source_tree_sha256": "18" * 32,
        "cargo_lock_sha256": "19" * 32,
        "proof_fixture_set_sha256": "1a" * 32,
        "release_sha256_by_target": {TARGET_TRIPLE: PROOF_VERIFIER_SHA256},
    }
    pins["finality_verifier"] = {
        "profile": "smoldot-verifier-attested-finality/1",
        "evidence_class": "verifier_attested_finality",
        "offline_finality_proof": False,
        "source_revision": "finality-verifier-v1",
        "source_tree_sha256": "1d" * 32,
        "cargo_lock_sha256": "1e" * 32,
        "finality_fixture_set_sha256": "1f" * 32,
        "release_sha256_by_target": {TARGET_TRIPLE: FINALITY_VERIFIER_SHA256},
        "chain_spec_source_revision": "da06f033663896ef2fdbbfc3ecc68ca908fba0f5",
        "chain_spec_sha256": CHAIN_SPEC_SHA256,
        "expected_genesis_hash": "15" * 32,
        "bootstrap_kind": "grandpa_warp_sync_checkpoint",
        "bootstrap_block_number": 1,
        "bootstrap_block_hash": "24" * 32,
    }
    return ScoringPolicy.model_validate(data)


def _block_hash(value: int) -> str:
    return "0x" + value.to_bytes(32, "big").hex()


def _snapshot(height: int) -> FinalizedSnapshotRef:
    return FinalizedSnapshotRef(
        block_number=height,
        block_hash=_block_hash(10_000 + height),
        parent_hash=_block_hash(9_999 + height),
        state_root=_block_hash(20_000 + height),
    )


def _attestation(height: int, extrinsics_root: str) -> bytes:
    return canonical_json_bytes(
        {
            "schema": RECORD_SCHEMA,
            "evidence_class": EVIDENCE_CLASS,
            "offline_finality_proof": False,
            "sequence": 0,
            "previous_finalized_hash": None,
            "previous_transcript_digest": "0" * 64,
            "block": {
                "number": height,
                "hash": _snapshot(height).block_hash,
                "parent_hash": _snapshot(height).parent_hash,
                "state_root": _snapshot(height).state_root,
                "extrinsics_root": extrinsics_root,
                "scale_header": "0x00",
                "timestamp_ms": height * 12_000,
            },
        }
    )


def _identity(height: int) -> tuple[VerifiedFinalizedBlockIdentity, bytes]:
    root = _block_hash(30_000 + height)
    attestation = _attestation(height, root)
    return (
        VerifiedFinalizedBlockIdentity(
            snapshot=_snapshot(height),
            parent_snapshot=_snapshot(height - 1),
            extrinsics_root=root,
            finality_verifier_sha256=FINALITY_VERIFIER_SHA256,
            finality_evidence_sha256=hashlib.sha256(attestation).hexdigest(),
        ),
        attestation,
    )


def _success_event(index: int = 0) -> dict[str, Any]:
    nested = {
        "event_index": "0000",
        "module_id": "System",
        "event_id": "ExtrinsicSuccess",
        "attributes": {},
    }
    return {
        "phase": "ApplyExtrinsic",
        "extrinsic_idx": index,
        "event": nested,
        "event_index": 0,
        "module_id": "System",
        "event_id": "ExtrinsicSuccess",
        "attributes": {},
        "topics": [],
    }


class _Entry:
    modifier = "Default"
    default_bytes = b"\x00"
    value_type = "Vec<EventRecord>"


class _Runtime:
    spec_version = 449
    transaction_version = 1

    def storage_key(self, pallet: str, item: str, params: list[Any]) -> bytes:
        assert (pallet, item, params) == ("System", "Events", [])
        return b"system-events-key"

    def storage_entry(self, pallet: str, item: str) -> _Entry:
        assert (pallet, item) == ("System", "Events")
        return _Entry()

    def decode(self, type_name: str, encoded: bytes, strict: bool = True):
        assert type_name == "Vec<EventRecord>" and strict
        if not encoded.startswith(b"events-"):
            raise ValueError("unknown event bytes")
        return [_success_event()]

    def decode_extrinsic(self, raw: bytes, strict: bool = True):
        assert strict
        if not raw.startswith(b"extrinsic-"):
            raise ValueError("unknown extrinsic bytes")
        return {
            "extrinsic_hash": "0x" + hashlib.blake2b(raw, digest_size=32).hexdigest(),
            "extrinsic_length": len(raw),
            "call": {
                "call_index": "0x0000",
                "call_module": "Timestamp",
                "call_function": "set",
                "call_args": [{"name": "now", "type": "u64", "value": 1}],
                "call_hash": _block_hash(40_000 + int.from_bytes(raw[-2:], "big")),
            },
        }


def _context(snapshot: FinalizedSnapshotRef) -> PinnedRuntimeContext:
    return PinnedRuntimeContext(
        snapshot=snapshot,
        pin=PIN,
        metadata_bytes=METADATA,
        runtime_version_bytes=RUNTIME_VERSION,
        _runtime=_Runtime(),
    )


class _Port:
    def __init__(self, identities: tuple[VerifiedFinalizedBlockIdentity, ...]) -> None:
        self.bodies = {}
        self.events = {}
        self.runtimes = {}
        for item in identities:
            height = item.snapshot.block_number
            extrinsic = b"extrinsic-" + height.to_bytes(2, "big")
            event_value = b"events-" + height.to_bytes(2, "big")
            self.bodies[height] = RawFinalizedBlockBody(
                block_hash=item.snapshot.block_hash,
                parent_hash=item.snapshot.parent_hash,
                state_root=item.snapshot.state_root,
                extrinsics_root=item.extrinsics_root,
                extrinsics=(extrinsic,),
                body_sha256=finalized_block_body_sha256((extrinsic,)),
            )
            self.events[height] = RawFinalizedEventStorage(
                block_hash=item.snapshot.block_hash,
                state_root=item.snapshot.state_root,
                storage_key=b"system-events-key",
                value=event_value,
                proof=(b"proof-" + height.to_bytes(2, "big"),),
                value_sha256=hashlib.sha256(event_value).hexdigest(),
            )
            self.runtimes[height] = _context(item.parent_snapshot)

    async def block_body_at(self, identity):
        return self.bodies[identity.snapshot.block_number]

    async def event_storage_at(self, identity, storage_key):
        assert storage_key == b"system-events-key"
        return self.events[identity.snapshot.block_number]

    async def execution_runtime_at(self, identity):
        return self.runtimes[identity.snapshot.block_number]


async def _interval(start: int = 1_000, end: int = 1_001) -> DecodedNoWeightInterval:
    pairs = tuple(_identity(height) for height in range(start, end + 1))
    identities = tuple(item[0] for item in pairs)
    scanner = FinalizedBlockScanner(
        _Port(identities),
        extrinsics_root_verifier=lambda **_values: True,
        event_proof_verifier=lambda **_values: True,
        supported_runtime_pins=(PIN,),
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
        validator_account=VALIDATOR,
    )


def _stage_inputs(
    policy: ScoringPolicy,
    *,
    arbitrary_first_receipt: bool = False,
    interval: DecodedNoWeightInterval | None = None,
) -> tuple[CalibrationStageInput, ...]:
    result = []
    for index, stage in enumerate(STAGE_IDS):
        if stage == "commit_and_terminal_state" and interval is not None:
            payload = canonical_json_bytes(
                build_terminal_stage_document(
                    policy_hash=scoring_policy_hash(policy),
                    validator_account=VALIDATOR,
                    window_id=WINDOW_ID,
                    window_index=0,
                    announcement_block=policy.activation_block,
                    close=interval.scan.end_snapshot,
                    captured=interval,
                )
            )
            media_type = TERMINAL_STAGE_MEDIA_TYPE
        else:
            payload = f"typed-stage-{index}".encode()
            media_type = f"application/vnd.umi.test-{stage}"
        reference = StageObject(
            sha256=hashlib.sha256(payload).hexdigest(),
            media_type=media_type,
            size_bytes=len(payload),
        )
        receipt = StageReceipt(
            schema=STAGE_RECEIPT_SCHEMA,
            protocol=PROTOCOL_VERSION,
            window_id=WINDOW_ID,
            stage=stage,
            operation_id=f"test:{stage}",
            objects=[reference],
            metadata={"fixture": stage},
        )
        receipt_bytes = canonical_json_bytes(receipt)
        if index == 0 and arbitrary_first_receipt:
            receipt_bytes = b"stage-0"
        result.append(
            CalibrationStageInput(
                receipt_bytes=receipt_bytes,
                objects=(CalibrationObjectInput(payload, media_type),),
                replay_hook_id=calibration_stage_replay_hook_id(policy, stage),
            )
        )
    return tuple(result)


def _sign(digest: bytes) -> bytes:
    return hashlib.sha512(SECRET + digest).digest()


def _runtime_factory(*, snapshot, pin, metadata_bytes, runtime_version_bytes):
    assert pin == PIN and metadata_bytes == METADATA and runtime_version_bytes == RUNTIME_VERSION
    return _context(snapshot)


def _ports(
    *,
    policy: ScoringPolicy | None = None,
    omit_hook: str | None = None,
    signature_ok: bool = True,
):
    policy = policy or _policy()
    hooks = {
        calibration_stage_replay_hook_id(policy, stage): (
            lambda *, evidence, receipt, objects, policy: bool(
                not policy.translation_weights_active
                and evidence.stage_id == receipt.stage
                and receipt.metadata == {"fixture": receipt.stage}
                and set(objects) == {item.sha256 for item in receipt.objects}
            )
        )
        for stage in STAGE_IDS
        if stage != omit_hook
    }
    return CalibrationVerificationPorts(
        finality_verifier=lambda *, identities, attestations, replay_bindings, policy: bool(
            not policy.translation_weights_active
            and len(identities) == len(attestations)
            and len(replay_bindings) == len(identities)
            and all(
                hashlib.sha256(attestation).hexdigest() == identity.finality_evidence_sha256
                for identity, attestation in zip(identities, attestations, strict=True)
            )
        ),
        extrinsics_root_verifier=lambda **_values: True,
        event_proof_verifier=lambda **_values: True,
        runtime_factory=_runtime_factory,
        signature_verifier=lambda *, account_id32, scheme, digest, signature: bool(
            signature_ok
            and account_id32 == VALIDATOR
            and scheme == "ed25519"
            and signature == _sign(digest)
        ),
        stage_replay_hooks=hooks,
        target_triple=TARGET_TRIPLE,
        storage_proof_verifier_sha256=PROOF_VERIFIER_SHA256,
        finality_verifier_sha256=FINALITY_VERIFIER_SHA256,
    )


def _incident_stage_inputs(
    policy: ScoringPolicy,
    *,
    terminal_stage_index: int = 3,
    reason_code: str = "response_anchor_failed",
    outcome: str = "skipped",
) -> tuple[CalibrationStageInput, ...]:
    result = []
    for index, stage in enumerate(STAGE_IDS[: terminal_stage_index + 1]):
        payload = f"incident-stage-{index}".encode()
        media_type = f"application/vnd.umi.incident-test-{stage}"
        reference = StageObject(
            sha256=hashlib.sha256(payload).hexdigest(),
            media_type=media_type,
            size_bytes=len(payload),
        )
        terminal = None
        kind = "completion"
        if index == terminal_stage_index:
            kind = "terminal"
            terminal = {
                "outcome": outcome,
                "reason_code": reason_code,
                "audit_release_block": 1_001,
                "incident": {
                    "incident_id": f"test/{stage}/incident",
                    "reason_code": reason_code,
                    "metadata": {"stage": stage},
                },
                "pause_scopes": [],
            }
        receipt = StageReceipt(
            schema=STAGE_RECEIPT_SCHEMA,
            protocol=PROTOCOL_VERSION,
            window_id=WINDOW_ID,
            stage=stage,
            operation_id=f"test:{stage}",
            objects=[reference],
            metadata={
                "schema": "umi-validator-adapter-result/1",
                "kind": kind,
                "metadata": {"fixture": stage},
                "terminal": terminal,
            },
        )
        result.append(
            CalibrationStageInput(
                receipt_bytes=canonical_json_bytes(receipt),
                objects=(CalibrationObjectInput(payload, media_type),),
                replay_hook_id=calibration_stage_replay_hook_id(policy, stage),
            )
        )
    return tuple(result)


def _incident_ports(policy: ScoringPolicy) -> CalibrationVerificationPorts:
    ports = _ports(policy=policy)
    hooks = {
        calibration_stage_replay_hook_id(policy, stage): (
            lambda *, evidence, receipt, objects, policy: bool(
                not policy.translation_weights_active
                and evidence.stage_id == receipt.stage
                and receipt.metadata.get("metadata") == {"fixture": receipt.stage}
                and set(objects) == {item.sha256 for item in receipt.objects}
            )
        )
        for stage in STAGE_IDS
    }
    return replace(ports, stage_replay_hooks=hooks)


async def _write(root: Path, **overrides) -> Path:
    interval = overrides.pop("no_weight_scan", await _interval())
    close = overrides.pop("weight_commit_close_snapshot", interval.scan.end_snapshot)
    policy = overrides.pop("policy", _policy())
    stages = overrides.pop("stages", None)
    if stages is None:
        try:
            stages = _stage_inputs(policy, interval=interval)
        except TerminalEffectError:
            # The writer itself owns the earlier proof/boundary rejection.  Keep
            # its negative fixtures from failing while constructing a later-stage
            # binding they can never legitimately reach.
            stages = _stage_inputs(policy)
    return write_calibration_bundle(
        root,
        policy=policy,
        window_id=WINDOW_ID,
        window_index=overrides.pop("window_index", 0),
        software_revisions={
            "umi": "test",
            "runtime": "test",
            "target_triple": TARGET_TRIPLE,
            "storage_proof_verifier_sha256": PROOF_VERIFIER_SHA256,
            "finality_verifier_sha256": FINALITY_VERIFIER_SHA256,
            "finality_chain_spec_sha256": CHAIN_SPEC_SHA256,
        },
        validator_account=VALIDATOR,
        weight_commit_close_snapshot=close,
        audit_release_snapshot=overrides.pop("audit_release_snapshot", close),
        no_weight_scan=interval,
        stages=stages,
        signature_scheme="ed25519",
        manifest_signer=overrides.pop("manifest_signer", _sign),
        **overrides,
    )


@pytest.mark.asyncio
async def test_valid_proof_bearing_fixture_replays_exact_complete_interval(tmp_path: Path) -> None:
    root = tmp_path / "bundle"
    path = await _write(root)
    verified = await verify_calibration_bundle(root, ports=_ports())

    assert path == root / "manifest.json"
    assert verified.manifest.schema_ == CALIBRATION_BUNDLE_SCHEMA
    assert verified.manifest.announcement_block == 1_000
    assert verified.manifest.weight_commit_close_block == 1_001
    assert verified.no_weight_scan.scanned_blocks == 2
    assert verified.replayed_interval.scan.scanned_calls == 2
    assert [stage.stage_id for stage in verified.stages] == list(STAGE_IDS)
    assert verified.manifest.validator_signature.account_id32 == VALIDATOR.hex()
    assert verified.manifest.audit_bundle_bytes == path.stat().st_size + sum(
        item.size_bytes for item in verified.manifest.objects
    )


@pytest.mark.asyncio
async def test_invented_logical_records_and_one_block_scan_are_rejected(tmp_path: Path) -> None:
    interval = await _interval()
    logical_only = replace(interval, evidence=())
    with pytest.raises(TypeError, match="proof-bearing"):
        await _write(tmp_path / "logical-only", no_weight_scan=logical_only)

    one_block = await _interval(1_000, 1_000)
    with pytest.raises(ValueError, match="one-block"):
        await _write(tmp_path / "one-block", no_weight_scan=one_block)


@pytest.mark.asyncio
async def test_policy_derived_announcement_is_the_scan_start(tmp_path: Path) -> None:
    shifted = await _interval(1_001, 1_002)
    with pytest.raises(ValueError, match="policy-derived announcement"):
        await _write(tmp_path / "shifted", no_weight_scan=shifted)


@pytest.mark.asyncio
async def test_terminal_receipt_scan_summary_must_match_raw_scan(tmp_path: Path) -> None:
    policy = _policy()
    interval = await _interval()
    stages = list(_stage_inputs(policy, interval=interval))
    terminal_input = stages[-1]
    document = json.loads(terminal_input.objects[0].data)
    document["scanned_calls"] += 1
    payload = canonical_json_bytes(document)
    media_type = terminal_input.objects[0].media_type
    reference = StageObject(
        sha256=hashlib.sha256(payload).hexdigest(),
        media_type=media_type,
        size_bytes=len(payload),
    )
    receipt = StageReceipt.model_validate_json(terminal_input.receipt_bytes).model_copy(
        update={"objects": [reference]}
    )
    stages[-1] = CalibrationStageInput(
        receipt_bytes=canonical_json_bytes(receipt),
        objects=(CalibrationObjectInput(payload, media_type),),
        replay_hook_id=terminal_input.replay_hook_id,
    )
    root = tmp_path / "terminal-scan-mismatch"
    await _write(root, policy=policy, no_weight_scan=interval, stages=tuple(stages))

    with pytest.raises(ValueError, match="terminal stage and no-weight scan disagree"):
        await verify_calibration_bundle(root, ports=_ports(policy=policy))


@pytest.mark.asyncio
async def test_arbitrary_stage_bytes_and_missing_replay_hook_are_rejected(tmp_path: Path) -> None:
    policy = _policy()
    with pytest.raises(ValueError, match="stage receipt"):
        await _write(
            tmp_path / "arbitrary",
            policy=policy,
            stages=_stage_inputs(policy, arbitrary_first_receipt=True),
        )

    root = tmp_path / "missing-hook"
    await _write(root)
    with pytest.raises(ValueError, match="replay hook"):
        await verify_calibration_bundle(root, ports=_ports(omit_hook=STAGE_IDS[3]))


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["raw_extrinsic", "trie_proof", "signature"])
async def test_tampered_raw_proof_or_signature_is_rejected(tmp_path: Path, kind: str) -> None:
    root = tmp_path / kind
    path = await _write(root)
    manifest = json.loads(path.read_bytes())
    if kind == "signature":
        manifest["validator_signature"]["signature"] = "0x" + "00" * 64
        path.write_bytes(canonical_json_bytes(manifest))
        match = "signature"
    else:
        scan_ref = manifest["no_weight_scan_object"]
        scan = json.loads((root / "objects" / scan_ref["sha256"]).read_bytes())
        block = scan["blocks"][0]
        target = (
            block["extrinsics"][0] if kind == "raw_extrinsic" else block["event_proof_nodes"][0]
        )
        (root / "objects" / target["sha256"]).write_bytes(b"tampered")
        match = "wrong byte length|SHA-256"
    with pytest.raises(ValueError, match=match):
        await verify_calibration_bundle(root, ports=_ports())


@pytest.mark.asyncio
async def test_signature_verifier_and_finality_verifier_cannot_be_bypassed(tmp_path: Path) -> None:
    root = tmp_path / "bundle"
    await _write(root)
    with pytest.raises(ValueError, match="signature"):
        await verify_calibration_bundle(root, ports=_ports(signature_ok=False))

    ports = _ports()
    rejecting = replace(ports, finality_verifier=lambda **_values: False)
    with pytest.raises(ValueError, match="finality"):
        await verify_calibration_bundle(root, ports=rejecting)

    wrong_binary = replace(ports, finality_verifier_sha256="00" * 32)
    with pytest.raises(ValueError, match="verification ports"):
        await verify_calibration_bundle(root, ports=wrong_binary)


@pytest.mark.asyncio
async def test_tampered_stage_payload_and_runtime_metadata_are_rejected(tmp_path: Path) -> None:
    root = tmp_path / "bundle"
    path = await _write(root)
    manifest = json.loads(path.read_bytes())
    stage = json.loads(
        (root / "objects" / manifest["stages"][0]["evidence_object"]["sha256"]).read_bytes()
    )
    payload = stage["payload_objects"][0]
    (root / "objects" / payload["sha256"]).write_bytes(b"different")
    with pytest.raises(ValueError):
        await verify_calibration_bundle(root, ports=_ports())

    root2 = tmp_path / "metadata"
    path2 = await _write(root2)
    manifest2 = json.loads(path2.read_bytes())
    scan = json.loads(
        (root2 / "objects" / manifest2["no_weight_scan_object"]["sha256"]).read_bytes()
    )
    metadata = scan["blocks"][0]["runtime_metadata_object"]
    (root2 / "objects" / metadata["sha256"]).write_bytes(b"different")
    with pytest.raises(ValueError):
        await verify_calibration_bundle(root2, ports=_ports())


@pytest.mark.asyncio
async def test_early_terminal_incident_bundle_replays_reached_prefix_and_markers(
    tmp_path: Path,
) -> None:
    policy = _policy()
    interval = await _interval()
    stages = _incident_stage_inputs(policy)
    root = tmp_path / "incident"
    path = write_incident_bundle(
        root,
        policy=policy,
        window_id=WINDOW_ID,
        window_index=0,
        software_revisions={
            "umi": "test",
            "target_triple": TARGET_TRIPLE,
            "storage_proof_verifier_sha256": PROOF_VERIFIER_SHA256,
            "finality_verifier_sha256": FINALITY_VERIFIER_SHA256,
            "finality_chain_spec_sha256": CHAIN_SPEC_SHA256,
        },
        validator_account=VALIDATOR,
        audit_release_snapshot=interval.scan.end_snapshot,
        no_weight_scan=interval,
        stages=stages,
        terminal_classification="skipped",
        reason_code="response_anchor_failed",
        incident={
            "incident_id": "test/sealed_response/incident",
            "reason_code": "response_anchor_failed",
            "metadata": {"stage": "sealed_response"},
        },
        signature_scheme="ed25519",
        manifest_signer=_sign,
    )
    verified = await verify_incident_bundle(root, ports=_incident_ports(policy))

    assert path == root / "manifest.json"
    assert verified.manifest.schema_ == INCIDENT_BUNDLE_SCHEMA
    assert verified.manifest.highest_stage == "sealed_response"
    assert verified.manifest.reason_codes == ["response_anchor_failed"]
    assert [item.status for item in verified.manifest.stages] == [
        "reached",
        "reached",
        "reached",
        "reached",
        "not_reached",
        "not_reached",
        "not_reached",
    ]
    assert len(verified.reached_stages) == 4
    assert verified.replayed_interval.scan.end_snapshot == interval.scan.end_snapshot


@pytest.mark.asyncio
async def test_incident_bundle_rejects_terminal_receipt_and_not_reached_tampering(
    tmp_path: Path,
) -> None:
    policy = _policy()
    interval = await _interval()
    stages = _incident_stage_inputs(policy)
    root = tmp_path / "incident"
    path = write_incident_bundle(
        root,
        policy=policy,
        window_id=WINDOW_ID,
        window_index=0,
        software_revisions={
            "umi": "test",
            "target_triple": TARGET_TRIPLE,
            "storage_proof_verifier_sha256": PROOF_VERIFIER_SHA256,
            "finality_verifier_sha256": FINALITY_VERIFIER_SHA256,
            "finality_chain_spec_sha256": CHAIN_SPEC_SHA256,
        },
        validator_account=VALIDATOR,
        audit_release_snapshot=interval.scan.end_snapshot,
        no_weight_scan=interval,
        stages=stages,
        terminal_classification="skipped",
        reason_code="response_anchor_failed",
        incident={
            "incident_id": "test/sealed_response/incident",
            "reason_code": "response_anchor_failed",
            "metadata": {"stage": "sealed_response"},
        },
        signature_scheme="ed25519",
        manifest_signer=_sign,
    )
    manifest = json.loads(path.read_bytes())
    manifest["stages"][4]["prior_stage_reason_code"] = "different_reason"
    path.write_bytes(canonical_json_bytes(manifest))

    with pytest.raises(ValueError):
        await verify_incident_bundle(root, ports=_incident_ports(policy))

    root2 = tmp_path / "receipt-mismatch"
    bad_stages = list(stages)
    receipt = StageReceipt.model_validate_json(bad_stages[-1].receipt_bytes)
    metadata = dict(receipt.metadata)
    terminal = dict(metadata["terminal"])
    terminal["reason_code"] = "different_reason"
    terminal["incident"] = {
        "incident_id": "test/sealed_response/incident",
        "reason_code": "different_reason",
        "metadata": {"stage": "sealed_response"},
    }
    metadata["terminal"] = terminal
    bad_stages[-1] = CalibrationStageInput(
        receipt_bytes=canonical_json_bytes(receipt.model_copy(update={"metadata": metadata})),
        objects=bad_stages[-1].objects,
        replay_hook_id=bad_stages[-1].replay_hook_id,
    )
    with pytest.raises(ValueError, match="terminal receipt"):
        write_incident_bundle(
            root2,
            policy=policy,
            window_id=WINDOW_ID,
            window_index=0,
            software_revisions={
                "umi": "test",
                "target_triple": TARGET_TRIPLE,
                "storage_proof_verifier_sha256": PROOF_VERIFIER_SHA256,
                "finality_verifier_sha256": FINALITY_VERIFIER_SHA256,
                "finality_chain_spec_sha256": CHAIN_SPEC_SHA256,
            },
            validator_account=VALIDATOR,
            audit_release_snapshot=interval.scan.end_snapshot,
            no_weight_scan=interval,
            stages=tuple(bad_stages),
            terminal_classification="skipped",
            reason_code="response_anchor_failed",
            incident={
                "incident_id": "test/sealed_response/incident",
                "reason_code": "response_anchor_failed",
                "metadata": {"stage": "sealed_response"},
            },
            signature_scheme="ed25519",
            manifest_signer=_sign,
        )
