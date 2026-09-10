from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.factories import dev_wallet
from tests.test_bootstrap_direct_weights import NOW
from tests.test_observer_bootstrap_service_feed import _terminal_records
from umi.bootstrap_result_intake import (
    BOOTSTRAP_CHAIN_BLOCK_SCHEMA,
    BOOTSTRAP_CHAIN_CAPTURE_SCHEMA,
    BootstrapChainCapture,
    BootstrapResultIntakePorts,
    CapturedBootstrapBlock,
    CapturedFinality,
    CapturedHeader,
    CapturedRuntime,
    CapturedSystemEvents,
    _verify_finality,
    build_bootstrap_result_archive,
    verify_bootstrap_result_archive,
)
from umi.calibration_bundle import (
    FinalityReplayBindingObject,
    RuntimePinObject,
)
from umi.chain import _header_hash
from umi.crypto import sign_response_digest
from umi.grandpa_finality_supervisor import (
    ACCEPTANCE_RECEIPT_SCHEMA,
    _acceptance_digest,
)
from umi.protocol import canonical_json_bytes
from umi.validator_supervisor_publication import (
    SUPERVISOR_BOOTSTRAP_RESULT_SCHEMA,
    SupervisorBootstrapResult,
    sign_supervisor_bootstrap_result,
)


def _header(number: int, *, salt: int) -> CapturedHeader:
    parent = "0x" + f"{salt:02x}" * 32
    state = "0x" + f"{salt + 1:02x}" * 32
    extrinsics = "0x" + f"{salt + 2:02x}" * 32
    value = {
        "number": number,
        "parentHash": parent,
        "stateRoot": state,
        "extrinsicsRoot": extrinsics,
        "digest": {"logs": []},
    }
    return CapturedHeader(
        number=number,
        block_hash=_header_hash(value, "test header"),
        parent_hash=parent,
        state_root=state,
        extrinsics_root=extrinsics,
        digest_logs=[],
    )


def _child_header(parent: CapturedHeader, *, salt: int) -> CapturedHeader:
    value = {
        "number": parent.number + 1,
        "parentHash": parent.block_hash,
        "stateRoot": "0x" + f"{salt:02x}" * 32,
        "extrinsicsRoot": "0x" + f"{salt + 1:02x}" * 32,
        "digest": {"logs": []},
    }
    return CapturedHeader(
        number=value["number"],
        block_hash=_header_hash(value, "test child header"),
        parent_hash=value["parentHash"],
        state_root=value["stateRoot"],
        extrinsics_root=value["extrinsicsRoot"],
        digest_logs=[],
    )


def _signed_result(anchor_hash: str, weight_hash: str):
    owner_fence, signed, authorization, material, receipt, journal, _owner, _participants = (
        _terminal_records(permitted=True)
    )
    anchor = receipt.anchor.model_copy(update={"block_hash": anchor_hash})
    weight = receipt.weight_call.model_copy(update={"block_hash": weight_hash})
    anchor_observation = material.manifest_anchor.model_copy(update={"anchor": anchor})
    material = material.model_copy(update={"manifest_anchor": anchor_observation})
    material_sha256 = hashlib.sha256(canonical_json_bytes(material)).hexdigest()
    receipt = receipt.model_copy(
        update={
            "anchor": anchor,
            "weight_call": weight,
            "call_material_sha256": material_sha256,
        }
    )
    receipt_sha256 = hashlib.sha256(canonical_json_bytes(receipt)).hexdigest()
    journal = journal.model_copy(
        update={
            "anchor": anchor,
            "weight_call": weight,
            "call_material_sha256": material_sha256,
            "receipt_sha256": receipt_sha256,
        }
    )
    result = SupervisorBootstrapResult(
        schema=SUPERVISOR_BOOTSTRAP_RESULT_SCHEMA,
        directive_sha256="71" * 32,
        release_manifest_sha256="72" * 32,
        validator_hotkey=authorization.validator_hotkey,
        submission_id=authorization.submission_id,
        owner_fence_receipt=owner_fence,
        signed_manifest=signed,
        transition_authorization=authorization,
        drain_checkpoint=material.operational_preflight,
        call_material=material,
        submission_receipt=receipt,
        submission_journal=journal,
        created_at=NOW,
    )
    return sign_supervisor_bootstrap_result(
        result,
        wallet=dev_wallet("//DirectBootstrapPermittedValidator"),
    )


def _body_sha256(values: list[bytes]) -> str:
    digest = hashlib.sha256(b"umi-finalized-block-body-v1\0")
    digest.update(len(values).to_bytes(4, "big"))
    for value in values:
        digest.update(len(value).to_bytes(4, "big"))
        digest.update(value)
    return digest.hexdigest()


def _finality(header: CapturedHeader, role: str) -> CapturedFinality:
    attestation = canonical_json_bytes(
        {
            "block_hash": header.block_hash,
            "parent_hash": header.parent_hash,
            "role": role,
        }
    )
    evidence_digest = hashlib.sha256(attestation).digest()
    previous = bytes(32)
    accepted_at = 1_788_700_000_000 + header.number
    acceptance_digest = _acceptance_digest(
        previous,
        height=header.number,
        block_hash=header.block_hash,
        evidence_digest=evidence_digest,
        segment_index=0,
        sequence=0,
        restart_gap=False,
        accepted_at_unix_ms=accepted_at,
    )
    acceptance = canonical_json_bytes(
        {
            "schema": ACCEPTANCE_RECEIPT_SCHEMA,
            "height": header.number,
            "block_hash": header.block_hash,
            "evidence_sha256": evidence_digest.hex(),
            "segment_index": 0,
            "segment_sequence": 0,
            "restart_gap_before": False,
            "accepted_at_unix_ms": accepted_at,
            "previous_acceptance_digest": previous.hex(),
            "acceptance_digest": acceptance_digest.hex(),
        }
    )
    return CapturedFinality(
        attestation_hex="0x" + attestation.hex(),
        attestation_sha256=evidence_digest.hex(),
        replay_binding=FinalityReplayBindingObject(
            minimum_finalized_block=1,
            maximum_records=1,
            startup_timeout_seconds=10,
            expected_sequence=0,
            previous_number=None,
            previous_timestamp_ms=None,
            previous_hash=None,
            previous_digest="00" * 32,
        ),
        acceptance_receipt_hex="0x" + acceptance.hex(),
        acceptance_receipt_sha256=hashlib.sha256(acceptance).hexdigest(),
    )


def _block(
    role: str,
    header: CapturedHeader,
    parent: CapturedHeader,
    body: list[bytes],
    index: int,
) -> CapturedBootstrapBlock:
    metadata = b"test-runtime-metadata"
    version = canonical_json_bytes({"specVersion": 449, "stateVersion": 1, "transactionVersion": 1})
    events = role.encode("ascii")
    target = body[index]
    raw_rpc = canonical_json_bytes(
        {
            "block_hash": header.block_hash,
            "block_number": header.number,
            "extrinsic_index": index,
            "role": role,
            "schema": "umi-bootstrap-raw-rpc-capture/1",
        }
    )
    return CapturedBootstrapBlock(
        schema=BOOTSTRAP_CHAIN_BLOCK_SCHEMA,
        role=role,
        header=header,
        extrinsic_index=index,
        target_extrinsic_sha256=hashlib.sha256(target).hexdigest(),
        target_extrinsic_blake2b256=("0x" + hashlib.blake2b(target, digest_size=32).hexdigest()),
        body_sha256=_body_sha256(body),
        extrinsics_hex=["0x" + item.hex() for item in body],
        raw_rpc_capture_hex="0x" + raw_rpc.hex(),
        raw_rpc_capture_sha256=hashlib.sha256(raw_rpc).hexdigest(),
        runtime=CapturedRuntime(
            execution_parent_header=parent,
            pin=RuntimePinObject(
                metadata_sha256=hashlib.sha256(metadata).hexdigest(),
                spec_version=449,
                transaction_version=1,
                state_version=1,
                ss58_prefix=42,
            ),
            metadata_hex="0x" + metadata.hex(),
            metadata_sha256=hashlib.sha256(metadata).hexdigest(),
            runtime_version_hex="0x" + version.hex(),
            runtime_version_sha256=hashlib.sha256(version).hexdigest(),
        ),
        system_events=CapturedSystemEvents(
            storage_key_hex="0x0102",
            value_hex="0x" + events.hex(),
            value_sha256=hashlib.sha256(events).hexdigest(),
            proof_node_hex=["0x03"],
        ),
        finality=_finality(header, role),
    )


class _ProofVerifier:
    def __init__(self, *, accepted: bool = True) -> None:
        self.accepted = accepted

    def verify_extrinsics_root(self, **_kwargs) -> bool:
        return self.accepted

    def __call__(self, **_kwargs) -> bool:
        return self.accepted


class _FinalityVerifier:
    def validate_attestation(self, encoded: bytes, **_kwargs):
        value = json.loads(encoded)
        return SimpleNamespace(
            block=SimpleNamespace(
                number=_ROLE_HEIGHT[value["role"]],
                hash=value["block_hash"],
                parent_hash=value["parent_hash"],
            ),
            ancestry=(),
        )


class _Runtime:
    def __init__(self, signed, *, break_weight: bool = False) -> None:
        self.signed = signed
        self.break_weight = break_weight

    def constant(self, pallet: str, item: str):
        assert (pallet, item) == ("System", "SS58Prefix")
        return 42

    def storage_key(self, pallet: str, item: str, params: list):
        assert (pallet, item, params) == ("System", "Events", [])
        return b"\x01\x02"

    def storage_entry(self, pallet: str, item: str):
        assert (pallet, item) == ("System", "Events")
        return SimpleNamespace(value_type="events")

    def decode(self, _type, encoded: bytes, *, strict: bool):
        assert strict
        role = encoded.decode("ascii")
        count = {"owner_fence": 1, "manifest_anchor": 2, "weight_call": 3}[role]
        values = [
            {
                "phase": "ApplyExtrinsic",
                "extrinsic_idx": index,
                "module_id": "System",
                "event_id": "ExtrinsicSuccess",
            }
            for index in range(count)
        ]
        if role == "weight_call":
            values.append(
                {
                    "phase": "ApplyExtrinsic",
                    "extrinsic_idx": 2,
                    "module_id": "SubtensorModule",
                    "event_id": "WeightsSet",
                }
            )
        return values

    def decode_extrinsic(self, encoded: bytes, strict: bool):
        assert strict
        raw = bytes(encoded)
        digest = "0x" + hashlib.blake2b(raw, digest_size=32).hexdigest()
        if raw.startswith(b"dummy"):
            return _extrinsic(b"\x00" * 32, "System", "remark", [], digest)
        if raw == b"owner":
            owner = bytes.fromhex(
                self.signed.result.owner_fence_receipt.call_material.preflight.subnet_owner_coldkey_account_id32[
                    2:
                ]
            )
            calls = [
                _call(
                    "AdminUtils",
                    "sudo_set_weights_version_key",
                    {"netuid": 78, "weights_version_key": 1 << 32},
                ),
                _call(
                    "AdminUtils",
                    "sudo_set_min_allowed_weights",
                    {"netuid": 78, "min_allowed_weights": 256},
                ),
                _call(
                    "AdminUtils",
                    "sudo_set_commit_reveal_weights_enabled",
                    {"netuid": 78, "enabled": False},
                ),
            ]
            return _extrinsic(owner, "Utility", "batch_all", [("calls", calls)], digest)
        validator = self.signed.result.validator_hotkey
        if raw == b"anchor":
            return _extrinsic(
                validator,
                "Commitments",
                "set_commitment",
                [
                    ("netuid", 78),
                    (
                        "info",
                        {
                            "fields": [
                                {
                                    "Sha256": (
                                        "0x" + self.signed.result.signed_manifest.manifest_sha256
                                    )
                                }
                            ]
                        },
                    ),
                ],
                digest,
            )
        material = self.signed.result.call_material
        weights = list(material.weights)
        if self.break_weight:
            weights[1] = 0
        return _extrinsic(
            validator,
            "SubtensorModule",
            "set_mechanism_weights",
            [
                ("netuid", 78),
                ("mecid", 0),
                ("dests", list(material.dests)),
                ("weights", weights),
                ("version_key", material.weights_version_key),
            ],
            digest,
        )


def _call(module: str, function: str, args):
    if isinstance(args, dict):
        args = list(args.items())
    return {
        "call_index": "0x0102",
        "call_module": module,
        "call_function": function,
        "call_args": [{"name": name, "type": "fixture", "value": value} for name, value in args],
        "call_hash": "0x" + "ab" * 32,
    }


def _extrinsic(signer, module: str, function: str, args, digest: str):
    return {
        "address": signer,
        "extrinsic_hash": digest,
        "extrinsic_length": 1,
        "call": _call(module, function, args),
    }


_ROLE_HEIGHT = {"owner_fence": 120, "manifest_anchor": 126, "weight_call": 130}


def _case(*, proof_accepted: bool = True, break_weight: bool = False):
    owner_parent = _header(119, salt=1)
    owner = _child_header(owner_parent, salt=3)
    anchor_parent = _header(125, salt=5)
    anchor = _child_header(anchor_parent, salt=7)
    weight_parent = _header(129, salt=9)
    weight = _child_header(weight_parent, salt=11)
    signed = _signed_result(anchor.block_hash, weight.block_hash)
    capture = BootstrapChainCapture(
        schema=BOOTSTRAP_CHAIN_CAPTURE_SCHEMA,
        protocol="umi-asl/0.1",
        network="finney",
        netuid=78,
        mechanism_id=0,
        submission_id=signed.result.submission_id,
        blocks=[
            _block("owner_fence", owner, owner_parent, [b"owner"], 0),
            _block("manifest_anchor", anchor, anchor_parent, [b"dummy-a", b"anchor"], 1),
            _block(
                "weight_call",
                weight,
                weight_parent,
                [b"dummy-a", b"dummy-b", b"weight"],
                2,
            ),
        ],
    )
    owner_cli = canonical_json_bytes(
        {
            "success": True,
            "message": "Success",
            "block_hash": owner.block_hash,
            "extrinsic_id": "120-0000",
            "explorer_url": "https://example.test/extrinsics/120-0000",
            "fee_tao": "0.0001",
        }
    )
    ports = BootstrapResultIntakePorts(
        proof_verifier=_ProofVerifier(accepted=proof_accepted),
        finality_observer=_FinalityVerifier(),
        runtime_factory=lambda _metadata, _pin: _Runtime(signed, break_weight=break_weight),
    )
    return canonical_json_bytes(signed), owner_cli, canonical_json_bytes(capture), ports


def test_intake_builds_complete_archive_and_existing_observer_publication(tmp_path: Path) -> None:
    signed, owner, capture, ports = _case()
    archive = tmp_path / "archive"
    publication = tmp_path / "publication"

    manifest_path, publication_path = build_bootstrap_result_archive(
        signed_result_bytes=signed,
        owner_cli_response_bytes=owner,
        captured_chain_material_bytes=capture,
        archive_root=archive,
        observer_publication_root=publication,
        ports=ports,
    )

    assert manifest_path == archive / "manifest.json"
    assert publication_path == publication / "manifest.json"
    verified = verify_bootstrap_result_archive(archive, ports=ports)
    assert verified.signed_result_sha256 == hashlib.sha256(signed).hexdigest()
    assert [item.semantic_call for item in verified.blocks] == [
        "Utility.batch_all(owner_fence)",
        "Commitments.set_commitment",
        "SubtensorModule.set_mechanism_weights",
    ]
    assert json.loads(publication_path.read_bytes())["submission_id"] == verified.submission_id


def test_intake_fails_closed_on_a_false_chain_proof(tmp_path: Path) -> None:
    signed, owner, capture, ports = _case(proof_accepted=False)
    with pytest.raises(ValueError, match="extrinsics-root verification"):
        build_bootstrap_result_archive(
            signed_result_bytes=signed,
            owner_cli_response_bytes=owner,
            captured_chain_material_bytes=capture,
            archive_root=tmp_path / "archive",
            observer_publication_root=tmp_path / "publication",
            ports=ports,
        )
    assert not (tmp_path / "archive").exists()
    assert not (tmp_path / "publication").exists()


def test_intake_rejects_semantically_different_raw_weight_call(tmp_path: Path) -> None:
    signed, owner, capture, ports = _case(break_weight=True)
    with pytest.raises(ValueError, match="weight call bytes differ"):
        build_bootstrap_result_archive(
            signed_result_bytes=signed,
            owner_cli_response_bytes=owner,
            captured_chain_material_bytes=capture,
            archive_root=tmp_path / "archive",
            observer_publication_root=tmp_path / "publication",
            ports=ports,
        )


def test_intake_rejects_noncanonical_or_wrong_index_capture(tmp_path: Path) -> None:
    signed, owner, capture, ports = _case()
    pretty = json.dumps(json.loads(capture), indent=2).encode()
    with pytest.raises(ValueError, match="not RFC 8785 canonical"):
        build_bootstrap_result_archive(
            signed_result_bytes=signed,
            owner_cli_response_bytes=owner,
            captured_chain_material_bytes=pretty,
            archive_root=tmp_path / "archive-a",
            observer_publication_root=tmp_path / "publication-a",
            ports=ports,
        )
    value = json.loads(capture)
    value["blocks"][1]["extrinsic_index"] = 0
    wrong = value["blocks"][1]["extrinsics_hex"][0]
    raw = bytes.fromhex(wrong[2:])
    value["blocks"][1]["target_extrinsic_sha256"] = hashlib.sha256(raw).hexdigest()
    value["blocks"][1]["target_extrinsic_blake2b256"] = (
        "0x" + hashlib.blake2b(raw, digest_size=32).hexdigest()
    )
    with pytest.raises(ValueError, match="binds another indexed extrinsic"):
        build_bootstrap_result_archive(
            signed_result_bytes=signed,
            owner_cli_response_bytes=owner,
            captured_chain_material_bytes=canonical_json_bytes(value),
            archive_root=tmp_path / "archive-b",
            observer_publication_root=tmp_path / "publication-b",
            ports=ports,
        )


def test_archive_replay_detects_missing_content_addressed_object(tmp_path: Path) -> None:
    signed, owner, capture, ports = _case()
    archive = tmp_path / "archive"
    build_bootstrap_result_archive(
        signed_result_bytes=signed,
        owner_cli_response_bytes=owner,
        captured_chain_material_bytes=capture,
        archive_root=archive,
        observer_publication_root=tmp_path / "publication",
        ports=ports,
    )
    manifest = json.loads((archive / "manifest.json").read_bytes())
    (archive / "objects" / manifest["blocks"][0]["target_extrinsic_sha256"]).unlink()
    with pytest.raises(ValueError, match="object directory differs"):
        verify_bootstrap_result_archive(archive, ports=ports)


def test_outer_validator_signature_tampering_is_rejected_before_outputs(tmp_path: Path) -> None:
    signed, owner, capture, ports = _case()
    value = json.loads(signed)
    value["result"]["release_manifest_sha256"] = "ff" * 32
    result_bytes = canonical_json_bytes(value["result"])
    value["result_sha256"] = hashlib.sha256(result_bytes).hexdigest()
    digest = hashlib.sha256(
        b"umi-validator-supervisor-bootstrap-result-v1\0" + result_bytes
    ).digest()
    value["result_digest"] = digest.hex()
    _scheme, signature = sign_response_digest(dev_wallet("//WrongSigner"), digest)
    value["signature"] = signature
    with pytest.raises(ValueError, match="signature is invalid"):
        build_bootstrap_result_archive(
            signed_result_bytes=canonical_json_bytes(value),
            owner_cli_response_bytes=owner,
            captured_chain_material_bytes=capture,
            archive_root=tmp_path / "archive",
            observer_publication_root=tmp_path / "publication",
            ports=ports,
        )


def test_finality_descendant_bridge_is_hash_linked_to_owned_attested_head() -> None:
    parent = _header(199, salt=57)
    target = _child_header(parent, salt=60)
    head = _child_header(target, salt=63)
    block = _block("owner_fence", target, parent, [b"owner"], 0)
    attestation = canonical_json_bytes({"attested_head": head.block_hash})
    evidence_digest = hashlib.sha256(attestation).digest()
    accepted_at = 1_788_800_000_000
    acceptance_digest = _acceptance_digest(
        bytes(32),
        height=head.number,
        block_hash=head.block_hash,
        evidence_digest=evidence_digest,
        segment_index=0,
        sequence=0,
        restart_gap=False,
        accepted_at_unix_ms=accepted_at,
    )
    acceptance = canonical_json_bytes(
        {
            "schema": ACCEPTANCE_RECEIPT_SCHEMA,
            "height": head.number,
            "block_hash": head.block_hash,
            "evidence_sha256": evidence_digest.hex(),
            "segment_index": 0,
            "segment_sequence": 0,
            "restart_gap_before": False,
            "accepted_at_unix_ms": accepted_at,
            "previous_acceptance_digest": "00" * 32,
            "acceptance_digest": acceptance_digest.hex(),
        }
    )
    bridged = block.model_copy(
        update={
            "finality": CapturedFinality(
                attestation_hex="0x" + attestation.hex(),
                attestation_sha256=evidence_digest.hex(),
                replay_binding=block.finality.replay_binding,
                acceptance_receipt_hex="0x" + acceptance.hex(),
                acceptance_receipt_sha256=hashlib.sha256(acceptance).hexdigest(),
                descendant_headers=[head],
            )
        }
    )

    class AttestedHead:
        def validate_attestation(self, _encoded: bytes, **_kwargs):
            return SimpleNamespace(
                block=SimpleNamespace(
                    number=head.number,
                    hash=head.block_hash,
                    parent_hash=head.parent_hash,
                    state_root=head.state_root,
                    extrinsics_root=head.extrinsics_root,
                ),
                ancestry=(),
            )

    _verify_finality(bridged, AttestedHead())
    unrelated = _header(head.number, salt=70)
    broken = bridged.model_copy(
        update={"finality": bridged.finality.model_copy(update={"descendant_headers": [unrelated]})}
    )
    with pytest.raises(ValueError, match="bridge is not contiguous"):
        _verify_finality(broken, AttestedHead())
