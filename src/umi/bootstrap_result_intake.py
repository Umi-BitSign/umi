"""Coordinator-owned intake and complete archive for one applied bootstrap row.

The validator publishes one signed terminal result.  This module does not ask the
validator for any more material: the coordinator combines that result with its
own proof-carrying chain capture, verifies both, writes the existing observer
publication, and preserves a self-contained content-addressed archive.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, Literal, Protocol

import bittensor_core
from pydantic import Field, field_validator, model_validator
from typing_extensions import Self

from .audit import EvidenceStore, ObjectRef, _read_bounded_regular_file
from .bootstrap_direct_weights import DIRECT_MINIMUM_WEIGHTS_VERSION_KEY
from .calibration_bundle import FinalityReplayBindingObject, RuntimePinObject
from .chain import _header_hash
from .encoding import account_id32
from .grandpa_finality import GrandpaFinalityObserver
from .grandpa_finality_supervisor import parse_finality_acceptance_receipt
from .observer_bootstrap_service_feed import (
    BootstrapServicePublicationManifest,
    build_bootstrap_service_publication,
)
from .protocol import PROTOCOL_VERSION, BlockHash, Hex32, StrictProtocolModel, canonical_json_bytes
from .substrate_proof import SubprocessStorageProofVerifier
from .validator_chain_scan import (
    _account,
    _commitment_call_binding,
    _decoded_call_parts,
    _extrinsic_statuses,
)
from .validator_supervisor_publication import (
    SignedSupervisorBootstrapResult,
    parse_canonical_signed_supervisor_bootstrap_result,
)

BOOTSTRAP_CHAIN_CAPTURE_SCHEMA = "umi-bootstrap-chain-capture/1"
BOOTSTRAP_COMPLETE_ARCHIVE_SCHEMA = "umi-bootstrap-complete-archive/1"
BOOTSTRAP_OWNER_CLI_EVIDENCE_SCHEMA = "umi-bootstrap-owner-cli-evidence/1"
BOOTSTRAP_CHAIN_BLOCK_SCHEMA = "umi-bootstrap-chain-block-evidence/1"

MAX_CAPTURE_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_ARCHIVE_OBJECT_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_BYTES = 384 * 1024 * 1024
MAX_METADATA_BYTES = 16 * 1024 * 1024
MAX_EXTRINSICS = 4_096
MAX_EXTRINSIC_BYTES = 16 * 1024 * 1024
MAX_BLOCK_BODY_BYTES = 64 * 1024 * 1024
MAX_EVENTS_BYTES = 16 * 1024 * 1024
MAX_PROOF_NODES = 4_096
MAX_PROOF_NODE_BYTES = 2 * 1024 * 1024
MAX_PROOF_BYTES = 32 * 1024 * 1024
MAX_FINALITY_BYTES = 16 * 1024 * 1024
MAX_RUNTIME_VERSION_BYTES = 1024 * 1024
MAX_OWNER_CLI_BYTES = 64 * 1024
MAX_RAW_RPC_CAPTURE_BYTES = 72 * 1024 * 1024
MAX_FINALITY_ANCESTRY_HEADERS = 16_384

_HEX_BYTES_RE = re.compile(r"^0x(?:[0-9a-f]{2})*$")
_GIT_REVISION_RE = re.compile(r"^[0-9a-f]{40}$")


class BootstrapResultIntakeError(RuntimeError):
    """Stable, non-sensitive intake failure."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class ArchiveObjectRef(StrictProtocolModel):
    sha256: Hex32
    media_type: Annotated[str, Field(min_length=1, max_length=256)]
    size_bytes: Annotated[int, Field(ge=0, le=MAX_ARCHIVE_OBJECT_BYTES)]

    @classmethod
    def from_ref(cls, value: ObjectRef) -> ArchiveObjectRef:
        return cls.model_validate(value.as_dict())

    def to_ref(self) -> ObjectRef:
        return ObjectRef(self.sha256, self.media_type, self.size_bytes)


class CapturedHeader(StrictProtocolModel):
    """All JSON-RPC header fields needed to reproduce its SCALE hash."""

    number: Annotated[int, Field(gt=0, le=(1 << 53) - 1)]
    block_hash: BlockHash
    parent_hash: BlockHash
    state_root: BlockHash
    extrinsics_root: BlockHash
    digest_logs: Annotated[list[str], Field(max_length=256)]

    @field_validator("digest_logs")
    @classmethod
    def validate_logs(cls, values: list[str]) -> list[str]:
        total = 0
        for value in values:
            raw = _unhex(value, "header_digest_log_invalid", 1024 * 1024, allow_empty=False)
            total += len(raw)
            if total > 1024 * 1024:
                raise ValueError("header digest logs exceed the byte limit")
        return values

    @model_validator(mode="after")
    def validate_hash(self) -> Self:
        if _header_hash(self.rpc_header(), "bootstrap capture header") != self.block_hash:
            raise ValueError("captured header does not reproduce its block hash")
        return self

    def rpc_header(self) -> dict[str, Any]:
        return {
            "number": self.number,
            "parentHash": self.parent_hash,
            "stateRoot": self.state_root,
            "extrinsicsRoot": self.extrinsics_root,
            "digest": {"logs": self.digest_logs},
        }


class CapturedRuntime(StrictProtocolModel):
    execution_parent_header: CapturedHeader
    pin: RuntimePinObject
    metadata_hex: Annotated[str, Field(min_length=3)]
    metadata_sha256: Hex32
    runtime_version_hex: Annotated[str, Field(min_length=3)]
    runtime_version_sha256: Hex32

    @model_validator(mode="after")
    def validate_bytes(self) -> Self:
        metadata = _unhex(self.metadata_hex, "runtime_metadata_invalid", MAX_METADATA_BYTES)
        version = _unhex(
            self.runtime_version_hex,
            "runtime_version_invalid",
            MAX_RUNTIME_VERSION_BYTES,
        )
        if hashlib.sha256(metadata).hexdigest() != self.metadata_sha256:
            raise ValueError("runtime metadata digest does not reproduce")
        if self.pin.metadata_sha256 != self.metadata_sha256:
            raise ValueError("runtime metadata differs from its runtime pin")
        if hashlib.sha256(version).hexdigest() != self.runtime_version_sha256:
            raise ValueError("runtime-version digest does not reproduce")
        _canonical_mapping(version, "runtime version")
        return self


class CapturedFinality(StrictProtocolModel):
    attestation_hex: Annotated[str, Field(min_length=3)]
    attestation_sha256: Hex32
    replay_binding: FinalityReplayBindingObject
    acceptance_receipt_hex: Annotated[str, Field(min_length=3)]
    acceptance_receipt_sha256: Hex32
    descendant_headers: Annotated[
        list[CapturedHeader], Field(max_length=MAX_FINALITY_ANCESTRY_HEADERS)
    ] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_bytes(self) -> Self:
        attestation = _unhex(
            self.attestation_hex,
            "finality_attestation_invalid",
            MAX_FINALITY_BYTES,
        )
        acceptance = _unhex(
            self.acceptance_receipt_hex,
            "finality_acceptance_invalid",
            4_096,
        )
        if hashlib.sha256(attestation).hexdigest() != self.attestation_sha256:
            raise ValueError("finality attestation digest does not reproduce")
        if hashlib.sha256(acceptance).hexdigest() != self.acceptance_receipt_sha256:
            raise ValueError("finality acceptance digest does not reproduce")
        parse_finality_acceptance_receipt(acceptance)
        return self


class CapturedSystemEvents(StrictProtocolModel):
    storage_key_hex: Annotated[str, Field(min_length=3)]
    value_hex: Annotated[str, Field(min_length=3)]
    value_sha256: Hex32
    proof_node_hex: Annotated[list[str], Field(min_length=1, max_length=MAX_PROOF_NODES)]

    @model_validator(mode="after")
    def validate_bytes(self) -> Self:
        key = _unhex(self.storage_key_hex, "system_events_key_invalid", 512)
        value = _unhex(self.value_hex, "system_events_value_invalid", MAX_EVENTS_BYTES)
        if hashlib.sha256(value).hexdigest() != self.value_sha256:
            raise ValueError("System.Events value digest does not reproduce")
        total = 0
        seen: set[bytes] = set()
        for encoded in self.proof_node_hex:
            node = _unhex(encoded, "system_events_proof_invalid", MAX_PROOF_NODE_BYTES)
            total += len(node)
            if total > MAX_PROOF_BYTES or node in seen:
                raise ValueError("System.Events proof is oversized or contains a duplicate")
            seen.add(node)
        if not key:
            raise ValueError("System.Events key is empty")
        return self


class CapturedBootstrapBlock(StrictProtocolModel):
    schema_: Literal[BOOTSTRAP_CHAIN_BLOCK_SCHEMA] = Field(alias="schema")
    role: Literal["owner_fence", "manifest_anchor", "weight_call"]
    header: CapturedHeader
    extrinsic_index: Annotated[int, Field(ge=0, le=(1 << 32) - 1)]
    target_extrinsic_sha256: Hex32
    target_extrinsic_blake2b256: BlockHash
    body_sha256: Hex32
    extrinsics_hex: Annotated[list[str], Field(min_length=1, max_length=MAX_EXTRINSICS)]
    raw_rpc_capture_hex: Annotated[str, Field(min_length=3)]
    raw_rpc_capture_sha256: Hex32
    runtime: CapturedRuntime
    system_events: CapturedSystemEvents
    finality: CapturedFinality

    @model_validator(mode="after")
    def validate_body(self) -> Self:
        source = _unhex(
            self.raw_rpc_capture_hex,
            "raw_rpc_capture_invalid",
            MAX_RAW_RPC_CAPTURE_BYTES,
        )
        if hashlib.sha256(source).hexdigest() != self.raw_rpc_capture_sha256:
            raise ValueError("raw RPC capture digest does not reproduce")
        _canonical_mapping(source, "raw RPC capture")
        if self.runtime.execution_parent_header.number + 1 != self.header.number:
            raise ValueError("execution-runtime parent height is not adjacent")
        if self.runtime.execution_parent_header.block_hash != self.header.parent_hash:
            raise ValueError("execution-runtime parent is not the captured block parent")
        if self.extrinsic_index >= len(self.extrinsics_hex):
            raise ValueError("target extrinsic index is outside the block body")
        values: list[bytes] = []
        total = 0
        for encoded in self.extrinsics_hex:
            raw = _unhex(encoded, "block_extrinsic_invalid", MAX_EXTRINSIC_BYTES)
            total += len(raw)
            if total > MAX_BLOCK_BODY_BYTES:
                raise ValueError("captured block body exceeds the byte limit")
            values.append(raw)
        if _body_sha256(values) != self.body_sha256:
            raise ValueError("captured block-body digest does not reproduce")
        target = values[self.extrinsic_index]
        if hashlib.sha256(target).hexdigest() != self.target_extrinsic_sha256:
            raise ValueError("target extrinsic SHA-256 does not reproduce")
        target_blake = "0x" + hashlib.blake2b(target, digest_size=32).hexdigest()
        if target_blake != self.target_extrinsic_blake2b256:
            raise ValueError("target extrinsic Blake2 hash does not reproduce")
        return self


class BootstrapChainCapture(StrictProtocolModel):
    schema_: Literal[BOOTSTRAP_CHAIN_CAPTURE_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    network: Literal["finney"]
    netuid: Literal[78]
    mechanism_id: Literal[0]
    submission_id: Hex32
    blocks: Annotated[list[CapturedBootstrapBlock], Field(min_length=3, max_length=3)]

    @model_validator(mode="after")
    def validate_roles(self) -> Self:
        if [item.role for item in self.blocks] != [
            "owner_fence",
            "manifest_anchor",
            "weight_call",
        ]:
            raise ValueError("chain capture roles must be complete and in protocol order")
        references = [(item.header.block_hash, item.extrinsic_index) for item in self.blocks]
        if len(set(references)) != len(references):
            raise ValueError("chain capture repeats one indexed extrinsic")
        return self


class OwnerCliEvidence(StrictProtocolModel):
    schema_: Literal[BOOTSTRAP_OWNER_CLI_EVIDENCE_SCHEMA] = Field(alias="schema")
    success: Literal[True]
    message: Literal["Success"]
    block_number: Annotated[int, Field(gt=0, le=(1 << 53) - 1)]
    block_hash: BlockHash
    extrinsic_index: Annotated[int, Field(ge=0, le=(1 << 32) - 1)]
    extrinsic_id: Annotated[str, Field(min_length=6, max_length=128)]
    raw_response_sha256: Hex32

    @model_validator(mode="after")
    def validate_id(self) -> Self:
        if self.extrinsic_id != f"{self.block_number}-{self.extrinsic_index:04d}":
            raise ValueError("owner CLI extrinsic ID is not canonical")
        return self


class ChainBlockArchiveEntry(StrictProtocolModel):
    role: Literal["owner_fence", "manifest_anchor", "weight_call"]
    block_number: Annotated[int, Field(gt=0)]
    block_hash: BlockHash
    extrinsic_index: Annotated[int, Field(ge=0)]
    semantic_call: Annotated[str, Field(min_length=3, max_length=128)]
    target_extrinsic_sha256: Hex32
    target_extrinsic_blake2b256: BlockHash
    raw_rpc_capture: ArchiveObjectRef
    header: ArchiveObjectRef
    execution_parent_header: ArchiveObjectRef
    runtime_metadata: ArchiveObjectRef
    runtime_version: ArchiveObjectRef
    complete_extrinsics: Annotated[list[ArchiveObjectRef], Field(min_length=1)]
    system_events_key: ArchiveObjectRef
    system_events_value: ArchiveObjectRef
    system_events_proof_nodes: Annotated[list[ArchiveObjectRef], Field(min_length=1)]
    finality_attestation: ArchiveObjectRef
    finality_acceptance_receipt: ArchiveObjectRef
    finality_descendant_headers: Annotated[
        list[ArchiveObjectRef], Field(max_length=MAX_FINALITY_ANCESTRY_HEADERS)
    ]
    header_hash_verified: Literal[True]
    finality_attestation_replayed: Literal[True]
    extrinsics_root_verified: Literal[True]
    system_events_storage_proof_verified: Literal[True]
    runtime_decode_verified: Literal[True]
    extrinsic_success_verified: Literal[True]

    def references(self) -> tuple[ArchiveObjectRef, ...]:
        return (
            self.raw_rpc_capture,
            self.header,
            self.execution_parent_header,
            self.runtime_metadata,
            self.runtime_version,
            *self.complete_extrinsics,
            self.system_events_key,
            self.system_events_value,
            *self.system_events_proof_nodes,
            self.finality_attestation,
            self.finality_acceptance_receipt,
            *self.finality_descendant_headers,
        )


class BootstrapCompleteArchiveManifest(StrictProtocolModel):
    schema_: Literal[BOOTSTRAP_COMPLETE_ARCHIVE_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    network: Literal["finney"]
    netuid: Literal[78]
    mechanism_id: Literal[0]
    submission_id: Hex32
    validator_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    validator_uid: Annotated[int, Field(ge=0, le=255)]
    umi_git_revision: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
    signed_result_sha256: Hex32
    signed_result: ArchiveObjectRef
    owner_cli_response: ArchiveObjectRef
    owner_cli_evidence: ArchiveObjectRef
    captured_chain_material: ArchiveObjectRef
    observer_publication_manifest: ArchiveObjectRef
    observer_publication_id: Hex32
    observer_publication_objects: Annotated[
        list[ArchiveObjectRef], Field(min_length=6, max_length=6)
    ]
    blocks: Annotated[list[ChainBlockArchiveEntry], Field(min_length=3, max_length=3)]
    objects: Annotated[list[ArchiveObjectRef], Field(min_length=20)]
    complete_archive_bytes: Annotated[int, Field(gt=0, le=MAX_ARCHIVE_BYTES)]
    signed_result_verified: Literal[True]
    chain_material_replayed: Literal[True]
    observer_publication_rebuilt: Literal[True]

    @field_validator("validator_hotkey")
    @classmethod
    def validate_hotkey(cls, value: str) -> str:
        account_id32(value)
        return value

    @model_validator(mode="after")
    def validate_manifest(self) -> Self:
        if not _GIT_REVISION_RE.fullmatch(self.umi_git_revision):
            raise ValueError("UMI revision is invalid")
        if [item.role for item in self.blocks] != [
            "owner_fence",
            "manifest_anchor",
            "weight_call",
        ]:
            raise ValueError("archive block roles are incomplete")
        if self.signed_result.sha256 != self.signed_result_sha256:
            raise ValueError("signed result reference and summary disagree")
        refs = self.required_references()
        table = {item.sha256: item for item in self.objects}
        if list(table) != sorted(table) or len(table) != len(self.objects):
            raise ValueError("archive object table must be unique and digest sorted")
        for reference in refs:
            if table.get(reference.sha256) != reference:
                raise ValueError("archive object table omits or changes a required object")
        expected_archive_bytes = len(canonical_json_bytes(self)) + sum(
            item.size_bytes for item in self.objects
        )
        if self.complete_archive_bytes != expected_archive_bytes:
            raise ValueError("archive byte accounting does not reproduce")
        return self

    def required_references(self) -> tuple[ArchiveObjectRef, ...]:
        values = [
            self.signed_result,
            self.owner_cli_response,
            self.owner_cli_evidence,
            self.captured_chain_material,
            self.observer_publication_manifest,
            *self.observer_publication_objects,
        ]
        for block in self.blocks:
            values.extend(block.references())
        return tuple(values)


class ProofVerifier(Protocol):
    def verify_extrinsics_root(
        self, *, expected_root: bytes, extrinsics: tuple[bytes, ...], state_version: int
    ) -> bool: ...

    def __call__(
        self,
        *,
        state_root: bytes,
        storage_key: bytes,
        expected_value: bytes | None,
        proof: tuple[bytes, ...],
    ) -> bool: ...


class FinalityVerifier(Protocol):
    def validate_attestation(self, encoded: bytes, **kwargs: Any) -> Any: ...


class RuntimeFactory(Protocol):
    def __call__(self, metadata: bytes, pin: RuntimePinObject) -> Any: ...


@dataclass(frozen=True, slots=True)
class BootstrapResultIntakePorts:
    proof_verifier: ProofVerifier
    finality_observer: FinalityVerifier
    runtime_factory: RuntimeFactory | None = None

    def __post_init__(self) -> None:
        if not callable(self.proof_verifier) or not callable(
            getattr(self.proof_verifier, "verify_extrinsics_root", None)
        ):
            raise TypeError("proof_verifier does not implement both proof checks")
        if not callable(getattr(self.finality_observer, "validate_attestation", None)):
            raise TypeError("finality_observer must replay finality attestations")
        if self.runtime_factory is not None and not callable(self.runtime_factory):
            raise TypeError("runtime_factory must be callable")


def _unhex(value: str, reason: str, maximum_bytes: int, *, allow_empty: bool = False) -> bytes:
    if not isinstance(value, str) or _HEX_BYTES_RE.fullmatch(value) is None:
        raise ValueError(reason)
    if len(value) > 2 + maximum_bytes * 2:
        raise ValueError(reason)
    raw = bytes.fromhex(value[2:])
    if not raw and not allow_empty:
        raise ValueError(reason)
    return raw


def _canonical_mapping(value: bytes, label: str) -> Mapping[str, Any]:
    try:
        decoded = json.loads(value, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError(f"{label} is not valid JSON") from error
    if not isinstance(decoded, Mapping) or canonical_json_bytes(decoded) != value:
        raise ValueError(f"{label} is not a canonical JSON object")
    return decoded


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("JSON object contains a duplicate key")
        result[key] = value
    return result


def _body_sha256(extrinsics: Sequence[bytes]) -> str:
    digest = hashlib.sha256(b"umi-finalized-block-body-v1\0")
    digest.update(len(extrinsics).to_bytes(4, "big"))
    for value in extrinsics:
        digest.update(len(value).to_bytes(4, "big"))
        digest.update(value)
    return digest.hexdigest()


def _parse_owner_cli_response(raw: bytes) -> OwnerCliEvidence:
    if not raw or len(raw) > MAX_OWNER_CLI_BYTES:
        raise ValueError("owner CLI response has an invalid size")
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError("owner CLI response is not valid unique-key JSON") from error
    if not isinstance(value, Mapping):
        raise ValueError("owner CLI response is not an object")
    required = {"success", "message", "block_hash", "extrinsic_id"}
    if (
        not required.issubset(value)
        or value["success"] is not True
        or value["message"] != "Success"
    ):
        raise ValueError("owner CLI response does not report success")
    extrinsic_id = value["extrinsic_id"]
    if (
        not isinstance(extrinsic_id, str)
        or re.fullmatch(r"[1-9][0-9]*-[0-9]{4}", extrinsic_id) is None
    ):
        raise ValueError("owner CLI response has an invalid extrinsic ID")
    number_text, index_text = extrinsic_id.split("-", 1)
    return OwnerCliEvidence(
        schema=BOOTSTRAP_OWNER_CLI_EVIDENCE_SCHEMA,
        success=True,
        message="Success",
        block_number=int(number_text),
        block_hash=value["block_hash"],
        extrinsic_index=int(index_text),
        extrinsic_id=extrinsic_id,
        raw_response_sha256=hashlib.sha256(raw).hexdigest(),
    )


def parse_canonical_chain_capture(raw: bytes) -> BootstrapChainCapture:
    if not raw or len(raw) > MAX_CAPTURE_BYTES:
        raise ValueError("bootstrap chain capture size is invalid")
    capture = BootstrapChainCapture.model_validate_json(raw)
    if canonical_json_bytes(capture) != raw:
        raise ValueError("bootstrap chain capture is not RFC 8785 canonical JSON")
    return capture


def _runtime_for(
    block: CapturedBootstrapBlock,
    factory: RuntimeFactory | None,
) -> tuple[Any, bytes, bytes, bytes]:
    metadata = _unhex(block.runtime.metadata_hex, "runtime_metadata_invalid", MAX_METADATA_BYTES)
    version_bytes = _unhex(
        block.runtime.runtime_version_hex,
        "runtime_version_invalid",
        MAX_RUNTIME_VERSION_BYTES,
    )
    version = _canonical_mapping(version_bytes, "runtime version")
    pin = block.runtime.pin
    if (
        version.get("specVersion") != pin.spec_version
        or version.get("transactionVersion") != pin.transaction_version
        or version.get("stateVersion") != pin.state_version
    ):
        raise ValueError("runtime version differs from its pin")
    try:
        runtime = (
            bittensor_core.Runtime(
                metadata,
                pin.spec_version,
                pin.transaction_version,
                ss58_format=pin.ss58_prefix,
            )
            if factory is None
            else factory(metadata, pin)
        )
        if runtime.constant("System", "SS58Prefix") != pin.ss58_prefix:
            raise ValueError("runtime SS58 prefix differs from its pin")
        storage_key = runtime.storage_key("System", "Events", [])
    except Exception as error:
        raise ValueError("captured runtime cannot be reconstructed") from error
    if not isinstance(storage_key, bytes) or not storage_key:
        raise ValueError("runtime produced an invalid System.Events key")
    return runtime, metadata, version_bytes, storage_key


def _verify_finality(
    block: CapturedBootstrapBlock,
    observer: FinalityVerifier,
) -> tuple[bytes, bytes, tuple[CapturedHeader, ...]]:
    finality = block.finality
    attestation_bytes = _unhex(
        finality.attestation_hex,
        "finality_attestation_invalid",
        MAX_FINALITY_BYTES,
    )
    acceptance_bytes = _unhex(
        finality.acceptance_receipt_hex,
        "finality_acceptance_invalid",
        4_096,
    )
    binding = finality.replay_binding.to_evidence()
    accepted = observer.validate_attestation(
        attestation_bytes,
        minimum_finalized_block=binding.minimum_finalized_block,
        maximum_records=binding.maximum_records,
        startup_timeout_seconds=binding.startup_timeout_seconds,
        expected_sequence=binding.expected_sequence,
        previous_hash=binding.previous_hash,
        previous_digest=binding.previous_digest,
        previous_number=binding.previous_number,
        previous_timestamp_ms=binding.previous_timestamp_ms,
    )
    target = (block.header.number, block.header.block_hash, block.header.parent_hash)
    represented = (
        accepted.block.number,
        accepted.block.hash,
        accepted.block.parent_hash,
    ) == target or target in accepted.ancestry
    bridge = tuple(finality.descendant_headers)
    if represented and bridge:
        raise ValueError("finality descendant bridge is redundant")
    if not represented:
        if not bridge:
            raise ValueError("finality attestation does not cover the captured block")
        previous_number = block.header.number
        previous_hash = block.header.block_hash
        for header in bridge:
            if (
                header.number != previous_number + 1
                or header.parent_hash != previous_hash
            ):
                raise ValueError("finality descendant bridge is not contiguous")
            previous_number = header.number
            previous_hash = header.block_hash
        final_header = bridge[-1]
        if (
            final_header.number != accepted.block.number
            or final_header.block_hash != accepted.block.hash
            or final_header.parent_hash != accepted.block.parent_hash
            or final_header.state_root != accepted.block.state_root
            or final_header.extrinsics_root != accepted.block.extrinsics_root
        ):
            raise ValueError("finality descendant bridge does not end at the attested head")
    receipt = parse_finality_acceptance_receipt(acceptance_bytes)
    if (
        receipt.height != accepted.block.number
        or receipt.block_hash != accepted.block.hash
        or receipt.evidence_sha256 != finality.attestation_sha256
    ):
        raise ValueError("finality acceptance receipt binds another attestation")
    return attestation_bytes, acceptance_bytes, bridge


def _semantic_call(
    block: CapturedBootstrapBlock,
    signed: SignedSupervisorBootstrapResult,
    runtime: Any,
    events_value: bytes,
    extrinsics: tuple[bytes, ...],
) -> str:
    try:
        decoded_extrinsics = tuple(runtime.decode_extrinsic(raw, True) for raw in extrinsics)
        decoded_events = runtime.decode(
            runtime.storage_entry("System", "Events").value_type, events_value, strict=True
        )
        if isinstance(decoded_events, (str, bytes, bytearray)) or not isinstance(
            decoded_events, Sequence
        ):
            raise ValueError("decoded events are not a sequence")
        statuses = _extrinsic_statuses(decoded_events, len(extrinsics))
        decoded = decoded_extrinsics[block.extrinsic_index]
        if not isinstance(decoded, Mapping) or not statuses[block.extrinsic_index]:
            raise ValueError("target extrinsic was not successful")
        expected_extrinsic_hash = block.target_extrinsic_blake2b256
        if decoded.get("extrinsic_hash") != expected_extrinsic_hash:
            raise ValueError("decoded target extrinsic hash differs")
        signer = _account(decoded.get("address"), "target_extrinsic_signer_invalid")
        call = decoded.get("call")
        if not isinstance(call, Mapping):
            raise ValueError("target root call is missing")
        module, function, _call_hash, args = _decoded_call_parts(call)
    except Exception as error:
        raise ValueError("captured target extrinsic or events cannot be decoded") from error

    result = signed.result
    if block.role == "owner_fence":
        expected_owner = bytes.fromhex(
            result.owner_fence_receipt.call_material.preflight.subnet_owner_coldkey_account_id32[2:]
        )
        if signer != expected_owner or (module, function) != ("Utility", "batch_all"):
            raise ValueError("owner-fence target signer or root call differs")
        children = args.get("calls")
        if isinstance(children, (str, bytes, bytearray)) or not isinstance(children, Sequence):
            raise ValueError("owner-fence batch omits its ordered inner calls")
        decoded_children = [_decoded_call_parts(child) for child in children]
        expected = (
            (
                "AdminUtils",
                "sudo_set_weights_version_key",
                "weights_version_key",
                DIRECT_MINIMUM_WEIGHTS_VERSION_KEY,
            ),
            ("AdminUtils", "sudo_set_min_allowed_weights", "min_allowed_weights", 256),
            ("AdminUtils", "sudo_set_commit_reveal_weights_enabled", "enabled", False),
        )
        if len(decoded_children) != len(expected):
            raise ValueError("owner-fence batch contains another number of calls")
        for (child_module, child_function, _hash, child_args), expectation in zip(
            decoded_children, expected, strict=True
        ):
            expected_module, expected_function, value_name, expected_value = expectation
            if (
                (child_module, child_function) != (expected_module, expected_function)
                or child_args.get("netuid") != 78
                or child_args.get(value_name) != expected_value
            ):
                raise ValueError("owner-fence batch contains another inner call")
        return "Utility.batch_all(owner_fence)"

    expected_validator = account_id32(result.validator_hotkey)
    if signer != expected_validator:
        raise ValueError("bootstrap target extrinsic has another signer")
    if block.role == "manifest_anchor":
        binding = _commitment_call_binding(decoded, block.extrinsic_index)
        if (
            binding is None
            or binding.netuid != 78
            or binding.field_sha256 != result.signed_manifest.manifest_sha256
        ):
            raise ValueError("manifest-anchor call differs from the signed result")
        return "Commitments.set_commitment"

    if (module, function) != ("SubtensorModule", "set_mechanism_weights"):
        raise ValueError("weight target is not set_mechanism_weights")
    material = result.call_material
    if set(args) != {"netuid", "mecid", "dests", "weights", "version_key"}:
        raise ValueError("weight call arguments have another shape")
    if (
        args["netuid"] != material.netuid
        or args["mecid"] != material.mechanism_id
        or list(args["dests"]) != material.dests
        or list(args["weights"]) != material.weights
        or args["version_key"] != material.weights_version_key
    ):
        raise ValueError("weight call bytes differ from the signed call material")
    weight_events = [
        item
        for item in decoded_events
        if isinstance(item, Mapping)
        and item.get("module_id") == "SubtensorModule"
        and item.get("event_id") == "WeightsSet"
        and item.get("phase") == "ApplyExtrinsic"
        and item.get("extrinsic_idx") == block.extrinsic_index
    ]
    if len(weight_events) != 1:
        raise ValueError("weight call lacks one matching WeightsSet event")
    return "SubtensorModule.set_mechanism_weights"


def _expected_reference(
    role: str,
    signed: SignedSupervisorBootstrapResult,
    owner_cli: OwnerCliEvidence,
) -> tuple[int, str, int]:
    receipt = signed.result.submission_receipt
    if role == "owner_fence":
        return owner_cli.block_number, owner_cli.block_hash, owner_cli.extrinsic_index
    reference = receipt.anchor if role == "manifest_anchor" else receipt.weight_call
    return reference.block_number, reference.block_hash, reference.extrinsic_index


def _add_bytes(store: EvidenceStore, value: bytes, media_type: str) -> ArchiveObjectRef:
    return ArchiveObjectRef.from_ref(store.add_bytes(value, media_type))


def _add_json(
    store: EvidenceStore, value: Any, media_type: str = "application/json"
) -> ArchiveObjectRef:
    return _add_bytes(store, canonical_json_bytes(value), media_type)


def _replay_and_store_blocks(
    *,
    store: EvidenceStore,
    capture: BootstrapChainCapture,
    signed: SignedSupervisorBootstrapResult,
    owner_cli: OwnerCliEvidence,
    ports: BootstrapResultIntakePorts,
) -> list[ChainBlockArchiveEntry]:
    entries: list[ChainBlockArchiveEntry] = []
    for block in capture.blocks:
        expected = _expected_reference(block.role, signed, owner_cli)
        actual = (block.header.number, block.header.block_hash, block.extrinsic_index)
        if actual != expected:
            raise ValueError(f"{block.role} capture binds another indexed extrinsic")

        attestation, acceptance, descendant_headers = _verify_finality(
            block, ports.finality_observer
        )
        runtime, metadata, version, expected_events_key = _runtime_for(
            block,
            ports.runtime_factory,
        )
        extrinsics = tuple(
            _unhex(value, "block_extrinsic_invalid", MAX_EXTRINSIC_BYTES)
            for value in block.extrinsics_hex
        )
        events_key = _unhex(block.system_events.storage_key_hex, "system_events_key_invalid", 512)
        events_value = _unhex(
            block.system_events.value_hex,
            "system_events_value_invalid",
            MAX_EVENTS_BYTES,
        )
        proof = tuple(
            _unhex(value, "system_events_proof_invalid", MAX_PROOF_NODE_BYTES)
            for value in block.system_events.proof_node_hex
        )
        if events_key != expected_events_key:
            raise ValueError("captured System.Events key differs from the pinned runtime")
        if (
            ports.proof_verifier.verify_extrinsics_root(
                expected_root=bytes.fromhex(block.header.extrinsics_root[2:]),
                extrinsics=extrinsics,
                state_version=block.runtime.pin.state_version,
            )
            is not True
        ):
            raise ValueError("captured block body failed extrinsics-root verification")
        if (
            ports.proof_verifier(
                state_root=bytes.fromhex(block.header.state_root[2:]),
                storage_key=events_key,
                expected_value=events_value,
                proof=proof,
            )
            is not True
        ):
            raise ValueError("captured System.Events bytes failed storage-proof verification")
        semantic = _semantic_call(block, signed, runtime, events_value, extrinsics)

        target = extrinsics[block.extrinsic_index]
        raw_rpc_ref = _add_bytes(
            store,
            _unhex(
                block.raw_rpc_capture_hex,
                "raw_rpc_capture_invalid",
                MAX_RAW_RPC_CAPTURE_BYTES,
            ),
            "application/vnd.umi.bootstrap-raw-rpc-capture-v1+json",
        )
        header_ref = _add_json(
            store,
            block.header,
            "application/vnd.umi.substrate-header-v1+json",
        )
        parent_ref = _add_json(
            store,
            block.runtime.execution_parent_header,
            "application/vnd.umi.substrate-header-v1+json",
        )
        metadata_ref = _add_bytes(
            store,
            metadata,
            "application/vnd.umi.substrate-runtime-metadata",
        )
        version_ref = _add_bytes(
            store,
            version,
            "application/vnd.umi.substrate-runtime-version+json",
        )
        extrinsic_refs = [
            _add_bytes(store, value, "application/vnd.umi.substrate-extrinsic")
            for value in extrinsics
        ]
        key_ref = _add_bytes(
            store,
            events_key,
            "application/vnd.umi.substrate-storage-key",
        )
        events_ref = _add_bytes(
            store,
            events_value,
            "application/vnd.umi.substrate-system-events",
        )
        proof_refs = [
            _add_bytes(store, value, "application/vnd.umi.substrate-trie-proof-node")
            for value in proof
        ]
        attestation_ref = _add_bytes(
            store,
            attestation,
            "application/vnd.umi.smol-dot-finality-attestation+json",
        )
        acceptance_ref = _add_bytes(
            store,
            acceptance,
            "application/vnd.umi.smol-dot-finality-acceptance+json",
        )
        descendant_refs = [
            _add_json(
                store,
                header,
                "application/vnd.umi.substrate-header-v1+json",
            )
            for header in descendant_headers
        ]
        entries.append(
            ChainBlockArchiveEntry(
                role=block.role,
                block_number=block.header.number,
                block_hash=block.header.block_hash,
                extrinsic_index=block.extrinsic_index,
                semantic_call=semantic,
                target_extrinsic_sha256=hashlib.sha256(target).hexdigest(),
                target_extrinsic_blake2b256=(
                    "0x" + hashlib.blake2b(target, digest_size=32).hexdigest()
                ),
                raw_rpc_capture=raw_rpc_ref,
                header=header_ref,
                execution_parent_header=parent_ref,
                runtime_metadata=metadata_ref,
                runtime_version=version_ref,
                complete_extrinsics=extrinsic_refs,
                system_events_key=key_ref,
                system_events_value=events_ref,
                system_events_proof_nodes=proof_refs,
                finality_attestation=attestation_ref,
                finality_acceptance_receipt=acceptance_ref,
                finality_descendant_headers=descendant_refs,
                header_hash_verified=True,
                finality_attestation_replayed=True,
                extrinsics_root_verified=True,
                system_events_storage_proof_verified=True,
                runtime_decode_verified=True,
                extrinsic_success_verified=True,
            )
        )
    return entries


def _copy_observer_publication(
    store: EvidenceStore,
    observer_root: Path,
) -> tuple[ArchiveObjectRef, str, list[ArchiveObjectRef]]:
    manifest_raw = _read_bounded_regular_file(
        observer_root / "manifest.json",
        MAX_ARCHIVE_MANIFEST_BYTES,
    )
    publication = BootstrapServicePublicationManifest.model_validate_json(manifest_raw)
    if canonical_json_bytes(publication) != manifest_raw:
        raise ValueError("observer publication manifest is not canonical")
    manifest_ref = _add_bytes(
        store,
        manifest_raw,
        "application/vnd.umi.bootstrap-direct-publication-v2+json",
    )
    observer_store = EvidenceStore(
        observer_root,
        maximum_object_bytes=MAX_ARCHIVE_OBJECT_BYTES,
        maximum_manifest_bytes=MAX_ARCHIVE_MANIFEST_BYTES,
        maximum_total_object_bytes=MAX_ARCHIVE_BYTES,
    )
    refs: list[ArchiveObjectRef] = []
    for reference in publication.object_references():
        raw = observer_store.read(ObjectRef(**reference.model_dump(mode="python")))
        refs.append(_add_bytes(store, raw, reference.media_type))
    return manifest_ref, hashlib.sha256(manifest_raw).hexdigest(), refs


def _unique_reference_table(references: Sequence[ArchiveObjectRef]) -> list[ArchiveObjectRef]:
    table: dict[str, ArchiveObjectRef] = {}
    for reference in references:
        previous = table.setdefault(reference.sha256, reference)
        if previous != reference:
            raise ValueError("one archive digest has conflicting type or length metadata")
    return [table[digest] for digest in sorted(table)]


def _complete_archive_size(payload: dict[str, Any], objects: Sequence[ArchiveObjectRef]) -> int:
    """Resolve the canonical manifest-length fixed point deterministically."""

    object_bytes = sum(item.size_bytes for item in objects)
    candidate = object_bytes
    for _ in range(8):
        payload["complete_archive_bytes"] = candidate
        updated = object_bytes + len(canonical_json_bytes(payload))
        if updated == candidate:
            return candidate
        candidate = updated
    raise RuntimeError("bootstrap archive byte accounting did not converge")


def build_bootstrap_result_archive(
    *,
    signed_result_bytes: bytes,
    owner_cli_response_bytes: bytes,
    captured_chain_material_bytes: bytes,
    archive_root: Path,
    observer_publication_root: Path,
    ports: BootstrapResultIntakePorts,
) -> tuple[Path, Path]:
    """Verify inputs and atomically materialize the archive and observer bundle."""

    if archive_root.exists() or observer_publication_root.exists():
        raise FileExistsError("bootstrap intake outputs must not already exist")
    if archive_root.resolve() == observer_publication_root.resolve():
        raise ValueError("archive and observer publication roots must differ")
    signed = parse_canonical_signed_supervisor_bootstrap_result(signed_result_bytes)
    owner_cli = _parse_owner_cli_response(owner_cli_response_bytes)
    capture = parse_canonical_chain_capture(captured_chain_material_bytes)
    if capture.submission_id != signed.result.submission_id:
        raise ValueError("chain capture binds another submission")

    archive_parent = archive_root.resolve().parent
    observer_parent = observer_publication_root.resolve().parent
    archive_parent.mkdir(parents=True, exist_ok=True)
    observer_parent.mkdir(parents=True, exist_ok=True)
    temporary_archive = Path(tempfile.mkdtemp(prefix=".bootstrap-archive-", dir=archive_parent))
    temporary_observer = Path(tempfile.mkdtemp(prefix=".bootstrap-observer-", dir=observer_parent))
    # The builder requires a nonexistent target rather than an already-created
    # mkdtemp directory.
    temporary_observer.rmdir()
    try:
        result = signed.result
        build_bootstrap_service_publication(
            owner_fence_receipt=result.owner_fence_receipt,
            signed_manifest=result.signed_manifest,
            authorization=result.transition_authorization,
            call_material=result.call_material,
            submission_receipt=result.submission_receipt,
            submission_journal=result.submission_journal,
            output_root=temporary_observer,
        )
        store = EvidenceStore(
            temporary_archive,
            maximum_object_bytes=MAX_ARCHIVE_OBJECT_BYTES,
            maximum_manifest_bytes=MAX_ARCHIVE_MANIFEST_BYTES,
            maximum_total_object_bytes=MAX_ARCHIVE_BYTES,
        )
        signed_ref = _add_bytes(
            store,
            signed_result_bytes,
            "application/vnd.umi.validator-supervisor-signed-bootstrap-result-v1+json",
        )
        owner_raw_ref = _add_bytes(
            store,
            owner_cli_response_bytes,
            "application/vnd.bittensor.btcli-result+json",
        )
        owner_ref = _add_json(
            store,
            owner_cli,
            "application/vnd.umi.bootstrap-owner-cli-evidence-v1+json",
        )
        capture_ref = _add_bytes(
            store,
            captured_chain_material_bytes,
            "application/vnd.umi.bootstrap-chain-capture-v1+json",
        )
        block_entries = _replay_and_store_blocks(
            store=store,
            capture=capture,
            signed=signed,
            owner_cli=owner_cli,
            ports=ports,
        )
        observer_manifest_ref, observer_id, observer_refs = _copy_observer_publication(
            store,
            temporary_observer,
        )
        required: list[ArchiveObjectRef] = [
            signed_ref,
            owner_raw_ref,
            owner_ref,
            capture_ref,
            observer_manifest_ref,
            *observer_refs,
        ]
        for block in block_entries:
            required.extend(block.references())
        objects = _unique_reference_table(required)
        manifest_payload = {
            "schema": BOOTSTRAP_COMPLETE_ARCHIVE_SCHEMA,
            "protocol": PROTOCOL_VERSION,
            "network": "finney",
            "netuid": 78,
            "mechanism_id": 0,
            "submission_id": result.submission_id,
            "validator_hotkey": result.validator_hotkey,
            "validator_uid": result.transition_authorization.validator_uid,
            "umi_git_revision": result.transition_authorization.umi_git_revision,
            "signed_result_sha256": hashlib.sha256(signed_result_bytes).hexdigest(),
            "signed_result": signed_ref.model_dump(mode="json"),
            "owner_cli_response": owner_raw_ref.model_dump(mode="json"),
            "owner_cli_evidence": owner_ref.model_dump(mode="json"),
            "captured_chain_material": capture_ref.model_dump(mode="json"),
            "observer_publication_manifest": observer_manifest_ref.model_dump(mode="json"),
            "observer_publication_id": observer_id,
            "observer_publication_objects": [
                item.model_dump(mode="json") for item in observer_refs
            ],
            "blocks": [item.model_dump(mode="json") for item in block_entries],
            "objects": [item.model_dump(mode="json") for item in objects],
            "complete_archive_bytes": 0,
            "signed_result_verified": True,
            "chain_material_replayed": True,
            "observer_publication_rebuilt": True,
        }
        manifest_payload["complete_archive_bytes"] = _complete_archive_size(
            manifest_payload,
            objects,
        )
        manifest = BootstrapCompleteArchiveManifest.model_validate(manifest_payload)
        manifest_path = store.write_manifest(manifest.model_dump(mode="json", by_alias=True))
        # Replay from the just-written immutable representation before exposing
        # either output directory to the observer service.
        verify_bootstrap_result_archive(temporary_archive, ports=ports)
        if archive_root.exists() or observer_publication_root.exists():
            raise FileExistsError("bootstrap intake output appeared during verification")
        os.rename(temporary_archive, archive_root)
        try:
            os.rename(temporary_observer, observer_publication_root)
        except Exception:
            # Move the unpublished archive back into the private temporary name
            # so the common cleanup path can restore the all-or-nothing result.
            os.rename(archive_root, temporary_archive)
            raise
        return archive_root / manifest_path.name, observer_publication_root / "manifest.json"
    except Exception:
        shutil.rmtree(temporary_archive, ignore_errors=True)
        shutil.rmtree(temporary_observer, ignore_errors=True)
        raise


def _load_archive_object(
    store: EvidenceStore,
    reference: ArchiveObjectRef,
) -> bytes:
    return store.read(reference.to_ref())


def verify_bootstrap_result_archive(
    archive_root: Path,
    *,
    ports: BootstrapResultIntakePorts,
) -> BootstrapCompleteArchiveManifest:
    """Replay every signed, hash, root, proof, runtime, and call binding."""

    for path, directory in (
        (archive_root, True),
        (archive_root / "objects", True),
        (archive_root / "manifest.json", False),
    ):
        try:
            metadata = path.lstat()
        except OSError as error:
            raise ValueError("bootstrap archive layout is incomplete") from error
        expected_type = stat.S_ISDIR if directory else stat.S_ISREG
        if path.is_symlink() or not expected_type(metadata.st_mode):
            raise ValueError("bootstrap archive layout contains an unsafe path")
        if metadata.st_uid != os.geteuid() or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise ValueError("bootstrap archive layout has unsafe ownership or permissions")
        if not directory and metadata.st_nlink != 1:
            raise ValueError("bootstrap archive manifest must have one hard link")

    store = EvidenceStore(
        archive_root,
        maximum_object_bytes=MAX_ARCHIVE_OBJECT_BYTES,
        maximum_manifest_bytes=MAX_ARCHIVE_MANIFEST_BYTES,
        maximum_total_object_bytes=MAX_ARCHIVE_BYTES,
    )
    manifest_value, manifest_bytes = store.load_manifest_with_bytes()
    manifest = BootstrapCompleteArchiveManifest.model_validate(manifest_value)
    if canonical_json_bytes(manifest) != manifest_bytes:
        raise ValueError("bootstrap archive manifest is not canonical")
    expected_names = {item.sha256 for item in manifest.objects}
    object_paths = tuple((archive_root / "objects").iterdir())
    if any(path.is_symlink() or not path.is_file() for path in object_paths):
        raise ValueError("bootstrap archive object directory contains an unsafe entry")
    actual_names = {path.name for path in object_paths}
    if actual_names != expected_names:
        raise ValueError("bootstrap archive object directory differs from its manifest")
    for reference in manifest.objects:
        _load_archive_object(store, reference)

    signed_bytes = _load_archive_object(store, manifest.signed_result)
    signed = parse_canonical_signed_supervisor_bootstrap_result(signed_bytes)
    if (
        signed.result.submission_id != manifest.submission_id
        or account_id32(signed.result.validator_hotkey) != account_id32(manifest.validator_hotkey)
        or signed.result.transition_authorization.validator_uid != manifest.validator_uid
        or signed.result.transition_authorization.umi_git_revision != manifest.umi_git_revision
    ):
        raise ValueError("archive summary differs from its signed validator result")
    owner_cli = _parse_owner_cli_response(_load_archive_object(store, manifest.owner_cli_response))
    owner_evidence = OwnerCliEvidence.model_validate_json(
        _load_archive_object(store, manifest.owner_cli_evidence)
    )
    if owner_cli != owner_evidence:
        raise ValueError("owner CLI normalized evidence does not reproduce")
    capture_bytes = _load_archive_object(store, manifest.captured_chain_material)
    capture = parse_canonical_chain_capture(capture_bytes)
    replay_entries = _replay_and_store_blocks(
        store=store,
        capture=capture,
        signed=signed,
        owner_cli=owner_cli,
        ports=ports,
    )
    if replay_entries != manifest.blocks:
        raise ValueError("archive chain replay differs from the indexed block evidence")

    publication_bytes = _load_archive_object(store, manifest.observer_publication_manifest)
    publication = BootstrapServicePublicationManifest.model_validate_json(publication_bytes)
    if (
        canonical_json_bytes(publication) != publication_bytes
        or hashlib.sha256(publication_bytes).hexdigest() != manifest.observer_publication_id
        or publication.submission_id != manifest.submission_id
    ):
        raise ValueError("archived observer publication does not reproduce")
    expected_publication_refs = list(publication.object_references())
    if [item.model_dump(mode="python") for item in manifest.observer_publication_objects] != [
        item.model_dump(mode="python") for item in expected_publication_refs
    ]:
        raise ValueError("archived observer publication object table differs")
    return manifest


def _build_ports(args: argparse.Namespace) -> BootstrapResultIntakePorts:
    proof = SubprocessStorageProofVerifier(
        binary_path=Path(args.proof_verifier).resolve(),
        expected_sha256=args.proof_verifier_sha256,
        timeout_seconds=args.proof_timeout_seconds,
    )
    observer = GrandpaFinalityObserver(
        binary_path=Path(args.finality_verifier).resolve(),
        expected_binary_sha256=args.finality_verifier_sha256,
        chain_spec_path=Path(args.chain_spec).resolve(),
        expected_chain_spec_sha256=args.chain_spec_sha256,
        expected_genesis_hash=args.genesis_hash,
        bootstrap_block_number=args.bootstrap_block_number,
        bootstrap_block_hash=args.bootstrap_block_hash,
    )
    return BootstrapResultIntakePorts(proof_verifier=proof, finality_observer=observer)


def _common_verifier_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--proof-verifier", required=True)
    parser.add_argument("--proof-verifier-sha256", required=True)
    parser.add_argument("--proof-timeout-seconds", type=float, default=10.0)
    parser.add_argument("--finality-verifier", required=True)
    parser.add_argument("--finality-verifier-sha256", required=True)
    parser.add_argument("--chain-spec", required=True)
    parser.add_argument("--chain-spec-sha256", required=True)
    parser.add_argument("--genesis-hash", required=True)
    parser.add_argument("--bootstrap-block-number", type=int, required=True)
    parser.add_argument("--bootstrap-block-hash", required=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="umi-bootstrap-result-intake",
        description="Verify and archive a signed bootstrap result with coordinator chain evidence",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    intake = commands.add_parser("intake")
    intake.add_argument("--signed-result", type=Path, required=True)
    intake.add_argument("--owner-cli-result", type=Path, required=True)
    intake.add_argument("--chain-capture", type=Path, required=True)
    intake.add_argument("--archive-root", type=Path, required=True)
    intake.add_argument("--observer-publication-root", type=Path, required=True)
    _common_verifier_arguments(intake)
    verify = commands.add_parser("verify")
    verify.add_argument("--archive-root", type=Path, required=True)
    _common_verifier_arguments(verify)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    ports = _build_ports(args)
    if args.command == "intake":
        manifest, publication = build_bootstrap_result_archive(
            signed_result_bytes=_read_bounded_regular_file(
                args.signed_result,
                4 * 1024 * 1024,
            ),
            owner_cli_response_bytes=_read_bounded_regular_file(
                args.owner_cli_result,
                MAX_OWNER_CLI_BYTES,
            ),
            captured_chain_material_bytes=_read_bounded_regular_file(
                args.chain_capture,
                MAX_CAPTURE_BYTES,
            ),
            archive_root=args.archive_root,
            observer_publication_root=args.observer_publication_root,
            ports=ports,
        )
        print(
            canonical_json_bytes(
                {
                    "archive_manifest": str(manifest.resolve()),
                    "observer_publication_manifest": str(publication.resolve()),
                    "status": "bootstrap_result_archived",
                }
            ).decode("utf-8")
        )
        return 0
    manifest = verify_bootstrap_result_archive(args.archive_root, ports=ports)
    print(
        canonical_json_bytes(
            {
                "archive_manifest_sha256": hashlib.sha256(
                    canonical_json_bytes(manifest)
                ).hexdigest(),
                "status": "bootstrap_result_archive_verified",
                "submission_id": manifest.submission_id,
            }
        ).decode("utf-8")
    )
    return 0


__all__ = [
    "BOOTSTRAP_CHAIN_BLOCK_SCHEMA",
    "BOOTSTRAP_CHAIN_CAPTURE_SCHEMA",
    "BOOTSTRAP_COMPLETE_ARCHIVE_SCHEMA",
    "BOOTSTRAP_OWNER_CLI_EVIDENCE_SCHEMA",
    "BootstrapChainCapture",
    "BootstrapCompleteArchiveManifest",
    "BootstrapResultIntakePorts",
    "CapturedBootstrapBlock",
    "CapturedFinality",
    "CapturedHeader",
    "CapturedRuntime",
    "CapturedSystemEvents",
    "OwnerCliEvidence",
    "build_bootstrap_result_archive",
    "main",
    "parse_canonical_chain_capture",
    "verify_bootstrap_result_archive",
]


if __name__ == "__main__":
    raise SystemExit(main())
