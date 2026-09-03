"""Immutable replay sidecars for production validator anchor reconciliation."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import JsonValue

from .audit import EvidenceStore, ObjectRef
from .protocol import canonical_json_bytes
from .validator_chain import VerifiedStorageRead
from .validator_chain_scan import (
    CapturedFinalizedBlockInterval,
    FinalizedBlockScanEvidence,
    finalized_block_body_sha256,
)
from .validator_extrinsics import ExtrinsicOperation

ANCHOR_SCAN_SIDECAR_SCHEMA = "umi-bittensor-anchor-scan-sidecar/1"
ANCHOR_SCAN_EVIDENCE_REF_SCHEMA = "umi-bittensor-anchor-scan-evidence-ref/1"
ANCHOR_SCAN_MEDIA_TYPE = "application/vnd.umi.anchor-scan+json"

MAX_ANCHOR_SCAN_OBJECT_BYTES = 128 * 1024 * 1024
MAX_ANCHOR_SCAN_TOTAL_BYTES = 2 * 1024 * 1024 * 1024

_HEX32_RE = re.compile(r"^[0-9a-f]{64}$")
_CHAIN_HASH_RE = re.compile(r"^0x[0-9a-f]{64}$")


class AnchorScanEvidenceError(RuntimeError):
    """Exact anchor scan evidence is absent, corrupt, or inconsistent."""


@dataclass(frozen=True, slots=True)
class AnchorScanEvidenceRef:
    """Compact receipt-safe reference to one complete replay manifest."""

    schema: str
    operation_id: str
    start_block: int
    end_block: int
    sha256: str
    size_bytes: int
    media_type: str = ANCHOR_SCAN_MEDIA_TYPE

    def __post_init__(self) -> None:
        if self.schema != ANCHOR_SCAN_EVIDENCE_REF_SCHEMA:
            raise ValueError("anchor scan evidence reference schema is unsupported")
        _hex32(self.operation_id, "anchor scan operation ID")
        _uint(self.start_block, "anchor scan start block")
        _uint(self.end_block, "anchor scan end block")
        if self.end_block < self.start_block:
            raise ValueError("anchor scan evidence interval is inverted")
        _hex32(self.sha256, "anchor scan evidence digest")
        if (
            isinstance(self.size_bytes, bool)
            or not isinstance(self.size_bytes, int)
            or not 0 < self.size_bytes <= MAX_ANCHOR_SCAN_OBJECT_BYTES
        ):
            raise ValueError("anchor scan evidence size is invalid")
        if self.media_type != ANCHOR_SCAN_MEDIA_TYPE:
            raise ValueError("anchor scan evidence media type is unsupported")

    def as_json(self) -> dict[str, JsonValue]:
        return {
            "schema": self.schema,
            "operation_id": self.operation_id,
            "start_block": self.start_block,
            "end_block": self.end_block,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "media_type": self.media_type,
        }

    @classmethod
    def from_json(cls, value: Mapping[str, Any]) -> AnchorScanEvidenceRef:
        if not isinstance(value, Mapping) or set(value) != {
            "schema",
            "operation_id",
            "start_block",
            "end_block",
            "sha256",
            "size_bytes",
            "media_type",
        }:
            raise ValueError("anchor scan evidence reference is malformed")
        return cls(
            schema=value["schema"],
            operation_id=value["operation_id"],
            start_block=value["start_block"],
            end_block=value["end_block"],
            sha256=value["sha256"],
            size_bytes=value["size_bytes"],
            media_type=value["media_type"],
        )


class DurableAnchorScanEvidenceStore:
    """Persist complete scanner inputs before a reconciliation can return.

    Large byte strings are deduplicated child objects.  The referenced sidecar
    is a canonical manifest which retains their order and all verifier-owned
    identities.  ``load`` reads and SHA-256 verifies every child, reproduces
    body/event digests, and locates the exact signed extrinsic again.
    """

    def __init__(
        self,
        root: str | Path,
        *,
        maximum_object_bytes: int = MAX_ANCHOR_SCAN_OBJECT_BYTES,
        maximum_total_object_bytes: int = MAX_ANCHOR_SCAN_TOTAL_BYTES,
    ) -> None:
        try:
            self._store = EvidenceStore(
                Path(root),
                maximum_object_bytes=maximum_object_bytes,
                maximum_manifest_bytes=maximum_object_bytes,
                maximum_total_object_bytes=maximum_total_object_bytes,
            )
        except Exception as error:
            raise AnchorScanEvidenceError("anchor scan evidence store is unavailable") from error

    def persist(
        self,
        *,
        operation: ExtrinsicOperation,
        expected_extrinsic_hash: str,
        signed_extrinsic: bytes,
        interval: CapturedFinalizedBlockInterval,
        storage: VerifiedStorageRead,
        matches: Sequence[tuple[int, int]],
    ) -> AnchorScanEvidenceRef:
        if not isinstance(operation, ExtrinsicOperation):
            raise TypeError("operation must be an ExtrinsicOperation")
        _chain_hash(expected_extrinsic_hash, "expected anchor extrinsic hash")
        if not isinstance(signed_extrinsic, bytes) or not signed_extrinsic:
            raise ValueError("signed anchor extrinsic must be nonempty exact bytes")
        if "0x" + hashlib.blake2b(signed_extrinsic, digest_size=32).hexdigest() != (
            expected_extrinsic_hash
        ):
            raise ValueError("signed anchor bytes do not reproduce the expected hash")
        if not isinstance(interval, CapturedFinalizedBlockInterval):
            raise TypeError("interval must be CapturedFinalizedBlockInterval")
        if not isinstance(storage, VerifiedStorageRead):
            raise TypeError("storage must be VerifiedStorageRead")
        match_tuple = tuple(matches)
        if any(
            not isinstance(item, tuple)
            or len(item) != 2
            or any(isinstance(part, bool) or not isinstance(part, int) or part < 0 for part in item)
            for item in match_tuple
        ):
            raise ValueError("anchor match coordinates are invalid")

        try:
            signed_ref = self._put(signed_extrinsic, "application/vnd.umi.extrinsic")
            blocks = [self._block_manifest(item) for item in interval.evidence]
            storage_manifest = self._storage_manifest(storage)
            manifest: dict[str, JsonValue] = {
                "schema": ANCHOR_SCAN_SIDECAR_SCHEMA,
                "operation_id": operation.operation_id,
                "anchor_kind": operation.request.anchor_kind,
                "field_sha256": operation.request.field.sha256,
                "expected_extrinsic_hash": expected_extrinsic_hash,
                "signed_extrinsic": signed_ref,
                "start_block": interval.blocks[0].snapshot.block_number,
                "end_block": interval.blocks[-1].snapshot.block_number,
                "matched_occurrences": [
                    {"block": block, "extrinsic_index": index} for block, index in match_tuple
                ],
                "blocks": blocks,
                "commitment_storage": storage_manifest,
            }
            encoded = canonical_json_bytes(manifest)
            raw_ref = self._store.add_bytes(encoded, ANCHOR_SCAN_MEDIA_TYPE)
            reference = AnchorScanEvidenceRef(
                schema=ANCHOR_SCAN_EVIDENCE_REF_SCHEMA,
                operation_id=operation.operation_id,
                start_block=interval.blocks[0].snapshot.block_number,
                end_block=interval.blocks[-1].snapshot.block_number,
                sha256=raw_ref.sha256,
                size_bytes=raw_ref.size_bytes,
            )
            # Do not let a receipt reference bytes this process cannot replay.
            self.load(reference)
            return reference
        except AnchorScanEvidenceError:
            raise
        except Exception as error:
            raise AnchorScanEvidenceError("anchor scan evidence persistence failed") from error

    def load(self, reference: AnchorScanEvidenceRef) -> dict[str, JsonValue]:
        if not isinstance(reference, AnchorScanEvidenceRef):
            raise TypeError("reference must be an AnchorScanEvidenceRef")
        try:
            encoded = self._store.read(
                ObjectRef(reference.sha256, reference.media_type, reference.size_bytes)
            )
            decoded = json.loads(encoded)
            if not isinstance(decoded, dict) or canonical_json_bytes(decoded) != encoded:
                raise AnchorScanEvidenceError("anchor scan manifest is not canonical JSON")
            self._verify_manifest(decoded, reference)
            return decoded
        except AnchorScanEvidenceError:
            raise
        except Exception as error:
            raise AnchorScanEvidenceError("anchor scan evidence replay failed") from error

    def _block_manifest(self, item: FinalizedBlockScanEvidence) -> dict[str, JsonValue]:
        identity = item.identity
        body = item.body
        events = item.event_storage
        return {
            "identity": {
                "snapshot": _snapshot_json(identity.snapshot),
                "parent_snapshot": _snapshot_json(identity.parent_snapshot),
                "extrinsics_root": identity.extrinsics_root,
                "finality_verifier_sha256": identity.finality_verifier_sha256,
                "finality_evidence_sha256": identity.finality_evidence_sha256,
            },
            "finality_attestation": self._put(
                item.finality_attestation, "application/vnd.umi.finality-attestation"
            ),
            "finality_replay_binding": _replay_binding_json(item.finality_replay_binding),
            "runtime": {
                "pin": _runtime_pin_json(item.runtime_pin),
                "metadata": self._put(
                    item.runtime_metadata_bytes,
                    "application/vnd.scale.metadata",
                ),
                "version": self._put(
                    item.runtime_version_bytes,
                    "application/json",
                ),
            },
            "body": {
                "block_hash": body.block_hash,
                "parent_hash": body.parent_hash,
                "state_root": body.state_root,
                "extrinsics_root": body.extrinsics_root,
                "body_sha256": body.body_sha256,
                "extrinsics": [
                    self._put(raw, "application/vnd.scale.extrinsic") for raw in body.extrinsics
                ],
            },
            "system_events": {
                "block_hash": events.block_hash,
                "state_root": events.state_root,
                "storage_key": "0x" + events.storage_key.hex(),
                "value_sha256": events.value_sha256,
                "value": (
                    None
                    if events.value is None
                    else self._put(events.value, "application/vnd.scale.storage-value")
                ),
                "proof": [
                    self._put(node, "application/vnd.substrate.trie-proof-node")
                    for node in events.proof
                ],
            },
            "commitment_calls": [
                {
                    "extrinsic_index": binding.extrinsic_index,
                    "call_hash": binding.call_hash,
                    "netuid": binding.netuid,
                    "field_sha256": binding.field_sha256,
                }
                for binding in item.commitment_calls
            ],
        }

    def _storage_manifest(self, storage: VerifiedStorageRead) -> dict[str, JsonValue]:
        evidence = storage.evidence
        runtime = storage.runtime
        return {
            "snapshot": _snapshot_json(evidence.snapshot),
            "pallet": storage.pallet,
            "item": storage.item,
            "params": _json_native(storage.params),
            "storage_key": "0x" + evidence.storage_key.hex(),
            "value": (
                None
                if evidence.value is None
                else self._put(evidence.value, "application/vnd.scale.storage-value")
            ),
            "proof": [
                self._put(node, "application/vnd.substrate.trie-proof-node")
                for node in evidence.proof
            ],
            "decoded": self._put(
                canonical_json_bytes(_json_native(storage.decoded_value)),
                "application/json",
            ),
            "runtime": {
                "pin": _runtime_pin_json(runtime.pin),
                "metadata": self._put(
                    runtime.metadata_bytes,
                    "application/vnd.scale.metadata",
                ),
                "version": self._put(runtime.runtime_version_bytes, "application/json"),
            },
        }

    def _put(self, data: bytes, media_type: str) -> dict[str, JsonValue]:
        return self._store.add_bytes(data, media_type).as_dict()

    def _read_ref(self, value: Any, label: str) -> bytes:
        if not isinstance(value, Mapping) or set(value) != {
            "sha256",
            "media_type",
            "size_bytes",
        }:
            raise AnchorScanEvidenceError(f"{label} object reference is malformed")
        try:
            reference = ObjectRef(
                sha256=value["sha256"],
                media_type=value["media_type"],
                size_bytes=value["size_bytes"],
            )
            return self._store.read(reference)
        except Exception as error:
            raise AnchorScanEvidenceError(f"{label} object is unavailable") from error

    def _verify_manifest(
        self,
        value: Mapping[str, Any],
        reference: AnchorScanEvidenceRef,
    ) -> None:
        required = {
            "schema",
            "operation_id",
            "anchor_kind",
            "field_sha256",
            "expected_extrinsic_hash",
            "signed_extrinsic",
            "start_block",
            "end_block",
            "matched_occurrences",
            "blocks",
            "commitment_storage",
        }
        if set(value) != required or value.get("schema") != ANCHOR_SCAN_SIDECAR_SCHEMA:
            raise AnchorScanEvidenceError("anchor scan manifest shape is invalid")
        if (
            value.get("operation_id") != reference.operation_id
            or value.get("start_block") != reference.start_block
            or value.get("end_block") != reference.end_block
        ):
            raise AnchorScanEvidenceError("anchor scan manifest binds another receipt")
        _hex32(value.get("field_sha256"), "anchor scan field")
        expected_hash = _chain_hash(
            value.get("expected_extrinsic_hash"),
            "anchor scan extrinsic hash",
        )
        signed = self._read_ref(value.get("signed_extrinsic"), "signed extrinsic")
        if "0x" + hashlib.blake2b(signed, digest_size=32).hexdigest() != expected_hash:
            raise AnchorScanEvidenceError("sidecar signed extrinsic hash does not reproduce")

        blocks = value.get("blocks")
        if isinstance(blocks, (str, bytes, bytearray)) or not isinstance(blocks, Sequence):
            raise AnchorScanEvidenceError("anchor scan block interval is malformed")
        expected_heights = tuple(range(reference.start_block, reference.end_block + 1))
        if len(blocks) != len(expected_heights):
            raise AnchorScanEvidenceError("anchor scan block interval is incomplete")
        occurrences: list[tuple[int, int]] = []
        prior_hash: str | None = None
        for height, block in zip(expected_heights, blocks, strict=True):
            if not isinstance(block, Mapping):
                raise AnchorScanEvidenceError("anchor scan block evidence is malformed")
            identity = _required_mapping(block.get("identity"), "block identity")
            snapshot = _required_mapping(identity.get("snapshot"), "block snapshot")
            parent = _required_mapping(identity.get("parent_snapshot"), "parent snapshot")
            if snapshot.get("block_number") != height:
                raise AnchorScanEvidenceError("anchor scan block height is not contiguous")
            block_hash = _chain_hash(snapshot.get("block_hash"), "sidecar block hash")
            if prior_hash is not None and snapshot.get("parent_hash") != prior_hash:
                raise AnchorScanEvidenceError("anchor scan block ancestry is not contiguous")
            if parent.get("block_hash") != snapshot.get("parent_hash"):
                raise AnchorScanEvidenceError("anchor scan parent identity is inconsistent")
            prior_hash = block_hash

            attestation = self._read_ref(block.get("finality_attestation"), "finality attestation")
            if hashlib.sha256(attestation).hexdigest() != identity.get("finality_evidence_sha256"):
                raise AnchorScanEvidenceError("finality attestation digest does not reproduce")
            _verify_replay_binding(block.get("finality_replay_binding"))

            runtime = _required_mapping(block.get("runtime"), "execution runtime")
            pin = _required_mapping(runtime.get("pin"), "execution runtime pin")
            metadata = self._read_ref(runtime.get("metadata"), "runtime metadata")
            if hashlib.sha256(metadata).hexdigest() != pin.get("metadata_sha256"):
                raise AnchorScanEvidenceError("runtime metadata digest does not reproduce")
            self._read_ref(runtime.get("version"), "runtime version")

            body = _required_mapping(block.get("body"), "block body")
            raw_refs = body.get("extrinsics")
            if isinstance(raw_refs, (str, bytes, bytearray)) or not isinstance(raw_refs, Sequence):
                raise AnchorScanEvidenceError("sidecar extrinsic vector is malformed")
            raw_extrinsics = tuple(self._read_ref(item, "block extrinsic") for item in raw_refs)
            if finalized_block_body_sha256(raw_extrinsics) != body.get("body_sha256"):
                raise AnchorScanEvidenceError("sidecar block body digest does not reproduce")
            if (
                body.get("block_hash") != block_hash
                or body.get("parent_hash") != snapshot.get("parent_hash")
                or body.get("state_root") != snapshot.get("state_root")
                or body.get("extrinsics_root") != identity.get("extrinsics_root")
            ):
                raise AnchorScanEvidenceError("sidecar body and finalized identity disagree")
            occurrences.extend(
                (height, index) for index, raw in enumerate(raw_extrinsics) if raw == signed
            )

            events = _required_mapping(block.get("system_events"), "System.Events")
            event_value_ref = events.get("value")
            event_value = (
                None
                if event_value_ref is None
                else self._read_ref(event_value_ref, "System.Events value")
            )
            if hashlib.sha256(event_value or b"").hexdigest() != events.get("value_sha256"):
                raise AnchorScanEvidenceError("System.Events value digest does not reproduce")
            proof = events.get("proof")
            if isinstance(proof, (str, bytes, bytearray)) or not isinstance(proof, Sequence):
                raise AnchorScanEvidenceError("System.Events proof vector is malformed")
            for node in proof:
                self._read_ref(node, "System.Events proof node")
            if events.get("block_hash") != block_hash or events.get("state_root") != snapshot.get(
                "state_root"
            ):
                raise AnchorScanEvidenceError("System.Events and finalized identity disagree")
            commitment_values = block.get("commitment_calls")
            if isinstance(commitment_values, (str, bytes, bytearray)) or not isinstance(
                commitment_values, Sequence
            ):
                raise AnchorScanEvidenceError("decoded commitment vector is malformed")
            commitments: dict[int, Mapping[str, Any]] = {}
            for raw_commitment in commitment_values:
                commitment = _required_mapping(raw_commitment, "decoded commitment")
                index = commitment.get("extrinsic_index")
                _uint(index, "decoded commitment extrinsic index")
                if index in commitments:
                    raise AnchorScanEvidenceError(
                        "decoded commitment vector contains duplicate indexes"
                    )
                _chain_hash(commitment.get("call_hash"), "decoded commitment call hash")
                _uint(commitment.get("netuid"), "decoded commitment netuid")
                _hex32(commitment.get("field_sha256"), "decoded commitment field")
                commitments[index] = commitment
            for index, raw in enumerate(raw_extrinsics):
                if raw != signed:
                    continue
                commitment = commitments.get(index)
                if (
                    commitment is None
                    or commitment.get("netuid") != 78
                    or commitment.get("field_sha256") != value.get("field_sha256")
                ):
                    raise AnchorScanEvidenceError(
                        "signed sidecar extrinsic lacks its exact decoded commitment"
                    )

        declared_matches = value.get("matched_occurrences")
        if isinstance(declared_matches, (str, bytes, bytearray)) or not isinstance(
            declared_matches, Sequence
        ):
            raise AnchorScanEvidenceError("sidecar anchor match vector is malformed")
        expected_occurrences = []
        for item in declared_matches:
            match = _required_mapping(item, "anchor match")
            expected_occurrences.append((match.get("block"), match.get("extrinsic_index")))
        if occurrences != expected_occurrences:
            raise AnchorScanEvidenceError("sidecar anchor matches do not reproduce")

        storage = _required_mapping(value.get("commitment_storage"), "commitment storage")
        self._verify_storage_manifest(storage)

    def _verify_storage_manifest(self, value: Mapping[str, Any]) -> None:
        snapshot = _required_mapping(value.get("snapshot"), "storage snapshot")
        _chain_hash(snapshot.get("block_hash"), "storage snapshot hash")
        raw_ref = value.get("value")
        if raw_ref is not None:
            self._read_ref(raw_ref, "commitment storage value")
        proof = value.get("proof")
        if isinstance(proof, (str, bytes, bytearray)) or not isinstance(proof, Sequence):
            raise AnchorScanEvidenceError("commitment storage proof vector is malformed")
        for node in proof:
            self._read_ref(node, "commitment storage proof node")
        decoded = self._read_ref(value.get("decoded"), "decoded commitment storage")
        _canonical_json_value(decoded, "decoded commitment storage")
        runtime = _required_mapping(value.get("runtime"), "storage runtime")
        pin = _required_mapping(runtime.get("pin"), "storage runtime pin")
        metadata = self._read_ref(runtime.get("metadata"), "storage runtime metadata")
        if hashlib.sha256(metadata).hexdigest() != pin.get("metadata_sha256"):
            raise AnchorScanEvidenceError("storage runtime metadata digest does not reproduce")
        self._read_ref(runtime.get("version"), "storage runtime version")


def _snapshot_json(value: Any) -> dict[str, JsonValue]:
    return {
        "block_number": value.block_number,
        "block_hash": value.block_hash,
        "parent_hash": value.parent_hash,
        "state_root": value.state_root,
    }


def _runtime_pin_json(value: Any) -> dict[str, JsonValue]:
    return {
        "metadata_sha256": value.metadata_sha256,
        "spec_version": value.spec_version,
        "transaction_version": value.transaction_version,
        "state_version": value.state_version,
        "ss58_prefix": value.ss58_prefix,
    }


def _replay_binding_json(value: Any) -> dict[str, JsonValue]:
    return {
        "minimum_finalized_block": value.minimum_finalized_block,
        "maximum_records": value.maximum_records,
        "startup_timeout_seconds": value.startup_timeout_seconds,
        "expected_sequence": value.expected_sequence,
        "previous_number": value.previous_number,
        "previous_timestamp_ms": value.previous_timestamp_ms,
        "previous_hash": value.previous_hash,
        "previous_digest": value.previous_digest,
    }


def _json_native(value: Any) -> JsonValue:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, bytes):
        return "0x" + value.hex()
    if isinstance(value, Mapping):
        result: dict[str, JsonValue] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise AnchorScanEvidenceError("sidecar mapping contains a non-string key")
            result[key] = _json_native(item)
        return result
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_json_native(item) for item in value]
    raise AnchorScanEvidenceError("sidecar contains a non-JSON value")


def _required_mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise AnchorScanEvidenceError(f"{label} is not a mapping")
    return value


def _verify_replay_binding(value: Any) -> None:
    mapping = _required_mapping(value, "finality replay binding")
    try:
        from .validator_chain_scan import FinalityAttestationReplayBinding

        FinalityAttestationReplayBinding(**mapping)
    except (TypeError, ValueError) as error:
        raise AnchorScanEvidenceError("finality replay binding is invalid") from error


def _canonical_json_value(value: bytes, label: str) -> JsonValue:
    try:
        decoded = json.loads(value)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AnchorScanEvidenceError(f"{label} is not JSON") from error
    if canonical_json_bytes(decoded) != value:
        raise AnchorScanEvidenceError(f"{label} is not canonical JSON")
    return decoded


def _hex32(value: Any, label: str) -> str:
    if not isinstance(value, str) or _HEX32_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be lowercase 32-byte hexadecimal")
    return value


def _chain_hash(value: Any, label: str) -> str:
    if not isinstance(value, str) or _CHAIN_HASH_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase 0x-prefixed hash")
    return value


def _uint(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{label} must be a nonnegative integer")
    return value


__all__ = [
    "ANCHOR_SCAN_EVIDENCE_REF_SCHEMA",
    "ANCHOR_SCAN_MEDIA_TYPE",
    "ANCHOR_SCAN_SIDECAR_SCHEMA",
    "MAX_ANCHOR_SCAN_OBJECT_BYTES",
    "MAX_ANCHOR_SCAN_TOTAL_BYTES",
    "AnchorScanEvidenceError",
    "AnchorScanEvidenceRef",
    "DurableAnchorScanEvidenceStore",
]
