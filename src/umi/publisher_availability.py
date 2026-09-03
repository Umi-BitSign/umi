"""Publisher assembly and pre-close availability certification.

This module closes the off-chain handoff that exists before a validator can
consume a certified pool.  Publishers assemble one content-addressed candidate
set.  Each active validator independently verifies that exact set, retains all
of its artifacts, and signs the common availability digest at most once per
window.  A publisher can then combine a quorum of those receipts into the final
pool manifests and a mirror tree consumed by :mod:`umi.validator_live_ports`.

There is deliberately no chain client or generic transaction callback here.
The final output contains an exact ``Commitments.set_commitment`` intent, but
this module cannot sign or broadcast it and never exposes a weight operation.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
import tempfile
from collections import Counter
from collections.abc import Callable, Collection, Mapping, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import Field, ValidationError, model_validator
from typing_extensions import Self

from .artifacts import PublicBatchManifest
from .crypto import sign_response_digest, verify_response_signature
from .encoding import account_id32
from .media import MediaInspectionResult, inspect_media_pinned
from .policy import ScoringPolicy, scoring_policy_hash
from .pool import (
    AVAILABILITY_SCHEMA,
    AvailabilityCertificate,
    AvailabilitySignature,
    PoolBody,
    PoolManifest,
    availability_digest,
    availability_leaf,
    availability_set_root,
    parse_pool_body_bytes,
    parse_pool_manifest_bytes,
    verify_availability_certificate,
    verify_pool_artifacts,
)
from .protocol import PROTOCOL_VERSION, StrictProtocolModel, base64url_decode, canonical_json_bytes
from .registries import spent_batch_leaf, spent_frame_leaf, spent_video_leaf
from .validator_live_ports import (
    DEFAULT_MIRROR_INDEX_PATH,
    MIRROR_WINDOW_INDEX_SCHEMA,
    MirrorObjectDescriptor,
    MirrorWindowIndex,
)
from .validator_state import WindowPlan
from .window import WindowClock

CANDIDATE_SET_SCHEMA = "umi-availability-candidate-set/1"
QUALIFICATION_CONTEXT_SCHEMA = "umi-availability-qualification-context/1"
QUALIFICATION_RECEIPT_SCHEMA = "umi-availability-qualification-receipt/1"
CERTIFIED_RELEASE_SCHEMA = "umi-certified-pool-release/1"
POOL_ANCHOR_INTENT_SCHEMA = "umi-pool-anchor-intent/1"

CANDIDATE_SET_FILENAME = "candidate-set.json"
CERTIFIED_RELEASE_FILENAME = "certified-release.json"
ANCHOR_INTENTS_FILENAME = "anchor-intents.json"
OBJECTS_DIRECTORY = "objects"
QUALIFICATION_RECEIPTS_DIRECTORY = "qualification-receipts"

MAX_CANDIDATE_OBJECTS = 128
MAX_CANDIDATE_SET_BYTES = 1024 * 1024
MAX_CONTEXT_BYTES = 4 * 1024 * 1024
MAX_RECEIPT_BYTES = 4 * 1024 * 1024
MAX_STATE_BYTES = 1 << 40
_MAX_SQLITE_INTEGER = (1 << 63) - 1
_READ_CHUNK_BYTES = 1024 * 1024
_SCHEMA_VERSION = "3"
_HEX32_RE = re.compile(r"^[0-9a-f]{64}$")

_CANDIDATE_KIND_ORDER = {
    "pool_body": 0,
    "public_manifest": 1,
    "ground_truth_envelope": 2,
    "video": 3,
}


class AvailabilityWorkflowError(RuntimeError):
    """Stable fail-closed publisher/certification workflow error."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = _reason_code(reason_code)
        super().__init__(self.reason_code)


class AvailabilityStateConflict(AvailabilityWorkflowError):
    """One validator has already reserved another availability root."""


class AvailabilityStateCorruption(AvailabilityWorkflowError):
    """Durable qualification state no longer reproduces its commitments."""


Hex32 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
BlockHash = Annotated[str, Field(pattern=r"^0x[0-9a-f]{64}$")]


class AvailabilityWindow(StrictProtocolModel):
    """Canonical window identity copied into a candidate set."""

    window_id: Hex32
    window_index: Annotated[int, Field(ge=0, le=_MAX_SQLITE_INTEGER)]
    scoring_policy_hash: Hex32
    announcement_block: Annotated[int, Field(ge=0, le=_MAX_SQLITE_INTEGER)]
    proposal_close_block: Annotated[int, Field(gt=0, le=_MAX_SQLITE_INTEGER)]
    closing_block: Annotated[int, Field(gt=0, le=_MAX_SQLITE_INTEGER)]
    selection_round: Annotated[int, Field(gt=0, le=_MAX_SQLITE_INTEGER)]
    issue_close_round: Annotated[int, Field(gt=0, le=_MAX_SQLITE_INTEGER)]
    response_close_round: Annotated[int, Field(gt=0, le=_MAX_SQLITE_INTEGER)]
    reveal_round: Annotated[int, Field(gt=0, le=_MAX_SQLITE_INTEGER)]

    @model_validator(mode="after")
    def validate_plan(self) -> Self:
        self.to_plan()
        return self

    @classmethod
    def from_plan(cls, plan: WindowPlan) -> AvailabilityWindow:
        if not isinstance(plan, WindowPlan):
            raise TypeError("window must be a WindowPlan")
        return cls(
            window_id=plan.window_id,
            window_index=plan.window_index,
            scoring_policy_hash=plan.scoring_policy_hash,
            announcement_block=plan.announcement_block,
            proposal_close_block=plan.proposal_close_block,
            closing_block=plan.closing_block,
            selection_round=plan.selection_round,
            issue_close_round=plan.issue_close_round,
            response_close_round=plan.response_close_round,
            reveal_round=plan.reveal_round,
        )

    def to_plan(self) -> WindowPlan:
        return WindowPlan(**self.model_dump())


class CandidateObjectDescriptor(StrictProtocolModel):
    """One exact object in the publisher-proposed candidate graph."""

    kind: Literal["pool_body", "public_manifest", "ground_truth_envelope", "video"]
    publisher_hotkey: Annotated[str, Field(min_length=1, max_length=256)] | None = None
    batch_id: Annotated[str, Field(min_length=1, max_length=64)] | None = None
    challenge_id: Annotated[str, Field(min_length=1, max_length=64)] | None = None
    sha256: Hex32
    size_bytes: Annotated[int, Field(gt=0, le=_MAX_SQLITE_INTEGER)]
    media_type: Literal["application/json", "application/octet-stream", "video/mp4"]

    @model_validator(mode="after")
    def validate_shape(self) -> Self:
        if self.kind == "pool_body":
            if (
                self.publisher_hotkey is None
                or self.batch_id is not None
                or self.challenge_id is not None
                or self.media_type != "application/json"
            ):
                raise ValueError("pool-body objects require only a publisher hotkey")
            account_id32(self.publisher_hotkey)
        elif self.kind in {"public_manifest", "ground_truth_envelope"}:
            expected_type = (
                "application/json" if self.kind == "public_manifest" else "application/octet-stream"
            )
            if (
                self.publisher_hotkey is not None
                or self.batch_id is None
                or self.challenge_id is not None
                or self.media_type != expected_type
            ):
                raise ValueError("batch objects require only a batch ID and canonical media type")
            _opaque_id(self.batch_id, "candidate batch ID")
        else:
            if (
                self.publisher_hotkey is not None
                or self.batch_id is None
                or self.challenge_id is None
                or self.media_type != "video/mp4"
            ):
                raise ValueError("video objects require batch and challenge IDs")
            _opaque_id(self.batch_id, "candidate video batch ID")
            _opaque_id(self.challenge_id, "candidate video challenge ID")
        return self

    @property
    def identity(self) -> tuple[object, ...]:
        return _candidate_object_sort_key(self)


class AvailabilityCandidateSet(StrictProtocolModel):
    """Complete pre-close publisher proposal set signed by validators."""

    schema_: Literal[CANDIDATE_SET_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    window: AvailabilityWindow
    objects: Annotated[
        list[CandidateObjectDescriptor],
        Field(min_length=4, max_length=MAX_CANDIDATE_OBJECTS),
    ]

    @model_validator(mode="after")
    def validate_graph_shape(self) -> Self:
        identities = [item.identity for item in self.objects]
        if identities != sorted(identities) or len(set(identities)) != len(identities):
            raise ValueError("candidate objects must be unique and canonically ordered")
        pools = [item for item in self.objects if item.kind == "pool_body"]
        public_ids = [item.batch_id for item in self.objects if item.kind == "public_manifest"]
        envelope_ids = [
            item.batch_id for item in self.objects if item.kind == "ground_truth_envelope"
        ]
        if len(public_ids) != len(set(public_ids)):
            raise ValueError("candidate set repeats a public-manifest batch identity")
        if len(envelope_ids) != len(set(envelope_ids)):
            raise ValueError("candidate set repeats a ground-truth batch identity")
        public = set(public_ids)
        envelopes = set(envelope_ids)
        videos = {item.batch_id for item in self.objects if item.kind == "video"}
        if not pools or not public or public != envelopes or public != videos:
            raise ValueError("candidate set is not a complete pool/batch/video graph")
        publishers = [account_id32(item.publisher_hotkey) for item in pools]
        if publishers != sorted(publishers) or len(set(publishers)) != len(publishers):
            raise ValueError(
                "candidate set must contain one canonically ordered pool per publisher"
            )
        video_ids = [
            (item.batch_id, item.challenge_id) for item in self.objects if item.kind == "video"
        ]
        if len(video_ids) != len(set(video_ids)):
            raise ValueError("candidate set repeats a video identity")
        return self


class AvailabilityQualificationContext(StrictProtocolModel):
    """Chain/state facts an active validator binds to its local qualification."""

    schema_: Literal[QUALIFICATION_CONTEXT_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    window_id: Hex32
    window_index: Annotated[int, Field(ge=0, le=_MAX_SQLITE_INTEGER)]
    scoring_policy_hash: Hex32
    candidate_set_sha256: Hex32
    announcement_block_hash: BlockHash
    announcement_timestamp_ms: Annotated[int, Field(ge=0, le=_MAX_SQLITE_INTEGER)]
    announcement_finality_evidence_sha256: Hex32
    active_validator_set_evidence_sha256: Hex32
    announcement_validator_proof_evidence_sha256: Hex32
    protocol_state_continuity_evidence_sha256: Hex32
    observed_finalized_block: Annotated[int, Field(ge=0, le=_MAX_SQLITE_INTEGER)]
    observed_finalized_block_hash: BlockHash
    observation_finality_evidence_sha256: Hex32
    validator_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    active_validator_hotkeys: Annotated[list[str], Field(min_length=4, max_length=256)]
    spent_registry_root: Hex32
    spent_registry_evidence_sha256: Hex32
    spent_leaves: Annotated[list[Hex32], Field(max_length=1_000_000)]

    @model_validator(mode="after")
    def validate_ordering(self) -> Self:
        validator_accounts = [account_id32(value) for value in self.active_validator_hotkeys]
        if validator_accounts != sorted(validator_accounts) or len(set(validator_accounts)) != len(
            validator_accounts
        ):
            raise ValueError("active validator hotkeys must be unique and account-sorted")
        if account_id32(self.validator_hotkey) not in set(validator_accounts):
            raise ValueError("qualifying validator is absent from the active set")
        leaves = [bytes.fromhex(value) for value in self.spent_leaves]
        if leaves != sorted(leaves) or len(set(leaves)) != len(leaves):
            raise ValueError("spent leaves must be unique and sorted by raw bytes")
        return self


class RetainedObject(StrictProtocolModel):
    sha256: Hex32
    size_bytes: Annotated[int, Field(gt=0, le=_MAX_SQLITE_INTEGER)]
    media_type: Literal["application/json", "application/octet-stream", "video/mp4"]


class AvailabilityQualificationReceipt(StrictProtocolModel):
    """Auditable proof of one validator's retained, one-root qualification."""

    schema_: Literal[QUALIFICATION_RECEIPT_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    window_id: Hex32
    window_index: Annotated[int, Field(ge=0, le=_MAX_SQLITE_INTEGER)]
    scoring_policy_hash: Hex32
    candidate_set_sha256: Hex32
    candidate_set_size_bytes: Annotated[int, Field(gt=0, le=MAX_CANDIDATE_SET_BYTES)]
    qualification_context_sha256: Hex32
    qualification_context_identity_sha256: Hex32
    announcement_block_hash: BlockHash
    announcement_timestamp_ms: Annotated[int, Field(ge=0, le=_MAX_SQLITE_INTEGER)]
    announcement_finality_evidence_sha256: Hex32
    active_validator_set_evidence_sha256: Hex32
    announcement_validator_proof_evidence_sha256: Hex32
    protocol_state_continuity_evidence_sha256: Hex32
    qualified_at_finalized_block: Annotated[int, Field(ge=0, le=_MAX_SQLITE_INTEGER)]
    qualified_at_finalized_block_hash: BlockHash
    observation_finality_evidence_sha256: Hex32
    validator_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    active_validator_hotkeys: Annotated[list[str], Field(min_length=4, max_length=256)]
    spent_registry_root: Hex32
    spent_registry_evidence_sha256: Hex32
    spent_leaf_set_sha256: Hex32
    availability_set_root: Hex32
    qualified_pool_leaves: Annotated[list[Hex32], Field(min_length=1, max_length=256)]
    retained_objects: Annotated[list[RetainedObject], Field(min_length=4)]
    authority_objects: Annotated[list[RetainedObject], Field(min_length=5, max_length=5)]
    scheme: Literal["sr25519", "ed25519"]
    signature: Annotated[str, Field(pattern=r"^0x[0-9a-f]{128}$")]
    receipt_signature: Annotated[str, Field(pattern=r"^0x[0-9a-f]{128}$")]
    mirror_retention_required_through_round: Annotated[int, Field(gt=0)]
    translation_weights_active: Literal[False]
    weight_submission_capability: Literal[False]

    @model_validator(mode="after")
    def validate_ordering(self) -> Self:
        validators = [account_id32(value) for value in self.active_validator_hotkeys]
        if validators != sorted(validators) or len(set(validators)) != len(validators):
            raise ValueError("receipt active validators are not canonical")
        if account_id32(self.validator_hotkey) not in set(validators):
            raise ValueError("receipt signer is absent from its active validator set")
        leaves = [bytes.fromhex(value) for value in self.qualified_pool_leaves]
        if leaves != sorted(leaves) or len(set(leaves)) != len(leaves):
            raise ValueError("receipt pool leaves are not canonical")
        object_keys = [
            (bytes.fromhex(item.sha256), item.media_type) for item in self.retained_objects
        ]
        if object_keys != sorted(object_keys) or len(set(object_keys)) != len(object_keys):
            raise ValueError("receipt retained objects are not canonical")
        authority_keys = [
            (bytes.fromhex(item.sha256), item.media_type) for item in self.authority_objects
        ]
        if authority_keys != sorted(authority_keys) or len(set(authority_keys)) != len(
            authority_keys
        ):
            raise ValueError("receipt authority objects are not canonical")
        return self

    @property
    def availability_signature(self) -> AvailabilitySignature:
        return AvailabilitySignature(
            validator_hotkey=self.validator_hotkey,
            scheme=self.scheme,
            signature=self.signature,
        )


class PoolAnchorField(StrictProtocolModel):
    variant: Literal["Data::Sha256"]
    sha256: Hex32


class PoolAnchorIntent(StrictProtocolModel):
    """Exact publisher hotkey commitment to submit through an external chain operator."""

    schema_: Literal[POOL_ANCHOR_INTENT_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    netuid: Annotated[int, Field(ge=0, le=65535)]
    window_id: Hex32
    closing_block: Annotated[int, Field(gt=0, le=_MAX_SQLITE_INTEGER)]
    publisher_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    pallet: Literal["Commitments"]
    call: Literal["set_commitment"]
    fields: Annotated[list[PoolAnchorField], Field(min_length=1, max_length=1)]
    pool_manifest_sha256: Hex32
    broadcast_authorized: Literal[False]
    translation_weights_active: Literal[False]
    weight_submission_capability: Literal[False]

    @model_validator(mode="after")
    def validate_field(self) -> Self:
        account_id32(self.publisher_hotkey)
        if self.fields[0].sha256 != self.pool_manifest_sha256:
            raise ValueError("anchor field does not contain the final pool-manifest hash")
        return self


class ReleasedPoolManifest(StrictProtocolModel):
    publisher_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    sha256: Hex32
    size_bytes: Annotated[int, Field(gt=0)]


class CertifiedPoolRelease(StrictProtocolModel):
    """Top-level receipt for a deterministic, hostable certified mirror tree."""

    schema_: Literal[CERTIFIED_RELEASE_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    window: AvailabilityWindow
    candidate_set_sha256: Hex32
    availability_certificate_sha256: Hex32
    availability_set_root: Hex32
    qualified_pool_leaves: Annotated[list[Hex32], Field(min_length=1, max_length=256)]
    signer_receipt_sha256s: Annotated[list[Hex32], Field(min_length=1, max_length=256)]
    qualification_receipts_directory: Literal[QUALIFICATION_RECEIPTS_DIRECTORY]
    pool_manifests: Annotated[list[ReleasedPoolManifest], Field(min_length=1, max_length=256)]
    mirror_index_path: Literal[DEFAULT_MIRROR_INDEX_PATH]
    mirror_index_sha256: Hex32
    mirror_index_size_bytes: Annotated[int, Field(gt=0)]
    anchor_intents_sha256: Hex32
    broadcast_performed: Literal[False]
    translation_weights_active: Literal[False]
    weight_submission_capability: Literal[False]

    @model_validator(mode="after")
    def validate_ordering(self) -> Self:
        leaves = [bytes.fromhex(value) for value in self.qualified_pool_leaves]
        if leaves != sorted(leaves) or len(set(leaves)) != len(leaves):
            raise ValueError("release pool leaves are not canonical")
        receipts = [bytes.fromhex(value) for value in self.signer_receipt_sha256s]
        if receipts != sorted(receipts) or len(set(receipts)) != len(receipts):
            raise ValueError("release signer receipts are not canonical")
        publishers = [account_id32(item.publisher_hotkey) for item in self.pool_manifests]
        if publishers != sorted(publishers) or len(set(publishers)) != len(publishers):
            raise ValueError("release pool manifests are not publisher-sorted")
        return self


@dataclass(frozen=True, slots=True)
class LoadedCandidateBundle:
    root: Path
    manifest: AvailabilityCandidateSet
    manifest_bytes: bytes
    objects: Mapping[str, bytes]
    object_paths: Mapping[str, Path]

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.manifest_bytes).hexdigest()


@dataclass(frozen=True, slots=True)
class ValidatedCandidateBundle:
    loaded: LoadedCandidateBundle
    pool_bodies: tuple[PoolBody, ...]
    public_manifests: Mapping[str, PublicBatchManifest]
    ciphertexts: Mapping[str, bytes]
    videos: Mapping[tuple[str, str], bytes]
    leaves: tuple[str, ...]
    set_root: str
    qualification_context_sha256: str | None


@dataclass(frozen=True, slots=True)
class CertifiedReleaseMaterial:
    release: CertifiedPoolRelease
    release_bytes: bytes
    certificate: AvailabilityCertificate
    pool_manifest_bytes: Mapping[str, bytes]
    mirror_index: MirrorWindowIndex
    mirror_index_bytes: bytes
    anchor_intents: tuple[PoolAnchorIntent, ...]
    anchor_intents_bytes: bytes
    objects: Mapping[str, bytes]


def build_candidate_set(
    *,
    policy: ScoringPolicy,
    window: WindowPlan,
    pool_body_bytes: Sequence[bytes],
    public_manifest_bytes: Mapping[str, bytes],
    ground_truth_envelopes: Mapping[str, bytes],
    videos: Mapping[tuple[str, str], bytes],
) -> tuple[AvailabilityCandidateSet, dict[str, bytes]]:
    """Build one canonical content-addressed candidate graph from exact bytes."""

    if not isinstance(policy, ScoringPolicy):
        raise TypeError("policy must be a ScoringPolicy")
    _require_shadow_policy(policy)
    if not isinstance(window, WindowPlan):
        raise TypeError("window must be a WindowPlan")
    policy_hash = scoring_policy_hash(policy)
    if window.scoring_policy_hash != policy_hash:
        raise ValueError("candidate window names a different scoring policy")
    descriptors: list[CandidateObjectDescriptor] = []
    objects: dict[str, bytes] = {}

    for raw in pool_body_bytes:
        body = parse_pool_body_bytes(raw, policy=policy)
        descriptor = _candidate_descriptor(
            kind="pool_body",
            data=raw,
            media_type="application/json",
            publisher_hotkey=body.publisher_hotkey,
        )
        descriptors.append(descriptor)
        _add_object(objects, descriptor.sha256, raw)
    for batch_id, raw in public_manifest_bytes.items():
        _opaque_id(batch_id, "public-manifest batch ID")
        descriptor = _candidate_descriptor(
            kind="public_manifest",
            data=raw,
            media_type="application/json",
            batch_id=batch_id,
        )
        descriptors.append(descriptor)
        _add_object(objects, descriptor.sha256, raw)
    for batch_id, raw in ground_truth_envelopes.items():
        _opaque_id(batch_id, "ground-truth batch ID")
        descriptor = _candidate_descriptor(
            kind="ground_truth_envelope",
            data=raw,
            media_type="application/octet-stream",
            batch_id=batch_id,
        )
        descriptors.append(descriptor)
        _add_object(objects, descriptor.sha256, raw)
    for (batch_id, challenge_id), raw in videos.items():
        _opaque_id(batch_id, "video batch ID")
        _opaque_id(challenge_id, "video challenge ID")
        descriptor = _candidate_descriptor(
            kind="video",
            data=raw,
            media_type="video/mp4",
            batch_id=batch_id,
            challenge_id=challenge_id,
        )
        descriptors.append(descriptor)
        _add_object(objects, descriptor.sha256, raw)
    descriptors.sort(key=_candidate_object_sort_key)
    if len(objects) != len(descriptors):
        raise ValueError("candidate descriptors must not reuse an object digest")
    manifest = AvailabilityCandidateSet(
        schema=CANDIDATE_SET_SCHEMA,
        protocol=PROTOCOL_VERSION,
        window=AvailabilityWindow.from_plan(window),
        objects=descriptors,
    )
    if len(canonical_json_bytes(manifest)) > MAX_CANDIDATE_SET_BYTES:
        raise ValueError("candidate-set manifest exceeds its byte ceiling")
    return manifest, objects


def write_candidate_bundle(
    output_root: str | Path,
    manifest: AvailabilityCandidateSet,
    objects: Mapping[str, bytes],
) -> Path:
    """Materialize a new immutable candidate bundle; existing output is never replaced."""

    if not isinstance(manifest, AvailabilityCandidateSet):
        raise TypeError("manifest must be an AvailabilityCandidateSet")
    root = _new_output_directory(Path(output_root))
    try:
        object_root = root / OBJECTS_DIRECTORY
        _make_private_directory(object_root)
        expected = {item.sha256 for item in manifest.objects}
        if set(objects) != expected:
            raise ValueError("candidate object bytes are not a bijection with descriptors")
        for digest in sorted(expected):
            raw = objects[digest]
            if hashlib.sha256(raw).hexdigest() != digest:
                raise ValueError("candidate object bytes do not reproduce their digest")
            _write_new_file(object_root / digest, raw)
        _write_new_file(root / CANDIDATE_SET_FILENAME, canonical_json_bytes(manifest))
        _fsync_directory(root)
        return root
    except BaseException:
        # A partial bundle is never mistaken for a complete bundle because its
        # canonical manifest is written last.  Leave bytes for operator forensics.
        raise


def load_candidate_bundle(
    root: str | Path,
    *,
    maximum_total_bytes: int = MAX_STATE_BYTES,
) -> LoadedCandidateBundle:
    """Load and hash every object in one no-follow candidate bundle snapshot."""

    root = _existing_real_directory(Path(root), label="candidate_bundle")
    manifest_path = root / CANDIDATE_SET_FILENAME
    raw = _read_stable_file(manifest_path, MAX_CANDIDATE_SET_BYTES, "candidate_set")
    try:
        manifest = AvailabilityCandidateSet.model_validate_json(raw)
    except (ValidationError, ValueError) as error:
        raise AvailabilityWorkflowError("candidate_set_invalid") from error
    if canonical_json_bytes(manifest) != raw:
        raise AvailabilityWorkflowError("candidate_set_noncanonical")
    expected = {item.sha256: item for item in manifest.objects}
    if len(expected) != len(manifest.objects):
        raise AvailabilityWorkflowError("candidate_set_reuses_object_digest")
    object_root = _existing_real_directory(root / OBJECTS_DIRECTORY, label="candidate_objects")
    actual_names = sorted(path.name for path in object_root.iterdir())
    if actual_names != sorted(expected):
        raise AvailabilityWorkflowError("candidate_object_set_mismatch")
    objects: dict[str, bytes] = {}
    paths: dict[str, Path] = {}
    total = len(raw)
    for digest, descriptor in expected.items():
        maximum = _descriptor_ceiling(descriptor)
        data = _read_stable_file(object_root / digest, maximum, "candidate_object")
        total += len(data)
        if total > maximum_total_bytes:
            raise AvailabilityWorkflowError("candidate_total_size_limit")
        if len(data) != descriptor.size_bytes:
            raise AvailabilityWorkflowError("candidate_object_size_mismatch")
        if hashlib.sha256(data).hexdigest() != descriptor.sha256:
            raise AvailabilityWorkflowError("candidate_object_digest_mismatch")
        objects[digest] = data
        paths[digest] = object_root / digest
    return LoadedCandidateBundle(root, manifest, raw, objects, paths)


def validate_candidate_bundle(
    loaded: LoadedCandidateBundle,
    *,
    policy: ScoringPolicy,
    context: AvailabilityQualificationContext | None = None,
) -> ValidatedCandidateBundle:
    """Reproduce every public artifact, media, limit, duplicate, and spent check."""

    if not isinstance(loaded, LoadedCandidateBundle):
        raise TypeError("loaded must be a LoadedCandidateBundle")
    if not isinstance(policy, ScoringPolicy):
        raise TypeError("policy must be a ScoringPolicy")
    _require_shadow_policy(policy)
    policy_hash = scoring_policy_hash(policy)
    window = loaded.manifest.window
    descriptor_digests = {item.sha256 for item in loaded.manifest.objects}
    if (
        canonical_json_bytes(loaded.manifest) != loaded.manifest_bytes
        or len(descriptor_digests) != len(loaded.manifest.objects)
        or set(loaded.objects) != descriptor_digests
        or not descriptor_digests.issubset(loaded.object_paths)
    ):
        raise AvailabilityWorkflowError("candidate_loaded_object_set_mismatch")
    if window.scoring_policy_hash != policy_hash:
        raise AvailabilityWorkflowError("candidate_policy_mismatch")
    if context is not None:
        _validate_qualification_context(context, loaded, policy)

    descriptors = loaded.manifest.objects
    bodies: list[PoolBody] = []
    public: dict[str, PublicBatchManifest] = {}
    ciphertexts: dict[str, bytes] = {}
    videos: dict[tuple[str, str], bytes] = {}

    for descriptor in descriptors:
        data = loaded.objects[descriptor.sha256]
        if (
            len(data) != descriptor.size_bytes
            or hashlib.sha256(data).hexdigest() != descriptor.sha256
        ):
            raise AvailabilityWorkflowError("candidate_loaded_object_binding_mismatch")
        if descriptor.kind == "pool_body":
            body = parse_pool_body_bytes(data, policy=policy)
            if descriptor.publisher_hotkey is None:  # pragma: no cover - model narrowed
                raise RuntimeError("pool-body descriptor lost its publisher")
            if account_id32(body.publisher_hotkey) != account_id32(descriptor.publisher_hotkey):
                raise AvailabilityWorkflowError("pool_body_descriptor_mismatch")
            bodies.append(body)
        elif descriptor.kind == "public_manifest":
            if descriptor.batch_id is None:  # pragma: no cover - model narrowed
                raise RuntimeError("public-manifest descriptor lost its batch ID")
            try:
                manifest = PublicBatchManifest.model_validate_json(data)
            except (ValidationError, ValueError) as error:
                raise AvailabilityWorkflowError("public_manifest_invalid") from error
            if canonical_json_bytes(manifest) != data:
                raise AvailabilityWorkflowError("public_manifest_noncanonical")
            if manifest.batch_id != descriptor.batch_id:
                raise AvailabilityWorkflowError("public_manifest_descriptor_mismatch")
            public[descriptor.batch_id] = manifest
        elif descriptor.kind == "ground_truth_envelope":
            if descriptor.batch_id is None:  # pragma: no cover - model narrowed
                raise RuntimeError("ground-truth descriptor lost its batch ID")
            ciphertexts[descriptor.batch_id] = data
        else:
            if descriptor.batch_id is None or descriptor.challenge_id is None:
                raise RuntimeError("video descriptor lost identifiers")
            videos[(descriptor.batch_id, descriptor.challenge_id)] = data

    bodies.sort(key=lambda body: account_id32(body.publisher_hotkey))
    _validate_pool_limits_and_uniqueness(bodies, public, policy)
    for body in bodies:
        if body.window_id != window.window_id:
            raise AvailabilityWorkflowError("pool_body_window_mismatch")
        batch_ids = {entry.batch_id for entry in body.batches}
        verify_pool_artifacts(
            body,
            public_manifests={batch_id: public[batch_id] for batch_id in batch_ids},
            ciphertexts={batch_id: ciphertexts[batch_id] for batch_id in batch_ids},
            policy=policy,
        )
        for batch_id in batch_ids:
            manifest = public[batch_id]
            if (
                manifest.response_close_round != window.response_close_round
                or manifest.reveal_round != window.reveal_round
            ):
                raise AvailabilityWorkflowError("public_manifest_window_round_mismatch")

    expected_videos = {
        (manifest.batch_id, item.challenge_id)
        for manifest in public.values()
        for item in manifest.items
    }
    if set(videos) != expected_videos:
        raise AvailabilityWorkflowError("candidate_video_set_mismatch")
    video_descriptors = {
        (item.batch_id, item.challenge_id): item for item in descriptors if item.kind == "video"
    }
    for manifest in public.values():
        for item in manifest.items:
            identity = (manifest.batch_id, item.challenge_id)
            data = videos[identity]
            descriptor = video_descriptors[identity]
            if descriptor.sha256 != item.media.sha256 or descriptor.size_bytes != (
                item.media.size_bytes
            ):
                raise AvailabilityWorkflowError("video_descriptor_manifest_mismatch")
            inspection = inspect_media_pinned(
                loaded.object_paths[descriptor.sha256],
                maximum_clip_size=policy.limits.maximum_clip_size_bytes,
                expected_ffmpeg_sha256=(policy.implementation_pins.media.ffmpeg_binary_sha256),
                expected_ffprobe_sha256=(policy.implementation_pins.media.ffprobe_binary_sha256),
            )
            _verify_media_inspection(inspection, item.media, policy)

    _validate_public_duplicates_and_spent(
        bodies,
        public,
        spent_leaves=(
            frozenset(bytes.fromhex(value) for value in context.spent_leaves)
            if context is not None
            else frozenset()
        ),
    )
    leaves = tuple(sorted((availability_leaf(body) for body in bodies), key=bytes.fromhex))
    return ValidatedCandidateBundle(
        loaded=loaded,
        pool_bodies=tuple(bodies),
        public_manifests=public,
        ciphertexts=ciphertexts,
        videos=videos,
        leaves=leaves,
        set_root=availability_set_root(leaves),
        qualification_context_sha256=(
            hashlib.sha256(canonical_json_bytes(context)).hexdigest()
            if context is not None
            else None
        ),
    )


def qualify_candidate_set_component(
    validated: ValidatedCandidateBundle,
    *,
    policy: ScoringPolicy,
    context: AvailabilityQualificationContext,
    authority_objects: Mapping[str, bytes],
    state: AvailabilityQualificationStore,
    wallet: Any,
    before_sign: Callable[[], None] | None = None,
) -> AvailabilityQualificationReceipt:
    """Component signer used after a caller establishes proof-backed authority.

    Production operators must use the proof-backed wrapper in
    :mod:`umi.publisher_availability_authority`. This function deliberately
    accepts no proof verifier and is kept for focused state-machine tests.
    """

    if not isinstance(validated, ValidatedCandidateBundle):
        raise TypeError("validated must be a ValidatedCandidateBundle")
    _require_shadow_policy(policy)
    _validate_qualification_context(context, validated.loaded, policy)
    context_sha256 = hashlib.sha256(canonical_json_bytes(context)).hexdigest()
    if validated.qualification_context_sha256 != context_sha256:
        raise AvailabilityWorkflowError("qualification_context_not_validated")
    if context.candidate_set_sha256 != validated.loaded.sha256:
        raise AvailabilityWorkflowError("qualification_candidate_digest_mismatch")
    if not isinstance(state, AvailabilityQualificationStore):
        raise TypeError("state must be an AvailabilityQualificationStore")
    if state.policy_hash != scoring_policy_hash(policy):
        raise AvailabilityStateConflict("qualification_store_policy_mismatch")
    if account_id32(state.validator_hotkey) != account_id32(context.validator_hotkey):
        raise AvailabilityStateConflict("qualification_store_validator_mismatch")
    if not isinstance(authority_objects, Mapping):
        raise TypeError("authority_objects must be a digest mapping")
    authority = _validate_authority_objects(context, authority_objects)
    if before_sign is not None and not callable(before_sign):
        raise TypeError("before_sign must be callable or None")

    existing = state.reserve(validated, context, authority_objects=authority)
    if existing is not None:
        return existing
    if before_sign is not None:
        before_sign()
    try:
        signer = wallet.hotkey
        signer_hotkey = signer.ss58_address
    except Exception as error:
        raise AvailabilityWorkflowError("availability_signer_unavailable") from error
    if account_id32(signer_hotkey) != account_id32(context.validator_hotkey):
        raise AvailabilityWorkflowError("availability_signer_hotkey_mismatch")
    digest = availability_digest(context.window_id, validated.set_root)
    try:
        scheme, signature = sign_response_digest(wallet, digest)
    except Exception as error:
        raise AvailabilityWorkflowError("availability_signer_failed") from error
    provisional = _qualification_receipt(
        validated,
        context,
        scheme,
        signature,
        receipt_signature="0x" + "00" * 64,
        authority_objects=_authority_object_rows(authority),
    )
    try:
        receipt_scheme, receipt_signature = sign_response_digest(
            wallet,
            qualification_receipt_digest(provisional),
        )
    except Exception as error:
        raise AvailabilityWorkflowError("availability_receipt_signer_failed") from error
    if receipt_scheme != scheme:
        raise AvailabilityWorkflowError("availability_signer_scheme_changed")
    receipt = provisional.model_copy(update={"receipt_signature": receipt_signature})
    _verify_receipt_signatures(receipt)
    return state.complete(receipt)


class AvailabilityQualificationStore:
    """Restart-safe one-root-per-window reservation and retained object store."""

    def __init__(
        self,
        root: str | Path,
        *,
        policy_hash: str,
        validator_hotkey: str,
        maximum_state_bytes: int = MAX_STATE_BYTES,
    ) -> None:
        _hex32(policy_hash, "qualification-store policy hash")
        account_id32(validator_hotkey)
        if (
            isinstance(maximum_state_bytes, bool)
            or not isinstance(maximum_state_bytes, int)
            or maximum_state_bytes <= 0
            or maximum_state_bytes > MAX_STATE_BYTES
        ):
            raise ValueError("qualification-store byte ceiling is invalid")
        self.policy_hash = policy_hash
        self.validator_hotkey = validator_hotkey
        self.maximum_state_bytes = maximum_state_bytes
        self.root = _private_state_directory(Path(root))
        self.objects = self.root / OBJECTS_DIRECTORY
        _make_private_directory(self.objects, exist_ok=True)
        self.database_path = self.root / "availability.sqlite3"
        self._initialize()
        self._audit()

    def reserve(
        self,
        validated: ValidatedCandidateBundle,
        context: AvailabilityQualificationContext,
        *,
        authority_objects: Mapping[str, bytes],
    ) -> AvailabilityQualificationReceipt | None:
        identity_hash = qualification_context_identity_sha256(context)
        object_rows = _retained_objects(validated.loaded)
        context_bytes = canonical_json_bytes(context)
        context_sha256 = hashlib.sha256(context_bytes).hexdigest()
        bytes_to_retain = dict(validated.loaded.objects)
        authority = _validate_authority_objects(context, authority_objects)
        for digest, data in authority.items():
            _add_object(bytes_to_retain, digest, data)
        _add_object(
            bytes_to_retain,
            validated.loaded.sha256,
            validated.loaded.manifest_bytes,
        )
        _add_object(bytes_to_retain, context_sha256, context_bytes)
        with self._transaction() as connection:
            existing = connection.execute(
                "SELECT * FROM qualifications WHERE window_id = ? OR window_index = ?",
                (context.window_id, context.window_index),
            ).fetchone()
            if existing is not None:
                _verify_reservation(
                    existing,
                    validated,
                    context,
                    identity_hash,
                )
                if existing["status"] == "completed":
                    receipt = _parse_receipt(bytes(existing["receipt_bytes"]))
                    _verify_receipt_signatures(receipt)
                    return receipt
                inventory = _content_store_inventory(
                    self.objects,
                    maximum_total_bytes=self.maximum_state_bytes,
                )
                new_bytes = sum(
                    len(data) for digest, data in bytes_to_retain.items() if digest not in inventory
                )
                if sum(inventory.values()) + new_bytes > self.maximum_state_bytes:
                    raise AvailabilityWorkflowError("qualification_state_size_limit")
                for digest in sorted(bytes_to_retain):
                    _store_content_addressed(self.objects / digest, bytes_to_retain[digest])
                refreshed_rows = [
                    *object_rows,
                    *_authority_object_rows(authority),
                    RetainedObject(
                        sha256=validated.loaded.sha256,
                        size_bytes=len(validated.loaded.manifest_bytes),
                        media_type="application/json",
                    ),
                    RetainedObject(
                        sha256=context_sha256,
                        size_bytes=len(context_bytes),
                        media_type="application/json",
                    ),
                ]
                for item in refreshed_rows:
                    prior = connection.execute(
                        "SELECT size_bytes, media_type FROM retained_objects WHERE sha256 = ?",
                        (item.sha256,),
                    ).fetchone()
                    if prior is None:
                        connection.execute(
                            "INSERT INTO retained_objects "
                            "(sha256, size_bytes, media_type) VALUES (?, ?, ?)",
                            (item.sha256, item.size_bytes, item.media_type),
                        )
                    elif (
                        prior["size_bytes"] != item.size_bytes
                        or prior["media_type"] != item.media_type
                    ):
                        raise AvailabilityStateCorruption("retained_object_metadata_conflict")
                connection.execute(
                    "DELETE FROM qualification_objects WHERE window_id = ?",
                    (context.window_id,),
                )
                for digest in sorted({item.sha256 for item in refreshed_rows}):
                    connection.execute(
                        "INSERT INTO qualification_objects (window_id, sha256) VALUES (?, ?)",
                        (context.window_id, digest),
                    )
                connection.execute(
                    "UPDATE qualifications SET context_sha256 = ? WHERE window_id = ?",
                    (context_sha256, context.window_id),
                )
                return None

            # Keep the database write lock through content retention. This makes
            # concurrent operator processes serialize on the one-window
            # reservation before either process can sign. A process crash can
            # leave valid content-addressed files without database rows; the
            # inventory scan counts and verifies those files on restart.
            inventory = _content_store_inventory(
                self.objects,
                maximum_total_bytes=self.maximum_state_bytes,
            )
            new_bytes = sum(
                len(data) for digest, data in bytes_to_retain.items() if digest not in inventory
            )
            if sum(inventory.values()) + new_bytes > self.maximum_state_bytes:
                raise AvailabilityWorkflowError("qualification_state_size_limit")
            for digest in sorted(bytes_to_retain):
                _store_content_addressed(self.objects / digest, bytes_to_retain[digest])

            connection.execute(
                "INSERT INTO qualifications (window_id, window_index, candidate_sha256, "
                "context_sha256, context_identity_sha256, availability_set_root, "
                "leaves_json, status) VALUES (?, ?, ?, ?, ?, ?, ?, 'reserved')",
                (
                    context.window_id,
                    context.window_index,
                    validated.loaded.sha256,
                    context_sha256,
                    identity_hash,
                    validated.set_root,
                    json.dumps(list(validated.leaves), separators=(",", ":")),
                ),
            )
            all_objects = [
                *object_rows,
                *_authority_object_rows(authority),
                RetainedObject(
                    sha256=validated.loaded.sha256,
                    size_bytes=len(validated.loaded.manifest_bytes),
                    media_type="application/json",
                ),
                RetainedObject(
                    sha256=context_sha256,
                    size_bytes=len(context_bytes),
                    media_type="application/json",
                ),
            ]
            distinct_objects: dict[str, RetainedObject] = {}
            for item in all_objects:
                prior = distinct_objects.get(item.sha256)
                if prior is not None and prior != item:
                    raise AvailabilityStateCorruption("retained_object_metadata_conflict")
                distinct_objects[item.sha256] = item
            for item in distinct_objects.values():
                prior = connection.execute(
                    "SELECT size_bytes, media_type FROM retained_objects WHERE sha256 = ?",
                    (item.sha256,),
                ).fetchone()
                if prior is None:
                    connection.execute(
                        "INSERT INTO retained_objects "
                        "(sha256, size_bytes, media_type) VALUES (?, ?, ?)",
                        (item.sha256, item.size_bytes, item.media_type),
                    )
                elif (
                    prior["size_bytes"] != item.size_bytes or prior["media_type"] != item.media_type
                ):
                    raise AvailabilityStateCorruption("retained_object_metadata_conflict")
                connection.execute(
                    "INSERT INTO qualification_objects (window_id, sha256) VALUES (?, ?)",
                    (context.window_id, item.sha256),
                )
        return None

    def complete(
        self,
        receipt: AvailabilityQualificationReceipt,
    ) -> AvailabilityQualificationReceipt:
        if not isinstance(receipt, AvailabilityQualificationReceipt):
            raise TypeError("receipt must be an AvailabilityQualificationReceipt")
        if receipt.scoring_policy_hash != self.policy_hash or account_id32(
            receipt.validator_hotkey
        ) != account_id32(self.validator_hotkey):
            raise AvailabilityStateConflict("qualification_receipt_store_mismatch")
        _verify_receipt_signatures(receipt)
        receipt_bytes = canonical_json_bytes(receipt)
        if len(receipt_bytes) > MAX_RECEIPT_BYTES:
            raise AvailabilityWorkflowError("qualification_receipt_size_limit")
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM qualifications WHERE window_id = ?", (receipt.window_id,)
            ).fetchone()
            if row is None:
                raise AvailabilityStateConflict("qualification_reservation_missing")
            try:
                leaves = json.loads(row["leaves_json"])
                candidate_bytes = _read_stable_file(
                    self.objects / row["candidate_sha256"],
                    MAX_CANDIDATE_SET_BYTES,
                    "retained_candidate_set",
                )
                context_bytes = _read_stable_file(
                    self.objects / row["context_sha256"],
                    MAX_CONTEXT_BYTES,
                    "retained_qualification_context",
                )
                candidate = AvailabilityCandidateSet.model_validate_json(candidate_bytes)
                context = AvailabilityQualificationContext.model_validate_json(context_bytes)
            except (json.JSONDecodeError, ValidationError, ValueError) as error:
                raise AvailabilityStateCorruption(
                    "qualification_reservation_material_invalid"
                ) from error
            linked = {
                value["sha256"]
                for value in connection.execute(
                    "SELECT sha256 FROM qualification_objects WHERE window_id = ?",
                    (receipt.window_id,),
                ).fetchall()
            }
            expected_linked = {
                receipt.candidate_set_sha256,
                receipt.qualification_context_sha256,
                *(item.sha256 for item in receipt.retained_objects),
                *(item.sha256 for item in receipt.authority_objects),
            }
            if (
                row["candidate_sha256"] != receipt.candidate_set_sha256
                or row["window_index"] != receipt.window_index
                or row["context_identity_sha256"] != receipt.qualification_context_identity_sha256
                or row["context_sha256"] != receipt.qualification_context_sha256
                or row["availability_set_root"] != receipt.availability_set_root
                or leaves != receipt.qualified_pool_leaves
                or hashlib.sha256(candidate_bytes).hexdigest() != row["candidate_sha256"]
                or hashlib.sha256(context_bytes).hexdigest() != row["context_sha256"]
                or canonical_json_bytes(candidate) != candidate_bytes
                or canonical_json_bytes(context) != context_bytes
                or receipt.candidate_set_size_bytes != len(candidate_bytes)
                or receipt.retained_objects != _retained_objects_from_manifest(candidate)
                or receipt.authority_objects
                != _authority_object_rows_from_store(context, connection)
                or linked != expected_linked
                or not _receipt_matches_context(receipt, context)
            ):
                raise AvailabilityStateConflict("qualification_receipt_reservation_mismatch")
            if row["status"] == "completed":
                existing = bytes(row["receipt_bytes"])
                if existing != receipt_bytes:
                    raise AvailabilityStateConflict("qualification_receipt_conflict")
                parsed = _parse_receipt(existing)
                _verify_receipt_signatures(parsed)
                return parsed
            changed = connection.execute(
                "UPDATE qualifications SET status = 'completed', receipt_sha256 = ?, "
                "receipt_bytes = ? WHERE window_id = ? AND status = 'reserved'",
                (hashlib.sha256(receipt_bytes).hexdigest(), receipt_bytes, receipt.window_id),
            ).rowcount
            if changed != 1:
                raise AvailabilityStateConflict("qualification_state_transition_conflict")
        return receipt

    def load(self, window_id: str) -> AvailabilityQualificationReceipt | None:
        _hex32(window_id, "qualification window ID")
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM qualifications WHERE window_id = ?", (window_id,)
            ).fetchone()
            if row is None or row["status"] == "reserved":
                return None
            receipt = _parse_receipt(bytes(row["receipt_bytes"]))
            _verify_receipt_signatures(receipt)
            return receipt

    def _initialize(self) -> None:
        with self._transaction() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                ) STRICT;
                CREATE TABLE IF NOT EXISTS qualifications (
                    window_id TEXT PRIMARY KEY,
                    window_index INTEGER NOT NULL UNIQUE,
                    candidate_sha256 TEXT NOT NULL,
                    context_sha256 TEXT NOT NULL,
                    context_identity_sha256 TEXT NOT NULL,
                    availability_set_root TEXT NOT NULL,
                    leaves_json TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('reserved', 'completed')),
                    receipt_sha256 TEXT,
                    receipt_bytes BLOB,
                    CHECK((status = 'reserved' AND receipt_sha256 IS NULL AND receipt_bytes IS NULL)
                       OR (status = 'completed' AND receipt_sha256 IS NOT NULL
                           AND receipt_bytes IS NOT NULL))
                ) STRICT;
                CREATE TABLE IF NOT EXISTS retained_objects (
                    sha256 TEXT PRIMARY KEY,
                    size_bytes INTEGER NOT NULL CHECK(size_bytes > 0),
                    media_type TEXT NOT NULL
                ) STRICT;
                CREATE TABLE IF NOT EXISTS qualification_objects (
                    window_id TEXT NOT NULL REFERENCES qualifications(window_id),
                    sha256 TEXT NOT NULL REFERENCES retained_objects(sha256),
                    PRIMARY KEY(window_id, sha256)
                ) STRICT;
                """
            )
            expected = {
                "schema_version": _SCHEMA_VERSION,
                "policy_hash": self.policy_hash,
                "validator_account_id32": account_id32(self.validator_hotkey).hex(),
            }
            for key, value in expected.items():
                row = connection.execute(
                    "SELECT value FROM metadata WHERE key = ?", (key,)
                ).fetchone()
                if row is None:
                    connection.execute(
                        "INSERT INTO metadata (key, value) VALUES (?, ?)", (key, value)
                    )
                elif row["value"] != value:
                    raise AvailabilityStateConflict("qualification_store_identity_conflict")

    def _audit(self) -> None:
        with self._connection() as connection:
            if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise AvailabilityStateCorruption("qualification_database_corrupt")
            inventory = _content_store_inventory(
                self.objects,
                maximum_total_bytes=self.maximum_state_bytes,
            )
            objects = connection.execute(
                "SELECT * FROM retained_objects ORDER BY sha256"
            ).fetchall()
            for row in objects:
                if inventory.get(row["sha256"]) != row["size_bytes"]:
                    raise AvailabilityStateCorruption("retained_object_tampered")
            rows = connection.execute(
                "SELECT * FROM qualifications ORDER BY window_index"
            ).fetchall()
            for row in rows:
                try:
                    leaves = json.loads(row["leaves_json"])
                except json.JSONDecodeError as error:
                    raise AvailabilityStateCorruption("qualification_leaves_corrupt") from error
                if (
                    not isinstance(leaves, list)
                    or leaves != sorted(leaves, key=bytes.fromhex)
                    or availability_set_root(leaves) != row["availability_set_root"]
                ):
                    raise AvailabilityStateCorruption("qualification_root_corrupt")
                candidate_bytes = _read_stable_file(
                    self.objects / row["candidate_sha256"],
                    MAX_CANDIDATE_SET_BYTES,
                    "retained_candidate_set",
                )
                if hashlib.sha256(candidate_bytes).hexdigest() != row["candidate_sha256"]:
                    raise AvailabilityStateCorruption("retained_candidate_set_tampered")
                try:
                    candidate = AvailabilityCandidateSet.model_validate_json(candidate_bytes)
                except (ValidationError, ValueError) as error:
                    raise AvailabilityStateCorruption("retained_candidate_set_invalid") from error
                if (
                    canonical_json_bytes(candidate) != candidate_bytes
                    or candidate.window.window_id != row["window_id"]
                    or candidate.window.window_index != row["window_index"]
                    or candidate.window.scoring_policy_hash != self.policy_hash
                ):
                    raise AvailabilityStateCorruption("retained_candidate_set_binding_corrupt")
                context_bytes = _read_stable_file(
                    self.objects / row["context_sha256"],
                    MAX_CONTEXT_BYTES,
                    "retained_qualification_context",
                )
                if hashlib.sha256(context_bytes).hexdigest() != row["context_sha256"]:
                    raise AvailabilityStateCorruption("retained_qualification_context_tampered")
                try:
                    context = AvailabilityQualificationContext.model_validate_json(context_bytes)
                except (ValidationError, ValueError) as error:
                    raise AvailabilityStateCorruption(
                        "retained_qualification_context_invalid"
                    ) from error
                if canonical_json_bytes(context) != context_bytes:
                    raise AvailabilityStateCorruption("retained_qualification_context_noncanonical")
                if (
                    context.window_id != row["window_id"]
                    or context.window_index != row["window_index"]
                    or context.scoring_policy_hash != self.policy_hash
                    or context.candidate_set_sha256 != row["candidate_sha256"]
                    or qualification_context_identity_sha256(context)
                    != row["context_identity_sha256"]
                    or account_id32(context.validator_hotkey) != account_id32(self.validator_hotkey)
                ):
                    raise AvailabilityStateCorruption(
                        "retained_qualification_context_binding_corrupt"
                    )
                linked = {
                    value["sha256"]
                    for value in connection.execute(
                        "SELECT sha256 FROM qualification_objects WHERE window_id = ?",
                        (row["window_id"],),
                    ).fetchall()
                }
                candidate_linked = {
                    row["candidate_sha256"],
                    row["context_sha256"],
                    *(item.sha256 for item in candidate.objects),
                    *_authority_object_digests(context),
                }
                if linked != candidate_linked:
                    raise AvailabilityStateCorruption("qualification_object_links_corrupt")
                if row["status"] == "completed":
                    receipt_bytes = bytes(row["receipt_bytes"])
                    if hashlib.sha256(receipt_bytes).hexdigest() != row["receipt_sha256"]:
                        raise AvailabilityStateCorruption("qualification_receipt_tampered")
                    receipt = _parse_receipt(receipt_bytes)
                    _verify_receipt_signatures(receipt)
                    expected_linked = {
                        receipt.candidate_set_sha256,
                        receipt.qualification_context_sha256,
                        *(item.sha256 for item in receipt.retained_objects),
                        *(item.sha256 for item in receipt.authority_objects),
                    }
                    if (
                        receipt.window_id != row["window_id"]
                        or receipt.window_index != row["window_index"]
                        or receipt.candidate_set_sha256 != row["candidate_sha256"]
                        or receipt.qualification_context_identity_sha256
                        != row["context_identity_sha256"]
                        or receipt.qualification_context_sha256 != row["context_sha256"]
                        or receipt.availability_set_root != row["availability_set_root"]
                        or receipt.qualified_pool_leaves != leaves
                        or receipt.scoring_policy_hash != self.policy_hash
                        or account_id32(receipt.validator_hotkey)
                        != account_id32(self.validator_hotkey)
                        or linked != expected_linked
                        or not _receipt_matches_context(receipt, context)
                        or receipt.retained_objects != _retained_objects_from_manifest(candidate)
                        or receipt.authority_objects
                        != _authority_object_rows_from_store(context, connection)
                    ):
                        raise AvailabilityStateCorruption("qualification_receipt_binding_corrupt")

    @contextmanager
    def _connection(self):
        connection = sqlite3.connect(self.database_path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            yield connection
        finally:
            connection.close()

    @contextmanager
    def _transaction(self):
        with self._connection() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
            if sys_platform_is_darwin():
                connection.execute("PRAGMA fullfsync = ON")
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
            except BaseException:
                connection.rollback()
                raise
            else:
                connection.commit()


def qualification_context_identity_sha256(
    context: AvailabilityQualificationContext,
) -> str:
    """Hash common qualification facts while excluding the polling observation."""

    if not isinstance(context, AvailabilityQualificationContext):
        raise TypeError("context must be an AvailabilityQualificationContext")
    document = context.model_dump(mode="json", by_alias=True)
    del document["observed_finalized_block"]
    del document["observed_finalized_block_hash"]
    del document["observation_finality_evidence_sha256"]
    return hashlib.sha256(canonical_json_bytes(document)).hexdigest()


def qualification_receipt_digest(receipt: AvailabilityQualificationReceipt) -> bytes:
    """Return the domain-separated digest authenticating the full retention receipt."""

    if not isinstance(receipt, AvailabilityQualificationReceipt):
        raise TypeError("receipt must be an AvailabilityQualificationReceipt")
    document = receipt.model_dump(mode="json", by_alias=True)
    del document["receipt_signature"]
    return hashlib.sha256(
        b"umi-availability-qualification-receipt-v1\0" + canonical_json_bytes(document)
    ).digest()


def build_certified_release(
    validated: ValidatedCandidateBundle,
    receipts: Sequence[AvailabilityQualificationReceipt],
    *,
    policy: ScoringPolicy,
) -> CertifiedReleaseMaterial:
    """Aggregate a valid quorum and construct exact final manifests and mirror index."""

    if not receipts:
        raise AvailabilityWorkflowError("availability_receipts_missing")
    _require_shadow_policy(policy)
    receipts = tuple(sorted(receipts, key=lambda item: account_id32(item.validator_hotkey)))
    if len({account_id32(item.validator_hotkey) for item in receipts}) != len(receipts):
        raise AvailabilityWorkflowError("availability_receipt_signer_duplicate")
    reference = receipts[0]
    for receipt in receipts:
        _validate_receipt_against_candidate(receipt, validated, policy)
        if (
            receipt.active_validator_hotkeys != reference.active_validator_hotkeys
            or receipt.announcement_block_hash != reference.announcement_block_hash
            or receipt.announcement_timestamp_ms != reference.announcement_timestamp_ms
            or receipt.announcement_finality_evidence_sha256
            != reference.announcement_finality_evidence_sha256
            or receipt.active_validator_set_evidence_sha256
            != reference.active_validator_set_evidence_sha256
            or receipt.announcement_validator_proof_evidence_sha256
            != reference.announcement_validator_proof_evidence_sha256
            or receipt.protocol_state_continuity_evidence_sha256
            != reference.protocol_state_continuity_evidence_sha256
            or receipt.spent_registry_root != reference.spent_registry_root
            or receipt.spent_registry_evidence_sha256 != reference.spent_registry_evidence_sha256
            or receipt.spent_leaf_set_sha256 != reference.spent_leaf_set_sha256
        ):
            raise AvailabilityWorkflowError("availability_receipt_context_disagreement")
    certificate = AvailabilityCertificate(
        schema=AVAILABILITY_SCHEMA,
        availability_set_root=validated.set_root,
        qualified_pool_leaves=list(validated.leaves),
        signatures=[item.availability_signature for item in receipts],
    )
    verify_availability_certificate(
        certificate,
        validated.pool_bodies,
        active_validator_hotkeys=reference.active_validator_hotkeys,
        policy=policy,
    )
    certificate_bytes = canonical_json_bytes(certificate)

    final_by_publisher: dict[str, bytes] = {}
    pool_models: list[PoolManifest] = []
    for body in validated.pool_bodies:
        final = PoolManifest.model_validate(
            {
                **body.model_dump(mode="json", by_alias=True),
                "availability_certificate": certificate.model_dump(mode="json", by_alias=True),
            }
        )
        raw = canonical_json_bytes(final)
        if len(raw) > policy.limits.maximum_manifest_bytes:
            raise AvailabilityWorkflowError("final_pool_manifest_size_limit")
        reparsed = parse_pool_manifest_bytes(raw, policy=policy)
        if reparsed.body() != body:
            raise AvailabilityWorkflowError("final_pool_manifest_body_changed")
        pool_models.append(reparsed)
        final_by_publisher[body.publisher_hotkey] = raw

    objects = dict(validated.loaded.objects)
    descriptors: list[MirrorObjectDescriptor] = []
    released_pools: list[ReleasedPoolManifest] = []
    intents: list[PoolAnchorIntent] = []
    for final in sorted(pool_models, key=lambda item: account_id32(item.publisher_hotkey)):
        raw = final_by_publisher[final.publisher_hotkey]
        digest = hashlib.sha256(raw).hexdigest()
        _add_object(objects, digest, raw)
        descriptors.append(
            MirrorObjectDescriptor(
                kind="pool_manifest",
                publisher_hotkey=final.publisher_hotkey,
                path=_object_mirror_path(digest),
                sha256=digest,
                size_bytes=len(raw),
                media_type="application/json",
            )
        )
        released_pools.append(
            ReleasedPoolManifest(
                publisher_hotkey=final.publisher_hotkey,
                sha256=digest,
                size_bytes=len(raw),
            )
        )
        intents.append(
            PoolAnchorIntent(
                schema=POOL_ANCHOR_INTENT_SCHEMA,
                protocol=PROTOCOL_VERSION,
                netuid=policy.netuid,
                window_id=validated.loaded.manifest.window.window_id,
                closing_block=validated.loaded.manifest.window.closing_block,
                publisher_hotkey=final.publisher_hotkey,
                pallet="Commitments",
                call="set_commitment",
                fields=[PoolAnchorField(variant="Data::Sha256", sha256=digest)],
                pool_manifest_sha256=digest,
                broadcast_authorized=False,
                translation_weights_active=False,
                weight_submission_capability=False,
            )
        )

    for descriptor in validated.loaded.manifest.objects:
        if descriptor.kind == "pool_body":
            continue
        mirror_kind = descriptor.kind
        descriptors.append(
            MirrorObjectDescriptor(
                kind=mirror_kind,
                batch_id=descriptor.batch_id,
                challenge_id=descriptor.challenge_id,
                path=_object_mirror_path(descriptor.sha256),
                sha256=descriptor.sha256,
                size_bytes=descriptor.size_bytes,
                media_type=descriptor.media_type,
            )
        )
    descriptors.sort(key=_mirror_object_sort_key)
    mirror_index = MirrorWindowIndex(
        schema=MIRROR_WINDOW_INDEX_SCHEMA,
        protocol=PROTOCOL_VERSION,
        window_id=validated.loaded.manifest.window.window_id,
        window_index=validated.loaded.manifest.window.window_index,
        scoring_policy_hash=validated.loaded.manifest.window.scoring_policy_hash,
        objects=descriptors,
    )
    mirror_index_bytes = canonical_json_bytes(mirror_index)
    if len(mirror_index_bytes) > policy.limits.maximum_manifest_bytes:
        raise AvailabilityWorkflowError("mirror_index_size_limit")
    intents.sort(key=lambda item: account_id32(item.publisher_hotkey))
    anchor_intents_bytes = canonical_json_bytes(
        [item.model_dump(mode="json", by_alias=True) for item in intents]
    )
    receipt_hashes = sorted(
        (hashlib.sha256(canonical_json_bytes(item)).hexdigest() for item in receipts),
        key=bytes.fromhex,
    )
    for receipt in receipts:
        raw = canonical_json_bytes(receipt)
        _add_object(objects, hashlib.sha256(raw).hexdigest(), raw)
    release = CertifiedPoolRelease(
        schema=CERTIFIED_RELEASE_SCHEMA,
        protocol=PROTOCOL_VERSION,
        window=validated.loaded.manifest.window,
        candidate_set_sha256=validated.loaded.sha256,
        availability_certificate_sha256=hashlib.sha256(certificate_bytes).hexdigest(),
        availability_set_root=validated.set_root,
        qualified_pool_leaves=list(validated.leaves),
        signer_receipt_sha256s=receipt_hashes,
        qualification_receipts_directory=QUALIFICATION_RECEIPTS_DIRECTORY,
        pool_manifests=released_pools,
        mirror_index_path=DEFAULT_MIRROR_INDEX_PATH,
        mirror_index_sha256=hashlib.sha256(mirror_index_bytes).hexdigest(),
        mirror_index_size_bytes=len(mirror_index_bytes),
        anchor_intents_sha256=hashlib.sha256(anchor_intents_bytes).hexdigest(),
        broadcast_performed=False,
        translation_weights_active=False,
        weight_submission_capability=False,
    )
    release_bytes = canonical_json_bytes(release)
    return CertifiedReleaseMaterial(
        release=release,
        release_bytes=release_bytes,
        certificate=certificate,
        pool_manifest_bytes=final_by_publisher,
        mirror_index=mirror_index,
        mirror_index_bytes=mirror_index_bytes,
        anchor_intents=tuple(intents),
        anchor_intents_bytes=anchor_intents_bytes,
        objects=objects,
    )


def write_certified_release(output_root: str | Path, material: CertifiedReleaseMaterial) -> Path:
    """Write a static mirror tree and operator-visible, non-broadcast anchor intents."""

    if not isinstance(material, CertifiedReleaseMaterial):
        raise TypeError("material must be CertifiedReleaseMaterial")
    root = _new_output_directory(Path(output_root))
    mirror_objects = root / "v1" / "umi" / OBJECTS_DIRECTORY
    mirror_window = root / "v1" / "umi" / "windows" / material.release.window.window_id
    receipt_root = root / QUALIFICATION_RECEIPTS_DIRECTORY
    _make_private_directory(root / "v1")
    _make_private_directory(root / "v1" / "umi")
    _make_private_directory(mirror_objects)
    _make_private_directory(root / "v1" / "umi" / "windows")
    _make_private_directory(mirror_window)
    _make_private_directory(receipt_root)
    used_digests = {item.sha256 for item in material.mirror_index.objects}
    for digest in sorted(used_digests):
        raw = material.objects.get(digest)
        if raw is None or hashlib.sha256(raw).hexdigest() != digest:
            raise AvailabilityWorkflowError("certified_release_object_missing")
        _write_new_file(mirror_objects / digest, raw)
    _write_new_file(mirror_window / "pool-source.json", material.mirror_index_bytes)
    for digest in material.release.signer_receipt_sha256s:
        raw = material.objects.get(digest)
        if raw is None or hashlib.sha256(raw).hexdigest() != digest:
            raise AvailabilityWorkflowError("certified_release_receipt_missing")
        receipt = _parse_receipt(raw)
        _verify_receipt_signatures(receipt)
        _write_new_file(receipt_root / f"{digest}.json", raw)
    _write_new_file(root / ANCHOR_INTENTS_FILENAME, material.anchor_intents_bytes)
    _write_new_file(root / CERTIFIED_RELEASE_FILENAME, material.release_bytes)
    _fsync_directory(root)
    return root


def parse_qualification_receipt_bytes(raw: bytes) -> AvailabilityQualificationReceipt:
    """Parse one exact canonical receipt for publisher aggregation."""

    return _parse_receipt(raw)


def _validate_qualification_context(
    context: AvailabilityQualificationContext,
    loaded: LoadedCandidateBundle,
    policy: ScoringPolicy,
) -> None:
    if not isinstance(context, AvailabilityQualificationContext):
        raise TypeError("context must be an AvailabilityQualificationContext")
    window = loaded.manifest.window
    if (
        context.window_id != window.window_id
        or context.window_index != window.window_index
        or context.scoring_policy_hash != window.scoring_policy_hash
        or context.candidate_set_sha256 != loaded.sha256
    ):
        raise AvailabilityWorkflowError("qualification_context_candidate_mismatch")
    if window.scoring_policy_hash != scoring_policy_hash(policy):
        raise AvailabilityWorkflowError("qualification_context_policy_mismatch")
    clock = WindowClock(
        activation_block=policy.activation_block,
        window_stride_blocks=policy.clock.window_stride_blocks,
        proposal_blocks=policy.clock.proposal_blocks,
        anchor_blocks=policy.clock.anchor_blocks,
        target_block_interval_seconds=policy.clock.target_block_interval_seconds,
        selection_finality_buffer_seconds=policy.clock.selection_finality_buffer_seconds,
        issue_allowance_seconds=policy.clock.issue_allowance_seconds,
        response_window_seconds=policy.clock.response_window_seconds,
        delivery_grace_seconds=policy.clock.delivery_grace_seconds,
        reveal_margin_seconds=policy.clock.reveal_margin_seconds,
    )
    expected_schedule = clock.derive(
        window.window_index,
        netuid=policy.netuid,
        announcement_block_hash=context.announcement_block_hash,
        announcement_timestamp_ms=context.announcement_timestamp_ms,
        scoring_policy_hash=scoring_policy_hash(policy),
    )
    expected_window = AvailabilityWindow.from_plan(
        WindowPlan.from_schedule(
            expected_schedule,
            scoring_policy_hash=scoring_policy_hash(policy),
        )
    )
    if expected_window != window:
        raise AvailabilityWorkflowError("qualification_window_clock_mismatch")
    # The workflow intentionally enforces the stricter operational boundary:
    # all expensive qualification and the durable root reservation finish while
    # the proposal interval is still open.
    if (
        not window.announcement_block
        <= context.observed_finalized_block
        < (window.proposal_close_block)
    ):
        raise AvailabilityWorkflowError("qualification_outside_proposal_interval")
    if (
        context.observed_finalized_block == window.announcement_block
        and context.observed_finalized_block_hash != context.announcement_block_hash
    ):
        raise AvailabilityWorkflowError("qualification_observation_hash_mismatch")
    active_accounts = {account_id32(value) for value in context.active_validator_hotkeys}
    registered = {account_id32(item.validator_hotkey) for item in policy.validator_registry}
    if not active_accounts.issubset(registered):
        raise AvailabilityWorkflowError("qualification_active_validator_unregistered")
    if len(active_accounts) < 4:
        raise AvailabilityWorkflowError("qualification_active_validator_count")


def _validate_pool_limits_and_uniqueness(
    bodies: Sequence[PoolBody],
    public: Mapping[str, PublicBatchManifest],
    policy: ScoringPolicy,
) -> None:
    if len(bodies) > policy.limits.max_active_publishers:
        raise AvailabilityWorkflowError("candidate_publisher_limit")
    publishers = [account_id32(body.publisher_hotkey) for body in bodies]
    if len(set(publishers)) != len(publishers):
        raise AvailabilityWorkflowError("candidate_publisher_duplicate")
    registry = {account_id32(item.publisher_hotkey): item for item in policy.publisher_registry}
    groups: list[str] = []
    all_batch_ids: list[str] = []
    commitments: list[str] = []
    for body in bodies:
        entry = registry.get(account_id32(body.publisher_hotkey))
        if entry is None:
            raise AvailabilityWorkflowError("candidate_publisher_unregistered")
        groups.extend(entry.control_group_id for _ in body.batches)
        all_batch_ids.extend(item.batch_id for item in body.batches)
        commitments.extend(item.batch_commitment for item in body.batches)
    if len(set(groups)) > policy.limits.max_active_control_groups:
        raise AvailabilityWorkflowError("candidate_control_group_limit")
    if any(
        count > policy.limits.max_candidate_batches_per_group for count in Counter(groups).values()
    ):
        raise AvailabilityWorkflowError("candidate_group_batch_limit")
    if len(all_batch_ids) > policy.limits.max_candidate_batches_total:
        raise AvailabilityWorkflowError("candidate_total_batch_limit")
    if len(set(all_batch_ids)) != len(all_batch_ids):
        raise AvailabilityWorkflowError("candidate_batch_id_duplicate")
    if len(set(commitments)) != len(commitments):
        raise AvailabilityWorkflowError("candidate_batch_commitment_duplicate")
    if set(public) != set(all_batch_ids):
        raise AvailabilityWorkflowError("candidate_public_manifest_set_mismatch")


def _validate_public_duplicates_and_spent(
    bodies: Sequence[PoolBody],
    public: Mapping[str, PublicBatchManifest],
    *,
    spent_leaves: Collection[bytes],
) -> None:
    video_hashes = [item.media.sha256 for manifest in public.values() for item in manifest.items]
    frame_hashes = [
        item.media.frame_digest for manifest in public.values() for item in manifest.items
    ]
    if len(set(video_hashes)) != len(video_hashes):
        raise AvailabilityWorkflowError("candidate_video_digest_duplicate")
    if len(set(frame_hashes)) != len(frame_hashes):
        raise AvailabilityWorkflowError("candidate_frame_digest_duplicate")
    public_leaves = {
        *(spent_batch_leaf(entry.batch_commitment) for body in bodies for entry in body.batches),
        *(spent_video_leaf(value) for value in video_hashes),
        *(spent_frame_leaf(value) for value in frame_hashes),
    }
    if public_leaves.intersection(spent_leaves):
        raise AvailabilityWorkflowError("candidate_public_content_spent")


def _verify_media_inspection(
    inspection: MediaInspectionResult,
    media,
    policy: ScoringPolicy,
) -> None:
    profile = inspection.profile
    frames = inspection.frames
    expected_format = (
        inspection.video_sha256,
        profile.size_bytes,
        profile.duration * 1000,
        profile.width,
        profile.height,
        profile.frame_rate,
        profile.codec_name,
        "mp4" in profile.format_names,
        frames.frame_digest,
        frames.width,
        frames.height,
    )
    declared = (
        media.sha256,
        media.size_bytes,
        Fraction(media.duration_ms, 1),
        media.width,
        media.height,
        Fraction(media.frame_rate_numerator, media.frame_rate_denominator),
        media.video_codec,
        media.container == "mp4",
        media.frame_digest,
        media.width,
        media.height,
    )
    if expected_format != declared:
        raise AvailabilityWorkflowError("candidate_video_media_mismatch")
    if frames.decoder_sha256 != policy.implementation_pins.media.ffmpeg_binary_sha256:
        raise AvailabilityWorkflowError("candidate_video_decoder_pin_mismatch")
    if frames.probe_sha256 != policy.implementation_pins.media.ffprobe_binary_sha256:
        raise AvailabilityWorkflowError("candidate_video_probe_pin_mismatch")
    if not frames.executables_content_pinned:
        raise AvailabilityWorkflowError("candidate_video_tools_not_content_pinned")


def _qualification_receipt(
    validated: ValidatedCandidateBundle,
    context: AvailabilityQualificationContext,
    scheme: str,
    signature: str,
    receipt_signature: str,
    authority_objects: list[RetainedObject],
) -> AvailabilityQualificationReceipt:
    digest = availability_digest(context.window_id, validated.set_root)
    if not verify_response_signature(
        digest,
        hotkey_ss58=context.validator_hotkey,
        scheme=scheme,
        signature=signature,
    ):
        raise AvailabilityWorkflowError("availability_signature_invalid")
    return AvailabilityQualificationReceipt(
        schema=QUALIFICATION_RECEIPT_SCHEMA,
        protocol=PROTOCOL_VERSION,
        window_id=context.window_id,
        window_index=context.window_index,
        scoring_policy_hash=context.scoring_policy_hash,
        candidate_set_sha256=validated.loaded.sha256,
        candidate_set_size_bytes=len(validated.loaded.manifest_bytes),
        qualification_context_sha256=hashlib.sha256(canonical_json_bytes(context)).hexdigest(),
        qualification_context_identity_sha256=qualification_context_identity_sha256(context),
        announcement_block_hash=context.announcement_block_hash,
        announcement_timestamp_ms=context.announcement_timestamp_ms,
        announcement_finality_evidence_sha256=(context.announcement_finality_evidence_sha256),
        active_validator_set_evidence_sha256=(context.active_validator_set_evidence_sha256),
        announcement_validator_proof_evidence_sha256=(
            context.announcement_validator_proof_evidence_sha256
        ),
        protocol_state_continuity_evidence_sha256=(
            context.protocol_state_continuity_evidence_sha256
        ),
        qualified_at_finalized_block=context.observed_finalized_block,
        qualified_at_finalized_block_hash=context.observed_finalized_block_hash,
        observation_finality_evidence_sha256=(context.observation_finality_evidence_sha256),
        validator_hotkey=context.validator_hotkey,
        active_validator_hotkeys=context.active_validator_hotkeys,
        spent_registry_root=context.spent_registry_root,
        spent_registry_evidence_sha256=context.spent_registry_evidence_sha256,
        spent_leaf_set_sha256=_spent_leaf_set_sha256(context.spent_leaves),
        availability_set_root=validated.set_root,
        qualified_pool_leaves=list(validated.leaves),
        retained_objects=_retained_objects(validated.loaded),
        authority_objects=authority_objects,
        scheme=scheme,
        signature=signature,
        receipt_signature=receipt_signature,
        mirror_retention_required_through_round=validated.loaded.manifest.window.reveal_round,
        translation_weights_active=False,
        weight_submission_capability=False,
    )


def _validate_receipt_against_candidate(
    receipt: AvailabilityQualificationReceipt,
    validated: ValidatedCandidateBundle,
    policy: ScoringPolicy,
) -> None:
    if not isinstance(receipt, AvailabilityQualificationReceipt):
        raise TypeError("receipts must be AvailabilityQualificationReceipt objects")
    _verify_receipt_signatures(receipt)
    window = validated.loaded.manifest.window
    if (
        receipt.window_id != window.window_id
        or receipt.window_index != window.window_index
        or receipt.scoring_policy_hash != scoring_policy_hash(policy)
        or receipt.candidate_set_sha256 != validated.loaded.sha256
        or receipt.candidate_set_size_bytes != len(validated.loaded.manifest_bytes)
        or receipt.availability_set_root != validated.set_root
        or tuple(receipt.qualified_pool_leaves) != validated.leaves
        or receipt.mirror_retention_required_through_round != window.reveal_round
        or receipt.retained_objects != _retained_objects(validated.loaded)
        or not window.announcement_block
        <= receipt.qualified_at_finalized_block
        < window.proposal_close_block
    ):
        raise AvailabilityWorkflowError("availability_receipt_candidate_mismatch")
    authority_digests = {item.sha256 for item in receipt.authority_objects}
    expected_authority_digests = {
        receipt.active_validator_set_evidence_sha256,
        receipt.announcement_validator_proof_evidence_sha256,
        receipt.protocol_state_continuity_evidence_sha256,
        receipt.spent_registry_evidence_sha256,
        receipt.observation_finality_evidence_sha256,
    }
    if authority_digests != expected_authority_digests or any(
        item.media_type != "application/json" for item in receipt.authority_objects
    ):
        raise AvailabilityWorkflowError("availability_receipt_authority_mismatch")
    active_registered = {account_id32(item.validator_hotkey) for item in policy.validator_registry}
    active = {account_id32(value) for value in receipt.active_validator_hotkeys}
    if len(active) < 4 or not active.issubset(active_registered):
        raise AvailabilityWorkflowError("availability_receipt_active_set_invalid")


def _verify_receipt_signatures(receipt: AvailabilityQualificationReceipt) -> None:
    if not verify_response_signature(
        availability_digest(receipt.window_id, receipt.availability_set_root),
        hotkey_ss58=receipt.validator_hotkey,
        scheme=receipt.scheme,
        signature=receipt.signature,
    ):
        raise AvailabilityWorkflowError("availability_receipt_signature_invalid")
    if not verify_response_signature(
        qualification_receipt_digest(receipt),
        hotkey_ss58=receipt.validator_hotkey,
        scheme=receipt.scheme,
        signature=receipt.receipt_signature,
    ):
        raise AvailabilityWorkflowError("availability_receipt_attestation_invalid")


def _receipt_matches_context(
    receipt: AvailabilityQualificationReceipt,
    context: AvailabilityQualificationContext,
) -> bool:
    return (
        receipt.qualification_context_sha256
        == hashlib.sha256(canonical_json_bytes(context)).hexdigest()
        and receipt.qualification_context_identity_sha256
        == qualification_context_identity_sha256(context)
        and receipt.window_id == context.window_id
        and receipt.window_index == context.window_index
        and receipt.scoring_policy_hash == context.scoring_policy_hash
        and receipt.candidate_set_sha256 == context.candidate_set_sha256
        and receipt.announcement_block_hash == context.announcement_block_hash
        and receipt.announcement_timestamp_ms == context.announcement_timestamp_ms
        and receipt.announcement_finality_evidence_sha256
        == context.announcement_finality_evidence_sha256
        and receipt.active_validator_set_evidence_sha256
        == context.active_validator_set_evidence_sha256
        and receipt.announcement_validator_proof_evidence_sha256
        == context.announcement_validator_proof_evidence_sha256
        and receipt.protocol_state_continuity_evidence_sha256
        == context.protocol_state_continuity_evidence_sha256
        and receipt.qualified_at_finalized_block == context.observed_finalized_block
        and receipt.qualified_at_finalized_block_hash == context.observed_finalized_block_hash
        and receipt.observation_finality_evidence_sha256
        == context.observation_finality_evidence_sha256
        and account_id32(receipt.validator_hotkey) == account_id32(context.validator_hotkey)
        and receipt.active_validator_hotkeys == context.active_validator_hotkeys
        and receipt.spent_registry_root == context.spent_registry_root
        and receipt.spent_registry_evidence_sha256 == context.spent_registry_evidence_sha256
        and receipt.spent_leaf_set_sha256 == _spent_leaf_set_sha256(context.spent_leaves)
        and {item.sha256 for item in receipt.authority_objects}
        == _authority_object_digests(context)
    )


def _require_shadow_policy(policy: ScoringPolicy) -> None:
    if not isinstance(policy, ScoringPolicy):
        raise TypeError("policy must be a ScoringPolicy")
    if policy.translation_weights_active is not False:
        raise AvailabilityWorkflowError("availability_requires_shadow_policy")


def _retained_objects(loaded: LoadedCandidateBundle) -> list[RetainedObject]:
    return _retained_objects_from_manifest(loaded.manifest)


def _retained_objects_from_manifest(
    manifest: AvailabilityCandidateSet,
) -> list[RetainedObject]:
    distinct = {
        (item.sha256, item.media_type): RetainedObject(
            sha256=item.sha256,
            size_bytes=item.size_bytes,
            media_type=item.media_type,
        )
        for item in manifest.objects
    }
    return [
        distinct[key]
        for key in sorted(distinct, key=lambda item: (bytes.fromhex(item[0]), item[1]))
    ]


def _authority_object_digests(context: AvailabilityQualificationContext) -> frozenset[str]:
    digests = frozenset(
        {
            context.active_validator_set_evidence_sha256,
            context.announcement_validator_proof_evidence_sha256,
            context.protocol_state_continuity_evidence_sha256,
            context.spent_registry_evidence_sha256,
            context.observation_finality_evidence_sha256,
        }
    )
    if len(digests) != 5:
        raise AvailabilityWorkflowError("qualification_authority_digest_alias")
    return digests


def _validate_authority_objects(
    context: AvailabilityQualificationContext,
    objects: Mapping[str, bytes],
) -> dict[str, bytes]:
    expected = _authority_object_digests(context)
    if set(objects) != expected:
        raise AvailabilityWorkflowError("qualification_authority_object_set_mismatch")
    checked: dict[str, bytes] = {}
    for digest, data in objects.items():
        if not isinstance(digest, str) or _HEX32_RE.fullmatch(digest) is None:
            raise AvailabilityWorkflowError("qualification_authority_digest_invalid")
        if not isinstance(data, bytes) or not data or len(data) > MAX_CONTEXT_BYTES * 16:
            raise AvailabilityWorkflowError("qualification_authority_object_size_limit")
        if hashlib.sha256(data).hexdigest() != digest:
            raise AvailabilityWorkflowError("qualification_authority_object_digest_mismatch")
        try:
            value = json.loads(data)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise AvailabilityWorkflowError("qualification_authority_object_invalid") from error
        if canonical_json_bytes(value) != data:
            raise AvailabilityWorkflowError("qualification_authority_object_noncanonical")
        checked[digest] = data
    return checked


def _authority_object_rows(objects: Mapping[str, bytes]) -> list[RetainedObject]:
    return [
        RetainedObject(
            sha256=digest,
            size_bytes=len(objects[digest]),
            media_type="application/json",
        )
        for digest in sorted(objects, key=bytes.fromhex)
    ]


def _authority_object_rows_from_store(
    context: AvailabilityQualificationContext,
    connection: sqlite3.Connection,
) -> list[RetainedObject]:
    rows: list[RetainedObject] = []
    for digest in sorted(_authority_object_digests(context), key=bytes.fromhex):
        row = connection.execute(
            "SELECT size_bytes, media_type FROM retained_objects WHERE sha256 = ?",
            (digest,),
        ).fetchone()
        if row is None or row["media_type"] != "application/json":
            raise AvailabilityStateCorruption("qualification_authority_object_missing")
        rows.append(
            RetainedObject(
                sha256=digest,
                size_bytes=row["size_bytes"],
                media_type="application/json",
            )
        )
    return rows


def _verify_reservation(
    row: sqlite3.Row,
    validated: ValidatedCandidateBundle,
    context: AvailabilityQualificationContext,
    identity_hash: str,
) -> None:
    try:
        leaves = json.loads(row["leaves_json"])
    except json.JSONDecodeError as error:
        raise AvailabilityStateCorruption("qualification_leaves_corrupt") from error
    if (
        row["window_index"] != context.window_index
        or row["candidate_sha256"] != validated.loaded.sha256
        or row["context_identity_sha256"] != identity_hash
        or row["availability_set_root"] != validated.set_root
        or leaves != list(validated.leaves)
    ):
        raise AvailabilityStateConflict("availability_equivocation_prevented")


def _parse_receipt(raw: bytes) -> AvailabilityQualificationReceipt:
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_RECEIPT_BYTES:
        raise AvailabilityWorkflowError("qualification_receipt_size_limit")
    try:
        receipt = AvailabilityQualificationReceipt.model_validate_json(raw)
    except (ValidationError, ValueError) as error:
        raise AvailabilityWorkflowError("qualification_receipt_invalid") from error
    if canonical_json_bytes(receipt) != raw:
        raise AvailabilityWorkflowError("qualification_receipt_noncanonical")
    return receipt


def _candidate_descriptor(
    *,
    kind: str,
    data: bytes,
    media_type: str,
    publisher_hotkey: str | None = None,
    batch_id: str | None = None,
    challenge_id: str | None = None,
) -> CandidateObjectDescriptor:
    if not isinstance(data, bytes) or not data:
        raise TypeError("candidate artifacts must be nonempty exact bytes")
    return CandidateObjectDescriptor(
        kind=kind,
        publisher_hotkey=publisher_hotkey,
        batch_id=batch_id,
        challenge_id=challenge_id,
        sha256=hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
        media_type=media_type,
    )


def _candidate_object_sort_key(item: CandidateObjectDescriptor) -> tuple[object, ...]:
    publisher = account_id32(item.publisher_hotkey) if item.publisher_hotkey is not None else b""
    batch = base64url_decode(item.batch_id) if item.batch_id is not None else b""
    challenge = base64url_decode(item.challenge_id) if item.challenge_id is not None else b""
    return (
        _CANDIDATE_KIND_ORDER[item.kind],
        publisher,
        batch,
        challenge,
        bytes.fromhex(item.sha256),
    )


def _mirror_object_sort_key(item: MirrorObjectDescriptor) -> tuple[object, ...]:
    kind_order = {
        "pool_manifest": 0,
        "public_manifest": 1,
        "ground_truth_envelope": 2,
        "video": 3,
    }
    publisher = account_id32(item.publisher_hotkey) if item.publisher_hotkey is not None else b""
    batch = base64url_decode(item.batch_id) if item.batch_id is not None else b""
    challenge = base64url_decode(item.challenge_id) if item.challenge_id is not None else b""
    return kind_order[item.kind], publisher, batch, challenge, bytes.fromhex(item.sha256)


def _descriptor_ceiling(descriptor: CandidateObjectDescriptor) -> int:
    if descriptor.kind in {"pool_body", "public_manifest"}:
        return MAX_CANDIDATE_SET_BYTES
    if descriptor.kind == "ground_truth_envelope":
        return 16 * 1024 * 1024
    return 16 * 1024 * 1024


def _object_mirror_path(digest: str) -> str:
    _hex32(digest, "mirror object digest")
    return f"/v1/umi/objects/{digest}"


def _spent_leaf_set_sha256(leaves: Sequence[str]) -> str:
    return hashlib.sha256(
        b"umi-spent-leaf-set-v1\0"
        + len(leaves).to_bytes(4, "big")
        + b"".join(bytes.fromhex(value) for value in leaves)
    ).hexdigest()


def _add_object(objects: dict[str, bytes], digest: str, raw: bytes) -> None:
    existing = objects.get(digest)
    if existing is not None and existing != raw:
        raise RuntimeError("content-addressed candidate object collision")
    objects[digest] = raw


def _opaque_id(value: str, label: str) -> None:
    if len(base64url_decode(value)) != 16:
        raise ValueError(f"{label} must encode exactly 16 bytes")


def _hex32(value: str, label: str) -> str:
    if not isinstance(value, str) or _HEX32_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be 64 lowercase hexadecimal characters")
    return value


def _reason_code(value: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,127}", value) is None:
        raise ValueError("availability reason code is invalid")
    return value


def _private_state_directory(path: Path) -> Path:
    absolute = path.expanduser().absolute()
    if absolute.exists():
        metadata = absolute.lstat()
        if (
            absolute.is_symlink()
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_mode & 0o077
        ):
            raise AvailabilityWorkflowError("qualification_state_directory_unsafe")
    else:
        absolute.mkdir(parents=True, mode=0o700)
        os.chmod(absolute, 0o700)
        _fsync_directory(absolute.parent)
    return absolute


def _existing_real_directory(path: Path, *, label: str) -> Path:
    absolute = path.expanduser().absolute()
    try:
        metadata = absolute.lstat()
    except OSError as error:
        raise AvailabilityWorkflowError(f"{label}_unavailable") from error
    if absolute.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise AvailabilityWorkflowError(f"{label}_unsafe")
    return absolute


def _new_output_directory(path: Path) -> Path:
    absolute = path.expanduser().absolute()
    if absolute.exists() or absolute.is_symlink():
        raise AvailabilityWorkflowError("output_already_exists")
    absolute.mkdir(parents=True, mode=0o700)
    os.chmod(absolute, 0o700)
    _fsync_directory(absolute.parent)
    return absolute


def _make_private_directory(path: Path, *, exist_ok: bool = False) -> None:
    path.mkdir(mode=0o700, exist_ok=exist_ok)
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise AvailabilityWorkflowError("output_directory_unsafe")
    os.chmod(path, 0o700)
    _fsync_directory(path.parent)


def _content_store_inventory(
    root: Path,
    *,
    maximum_total_bytes: int,
) -> dict[str, int]:
    """Verify every retained file and count crash-left staging bytes."""

    inventory: dict[str, int] = {}
    total = 0
    try:
        entries = sorted(os.scandir(root), key=lambda item: item.name)
    except OSError as error:
        raise AvailabilityStateCorruption("retained_object_store_unavailable") from error
    for entry in entries:
        name = entry.name
        is_object = _HEX32_RE.fullmatch(name) is not None
        is_staging = re.fullmatch(r"\.[0-9a-f]{64}\.[A-Za-z0-9_-]+", name) is not None
        if not is_object and not is_staging:
            raise AvailabilityStateCorruption("retained_object_store_unknown_entry")
        size, digest = _stable_file_digest(
            Path(entry.path),
            maximum_bytes=maximum_total_bytes,
            allow_empty=is_staging,
        )
        if is_object and digest != name:
            raise AvailabilityStateCorruption("retained_object_tampered")
        inventory[name] = size
        total += size
        if total > maximum_total_bytes:
            raise AvailabilityStateCorruption("qualification_state_size_limit")
    return inventory


def _stable_file_digest(
    path: Path,
    *,
    maximum_bytes: int,
    allow_empty: bool,
) -> tuple[int, str]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise AvailabilityStateCorruption("retained_object_unavailable") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_mode & 0o077
            or (before.st_size == 0 and not allow_empty)
            or before.st_size < 0
            or before.st_size > maximum_bytes
        ):
            raise AvailabilityStateCorruption("retained_object_unsafe")
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(descriptor, _READ_CHUNK_BYTES)
            if not chunk:
                break
            total += len(chunk)
            if total > maximum_bytes:
                raise AvailabilityStateCorruption("qualification_state_size_limit")
            digest.update(chunk)
        after = os.fstat(descriptor)
        before_identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        if before_identity != after_identity or total != before.st_size:
            raise AvailabilityStateCorruption("retained_object_changed")
        return total, digest.hexdigest()
    finally:
        os.close(descriptor)


def _read_stable_file(path: Path, maximum_bytes: int, label: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
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

        def identity(value: os.stat_result) -> tuple[int, int, int, int]:
            return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)

        if identity(before) != identity(after) or total != before.st_size:
            raise AvailabilityWorkflowError(f"{label}_changed")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _write_new_file(path: Path, data: bytes) -> None:
    if not isinstance(data, bytes):
        raise TypeError("output must be exact bytes")
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("output write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _fsync_directory(path.parent)


def _store_content_addressed(path: Path, data: bytes) -> None:
    if path.exists():
        existing = _read_stable_file(path, len(data), "retained_object")
        if existing != data:
            raise AvailabilityStateCorruption("retained_object_content_conflict")
        return
    descriptor: int | None = None
    temporary: str | None = None
    try:
        descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        os.fchmod(descriptor, 0o600)
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("retained object write made no progress")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError:
            existing = _read_stable_file(path, len(data), "retained_object")
            if existing != data:
                raise AvailabilityStateCorruption("retained_object_content_conflict") from None
        _fsync_directory(path.parent)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary is not None:
            with suppress(FileNotFoundError):
                os.unlink(temporary)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def sys_platform_is_darwin() -> bool:
    # Kept tiny and local so the durability branch is obvious in review.
    import sys

    return sys.platform == "darwin"


__all__ = [
    "ANCHOR_INTENTS_FILENAME",
    "CANDIDATE_SET_FILENAME",
    "CANDIDATE_SET_SCHEMA",
    "CERTIFIED_RELEASE_FILENAME",
    "CERTIFIED_RELEASE_SCHEMA",
    "POOL_ANCHOR_INTENT_SCHEMA",
    "QUALIFICATION_CONTEXT_SCHEMA",
    "QUALIFICATION_RECEIPTS_DIRECTORY",
    "QUALIFICATION_RECEIPT_SCHEMA",
    "AvailabilityCandidateSet",
    "AvailabilityQualificationContext",
    "AvailabilityQualificationReceipt",
    "AvailabilityQualificationStore",
    "AvailabilityStateConflict",
    "AvailabilityStateCorruption",
    "AvailabilityWindow",
    "AvailabilityWorkflowError",
    "CandidateObjectDescriptor",
    "CertifiedPoolRelease",
    "CertifiedReleaseMaterial",
    "LoadedCandidateBundle",
    "PoolAnchorIntent",
    "RetainedObject",
    "ValidatedCandidateBundle",
    "build_candidate_set",
    "build_certified_release",
    "load_candidate_bundle",
    "parse_qualification_receipt_bytes",
    "qualification_context_identity_sha256",
    "qualification_receipt_digest",
    "qualify_candidate_set_component",
    "validate_candidate_bundle",
    "write_candidate_bundle",
    "write_certified_release",
]
