"""Production construction of one sealed version 0.1 publisher batch.

The availability workflow intentionally accepts only completed protocol objects.
This module supplies the preceding publisher-side boundary: it creates opaque
identifiers, checks the complete 12+2 launch shape, inspects exact video bytes,
constructs the public and hidden manifests, and timelocks the hidden payload.

Human consent, ASL fluency, review independence, and reference quality remain
external facts. The installed path requires the exact owner-held evidence files
behind their declared digests; it does not claim to establish those facts itself.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import stat
import tempfile
import time
from collections.abc import Callable, Mapping
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator
from typing_extensions import Self

try:
    import fcntl
except ImportError:  # pragma: no cover - production targets are Unix hosts
    fcntl = None

from .artifacts import (
    PUBLIC_BATCH_MANIFEST_SCHEMA,
    MediaCommitment,
    PublicBatchItem,
    PublicBatchManifest,
    validate_revealed_batch_shape,
)
from .canary import wer_canary_stratum
from .crypto import SealedResponse, parse_sealed_response, seal_response
from .encoding import account_id32
from .media import MediaConformanceError, MediaInspectionResult, inspect_media_pinned
from .policy import ScoringPolicy, scoring_policy_hash, validate_rehearsal_runtime
from .pool import (
    POOL_MANIFEST_SCHEMA,
    PoolBatchEntry,
    PoolBody,
    batch_commitment,
    parse_pool_body_bytes,
    verify_pool_artifacts,
)
from .protocol import (
    GROUND_TRUTH_SCHEMA,
    GROUND_TRUTH_TLE_PROFILE,
    PROTOCOL_VERSION,
    BlockHash,
    GroundTruthItem,
    GroundTruthPayload,
    Hex32,
    NonEmptyText,
    OpaqueId,
    ReferenceText,
    StrictProtocolModel,
    base64url_decode,
    base64url_encode,
    canonical_json_bytes,
    normalized_grapheme_count,
    normalized_token_count,
)
from .scoring import normalize_text
from .validator_state import WindowPlan
from .window import WindowClock, quicknet_round_at_ms

PUBLISHER_BATCH_IDENTITY_SCHEMA = "umi-publisher-batch-identity/1"
PUBLISHER_BATCH_SOURCE_SCHEMA = "umi-publisher-batch-source/1"
PUBLISHER_BATCH_RELEASE_SCHEMA = "umi-publisher-batch-release/1"
PUBLISHER_RESERVE_VIDEO_INSPECTION_SCHEMA = "umi-publisher-reserve-video-inspection/1"

MAXIMUM_PUBLISHER_BATCH_INPUT_BYTES = 4 * 1024 * 1024
MAXIMUM_PRIVATE_EVIDENCE_BYTES = 4 * 1024 * 1024
MAXIMUM_PRIVATE_SCRIPT_BYTES = 16 * 1024
MAXIMUM_OPAQUE_ID_DRAWS = 64

ORDINARY_FINGERSPELLING_ROLES = tuple(f"ordinary_fingerspelling_{index}" for index in range(1, 3))
ORDINARY_SHORT_ROLES = tuple(f"ordinary_short_utterance_{index}" for index in range(1, 5))
ORDINARY_CONTINUOUS_ROLES = tuple(f"ordinary_continuous_{index}" for index in range(1, 7))
CANARY_CER_ROLE = "canary_cer"
CANARY_WER_ROLE = "canary_wer"
PUBLISHER_BATCH_ROLES = (
    *ORDINARY_FINGERSPELLING_ROLES,
    *ORDINARY_SHORT_ROLES,
    *ORDINARY_CONTINUOUS_ROLES,
    CANARY_CER_ROLE,
    CANARY_WER_ROLE,
)
PublisherBatchRole = Literal[
    "ordinary_fingerspelling_1",
    "ordinary_fingerspelling_2",
    "ordinary_short_utterance_1",
    "ordinary_short_utterance_2",
    "ordinary_short_utterance_3",
    "ordinary_short_utterance_4",
    "ordinary_continuous_1",
    "ordinary_continuous_2",
    "ordinary_continuous_3",
    "ordinary_continuous_4",
    "ordinary_continuous_5",
    "ordinary_continuous_6",
    "canary_cer",
    "canary_wer",
]


class PublisherBatchError(RuntimeError):
    """Stable fail-closed publisher construction error."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class PublisherBatchWindow(StrictProtocolModel):
    """Exact finalized window material required before batch preparation."""

    window_id: Hex32
    window_index: Annotated[int, Field(ge=0)]
    scoring_policy_hash: Hex32
    announcement_block: Annotated[int, Field(ge=0)]
    announcement_block_hash: BlockHash
    announcement_timestamp_ms: Annotated[int, Field(ge=0)]
    proposal_close_block: Annotated[int, Field(gt=0)]
    closing_block: Annotated[int, Field(gt=0)]
    selection_round: Annotated[int, Field(gt=0)]
    issue_close_round: Annotated[int, Field(gt=0)]
    response_close_round: Annotated[int, Field(gt=0)]
    reveal_round: Annotated[int, Field(gt=0)]

    @model_validator(mode="after")
    def validate_window(self) -> Self:
        self.to_plan()
        return self

    @classmethod
    def from_plan(
        cls,
        plan: WindowPlan,
        *,
        announcement_block_hash: str,
        announcement_timestamp_ms: int,
    ) -> PublisherBatchWindow:
        if not isinstance(plan, WindowPlan):
            raise TypeError("plan must be a WindowPlan")
        return cls(
            window_id=plan.window_id,
            window_index=plan.window_index,
            scoring_policy_hash=plan.scoring_policy_hash,
            announcement_block=plan.announcement_block,
            announcement_block_hash=announcement_block_hash,
            announcement_timestamp_ms=announcement_timestamp_ms,
            proposal_close_block=plan.proposal_close_block,
            closing_block=plan.closing_block,
            selection_round=plan.selection_round,
            issue_close_round=plan.issue_close_round,
            response_close_round=plan.response_close_round,
            reveal_round=plan.reveal_round,
        )

    def to_plan(self) -> WindowPlan:
        return WindowPlan(
            window_id=self.window_id,
            window_index=self.window_index,
            scoring_policy_hash=self.scoring_policy_hash,
            announcement_block=self.announcement_block,
            proposal_close_block=self.proposal_close_block,
            closing_block=self.closing_block,
            selection_round=self.selection_round,
            issue_close_round=self.issue_close_round,
            response_close_round=self.response_close_round,
            reveal_round=self.reveal_round,
        )


class PublisherBatchIdentityItem(StrictProtocolModel):
    role: PublisherBatchRole
    challenge_id: OpaqueId


class PublisherBatchIdentity(StrictProtocolModel):
    """Private immutable identifier allocation created from OS randomness."""

    schema_: Literal[PUBLISHER_BATCH_IDENTITY_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    publisher_hotkey: NonEmptyText
    window: PublisherBatchWindow
    batch_id: OpaqueId
    items: Annotated[list[PublisherBatchIdentityItem], Field(min_length=14, max_length=14)]

    @model_validator(mode="after")
    def validate_identity(self) -> Self:
        account_id32(self.publisher_hotkey)
        roles = [item.role for item in self.items]
        if roles != list(PUBLISHER_BATCH_ROLES):
            raise ValueError("batch identity roles must use the canonical launch order")
        identifiers = [base64url_decode(item.challenge_id) for item in self.items]
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("batch identity challenge IDs must be unique")
        batch = base64url_decode(self.batch_id)
        if batch in identifiers:
            raise ValueError("batch and challenge identifiers must be distinct")
        return self

    @property
    def expected_wer_canary_stratum(self) -> Literal["short_utterance", "continuous"]:
        return wer_canary_stratum(self.window.window_id, self.batch_id)


class PublisherBatchSourceItem(StrictProtocolModel):
    """Private source record for one ordinary or canary clip."""

    role: PublisherBatchRole
    video_path: Annotated[str, Field(min_length=1, max_length=4096)]
    video_sha256: Hex32
    signer_id_sha256: Hex32
    consent_manifest_sha256: Hex32
    consent_manifest_path: Annotated[str, Field(min_length=1, max_length=4096)]
    provenance_manifest_sha256: Hex32
    provenance_manifest_path: Annotated[str, Field(min_length=1, max_length=4096)]
    review_manifest_sha256: Hex32
    review_manifest_path: Annotated[str, Field(min_length=1, max_length=4096)]
    script: Annotated[str, Field(min_length=1, max_length=MAXIMUM_PRIVATE_SCRIPT_BYTES)]
    references: Annotated[list[ReferenceText] | None, Field(default=None)]
    actual_references: Annotated[list[ReferenceText] | None, Field(default=None)]
    reserved_script: Annotated[
        str | None,
        Field(default=None, min_length=1, max_length=MAXIMUM_PRIVATE_SCRIPT_BYTES),
    ]
    mismatched_references: Annotated[list[ReferenceText] | None, Field(default=None)]

    @field_validator("script", "reserved_script")
    @classmethod
    def validate_private_script_bytes(cls, value: str | None) -> str | None:
        if value is not None and len(value.encode("utf-8")) > MAXIMUM_PRIVATE_SCRIPT_BYTES:
            raise ValueError("publisher script exceeds its private UTF-8 byte ceiling")
        return value

    @model_validator(mode="after")
    def validate_role_shape(self) -> Self:
        local_paths = (
            self.video_path,
            self.consent_manifest_path,
            self.provenance_manifest_path,
            self.review_manifest_path,
        )
        if any(not _is_absolute_normal_path(Path(value)) for value in local_paths):
            raise ValueError("publisher private paths must be absolute and normalized")
        if len(set(local_paths)) != len(local_paths):
            raise ValueError("one item must use distinct video and evidence paths")
        if not normalize_text(self.script):
            raise ValueError("publisher script has no canonical scoring units")
        canary = self.role in {CANARY_CER_ROLE, CANARY_WER_ROLE}
        if canary:
            if (
                self.references is not None
                or self.actual_references is None
                or self.reserved_script is None
                or not normalize_text(self.reserved_script)
                or self.mismatched_references is None
            ):
                raise ValueError("canary source fields are incomplete or ambiguous")
            if normalized_script_sha256(self.script) == normalized_script_sha256(
                self.reserved_script
            ):
                raise ValueError("canary scripts must normalize to different hashes")
        elif (
            self.references is None
            or self.actual_references is not None
            or self.reserved_script is not None
            or self.mismatched_references is not None
        ):
            raise ValueError("ordinary source fields are incomplete or contain canary data")
        return self


class PublisherBatchSource(StrictProtocolModel):
    """Complete private 14-item source set bound to one identifier allocation."""

    schema_: Literal[PUBLISHER_BATCH_SOURCE_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    identity_sha256: Hex32
    items: Annotated[list[PublisherBatchSourceItem], Field(min_length=14, max_length=14)]

    @model_validator(mode="after")
    def validate_items(self) -> Self:
        roles = [item.role for item in self.items]
        if roles != list(PUBLISHER_BATCH_ROLES):
            raise ValueError("batch source roles must use the canonical launch order")
        paths = [item.video_path for item in self.items]
        if len(set(paths)) != len(paths):
            raise ValueError("each launch item must name a distinct video path")
        evidence_paths = {
            path
            for item in self.items
            for path in (
                item.consent_manifest_path,
                item.provenance_manifest_path,
                item.review_manifest_path,
            )
        }
        if set(paths).intersection(evidence_paths):
            raise ValueError("video paths must not be reused as evidence paths")
        scripts: list[str] = []
        for item in self.items:
            scripts.append(normalized_script_sha256(item.script))
            if item.reserved_script is not None:
                scripts.append(normalized_script_sha256(item.reserved_script))
        if len(set(scripts)) != len(scripts):
            raise ValueError("batch scripts and canary reservations must be unique")
        return self


class PublisherReserveVideoInspection(StrictProtocolModel):
    """Private receipt for one policy-pinned reserve-video inspection."""

    schema_: Literal[PUBLISHER_RESERVE_VIDEO_INSPECTION_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    status: Literal["passed"]
    scoring_policy_hash: Hex32
    ffmpeg_binary_sha256: Hex32
    ffprobe_binary_sha256: Hex32
    frame_count: Annotated[int, Field(gt=0)]
    media: MediaCommitment
    state_mutated: Literal[False]
    translation_weights_active: Literal[False]


class PublisherBatchReleaseObject(StrictProtocolModel):
    kind: Literal["pool_body", "public_manifest", "ground_truth_envelope", "video"]
    relative_path: Annotated[str, Field(min_length=1, max_length=4096)]
    sha256: Hex32
    size_bytes: Annotated[int, Field(gt=0)]
    batch_id: OpaqueId | None
    challenge_id: OpaqueId | None


class PublisherBatchRelease(StrictProtocolModel):
    """Public digest index written last after every artifact is durable."""

    schema_: Literal[PUBLISHER_BATCH_RELEASE_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    window_id: Hex32
    window_index: Annotated[int, Field(ge=0)]
    scoring_policy_hash: Hex32
    publisher_hotkey: NonEmptyText
    batch_id: OpaqueId
    batch_commitment: Hex32
    objects: Annotated[list[PublisherBatchReleaseObject], Field(min_length=17, max_length=17)]
    translation_weights_active: Literal[False]
    weight_submission_capability: Literal[False]

    @model_validator(mode="after")
    def validate_release(self) -> Self:
        account_id32(self.publisher_hotkey)
        paths = [item.relative_path for item in self.objects]
        if paths != sorted(paths) or len(set(paths)) != len(paths):
            raise ValueError("publisher release objects must have unique sorted paths")
        kinds = [item.kind for item in self.objects]
        if kinds.count("pool_body") != 1 or kinds.count("public_manifest") != 1:
            raise ValueError("publisher release requires one pool body and public manifest")
        if kinds.count("ground_truth_envelope") != 1 or kinds.count("video") != 14:
            raise ValueError("publisher release requires one envelope and fourteen videos")
        fixed_paths = {
            "pool_body": "pool-body.json",
            "public_manifest": "public-manifest.json",
            "ground_truth_envelope": "ground-truth.tle",
        }
        challenges: list[bytes] = []
        for item in self.objects:
            if item.kind in fixed_paths:
                expected_batch = None if item.kind == "pool_body" else self.batch_id
                if (
                    item.relative_path != fixed_paths[item.kind]
                    or item.batch_id != expected_batch
                    or item.challenge_id is not None
                ):
                    raise ValueError("publisher release fixed-object identity is invalid")
            else:
                if item.batch_id != self.batch_id or item.challenge_id is None:
                    raise ValueError("publisher release video identity is invalid")
                challenge = base64url_decode(item.challenge_id)
                challenges.append(challenge)
                if item.relative_path != f"videos/{item.challenge_id}.mp4":
                    raise ValueError("publisher release video path is invalid")
        if len(set(challenges)) != 14:
            raise ValueError("publisher release video challenges must be unique")
        return self


@dataclass(frozen=True, slots=True)
class PublisherBatchPrepared:
    identity: PublisherBatchIdentity
    public_manifest: PublicBatchManifest
    ground_truth: GroundTruthPayload
    ground_truth_envelope: bytes
    pool_body: PoolBody
    video_bytes_by_challenge: Mapping[str, bytes]
    release: PublisherBatchRelease


@dataclass(frozen=True, slots=True)
class LoadedPublisherBatchRelease:
    root: Path
    release: PublisherBatchRelease
    pool_body: PoolBody
    public_manifest: PublicBatchManifest
    envelope_path: Path
    pool_body_path: Path
    public_manifest_path: Path
    video_paths_by_challenge: Mapping[str, Path]


InspectionFunction = Callable[[str | Path], MediaInspectionResult]
SealFunction = Callable[..., SealedResponse]


def normalized_script_sha256(script: str) -> str:
    """Hash the exact UTF-8 encoding of the Section 9.1-normalized script."""

    if not isinstance(script, str):
        raise TypeError("script must be text")
    normalized = normalize_text(script)
    if not normalized:
        raise ValueError("script has no canonical scoring units")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def derive_publisher_batch_window(
    *,
    policy: ScoringPolicy,
    window_index: int,
    announcement_block_hash: str,
    announcement_timestamp_ms: int,
    now_ms: int | None = None,
) -> PublisherBatchWindow:
    """Derive exact public window bytes from one externally finalized announcement."""

    if not isinstance(policy, ScoringPolicy):
        raise TypeError("policy must be a ScoringPolicy")
    validate_rehearsal_runtime(policy)
    if policy.translation_weights_active:
        raise PublisherBatchError("publisher_builder_requires_inactive_policy")
    schedule = _window_clock(policy).derive(
        window_index,
        netuid=policy.netuid,
        announcement_block_hash=announcement_block_hash,
        announcement_timestamp_ms=announcement_timestamp_ms,
        scoring_policy_hash=scoring_policy_hash(policy),
    )
    result = PublisherBatchWindow.from_plan(
        WindowPlan.from_schedule(schedule, scoring_policy_hash=scoring_policy_hash(policy)),
        announcement_block_hash=announcement_block_hash,
        announcement_timestamp_ms=announcement_timestamp_ms,
    )
    _require_future_publisher_window(result, now_ms=now_ms)
    return result


def create_publisher_batch_identity(
    *,
    policy: ScoringPolicy,
    window: PublisherBatchWindow,
    publisher_hotkey: str,
    random_bytes: Callable[[int], bytes] = secrets.token_bytes,
    now_ms: int | None = None,
) -> PublisherBatchIdentity:
    """Allocate one batch and fourteen challenge IDs from independent OS draws."""

    validate_publisher_batch_window(
        policy=policy,
        window=window,
        publisher_hotkey=publisher_hotkey,
        now_ms=now_ms,
    )
    if not callable(random_bytes):
        raise TypeError("random_bytes must be callable")
    generated: list[bytes] = []
    draws = 0
    while len(generated) < 15 and draws < MAXIMUM_OPAQUE_ID_DRAWS:
        draws += 1
        value = random_bytes(16)
        if not isinstance(value, bytes) or len(value) != 16:
            raise PublisherBatchError("opaque_id_randomness_invalid")
        if value not in generated:
            generated.append(value)
    if len(generated) != 15:
        raise PublisherBatchError("opaque_id_randomness_collision_limit")
    return PublisherBatchIdentity(
        schema=PUBLISHER_BATCH_IDENTITY_SCHEMA,
        protocol=PROTOCOL_VERSION,
        publisher_hotkey=publisher_hotkey,
        window=window,
        batch_id=base64url_encode(generated[0]),
        items=[
            PublisherBatchIdentityItem(role=role, challenge_id=base64url_encode(identifier))
            for role, identifier in zip(PUBLISHER_BATCH_ROLES, generated[1:], strict=True)
        ],
    )


def validate_publisher_batch_window(
    *,
    policy: ScoringPolicy,
    window: PublisherBatchWindow,
    publisher_hotkey: str,
    now_ms: int | None = None,
) -> None:
    """Check the public policy, exact derived schedule, publisher, and live round."""

    _validate_policy_window_publisher(policy, window, publisher_hotkey)
    _require_future_publisher_window(window, now_ms=now_ms)


def prepare_publisher_batch(
    *,
    policy: ScoringPolicy,
    identity: PublisherBatchIdentity,
    source: PublisherBatchSource,
    video_bytes_by_role: Mapping[str, bytes],
    inspection_by_role: Mapping[str, MediaInspectionResult],
    seal: SealFunction = seal_response,
    now_ms: int | None = None,
) -> PublisherBatchPrepared:
    """Build and internally replay one complete sealed publisher batch."""

    if not isinstance(policy, ScoringPolicy):
        raise TypeError("policy must be a ScoringPolicy")
    if not isinstance(identity, PublisherBatchIdentity):
        raise TypeError("identity must be a PublisherBatchIdentity")
    if not isinstance(source, PublisherBatchSource):
        raise TypeError("source must be a PublisherBatchSource")
    window_material = identity.window
    window = window_material.to_plan()
    _validate_policy_window_publisher(policy, window_material, identity.publisher_hotkey)
    _require_future_publisher_window(window_material, now_ms=now_ms)
    _validate_identity_source_binding(identity, source)
    _validate_private_source_evidence(source)
    if set(video_bytes_by_role) != set(PUBLISHER_BATCH_ROLES) or set(inspection_by_role) != set(
        PUBLISHER_BATCH_ROLES
    ):
        raise PublisherBatchError("publisher_batch_media_set_mismatch")
    if not callable(seal):
        raise TypeError("seal must be callable")

    identity_by_role = {item.role: item for item in identity.items}
    source_by_role = {item.role: item for item in source.items}
    public_items: list[PublicBatchItem] = []
    ground_items: list[GroundTruthItem] = []
    video_by_challenge: dict[str, bytes] = {}
    video_digests: set[str] = set()
    frame_digests: set[str] = set()
    for role in PUBLISHER_BATCH_ROLES:
        identity_item = identity_by_role[role]
        source_item = source_by_role[role]
        video = video_bytes_by_role[role]
        inspection = inspection_by_role[role]
        if not isinstance(video, bytes) or not video:
            raise PublisherBatchError("publisher_video_bytes_invalid")
        _validate_video_source_digest(video, source_item.video_sha256)
        _validate_inspection(video, inspection, policy)
        media = _media_commitment_from_inspection(inspection)
        if (
            inspection.video_sha256 in video_digests
            or inspection.frames.frame_digest in frame_digests
        ):
            raise PublisherBatchError("publisher_batch_media_duplicate")
        video_digests.add(inspection.video_sha256)
        frame_digests.add(inspection.frames.frame_digest)
        stratum, metric, canary = _role_shape(role, identity)
        script_hash = normalized_script_sha256(source_item.script)
        if canary:
            if (
                source_item.actual_references is None
                or source_item.reserved_script is None
                or source_item.mismatched_references is None
            ):
                raise RuntimeError("validated canary source lost required fields")
            reserved_hash = normalized_script_sha256(source_item.reserved_script)
            references = source_item.mismatched_references
            _validate_reference_set(
                source_item.actual_references,
                policy=policy,
                label="canary_actual_references",
            )
            _validate_reference_set(
                source_item.mismatched_references,
                policy=policy,
                label="canary_mismatched_references",
            )
            canary_evidence = {
                "actual_references": source_item.actual_references,
                "actual_script_sha256": script_hash,
                "reserved_script_sha256": reserved_hash,
                "mismatched_references": source_item.mismatched_references,
            }
            retirement = sorted({script_hash, reserved_hash})
        else:
            if source_item.references is None:
                raise RuntimeError("validated ordinary source lost its references")
            references = source_item.references
            _validate_reference_set(
                source_item.references,
                policy=policy,
                label="ordinary_references",
            )
            canary_evidence = None
            retirement = [script_hash]
        ground_items.append(
            GroundTruthItem(
                challenge_id=identity_item.challenge_id,
                metric=metric,
                canary=canary,
                references=references,
                canary_evidence=canary_evidence,
                normalized_script_sha256=script_hash,
                retirement_script_sha256s=retirement,
                consent_manifest_sha256=source_item.consent_manifest_sha256,
            )
        )
        public_items.append(
            PublicBatchItem(
                challenge_id=identity_item.challenge_id,
                metric=metric,
                stratum=stratum,
                media=media,
                signer_id_sha256=source_item.signer_id_sha256,
                consent_manifest_sha256=source_item.consent_manifest_sha256,
                provenance_manifest_sha256=source_item.provenance_manifest_sha256,
            )
        )
        video_by_challenge[identity_item.challenge_id] = video

    public_items.sort(key=lambda item: base64url_decode(item.challenge_id))
    ground_items.sort(key=lambda item: base64url_decode(item.challenge_id))
    ground_truth = GroundTruthPayload(
        schema=GROUND_TRUTH_SCHEMA,
        window_id=window.window_id,
        batch_id=identity.batch_id,
        scoring_policy_hash=scoring_policy_hash(policy),
        tle_profile=GROUND_TRUTH_TLE_PROFILE,
        response_close_round=window.response_close_round,
        reveal_round=window.reveal_round,
        items=ground_items,
    )
    ground_truth_bytes = canonical_json_bytes(ground_truth)
    sealed = seal(ground_truth_bytes, reveal_round=window.reveal_round)
    if not isinstance(sealed, SealedResponse):
        raise PublisherBatchError("publisher_timelock_result_invalid")
    if sealed.reveal_round != window.reveal_round:
        raise PublisherBatchError("publisher_timelock_round_mismatch")
    if len(sealed.portable_bytes) > policy.limits.maximum_ground_truth_envelope_bytes:
        raise PublisherBatchError("publisher_ground_truth_envelope_size_limit")
    public_manifest = PublicBatchManifest(
        schema=PUBLIC_BATCH_MANIFEST_SCHEMA,
        protocol=PROTOCOL_VERSION,
        window_id=window.window_id,
        batch_id=identity.batch_id,
        publisher_hotkey=identity.publisher_hotkey,
        scoring_policy_hash=scoring_policy_hash(policy),
        tle_profile=GROUND_TRUTH_TLE_PROFILE,
        response_close_round=window.response_close_round,
        reveal_round=window.reveal_round,
        ciphertext_sha256=sealed.sha256_hex,
        items=public_items,
    )
    validate_revealed_batch_shape(public_manifest, ground_truth, policy)
    if len(canonical_json_bytes(public_manifest)) > policy.limits.maximum_manifest_bytes:
        raise PublisherBatchError("publisher_public_manifest_size_limit")
    commitment = batch_commitment(public_manifest, sealed.portable_bytes, window.reveal_round)
    pool_body = PoolBody(
        schema=POOL_MANIFEST_SCHEMA,
        window_id=window.window_id,
        publisher_hotkey=identity.publisher_hotkey,
        scoring_policy_hash=scoring_policy_hash(policy),
        batches=[
            PoolBatchEntry(
                batch_id=identity.batch_id,
                batch_commitment=commitment,
                public_manifest_sha256=hashlib.sha256(
                    canonical_json_bytes(public_manifest)
                ).hexdigest(),
                ciphertext_sha256=sealed.sha256_hex,
                reveal_round=window.reveal_round,
            )
        ],
    )
    if len(canonical_json_bytes(pool_body)) > policy.limits.maximum_manifest_bytes:
        raise PublisherBatchError("publisher_pool_body_size_limit")
    try:
        verify_pool_artifacts(
            pool_body,
            public_manifests={identity.batch_id: public_manifest},
            ciphertexts={identity.batch_id: sealed.portable_bytes},
            policy=policy,
        )
    except Exception as error:
        raise PublisherBatchError("publisher_generated_artifact_replay_failed") from error
    release = _release_index(
        policy=policy,
        identity=identity,
        public_manifest=public_manifest,
        envelope=sealed.portable_bytes,
        pool_body=pool_body,
        videos=video_by_challenge,
        commitment=commitment,
    )
    return PublisherBatchPrepared(
        identity=identity,
        public_manifest=public_manifest,
        ground_truth=ground_truth,
        ground_truth_envelope=sealed.portable_bytes,
        pool_body=pool_body,
        video_bytes_by_challenge=video_by_challenge,
        release=release,
    )


def prepare_publisher_batch_from_paths(
    *,
    policy: ScoringPolicy,
    identity: PublisherBatchIdentity,
    source: PublisherBatchSource,
    ffmpeg: str = "ffmpeg",
    ffprobe: str = "ffprobe",
    now_ms: int | None = None,
) -> PublisherBatchPrepared:
    """Snapshot each source clip, inspect the snapshot, and build the batch."""

    video_bytes: dict[str, bytes] = {}
    inspections: dict[str, MediaInspectionResult] = {}
    _validate_policy_window_publisher(policy, identity.window, identity.publisher_hotkey)
    _require_future_publisher_window(identity.window, now_ms=now_ms)
    _validate_identity_source_binding(identity, source)
    _validate_private_source_evidence(source)
    with tempfile.TemporaryDirectory(prefix="umi-publisher-batch-") as temporary:
        root = Path(temporary)
        for index, item in enumerate(source.items):
            payload = _read_private_regular_file(
                Path(item.video_path),
                maximum_bytes=policy.limits.maximum_clip_size_bytes,
                label="publisher_video",
            )
            _validate_video_source_digest(payload, item.video_sha256)
            snapshot = root / f"{index:02d}.mp4"
            snapshot.write_bytes(payload)
            snapshot.chmod(0o400)
            inspection = inspect_media_pinned(
                snapshot,
                expected_ffmpeg_sha256=policy.implementation_pins.media.ffmpeg_binary_sha256,
                expected_ffprobe_sha256=policy.implementation_pins.media.ffprobe_binary_sha256,
                ffmpeg=ffmpeg,
                ffprobe=ffprobe,
                maximum_clip_size=policy.limits.maximum_clip_size_bytes,
            )
            video_bytes[item.role] = payload
            inspections[item.role] = inspection
        return prepare_publisher_batch(
            policy=policy,
            identity=identity,
            source=source,
            video_bytes_by_role=video_bytes,
            inspection_by_role=inspections,
            now_ms=now_ms,
        )


def inspect_publisher_reserve_video(
    *,
    policy: ScoringPolicy,
    video_path: str | Path,
    expected_video_sha256: str,
    ffmpeg: str = "ffmpeg",
    ffprobe: str = "ffprobe",
) -> PublisherReserveVideoInspection:
    """Inspect one owner-held reserve clip with the policy-pinned media path."""

    if not isinstance(policy, ScoringPolicy):
        raise TypeError("reserve-video inspection requires a ScoringPolicy")
    validate_rehearsal_runtime(policy)
    if policy.translation_weights_active:
        raise PublisherBatchError("publisher_builder_requires_inactive_policy")
    _validate_expected_video_sha256(expected_video_sha256)
    payload = _read_private_regular_file(
        Path(video_path),
        maximum_bytes=policy.limits.maximum_clip_size_bytes,
        label="publisher_reserve_video",
    )
    _validate_video_source_digest(payload, expected_video_sha256)
    with tempfile.TemporaryDirectory(prefix="umi-publisher-reserve-video-") as temporary:
        snapshot = Path(temporary) / "reserve.mp4"
        snapshot.write_bytes(payload)
        snapshot.chmod(0o400)
        try:
            inspection = inspect_media_pinned(
                snapshot,
                expected_ffmpeg_sha256=policy.implementation_pins.media.ffmpeg_binary_sha256,
                expected_ffprobe_sha256=policy.implementation_pins.media.ffprobe_binary_sha256,
                ffmpeg=ffmpeg,
                ffprobe=ffprobe,
                maximum_clip_size=policy.limits.maximum_clip_size_bytes,
            )
        except MediaConformanceError as error:
            raise PublisherBatchError("publisher_reserve_media_inspection_failed") from error
        _validate_inspection(payload, inspection, policy)
        media = _media_commitment_from_inspection(inspection)
    return PublisherReserveVideoInspection(
        schema=PUBLISHER_RESERVE_VIDEO_INSPECTION_SCHEMA,
        protocol=PROTOCOL_VERSION,
        status="passed",
        scoring_policy_hash=scoring_policy_hash(policy),
        ffmpeg_binary_sha256=policy.implementation_pins.media.ffmpeg_binary_sha256,
        ffprobe_binary_sha256=policy.implementation_pins.media.ffprobe_binary_sha256,
        frame_count=inspection.frames.frame_count,
        media=media,
        state_mutated=False,
        translation_weights_active=False,
    )


def write_publisher_batch(prepared: PublisherBatchPrepared, output: str | Path) -> Path:
    """Atomically install one immutable public publisher batch directory."""

    if not isinstance(prepared, PublisherBatchPrepared):
        raise TypeError("prepared must be a PublisherBatchPrepared")
    destination = Path(output)
    if not _is_absolute_normal_path(destination):
        raise ValueError("publisher batch output must be absolute")
    _require_private_directory(destination.parent, "publisher_batch_output_parent")
    with _destination_lock(destination):
        if os.path.lexists(destination):
            raise FileExistsError("publisher batch output already exists")
        temporary = Path(tempfile.mkdtemp(prefix=f".{destination.name}.", dir=destination.parent))
        try:
            temporary.chmod(0o700)
            files = _prepared_files(prepared)
            release_name = "publisher-batch-release.json"
            release_payload = files.pop(release_name)
            # Creation order is observable on common filesystems. Write by the
            # public opaque pathname so directory order cannot preserve the
            # private source-role order and identify either canary.
            for relative, payload in sorted(files.items()):
                path = temporary / relative
                path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                _write_file_bytes(path, payload, mode=0o400)
            _write_file_bytes(temporary / release_name, release_payload, mode=0o400)
            _seal_directory_tree(temporary)
            _fsync_tree(temporary)
            if os.path.lexists(destination):
                raise FileExistsError("publisher batch output already exists")
            os.rename(temporary, destination)
            _fsync_directory(destination.parent)
        except BaseException:
            _remove_private_tree(temporary)
            raise
    return destination


def write_publisher_batch_identity(
    identity: PublisherBatchIdentity,
    output: str | Path,
) -> Path:
    """Atomically create one read-only owner-held identity file."""

    if not isinstance(identity, PublisherBatchIdentity):
        raise TypeError("identity must be a PublisherBatchIdentity")
    destination = Path(output)
    if not _is_absolute_normal_path(destination):
        raise ValueError("publisher identity output must be absolute and normalized")
    _require_private_directory(destination.parent, "publisher_identity_output_parent")
    with _destination_lock(destination):
        if os.path.lexists(destination):
            raise FileExistsError("publisher identity output already exists")
        descriptor, temporary_text = tempfile.mkstemp(
            prefix=f".{destination.name}.",
            dir=destination.parent,
        )
        temporary = Path(temporary_text)
        try:
            payload = canonical_json_bytes(identity)
            os.fchmod(descriptor, 0o400)
            _write_descriptor_bytes(descriptor, payload)
            os.fsync(descriptor)
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o400
            ):
                raise PublisherBatchError("publisher_identity_output_unsafe")
            os.close(descriptor)
            descriptor = -1
            if os.path.lexists(destination):
                raise FileExistsError("publisher identity output already exists")
            os.rename(temporary, destination)
            _fsync_directory(destination.parent)
        except BaseException:
            if descriptor >= 0:
                with suppress(OSError):
                    os.close(descriptor)
            with suppress(OSError):
                temporary.chmod(0o600)
                temporary.unlink()
            raise
    return destination


def write_private_publisher_document(document: object, output: str | Path) -> Path:
    """Atomically write canonical owner-only JSON used by a later publisher step."""

    payload = canonical_json_bytes(document)
    destination = Path(output)
    if not _is_absolute_normal_path(destination):
        raise ValueError("publisher document output must be absolute and normalized")
    _require_private_directory(destination.parent, "publisher_document_output_parent")
    with _destination_lock(destination):
        if os.path.lexists(destination):
            raise FileExistsError("publisher document output already exists")
        descriptor, temporary_text = tempfile.mkstemp(
            prefix=f".{destination.name}.",
            dir=destination.parent,
        )
        temporary = Path(temporary_text)
        try:
            os.fchmod(descriptor, 0o400)
            _write_descriptor_bytes(descriptor, payload)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            if os.path.lexists(destination):
                raise FileExistsError("publisher document output already exists")
            os.rename(temporary, destination)
            _fsync_directory(destination.parent)
        except BaseException:
            if descriptor >= 0:
                with suppress(OSError):
                    os.close(descriptor)
            with suppress(OSError):
                temporary.chmod(0o600)
                temporary.unlink()
            raise
    return destination


def load_publisher_batch_release(
    root: str | Path,
    *,
    policy: ScoringPolicy,
    window: PublisherBatchWindow,
) -> LoadedPublisherBatchRelease:
    """Replay one immutable batch output before generating availability input."""

    if not isinstance(policy, ScoringPolicy) or not isinstance(window, PublisherBatchWindow):
        raise TypeError("publisher release loading requires a policy and window")
    release_root = Path(root)
    _require_release_directory(release_root)
    release_raw = _read_public_regular_file(
        release_root / "publisher-batch-release.json",
        maximum_bytes=MAXIMUM_PUBLISHER_BATCH_INPUT_BYTES,
        label="publisher_batch_release",
    )
    try:
        release = PublisherBatchRelease.model_validate_json(release_raw)
    except Exception as error:
        raise PublisherBatchError("publisher_batch_release_invalid") from error
    if canonical_json_bytes(release) != release_raw:
        raise PublisherBatchError("publisher_batch_release_noncanonical")
    if (
        release.window_id != window.window_id
        or release.window_index != window.window_index
        or release.scoring_policy_hash != scoring_policy_hash(policy)
    ):
        raise PublisherBatchError("publisher_batch_release_window_mismatch")
    _validate_policy_window_publisher(policy, window, release.publisher_hotkey)

    expected_paths = {
        "publisher-batch-release.json",
        *(item.relative_path for item in release.objects),
    }
    actual_paths = _release_file_inventory(release_root)
    if actual_paths != expected_paths:
        raise PublisherBatchError("publisher_batch_release_file_set_mismatch")

    bytes_by_path: dict[str, bytes] = {}
    for item in release.objects:
        maximum = {
            "pool_body": policy.limits.maximum_manifest_bytes,
            "public_manifest": policy.limits.maximum_manifest_bytes,
            "ground_truth_envelope": policy.limits.maximum_ground_truth_envelope_bytes,
            "video": policy.limits.maximum_clip_size_bytes,
        }[item.kind]
        payload = _read_public_regular_file(
            release_root / item.relative_path,
            maximum_bytes=maximum,
            label="publisher_batch_release_object",
        )
        if len(payload) != item.size_bytes or not hmac.compare_digest(
            hashlib.sha256(payload).hexdigest(), item.sha256
        ):
            raise PublisherBatchError("publisher_batch_release_object_mismatch")
        bytes_by_path[item.relative_path] = payload

    pool_raw = bytes_by_path["pool-body.json"]
    public_raw = bytes_by_path["public-manifest.json"]
    envelope = bytes_by_path["ground-truth.tle"]
    try:
        pool_body = parse_pool_body_bytes(pool_raw, policy=policy)
        public_manifest = PublicBatchManifest.model_validate_json(public_raw)
    except Exception as error:
        raise PublisherBatchError("publisher_batch_release_protocol_invalid") from error
    if canonical_json_bytes(public_manifest) != public_raw:
        raise PublisherBatchError("publisher_batch_release_public_noncanonical")
    if (
        public_manifest.batch_id != release.batch_id
        or public_manifest.publisher_hotkey != release.publisher_hotkey
        or public_manifest.window_id != release.window_id
        or public_manifest.response_close_round != window.response_close_round
        or public_manifest.reveal_round != window.reveal_round
    ):
        raise PublisherBatchError("publisher_batch_release_identity_mismatch")
    try:
        verify_pool_artifacts(
            pool_body,
            public_manifests={release.batch_id: public_manifest},
            ciphertexts={release.batch_id: envelope},
            policy=policy,
        )
        parse_sealed_response(
            base64url_encode(envelope),
            reveal_round=window.reveal_round,
            sha256_hex=hashlib.sha256(envelope).hexdigest(),
        )
    except Exception as error:
        raise PublisherBatchError("publisher_batch_release_binding_invalid") from error
    if len(pool_body.batches) != 1 or pool_body.batches[0].batch_commitment != (
        release.batch_commitment
    ):
        raise PublisherBatchError("publisher_batch_release_commitment_mismatch")

    video_paths: dict[str, Path] = {}
    manifest_challenges = {item.challenge_id: item for item in public_manifest.items}
    for item in release.objects:
        if item.kind != "video" or item.challenge_id is None:
            continue
        manifest_item = manifest_challenges.get(item.challenge_id)
        if (
            manifest_item is None
            or manifest_item.media.sha256 != item.sha256
            or manifest_item.media.size_bytes != item.size_bytes
        ):
            raise PublisherBatchError("publisher_batch_release_video_binding_invalid")
        video_paths[item.challenge_id] = release_root / item.relative_path
    if set(video_paths) != set(manifest_challenges):
        raise PublisherBatchError("publisher_batch_release_video_set_mismatch")
    return LoadedPublisherBatchRelease(
        root=release_root,
        release=release,
        pool_body=pool_body,
        public_manifest=public_manifest,
        envelope_path=release_root / "ground-truth.tle",
        pool_body_path=release_root / "pool-body.json",
        public_manifest_path=release_root / "public-manifest.json",
        video_paths_by_challenge=video_paths,
    )


def read_canonical_public_publisher_input(path: str | Path, model_type: type):
    """Read one canonical public input from stable non-writable bytes."""

    raw = _read_public_regular_file(
        Path(path), maximum_bytes=MAXIMUM_PUBLISHER_BATCH_INPUT_BYTES, label="publisher_input"
    )
    try:
        value = model_type.model_validate_json(raw)
    except Exception as error:
        raise PublisherBatchError("publisher_input_invalid") from error
    if canonical_json_bytes(value) != raw:
        raise PublisherBatchError("publisher_input_noncanonical")
    return value


def read_canonical_private_publisher_input(path: str | Path, model_type: type):
    """Read canonical owner-only source material without following links."""

    raw = _read_private_regular_file(
        Path(path),
        maximum_bytes=MAXIMUM_PUBLISHER_BATCH_INPUT_BYTES,
        label="publisher_private_input",
    )
    try:
        value = model_type.model_validate_json(raw)
    except Exception as error:
        raise PublisherBatchError("publisher_private_input_invalid") from error
    if canonical_json_bytes(value) != raw:
        raise PublisherBatchError("publisher_private_input_noncanonical")
    return value


def _validate_policy_window_publisher(
    policy: ScoringPolicy,
    window: PublisherBatchWindow,
    publisher_hotkey: str,
) -> None:
    if not isinstance(policy, ScoringPolicy) or not isinstance(window, PublisherBatchWindow):
        raise TypeError("publisher identity requires a policy and PublisherBatchWindow")
    validate_rehearsal_runtime(policy)
    if policy.translation_weights_active:
        raise PublisherBatchError("publisher_builder_requires_inactive_policy")
    if window.scoring_policy_hash != scoring_policy_hash(policy):
        raise PublisherBatchError("publisher_window_policy_mismatch")
    expected = _window_clock(policy).derive(
        window.window_index,
        netuid=policy.netuid,
        announcement_block_hash=window.announcement_block_hash,
        announcement_timestamp_ms=window.announcement_timestamp_ms,
        scoring_policy_hash=window.scoring_policy_hash,
    )
    if (
        WindowPlan.from_schedule(
            expected,
            scoring_policy_hash=window.scoring_policy_hash,
        )
        != window.to_plan()
    ):
        raise PublisherBatchError("publisher_window_schedule_mismatch")
    registered = {account_id32(item.publisher_hotkey) for item in policy.publisher_registry}
    if account_id32(publisher_hotkey) not in registered:
        raise PublisherBatchError("publisher_not_registered")


def _window_clock(policy: ScoringPolicy) -> WindowClock:
    clock = policy.clock
    return WindowClock(
        activation_block=policy.activation_block,
        window_stride_blocks=clock.window_stride_blocks,
        proposal_blocks=clock.proposal_blocks,
        anchor_blocks=clock.anchor_blocks,
        target_block_interval_seconds=clock.target_block_interval_seconds,
        selection_finality_buffer_seconds=clock.selection_finality_buffer_seconds,
        issue_allowance_seconds=clock.issue_allowance_seconds,
        response_window_seconds=clock.response_window_seconds,
        delivery_grace_seconds=clock.delivery_grace_seconds,
        reveal_margin_seconds=clock.reveal_margin_seconds,
    )


def _require_future_publisher_window(
    window: PublisherBatchWindow,
    *,
    now_ms: int | None,
) -> None:
    observed_ms = time.time_ns() // 1_000_000 if now_ms is None else now_ms
    if isinstance(observed_ms, bool) or not isinstance(observed_ms, int) or observed_ms < 0:
        raise ValueError("now_ms must be a non-negative integer")
    if window.response_close_round <= quicknet_round_at_ms(observed_ms):
        raise PublisherBatchError("publisher_window_response_close_not_future")


def _validate_reference_set(
    references: list[str],
    *,
    policy: ScoringPolicy,
    label: str,
) -> None:
    limits = policy.limits
    if (
        not limits.minimum_accepted_references
        <= len(references)
        <= limits.maximum_accepted_references
    ):
        raise PublisherBatchError(f"publisher_{label}_count")
    normalized: list[str] = []
    for value in references:
        try:
            encoded = value.encode("utf-8")
        except UnicodeEncodeError as error:
            raise PublisherBatchError(f"publisher_{label}_utf8") from error
        if (
            len(encoded) > limits.maximum_reference_utf8_bytes
            or normalized_token_count(value) > limits.maximum_reference_tokens
            or normalized_grapheme_count(value) > limits.maximum_reference_graphemes
        ):
            raise PublisherBatchError(f"publisher_{label}_limit")
        normalized.append(normalize_text(value))
    if len(set(normalized)) != len(normalized):
        raise PublisherBatchError(f"publisher_{label}_duplicate")


def _validate_identity_source_binding(
    identity: PublisherBatchIdentity,
    source: PublisherBatchSource,
) -> None:
    identity_sha256 = hashlib.sha256(canonical_json_bytes(identity)).hexdigest()
    if not hmac.compare_digest(source.identity_sha256, identity_sha256):
        raise PublisherBatchError("publisher_batch_identity_mismatch")


def _validate_private_source_evidence(source: PublisherBatchSource) -> None:
    for item in source.items:
        for label, path_text, expected in (
            (
                "publisher_consent_manifest",
                item.consent_manifest_path,
                item.consent_manifest_sha256,
            ),
            (
                "publisher_provenance_manifest",
                item.provenance_manifest_path,
                item.provenance_manifest_sha256,
            ),
            (
                "publisher_review_manifest",
                item.review_manifest_path,
                item.review_manifest_sha256,
            ),
        ):
            payload = _read_private_regular_file(
                Path(path_text),
                maximum_bytes=MAXIMUM_PRIVATE_EVIDENCE_BYTES,
                label=label,
            )
            if not hmac.compare_digest(hashlib.sha256(payload).hexdigest(), expected):
                raise PublisherBatchError(f"{label}_digest_mismatch")


def _role_shape(
    role: str,
    identity: PublisherBatchIdentity,
) -> tuple[
    Literal["fingerspelling", "short_utterance", "continuous"],
    Literal["cer", "wer"],
    bool,
]:
    if role in ORDINARY_FINGERSPELLING_ROLES or role == CANARY_CER_ROLE:
        return "fingerspelling", "cer", role == CANARY_CER_ROLE
    if role in ORDINARY_SHORT_ROLES:
        return "short_utterance", "wer", False
    if role in ORDINARY_CONTINUOUS_ROLES:
        return "continuous", "wer", False
    if role == CANARY_WER_ROLE:
        return identity.expected_wer_canary_stratum, "wer", True
    raise RuntimeError("validated identity contains an unknown publisher role")


def _validate_inspection(
    video: bytes,
    inspection: MediaInspectionResult,
    policy: ScoringPolicy,
) -> None:
    if not isinstance(inspection, MediaInspectionResult):
        raise PublisherBatchError("publisher_media_inspection_invalid")
    profile = inspection.profile
    frames = inspection.frames
    if (
        hashlib.sha256(video).hexdigest() != inspection.video_sha256
        or len(video) != profile.size_bytes
        or profile.size_bytes > policy.limits.maximum_clip_size_bytes
        or profile.duration * 1000 < policy.limits.minimum_clip_duration_ms
        or profile.duration * 1000 > policy.limits.maximum_clip_duration_ms
        or profile.width > policy.limits.maximum_clip_width
        or profile.height > policy.limits.maximum_clip_height
        or profile.frame_rate > policy.limits.maximum_clip_fps
        or profile.codec_name != "h264"
        or "mp4" not in profile.format_names
        or frames.width != profile.width
        or frames.height != profile.height
        or frames.decoder_sha256 != policy.implementation_pins.media.ffmpeg_binary_sha256
        or frames.probe_sha256 != policy.implementation_pins.media.ffprobe_binary_sha256
        or not frames.executables_content_pinned
    ):
        raise PublisherBatchError("publisher_media_inspection_mismatch")


def _media_commitment_from_inspection(inspection: MediaInspectionResult) -> MediaCommitment:
    duration_ms = inspection.profile.duration * 1000
    if duration_ms.denominator != 1:
        raise PublisherBatchError("publisher_video_duration_not_integer_milliseconds")
    return MediaCommitment(
        sha256=inspection.video_sha256,
        frame_digest=inspection.frames.frame_digest,
        size_bytes=inspection.profile.size_bytes,
        duration_ms=duration_ms.numerator,
        width=inspection.profile.width,
        height=inspection.profile.height,
        frame_rate_numerator=inspection.profile.frame_rate.numerator,
        frame_rate_denominator=inspection.profile.frame_rate.denominator,
        media_type="video/mp4",
        container="mp4",
        video_codec="h264",
        audio_track_count=0,
        metadata_stripped=True,
    )


def _validate_expected_video_sha256(value: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise PublisherBatchError("publisher_reserve_expected_video_sha256_invalid")


def _validate_video_source_digest(video: bytes, expected: str) -> None:
    if not hmac.compare_digest(hashlib.sha256(video).hexdigest(), expected):
        raise PublisherBatchError("publisher_video_digest_mismatch")


def _release_index(
    *,
    policy: ScoringPolicy,
    identity: PublisherBatchIdentity,
    public_manifest: PublicBatchManifest,
    envelope: bytes,
    pool_body: PoolBody,
    videos: Mapping[str, bytes],
    commitment: str,
) -> PublisherBatchRelease:
    fixed = {
        "pool-body.json": ("pool_body", canonical_json_bytes(pool_body), None),
        "public-manifest.json": (
            "public_manifest",
            canonical_json_bytes(public_manifest),
            identity.batch_id,
        ),
        "ground-truth.tle": ("ground_truth_envelope", envelope, identity.batch_id),
    }
    records: list[PublisherBatchReleaseObject] = []
    for relative, (kind, payload, batch_id) in fixed.items():
        records.append(
            PublisherBatchReleaseObject(
                kind=kind,
                relative_path=relative,
                sha256=hashlib.sha256(payload).hexdigest(),
                size_bytes=len(payload),
                batch_id=batch_id,
                challenge_id=None,
            )
        )
    for challenge_id, payload in videos.items():
        relative = f"videos/{challenge_id}.mp4"
        records.append(
            PublisherBatchReleaseObject(
                kind="video",
                relative_path=relative,
                sha256=hashlib.sha256(payload).hexdigest(),
                size_bytes=len(payload),
                batch_id=identity.batch_id,
                challenge_id=challenge_id,
            )
        )
    records.sort(key=lambda item: item.relative_path)
    return PublisherBatchRelease(
        schema=PUBLISHER_BATCH_RELEASE_SCHEMA,
        protocol=PROTOCOL_VERSION,
        window_id=identity.window.window_id,
        window_index=identity.window.window_index,
        scoring_policy_hash=scoring_policy_hash(policy),
        publisher_hotkey=identity.publisher_hotkey,
        batch_id=identity.batch_id,
        batch_commitment=commitment,
        objects=records,
        translation_weights_active=False,
        weight_submission_capability=False,
    )


def _prepared_files(prepared: PublisherBatchPrepared) -> dict[str, bytes]:
    files = {
        "pool-body.json": canonical_json_bytes(prepared.pool_body),
        "public-manifest.json": canonical_json_bytes(prepared.public_manifest),
        "ground-truth.tle": prepared.ground_truth_envelope,
    }
    files.update(
        {
            f"videos/{challenge_id}.mp4": payload
            for challenge_id, payload in prepared.video_bytes_by_challenge.items()
        }
    )
    files["publisher-batch-release.json"] = canonical_json_bytes(prepared.release)
    expected = {item.relative_path: item.sha256 for item in prepared.release.objects}
    actual = {
        path: hashlib.sha256(payload).hexdigest()
        for path, payload in files.items()
        if path != "publisher-batch-release.json"
    }
    if actual != expected:
        raise PublisherBatchError("publisher_release_index_mismatch")
    return files


def _read_public_regular_file(path: Path, *, maximum_bytes: int, label: str) -> bytes:
    return _read_regular_file(path, maximum_bytes=maximum_bytes, label=label, private=False)


def _read_private_regular_file(path: Path, *, maximum_bytes: int, label: str) -> bytes:
    _require_private_input_directory(path.parent, f"{label}_parent")
    return _read_regular_file(path, maximum_bytes=maximum_bytes, label=label, private=True)


def _read_regular_file(
    path: Path,
    *,
    maximum_bytes: int,
    label: str,
    private: bool,
) -> bytes:
    if not _is_absolute_normal_path(path):
        raise PublisherBatchError(f"{label}_path_not_absolute")
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "geteuid"):
        raise PublisherBatchError(f"{label}_safe_read_unsupported")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
    except OSError as error:
        raise PublisherBatchError(f"{label}_unavailable") from error
    try:
        before = os.fstat(descriptor)
        mode = stat.S_IMODE(before.st_mode)
        owner_valid = (
            before.st_uid == os.geteuid()
            if private
            else before.st_uid
            in {
                0,
                os.geteuid(),
            }
        )
        mode_valid = mode == 0o400 if private else mode & 0o022 == 0
        if (
            not stat.S_ISREG(before.st_mode)
            or not owner_valid
            or not mode_valid
            or (private and before.st_nlink != 1)
            or before.st_size <= 0
            or before.st_size > maximum_bytes
        ):
            raise PublisherBatchError(f"{label}_unsafe")
        result = bytearray()
        while chunk := os.read(descriptor, min(1024 * 1024, maximum_bytes + 1 - len(result))):
            result.extend(chunk)
            if len(result) > maximum_bytes:
                raise PublisherBatchError(f"{label}_size_limit")
        after = os.fstat(descriptor)
        if _stat_identity(before) != _stat_identity(after) or len(result) != before.st_size:
            raise PublisherBatchError(f"{label}_changed")
        return bytes(result)
    finally:
        os.close(descriptor)


def _is_absolute_normal_path(path: Path) -> bool:
    return path.is_absolute() and path == Path(os.path.normpath(path))


def _stat_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_uid,
        value.st_nlink,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _require_private_directory(path: Path, label: str) -> None:
    if not _is_absolute_normal_path(path):
        raise PublisherBatchError(f"{label}_path_invalid")
    try:
        metadata = path.lstat()
    except OSError as error:
        raise PublisherBatchError(f"{label}_unavailable") from error
    if (
        path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise PublisherBatchError(f"{label}_unsafe")


def _require_private_input_directory(path: Path, label: str) -> None:
    if not _is_absolute_normal_path(path):
        raise PublisherBatchError(f"{label}_path_invalid")
    try:
        metadata = path.lstat()
    except OSError as error:
        raise PublisherBatchError(f"{label}_unavailable") from error
    mode = stat.S_IMODE(metadata.st_mode)
    if (
        path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or mode & 0o077
        or mode & 0o500 != 0o500
    ):
        raise PublisherBatchError(f"{label}_unsafe")


def _require_release_directory(path: Path) -> None:
    if not _is_absolute_normal_path(path):
        raise PublisherBatchError("publisher_batch_release_path_invalid")
    try:
        metadata = path.lstat()
    except OSError as error:
        raise PublisherBatchError("publisher_batch_release_unavailable") from error
    if (
        path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o500
    ):
        raise PublisherBatchError("publisher_batch_release_directory_unsafe")


def _release_file_inventory(root: Path) -> set[str]:
    result: set[str] = set()
    directories: set[str] = set()
    for directory, directory_names, file_names in os.walk(root, followlinks=False):
        current = Path(directory)
        for name in directory_names:
            child = current / name
            metadata = child.lstat()
            if (
                child.is_symlink()
                or not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o500
            ):
                raise PublisherBatchError("publisher_batch_release_tree_unsafe")
            directories.add(child.relative_to(root).as_posix())
        for name in file_names:
            child = current / name
            metadata = child.lstat()
            if (
                child.is_symlink()
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o400
            ):
                raise PublisherBatchError("publisher_batch_release_tree_unsafe")
            result.add(child.relative_to(root).as_posix())
    if directories != {"videos"}:
        raise PublisherBatchError("publisher_batch_release_directory_set_mismatch")
    return result


@contextmanager
def _destination_lock(destination: Path):
    if fcntl is None:
        raise PublisherBatchError("publisher_output_lock_unsupported")
    lock_path = destination.parent / f".{destination.name}.lock"
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError as error:
        raise PublisherBatchError("publisher_output_lock_unavailable") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise PublisherBatchError("publisher_output_lock_unsafe")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


def _write_descriptor_bytes(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("publisher artifact write made no progress")
        view = view[written:]


def _write_file_bytes(path: Path, payload: bytes, *, mode: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, mode)
    try:
        _write_descriptor_bytes(descriptor, payload)
        os.fsync(descriptor)
        os.fchmod(descriptor, mode)
    except BaseException:
        with suppress(OSError):
            os.close(descriptor)
        with suppress(OSError):
            path.chmod(0o600)
            path.unlink()
        raise
    else:
        os.close(descriptor)


def _seal_directory_tree(root: Path) -> None:
    directories = [path for path in root.rglob("*") if path.is_dir()]
    for path in sorted(directories, reverse=True):
        path.chmod(0o500)
    root.chmod(0o500)


def _fsync_tree(root: Path) -> None:
    for path in sorted(root.rglob("*"), reverse=True):
        if path.is_file():
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        elif path.is_dir():
            _fsync_directory(path)
    _fsync_directory(root)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _remove_private_tree(root: Path) -> None:
    if not root.exists():
        return
    root.chmod(0o700)
    for path in sorted(root.rglob("*"), reverse=True):
        if path.is_file():
            path.chmod(0o600)
            path.unlink()
        elif path.is_dir():
            path.chmod(0o700)
            path.rmdir()
    root.rmdir()


__all__ = [
    "CANARY_CER_ROLE",
    "CANARY_WER_ROLE",
    "MAXIMUM_PUBLISHER_BATCH_INPUT_BYTES",
    "PUBLISHER_BATCH_IDENTITY_SCHEMA",
    "PUBLISHER_BATCH_RELEASE_SCHEMA",
    "PUBLISHER_BATCH_ROLES",
    "PUBLISHER_BATCH_SOURCE_SCHEMA",
    "PUBLISHER_RESERVE_VIDEO_INSPECTION_SCHEMA",
    "LoadedPublisherBatchRelease",
    "PublisherBatchError",
    "PublisherBatchIdentity",
    "PublisherBatchIdentityItem",
    "PublisherBatchPrepared",
    "PublisherBatchRelease",
    "PublisherBatchReleaseObject",
    "PublisherBatchSource",
    "PublisherBatchSourceItem",
    "PublisherBatchWindow",
    "PublisherReserveVideoInspection",
    "create_publisher_batch_identity",
    "derive_publisher_batch_window",
    "inspect_publisher_reserve_video",
    "load_publisher_batch_release",
    "normalized_script_sha256",
    "prepare_publisher_batch",
    "prepare_publisher_batch_from_paths",
    "read_canonical_private_publisher_input",
    "read_canonical_public_publisher_input",
    "validate_publisher_batch_window",
    "write_private_publisher_document",
    "write_publisher_batch",
    "write_publisher_batch_identity",
]
