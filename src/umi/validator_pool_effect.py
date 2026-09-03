"""Proof-bound pool qualification and deterministic live-shadow selection.

This is the production boundary between externally collected chain/artifact facts
and UMI's first durable stage receipt.  It owns no wallet, generic RPC client,
HTTP transport, or chain-write capability.  Narrow ports provide exact bytes and
already signed initial requests; this module independently parses and binds those
bytes to the policy, finalized closing snapshot, Quicknet pulse, spent/fault
state, deterministic selection functions, and immutable window-material store.

``VerifiedClosingSnapshot`` is intentionally explicit about the one collector
that is still external to this module.  Its proof evidence must be produced by a
policy-pinned collector that verifies the complete closing-block storage snapshot
and finality attestation.  This module rechecks every semantic binding and retains
the proof bytes, but does not pretend that a digest alone verifies a Substrate
storage proof.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import math
import re
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Annotated, Any, Literal, Protocol, TypeVar
from urllib.parse import urlsplit

from pydantic import Field, model_validator
from typing_extensions import Self

from .artifacts import PublicBatchManifest, validate_public_batch_manifest
from .drand import DrandPulse, DrandVerificationError
from .encoding import account_id32
from .policy import SCORING_POLICY_MEDIA_TYPE, ScoringPolicy, scoring_policy_hash
from .pool import (
    CandidateBatch,
    MinerCandidate,
    PoolManifest,
    batch_rank,
    candidate_pool_root,
    miner_rank,
    parse_pool_manifest_bytes,
    select_batches,
    select_miner_panel,
    selection_seed,
    verify_availability_certificate_member,
    verify_pool_artifacts,
)
from .protocol import (
    PROTOCOL_VERSION,
    StrictProtocolModel,
    base64url_decode,
    canonical_json_bytes,
)
from .registries import SpentCohortBatch
from .validator_adapters import (
    CompleteStageEffect,
    StageEffectResult,
    TerminalStageEffect,
    stage_operation_id,
)
from .validator_assignments import (
    MAX_ASSIGNMENTS_PER_WINDOW,
    MAX_REQUEST_BODY_BYTES,
    MAX_RESPONSE_BODY_BYTES,
    MAX_RETAINED_PREFIX_BYTES,
    WINDOW_SCHEMA,
    TranscriptWindowSpec,
)
from .validator_delivery import (
    IssuedVideoDelivery,
    IssuedVideoDeliverySet,
    MirrorDiscoveryRule,
    VideoDeliveryCommitment,
    VideoDeliveryIssuanceEvidence,
    validate_delivery_issuance,
)
from .validator_delivery import (
    parse_canonical_model as parse_canonical_delivery_model,
)
from .validator_journal import (
    MAX_JOURNAL_OBJECT_BYTES,
    MAX_STAGE_OBJECT_BYTES,
    StageJournalRecord,
    StageObjectInput,
)
from .validator_pool_no_score import (
    POOL_EMPTY_SOURCE_SCHEMA,
    POOL_NO_SCORE_SCHEMA,
    PoolEmptySourceEvidence,
    PoolNoScoreCandidate,
    PoolNoScoreEvidence,
    PoolNoScoreObjectRef,
    PoolNoScoreWindow,
    pool_no_score_metadata,
)
from .validator_protocol_state import (
    ValidatorProtocolStateStore,
    encode_protocol_state_snapshot,
)
from .validator_state import (
    IncidentSpec,
    PauseScope,
    StageWorkItem,
    TerminalOutcome,
    WindowPlan,
    WindowStage,
)
from .validator_transcript_abort import (
    DurableTranscriptAbortRegistry,
    TranscriptAbortRegistryError,
    read_receipt_objects,
)
from .validator_transcript_effects import TranscriptAssignment, TranscriptExecutionPlan
from .validator_window_material import ValidatorWindowMaterialStore
from .window import QUICKNET_GENESIS_MS, QUICKNET_PERIOD_MS, ceil_div

POOL_SELECTION_EVIDENCE_SCHEMA = "umi-validator-pool-selection/1"
POOL_CERTIFICATE_BREACH_SCHEMA = "umi-validator-pool-certificate-breach/1"
POOL_ANCHOR_RETRIEVAL_SCHEMA = "umi-pool-anchor-retrieval/1"
CLOSING_SNAPSHOT_SCHEMA = "umi-validator-closing-snapshot/1"
CLOSING_SNAPSHOT_PROOF_PROFILE = "umi-closing-snapshot-proof/1"
ANNOUNCEMENT_VALIDATOR_SNAPSHOT_SCHEMA = "umi-validator-announcement-set/1"
ANNOUNCEMENT_VALIDATOR_PROOF_PROFILE = "umi-announcement-validator-proof/1"

MAX_CLOSING_SNAPSHOT_BYTES = 4 * 1024 * 1024
MAX_CLOSING_PROOF_BYTES = 64 * 1024 * 1024
MAX_QUICKNET_PULSE_BYTES = 64 * 1024
MAX_PREPARED_ISSUANCE_EVIDENCE_BYTES = 4 * 1024 * 1024
MAX_MIRROR_READINESS_SET_BYTES = 1024 * 1024
MAX_SOURCE_OBJECTS = 32_768
MAX_MINER_SNAPSHOT_ROWS = 65_536
MAX_SERVING_URL_BYTES = 2_048
_MAX_SQLITE_INTEGER = (1 << 63) - 1
_HEX32_PATTERN = r"^[0-9a-f]{64}$"
_BLOCK_HASH_PATTERN = r"^0x[0-9a-f]{64}$"
_REASON_CODE_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_.-]*$")
_T = TypeVar("_T")


class PoolEffectError(RuntimeError):
    """A pool-stage input cannot produce a conforming immutable plan."""

    def __init__(self, message: str, *, reason_code: str = "pool_effect_failed") -> None:
        if _REASON_CODE_PATTERN.fullmatch(reason_code) is None:
            raise ValueError("pool effect reason code is invalid")
        self.reason_code = reason_code
        super().__init__(message)


class PoolEffectBindingError(PoolEffectError):
    """A typed fact is valid in isolation but bound to another window or policy."""


class PoolEffectLimitError(PoolEffectError):
    """Pool material cannot fit a policy or seven-stage journal ceiling."""


class CertifiedPoolArtifactUnavailable(PoolEffectError):
    """Every mirror exhausted a child promised by a verified pool certificate.

    Only the production mirror source raises this narrow boundary value.  The
    pool effect re-verifies every carried byte against finalized chain state and
    the certificate before it can turn the failure into ``certificate_breach``.
    Ordinary port exceptions and implementation defects still propagate.
    """

    def __init__(
        self,
        *,
        final_pool_manifest_bytes: bytes,
        artifact_retrieval_evidence_bytes: bytes,
        discovery_rule_bytes: bytes,
        mirror_readiness_set_bytes: bytes | None,
        artifact_kind: Literal["public_manifest", "ground_truth_envelope", "video"],
        batch_id: str,
        expected_sha256: str,
        resource_key: str,
        challenge_id: str | None = None,
        expected_size_bytes: int | None = None,
        parent_public_manifest_bytes: bytes | None = None,
    ) -> None:
        super().__init__(
            "a quorum-certified pool child is unavailable from every mirror",
            reason_code="certificate_breach",
        )
        for name, value in (
            ("final pool manifest", final_pool_manifest_bytes),
            ("artifact retrieval evidence", artifact_retrieval_evidence_bytes),
            ("mirror discovery rule", discovery_rule_bytes),
        ):
            if not isinstance(value, bytes) or not value:
                raise TypeError(f"{name} must be nonempty exact bytes")
        if mirror_readiness_set_bytes is not None and (
            not isinstance(mirror_readiness_set_bytes, bytes)
            or not mirror_readiness_set_bytes
            or len(mirror_readiness_set_bytes) > MAX_MIRROR_READINESS_SET_BYTES
        ):
            raise TypeError("mirror readiness set must be bounded exact bytes")
        if artifact_kind not in {"public_manifest", "ground_truth_envelope", "video"}:
            raise ValueError("certified unavailable artifact kind is unsupported")
        if not isinstance(batch_id, str) or len(base64url_decode(batch_id)) != 16:
            raise ValueError("certified unavailable batch ID must encode 16 bytes")
        if (
            not isinstance(expected_sha256, str)
            or re.fullmatch(_HEX32_PATTERN, expected_sha256) is None
        ):
            raise ValueError("certified unavailable digest must be lowercase SHA-256")
        if not isinstance(resource_key, str) or not resource_key or len(resource_key) > 512:
            raise ValueError("certified unavailable resource key is invalid")
        if artifact_kind == "video":
            if not isinstance(challenge_id, str) or len(base64url_decode(challenge_id)) != 16:
                raise ValueError("certified unavailable video challenge ID must encode 16 bytes")
            if (
                isinstance(expected_size_bytes, bool)
                or not isinstance(expected_size_bytes, int)
                or expected_size_bytes <= 0
            ):
                raise ValueError("certified unavailable video size must be positive")
            if not isinstance(parent_public_manifest_bytes, bytes) or not (
                parent_public_manifest_bytes
            ):
                raise TypeError("certified unavailable video requires its public manifest")
        elif any(
            value is not None
            for value in (challenge_id, expected_size_bytes, parent_public_manifest_bytes)
        ):
            raise ValueError("non-video certified unavailability carries video-only fields")
        self.final_pool_manifest_bytes = final_pool_manifest_bytes
        self.artifact_retrieval_evidence_bytes = artifact_retrieval_evidence_bytes
        self.discovery_rule_bytes = discovery_rule_bytes
        self.mirror_readiness_set_bytes = mirror_readiness_set_bytes
        self.artifact_kind = artifact_kind
        self.batch_id = batch_id
        self.challenge_id = challenge_id
        self.expected_sha256 = expected_sha256
        self.expected_size_bytes = expected_size_bytes
        self.resource_key = resource_key
        self.parent_public_manifest_bytes = parent_public_manifest_bytes


Hex32 = Annotated[str, Field(pattern=_HEX32_PATTERN)]
BlockHash = Annotated[str, Field(pattern=_BLOCK_HASH_PATTERN)]


class PoolEvidenceObjectRef(StrictProtocolModel):
    sha256: Hex32
    media_type: Literal[
        "application/json",
        "application/octet-stream",
        "application/vnd.umi.scoring-policy+json",
    ]
    size_bytes: Annotated[int, Field(ge=0, le=MAX_JOURNAL_OBJECT_BYTES)]


class PoolCertificateBreachEvidence(StrictProtocolModel):
    """Self-contained proof of one unavailable quorum-certified child object."""

    schema_: Literal[POOL_CERTIFICATE_BREACH_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    window_id: Hex32
    window_index: Annotated[int, Field(ge=0, le=_MAX_SQLITE_INTEGER)]
    scoring_policy_hash: Hex32
    validator_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    operation_id: Annotated[str, Field(min_length=1, max_length=160)]
    window: PoolNoScoreWindow
    reason_code: Literal["certificate_breach"]
    terminal_outcome: Literal["skipped"]
    publisher_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    artifact_kind: Literal["public_manifest", "ground_truth_envelope", "video"]
    batch_id: Annotated[str, Field(min_length=1, max_length=64)]
    challenge_id: Annotated[str, Field(min_length=1, max_length=64)] | None
    expected_sha256: Hex32
    expected_size_bytes: Annotated[int, Field(gt=0, le=MAX_JOURNAL_OBJECT_BYTES)] | None
    resource_key_sha256: Hex32
    final_pool_manifest: PoolEvidenceObjectRef
    parent_public_manifest: PoolEvidenceObjectRef | None
    artifact_retrieval_evidence: PoolEvidenceObjectRef
    mirror_discovery_rule: PoolEvidenceObjectRef
    mirror_readiness_set: PoolEvidenceObjectRef
    announcement_validator_snapshot: PoolEvidenceObjectRef
    announcement_validator_proof_evidence: PoolEvidenceObjectRef
    closing_snapshot: PoolEvidenceObjectRef
    closing_proof_evidence: PoolEvidenceObjectRef
    selection_pulse: PoolEvidenceObjectRef
    selection_pulse_evidence_digest: Hex32
    policy_object: PoolEvidenceObjectRef
    prior_protocol_state: PoolEvidenceObjectRef
    protocol_state_digest: Hex32
    prior_spent_root: Hex32
    prior_publisher_fault_root: Hex32
    source_objects: Annotated[list[PoolEvidenceObjectRef], Field(min_length=1)]

    @model_validator(mode="after")
    def validate_bindings(self) -> Self:
        account_id32(self.validator_hotkey)
        account_id32(self.publisher_hotkey)
        if len(base64url_decode(self.batch_id)) != 16:
            raise ValueError("certificate-breach batch ID must encode 16 bytes")
        if (
            self.window_id != self.window.window_id
            or self.window_index != self.window.window_index
            or self.scoring_policy_hash != self.window.scoring_policy_hash
        ):
            raise ValueError("certificate-breach window schedule changes its identity")
        if self.artifact_kind == "video":
            if self.challenge_id is None or len(base64url_decode(self.challenge_id)) != 16:
                raise ValueError("certificate-breach video challenge ID must encode 16 bytes")
            if self.expected_size_bytes is None or self.parent_public_manifest is None:
                raise ValueError("certificate-breach video lacks its public commitment")
        elif (
            self.challenge_id is not None
            or self.expected_size_bytes is not None
            or self.parent_public_manifest is not None
        ):
            raise ValueError("non-video certificate breach carries video-only fields")
        digests = [bytes.fromhex(item.sha256) for item in self.source_objects]
        if digests != sorted(digests) or len(digests) != len(set(digests)):
            raise ValueError("certificate-breach sources must be unique and digest-sorted")
        required = {
            self.final_pool_manifest.sha256,
            self.artifact_retrieval_evidence.sha256,
            self.mirror_discovery_rule.sha256,
            self.mirror_readiness_set.sha256,
            self.announcement_validator_snapshot.sha256,
            self.announcement_validator_proof_evidence.sha256,
            self.closing_snapshot.sha256,
            self.closing_proof_evidence.sha256,
            self.selection_pulse.sha256,
            self.policy_object.sha256,
            self.prior_protocol_state.sha256,
        }
        if self.parent_public_manifest is not None:
            required.add(self.parent_public_manifest.sha256)
        if required != {item.sha256 for item in self.source_objects}:
            raise ValueError("certificate-breach source index is not exact")
        return self


def pool_certificate_breach_metadata(
    evidence: PoolCertificateBreachEvidence,
    *,
    evidence_sha256: str,
) -> dict[str, Any]:
    """Return the exact adapter metadata independently reproduced by replay."""

    return {
        "certificate_breach_evidence_sha256": evidence_sha256,
        "reason_code": evidence.reason_code,
        "publisher_hotkey": evidence.publisher_hotkey,
        "artifact_kind": evidence.artifact_kind,
        "batch_id": evidence.batch_id,
        "challenge_id": evidence.challenge_id,
        "expected_sha256": evidence.expected_sha256,
        "resource_key_sha256": evidence.resource_key_sha256,
        "protocol_state_digest": evidence.protocol_state_digest,
    }


class ClosingPublisherState(StrictProtocolModel):
    publisher_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    owner_coldkey: Annotated[str, Field(min_length=1, max_length=256)]
    control_group_id: Hex32
    registered: bool
    locked_collateral_alpha_rao: Annotated[int, Field(ge=0, le=_MAX_SQLITE_INTEGER)]
    minimum_locked_collateral_alpha_rao: Annotated[
        int,
        Field(ge=0, le=_MAX_SQLITE_INTEGER),
    ]
    pool_manifest_sha256: Hex32 | None
    anchor_inclusion_block: Annotated[int, Field(ge=0, le=_MAX_SQLITE_INTEGER)] | None

    @model_validator(mode="after")
    def validate_anchor_pair(self) -> Self:
        account_id32(self.publisher_hotkey)
        account_id32(self.owner_coldkey)
        if (self.pool_manifest_sha256 is None) != (self.anchor_inclusion_block is None):
            raise ValueError("publisher anchor digest and inclusion block must appear together")
        return self


class ClosingValidatorState(StrictProtocolModel):
    validator_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    validator_permit: bool

    @model_validator(mode="after")
    def validate_account(self) -> Self:
        account_id32(self.validator_hotkey)
        return self


class ClosingNeuron(StrictProtocolModel):
    uid: Annotated[int, Field(ge=0, le=65_535)]
    hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    root: Annotated[str, Field(min_length=1, max_length=256)]
    registered: Literal[True]
    validator_permit: bool
    serving_url: Annotated[str, Field(min_length=1, max_length=MAX_SERVING_URL_BYTES)] | None

    @model_validator(mode="after")
    def validate_accounts(self) -> Self:
        account_id32(self.hotkey)
        account_id32(self.root)
        if self.serving_url is not None:
            _serving_origin(self.serving_url)
        return self


class ClosingSnapshot(StrictProtocolModel):
    """Canonical complete facts asserted by the pinned proof collector."""

    schema_: Literal[CLOSING_SNAPSHOT_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    proof_profile: Literal[CLOSING_SNAPSHOT_PROOF_PROFILE]
    collector_revision: Annotated[str, Field(min_length=1, max_length=256)]
    proof_evidence_sha256: Hex32
    netuid: Literal[78]
    window_id: Hex32
    window_index: Annotated[int, Field(ge=0, le=_MAX_SQLITE_INTEGER)]
    scoring_policy_hash: Hex32
    closing_block: Annotated[int, Field(ge=0, le=_MAX_SQLITE_INTEGER)]
    closing_block_hash: BlockHash
    closing_block_timestamp_ms: Annotated[int, Field(ge=0, le=_MAX_SQLITE_INTEGER)]
    accepted_at_unix_ms: Annotated[int, Field(gt=0, le=_MAX_SQLITE_INTEGER)]
    complete_publisher_registry: Literal[True]
    complete_validator_registry: Literal[True]
    complete_uid_snapshot: Literal[True]
    publishers: Annotated[list[ClosingPublisherState], Field(min_length=1)]
    validators: Annotated[list[ClosingValidatorState], Field(min_length=1)]
    neurons: Annotated[list[ClosingNeuron], Field(min_length=1, max_length=MAX_MINER_SNAPSHOT_ROWS)]

    @model_validator(mode="after")
    def validate_ordering(self) -> Self:
        publisher_accounts = [account_id32(item.publisher_hotkey) for item in self.publishers]
        if publisher_accounts != sorted(publisher_accounts) or len(set(publisher_accounts)) != len(
            publisher_accounts
        ):
            raise ValueError("closing publishers must be unique and sorted by account")
        validator_accounts = [account_id32(item.validator_hotkey) for item in self.validators]
        if validator_accounts != sorted(validator_accounts) or len(set(validator_accounts)) != len(
            validator_accounts
        ):
            raise ValueError("closing validators must be unique and sorted by account")
        uids = [item.uid for item in self.neurons]
        neuron_accounts = [account_id32(item.hotkey) for item in self.neurons]
        if uids != sorted(uids) or len(set(uids)) != len(uids):
            raise ValueError("closing neuron UIDs must be unique and sorted")
        if len(set(neuron_accounts)) != len(neuron_accounts):
            raise ValueError("closing neuron hotkeys must be unique")
        return self


class AnnouncementValidatorSnapshot(StrictProtocolModel):
    """Complete policy-registry permit state at the finalized announcement block."""

    schema_: Literal[ANNOUNCEMENT_VALIDATOR_SNAPSHOT_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    proof_profile: Literal[ANNOUNCEMENT_VALIDATOR_PROOF_PROFILE]
    collector_revision: Annotated[str, Field(min_length=1, max_length=256)]
    proof_evidence_sha256: Hex32
    netuid: Literal[78]
    window_id: Hex32
    window_index: Annotated[int, Field(ge=0, le=_MAX_SQLITE_INTEGER)]
    scoring_policy_hash: Hex32
    announcement_block: Annotated[int, Field(ge=0, le=_MAX_SQLITE_INTEGER)]
    announcement_block_hash: BlockHash
    announcement_block_timestamp_ms: Annotated[int, Field(ge=0, le=_MAX_SQLITE_INTEGER)]
    complete_validator_registry: Literal[True]
    validators: Annotated[list[ClosingValidatorState], Field(min_length=1)]

    @model_validator(mode="after")
    def validate_ordering(self) -> Self:
        accounts = [account_id32(item.validator_hotkey) for item in self.validators]
        if accounts != sorted(accounts) or len(set(accounts)) != len(accounts):
            raise ValueError("announcement validators must be unique and sorted by account")
        return self


@dataclass(frozen=True, slots=True)
class VerifiedClosingSnapshot:
    """Exact closing and announcement snapshots with their retained proof evidence."""

    snapshot: ClosingSnapshot
    snapshot_bytes: bytes
    proof_evidence_bytes: bytes
    announcement_snapshot: AnnouncementValidatorSnapshot
    announcement_snapshot_bytes: bytes
    announcement_proof_evidence_bytes: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.snapshot, ClosingSnapshot):
            raise TypeError("snapshot must be ClosingSnapshot")
        if not isinstance(self.snapshot_bytes, bytes):
            raise TypeError("snapshot bytes must be exact bytes")
        if not isinstance(self.proof_evidence_bytes, bytes):
            raise TypeError("closing proof evidence must be exact bytes")
        if not isinstance(self.announcement_snapshot, AnnouncementValidatorSnapshot):
            raise TypeError("announcement snapshot must be AnnouncementValidatorSnapshot")
        if not isinstance(self.announcement_snapshot_bytes, bytes):
            raise TypeError("announcement snapshot bytes must be exact bytes")
        if not isinstance(self.announcement_proof_evidence_bytes, bytes):
            raise TypeError("announcement proof evidence must be exact bytes")
        if not self.snapshot_bytes or len(self.snapshot_bytes) > MAX_CLOSING_SNAPSHOT_BYTES:
            raise PoolEffectLimitError("closing snapshot exceeds its byte ceiling")
        if (
            not self.proof_evidence_bytes
            or len(self.proof_evidence_bytes) > MAX_CLOSING_PROOF_BYTES
        ):
            raise PoolEffectLimitError("closing proof evidence exceeds its byte ceiling")
        if canonical_json_bytes(self.snapshot) != self.snapshot_bytes:
            raise PoolEffectBindingError("closing snapshot bytes are not exact canonical JSON")
        if hashlib.sha256(self.proof_evidence_bytes).hexdigest() != (
            self.snapshot.proof_evidence_sha256
        ):
            raise PoolEffectBindingError("closing proof evidence digest does not reproduce")
        if (
            not self.announcement_snapshot_bytes
            or len(self.announcement_snapshot_bytes) > MAX_CLOSING_SNAPSHOT_BYTES
        ):
            raise PoolEffectLimitError("announcement snapshot exceeds its byte ceiling")
        if (
            not self.announcement_proof_evidence_bytes
            or len(self.announcement_proof_evidence_bytes) > MAX_CLOSING_PROOF_BYTES
        ):
            raise PoolEffectLimitError("announcement proof evidence exceeds its byte ceiling")
        if canonical_json_bytes(self.announcement_snapshot) != self.announcement_snapshot_bytes:
            raise PoolEffectBindingError("announcement snapshot bytes are not exact canonical JSON")
        if hashlib.sha256(self.announcement_proof_evidence_bytes).hexdigest() != (
            self.announcement_snapshot.proof_evidence_sha256
        ):
            raise PoolEffectBindingError("announcement proof evidence digest does not reproduce")


@dataclass(frozen=True, slots=True)
class PoolBatchSource:
    batch_id: str
    public_manifest_bytes: bytes
    ground_truth_envelope_bytes: bytes

    def __post_init__(self) -> None:
        if len(base64url_decode(self.batch_id)) != 16:
            raise ValueError("source batch ID must encode exactly 16 bytes")
        if not isinstance(self.public_manifest_bytes, bytes):
            raise TypeError("public manifest source must be exact bytes")
        if not isinstance(self.ground_truth_envelope_bytes, bytes):
            raise TypeError("ground-truth envelope source must be exact bytes")


class VideoDeliverySource(StrictProtocolModel):
    """Exact selected-video delivery material asserted by the source collector.

    Raw video is deliberately not embedded in the stage journal.  The collector
    must stream and hash the video under the policy ceilings and place that
    bounded transcript in ``artifact_retrieval_evidence_bytes``.  This index
    binds the resulting short-lived URL to the public media commitment and to
    every request constructed from it.
    """

    batch_id: Annotated[str, Field(min_length=1, max_length=64)]
    challenge_id: Annotated[str, Field(min_length=1, max_length=64)]
    url: Annotated[str, Field(min_length=1, max_length=8_192)]
    sha256: Hex32
    size_bytes: Annotated[int, Field(gt=0, le=MAX_JOURNAL_OBJECT_BYTES)]

    @model_validator(mode="after")
    def validate_identifiers(self) -> Self:
        if len(base64url_decode(self.batch_id)) != 16:
            raise ValueError("video source batch ID must encode 16 bytes")
        if len(base64url_decode(self.challenge_id)) != 16:
            raise ValueError("video source challenge ID must encode 16 bytes")
        parsed = urlsplit(self.url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("video source URL must be absolute HTTP(S)")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("video source URL must not contain user information")
        return self


@dataclass(frozen=True, slots=True)
class PoolSourcePackage:
    final_pool_manifest_bytes: tuple[bytes, ...]
    batch_artifacts: tuple[PoolBatchSource, ...]
    video_deliveries: tuple[VideoDeliverySource, ...]
    artifact_retrieval_evidence_bytes: bytes
    mirror_discovery_rule_bytes: bytes | None = None
    mirror_readiness_set_bytes: bytes | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.final_pool_manifest_bytes, tuple) or any(
            not isinstance(value, bytes) for value in self.final_pool_manifest_bytes
        ):
            raise TypeError("final pool manifests must be a tuple of exact bytes")
        if not isinstance(self.batch_artifacts, tuple) or any(
            not isinstance(value, PoolBatchSource) for value in self.batch_artifacts
        ):
            raise TypeError("batch artifacts must be a tuple of PoolBatchSource")
        identifiers = [base64url_decode(item.batch_id) for item in self.batch_artifacts]
        if identifiers != sorted(identifiers) or len(set(identifiers)) != len(identifiers):
            raise ValueError("batch artifact sources must be unique and sorted by batch ID")
        if not isinstance(self.video_deliveries, tuple) or any(
            not isinstance(value, VideoDeliverySource) for value in self.video_deliveries
        ):
            raise TypeError("video deliveries must be a tuple of VideoDeliverySource")
        video_keys = [
            (base64url_decode(item.batch_id), base64url_decode(item.challenge_id))
            for item in self.video_deliveries
        ]
        if video_keys != sorted(video_keys) or len(set(video_keys)) != len(video_keys):
            raise ValueError("video deliveries must be unique and sorted by batch/challenge ID")
        if (
            not isinstance(self.artifact_retrieval_evidence_bytes, bytes)
            or not self.artifact_retrieval_evidence_bytes
            or len(self.artifact_retrieval_evidence_bytes) > MAX_CLOSING_PROOF_BYTES
        ):
            raise PoolEffectLimitError("artifact retrieval evidence exceeds its byte ceiling")
        if (self.mirror_discovery_rule_bytes is None) != (self.mirror_readiness_set_bytes is None):
            raise TypeError("mirror discovery and readiness must appear together")
        if self.mirror_discovery_rule_bytes is not None and (
            not isinstance(self.mirror_discovery_rule_bytes, bytes)
            or not self.mirror_discovery_rule_bytes
        ):
            raise TypeError("mirror discovery rule must be nonempty exact bytes")
        if self.mirror_readiness_set_bytes is not None and (
            not isinstance(self.mirror_readiness_set_bytes, bytes)
            or not self.mirror_readiness_set_bytes
            or len(self.mirror_readiness_set_bytes) > MAX_MIRROR_READINESS_SET_BYTES
        ):
            raise PoolEffectLimitError("mirror readiness set exceeds its byte ceiling")


@dataclass(frozen=True, slots=True)
class PoolSourceRequest:
    """Chain-authoritative discovery request for eligible timely anchors."""

    work: StageWorkItem
    eligible_anchor_hashes: tuple[tuple[str, str], ...]
    timely_anchor_hashes: tuple[tuple[str, str], ...]
    active_validator_hotkeys: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.work, StageWorkItem):
            raise TypeError("pool source request work must be StageWorkItem")
        rows = self.timely_anchor_hashes or self.eligible_anchor_hashes
        accounts = [account_id32(hotkey) for hotkey, _digest in rows]
        if accounts != sorted(accounts) or len(accounts) != len(set(accounts)):
            raise ValueError("eligible pool anchors must be unique and sorted")


class PoolAnchorOutcome(StrictProtocolModel):
    publisher_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    sha256: Hex32
    status: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9_.-]*$")]


class PoolAnchorAttemptEvidence(StrictProtocolModel):
    resource_key_sha256: Hex32
    attempt_index: Annotated[int, Field(ge=0, le=255)]
    url_sha256: Hex32
    status: Literal["pending_after_restart", "failed", "success"]
    observed_wire_bytes: Annotated[int, Field(ge=0, le=_MAX_SQLITE_INTEGER)]
    accounted_wire_bytes: Annotated[int, Field(gt=0, le=_MAX_SQLITE_INTEGER)]
    error_code: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9_.-]*$")] | None
    response_body_sha256: Hex32 | None
    response_body_size_bytes: Annotated[int, Field(ge=0, le=_MAX_SQLITE_INTEGER)]

    @model_validator(mode="after")
    def validate_attempt(self) -> Self:
        if (self.status == "success") != (self.error_code is None):
            raise ValueError("anchor retrieval attempt status and error code disagree")
        if self.observed_wire_bytes > self.accounted_wire_bytes:
            raise ValueError("anchor retrieval observed bytes exceed their reservation")
        if self.response_body_sha256 is None and self.response_body_size_bytes != 0:
            raise ValueError("anchor retrieval body size lacks its digest")
        return self


class PoolAnchorRetrievalEvidence(StrictProtocolModel):
    schema_: Literal[POOL_ANCHOR_RETRIEVAL_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    window_id: Hex32
    window_index: Annotated[int, Field(ge=0)]
    scoring_policy_hash: Hex32
    discovery_rule_sha256: Hex32
    anchor_outcomes: Annotated[list[PoolAnchorOutcome], Field(max_length=65_535)]
    attempts: Annotated[list[PoolAnchorAttemptEvidence], Field(max_length=65_535)]
    artifact_observed_wire_bytes: Annotated[int, Field(ge=0, le=_MAX_SQLITE_INTEGER)]
    artifact_accounted_wire_bytes: Annotated[int, Field(ge=0, le=_MAX_SQLITE_INTEGER)]

    @model_validator(mode="after")
    def validate_outcomes(self) -> Self:
        accounts = [account_id32(item.publisher_hotkey) for item in self.anchor_outcomes]
        if accounts != sorted(accounts) or len(accounts) != len(set(accounts)):
            raise ValueError("anchor outcomes must be unique and publisher-sorted")
        attempt_keys = [(item.resource_key_sha256, item.attempt_index) for item in self.attempts]
        if attempt_keys != sorted(attempt_keys) or len(attempt_keys) != len(set(attempt_keys)):
            raise ValueError("anchor retrieval attempts must be unique and canonically ordered")
        indices_by_resource: dict[str, list[int]] = {}
        for item in self.attempts:
            indices_by_resource.setdefault(item.resource_key_sha256, []).append(item.attempt_index)
        if any(indices != list(range(len(indices))) for indices in indices_by_resource.values()):
            raise ValueError("anchor retrieval attempt indices must be contiguous")
        if self.artifact_observed_wire_bytes != sum(
            item.observed_wire_bytes for item in self.attempts
        ):
            raise ValueError("anchor retrieval observed-byte total does not reproduce")
        if self.artifact_accounted_wire_bytes != sum(
            item.accounted_wire_bytes for item in self.attempts
        ):
            raise ValueError("anchor retrieval accounted-byte total does not reproduce")
        if self.artifact_observed_wire_bytes > self.artifact_accounted_wire_bytes:
            raise ValueError("anchor retrieval observed bytes exceed reserved accounting")
        return self


@dataclass(frozen=True, slots=True)
class PreparedAssignmentSet:
    assignments: tuple[TranscriptAssignment, ...]
    issuance_block: int
    issuance_block_hash: str
    issuance_block_timestamp_ms: int
    finality_evidence_bytes: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.assignments, tuple) or any(
            not isinstance(value, TranscriptAssignment) for value in self.assignments
        ):
            raise TypeError("prepared assignments must be a tuple of TranscriptAssignment")
        _nonnegative_int(self.issuance_block, "issuance block")
        _nonnegative_int(self.issuance_block_timestamp_ms, "issuance block timestamp")
        if (
            not isinstance(self.issuance_block_hash, str)
            or not self.issuance_block_hash.startswith("0x")
            or len(self.issuance_block_hash) != 66
        ):
            raise ValueError("issuance block hash must be a 0x-prefixed 32-byte hash")
        try:
            if self.issuance_block_hash != "0x" + bytes.fromhex(self.issuance_block_hash[2:]).hex():
                raise ValueError
        except ValueError as error:
            raise ValueError("issuance block hash must be lowercase hexadecimal") from error
        if (
            not isinstance(self.finality_evidence_bytes, bytes)
            or not self.finality_evidence_bytes
            or len(self.finality_evidence_bytes) > MAX_PREPARED_ISSUANCE_EVIDENCE_BYTES
        ):
            raise PoolEffectLimitError("issuance finality evidence exceeds its byte ceiling")


@dataclass(frozen=True, slots=True)
class PoolSelectionContext:
    window: WindowPlan
    selected_batches: tuple[CandidateBatch, ...]
    selected_manifests: tuple[PublicBatchManifest, ...]
    selected_video_deliveries: tuple[IssuedVideoDelivery, ...]
    selected_panel: tuple[ClosingNeuron, ...]
    selection_seed: bytes
    response_deadline_blocks: int

    def __post_init__(self) -> None:
        if not isinstance(self.window, WindowPlan):
            raise TypeError("selection context window must be WindowPlan")
        if not self.selected_batches or len(self.selected_batches) != len(self.selected_manifests):
            raise ValueError("selected batches and manifests must be nonempty and paired")
        if not self.selected_panel:
            raise ValueError("selected miner panel must not be empty")
        expected_video_keys = sorted(
            (
                (manifest.batch_id, item.challenge_id)
                for manifest in self.selected_manifests
                for item in manifest.items
            ),
            key=_decoded_delivery_key,
        )
        actual_video_keys = [
            (item.batch_id, item.challenge_id) for item in self.selected_video_deliveries
        ]
        if actual_video_keys != expected_video_keys:
            raise ValueError("selected video deliveries are not the selected batch-item set")
        if not isinstance(self.selection_seed, bytes) or len(self.selection_seed) != 32:
            raise ValueError("selection seed must be exactly 32 bytes")
        if self.response_deadline_blocks <= 0:
            raise ValueError("response deadline blocks must be positive")


@dataclass(frozen=True, slots=True)
class DeliveryIssuanceContext:
    """Selected media commitments exposed to the delivery issuance port."""

    window: WindowPlan
    selected_video_commitments: tuple[VideoDeliveryCommitment, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.window, WindowPlan):
            raise TypeError("delivery issuance context window must be WindowPlan")
        if not self.selected_video_commitments or any(
            not isinstance(item, VideoDeliveryCommitment)
            for item in self.selected_video_commitments
        ):
            raise TypeError("delivery issuance context requires selected commitments")
        keys = [
            (base64url_decode(item.batch_id), base64url_decode(item.challenge_id))
            for item in self.selected_video_commitments
        ]
        if keys != sorted(keys) or len(set(keys)) != len(keys):
            raise ValueError("delivery issuance commitments must be unique and sorted")


class SelectedCandidateEvidence(StrictProtocolModel):
    publisher_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    control_group_id: Hex32
    batch_id: Annotated[str, Field(min_length=1, max_length=64)]
    batch_commitment: Hex32
    pool_leaf: Hex32
    batch_rank: Hex32
    selection_ordinal: Annotated[int, Field(ge=0)] | None
    final_pool_manifest: PoolEvidenceObjectRef
    public_manifest: PoolEvidenceObjectRef
    ground_truth_envelope: PoolEvidenceObjectRef

    @model_validator(mode="after")
    def validate_identifiers(self) -> Self:
        account_id32(self.publisher_hotkey)
        if len(base64url_decode(self.batch_id)) != 16:
            raise ValueError("candidate batch ID must encode 16 bytes")
        return self


class SelectedMinerEvidence(StrictProtocolModel):
    panel_ordinal: Annotated[int, Field(ge=0)]
    uid: Annotated[int, Field(ge=0, le=65_535)]
    hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    root: Annotated[str, Field(min_length=1, max_length=256)]
    serving_url: Annotated[str, Field(min_length=1, max_length=MAX_SERVING_URL_BYTES)]
    assigned_observation_count: Annotated[int, Field(ge=0, le=_MAX_SQLITE_INTEGER)]
    miner_rank: Hex32

    @model_validator(mode="after")
    def validate_accounts(self) -> Self:
        account_id32(self.hotkey)
        account_id32(self.root)
        _serving_origin(self.serving_url)
        return self


class SelectedVideoDeliveryEvidence(StrictProtocolModel):
    batch_id: Annotated[str, Field(min_length=1, max_length=64)]
    challenge_id: Annotated[str, Field(min_length=1, max_length=64)]
    url: Annotated[str, Field(min_length=1, max_length=8_192)]
    sha256: Hex32
    size_bytes: Annotated[int, Field(gt=0, le=MAX_JOURNAL_OBJECT_BYTES)]
    expires_at_unix_ms: Annotated[int, Field(gt=0, le=_MAX_SQLITE_INTEGER)]

    @model_validator(mode="after")
    def validate_identifiers(self) -> Self:
        if len(base64url_decode(self.batch_id)) != 16:
            raise ValueError("selected video batch ID must encode 16 bytes")
        if len(base64url_decode(self.challenge_id)) != 16:
            raise ValueError("selected video challenge ID must encode 16 bytes")
        parsed = urlsplit(self.url)
        if parsed.scheme != "https" or not parsed.netloc:
            raise ValueError("selected video URL must be absolute HTTPS")
        return self


class PoolSelectionEvidence(StrictProtocolModel):
    """Canonical downstream representation of all selected source material."""

    schema_: Literal[POOL_SELECTION_EVIDENCE_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    window_id: Hex32
    window_index: Annotated[int, Field(ge=0, le=_MAX_SQLITE_INTEGER)]
    scoring_policy_hash: Hex32
    validator_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    announcement_validator_snapshot: PoolEvidenceObjectRef
    announcement_validator_proof_evidence: PoolEvidenceObjectRef
    closing_snapshot: PoolEvidenceObjectRef
    closing_proof_evidence: PoolEvidenceObjectRef
    artifact_retrieval_evidence: PoolEvidenceObjectRef
    mirror_discovery_rule: PoolEvidenceObjectRef
    mirror_readiness_set: PoolEvidenceObjectRef
    delivery_issuance_request: PoolEvidenceObjectRef
    delivery_issuance_response: PoolEvidenceObjectRef
    delivery_issuance_evidence: PoolEvidenceObjectRef
    selection_pulse: PoolEvidenceObjectRef
    selection_pulse_evidence_digest: Hex32
    policy_object: PoolEvidenceObjectRef
    prior_protocol_state: PoolEvidenceObjectRef
    protocol_state_digest: Hex32
    prior_spent_root: Hex32
    prior_publisher_fault_root: Hex32
    candidate_pool_root: Hex32
    selection_seed: Hex32
    candidates: Annotated[list[SelectedCandidateEvidence], Field(min_length=1)]
    selected_panel: Annotated[list[SelectedMinerEvidence], Field(min_length=1)]
    selected_video_deliveries: Annotated[
        list[SelectedVideoDeliveryEvidence],
        Field(min_length=1),
    ]
    issuance_block: Annotated[int, Field(ge=0, le=_MAX_SQLITE_INTEGER)]
    issuance_block_hash: BlockHash
    issuance_finality_evidence: PoolEvidenceObjectRef
    assignment_ids: Annotated[list[Hex32], Field(min_length=1)]
    source_objects: Annotated[list[PoolEvidenceObjectRef], Field(min_length=1)]

    @model_validator(mode="after")
    def validate_canonical_lists(self) -> Self:
        account_id32(self.validator_hotkey)
        candidate_keys = [
            (bytes.fromhex(item.batch_rank), bytes.fromhex(item.pool_leaf))
            for item in self.candidates
        ]
        if candidate_keys != sorted(candidate_keys):
            raise ValueError("candidate evidence must be sorted by batch rank and pool leaf")
        selected_with_zero = [
            item.selection_ordinal for item in self.candidates if item.selection_ordinal is not None
        ]
        if selected_with_zero != list(range(len(selected_with_zero))):
            raise ValueError("selected candidate ordinals must be contiguous")
        panel_ordinals = [item.panel_ordinal for item in self.selected_panel]
        if panel_ordinals != list(range(len(panel_ordinals))):
            raise ValueError("selected panel ordinals must be contiguous")
        video_keys = [
            (base64url_decode(item.batch_id), base64url_decode(item.challenge_id))
            for item in self.selected_video_deliveries
        ]
        if video_keys != sorted(video_keys) or len(set(video_keys)) != len(video_keys):
            raise ValueError("selected video deliveries must be unique and canonically ordered")
        if self.assignment_ids != sorted(set(self.assignment_ids)):
            raise ValueError("assignment IDs must be unique and sorted")
        refs = [(bytes.fromhex(item.sha256), item) for item in self.source_objects]
        if [digest for digest, _item in refs] != sorted(digest for digest, _item in refs):
            raise ValueError("source object references must be sorted by digest")
        if len({digest for digest, _item in refs}) != len(refs):
            raise ValueError("source object references must be unique")
        required = {
            self.announcement_validator_snapshot.sha256,
            self.announcement_validator_proof_evidence.sha256,
            self.closing_snapshot.sha256,
            self.closing_proof_evidence.sha256,
            self.artifact_retrieval_evidence.sha256,
            self.mirror_discovery_rule.sha256,
            self.mirror_readiness_set.sha256,
            self.delivery_issuance_request.sha256,
            self.delivery_issuance_response.sha256,
            self.delivery_issuance_evidence.sha256,
            self.selection_pulse.sha256,
            self.policy_object.sha256,
            self.prior_protocol_state.sha256,
            self.issuance_finality_evidence.sha256,
        }
        required.update(item.final_pool_manifest.sha256 for item in self.candidates)
        required.update(item.public_manifest.sha256 for item in self.candidates)
        required.update(item.ground_truth_envelope.sha256 for item in self.candidates)
        if not required.issubset({item.sha256 for item in self.source_objects}):
            raise ValueError("source object index omits referenced evidence")
        return self


class PoolSourcePort(Protocol):
    def __call__(
        self,
        request: PoolSourceRequest,
    ) -> PoolSourcePackage | Awaitable[PoolSourcePackage]: ...


class ClosingSnapshotPort(Protocol):
    def __call__(
        self,
        work: StageWorkItem,
    ) -> VerifiedClosingSnapshot | Awaitable[VerifiedClosingSnapshot]: ...


class SelectionPulsePort(Protocol):
    def __call__(self, work: StageWorkItem) -> bytes | Awaitable[bytes]: ...


class PreparedAssignmentsPort(Protocol):
    def __call__(
        self,
        context: PoolSelectionContext,
        work: StageWorkItem,
    ) -> PreparedAssignmentSet | Awaitable[PreparedAssignmentSet]: ...


class DeliveryIssuancePort(Protocol):
    def __call__(
        self,
        context: DeliveryIssuanceContext,
        work: StageWorkItem,
    ) -> IssuedVideoDeliverySet | Awaitable[IssuedVideoDeliverySet]: ...


class PoolIncidentAuditReleasePort(Protocol):
    def __call__(
        self,
        work: StageWorkItem,
        reason_code: str,
    ) -> int | Awaitable[int]: ...


@dataclass(frozen=True, slots=True)
class PoolEffectPorts:
    source: PoolSourcePort
    closing_snapshot: ClosingSnapshotPort
    selection_pulse: SelectionPulsePort
    delivery_issuance: DeliveryIssuancePort
    prepared_assignments: PreparedAssignmentsPort
    incident_audit_release: PoolIncidentAuditReleasePort | None = None

    def __post_init__(self) -> None:
        for name in (
            "source",
            "closing_snapshot",
            "selection_pulse",
            "delivery_issuance",
            "prepared_assignments",
        ):
            if not callable(getattr(self, name)):
                raise TypeError(f"pool effect {name} port must be callable")
        if self.incident_audit_release is not None and not callable(self.incident_audit_release):
            raise TypeError("pool effect incident-audit-release port must be callable")


@dataclass(frozen=True, slots=True)
class _QualifiedPool:
    raw: bytes
    manifest: PoolManifest
    public_by_batch: Mapping[str, PublicBatchManifest]
    public_bytes_by_batch: Mapping[str, bytes]
    envelope_by_batch: Mapping[str, bytes]


class PoolAndSelectionEffect:
    """Verify and durably receipt one live pool-and-selection operation.

    The injected ports cannot mutate chain state through this object: they return
    only typed values or exact bytes.  In particular, the request-preparation port
    may hold signing authority elsewhere, but receives only the already verified
    selection context and cannot transmit a request through this effect.
    """

    def __init__(
        self,
        *,
        policy: ScoringPolicy,
        validator_hotkey: str,
        material_store: ValidatorWindowMaterialStore,
        protocol_state: ValidatorProtocolStateStore,
        ports: PoolEffectPorts,
        abort_registry: DurableTranscriptAbortRegistry | None = None,
        port_timeout_seconds: float = 30.0,
        maximum_stage_object_bytes: int = MAX_STAGE_OBJECT_BYTES,
        maximum_stage_total_bytes: int = MAX_JOURNAL_OBJECT_BYTES,
    ) -> None:
        if not isinstance(policy, ScoringPolicy):
            raise TypeError("pool effect policy must be ScoringPolicy")
        account_id32(validator_hotkey)
        if account_id32(validator_hotkey) not in {
            account_id32(entry.validator_hotkey) for entry in policy.validator_registry
        }:
            raise ValueError("pool effect validator is absent from the policy registry")
        if not isinstance(material_store, ValidatorWindowMaterialStore):
            raise TypeError("material_store must be ValidatorWindowMaterialStore")
        if not isinstance(protocol_state, ValidatorProtocolStateStore):
            raise TypeError("protocol_state must be ValidatorProtocolStateStore")
        if not isinstance(ports, PoolEffectPorts):
            raise TypeError("ports must be PoolEffectPorts")
        if (
            isinstance(port_timeout_seconds, bool)
            or not isinstance(port_timeout_seconds, (int, float))
            or not math.isfinite(port_timeout_seconds)
            or port_timeout_seconds <= 0
            or port_timeout_seconds > 300
        ):
            raise ValueError("pool effect port timeout must be in (0, 300]")
        maximum_stage_object_bytes = _bounded_int(
            maximum_stage_object_bytes,
            1,
            MAX_STAGE_OBJECT_BYTES,
            "stage object byte ceiling",
        )
        maximum_stage_total_bytes = _bounded_int(
            maximum_stage_total_bytes,
            maximum_stage_object_bytes,
            MAX_JOURNAL_OBJECT_BYTES,
            "stage aggregate byte ceiling",
        )
        self.policy = policy
        self.validator_hotkey = validator_hotkey
        self.material_store = material_store
        self.protocol_state = protocol_state
        self.ports = ports
        self.abort_registry = abort_registry or DurableTranscriptAbortRegistry(
            material_store.root / "abort-registry"
        )
        self.port_timeout_seconds = float(port_timeout_seconds)
        self.maximum_stage_object_bytes = maximum_stage_object_bytes
        self.maximum_stage_total_bytes = maximum_stage_total_bytes
        self._policy_hash = scoring_policy_hash(policy)
        self._policy_bytes = canonical_json_bytes(policy)

    async def perform(
        self,
        *,
        operation_id: str,
        work: StageWorkItem,
    ) -> StageEffectResult:
        """Independently verify sources and persist the exact signed request plan."""

        self._validate_work(operation_id, work)
        try:
            pulse_value = await self._invoke(
                self.ports.selection_pulse,
                work,
                label="selection pulse",
            )
            if not isinstance(pulse_value, bytes):
                raise PoolEffectBindingError(
                    "selection pulse port did not return exact bytes",
                    reason_code="selection_pulse_type_invalid",
                )
            if not pulse_value or len(pulse_value) > MAX_QUICKNET_PULSE_BYTES:
                raise PoolEffectLimitError(
                    "selection pulse exceeds its byte ceiling",
                    reason_code="selection_pulse_size_limit",
                )
            pulse = _parse_pulse(
                pulse_value,
                expected_round=work.window.plan.selection_round,
            )

            snapshot_value = await self._invoke(
                self.ports.closing_snapshot,
                work,
                label="closing snapshot",
            )
            if not isinstance(snapshot_value, VerifiedClosingSnapshot):
                raise PoolEffectBindingError(
                    "closing snapshot port returned another type",
                    reason_code="closing_snapshot_type_invalid",
                )

            state_before = self.protocol_state.snapshot
            self._validate_protocol_state(state_before, work.window.plan)
            active_validators = self._validate_announcement_snapshot(
                snapshot_value,
                work.window.plan,
            )
            (
                timely_anchor_hashes,
                eligible_anchor_hashes,
            ) = self._validate_closing_snapshot(
                snapshot_value,
                state_before,
                work.window.plan,
            )
            if not timely_anchor_hashes:
                return self._no_score_result(
                    operation_id=operation_id,
                    work=work,
                    snapshot=snapshot_value,
                    pulse=pulse,
                    pulse_bytes=pulse_value,
                    state=state_before,
                    qualified=(),
                    candidates=(),
                    selected_batches=(),
                    pool_root=None,
                    seed=None,
                    source=None,
                    reason_code="candidate_pool_empty",
                )

            source_request = PoolSourceRequest(
                work=work,
                eligible_anchor_hashes=tuple(
                    (str(self._policy_publisher(account).publisher_hotkey), digest)
                    for account, digest in sorted(eligible_anchor_hashes.items())
                ),
                timely_anchor_hashes=tuple(
                    (str(self._policy_publisher(account).publisher_hotkey), digest)
                    for account, digest in sorted(timely_anchor_hashes.items())
                ),
                active_validator_hotkeys=tuple(active_validators),
            )
            try:
                source_value = await self._invoke(
                    self.ports.source,
                    source_request,
                    label="pool source",
                )
            except CertifiedPoolArtifactUnavailable as breach:
                return await self._certificate_breach_result(
                    operation_id=operation_id,
                    work=work,
                    snapshot=snapshot_value,
                    pulse=pulse,
                    pulse_bytes=pulse_value,
                    state=state_before,
                    active_validator_hotkeys=active_validators,
                    timely_anchor_hashes=timely_anchor_hashes,
                    eligible_anchor_hashes=eligible_anchor_hashes,
                    breach=breach,
                )
            if not isinstance(source_value, PoolSourcePackage):
                raise PoolEffectBindingError(
                    "pool source port returned another type",
                    reason_code="pool_source_type_invalid",
                )
            qualified, candidates = self._qualify_pool(
                source_value,
                timely_anchor_hashes=timely_anchor_hashes,
                eligible_anchor_hashes=eligible_anchor_hashes,
                active_validator_hotkeys=active_validators,
                state=state_before,
                window=work.window.plan,
            )
            source_value = self._qualified_source(source_value, qualified)
            pool_root: bytes | None = None
            seed: bytes | None = None
            selected_batches: tuple[CandidateBatch, ...] = ()
            no_score_reason: str | None = None
            if not candidates:
                no_score_reason = "candidate_pool_empty"
            else:
                pool_root = candidate_pool_root(candidates)
                seed = selection_seed(pulse.signature_bytes, pool_root)
                try:
                    selected_batches = select_batches(
                        candidates,
                        seed,
                        count=self.policy.limits.batches_selected_per_window,
                    )
                except ValueError:
                    no_score_reason = "candidate_control_group_count_insufficient"
            if no_score_reason is not None:
                self._validate_video_sources(source_value, qualified, ())
                return self._no_score_result(
                    operation_id=operation_id,
                    work=work,
                    snapshot=snapshot_value,
                    pulse=pulse,
                    pulse_bytes=pulse_value,
                    state=state_before,
                    qualified=qualified,
                    candidates=candidates,
                    selected_batches=selected_batches,
                    pool_root=pool_root,
                    seed=seed,
                    source=source_value,
                    reason_code=no_score_reason,
                )
            if pool_root is None or seed is None:
                raise RuntimeError("nonempty candidate selection lost its root or seed")
            selected_manifests = tuple(
                _manifest_for_candidate(candidate, qualified) for candidate in selected_batches
            )
            selected_panel, selected_neurons = self._select_panel(
                snapshot_value.snapshot,
                state_before,
                seed,
            )
            if not selected_panel:
                self._validate_video_sources(source_value, qualified, selected_batches)
                return self._no_score_result(
                    operation_id=operation_id,
                    work=work,
                    snapshot=snapshot_value,
                    pulse=pulse,
                    pulse_bytes=pulse_value,
                    state=state_before,
                    qualified=qualified,
                    candidates=candidates,
                    selected_batches=selected_batches,
                    pool_root=pool_root,
                    seed=seed,
                    source=source_value,
                    reason_code="eligible_miner_set_empty",
                )
            response_deadline_blocks = ceil_div(
                self.policy.clock.issue_allowance_seconds
                + self.policy.clock.response_window_seconds,
                self.policy.clock.target_block_interval_seconds,
            )
            source_video_by_key = self._validate_video_sources(
                source_value,
                qualified,
                selected_batches,
            )
            delivery_context = DeliveryIssuanceContext(
                window=work.window.plan,
                selected_video_commitments=tuple(
                    VideoDeliveryCommitment(
                        batch_id=item.batch_id,
                        challenge_id=item.challenge_id,
                        sha256=item.sha256,
                        size_bytes=item.size_bytes,
                    )
                    for _key, item in sorted(
                        source_video_by_key.items(),
                        key=lambda pair: _decoded_delivery_key(pair[0]),
                    )
                ),
            )
            delivery_value = await self._invoke(
                self.ports.delivery_issuance,
                delivery_context,
                work,
                label="video delivery issuance",
            )
            if not isinstance(delivery_value, IssuedVideoDeliverySet):
                raise PoolEffectBindingError(
                    "video delivery issuance port returned another type",
                    reason_code="delivery_issuance_type_invalid",
                )
            try:
                issued_deliveries = validate_delivery_issuance(
                    policy=self.policy,
                    window=work.window.plan,
                    expected_commitments=delivery_context.selected_video_commitments,
                    result=delivery_value,
                    private_source_urls=tuple(
                        item.url
                        for _key, item in sorted(
                            source_video_by_key.items(),
                            key=lambda pair: _decoded_delivery_key(pair[0]),
                        )
                    ),
                )
                retrieval_evidence = parse_canonical_delivery_model(
                    source_value.artifact_retrieval_evidence_bytes,
                    PoolAnchorRetrievalEvidence,
                    maximum_bytes=MAX_CLOSING_PROOF_BYTES,
                    label="pool anchor retrieval evidence",
                )
                delivery_evidence = parse_canonical_delivery_model(
                    delivery_value.evidence_bytes,
                    VideoDeliveryIssuanceEvidence,
                    maximum_bytes=self.policy.limits.maximum_manifest_bytes,
                    label="video delivery issuance evidence",
                )
                if (
                    delivery_evidence.observed_window_wire_bytes
                    != retrieval_evidence.artifact_observed_wire_bytes
                    + delivery_evidence.delivery_observed_wire_bytes
                    or delivery_evidence.accounted_window_wire_bytes
                    != retrieval_evidence.artifact_accounted_wire_bytes
                    + delivery_evidence.delivery_accounted_wire_bytes
                    or delivery_evidence.accounted_window_wire_bytes
                    > self.policy.limits.maximum_validator_window_wire_bytes
                ):
                    raise ValueError("delivery evidence does not reconcile window accounting")
            except (TypeError, ValueError) as error:
                raise PoolEffectBindingError(
                    "video delivery issuance evidence does not reproduce",
                    reason_code="delivery_issuance_binding_invalid",
                ) from error
            video_by_key = {(item.batch_id, item.challenge_id): item for item in issued_deliveries}
            context = PoolSelectionContext(
                window=work.window.plan,
                selected_batches=selected_batches,
                selected_manifests=selected_manifests,
                selected_video_deliveries=tuple(
                    video_by_key[key] for key in sorted(video_by_key, key=_decoded_delivery_key)
                ),
                selected_panel=selected_neurons,
                selection_seed=seed,
                response_deadline_blocks=response_deadline_blocks,
            )
            prepared_value = await self._invoke(
                self.ports.prepared_assignments,
                context,
                work,
                label="prepared assignments",
            )
            if not isinstance(prepared_value, PreparedAssignmentSet):
                raise PoolEffectBindingError("prepared-assignment port returned another type")
            execution_plan = self._validate_and_build_execution_plan(
                prepared_value,
                context,
                video_by_key,
            )

            # The observation counts and fault/spent roots are mutable only at a
            # completed scheduled-window boundary.  Recheck after potentially
            # slow signing so a concurrent state advance cannot be silently used.
            state_after = self.protocol_state.snapshot
            if state_after != state_before:
                raise PoolEffectBindingError(
                    "protocol state changed while pool material was being prepared"
                )

            source_objects = self._source_objects(
                source_value,
                snapshot_value,
                pulse_value,
                prepared_value,
                state_before,
                delivery_value,
            )
            evidence = self._selection_evidence(
                work=work,
                snapshot=snapshot_value,
                pulse=pulse,
                pulse_bytes=pulse_value,
                state=state_before,
                qualified=qualified,
                candidates=candidates,
                selected_batches=selected_batches,
                selected_panel=selected_panel,
                selected_neurons=selected_neurons,
                video_by_key=video_by_key,
                prepared=prepared_value,
                execution_plan=execution_plan,
                pool_root=pool_root,
                seed=seed,
                source_objects=source_objects,
                source=source_value,
                delivery=delivery_value,
            )
            evidence_bytes = canonical_json_bytes(evidence)
            source_digest = hashlib.sha256(evidence_bytes).hexdigest()
            stored = self.material_store.put(
                work.window.plan,
                execution_plan,
                source_evidence_sha256=source_digest,
            )
            objects = self._stage_objects(
                evidence_bytes=evidence_bytes,
                stored_material_bytes=stored.material_bytes,
                material_receipt_bytes=stored.receipt_bytes,
                sources=source_objects,
            )
            metadata: dict[str, Any] = {
                "pool_selection_evidence_sha256": source_digest,
                "window_material_sha256": stored.receipt.material_sha256,
                "window_material_receipt_sha256": stored.receipt_sha256,
                "candidate_pool_root": pool_root.hex(),
                "selection_seed": seed.hex(),
                "selected_batch_ids": [item.batch_id for item in selected_batches],
                "selected_miner_hotkeys": [item.hotkey for item in selected_neurons],
                "assignment_count": len(execution_plan.assignments),
                "announcement_validator_proof_evidence_sha256": (
                    snapshot_value.announcement_snapshot.proof_evidence_sha256
                ),
                "closing_proof_evidence_sha256": (snapshot_value.snapshot.proof_evidence_sha256),
            }
            return StageEffectResult(
                operation_id=operation_id,
                window_id=work.window.plan.window_id,
                stage=WindowStage.POOL_AND_SELECTION,
                objects=objects,
                metadata=metadata,
                decision=CompleteStageEffect(),
            )
        except PoolEffectError:
            raise
        except (TypeError, ValueError) as error:
            raise PoolEffectBindingError(
                "pool-and-selection verification failed",
                reason_code="pool_verification_failed",
            ) from error

    async def after_receipt(
        self,
        *,
        record: StageJournalRecord,
        work: StageWorkItem,
    ) -> None:
        """Bind the immutable plan to the authoritative recovery-safe receipt."""

        expected_operation = stage_operation_id(
            work.window.plan.window_id,
            WindowStage.POOL_AND_SELECTION,
        )
        if (
            work.stage is not WindowStage.POOL_AND_SELECTION
            or record.receipt.stage != WindowStage.POOL_AND_SELECTION.value
            or record.receipt.window_id != work.window.plan.window_id
            or record.receipt.operation_id != expected_operation
        ):
            raise PoolEffectBindingError("pool receipt hook received another operation")
        try:
            payloads = read_receipt_objects(record)
        except TranscriptAbortRegistryError as error:
            raise PoolEffectBindingError("pool receipt object graph cannot be read") from error
        no_score_rows: list[tuple[PoolNoScoreEvidence, bytes]] = []
        breach_rows: list[tuple[PoolCertificateBreachEvidence, bytes]] = []
        for reference in record.receipt.objects:
            if reference.media_type != "application/json":
                continue
            data = payloads[reference.sha256]
            try:
                decoded = json.loads(data)
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            if not isinstance(decoded, dict):
                continue
            if decoded.get("schema") == POOL_CERTIFICATE_BREACH_SCHEMA:
                try:
                    breach = PoolCertificateBreachEvidence.model_validate_json(data)
                except ValueError as error:
                    raise PoolEffectBindingError(
                        "pool certificate-breach receipt is invalid"
                    ) from error
                if canonical_json_bytes(breach) != data:
                    raise PoolEffectBindingError("pool certificate-breach receipt is not canonical")
                breach_rows.append((breach, data))
                continue
            if decoded.get("schema") != POOL_NO_SCORE_SCHEMA:
                continue
            try:
                value = PoolNoScoreEvidence.model_validate_json(data)
            except ValueError as error:
                raise PoolEffectBindingError("pool no-score receipt is invalid") from error
            if canonical_json_bytes(value) != data:
                raise PoolEffectBindingError("pool no-score receipt is not canonical")
            no_score_rows.append((value, data))
        if breach_rows:
            if len(breach_rows) != 1 or no_score_rows:
                raise PoolEffectBindingError(
                    "pool certificate-breach receipt cardinality is not one"
                )
            breach, breach_bytes = breach_rows[0]
            expected_metadata = pool_certificate_breach_metadata(
                breach,
                evidence_sha256=hashlib.sha256(breach_bytes).hexdigest(),
            )
            adapter = record.receipt.metadata
            terminal = adapter.get("terminal")
            incident = terminal.get("incident") if isinstance(terminal, dict) else None
            metadata = adapter.get("metadata")
            if (
                breach.window_id != work.window.plan.window_id
                or breach.operation_id != expected_operation
                or breach.window.to_plan() != work.window.plan
                or breach.scoring_policy_hash != self._policy_hash
                or adapter.get("kind") != "terminal"
                or metadata != expected_metadata
                or not isinstance(terminal, dict)
                or terminal.get("outcome") != "skipped"
                or terminal.get("reason_code") != "certificate_breach"
                or not isinstance(incident, dict)
                or incident.get("reason_code") != "certificate_breach"
            ):
                raise PoolEffectBindingError("pool certificate-breach receipt binding changed")
            return
        if no_score_rows:
            if len(no_score_rows) != 1:
                raise PoolEffectBindingError("pool no-score receipt cardinality is not one")
            no_score, no_score_bytes = no_score_rows[0]
            expected_metadata = pool_no_score_metadata(
                no_score,
                origin_sha256=hashlib.sha256(no_score_bytes).hexdigest(),
            )
            metadata = record.receipt.metadata.get("metadata")
            if (
                no_score.window_id != work.window.plan.window_id
                or no_score.operation_id != expected_operation
                or no_score.window.to_plan() != work.window.plan
                or no_score.scoring_policy_hash != self._policy_hash
                or not isinstance(metadata, dict)
                or metadata != expected_metadata
            ):
                raise PoolEffectBindingError("pool no-score receipt binding changed")
            self.abort_registry.record(
                window_id=no_score.window_id,
                origin_stage=WindowStage.POOL_AND_SELECTION.value,
                origin_receipt_evidence_sha256=record.evidence_sha256,
                origin_bytes=no_score_bytes,
            )
            return
        stored = self.material_store.load(work.window.plan.window_id)
        objects = {item.sha256: item for item in record.receipt.objects}
        required = {
            stored.receipt.source_evidence_sha256: self._receipted_source_size(
                record,
                stored.receipt.source_evidence_sha256,
            ),
            stored.receipt.material_sha256: len(stored.material_bytes),
            stored.receipt_sha256: len(stored.receipt_bytes),
        }
        for digest, expected_size in required.items():
            reference = objects.get(digest)
            if (
                reference is None
                or reference.media_type != "application/json"
                or reference.size_bytes != expected_size
            ):
                raise PoolEffectBindingError(
                    "pool receipt omits exact selection or window material"
                )
        binding = self.material_store.attach_pool_stage_receipt(
            work.window.plan.window_id,
            record.receipt_bytes,
        )
        if binding.pool_stage_evidence_sha256 != record.evidence_sha256:
            raise PoolEffectBindingError("material binding returned another pool receipt digest")

    def _no_score_result(
        self,
        *,
        operation_id: str,
        work: StageWorkItem,
        snapshot: VerifiedClosingSnapshot,
        pulse: DrandPulse,
        pulse_bytes: bytes,
        state: Any,
        qualified: Sequence[_QualifiedPool],
        candidates: Sequence[CandidateBatch],
        selected_batches: Sequence[CandidateBatch],
        pool_root: bytes | None,
        seed: bytes | None,
        source: PoolSourcePackage | None,
        reason_code: str,
    ) -> StageEffectResult:
        if reason_code not in {
            "candidate_pool_empty",
            "candidate_control_group_count_insufficient",
            "eligible_miner_set_empty",
        }:
            raise ValueError("pool no-score reason is unsupported")
        state_after = self.protocol_state.snapshot
        if state_after != state:
            raise PoolEffectBindingError(
                "protocol state changed while pool no-score evidence was being prepared"
            )
        empty_source: PoolEmptySourceEvidence | None = None
        if source is None:
            if (
                reason_code != "candidate_pool_empty"
                or qualified
                or candidates
                or selected_batches
                or pool_root is not None
                or seed is not None
            ):
                raise PoolEffectBindingError(
                    "empty-source settlement carries pool or selection material"
                )
            if any(
                row.pool_manifest_sha256 is not None
                and row.anchor_inclusion_block is not None
                and row.anchor_inclusion_block <= work.window.plan.closing_block
                for row in snapshot.snapshot.publishers
            ):
                raise PoolEffectBindingError(
                    "empty-source settlement conflicts with a timely pool anchor"
                )
            snapshot_sha256 = hashlib.sha256(snapshot.snapshot_bytes).hexdigest()
            proof_sha256 = hashlib.sha256(snapshot.proof_evidence_bytes).hexdigest()
            empty_source = PoolEmptySourceEvidence(
                schema=POOL_EMPTY_SOURCE_SCHEMA,
                protocol=PROTOCOL_VERSION,
                window_id=work.window.plan.window_id,
                window_index=work.window.plan.window_index,
                scoring_policy_hash=self._policy_hash,
                closing_block=work.window.plan.closing_block,
                closing_block_hash=snapshot.snapshot.closing_block_hash,
                closing_snapshot_sha256=snapshot_sha256,
                closing_proof_evidence_sha256=proof_sha256,
                complete_publisher_registry=True,
                publisher_registry_count=len(snapshot.snapshot.publishers),
                timely_anchor_count=0,
                determination=("complete_closing_snapshot_has_zero_timely_pool_anchors"),
            )
            empty_source_bytes = canonical_json_bytes(empty_source)
            source_objects = self._empty_source_objects(
                snapshot=snapshot,
                pulse_bytes=pulse_bytes,
                prior_state=state,
                empty_source_bytes=empty_source_bytes,
            )
        else:
            source_objects = self._source_objects(
                source,
                snapshot,
                pulse_bytes,
                None,
                state,
            )
        refs = {reference.sha256: reference for reference, _data in source_objects}
        pool_by_publisher = {
            account_id32(pool.manifest.publisher_hotkey): pool for pool in qualified
        }
        selected_ordinals = {
            candidate.pool_leaf: ordinal for ordinal, candidate in enumerate(selected_batches)
        }
        candidate_rows: list[PoolNoScoreCandidate] = []
        if seed is not None:
            for candidate in sorted(
                candidates,
                key=lambda item: (batch_rank(seed, item), item.pool_leaf),
            ):
                pool = pool_by_publisher[account_id32(candidate.publisher_hotkey)]
                public_bytes = pool.public_bytes_by_batch[candidate.batch_id]
                envelope = pool.envelope_by_batch[candidate.batch_id]
                candidate_rows.append(
                    PoolNoScoreCandidate(
                        publisher_hotkey=str(candidate.publisher_hotkey),
                        control_group_id=_hex_value(candidate.control_group_id),
                        batch_id=candidate.batch_id,
                        batch_commitment=_hex_value(candidate.batch_commitment),
                        pool_leaf=candidate.pool_leaf.hex(),
                        batch_rank=batch_rank(seed, candidate).hex(),
                        selection_ordinal=selected_ordinals.get(candidate.pool_leaf),
                        final_pool_manifest=PoolNoScoreObjectRef.model_validate(
                            refs[hashlib.sha256(pool.raw).hexdigest()].model_dump()
                        ),
                        public_manifest=PoolNoScoreObjectRef.model_validate(
                            refs[hashlib.sha256(public_bytes).hexdigest()].model_dump()
                        ),
                        ground_truth_envelope=PoolNoScoreObjectRef.model_validate(
                            refs[hashlib.sha256(envelope).hexdigest()].model_dump()
                        ),
                    )
                )
        no_score = PoolNoScoreEvidence(
            schema=POOL_NO_SCORE_SCHEMA,
            protocol=PROTOCOL_VERSION,
            window_id=work.window.plan.window_id,
            window_index=work.window.plan.window_index,
            scoring_policy_hash=self._policy_hash,
            validator_hotkey=self.validator_hotkey,
            operation_id=operation_id,
            window=PoolNoScoreWindow.from_plan(work.window.plan),
            reason_code=reason_code,
            terminal_outcome=(
                "void" if reason_code == "candidate_control_group_count_insufficient" else "skipped"
            ),
            announcement_validator_snapshot=PoolNoScoreObjectRef.model_validate(
                refs[hashlib.sha256(snapshot.announcement_snapshot_bytes).hexdigest()].model_dump()
            ),
            announcement_validator_proof_evidence=PoolNoScoreObjectRef.model_validate(
                refs[
                    hashlib.sha256(snapshot.announcement_proof_evidence_bytes).hexdigest()
                ].model_dump()
            ),
            closing_snapshot=PoolNoScoreObjectRef.model_validate(
                refs[hashlib.sha256(snapshot.snapshot_bytes).hexdigest()].model_dump()
            ),
            closing_proof_evidence=PoolNoScoreObjectRef.model_validate(
                refs[hashlib.sha256(snapshot.proof_evidence_bytes).hexdigest()].model_dump()
            ),
            artifact_retrieval_evidence=(
                None
                if source is None
                else PoolNoScoreObjectRef.model_validate(
                    refs[
                        hashlib.sha256(source.artifact_retrieval_evidence_bytes).hexdigest()
                    ].model_dump()
                )
            ),
            mirror_discovery_rule=(
                None
                if source is None or source.mirror_discovery_rule_bytes is None
                else PoolNoScoreObjectRef.model_validate(
                    refs[
                        hashlib.sha256(source.mirror_discovery_rule_bytes).hexdigest()
                    ].model_dump()
                )
            ),
            mirror_readiness_set=(
                None
                if source is None or source.mirror_readiness_set_bytes is None
                else PoolNoScoreObjectRef.model_validate(
                    refs[hashlib.sha256(source.mirror_readiness_set_bytes).hexdigest()].model_dump()
                )
            ),
            empty_source_evidence=(
                None
                if empty_source is None
                else PoolNoScoreObjectRef.model_validate(
                    refs[
                        hashlib.sha256(canonical_json_bytes(empty_source)).hexdigest()
                    ].model_dump()
                )
            ),
            selection_pulse=PoolNoScoreObjectRef.model_validate(
                refs[hashlib.sha256(pulse_bytes).hexdigest()].model_dump()
            ),
            selection_pulse_evidence_digest=pulse.evidence_digest,
            policy_object=PoolNoScoreObjectRef.model_validate(
                refs[hashlib.sha256(self._policy_bytes).hexdigest()].model_dump()
            ),
            prior_protocol_state=PoolNoScoreObjectRef.model_validate(
                refs[hashlib.sha256(encode_protocol_state_snapshot(state)).hexdigest()].model_dump()
            ),
            protocol_state_digest=state.state_digest.hex(),
            prior_spent_root=state.spent_registry.root.hex(),
            prior_publisher_fault_root=state.publisher_faults.root.hex(),
            candidate_pool_root=None if pool_root is None else pool_root.hex(),
            selection_seed=None if seed is None else seed.hex(),
            candidates=candidate_rows,
            source_objects=[
                PoolNoScoreObjectRef.model_validate(reference.model_dump())
                for reference, _data in source_objects
            ],
        )
        no_score_bytes = canonical_json_bytes(no_score)
        no_score_sha256 = hashlib.sha256(no_score_bytes).hexdigest()
        objects = self._stage_objects(
            evidence_bytes=no_score_bytes,
            stored_material_bytes=None,
            material_receipt_bytes=None,
            sources=source_objects,
        )
        return StageEffectResult(
            operation_id=operation_id,
            window_id=work.window.plan.window_id,
            stage=WindowStage.POOL_AND_SELECTION,
            objects=objects,
            metadata=pool_no_score_metadata(
                no_score,
                origin_sha256=no_score_sha256,
            ),
            decision=CompleteStageEffect(),
        )

    async def _certificate_breach_result(
        self,
        *,
        operation_id: str,
        work: StageWorkItem,
        snapshot: VerifiedClosingSnapshot,
        pulse: DrandPulse,
        pulse_bytes: bytes,
        state: Any,
        active_validator_hotkeys: Sequence[str],
        timely_anchor_hashes: Mapping[bytes, str],
        eligible_anchor_hashes: Mapping[bytes, str],
        breach: CertifiedPoolArtifactUnavailable,
    ) -> StageEffectResult:
        release_port = self.ports.incident_audit_release
        if release_port is None:
            raise PoolEffectError(
                "certificate breach lacks an incident audit-release port",
                reason_code="certificate_breach_release_port_missing",
            )
        evidence, source_objects = self._certificate_breach_evidence(
            operation_id=operation_id,
            work=work,
            snapshot=snapshot,
            pulse=pulse,
            pulse_bytes=pulse_bytes,
            state=state,
            active_validator_hotkeys=active_validator_hotkeys,
            timely_anchor_hashes=timely_anchor_hashes,
            eligible_anchor_hashes=eligible_anchor_hashes,
            breach=breach,
        )
        release_value = await self._invoke(
            release_port,
            work,
            "certificate_breach",
            label="certificate-breach audit release",
        )
        release = _nonnegative_int(release_value, "certificate-breach audit release block")
        if release <= work.window.plan.announcement_block:
            raise PoolEffectBindingError(
                "certificate-breach audit release precedes its window",
                reason_code="certificate_breach_release_invalid",
            )
        evidence_bytes = canonical_json_bytes(evidence)
        evidence_sha256 = hashlib.sha256(evidence_bytes).hexdigest()
        objects = self._stage_objects(
            evidence_bytes=evidence_bytes,
            stored_material_bytes=None,
            material_receipt_bytes=None,
            sources=source_objects,
        )
        incident = IncidentSpec(
            incident_id=f"umi-certificate-breach/{work.window.plan.window_id}",
            reason_code="certificate_breach",
            metadata={
                "certificate_breach_evidence_sha256": evidence_sha256,
                "publisher_hotkey": evidence.publisher_hotkey,
                "artifact_kind": evidence.artifact_kind,
                "batch_id": evidence.batch_id,
                "challenge_id": evidence.challenge_id,
                "expected_sha256": evidence.expected_sha256,
            },
        )
        return StageEffectResult(
            operation_id=operation_id,
            window_id=work.window.plan.window_id,
            stage=WindowStage.POOL_AND_SELECTION,
            objects=objects,
            metadata=pool_certificate_breach_metadata(
                evidence,
                evidence_sha256=evidence_sha256,
            ),
            decision=TerminalStageEffect(
                outcome=TerminalOutcome.SKIPPED,
                audit_release_block=release,
                reason_code="certificate_breach",
                incident=incident,
                pause_scopes=(PauseScope.WINDOW_INTAKE,),
            ),
        )

    def _certificate_breach_evidence(
        self,
        *,
        operation_id: str,
        work: StageWorkItem,
        snapshot: VerifiedClosingSnapshot,
        pulse: DrandPulse,
        pulse_bytes: bytes,
        state: Any,
        active_validator_hotkeys: Sequence[str],
        timely_anchor_hashes: Mapping[bytes, str],
        eligible_anchor_hashes: Mapping[bytes, str],
        breach: CertifiedPoolArtifactUnavailable,
    ) -> tuple[
        PoolCertificateBreachEvidence,
        tuple[tuple[PoolEvidenceObjectRef, bytes], ...],
    ]:
        try:
            manifest = parse_pool_manifest_bytes(
                breach.final_pool_manifest_bytes,
                policy=self.policy,
            )
            publisher = account_id32(manifest.publisher_hotkey)
            manifest_sha256 = hashlib.sha256(breach.final_pool_manifest_bytes).hexdigest()
            if (
                manifest.window_id != work.window.plan.window_id
                or manifest.scoring_policy_hash != self._policy_hash
                or timely_anchor_hashes.get(publisher) != manifest_sha256
                or eligible_anchor_hashes.get(publisher) != manifest_sha256
            ):
                raise ValueError("certified pool anchor binding changed")
            verify_availability_certificate_member(
                manifest.availability_certificate,
                manifest.body(),
                active_validator_hotkeys=active_validator_hotkeys,
                policy=self.policy,
            )
            entries = [item for item in manifest.batches if item.batch_id == breach.batch_id]
            if len(entries) != 1:
                raise ValueError("certificate-breach batch is absent or duplicated")
            entry = entries[0]
            parent_public: PublicBatchManifest | None = None
            if breach.artifact_kind == "public_manifest":
                expected_sha256 = entry.public_manifest_sha256
                expected_resource_key = f"public:{entry.batch_id}:{entry.public_manifest_sha256}"
            elif breach.artifact_kind == "ground_truth_envelope":
                expected_sha256 = entry.ciphertext_sha256
                expected_resource_key = f"envelope:{entry.batch_id}:{entry.ciphertext_sha256}"
            else:
                if breach.parent_public_manifest_bytes is None:
                    raise ValueError("certificate-breach video lacks its parent manifest")
                if (
                    hashlib.sha256(breach.parent_public_manifest_bytes).hexdigest()
                    != entry.public_manifest_sha256
                ):
                    raise ValueError("certificate-breach public-manifest digest changed")
                parent_public = PublicBatchManifest.model_validate_json(
                    breach.parent_public_manifest_bytes
                )
                if canonical_json_bytes(parent_public) != breach.parent_public_manifest_bytes:
                    raise ValueError("certificate-breach public manifest is not canonical")
                validate_public_batch_manifest(parent_public, self.policy)
                items = [
                    item for item in parent_public.items if item.challenge_id == breach.challenge_id
                ]
                if len(items) != 1:
                    raise ValueError("certificate-breach video item is absent or duplicated")
                item = items[0]
                expected_sha256 = item.media.sha256
                if breach.expected_size_bytes != item.media.size_bytes:
                    raise ValueError("certificate-breach video size changed")
                expected_resource_key = (
                    f"video:{entry.batch_id}:{item.challenge_id}:{item.media.sha256}"
                )
            if (
                breach.expected_sha256 != expected_sha256
                or breach.resource_key != expected_resource_key
            ):
                raise ValueError("certificate-breach target changes its committed identity")

            discovery = MirrorDiscoveryRule.model_validate_json(breach.discovery_rule_bytes)
            if canonical_json_bytes(discovery) != breach.discovery_rule_bytes:
                raise ValueError("certificate-breach discovery rule is not canonical")
            if (
                hashlib.sha256(breach.discovery_rule_bytes).hexdigest()
                != self.policy.implementation_pins.rules.mirror_discovery_rule_sha256
                or discovery.authentication_profile
                != self.policy.implementation_pins.rules.mirror_authentication_profile
            ):
                raise ValueError("certificate-breach discovery rule differs from policy")
            if breach.mirror_readiness_set_bytes is None:
                raise ValueError("certificate-breach source lacks mirror readiness")
            from .mirror_readiness import MirrorReadinessError, verify_live_mirror_readiness

            try:
                readiness = verify_live_mirror_readiness(
                    policy=self.policy,
                    discovery_rule_bytes=breach.discovery_rule_bytes,
                    readiness_set_bytes=breach.mirror_readiness_set_bytes,
                )
            except MirrorReadinessError as error:
                raise ValueError("certificate-breach mirror readiness is invalid") from error
            certificate_signers = {
                account_id32(item.validator_hotkey)
                for item in manifest.availability_certificate.signatures
            }
            if (
                readiness.readiness.window_id != work.window.plan.window_id
                or readiness.readiness.window_index != work.window.plan.window_index
                or readiness.expected_pool_manifest_sha256_by_publisher_account.get(publisher)
                != manifest_sha256
                or certificate_signers != set(readiness.signer_accounts)
            ):
                raise ValueError("certificate-breach mirror readiness is misbound")
            retrieval = parse_canonical_delivery_model(
                breach.artifact_retrieval_evidence_bytes,
                PoolAnchorRetrievalEvidence,
                maximum_bytes=MAX_CLOSING_PROOF_BYTES,
                label="certificate-breach retrieval evidence",
            )
            if (
                retrieval.window_id != work.window.plan.window_id
                or retrieval.window_index != work.window.plan.window_index
                or retrieval.scoring_policy_hash != self._policy_hash
                or retrieval.discovery_rule_sha256
                != hashlib.sha256(breach.discovery_rule_bytes).hexdigest()
            ):
                raise ValueError("certificate-breach retrieval evidence is misbound")
            outcomes = {
                account_id32(item.publisher_hotkey): item for item in retrieval.anchor_outcomes
            }
            if set(outcomes) != set(timely_anchor_hashes) or any(
                item.sha256 != timely_anchor_hashes[account] for account, item in outcomes.items()
            ):
                raise ValueError("certificate-breach anchor outcomes are incomplete")
            target_outcome = outcomes.get(publisher)
            if target_outcome is None or target_outcome.status != "qualified":
                raise ValueError("certificate-breach publisher was not certificate-qualified")
            target_key_sha256 = hashlib.sha256(breach.resource_key.encode("utf-8")).hexdigest()
            target_attempts = [
                item for item in retrieval.attempts if item.resource_key_sha256 == target_key_sha256
            ]
            expected_urls = [
                hashlib.sha256(
                    (origin + f"/v1/umi/objects/{expected_sha256}").encode("utf-8")
                ).hexdigest()
                for origin in discovery.origins[
                    : self.policy.limits.maximum_video_fetch_attempts_per_actor
                ]
            ]
            if (
                len(target_attempts) != len(expected_urls)
                or [item.attempt_index for item in target_attempts]
                != list(range(len(expected_urls)))
                or [item.url_sha256 for item in target_attempts] != expected_urls
                or any(item.status == "success" for item in target_attempts)
            ):
                raise ValueError("certificate-breach mirror exhaustion does not reproduce")
        except (TypeError, ValueError) as error:
            raise PoolEffectBindingError(
                "certificate-breach source evidence does not reproduce",
                reason_code="certificate_breach_evidence_invalid",
            ) from error

        values: list[tuple[bytes, str]] = [
            (self._policy_bytes, SCORING_POLICY_MEDIA_TYPE),
            (encode_protocol_state_snapshot(state), "application/json"),
            (snapshot.announcement_snapshot_bytes, "application/json"),
            (snapshot.announcement_proof_evidence_bytes, "application/json"),
            (snapshot.snapshot_bytes, "application/json"),
            (snapshot.proof_evidence_bytes, "application/json"),
            (pulse_bytes, "application/json"),
            (breach.final_pool_manifest_bytes, "application/json"),
            (breach.artifact_retrieval_evidence_bytes, "application/octet-stream"),
            (breach.discovery_rule_bytes, "application/json"),
            (breach.mirror_readiness_set_bytes, "application/json"),
        ]
        if breach.parent_public_manifest_bytes is not None:
            values.append((breach.parent_public_manifest_bytes, "application/json"))
        indexed: dict[str, tuple[PoolEvidenceObjectRef, bytes]] = {}
        for data, media_type in values:
            reference = _object_ref(data, media_type)
            existing = indexed.get(reference.sha256)
            if existing is not None and existing[0] != reference:
                raise PoolEffectBindingError(
                    "certificate-breach source digest has conflicting media metadata"
                )
            indexed[reference.sha256] = (reference, data)
        source_objects = tuple(indexed[key] for key in sorted(indexed, key=bytes.fromhex))
        refs = {reference.sha256: reference for reference, _data in source_objects}
        parent_ref = (
            None
            if breach.parent_public_manifest_bytes is None
            else refs[hashlib.sha256(breach.parent_public_manifest_bytes).hexdigest()]
        )
        evidence = PoolCertificateBreachEvidence(
            schema=POOL_CERTIFICATE_BREACH_SCHEMA,
            protocol=PROTOCOL_VERSION,
            window_id=work.window.plan.window_id,
            window_index=work.window.plan.window_index,
            scoring_policy_hash=self._policy_hash,
            validator_hotkey=self.validator_hotkey,
            operation_id=operation_id,
            window=PoolNoScoreWindow.from_plan(work.window.plan),
            reason_code="certificate_breach",
            terminal_outcome="skipped",
            publisher_hotkey=str(manifest.publisher_hotkey),
            artifact_kind=breach.artifact_kind,
            batch_id=breach.batch_id,
            challenge_id=breach.challenge_id,
            expected_sha256=breach.expected_sha256,
            expected_size_bytes=breach.expected_size_bytes,
            resource_key_sha256=hashlib.sha256(breach.resource_key.encode("utf-8")).hexdigest(),
            final_pool_manifest=refs[hashlib.sha256(breach.final_pool_manifest_bytes).hexdigest()],
            parent_public_manifest=parent_ref,
            artifact_retrieval_evidence=refs[
                hashlib.sha256(breach.artifact_retrieval_evidence_bytes).hexdigest()
            ],
            mirror_discovery_rule=refs[hashlib.sha256(breach.discovery_rule_bytes).hexdigest()],
            mirror_readiness_set=refs[
                hashlib.sha256(breach.mirror_readiness_set_bytes).hexdigest()
            ],
            announcement_validator_snapshot=refs[
                hashlib.sha256(snapshot.announcement_snapshot_bytes).hexdigest()
            ],
            announcement_validator_proof_evidence=refs[
                hashlib.sha256(snapshot.announcement_proof_evidence_bytes).hexdigest()
            ],
            closing_snapshot=refs[hashlib.sha256(snapshot.snapshot_bytes).hexdigest()],
            closing_proof_evidence=refs[hashlib.sha256(snapshot.proof_evidence_bytes).hexdigest()],
            selection_pulse=refs[hashlib.sha256(pulse_bytes).hexdigest()],
            selection_pulse_evidence_digest=pulse.evidence_digest,
            policy_object=refs[hashlib.sha256(self._policy_bytes).hexdigest()],
            prior_protocol_state=refs[
                hashlib.sha256(encode_protocol_state_snapshot(state)).hexdigest()
            ],
            protocol_state_digest=state.state_digest.hex(),
            prior_spent_root=state.spent_registry.root.hex(),
            prior_publisher_fault_root=state.publisher_faults.root.hex(),
            source_objects=[reference for reference, _data in source_objects],
        )
        return evidence, source_objects

    @staticmethod
    def _receipted_source_size(record: StageJournalRecord, digest: str) -> int:
        # The hook receives no journal reader by design.  The canonical selection
        # object is exactly the source digest, so its recorded size can be taken
        # from the already verified receipt without trusting effect metadata.
        references = [item for item in record.receipt.objects if item.sha256 == digest]
        if len(references) != 1:
            raise PoolEffectBindingError("pool receipt lacks one selection evidence object")
        return references[0].size_bytes

    def _validate_work(self, operation_id: str, work: StageWorkItem) -> None:
        if not isinstance(work, StageWorkItem):
            raise TypeError("pool effect work must be StageWorkItem")
        if work.stage is not WindowStage.POOL_AND_SELECTION:
            raise PoolEffectBindingError("pool effect received work for another stage")
        expected = stage_operation_id(work.window.plan.window_id, work.stage)
        if operation_id != expected:
            raise PoolEffectBindingError("pool effect operation ID is not deterministic")
        if work.completed_evidence:
            raise PoolEffectBindingError("new pool-stage work already carries completed evidence")
        window = work.window.plan
        if window.scoring_policy_hash != self._policy_hash:
            raise PoolEffectBindingError("window names another scoring policy")
        expected_announcement = (
            self.policy.activation_block
            + window.window_index * self.policy.clock.window_stride_blocks
        )
        if (
            window.announcement_block != expected_announcement
            or window.proposal_close_block
            != expected_announcement + self.policy.clock.proposal_blocks
            or window.closing_block != expected_announcement + self.policy.clock.anchor_blocks
        ):
            raise PoolEffectBindingError("window block schedule disagrees with policy")

    def _validate_protocol_state(self, state: Any, window: WindowPlan) -> None:
        if state.last_window_index != window.window_index - 1:
            raise PoolEffectBindingError(
                "protocol state does not end at the immediately preceding scheduled window"
            )

    def _policy_publisher(self, account: bytes) -> Any:
        return next(
            entry
            for entry in self.policy.publisher_registry
            if account_id32(entry.publisher_hotkey) == account
        )

    def _validate_announcement_snapshot(
        self,
        verified: VerifiedClosingSnapshot,
        window: WindowPlan,
    ) -> tuple[str, ...]:
        snapshot = verified.announcement_snapshot
        expected = (
            snapshot.netuid,
            snapshot.window_id,
            snapshot.window_index,
            snapshot.scoring_policy_hash,
            snapshot.announcement_block,
        )
        actual = (
            self.policy.netuid,
            window.window_id,
            window.window_index,
            self._policy_hash,
            window.announcement_block,
        )
        if expected != actual:
            raise PoolEffectBindingError(
                "announcement validator snapshot binds another window",
                reason_code="announcement_validator_snapshot_window_mismatch",
            )
        policy_validators = {
            account_id32(entry.validator_hotkey): entry.validator_hotkey
            for entry in self.policy.validator_registry
        }
        snapshot_validators = {
            account_id32(entry.validator_hotkey): entry for entry in snapshot.validators
        }
        if set(snapshot_validators) != set(policy_validators):
            raise PoolEffectBindingError(
                "announcement snapshot is not the complete validator registry",
                reason_code="announcement_validator_registry_incomplete",
            )
        active = tuple(
            policy_validators[account]
            for account in sorted(policy_validators)
            if snapshot_validators[account].validator_permit
        )
        if len(active) < 4:
            raise PoolEffectBindingError(
                "announcement snapshot has fewer than four active validators",
                reason_code="announcement_active_validator_count_below_minimum",
            )
        return active

    def _validate_closing_snapshot(
        self,
        verified: VerifiedClosingSnapshot,
        state: Any,
        window: WindowPlan,
    ) -> tuple[dict[bytes, str], dict[bytes, str]]:
        snapshot = verified.snapshot
        expected = (
            snapshot.netuid,
            snapshot.window_id,
            snapshot.window_index,
            snapshot.scoring_policy_hash,
            snapshot.closing_block,
        )
        actual = (
            self.policy.netuid,
            window.window_id,
            window.window_index,
            self._policy_hash,
            window.closing_block,
        )
        if expected != actual:
            raise PoolEffectBindingError(
                "closing snapshot binds another window",
                reason_code="closing_snapshot_window_mismatch",
            )
        selection_publication_ms = (
            QUICKNET_GENESIS_MS + (window.selection_round - 1) * QUICKNET_PERIOD_MS
        )
        if snapshot.accepted_at_unix_ms >= selection_publication_ms:
            raise PoolEffectBindingError(
                "closing finality was accepted after selection pulse publication",
                reason_code="closing_acceptance_not_before_selection_pulse",
            )

        policy_publishers = {
            account_id32(entry.publisher_hotkey): entry for entry in self.policy.publisher_registry
        }
        snapshot_publishers = {
            account_id32(entry.publisher_hotkey): entry for entry in snapshot.publishers
        }
        if set(snapshot_publishers) != set(policy_publishers):
            raise PoolEffectBindingError(
                "closing snapshot is not the complete publisher registry",
                reason_code="closing_publisher_registry_incomplete",
            )
        timely_anchors: dict[bytes, str] = {}
        eligible_anchors: dict[bytes, str] = {}
        for account, policy_entry in policy_publishers.items():
            entry = snapshot_publishers[account]
            if entry.control_group_id != policy_entry.control_group_id:
                raise PoolEffectBindingError("closing publisher changes its policy control group")
            owner_matches = account_id32(entry.owner_coldkey) == account_id32(
                policy_entry.owner_coldkey
            )
            eligible = (
                entry.registered
                and owner_matches
                and entry.locked_collateral_alpha_rao
                >= self.policy.minimum_publisher_collateral_alpha_rao
                and entry.minimum_locked_collateral_alpha_rao
                >= self.policy.minimum_publisher_collateral_alpha_rao
                and state.publisher_faults.is_eligible(
                    policy_entry.control_group_id,
                    window.window_index,
                )
            )
            timely_anchor = (
                entry.pool_manifest_sha256 is not None
                and entry.anchor_inclusion_block is not None
                and entry.anchor_inclusion_block <= window.closing_block
            )
            if timely_anchor:
                digest = entry.pool_manifest_sha256
                if digest is None:  # pragma: no cover - narrowed by timely_anchor
                    raise RuntimeError("timely anchor lost its digest")
                timely_anchors[account] = digest
                if eligible:
                    eligible_anchors[account] = digest

        policy_validators = {
            account_id32(entry.validator_hotkey): entry.validator_hotkey
            for entry in self.policy.validator_registry
        }
        snapshot_validators = {
            account_id32(entry.validator_hotkey): entry for entry in snapshot.validators
        }
        if set(snapshot_validators) != set(policy_validators):
            raise PoolEffectBindingError(
                "closing snapshot is not the complete validator registry",
                reason_code="closing_validator_registry_incomplete",
            )
        issuer = snapshot_validators[account_id32(self.validator_hotkey)]
        if not issuer.validator_permit:
            raise PoolEffectBindingError(
                "issuing validator has no closing-block permit",
                reason_code="issuing_validator_closing_permit_missing",
            )
        return timely_anchors, eligible_anchors

    def _qualify_pool(
        self,
        source: PoolSourcePackage,
        *,
        timely_anchor_hashes: Mapping[bytes, str],
        eligible_anchor_hashes: Mapping[bytes, str],
        active_validator_hotkeys: Sequence[str],
        state: Any,
        window: WindowPlan,
    ) -> tuple[tuple[_QualifiedPool, ...], tuple[CandidateBatch, ...]]:
        readiness = self._verify_source_readiness(source, window)
        try:
            retrieval = PoolAnchorRetrievalEvidence.model_validate_json(
                source.artifact_retrieval_evidence_bytes
            )
        except (TypeError, ValueError) as error:
            raise PoolEffectBindingError(
                "pool source lacks canonical retrieval evidence",
                reason_code="eligible_anchor_retrieval_evidence_missing",
            ) from error
        if (
            canonical_json_bytes(retrieval) != source.artifact_retrieval_evidence_bytes
            or retrieval.window_id != window.window_id
            or retrieval.window_index != window.window_index
            or retrieval.scoring_policy_hash != self._policy_hash
            or retrieval.discovery_rule_sha256
            != self.policy.implementation_pins.rules.mirror_discovery_rule_sha256
        ):
            raise PoolEffectBindingError("eligible-anchor retrieval evidence is misbound")

        accepted: list[tuple[bytes, PoolManifest]] = []
        for raw in source.final_pool_manifest_bytes:
            try:
                manifest = parse_pool_manifest_bytes(raw, policy=self.policy)
            except (TypeError, ValueError):
                # A malformed anchored value is not a candidate.  The closing
                # snapshot remains the authority for whether its publisher was
                # eligible; mirror bytes cannot promote it into the pool.
                continue
            account = account_id32(manifest.publisher_hotkey)
            expected_digest = timely_anchor_hashes.get(account)
            readiness_digest = readiness.expected_pool_manifest_sha256_by_publisher_account.get(
                account
            )
            if (
                expected_digest is None
                or hashlib.sha256(raw).hexdigest() != expected_digest
                or readiness_digest != expected_digest
            ):
                continue
            if (
                manifest.window_id != window.window_id
                or manifest.scoring_policy_hash != self._policy_hash
            ):
                continue
            try:
                verify_availability_certificate_member(
                    manifest.availability_certificate,
                    manifest.body(),
                    active_validator_hotkeys=active_validator_hotkeys,
                    policy=self.policy,
                )
            except (TypeError, ValueError):
                # Uncertified anchors contribute no candidates and cannot halt
                # an otherwise valid pool.
                continue
            accepted.append((raw, manifest))
        accepted.sort(key=lambda item: account_id32(item[1].publisher_hotkey))
        manifests = tuple(item[1] for item in accepted)
        manifest_raw = tuple(item[0] for item in accepted)
        publisher_accounts = [account_id32(item.publisher_hotkey) for item in manifests]
        if publisher_accounts != sorted(publisher_accounts) or len(set(publisher_accounts)) != len(
            publisher_accounts
        ):
            raise PoolEffectBindingError("final pool manifests are not unique and sorted")
        accepted_accounts = set(publisher_accounts)
        accepted_digests = {
            account_id32(manifest.publisher_hotkey): hashlib.sha256(raw).hexdigest()
            for raw, manifest in accepted
        }
        readiness_timely_digests = {
            account: digest
            for account, digest in timely_anchor_hashes.items()
            if readiness.expected_pool_manifest_sha256_by_publisher_account.get(account) == digest
        }
        if accepted_digests != readiness_timely_digests:
            raise PoolEffectBindingError(
                "pool source omits a readiness-bound timely anchor",
                reason_code="mirror_readiness_anchor_set_incomplete",
            )
        outcomes = {account_id32(item.publisher_hotkey): item for item in retrieval.anchor_outcomes}
        if set(outcomes) != set(timely_anchor_hashes) or any(
            item.sha256 != timely_anchor_hashes[account] for account, item in outcomes.items()
        ):
            raise PoolEffectBindingError("eligible-anchor retrieval evidence is incomplete")
        if any(
            (account in accepted_accounts) != (item.status == "qualified")
            for account, item in outcomes.items()
        ):
            raise PoolEffectBindingError("eligible-anchor outcome disagrees with pool bytes")
        if len(manifests) > self.policy.limits.max_active_publishers:
            raise PoolEffectLimitError("pool exceeds active-publisher limit")
        if sum(len(item.batches) for item in manifests) > (
            self.policy.limits.max_candidate_batches_total
        ):
            raise PoolEffectLimitError("pool exceeds global candidate-batch limit")
        certificates = [canonical_json_bytes(item.availability_certificate) for item in manifests]
        if certificates and len(set(certificates)) != 1:
            raise PoolEffectBindingError("final pools do not carry one common certificate")
        if manifests:
            certificate_signers = {
                account_id32(item.validator_hotkey)
                for item in manifests[0].availability_certificate.signatures
            }
            if certificate_signers != set(readiness.signer_accounts):
                raise PoolEffectBindingError(
                    "pool certificate signers differ from mirror-readiness signers",
                    reason_code="mirror_readiness_certificate_signer_mismatch",
                )
        bodies = tuple(item.body() for item in manifests)

        all_entries = [entry for manifest in manifests for entry in manifest.batches]
        batch_ids = [entry.batch_id for entry in all_entries]
        commitments = [entry.batch_commitment for entry in all_entries]
        if len(set(batch_ids)) != len(batch_ids) or len(set(commitments)) != len(commitments):
            raise PoolEffectBindingError(
                "certified pools contain a cross-publisher batch duplicate"
            )
        artifact_by_id = {item.batch_id: item for item in source.batch_artifacts}
        expected_ids = set(batch_ids)
        if not expected_ids.issubset(artifact_by_id):
            raise PoolEffectBindingError("source omits artifacts promised by a valid certificate")
        registry_by_publisher = {
            account_id32(entry.publisher_hotkey): entry for entry in self.policy.publisher_registry
        }
        group_counts: dict[str, int] = {}
        qualified: list[_QualifiedPool] = []
        candidates: list[CandidateBatch] = []
        spent_batches: list[SpentCohortBatch] = []
        for raw, manifest, body in zip(
            manifest_raw,
            manifests,
            bodies,
            strict=True,
        ):
            public_by_batch: dict[str, PublicBatchManifest] = {}
            public_bytes_by_batch: dict[str, bytes] = {}
            envelopes: dict[str, bytes] = {}
            for entry in manifest.batches:
                artifact = artifact_by_id[entry.batch_id]
                public = _parse_public_manifest(artifact.public_manifest_bytes, self.policy)
                public_by_batch[entry.batch_id] = public
                public_bytes_by_batch[entry.batch_id] = artifact.public_manifest_bytes
                envelopes[entry.batch_id] = artifact.ground_truth_envelope_bytes
            try:
                verify_pool_artifacts(
                    body,
                    public_manifests=public_by_batch,
                    ciphertexts=envelopes,
                    policy=self.policy,
                )
            except (TypeError, ValueError) as error:
                raise PoolEffectBindingError(
                    "pool artifacts do not reproduce their certified manifest",
                    reason_code="pool_artifact_binding_invalid",
                ) from error
            publisher_account = account_id32(manifest.publisher_hotkey)
            policy_publisher = registry_by_publisher[publisher_account]
            is_candidate_publisher = publisher_account in eligible_anchor_hashes
            if is_candidate_publisher and not state.publisher_faults.is_eligible(
                policy_publisher.control_group_id,
                window.window_index,
            ):
                raise PoolEffectBindingError("fault-ineligible publisher entered candidate pool")
            if is_candidate_publisher:
                group_counts[policy_publisher.control_group_id] = group_counts.get(
                    policy_publisher.control_group_id, 0
                ) + len(manifest.batches)
            for entry in manifest.batches:
                public = public_by_batch[entry.batch_id]
                if is_candidate_publisher:
                    candidate = CandidateBatch(
                        publisher_hotkey=manifest.publisher_hotkey,
                        control_group_id=policy_publisher.control_group_id,
                        batch_id=entry.batch_id,
                        batch_commitment=entry.batch_commitment,
                    )
                    candidates.append(candidate)
                    spent_batches.append(
                        SpentCohortBatch(
                            batch_commitment=entry.batch_commitment,
                            video_hashes=tuple(item.media.sha256 for item in public.items),
                            frame_digests=tuple(item.media.frame_digest for item in public.items),
                        )
                    )
            qualified.append(
                _QualifiedPool(
                    raw=raw,
                    manifest=manifest,
                    public_by_batch=public_by_batch,
                    public_bytes_by_batch=public_bytes_by_batch,
                    envelope_by_batch=envelopes,
                )
            )
        if any(
            count > self.policy.limits.max_candidate_batches_per_group
            for count in group_counts.values()
        ):
            raise PoolEffectLimitError("pool exceeds per-control-group candidate limit")
        if len(group_counts) > self.policy.limits.max_active_control_groups:
            raise PoolEffectLimitError("pool exceeds active control-group limit")
        _next_spent, spent_transition = state.spent_registry.apply(
            window.reveal_round,
            tuple(spent_batches),
        )
        if spent_transition.has_eligibility_fault:
            raise PoolEffectBindingError("candidate pool contains spent or duplicate public media")
        return tuple(qualified), tuple(candidates)

    def _verify_source_readiness(
        self,
        source: PoolSourcePackage,
        window: WindowPlan,
    ) -> Any:
        """Reverify the exact signed readiness bytes before pool eligibility."""

        if source.mirror_discovery_rule_bytes is None or source.mirror_readiness_set_bytes is None:
            raise PoolEffectBindingError(
                "anchor-backed pool source lacks mirror readiness evidence",
                reason_code="mirror_readiness_evidence_missing",
            )
        # Local import avoids a module cycle through publisher_availability's
        # mirror-index model import while keeping the pool boundary fail closed.
        from .mirror_readiness import MirrorReadinessError, verify_live_mirror_readiness

        try:
            readiness = verify_live_mirror_readiness(
                policy=self.policy,
                discovery_rule_bytes=source.mirror_discovery_rule_bytes,
                readiness_set_bytes=source.mirror_readiness_set_bytes,
            )
        except MirrorReadinessError as error:
            raise PoolEffectBindingError(
                "mirror readiness evidence does not verify",
                reason_code=error.reason_code,
            ) from error
        if (
            readiness.readiness.window_id != window.window_id
            or readiness.readiness.window_index != window.window_index
            or readiness.readiness.scoring_policy_sha256 != self._policy_hash
        ):
            raise PoolEffectBindingError(
                "mirror readiness evidence is bound to another window",
                reason_code="mirror_readiness_window_mismatch",
            )
        return readiness

    def _select_panel(
        self,
        snapshot: ClosingSnapshot,
        state: Any,
        seed: bytes,
    ) -> tuple[tuple[MinerCandidate, ...], tuple[ClosingNeuron, ...]]:
        publisher_accounts = {
            account_id32(entry.publisher_hotkey) for entry in self.policy.publisher_registry
        }
        candidates: list[MinerCandidate] = []
        neuron_by_account: dict[bytes, ClosingNeuron] = {}
        roots: set[bytes] = set()
        for neuron in snapshot.neurons:
            account = account_id32(neuron.hotkey)
            if (
                neuron.validator_permit
                or account in publisher_accounts
                or neuron.serving_url is None
            ):
                continue
            root = account_id32(neuron.root)
            if root in roots:
                raise PoolEffectBindingError("eligible miner snapshot contains duplicate roots")
            roots.add(root)
            candidates.append(
                MinerCandidate(
                    hotkey=neuron.hotkey,
                    root=neuron.root,
                    assigned_observation_count=state.assigned_observation_count(root),
                )
            )
            neuron_by_account[account] = neuron
        panel = select_miner_panel(
            tuple(candidates),
            seed,
            validator_hotkey=self.validator_hotkey,
            panel_size=self.policy.limits.miner_panel_size,
        )
        neurons = tuple(neuron_by_account[account_id32(item.hotkey)] for item in panel)
        return panel, neurons

    def _validate_video_sources(
        self,
        source: PoolSourcePackage,
        qualified: Sequence[_QualifiedPool],
        selected: Sequence[CandidateBatch],
    ) -> dict[tuple[str, str], VideoDeliverySource]:
        expected: dict[tuple[str, str], Any] = {}
        for pool in qualified:
            for manifest in pool.public_by_batch.values():
                for item in manifest.items:
                    expected[(manifest.batch_id, item.challenge_id)] = item.media
        actual = {(item.batch_id, item.challenge_id): item for item in source.video_deliveries}
        if not set(expected).issubset(actual):
            raise PoolEffectBindingError("video delivery index omits a candidate public item")
        for key, media in expected.items():
            delivery = actual[key]
            if delivery.sha256 != media.sha256 or delivery.size_bytes != media.size_bytes:
                raise PoolEffectBindingError("video delivery changes its public media commitment")
        selected_ids = {item.batch_id for item in selected}
        return {key: value for key, value in actual.items() if key[0] in selected_ids}

    @staticmethod
    def _qualified_source(
        source: PoolSourcePackage,
        qualified: Sequence[_QualifiedPool],
    ) -> PoolSourcePackage:
        batch_ids = {entry.batch_id for pool in qualified for entry in pool.manifest.batches}
        return PoolSourcePackage(
            final_pool_manifest_bytes=tuple(pool.raw for pool in qualified),
            batch_artifacts=tuple(
                item for item in source.batch_artifacts if item.batch_id in batch_ids
            ),
            video_deliveries=tuple(
                item for item in source.video_deliveries if item.batch_id in batch_ids
            ),
            artifact_retrieval_evidence_bytes=source.artifact_retrieval_evidence_bytes,
            mirror_discovery_rule_bytes=source.mirror_discovery_rule_bytes,
            mirror_readiness_set_bytes=source.mirror_readiness_set_bytes,
        )

    def _validate_and_build_execution_plan(
        self,
        prepared: PreparedAssignmentSet,
        context: PoolSelectionContext,
        video_by_key: Mapping[tuple[str, str], IssuedVideoDelivery],
    ) -> TranscriptExecutionPlan:
        selection_ms = (
            QUICKNET_GENESIS_MS + (context.window.selection_round - 1) * QUICKNET_PERIOD_MS
        )
        issue_close_ms = (
            QUICKNET_GENESIS_MS + (context.window.issue_close_round - 1) * QUICKNET_PERIOD_MS
        )
        if prepared.issuance_block <= context.window.closing_block:
            raise PoolEffectBindingError("request issuance block is not after pool close")
        if not selection_ms <= prepared.issuance_block_timestamp_ms < issue_close_ms:
            raise PoolEffectBindingError(
                "initial requests were not prepared between selection and issue close"
            )

        panel_by_account = {account_id32(item.hotkey): item for item in context.selected_panel}
        manifest_by_batch = {item.batch_id: item for item in context.selected_manifests}
        expected_keys = {
            (manifest.batch_id, item.challenge_id, account)
            for manifest in context.selected_manifests
            for item in manifest.items
            for account in panel_by_account
        }
        seen: set[tuple[str, str, bytes]] = set()
        for assignment in prepared.assignments:
            attempt = assignment.initial_attempt
            request = attempt.request
            miner_account = account_id32(attempt.miner_hotkey)
            key = (request.batch_id, request.challenge_id, miner_account)
            if key not in expected_keys or key in seen:
                raise PoolEffectBindingError(
                    "prepared assignments are not the selected Cartesian set"
                )
            seen.add(key)
            manifest = manifest_by_batch[request.batch_id]
            public_item = next(
                item for item in manifest.items if item.challenge_id == request.challenge_id
            )
            delivery = video_by_key[(request.batch_id, request.challenge_id)]
            neuron = panel_by_account[miner_account]
            if (
                attempt.validator_hotkey != self.validator_hotkey
                or attempt.miner_hotkey != neuron.hotkey
                or assignment.miner_url != neuron.serving_url
                or request.protocol != PROTOCOL_VERSION
                or request.window_id != context.window.window_id
                or request.scoring_policy_hash != context.window.scoring_policy_hash
                or request.response_close_round != context.window.response_close_round
                or request.reveal_round != context.window.reveal_round
                or request.issued_block != prepared.issuance_block
                or request.issued_block_hash != prepared.issuance_block_hash
                or request.deadline_block
                != prepared.issuance_block + context.response_deadline_blocks
                or request.video.url != delivery.url
                or request.video.sha256 != public_item.media.sha256
                or request.video.size_bytes != public_item.media.size_bytes
                or request.video.media_type != public_item.media.media_type
                or request.task.source_language != "ase"
                or request.task.target_language != "en"
                or request.task.stratum != public_item.stratum
            ):
                raise PoolEffectBindingError("prepared request changes selected source material")
            if len(attempt.request_bytes) > min(
                self.policy.limits.maximum_request_body_bytes,
                MAX_REQUEST_BODY_BYTES,
            ):
                raise PoolEffectLimitError("prepared request exceeds body ceiling")
        if seen != expected_keys:
            raise PoolEffectBindingError("prepared assignments omit selected work")
        assignments = tuple(sorted(prepared.assignments, key=lambda item: item.assignment_id))
        expected_count = len(expected_keys)
        if expected_count > MAX_ASSIGNMENTS_PER_WINDOW:
            raise PoolEffectLimitError("selected assignment count exceeds transcript ceiling")
        spec = TranscriptWindowSpec(
            schema=WINDOW_SCHEMA,
            protocol=PROTOCOL_VERSION,
            window_id=context.window.window_id,
            validator_hotkey=self.validator_hotkey,
            expected_assignment_count=expected_count,
            maximum_request_transmissions_per_assignment=(
                self.policy.limits.maximum_request_transmissions_per_assignment
            ),
            issue_close_round=context.window.issue_close_round,
            response_close_round=context.window.response_close_round,
            reveal_round=context.window.reveal_round,
            maximum_request_body_bytes=min(
                self.policy.limits.maximum_request_body_bytes,
                MAX_REQUEST_BODY_BYTES,
            ),
            maximum_response_body_bytes=min(
                self.policy.limits.maximum_response_body_bytes,
                MAX_RESPONSE_BODY_BYTES,
            ),
            maximum_retained_prefix_bytes=min(
                self.policy.limits.maximum_response_body_bytes,
                MAX_RETAINED_PREFIX_BYTES,
            ),
        )
        return TranscriptExecutionPlan(spec=spec, assignments=assignments)

    def _source_objects(
        self,
        source: PoolSourcePackage,
        snapshot: VerifiedClosingSnapshot,
        pulse_bytes: bytes,
        prepared: PreparedAssignmentSet | None,
        prior_state: Any,
        delivery: IssuedVideoDeliverySet | None = None,
    ) -> tuple[tuple[PoolEvidenceObjectRef, bytes], ...]:
        values: list[tuple[bytes, str]] = [
            (self._policy_bytes, SCORING_POLICY_MEDIA_TYPE),
            (encode_protocol_state_snapshot(prior_state), "application/json"),
            (snapshot.announcement_snapshot_bytes, "application/json"),
            (snapshot.announcement_proof_evidence_bytes, "application/json"),
            (snapshot.snapshot_bytes, "application/json"),
            (snapshot.proof_evidence_bytes, "application/json"),
            (pulse_bytes, "application/json"),
            (source.artifact_retrieval_evidence_bytes, "application/octet-stream"),
        ]
        if source.mirror_discovery_rule_bytes is None or source.mirror_readiness_set_bytes is None:
            raise PoolEffectBindingError(
                "anchor-backed pool source lacks mirror readiness evidence",
                reason_code="mirror_readiness_evidence_missing",
            )
        values.extend(
            (
                (source.mirror_discovery_rule_bytes, "application/json"),
                (source.mirror_readiness_set_bytes, "application/json"),
            )
        )
        if prepared is not None:
            values.append((prepared.finality_evidence_bytes, "application/json"))
        if delivery is not None:
            values.extend(
                (
                    (delivery.discovery_rule_bytes, "application/json"),
                    (delivery.request_bytes, "application/json"),
                    (delivery.response_bytes, "application/json"),
                    (delivery.evidence_bytes, "application/json"),
                )
            )
        values.extend((raw, "application/json") for raw in source.final_pool_manifest_bytes)
        for artifact in source.batch_artifacts:
            values.append((artifact.public_manifest_bytes, "application/json"))
            values.append((artifact.ground_truth_envelope_bytes, "application/octet-stream"))
        indexed: dict[str, tuple[PoolEvidenceObjectRef, bytes]] = {}
        for data, media_type in values:
            reference = _object_ref(data, media_type)
            existing = indexed.get(reference.sha256)
            if existing is not None and existing[0] != reference:
                raise PoolEffectBindingError("one source digest has conflicting media metadata")
            indexed[reference.sha256] = (reference, data)
        if len(indexed) > MAX_SOURCE_OBJECTS:
            raise PoolEffectLimitError("pool source object count exceeds its ceiling")
        return tuple(indexed[key] for key in sorted(indexed, key=bytes.fromhex))

    def _empty_source_objects(
        self,
        *,
        snapshot: VerifiedClosingSnapshot,
        pulse_bytes: bytes,
        prior_state: Any,
        empty_source_bytes: bytes,
    ) -> tuple[tuple[PoolEvidenceObjectRef, bytes], ...]:
        values: tuple[tuple[bytes, str], ...] = (
            (self._policy_bytes, SCORING_POLICY_MEDIA_TYPE),
            (encode_protocol_state_snapshot(prior_state), "application/json"),
            (snapshot.announcement_snapshot_bytes, "application/json"),
            (snapshot.announcement_proof_evidence_bytes, "application/json"),
            (snapshot.snapshot_bytes, "application/json"),
            (snapshot.proof_evidence_bytes, "application/json"),
            (pulse_bytes, "application/json"),
            (empty_source_bytes, "application/json"),
        )
        indexed: dict[str, tuple[PoolEvidenceObjectRef, bytes]] = {}
        for data, media_type in values:
            reference = _object_ref(data, media_type)
            existing = indexed.get(reference.sha256)
            if existing is not None and existing[0] != reference:
                raise PoolEffectBindingError(
                    "one empty-source digest has conflicting media metadata"
                )
            indexed[reference.sha256] = (reference, data)
        return tuple(indexed[key] for key in sorted(indexed, key=bytes.fromhex))

    def _selection_evidence(
        self,
        *,
        work: StageWorkItem,
        snapshot: VerifiedClosingSnapshot,
        pulse: DrandPulse,
        pulse_bytes: bytes,
        state: Any,
        qualified: Sequence[_QualifiedPool],
        candidates: Sequence[CandidateBatch],
        selected_batches: Sequence[CandidateBatch],
        selected_panel: Sequence[MinerCandidate],
        selected_neurons: Sequence[ClosingNeuron],
        video_by_key: Mapping[tuple[str, str], IssuedVideoDelivery],
        prepared: PreparedAssignmentSet,
        execution_plan: TranscriptExecutionPlan,
        pool_root: bytes,
        seed: bytes,
        source_objects: Sequence[tuple[PoolEvidenceObjectRef, bytes]],
        source: PoolSourcePackage,
        delivery: IssuedVideoDeliverySet,
    ) -> PoolSelectionEvidence:
        refs = {reference.sha256: reference for reference, _data in source_objects}
        pool_by_publisher = {
            account_id32(pool.manifest.publisher_hotkey): pool for pool in qualified
        }
        selected_ordinals = {
            candidate.pool_leaf: ordinal for ordinal, candidate in enumerate(selected_batches)
        }
        candidate_evidence: list[SelectedCandidateEvidence] = []
        for candidate in sorted(
            candidates,
            key=lambda item: (batch_rank(seed, item), item.pool_leaf),
        ):
            pool = pool_by_publisher[account_id32(candidate.publisher_hotkey)]
            public_bytes = pool.public_bytes_by_batch[candidate.batch_id]
            envelope = pool.envelope_by_batch[candidate.batch_id]
            candidate_evidence.append(
                SelectedCandidateEvidence(
                    publisher_hotkey=str(candidate.publisher_hotkey),
                    control_group_id=_hex_value(candidate.control_group_id),
                    batch_id=candidate.batch_id,
                    batch_commitment=_hex_value(candidate.batch_commitment),
                    pool_leaf=candidate.pool_leaf.hex(),
                    batch_rank=batch_rank(seed, candidate).hex(),
                    selection_ordinal=selected_ordinals.get(candidate.pool_leaf),
                    final_pool_manifest=refs[hashlib.sha256(pool.raw).hexdigest()],
                    public_manifest=refs[hashlib.sha256(public_bytes).hexdigest()],
                    ground_truth_envelope=refs[hashlib.sha256(envelope).hexdigest()],
                )
            )
        miner_evidence = [
            SelectedMinerEvidence(
                panel_ordinal=index,
                uid=neuron.uid,
                hotkey=neuron.hotkey,
                root=neuron.root,
                serving_url=neuron.serving_url or "",
                assigned_observation_count=miner.assigned_observation_count,
                miner_rank=miner_rank(seed, self.validator_hotkey, neuron.hotkey).hex(),
            )
            for index, (miner, neuron) in enumerate(
                zip(selected_panel, selected_neurons, strict=True)
            )
        ]
        videos = [
            SelectedVideoDeliveryEvidence.model_validate(item.model_dump(mode="json"))
            for _key, item in sorted(
                video_by_key.items(),
                key=lambda pair: (
                    base64url_decode(pair[0][0]),
                    base64url_decode(pair[0][1]),
                ),
            )
        ]
        return PoolSelectionEvidence(
            schema=POOL_SELECTION_EVIDENCE_SCHEMA,
            protocol=PROTOCOL_VERSION,
            window_id=work.window.plan.window_id,
            window_index=work.window.plan.window_index,
            scoring_policy_hash=self._policy_hash,
            validator_hotkey=self.validator_hotkey,
            announcement_validator_snapshot=refs[
                hashlib.sha256(snapshot.announcement_snapshot_bytes).hexdigest()
            ],
            announcement_validator_proof_evidence=refs[
                hashlib.sha256(snapshot.announcement_proof_evidence_bytes).hexdigest()
            ],
            closing_snapshot=refs[hashlib.sha256(snapshot.snapshot_bytes).hexdigest()],
            closing_proof_evidence=refs[hashlib.sha256(snapshot.proof_evidence_bytes).hexdigest()],
            artifact_retrieval_evidence=refs[
                hashlib.sha256(source.artifact_retrieval_evidence_bytes).hexdigest()
            ],
            mirror_discovery_rule=refs[hashlib.sha256(delivery.discovery_rule_bytes).hexdigest()],
            mirror_readiness_set=refs[
                hashlib.sha256(source.mirror_readiness_set_bytes).hexdigest()
            ],
            delivery_issuance_request=refs[hashlib.sha256(delivery.request_bytes).hexdigest()],
            delivery_issuance_response=refs[hashlib.sha256(delivery.response_bytes).hexdigest()],
            delivery_issuance_evidence=refs[hashlib.sha256(delivery.evidence_bytes).hexdigest()],
            selection_pulse=refs[hashlib.sha256(pulse_bytes).hexdigest()],
            selection_pulse_evidence_digest=pulse.evidence_digest,
            policy_object=refs[hashlib.sha256(self._policy_bytes).hexdigest()],
            prior_protocol_state=refs[
                hashlib.sha256(encode_protocol_state_snapshot(state)).hexdigest()
            ],
            protocol_state_digest=state.state_digest.hex(),
            prior_spent_root=state.spent_registry.root.hex(),
            prior_publisher_fault_root=state.publisher_faults.root.hex(),
            candidate_pool_root=pool_root.hex(),
            selection_seed=seed.hex(),
            candidates=candidate_evidence,
            selected_panel=miner_evidence,
            selected_video_deliveries=videos,
            issuance_block=prepared.issuance_block,
            issuance_block_hash=prepared.issuance_block_hash,
            issuance_finality_evidence=refs[
                hashlib.sha256(prepared.finality_evidence_bytes).hexdigest()
            ],
            assignment_ids=[item.assignment_id for item in execution_plan.assignments],
            source_objects=[reference for reference, _data in source_objects],
        )

    def _stage_objects(
        self,
        *,
        evidence_bytes: bytes,
        stored_material_bytes: bytes | None,
        material_receipt_bytes: bytes | None,
        sources: Sequence[tuple[PoolEvidenceObjectRef, bytes]],
    ) -> tuple[StageObjectInput, ...]:
        if (stored_material_bytes is None) != (material_receipt_bytes is None):
            raise ValueError("pool material and receipt must appear together")
        values: list[tuple[bytes, str]] = [(evidence_bytes, "application/json")]
        if stored_material_bytes is not None and material_receipt_bytes is not None:
            values.extend(
                (
                    (stored_material_bytes, "application/json"),
                    (material_receipt_bytes, "application/json"),
                )
            )
        values.extend((data, reference.media_type) for reference, data in sources)
        unique: dict[str, StageObjectInput] = {}
        total = 0
        aggregate_ceiling = min(
            self.maximum_stage_total_bytes,
            self.policy.limits.maximum_audit_bundle_bytes,
        )
        for data, media_type in values:
            if len(data) > self.maximum_stage_object_bytes:
                raise PoolEffectLimitError(
                    "pool material exceeds the configured stage-journal object ceiling"
                )
            digest = hashlib.sha256(data).hexdigest()
            item = StageObjectInput(data=data, media_type=media_type)
            previous = unique.get(digest)
            if previous is not None:
                if previous.media_type != media_type:
                    raise PoolEffectBindingError("one stage digest has conflicting media types")
                continue
            unique[digest] = item
            total += len(data)
            if total > aggregate_ceiling:
                raise PoolEffectLimitError(
                    "pool material exceeds the stage-journal aggregate byte ceiling"
                )
        if len(unique) > MAX_SOURCE_OBJECTS + 3:
            raise PoolEffectLimitError("pool stage object count exceeds its ceiling")
        return tuple(unique[key] for key in sorted(unique, key=bytes.fromhex))

    async def _invoke(self, function: Callable[..., Any], *args: Any, label: str) -> Any:
        try:
            if inspect.iscoroutinefunction(function):
                return await asyncio.wait_for(
                    function(*args),
                    timeout=self.port_timeout_seconds,
                )
            result = await asyncio.wait_for(
                asyncio.to_thread(function, *args),
                timeout=self.port_timeout_seconds,
            )
            if inspect.isawaitable(result):
                return await asyncio.wait_for(result, timeout=self.port_timeout_seconds)
            return result
        except TimeoutError as error:
            raise PoolEffectError(f"{label} port timed out") from error


def _manifest_for_candidate(
    candidate: CandidateBatch,
    qualified: Sequence[_QualifiedPool],
) -> PublicBatchManifest:
    for pool in qualified:
        if candidate.batch_id in pool.public_by_batch:
            return pool.public_by_batch[candidate.batch_id]
    raise PoolEffectBindingError("selected candidate has no qualified public manifest")


def _parse_public_manifest(raw: bytes, policy: ScoringPolicy) -> PublicBatchManifest:
    if not isinstance(raw, bytes):
        raise TypeError("public manifest must be exact bytes")
    if len(raw) > policy.limits.maximum_manifest_bytes:
        raise PoolEffectLimitError("public manifest exceeds policy byte ceiling")
    value = _strict_json(raw, "public manifest")
    manifest = PublicBatchManifest.model_validate(value)
    if canonical_json_bytes(manifest) != raw:
        raise PoolEffectBindingError("public manifest is not exact canonical JSON")
    validate_public_batch_manifest(manifest, policy)
    return manifest


def _parse_pulse(raw: bytes, *, expected_round: int) -> DrandPulse:
    value = _strict_json(raw, "selection pulse")
    if (
        not isinstance(value, dict)
        or type(value.get("round")) is not int
        or type(value.get("randomness")) is not str
        or type(value.get("signature")) is not str
    ):
        raise PoolEffectBindingError(
            "selection pulse fields have noncanonical JSON types",
            reason_code="selection_pulse_shape_invalid",
        )
    try:
        return DrandPulse.from_json(value, expected_round=expected_round)
    except DrandVerificationError as error:
        raise PoolEffectBindingError(
            "selection pulse does not verify",
            reason_code="selection_pulse_verification_failed",
        ) from error


def _strict_json(raw: bytes, label: str) -> Any:
    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise ValueError(f"{label} contains a duplicate JSON key")
            result[key] = value
        return result

    try:
        return json.loads(raw, object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        detail = "duplicate JSON key" if "duplicate JSON key" in str(error) else "invalid JSON"
        raise PoolEffectBindingError(f"{label} contains {detail}") from error


def _object_ref(data: bytes, media_type: str) -> PoolEvidenceObjectRef:
    if not isinstance(data, bytes):
        raise TypeError("source object must be exact bytes")
    if media_type not in {
        "application/json",
        "application/octet-stream",
        SCORING_POLICY_MEDIA_TYPE,
    }:
        raise ValueError("source object media type is unsupported")
    return PoolEvidenceObjectRef(
        sha256=hashlib.sha256(data).hexdigest(),
        media_type=media_type,
        size_bytes=len(data),
    )


def _hex_value(value: str | bytes) -> str:
    if isinstance(value, bytes):
        if len(value) != 32:
            raise ValueError("binary hash value must contain 32 bytes")
        return value.hex()
    if isinstance(value, str) and len(value) == 64:
        try:
            if bytes.fromhex(value).hex() == value:
                return value
        except ValueError:
            pass
    raise ValueError("hash value must be 32 lowercase hexadecimal bytes")


def _serving_origin(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("serving URL must be a nonempty origin")
    if len(value.encode("utf-8")) > MAX_SERVING_URL_BYTES or any(
        ord(character) < 0x20 or ord(character) == 0x7F for character in value
    ):
        raise ValueError("serving URL exceeds its bounded text domain")
    try:
        parsed = urlsplit(value)
        _ = parsed.port
    except ValueError as error:
        raise ValueError("serving URL has an invalid origin") from error
    if parsed.scheme != "https" or not parsed.netloc or parsed.hostname is None:
        raise ValueError("serving URL must be an absolute HTTPS origin")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("serving URL must not contain a path, query, or fragment")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("serving URL must not contain user information")
    return value


def _decoded_delivery_key(value: tuple[str, str]) -> tuple[bytes, bytes]:
    return base64url_decode(value[0]), base64url_decode(value[1])


def _nonnegative_int(value: int, label: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value <= _MAX_SQLITE_INTEGER
    ):
        raise ValueError(f"{label} must be a non-negative bounded integer")
    return value


def _bounded_int(value: int, minimum: int, maximum: int, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{label} must be in [{minimum}, {maximum}]")
    return value


__all__ = [
    "ANNOUNCEMENT_VALIDATOR_PROOF_PROFILE",
    "ANNOUNCEMENT_VALIDATOR_SNAPSHOT_SCHEMA",
    "CLOSING_SNAPSHOT_PROOF_PROFILE",
    "CLOSING_SNAPSHOT_SCHEMA",
    "POOL_SELECTION_EVIDENCE_SCHEMA",
    "AnnouncementValidatorSnapshot",
    "ClosingNeuron",
    "ClosingPublisherState",
    "ClosingSnapshot",
    "ClosingValidatorState",
    "DeliveryIssuanceContext",
    "DeliveryIssuancePort",
    "PoolAndSelectionEffect",
    "PoolBatchSource",
    "PoolEffectBindingError",
    "PoolEffectError",
    "PoolEffectLimitError",
    "PoolEffectPorts",
    "PoolEvidenceObjectRef",
    "PoolSelectionContext",
    "PoolSelectionEvidence",
    "PoolSourcePackage",
    "PreparedAssignmentSet",
    "SelectedCandidateEvidence",
    "SelectedMinerEvidence",
    "SelectedVideoDeliveryEvidence",
    "VerifiedClosingSnapshot",
    "VideoDeliverySource",
]
