"""Production ports for the live assignment/request/response transcript effects.

The stage effects intentionally depend on narrow callables.  This module supplies
the production implementations of those callables without giving the effects a
generic wallet, HTTP client, clock, or chain RPC surface:

* window material is reloaded from the pool-bound durable store and passes a
  policy/capacity preflight before the assignment anchor can be built;
* btauth nonces are allocated durably and signed attempts are self-verified before
  they can enter the transcript store;
* the HTTP port sends the exact prepared bytes, uses the policy ceilings, shares a
  crash-safe per-window resource ledger, and retains the validator-bound encrypted
  response returned by :func:`umi.validator.send_prepared_request`;
* protocol boundary observations come only from the owned finalized-header store
  and its Quicknet adapter; and
* early terminal audit release is the observed Section 10.3 commit-close block,
  never a predicted tempo boundary.

The only resource input supplied by deployment is the complete signed validator
capacity set whose root is pinned in policy.  Pool/material receipts deterministically
derive every byte bound from that set; no opaque meter callback can authorize a
larger transcript.  The proof-backed weight-schedule capture remains a genuine
deployment input shared with the shadow weight build.
"""

from __future__ import annotations

import hashlib
import inspect
import math
import os
import re
import sqlite3
import stat
import time
from collections.abc import Awaitable, Callable
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, Literal, Protocol

import httpx
from pydantic import Field, model_validator
from typing_extensions import Self

from .artifacts import PublicBatchManifest, validate_public_batch_manifest
from .chain_evidence import FinalizedSnapshotRef
from .config import Limits
from .crypto import verify_response_signature
from .encoding import account_id32
from .policy import ScoringPolicy, scoring_policy_hash
from .protocol import PROTOCOL_VERSION, StrictProtocolModel, canonical_json_bytes
from .resources import PreflightBound, ResourceLimitExceeded, ResourceSnapshot
from .validator import (
    OriginResolver,
    PreparedRequestAttempt,
    QueryOutcome,
    prepare_request_attempt,
    send_prepared_request,
)
from .validator_anchor_ports import (
    BittensorAnchorPorts,
    GrandpaQuicknetRoundPort,
    VerifiedRoundAtBlock,
)
from .validator_assignments import (
    MAX_REQUEST_BODY_BYTES,
    MAX_RESPONSE_BODY_BYTES,
    MAX_RETAINED_PREFIX_BYTES,
    AttemptSnapshot,
    deterministic_assignment_id,
)
from .validator_journal import MAX_STAGE_RECEIPT_BYTES, ValidatorStageJournal
from .validator_pool_effect import POOL_SELECTION_EVIDENCE_SCHEMA, PoolSelectionEvidence
from .validator_state import StageWorkItem, WindowStage
from .validator_transcript_effects import (
    TranscriptAssignment,
    TranscriptEffectPending,
    TranscriptEffectPorts,
    VerifiedProtocolObservation,
)
from .validator_weight_build_effect import WeightScheduleCapture, WeightSchedulePort
from .validator_weight_schedule import (
    WeightCommitSchedule,
    WeightCommitSchedulePending,
    WeightScheduleError,
    derive_weight_commit_schedule,
)
from .validator_window_material import StoredWindowMaterial, ValidatorWindowMaterialStore
from .window import QUICKNET_GENESIS_MS, QUICKNET_PERIOD_MS

RESOURCE_BASELINE_SCHEMA = "umi-validator-transcript-resource-baseline/1"
RESOURCE_PREFLIGHT_SCHEMA = "umi-validator-transcript-resource-preflight/1"
VALIDATOR_CAPACITY_SCHEMA = "umi-validator-capacity/1"
VALIDATOR_CAPACITY_SET_EVIDENCE_SCHEMA = "umi-validator-capacity-set-evidence/1"
RESOURCE_DERIVATION_SCHEMA = "umi-validator-transcript-resource-derivation/1"

MAX_RESOURCE_BASELINE_EVIDENCE_BYTES = 4 * 1024 * 1024
MAX_RESOURCE_DATABASE_BYTES = 256 * 1024 * 1024
_MAX_SQLITE_INTEGER = (1 << 63) - 1
MAX_NONCE = _MAX_SQLITE_INTEGER
_HEX32_RE = re.compile(r"^[0-9a-f]{64}$")
_BOUNDARY_RE = re.compile(r"^[a-z0-9][a-z0-9_]{0,95}$")
_REASON_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,127}$")
_SCHEMA_VERSION = "1"
_CAPACITY_DIGEST_DOMAIN = b"umi-validator-capacity-v1\0"
_CAPACITY_LEAF_DOMAIN = b"umi-validator-capacity-leaf-v1\0"
_CAPACITY_SET_DOMAIN = b"umi-validator-capacity-set-v1\0"


class TranscriptPortError(RuntimeError):
    """Stable fail-closed error at a concrete live transcript port."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class TranscriptPortBindingError(TranscriptPortError):
    """An exact durable or injected value is bound to another protocol object."""


class TranscriptResourceStoreError(TranscriptPortError):
    """Crash-safe resource accounting cannot be reproduced."""


Hex32 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
SignatureHex = Annotated[str, Field(pattern=r"^0x[0-9a-f]{128}$")]


class ValidatorResourceCapacities(StrictProtocolModel):
    cpu_core_milliseconds_per_window: Annotated[int, Field(gt=0, le=_MAX_SQLITE_INTEGER)]
    accelerator_milliseconds_per_window: Annotated[
        int,
        Field(ge=0, le=_MAX_SQLITE_INTEGER),
    ]
    peak_host_memory_bytes: Annotated[int, Field(gt=0, le=_MAX_SQLITE_INTEGER)]
    peak_accelerator_memory_bytes: Annotated[
        int,
        Field(ge=0, le=_MAX_SQLITE_INTEGER),
    ]
    retained_storage_bytes: Annotated[int, Field(gt=0, le=_MAX_SQLITE_INTEGER)]

    @model_validator(mode="after")
    def validate_accelerator_pair(self) -> Self:
        if (self.accelerator_milliseconds_per_window == 0) != (
            self.peak_accelerator_memory_bytes == 0
        ):
            raise ValueError(
                "accelerator compute and memory capacities must both be zero or positive"
            )
        return self


class ValidatorCapacityStatement(StrictProtocolModel):
    schema_: Literal[VALIDATOR_CAPACITY_SCHEMA] = Field(alias="schema")
    validator_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    hardware_class: Annotated[str, Field(min_length=1, max_length=256)]
    region_class: Annotated[str, Field(min_length=1, max_length=256)]
    meter_adapter_version: Annotated[str, Field(min_length=1, max_length=512)]
    capacities: ValidatorResourceCapacities

    @model_validator(mode="after")
    def validate_validator(self) -> Self:
        account_id32(self.validator_hotkey)
        return self


class SignedValidatorCapacityStatement(StrictProtocolModel):
    statement: ValidatorCapacityStatement
    signature_scheme: Literal["sr25519", "ed25519"]
    signature: SignatureHex


class ValidatorCapacitySetEvidence(StrictProtocolModel):
    schema_: Literal[VALIDATOR_CAPACITY_SET_EVIDENCE_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    statements: Annotated[list[SignedValidatorCapacityStatement], Field(min_length=1)]

    @model_validator(mode="after")
    def validate_order(self) -> Self:
        accounts = [account_id32(item.statement.validator_hotkey) for item in self.statements]
        if accounts != sorted(accounts) or len(set(accounts)) != len(accounts):
            raise ValueError("capacity statements must be unique and sorted by validator account")
        return self


class TranscriptResourceDerivationEvidence(StrictProtocolModel):
    """Self-contained signed-capacity and receipt-derived resource calculation."""

    schema_: Literal[RESOURCE_DERIVATION_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    window_id: Hex32
    scoring_policy_hash: Hex32
    validator_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    window_material_sha256: Hex32
    window_material_receipt_sha256: Hex32
    pool_stage_evidence_sha256: Hex32
    capacity_set: ValidatorCapacitySetEvidence
    capacity_set_sha256: Hex32
    validator_capacity_statement_sha256: Hex32
    pool_object_count: Annotated[int, Field(gt=0, le=_MAX_SQLITE_INTEGER)]
    pool_object_bytes: Annotated[int, Field(gt=0, le=_MAX_SQLITE_INTEGER)]
    raw_video_count: Annotated[int, Field(gt=0, le=_MAX_SQLITE_INTEGER)]
    raw_video_bytes: Annotated[int, Field(gt=0, le=_MAX_SQLITE_INTEGER)]
    fetch_attempt_bound: Annotated[int, Field(gt=0, le=_MAX_SQLITE_INTEGER)]
    transfer_object_bound: Annotated[int, Field(gt=0, le=_MAX_SQLITE_INTEGER)]
    shared_artifact_wire_bytes: Annotated[int, Field(gt=0, le=_MAX_SQLITE_INTEGER)]
    retained_object_bytes: Annotated[int, Field(gt=0, le=_MAX_SQLITE_INTEGER)]
    audit_manifest_bytes: Annotated[int, Field(gt=0, le=_MAX_SQLITE_INTEGER)]
    audit_object_bytes: Annotated[int, Field(gt=0, le=_MAX_SQLITE_INTEGER)]


class VerifiedValidatorCapacitySet:
    """One immutable, fully signed capacity set whose root matches policy bytes."""

    __slots__ = ("_by_account", "evidence", "evidence_bytes", "evidence_sha256", "policy_hash")

    def __init__(self, policy: ScoringPolicy, evidence_bytes: bytes) -> None:
        if not isinstance(policy, ScoringPolicy):
            raise TypeError("capacity-set policy must be ScoringPolicy")
        if not isinstance(evidence_bytes, bytes) or not evidence_bytes:
            raise TypeError("capacity-set evidence must be nonempty exact bytes")
        if len(evidence_bytes) > MAX_RESOURCE_BASELINE_EVIDENCE_BYTES:
            raise ValueError("capacity-set evidence exceeds its byte ceiling")
        evidence = _parse_exact_json_model(
            evidence_bytes,
            ValidatorCapacitySetEvidence,
            "validator_capacity_set_invalid",
        )
        expected_accounts = sorted(
            account_id32(item.validator_hotkey) for item in policy.validator_registry
        )
        actual_accounts = [
            account_id32(item.statement.validator_hotkey) for item in evidence.statements
        ]
        if actual_accounts != expected_accounts:
            raise TranscriptPortBindingError("validator_capacity_set_registry_mismatch")
        for signed in evidence.statements:
            statement_bytes = canonical_json_bytes(signed.statement)
            digest = hashlib.sha256(_CAPACITY_DIGEST_DOMAIN + statement_bytes).digest()
            if not verify_response_signature(
                digest,
                hotkey_ss58=signed.statement.validator_hotkey,
                scheme=signed.signature_scheme,
                signature=signed.signature,
            ):
                raise TranscriptPortBindingError("validator_capacity_signature_invalid")
        root = validator_capacity_set_root(evidence)
        if root != policy.validator_capacity_set_root:
            raise TranscriptPortBindingError("validator_capacity_set_root_mismatch")
        self.evidence = evidence
        self.evidence_bytes = evidence_bytes
        self.evidence_sha256 = hashlib.sha256(evidence_bytes).hexdigest()
        self.policy_hash = scoring_policy_hash(policy)
        self._by_account = {
            account_id32(item.statement.validator_hotkey): item.statement
            for item in evidence.statements
        }

    def statement_for(self, validator_hotkey: str) -> ValidatorCapacityStatement:
        try:
            return self._by_account[account_id32(validator_hotkey)]
        except KeyError as error:
            raise TranscriptPortBindingError("validator_capacity_statement_missing") from error


def validator_capacity_set_root(evidence: ValidatorCapacitySetEvidence) -> str:
    if not isinstance(evidence, ValidatorCapacitySetEvidence):
        raise TypeError("capacity root requires ValidatorCapacitySetEvidence")
    leaves = []
    for signed in evidence.statements:
        account = account_id32(signed.statement.validator_hotkey)
        statement_digest = hashlib.sha256(canonical_json_bytes(signed.statement)).digest()
        leaves.append(
            (
                account,
                hashlib.sha256(_CAPACITY_LEAF_DOMAIN + account + statement_digest).digest(),
            )
        )
    leaves.sort(key=lambda item: item[0])
    return hashlib.sha256(
        _CAPACITY_SET_DOMAIN
        + len(leaves).to_bytes(4, "big")
        + b"".join(leaf for _account, leaf in leaves)
    ).hexdigest()


class TranscriptResourceBaseline(StrictProtocolModel):
    """Pool-stage meter output required before the assignment stage can start."""

    schema_: Literal[RESOURCE_BASELINE_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    window_id: Hex32
    scoring_policy_hash: Hex32
    window_material_sha256: Hex32
    window_material_receipt_sha256: Hex32
    pool_stage_evidence_sha256: Hex32
    shared_artifact_wire_bytes: Annotated[int, Field(ge=0, le=_MAX_SQLITE_INTEGER)]
    retained_object_bytes: Annotated[int, Field(ge=0, le=_MAX_SQLITE_INTEGER)]
    audit_manifest_bytes: Annotated[int, Field(ge=0, le=_MAX_SQLITE_INTEGER)]
    audit_object_bytes: Annotated[int, Field(ge=0, le=_MAX_SQLITE_INTEGER)]
    retained_storage_capacity: Annotated[int, Field(gt=0, le=_MAX_SQLITE_INTEGER)]
    signed_meter_evidence_sha256: Hex32


@dataclass(frozen=True, slots=True)
class VerifiedTranscriptResourceBaseline:
    """Canonical baseline plus the exact policy-pinned signed meter evidence."""

    baseline: TranscriptResourceBaseline
    baseline_bytes: bytes
    signed_meter_evidence_bytes: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.baseline, TranscriptResourceBaseline):
            raise TypeError("resource baseline must be TranscriptResourceBaseline")
        if not isinstance(self.baseline_bytes, bytes):
            raise TypeError("resource baseline bytes must be exact bytes")
        if canonical_json_bytes(self.baseline) != self.baseline_bytes:
            raise ValueError("resource baseline bytes are not canonical")
        meter = self.signed_meter_evidence_bytes
        if (
            not isinstance(meter, bytes)
            or not meter
            or len(meter) > MAX_RESOURCE_BASELINE_EVIDENCE_BYTES
        ):
            raise ValueError("signed resource meter evidence has an invalid size")
        if hashlib.sha256(meter).hexdigest() != self.baseline.signed_meter_evidence_sha256:
            raise ValueError("signed resource meter evidence digest does not reproduce")


class TranscriptResourceBaselinePort(Protocol):
    def __call__(
        self,
        work: StageWorkItem,
        material: StoredWindowMaterial,
    ) -> VerifiedTranscriptResourceBaseline | Awaitable[VerifiedTranscriptResourceBaseline]: ...


class ReceiptReplayTranscriptResourceBaseline:
    """Derive a conservative transcript baseline solely from receipted pool material.

    Physical CPU/memory meters are still required for soak telemetry, but they are
    not needed to make the transcript byte preflight safe.  The only external
    activation artifact accepted here is the immutable signed validator-capacity
    set whose flat root is already pinned in the scoring policy.
    """

    def __init__(
        self,
        *,
        policy: ScoringPolicy,
        validator_hotkey: str,
        material_store: ValidatorWindowMaterialStore,
        journal: ValidatorStageJournal,
        capacity_set: VerifiedValidatorCapacitySet,
    ) -> None:
        _live_shadow_policy(policy)
        if not isinstance(material_store, ValidatorWindowMaterialStore):
            raise TypeError("material_store must be ValidatorWindowMaterialStore")
        if not isinstance(journal, ValidatorStageJournal):
            raise TypeError("journal must be ValidatorStageJournal")
        if not isinstance(capacity_set, VerifiedValidatorCapacitySet):
            raise TypeError("capacity_set must be VerifiedValidatorCapacitySet")
        policy_hash = scoring_policy_hash(policy)
        if capacity_set.policy_hash != policy_hash:
            raise TranscriptPortBindingError("validator_capacity_policy_mismatch")
        validator = account_id32(validator_hotkey)
        if validator not in {
            account_id32(item.validator_hotkey) for item in policy.validator_registry
        }:
            raise ValueError("resource-baseline validator is absent from the policy registry")
        capacity_set.statement_for(validator_hotkey)
        self.policy = policy
        self.policy_hash = policy_hash
        self.validator_hotkey = validator_hotkey
        self.validator_account_id32 = validator
        self.material_store = material_store
        self.journal = journal
        self.capacity_set = capacity_set

    def __call__(
        self,
        work: StageWorkItem,
        material: StoredWindowMaterial,
    ) -> VerifiedTranscriptResourceBaseline:
        if not isinstance(material, StoredWindowMaterial):
            raise TypeError("resource baseline requires StoredWindowMaterial")
        authoritative = self.material_store.load_for_work(work)
        if (
            authoritative.receipt_bytes != material.receipt_bytes
            or authoritative.receipt_sha256 != material.receipt_sha256
            or authoritative.pool_stage_evidence_sha256 != material.pool_stage_evidence_sha256
        ):
            raise TranscriptPortBindingError("resource_material_argument_mismatch")
        record = self.journal.load(material.window.window_id, WindowStage.POOL_AND_SELECTION)
        if record.evidence_sha256 != material.pool_stage_evidence_sha256:
            raise TranscriptPortBindingError("resource_pool_receipt_mismatch")
        object_bytes = {
            reference.sha256: self.journal.read_object(reference)
            for reference in record.receipt.objects
        }
        selection_bytes = object_bytes.get(material.receipt.source_evidence_sha256)
        if selection_bytes is None:
            raise TranscriptPortBindingError("resource_pool_selection_missing")
        selection = _parse_exact_json_model(
            selection_bytes,
            PoolSelectionEvidence,
            "resource_pool_selection_invalid",
        )
        self._validate_selection(selection, material, record.receipt.objects, object_bytes)

        videos: dict[str, int] = {}
        for candidate in selection.candidates:
            manifest_bytes = object_bytes[candidate.public_manifest.sha256]
            manifest = _parse_exact_json_model(
                manifest_bytes,
                PublicBatchManifest,
                "resource_public_manifest_invalid",
            )
            try:
                validate_public_batch_manifest(manifest, self.policy)
            except (TypeError, ValueError) as error:
                raise TranscriptPortBindingError(
                    "resource_public_manifest_policy_mismatch"
                ) from error
            if manifest.batch_id != candidate.batch_id:
                raise TranscriptPortBindingError("resource_public_manifest_candidate_mismatch")
            if (
                manifest.window_id != material.window.window_id
                or manifest.scoring_policy_hash != self.policy_hash
                or manifest.response_close_round != material.window.response_close_round
                or manifest.reveal_round != material.window.reveal_round
                or account_id32(manifest.publisher_hotkey)
                != account_id32(candidate.publisher_hotkey)
            ):
                raise TranscriptPortBindingError("resource_public_manifest_window_mismatch")
            for item in manifest.items:
                prior = videos.setdefault(item.media.sha256, item.media.size_bytes)
                if prior != item.media.size_bytes:
                    raise TranscriptPortBindingError("resource_video_size_conflict")

        pool_object_bytes = _bounded_sum(
            (reference.size_bytes for reference in record.receipt.objects),
            "pool receipt objects",
        )
        raw_video_bytes = _bounded_sum(videos.values(), "candidate raw videos")
        retained_sizes = {
            reference.sha256: reference.size_bytes for reference in record.receipt.objects
        }
        for digest, size in videos.items():
            previous = retained_sizes.setdefault(digest, size)
            if previous != size:
                raise TranscriptPortBindingError("resource_retained_size_conflict")
        retained_object_bytes = _bounded_sum(retained_sizes.values(), "retained pool objects")
        attempts = self.policy.limits.maximum_video_fetch_attempts_per_actor
        transfer_objects = len(record.receipt.objects) + len(videos)
        one_attempt = _bounded_sum(
            (
                pool_object_bytes,
                raw_video_bytes,
                transfer_objects * self.policy.limits.maximum_http_header_bytes,
            ),
            "one pool artifact transfer",
        )
        shared_wire_bytes = _bounded_product(
            one_attempt,
            attempts,
            "pool artifact transfer attempts",
        )
        statement = self.capacity_set.statement_for(self.validator_hotkey)
        statement_sha256 = hashlib.sha256(canonical_json_bytes(statement)).hexdigest()
        derivation = TranscriptResourceDerivationEvidence(
            schema=RESOURCE_DERIVATION_SCHEMA,
            protocol=PROTOCOL_VERSION,
            window_id=material.window.window_id,
            scoring_policy_hash=self.policy_hash,
            validator_hotkey=self.validator_hotkey,
            window_material_sha256=material.receipt.material_sha256,
            window_material_receipt_sha256=material.receipt_sha256,
            pool_stage_evidence_sha256=record.evidence_sha256,
            capacity_set=self.capacity_set.evidence,
            capacity_set_sha256=self.capacity_set.evidence_sha256,
            validator_capacity_statement_sha256=statement_sha256,
            pool_object_count=len(record.receipt.objects),
            pool_object_bytes=pool_object_bytes,
            raw_video_count=len(videos),
            raw_video_bytes=raw_video_bytes,
            fetch_attempt_bound=attempts,
            transfer_object_bound=transfer_objects,
            shared_artifact_wire_bytes=shared_wire_bytes,
            retained_object_bytes=retained_object_bytes,
            audit_manifest_bytes=len(record.receipt_bytes),
            audit_object_bytes=pool_object_bytes,
        )
        derivation_bytes = canonical_json_bytes(derivation)
        baseline = TranscriptResourceBaseline(
            schema=RESOURCE_BASELINE_SCHEMA,
            protocol=PROTOCOL_VERSION,
            window_id=material.window.window_id,
            scoring_policy_hash=self.policy_hash,
            window_material_sha256=material.receipt.material_sha256,
            window_material_receipt_sha256=material.receipt_sha256,
            pool_stage_evidence_sha256=record.evidence_sha256,
            shared_artifact_wire_bytes=shared_wire_bytes,
            retained_object_bytes=retained_object_bytes,
            audit_manifest_bytes=len(record.receipt_bytes),
            audit_object_bytes=pool_object_bytes,
            retained_storage_capacity=statement.capacities.retained_storage_bytes,
            signed_meter_evidence_sha256=hashlib.sha256(derivation_bytes).hexdigest(),
        )
        return VerifiedTranscriptResourceBaseline(
            baseline=baseline,
            baseline_bytes=canonical_json_bytes(baseline),
            signed_meter_evidence_bytes=derivation_bytes,
        )

    def _validate_selection(
        self,
        selection: PoolSelectionEvidence,
        material: StoredWindowMaterial,
        references: list[Any],
        object_bytes: dict[str, bytes],
    ) -> None:
        if (
            selection.schema_ != POOL_SELECTION_EVIDENCE_SCHEMA
            or selection.window_id != material.window.window_id
            or selection.window_index != material.window.window_index
            or selection.scoring_policy_hash != self.policy_hash
            or account_id32(selection.validator_hotkey) != self.validator_account_id32
            or selection.assignment_ids
            != [item.assignment_id for item in material.plan.assignments]
        ):
            raise TranscriptPortBindingError("resource_pool_selection_binding_mismatch")
        indexed = {reference.sha256: reference for reference in references}
        if len(indexed) != len(references):
            raise TranscriptPortBindingError("resource_pool_receipt_duplicate")
        for source in selection.source_objects:
            receipted = indexed.get(source.sha256)
            data = object_bytes.get(source.sha256)
            if (
                receipted is None
                or data is None
                or receipted.media_type != source.media_type
                or receipted.size_bytes != source.size_bytes
                or len(data) != source.size_bytes
                or hashlib.sha256(data).hexdigest() != source.sha256
            ):
                raise TranscriptPortBindingError("resource_pool_source_object_mismatch")
        for digest, expected_size in (
            (material.receipt.material_sha256, len(material.material_bytes)),
            (material.receipt_sha256, len(material.receipt_bytes)),
            (material.receipt.source_evidence_sha256, len(canonical_json_bytes(selection))),
        ):
            reference = indexed.get(digest)
            if (
                reference is None
                or reference.media_type != "application/json"
                or reference.size_bytes != expected_size
            ):
                raise TranscriptPortBindingError("resource_pool_material_object_mismatch")


class TranscriptResourcePreflightReceipt(StrictProtocolModel):
    """Durable calculation that binds preflight and future ledger accounting."""

    schema_: Literal[RESOURCE_PREFLIGHT_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    window_id: Hex32
    scoring_policy_hash: Hex32
    window_material_sha256: Hex32
    window_material_receipt_sha256: Hex32
    pool_stage_evidence_sha256: Hex32
    resource_baseline_sha256: Hex32
    signed_meter_evidence_sha256: Hex32
    assignment_count: Annotated[int, Field(gt=0, le=_MAX_SQLITE_INTEGER)]
    maximum_request_transmissions: Annotated[int, Field(gt=0, le=_MAX_SQLITE_INTEGER)]
    maximum_response_bodies: Annotated[int, Field(gt=0, le=_MAX_SQLITE_INTEGER)]
    maximum_http_header_bytes: Annotated[int, Field(gt=0, le=_MAX_SQLITE_INTEGER)]
    maximum_request_body_bytes: Annotated[int, Field(gt=0, le=_MAX_SQLITE_INTEGER)]
    maximum_response_body_bytes: Annotated[int, Field(gt=0, le=_MAX_SQLITE_INTEGER)]
    maximum_assignment_wire_bytes: Annotated[int, Field(gt=0, le=_MAX_SQLITE_INTEGER)]
    maximum_window_wire_bytes: Annotated[int, Field(gt=0, le=_MAX_SQLITE_INTEGER)]
    retained_storage_capacity: Annotated[int, Field(gt=0, le=_MAX_SQLITE_INTEGER)]
    maximum_audit_bundle_bytes: Annotated[int, Field(gt=0, le=_MAX_SQLITE_INTEGER)]
    assignment_wire_bound: Annotated[int, Field(ge=0, le=_MAX_SQLITE_INTEGER)]
    window_wire_bound: Annotated[int, Field(ge=0, le=_MAX_SQLITE_INTEGER)]
    retained_object_bound: Annotated[int, Field(ge=0, le=_MAX_SQLITE_INTEGER)]
    audit_bundle_bound: Annotated[int, Field(ge=0, le=_MAX_SQLITE_INTEGER)]
    initial_window_wire_bytes: Annotated[int, Field(ge=0, le=_MAX_SQLITE_INTEGER)]


class DurableWindowResourceLedger:
    """One window-bound, cross-process implementation of ``ResourceLedger``."""

    def __init__(self, store: DurableTranscriptResourceStore, window_id: str) -> None:
        self._store = store
        self.window_id = _hex32(window_id, "resource-ledger window ID")

    @property
    def maximum_assignment_wire_bytes(self) -> int:
        return self._store._window_limits(self.window_id)[0]

    @property
    def maximum_window_wire_bytes(self) -> int:
        return self._store._window_limits(self.window_id)[1]

    def charge(self, byte_count: int, *, assignment_id: str | None = None) -> None:
        if assignment_id is None:
            raise ValueError("transcript ledger charges must bind one assignment")
        self._store._charge(self.window_id, byte_count, assignment_id=assignment_id)

    def begin_attempt(self, key: str, *, maximum_attempts: int) -> int:
        return self._store._begin_attempt(
            self.window_id,
            key,
            maximum_attempts=maximum_attempts,
        )

    def snapshot(self) -> ResourceSnapshot:
        return self._store._snapshot(self.window_id)


class DurableTranscriptResourceStore:
    """SQLite-authoritative per-window wire accounting and preflight receipts."""

    def __init__(
        self,
        root: str | Path,
        *,
        maximum_database_bytes: int = MAX_RESOURCE_DATABASE_BYTES,
        busy_timeout_ms: int = 5_000,
    ) -> None:
        if (
            isinstance(maximum_database_bytes, bool)
            or not isinstance(maximum_database_bytes, int)
            or not 1 <= maximum_database_bytes <= MAX_RESOURCE_DATABASE_BYTES
        ):
            raise ValueError("resource database byte ceiling is invalid")
        if (
            isinstance(busy_timeout_ms, bool)
            or not isinstance(busy_timeout_ms, int)
            or not 1 <= busy_timeout_ms <= 60_000
        ):
            raise ValueError("resource database busy timeout is invalid")
        self.root = Path(root)
        _ensure_real_directory(self.root)
        self.database_path = self.root / "transcript-resources.sqlite3"
        if os.path.lexists(self.database_path) and self.database_path.is_symlink():
            raise TranscriptResourceStoreError("resource_database_symlink")
        self.maximum_database_bytes = maximum_database_bytes
        self._busy_timeout_ms = busy_timeout_ms
        self._initialize()
        self.audit()

    def record_preflight(
        self,
        receipt: TranscriptResourcePreflightReceipt,
        *,
        baseline_bytes: bytes,
        signed_meter_evidence_bytes: bytes,
    ) -> DurableWindowResourceLedger:
        if not isinstance(receipt, TranscriptResourcePreflightReceipt):
            raise TypeError("preflight receipt must be TranscriptResourcePreflightReceipt")
        if not isinstance(baseline_bytes, bytes) or not isinstance(
            signed_meter_evidence_bytes, bytes
        ):
            raise TypeError("preflight source evidence must be exact bytes")
        encoded = canonical_json_bytes(receipt)
        baseline_sha256 = hashlib.sha256(baseline_bytes).hexdigest()
        meter_sha256 = hashlib.sha256(signed_meter_evidence_bytes).hexdigest()
        if (
            baseline_sha256 != receipt.resource_baseline_sha256
            or meter_sha256 != receipt.signed_meter_evidence_sha256
        ):
            raise TranscriptPortBindingError("resource_preflight_source_digest_mismatch")
        values = (
            receipt.window_id,
            receipt.scoring_policy_hash,
            receipt.window_material_sha256,
            receipt.pool_stage_evidence_sha256,
            receipt.maximum_assignment_wire_bytes,
            receipt.maximum_window_wire_bytes,
            receipt.initial_window_wire_bytes,
            encoded,
            baseline_bytes,
            signed_meter_evidence_bytes,
        )
        with self._transaction() as connection:
            existing = connection.execute(
                "SELECT * FROM windows WHERE window_id = ?",
                (receipt.window_id,),
            ).fetchone()
            if existing is None:
                connection.execute(
                    """
                    INSERT INTO windows (
                        window_id, scoring_policy_hash, material_sha256,
                        pool_stage_evidence_sha256,
                        maximum_assignment_wire_bytes, maximum_window_wire_bytes,
                        window_wire_bytes, preflight_receipt, baseline_bytes,
                        meter_evidence_bytes
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    values,
                )
            else:
                static_values = (
                    receipt.window_id,
                    receipt.scoring_policy_hash,
                    receipt.window_material_sha256,
                    receipt.pool_stage_evidence_sha256,
                    receipt.maximum_assignment_wire_bytes,
                    receipt.maximum_window_wire_bytes,
                    encoded,
                    baseline_bytes,
                    signed_meter_evidence_bytes,
                )
                if (
                    self._window_static_values(existing) != static_values
                    or int(existing["window_wire_bytes"]) < receipt.initial_window_wire_bytes
                ):
                    raise TranscriptResourceStoreError("resource_preflight_conflict")
            self._enforce_database_size(connection)
        return DurableWindowResourceLedger(self, receipt.window_id)

    def ledger(self, window_id: str) -> DurableWindowResourceLedger:
        window_id = _hex32(window_id, "resource-ledger window ID")
        with self._connection() as connection:
            if (
                connection.execute(
                    "SELECT 1 FROM windows WHERE window_id = ?",
                    (window_id,),
                ).fetchone()
                is None
            ):
                raise TranscriptResourceStoreError("resource_preflight_missing")
        return DurableWindowResourceLedger(self, window_id)

    def preflight_receipt(self, window_id: str) -> TranscriptResourcePreflightReceipt:
        window_id = _hex32(window_id, "resource-ledger window ID")
        with self._connection() as connection:
            row = connection.execute(
                "SELECT preflight_receipt FROM windows WHERE window_id = ?",
                (window_id,),
            ).fetchone()
        if row is None:
            raise TranscriptResourceStoreError("resource_preflight_missing")
        return _parse_canonical_model(
            bytes(row["preflight_receipt"]),
            TranscriptResourcePreflightReceipt,
            "resource_preflight_invalid",
        )

    def audit(self) -> None:
        with self._connection() as connection:
            rows = connection.execute("SELECT * FROM windows ORDER BY window_id").fetchall()
            for row in rows:
                receipt = _parse_canonical_model(
                    bytes(row["preflight_receipt"]),
                    TranscriptResourcePreflightReceipt,
                    "resource_preflight_invalid",
                )
                baseline = _parse_canonical_model(
                    bytes(row["baseline_bytes"]),
                    TranscriptResourceBaseline,
                    "resource_baseline_invalid",
                )
                if self._window_row_values(row) != (
                    receipt.window_id,
                    receipt.scoring_policy_hash,
                    receipt.window_material_sha256,
                    receipt.pool_stage_evidence_sha256,
                    receipt.maximum_assignment_wire_bytes,
                    receipt.maximum_window_wire_bytes,
                    int(row["window_wire_bytes"]),
                    bytes(row["preflight_receipt"]),
                    bytes(row["baseline_bytes"]),
                    bytes(row["meter_evidence_bytes"]),
                ):
                    raise TranscriptResourceStoreError("resource_window_row_corrupt")
                if (
                    baseline.window_id != receipt.window_id
                    or baseline.scoring_policy_hash != receipt.scoring_policy_hash
                    or baseline.window_material_sha256 != receipt.window_material_sha256
                    or baseline.window_material_receipt_sha256
                    != receipt.window_material_receipt_sha256
                    or baseline.pool_stage_evidence_sha256 != receipt.pool_stage_evidence_sha256
                    or hashlib.sha256(bytes(row["baseline_bytes"])).hexdigest()
                    != receipt.resource_baseline_sha256
                    or baseline.signed_meter_evidence_sha256 != receipt.signed_meter_evidence_sha256
                    or hashlib.sha256(bytes(row["meter_evidence_bytes"])).hexdigest()
                    != receipt.signed_meter_evidence_sha256
                    or baseline.shared_artifact_wire_bytes != receipt.initial_window_wire_bytes
                    or baseline.retained_storage_capacity != receipt.retained_storage_capacity
                    or int(row["window_wire_bytes"]) > receipt.maximum_window_wire_bytes
                ):
                    raise TranscriptResourceStoreError("resource_preflight_binding_corrupt")
                reproduced_assignment_bound = receipt.maximum_request_transmissions * (
                    receipt.maximum_http_header_bytes + receipt.maximum_request_body_bytes
                ) + receipt.maximum_response_bodies * (
                    receipt.maximum_http_header_bytes + receipt.maximum_response_body_bytes
                )
                if (
                    receipt.assignment_wire_bound != reproduced_assignment_bound
                    or receipt.window_wire_bound
                    != receipt.initial_window_wire_bytes
                    + receipt.assignment_count * receipt.assignment_wire_bound
                    or receipt.retained_object_bound < baseline.retained_object_bytes
                    or receipt.audit_bundle_bound
                    < baseline.audit_manifest_bytes + baseline.audit_object_bytes
                    or receipt.assignment_wire_bound > receipt.maximum_assignment_wire_bytes
                    or receipt.window_wire_bound > receipt.maximum_window_wire_bytes
                    or receipt.retained_object_bound > receipt.retained_storage_capacity
                    or receipt.audit_bundle_bound > receipt.maximum_audit_bundle_bytes
                ):
                    raise TranscriptResourceStoreError("resource_preflight_bound_corrupt")
                assignment_total = connection.execute(
                    "SELECT COALESCE(SUM(byte_count), 0) FROM assignments WHERE window_id = ?",
                    (receipt.window_id,),
                ).fetchone()[0]
                if int(row["window_wire_bytes"]) != receipt.initial_window_wire_bytes + int(
                    assignment_total
                ):
                    raise TranscriptResourceStoreError("resource_window_total_corrupt")
            self._enforce_database_size(connection)

    def _window_limits(self, window_id: str) -> tuple[int, int]:
        with self._connection() as connection:
            row = self._require_window(connection, window_id)
            return (
                int(row["maximum_assignment_wire_bytes"]),
                int(row["maximum_window_wire_bytes"]),
            )

    def _charge(
        self,
        window_id: str,
        byte_count: int,
        *,
        assignment_id: str | None,
    ) -> None:
        if isinstance(byte_count, bool) or not isinstance(byte_count, int) or byte_count < 0:
            raise ValueError("charged byte count must be a non-negative integer")
        if assignment_id is not None and (not isinstance(assignment_id, str) or not assignment_id):
            raise ValueError("assignment ID must not be empty")
        with self._transaction() as connection:
            row = self._require_window(connection, window_id)
            window_total = int(row["window_wire_bytes"]) + byte_count
            if window_total > int(row["maximum_window_wire_bytes"]):
                raise ResourceLimitExceeded("validator window wire-byte ceiling reached")
            if assignment_id is not None:
                prior = connection.execute(
                    "SELECT byte_count FROM assignments WHERE window_id = ? AND assignment_id = ?",
                    (window_id, assignment_id),
                ).fetchone()
                assignment_total = (0 if prior is None else int(prior[0])) + byte_count
                if assignment_total > int(row["maximum_assignment_wire_bytes"]):
                    raise ResourceLimitExceeded("assignment wire-byte ceiling reached")
                connection.execute(
                    """
                    INSERT INTO assignments (window_id, assignment_id, byte_count)
                    VALUES (?, ?, ?)
                    ON CONFLICT(window_id, assignment_id)
                    DO UPDATE SET byte_count = excluded.byte_count
                    """,
                    (window_id, assignment_id, assignment_total),
                )
            connection.execute(
                "UPDATE windows SET window_wire_bytes = ? WHERE window_id = ?",
                (window_total, window_id),
            )
            self._enforce_database_size(connection)

    def _begin_attempt(self, window_id: str, key: str, *, maximum_attempts: int) -> int:
        if not isinstance(key, str) or not key:
            raise ValueError("attempt key must not be empty")
        if (
            isinstance(maximum_attempts, bool)
            or not isinstance(maximum_attempts, int)
            or maximum_attempts <= 0
        ):
            raise ValueError("maximum attempts must be positive")
        with self._transaction() as connection:
            self._require_window(connection, window_id)
            prior = connection.execute(
                "SELECT attempt_count FROM attempts WHERE window_id = ? AND attempt_key = ?",
                (window_id, key),
            ).fetchone()
            next_count = (0 if prior is None else int(prior[0])) + 1
            if next_count > maximum_attempts:
                raise ResourceLimitExceeded("attempt ceiling reached")
            connection.execute(
                """
                INSERT INTO attempts (window_id, attempt_key, attempt_count)
                VALUES (?, ?, ?)
                ON CONFLICT(window_id, attempt_key)
                DO UPDATE SET attempt_count = excluded.attempt_count
                """,
                (window_id, key, next_count),
            )
            self._enforce_database_size(connection)
            return next_count

    def _snapshot(self, window_id: str) -> ResourceSnapshot:
        with self._connection() as connection:
            row = self._require_window(connection, window_id)
            assignments = tuple(
                (item["assignment_id"], int(item["byte_count"]))
                for item in connection.execute(
                    """
                    SELECT assignment_id, byte_count FROM assignments
                    WHERE window_id = ? ORDER BY assignment_id
                    """,
                    (window_id,),
                ).fetchall()
            )
            attempts = tuple(
                (item["attempt_key"], int(item["attempt_count"]))
                for item in connection.execute(
                    """
                    SELECT attempt_key, attempt_count FROM attempts
                    WHERE window_id = ? ORDER BY attempt_key
                    """,
                    (window_id,),
                ).fetchall()
            )
            return ResourceSnapshot(
                window_wire_bytes=int(row["window_wire_bytes"]),
                assignment_wire_bytes=assignments,
                attempts=attempts,
            )

    def _require_window(self, connection: sqlite3.Connection, window_id: str) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM windows WHERE window_id = ?",
            (window_id,),
        ).fetchone()
        if row is None:
            raise TranscriptResourceStoreError("resource_preflight_missing")
        return row

    @staticmethod
    def _window_row_values(row: sqlite3.Row) -> tuple[object, ...]:
        return (
            row["window_id"],
            row["scoring_policy_hash"],
            row["material_sha256"],
            row["pool_stage_evidence_sha256"],
            int(row["maximum_assignment_wire_bytes"]),
            int(row["maximum_window_wire_bytes"]),
            int(row["window_wire_bytes"]),
            bytes(row["preflight_receipt"]),
            bytes(row["baseline_bytes"]),
            bytes(row["meter_evidence_bytes"]),
        )

    @staticmethod
    def _window_static_values(row: sqlite3.Row) -> tuple[object, ...]:
        return (
            row["window_id"],
            row["scoring_policy_hash"],
            row["material_sha256"],
            row["pool_stage_evidence_sha256"],
            int(row["maximum_assignment_wire_bytes"]),
            int(row["maximum_window_wire_bytes"]),
            bytes(row["preflight_receipt"]),
            bytes(row["baseline_bytes"]),
            bytes(row["meter_evidence_bytes"]),
        )

    def _initialize(self) -> None:
        with self._connection() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS schema_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                ) STRICT;
                CREATE TABLE IF NOT EXISTS windows (
                    window_id TEXT PRIMARY KEY,
                    scoring_policy_hash TEXT NOT NULL,
                    material_sha256 TEXT NOT NULL,
                    pool_stage_evidence_sha256 TEXT NOT NULL,
                    maximum_assignment_wire_bytes INTEGER NOT NULL,
                    maximum_window_wire_bytes INTEGER NOT NULL,
                    window_wire_bytes INTEGER NOT NULL,
                    preflight_receipt BLOB NOT NULL,
                    baseline_bytes BLOB NOT NULL,
                    meter_evidence_bytes BLOB NOT NULL
                ) STRICT;
                CREATE TABLE IF NOT EXISTS assignments (
                    window_id TEXT NOT NULL,
                    assignment_id TEXT NOT NULL,
                    byte_count INTEGER NOT NULL,
                    PRIMARY KEY(window_id, assignment_id),
                    FOREIGN KEY(window_id) REFERENCES windows(window_id)
                ) STRICT;
                CREATE TABLE IF NOT EXISTS attempts (
                    window_id TEXT NOT NULL,
                    attempt_key TEXT NOT NULL,
                    attempt_count INTEGER NOT NULL,
                    PRIMARY KEY(window_id, attempt_key),
                    FOREIGN KEY(window_id) REFERENCES windows(window_id)
                ) STRICT;
                """
            )
            existing = connection.execute(
                "SELECT value FROM schema_metadata WHERE key = 'schema_version'"
            ).fetchone()
            if existing is None:
                connection.execute(
                    "INSERT INTO schema_metadata(key, value) VALUES ('schema_version', ?)",
                    (_SCHEMA_VERSION,),
                )
            elif existing[0] != _SCHEMA_VERSION:
                raise TranscriptResourceStoreError("resource_schema_version_mismatch")

    def _enforce_database_size(self, connection: sqlite3.Connection) -> None:
        page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
        page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
        if page_count * page_size > self.maximum_database_bytes:
            raise TranscriptResourceStoreError("resource_database_size_limit")

    @contextmanager
    def _connection(self):
        connection = sqlite3.connect(
            self.database_path,
            timeout=self._busy_timeout_ms / 1_000,
        )
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
            connection.execute(f"PRAGMA busy_timeout = {self._busy_timeout_ms}")
            yield connection
            connection.commit()
        except sqlite3.Error as error:
            connection.rollback()
            raise TranscriptResourceStoreError("resource_database_failure") from error
        finally:
            connection.close()

    @contextmanager
    def _transaction(self):
        with self._connection() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                yield connection
                connection.commit()
            except Exception:
                connection.rollback()
                raise


class TranscriptPreflightPlanPort:
    """Pool-bound plan loader that makes resource preflight an assignment prerequisite."""

    def __init__(
        self,
        *,
        policy: ScoringPolicy,
        material_store: ValidatorWindowMaterialStore,
        journal: ValidatorStageJournal,
        baseline: TranscriptResourceBaselinePort,
        resources: DurableTranscriptResourceStore,
    ) -> None:
        _live_shadow_policy(policy)
        if not isinstance(material_store, ValidatorWindowMaterialStore):
            raise TypeError("material_store must be ValidatorWindowMaterialStore")
        if not isinstance(journal, ValidatorStageJournal):
            raise TypeError("journal must be ValidatorStageJournal")
        if not callable(baseline):
            raise TypeError("resource baseline port must be callable")
        if not isinstance(resources, DurableTranscriptResourceStore):
            raise TypeError("resources must be DurableTranscriptResourceStore")
        self.policy = policy
        self.policy_hash = scoring_policy_hash(policy)
        self.material_store = material_store
        self.journal = journal
        self.baseline = baseline
        self.resources = resources

    async def __call__(self, work: StageWorkItem) -> StoredWindowMaterial:
        stored = self.material_store.load_for_work(work)
        self._validate_spec(stored)
        value = self.baseline(work, stored)
        baseline = await value if inspect.isawaitable(value) else value
        if not isinstance(baseline, VerifiedTranscriptResourceBaseline):
            raise TranscriptPortBindingError("resource_baseline_type_invalid")
        self._validate_baseline(stored, baseline)
        pool_record = self.journal.load(stored.window.window_id, WindowStage.POOL_AND_SELECTION)
        if pool_record.evidence_sha256 != stored.pool_stage_evidence_sha256:
            raise TranscriptPortBindingError("resource_pool_receipt_mismatch")
        pool_object_bytes = sum(item.size_bytes for item in pool_record.receipt.objects)
        if baseline.baseline.retained_object_bytes < pool_object_bytes:
            raise TranscriptPortBindingError("resource_retained_baseline_omits_pool_objects")
        if baseline.baseline.audit_object_bytes < pool_object_bytes:
            raise TranscriptPortBindingError("resource_audit_baseline_omits_pool_objects")

        transcript_bound = _transcript_retained_bound(stored, self.policy)
        limits = self.policy.limits
        bound = PreflightBound(
            assignment_count=len(stored.plan.assignments),
            shared_artifact_bytes=baseline.baseline.shared_artifact_wire_bytes,
            retained_object_bytes=baseline.baseline.retained_object_bytes + transcript_bound,
            audit_manifest_bytes=baseline.baseline.audit_manifest_bytes,
            audit_object_bytes=baseline.baseline.audit_object_bytes + transcript_bound,
            maximum_request_transmissions=(limits.maximum_request_transmissions_per_assignment),
            maximum_response_bodies=limits.maximum_response_bodies_per_assignment,
            maximum_http_header_bytes=limits.maximum_http_header_bytes,
            maximum_request_body_bytes=limits.maximum_request_body_bytes,
            maximum_response_body_bytes=limits.maximum_response_body_bytes,
        )
        bound.enforce(
            maximum_assignment_wire_bytes=limits.maximum_assignment_wire_bytes,
            maximum_window_wire_bytes=limits.maximum_validator_window_wire_bytes,
            retained_storage_capacity=baseline.baseline.retained_storage_capacity,
            maximum_audit_bundle_bytes=limits.maximum_audit_bundle_bytes,
        )
        receipt = TranscriptResourcePreflightReceipt(
            schema=RESOURCE_PREFLIGHT_SCHEMA,
            protocol=PROTOCOL_VERSION,
            window_id=stored.window.window_id,
            scoring_policy_hash=self.policy_hash,
            window_material_sha256=stored.receipt.material_sha256,
            window_material_receipt_sha256=stored.receipt_sha256,
            pool_stage_evidence_sha256=stored.pool_stage_evidence_sha256,
            resource_baseline_sha256=hashlib.sha256(baseline.baseline_bytes).hexdigest(),
            signed_meter_evidence_sha256=(baseline.baseline.signed_meter_evidence_sha256),
            assignment_count=len(stored.plan.assignments),
            maximum_request_transmissions=(limits.maximum_request_transmissions_per_assignment),
            maximum_response_bodies=limits.maximum_response_bodies_per_assignment,
            maximum_http_header_bytes=limits.maximum_http_header_bytes,
            maximum_request_body_bytes=limits.maximum_request_body_bytes,
            maximum_response_body_bytes=limits.maximum_response_body_bytes,
            maximum_assignment_wire_bytes=limits.maximum_assignment_wire_bytes,
            maximum_window_wire_bytes=limits.maximum_validator_window_wire_bytes,
            retained_storage_capacity=baseline.baseline.retained_storage_capacity,
            maximum_audit_bundle_bytes=limits.maximum_audit_bundle_bytes,
            assignment_wire_bound=bound.assignment_wire_bytes,
            window_wire_bound=bound.window_wire_bytes,
            retained_object_bound=bound.retained_object_bytes,
            audit_bundle_bound=bound.audit_bundle_bytes,
            initial_window_wire_bytes=baseline.baseline.shared_artifact_wire_bytes,
        )
        self.resources.record_preflight(
            receipt,
            baseline_bytes=baseline.baseline_bytes,
            signed_meter_evidence_bytes=baseline.signed_meter_evidence_bytes,
        )
        return stored

    def _validate_spec(self, stored: StoredWindowMaterial) -> None:
        spec = stored.plan.spec
        limits = self.policy.limits
        if (
            stored.window.scoring_policy_hash != self.policy_hash
            or spec.maximum_request_transmissions_per_assignment
            != limits.maximum_request_transmissions_per_assignment
            or spec.maximum_request_body_bytes
            != min(limits.maximum_request_body_bytes, MAX_REQUEST_BODY_BYTES)
            or spec.maximum_response_body_bytes
            != min(limits.maximum_response_body_bytes, MAX_RESPONSE_BODY_BYTES)
            or spec.maximum_retained_prefix_bytes
            != min(limits.maximum_response_body_bytes, MAX_RETAINED_PREFIX_BYTES)
        ):
            raise TranscriptPortBindingError("resource_plan_policy_limits_mismatch")

    def _validate_baseline(
        self,
        stored: StoredWindowMaterial,
        verified: VerifiedTranscriptResourceBaseline,
    ) -> None:
        value = verified.baseline
        if (
            value.window_id != stored.window.window_id
            or value.scoring_policy_hash != self.policy_hash
            or value.window_material_sha256 != stored.receipt.material_sha256
            or value.window_material_receipt_sha256 != stored.receipt_sha256
            or value.pool_stage_evidence_sha256 != stored.pool_stage_evidence_sha256
        ):
            raise TranscriptPortBindingError("resource_baseline_binding_mismatch")


class DurableBtauthNonceStore:
    """Cross-process monotonic btauth nonce allocator for one validator signer."""

    def __init__(
        self,
        root: str | Path,
        *,
        now_ns: Callable[[], int] = time.time_ns,
        busy_timeout_ms: int = 5_000,
    ) -> None:
        if not callable(now_ns):
            raise TypeError("nonce clock must be callable")
        if (
            isinstance(busy_timeout_ms, bool)
            or not isinstance(busy_timeout_ms, int)
            or not 1 <= busy_timeout_ms <= 60_000
        ):
            raise ValueError("nonce database busy timeout is invalid")
        self.root = Path(root)
        _ensure_real_directory(self.root)
        self.database_path = self.root / "btauth-nonces.sqlite3"
        if os.path.lexists(self.database_path) and self.database_path.is_symlink():
            raise TranscriptPortError("nonce_database_symlink")
        self._now_ns = now_ns
        self._busy_timeout_ms = busy_timeout_ms
        with self._connection() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS allocators (
                    validator_account_id32 TEXT PRIMARY KEY,
                    last_nonce INTEGER NOT NULL
                ) STRICT
                """
            )

    def next_nonce(self, validator_account_id32: bytes, *, floor: int) -> int:
        account = bytes(validator_account_id32)
        if len(account) != 32:
            raise ValueError("validator account must contain exactly 32 bytes")
        if isinstance(floor, bool) or not isinstance(floor, int) or not 0 <= floor < MAX_NONCE:
            raise ValueError("nonce floor is invalid")
        now = self._now_ns()
        if isinstance(now, bool) or not isinstance(now, int) or not 0 <= now <= MAX_NONCE:
            raise TranscriptPortError("nonce_clock_invalid")
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT last_nonce FROM allocators WHERE validator_account_id32 = ?",
                (account.hex(),),
            ).fetchone()
            previous = -1 if row is None else int(row[0])
            nonce = max(now, floor + 1, previous + 1)
            if nonce > MAX_NONCE:
                raise TranscriptPortError("nonce_space_exhausted")
            connection.execute(
                """
                INSERT INTO allocators (validator_account_id32, last_nonce)
                VALUES (?, ?)
                ON CONFLICT(validator_account_id32)
                DO UPDATE SET last_nonce = excluded.last_nonce
                """,
                (account.hex(), nonce),
            )
            return nonce

    @contextmanager
    def _connection(self):
        connection = sqlite3.connect(
            self.database_path,
            timeout=self._busy_timeout_ms / 1_000,
        )
        try:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
            connection.execute(f"PRAGMA busy_timeout = {self._busy_timeout_ms}")
            yield connection
            connection.commit()
        except sqlite3.Error as error:
            connection.rollback()
            raise TranscriptPortError("nonce_database_failure") from error
        finally:
            connection.close()

    @contextmanager
    def _transaction(self):
        with self._connection() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                yield connection
                connection.commit()
            except Exception:
                connection.rollback()
                raise


class LiveBtauthAttemptPort:
    """Prepare initial or retry attempts using one private hotkey and durable nonces."""

    def __init__(
        self,
        *,
        policy: ScoringPolicy,
        validator_hotkey: str,
        wallet: Any,
        material_store: ValidatorWindowMaterialStore,
        nonces: DurableBtauthNonceStore,
    ) -> None:
        _live_shadow_policy(policy)
        validator = account_id32(validator_hotkey)
        if validator not in {
            account_id32(item.validator_hotkey) for item in policy.validator_registry
        }:
            raise ValueError("btauth validator is absent from the policy registry")
        try:
            import bittensor as bt

            signer_address = bt.resolve_signer(wallet, role="hotkey").ss58_address
        except Exception as error:
            raise TypeError("wallet does not expose a Bittensor hotkey signer") from error
        if account_id32(signer_address) != validator:
            raise ValueError("btauth wallet belongs to another validator")
        if not isinstance(material_store, ValidatorWindowMaterialStore):
            raise TypeError("material_store must be ValidatorWindowMaterialStore")
        if not isinstance(nonces, DurableBtauthNonceStore):
            raise TypeError("nonces must be DurableBtauthNonceStore")
        self.policy = policy
        self.policy_hash = scoring_policy_hash(policy)
        self.validator_hotkey = validator_hotkey
        self.validator_account_id32 = validator
        self._wallet = wallet
        self.material_store = material_store
        self.nonces = nonces

    def prepare_initial(self, request, *, miner_hotkey: str) -> PreparedRequestAttempt:
        if request.scoring_policy_hash != self.policy_hash:
            raise TranscriptPortBindingError("btauth_request_policy_mismatch")
        nonce = self.nonces.next_nonce(self.validator_account_id32, floor=0)
        return prepare_request_attempt(
            request,
            wallet=self._wallet,
            miner_hotkey=miner_hotkey,
            nonce_ns=nonce,
        )

    async def __call__(
        self,
        assignment: TranscriptAssignment,
        previous: AttemptSnapshot,
        next_attempt_index: int,
        work: StageWorkItem,
    ) -> PreparedRequestAttempt:
        if not isinstance(assignment, TranscriptAssignment) or not isinstance(
            previous, AttemptSnapshot
        ):
            raise TypeError("retry preparation requires exact assignment state")
        stored = self.material_store.load_for_work(work)
        authoritative = _assignment_for(stored, assignment.assignment_id)
        if authoritative != assignment:
            raise TranscriptPortBindingError("btauth_retry_assignment_mismatch")
        if (
            previous.assignment_id != assignment.assignment_id
            or previous.attempt_index + 1 != next_attempt_index
            or previous.outcome is None
            or previous.final
            or next_attempt_index >= stored.plan.spec.maximum_request_transmissions_per_assignment
        ):
            raise TranscriptPortBindingError("btauth_retry_state_invalid")
        floor = max(
            previous.prepared.auth_evidence.auth_record.nonce_int,
            *(
                item.initial_attempt.auth_evidence.auth_record.nonce_int
                for item in stored.plan.assignments
            ),
        )
        nonce = self.nonces.next_nonce(self.validator_account_id32, floor=floor)
        prepared = prepare_request_attempt(
            assignment.initial_attempt.request,
            wallet=self._wallet,
            miner_hotkey=assignment.initial_attempt.miner_hotkey,
            nonce_ns=nonce,
        )
        if (
            prepared.request_bytes != assignment.initial_attempt.request_bytes
            or prepared.request != assignment.initial_attempt.request
            or prepared.validator_hotkey != assignment.initial_attempt.validator_hotkey
            or prepared.miner_hotkey != assignment.initial_attempt.miner_hotkey
        ):
            raise TranscriptPortBindingError("btauth_retry_changed_anchored_request")
        return prepared


class BoundedHttpTranscriptTransport:
    """Send exact prepared attempts through the durable policy-bound resource ledger."""

    def __init__(
        self,
        *,
        policy: ScoringPolicy,
        material_store: ValidatorWindowMaterialStore,
        resources: DurableTranscriptResourceStore,
        timeout_seconds: float,
        transport: httpx.AsyncBaseTransport | None = None,
        resolver: OriginResolver | None = None,
        allow_in_process_transport: bool = False,
    ) -> None:
        _live_shadow_policy(policy)
        if not isinstance(material_store, ValidatorWindowMaterialStore):
            raise TypeError("material_store must be ValidatorWindowMaterialStore")
        if not isinstance(resources, DurableTranscriptResourceStore):
            raise TypeError("resources must be DurableTranscriptResourceStore")
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
        ):
            raise ValueError("HTTP transcript timeout must be positive and finite")
        if transport is not None and not isinstance(transport, httpx.AsyncBaseTransport):
            raise TypeError("HTTP transport must be an async httpx transport")
        if transport is not None and not allow_in_process_transport:
            raise ValueError("custom HTTP transports require explicit test-only opt-in")
        if resolver is not None and not callable(resolver):
            raise TypeError("origin resolver must be callable")
        self.policy = policy
        self.policy_hash = scoring_policy_hash(policy)
        self.material_store = material_store
        self.resources = resources
        self.timeout_seconds = float(timeout_seconds)
        self.transport = transport
        self.resolver = resolver
        self.limits = Limits.from_policy(policy)

    async def __call__(
        self,
        prepared: PreparedRequestAttempt,
        assignment_id: str,
        miner_url: str,
        work: StageWorkItem,
    ) -> QueryOutcome:
        stored = self.material_store.load_for_work(work)
        authoritative = _assignment_for(stored, assignment_id)
        base = authoritative.initial_attempt
        if (
            prepared.request != base.request
            or prepared.request_bytes != base.request_bytes
            or prepared.validator_hotkey != base.validator_hotkey
            or prepared.miner_hotkey != base.miner_hotkey
            or deterministic_assignment_id(prepared) != assignment_id
            or miner_url != authoritative.miner_url
            or prepared.request.scoring_policy_hash != self.policy_hash
        ):
            raise TranscriptPortBindingError("http_transport_material_mismatch")
        if len(prepared.request_bytes) > self.policy.limits.maximum_request_body_bytes:
            return _transport_failure(prepared, "resource_limit")
        ledger = self.resources.ledger(stored.window.window_id)
        try:
            outcome = await send_prepared_request(
                prepared,
                miner_url=miner_url,
                limits=self.limits,
                timeout_seconds=self.timeout_seconds,
                transport=self.transport,
                resolver=self.resolver,
                resource_ledger=ledger,
                assignment_id=assignment_id,
                maximum_request_transmissions=(
                    self.policy.limits.maximum_request_transmissions_per_assignment
                ),
                maximum_response_bodies=(self.policy.limits.maximum_response_bodies_per_assignment),
            )
        except ValueError as error:
            if str(error) != "component request response window has already closed":
                raise
            outcome = _transport_failure(prepared, "late")
        if (
            outcome.request != prepared.request
            or tuple(sorted(outcome.auth_headers.items())) != prepared.auth_headers
        ):
            raise TranscriptPortBindingError("http_transport_changed_anchored_request")
        return outcome


class FinalizedTranscriptObservationPort:
    """Map the newest owned finalized block onto the pinned Quicknet schedule."""

    def __init__(
        self,
        *,
        policy: ScoringPolicy,
        finality: Any,
        rounds: GrandpaQuicknetRoundPort,
    ) -> None:
        _live_shadow_policy(policy)
        for name in ("verified_finalized_snapshot", "verified_block_at"):
            if not callable(getattr(finality, name, None)):
                raise TypeError(f"finality port must define {name}()")
        if not isinstance(rounds, GrandpaQuicknetRoundPort):
            raise TypeError("rounds must be GrandpaQuicknetRoundPort")
        digest = scoring_policy_hash(policy)
        live = policy.implementation_pins.live_chain
        finality_pin = policy.implementation_pins.finality_verifier
        if live is None or finality_pin is None:
            raise ValueError("live finality pins are missing")
        if (
            getattr(finality, "scoring_policy_digest", None) != digest
            or getattr(finality, "chain_observation", None) != live
            or getattr(finality, "finality_verifier_sha256", None)
            not in finality_pin.release_sha256_by_target.values()
        ):
            raise ValueError("finality port differs from the live policy")
        self.policy_hash = digest
        self.live = live
        self.finality = finality
        self.rounds = rounds

    async def __call__(
        self,
        boundary: str,
        work: StageWorkItem,
    ) -> VerifiedProtocolObservation:
        if not isinstance(boundary, str) or _BOUNDARY_RE.fullmatch(boundary) is None:
            raise ValueError("transcript observation boundary is invalid")
        _validate_transcript_work(work, self.policy_hash)
        snapshot = await self.finality.verified_finalized_snapshot()
        if not isinstance(snapshot, FinalizedSnapshotRef):
            raise TranscriptPortBindingError("finalized_snapshot_type_invalid")
        block = await self.finality.verified_block_at(snapshot.block_number)
        if block is None:
            raise TranscriptEffectPending(f"{boundary}_finality_pending")
        if (
            block.height != snapshot.block_number
            or block.block_hash != snapshot.block_hash
            or block.state_root != snapshot.state_root
            or block.scoring_policy_hash != self.policy_hash
            or block.chain_observation != self.live
        ):
            raise TranscriptPortBindingError("finalized_observation_binding_mismatch")
        round_value = await self.rounds.verified_round_at(block.height, block.block_hash)
        if round_value is None:
            raise TranscriptEffectPending(f"{boundary}_round_pending")
        if not isinstance(round_value, VerifiedRoundAtBlock):
            raise TranscriptPortBindingError("quicknet_observation_type_invalid")
        if (
            round_value.block_number != block.height
            or round_value.block_hash != block.block_hash
            or round_value.state_root != block.state_root
            or round_value.timestamp_ms != block.timestamp_ms
            or round_value.finality_evidence_sha256 != block.finality_evidence_sha256
        ):
            raise TranscriptPortBindingError("quicknet_observation_binding_mismatch")
        return VerifiedProtocolObservation(
            finalized_block=block.height,
            finalized_block_hash=block.block_hash,
            quicknet_round=round_value.quicknet_round,
            evidence_bytes=round_value.evidence_bytes,
        )


class ObservedScheduleAuditReleasePort:
    """Resolve transcript incidents to the proof-backed shared commit close."""

    def __init__(self, *, policy: ScoringPolicy, schedule: WeightSchedulePort) -> None:
        _live_shadow_policy(policy)
        if not callable(schedule):
            raise TypeError("weight schedule port must be callable")
        self.policy = policy
        self.policy_hash = scoring_policy_hash(policy)
        self.schedule = schedule

    async def __call__(self, work: StageWorkItem, reason_code: str) -> int:
        _validate_transcript_work(work, self.policy_hash)
        if not isinstance(reason_code, str) or _REASON_RE.fullmatch(reason_code) is None:
            raise ValueError("transcript terminal reason code is invalid")
        value = self.schedule(work)
        capture = await value if inspect.isawaitable(value) else value
        if not isinstance(capture, WeightScheduleCapture):
            raise TranscriptPortBindingError("audit_schedule_capture_type_invalid")
        _validate_schedule_capture(capture, self.policy)
        reveal_time_ms = (
            QUICKNET_GENESIS_MS + (work.window.plan.reveal_round - 1) * QUICKNET_PERIOD_MS
        )
        try:
            result = derive_weight_commit_schedule(
                capture.observations,
                identity=capture.identity,
                reveal_time_ms=reveal_time_ms,
                weight_commit_buffer_blocks=self.policy.clock.weight_commit_buffer_blocks,
                weight_commit_submission_blocks=(self.policy.clock.weight_commit_submission_blocks),
            )
        except WeightScheduleError as error:
            raise TranscriptPortBindingError(f"audit_schedule_{error.reason_code}") from error
        if isinstance(result, WeightCommitSchedulePending):
            raise TranscriptEffectPending(f"audit_release_{result.reason_code}")
        if not isinstance(result, WeightCommitSchedule):
            raise TranscriptPortBindingError("audit_schedule_result_type_invalid")
        return result.weight_commit_close_block.snapshot.block_number


@dataclass(frozen=True, slots=True)
class ProductionTranscriptPorts:
    """Concrete effects-facing ports and their durable supporting adapters."""

    ports: TranscriptEffectPorts
    plan: TranscriptPreflightPlanPort
    transport: BoundedHttpTranscriptTransport
    btauth: LiveBtauthAttemptPort
    observe: FinalizedTranscriptObservationPort
    audit_release: ObservedScheduleAuditReleasePort
    resources: DurableTranscriptResourceStore


def build_production_transcript_ports(
    *,
    policy: ScoringPolicy,
    validator_hotkey: str,
    wallet: Any,
    material_store: ValidatorWindowMaterialStore,
    journal: ValidatorStageJournal,
    anchor_ports: BittensorAnchorPorts,
    finality: Any,
    rounds: GrandpaQuicknetRoundPort,
    schedule: WeightSchedulePort,
    validator_capacity_set: VerifiedValidatorCapacitySet,
    resource_root: str | Path,
    nonce_root: str | Path,
    request_timeout_seconds: float,
) -> ProductionTranscriptPorts:
    """Build production transcript ports without performing network or chain work.

    Custom HTTP transports and DNS resolvers are intentionally absent here.  The
    live transport resolves and pins a public address itself.  Tests may construct
    :class:`BoundedHttpTranscriptTransport` directly with explicit opt-in.
    """

    _live_shadow_policy(policy)
    validator = account_id32(validator_hotkey)
    if not isinstance(anchor_ports, BittensorAnchorPorts):
        raise TypeError("anchor_ports must be BittensorAnchorPorts")
    if anchor_ports.signer_account_id32 != validator:
        raise ValueError("anchor signer belongs to another validator")
    if Path(resource_root).resolve(strict=False) == Path(nonce_root).resolve(strict=False):
        raise ValueError("resource and nonce state roots must be distinct")
    resources = DurableTranscriptResourceStore(resource_root)
    nonces = DurableBtauthNonceStore(nonce_root)
    resource_baseline = ReceiptReplayTranscriptResourceBaseline(
        policy=policy,
        validator_hotkey=validator_hotkey,
        material_store=material_store,
        journal=journal,
        capacity_set=validator_capacity_set,
    )
    plan = TranscriptPreflightPlanPort(
        policy=policy,
        material_store=material_store,
        journal=journal,
        baseline=resource_baseline,
        resources=resources,
    )
    btauth = LiveBtauthAttemptPort(
        policy=policy,
        validator_hotkey=validator_hotkey,
        wallet=wallet,
        material_store=material_store,
        nonces=nonces,
    )
    transport = BoundedHttpTranscriptTransport(
        policy=policy,
        material_store=material_store,
        resources=resources,
        timeout_seconds=request_timeout_seconds,
    )
    observe = FinalizedTranscriptObservationPort(
        policy=policy,
        finality=finality,
        rounds=rounds,
    )
    audit_release = ObservedScheduleAuditReleasePort(policy=policy, schedule=schedule)
    effect_ports = TranscriptEffectPorts(
        plan=plan,
        observe=observe,
        anchor_ports=anchor_ports,
        verify_anchor=anchor_ports.verify_anchor,
        audit_release_block=audit_release,
        transport=transport,
        prepare_retry=btauth,
    )
    return ProductionTranscriptPorts(
        ports=effect_ports,
        plan=plan,
        transport=transport,
        btauth=btauth,
        observe=observe,
        audit_release=audit_release,
        resources=resources,
    )


def _transcript_retained_bound(
    stored: StoredWindowMaterial,
    policy: ScoringPolicy,
) -> int:
    """Conservative unique-object bound for all three transcript receipts."""

    assignment_count = len(stored.plan.assignments)
    attempts = policy.limits.maximum_request_transmissions_per_assignment
    request_bytes = sum(len(item.initial_attempt.request_bytes) for item in stored.plan.assignments)
    # Prepared evidence stores bounded btauth headers and references the request;
    # outcome evidence stores bounded receipt metadata and references the retained
    # body.  The 4096-byte structural allowance is deliberately conservative for
    # canonical JSON fields, hashes, account IDs, and per-stage manifest entries.
    prepared_evidence = (
        assignment_count * attempts * (policy.limits.maximum_http_header_bytes + 4_096)
    )
    outcome_evidence = (
        assignment_count * attempts * (policy.limits.maximum_response_body_bytes + 4_096)
    )
    freeze_and_manifest = 3 * (MAX_STAGE_RECEIPT_BYTES + assignment_count * 512)
    total = request_bytes + prepared_evidence + outcome_evidence + freeze_and_manifest
    if total > _MAX_SQLITE_INTEGER:
        raise ResourceLimitExceeded("transcript evidence bound overflows accounting")
    return total


def _validate_schedule_capture(capture: WeightScheduleCapture, policy: ScoringPolicy) -> None:
    live = policy.implementation_pins.live_chain
    finality = policy.implementation_pins.finality_verifier
    proof = policy.implementation_pins.storage_proof_verifier
    if live is None or finality is None or proof is None:
        raise TranscriptPortBindingError("audit_schedule_policy_pins_missing")
    identity = capture.identity
    if (
        identity.chain_genesis_hash != live.genesis_block_hash
        or identity.finality_verifier_sha256 not in finality.release_sha256_by_target.values()
        or identity.runtime_pin.metadata_sha256 != live.metadata_sha256
        or identity.runtime_pin.spec_version != live.runtime_spec_version
        or identity.runtime_pin.transaction_version != live.transaction_version
        or identity.runtime_pin.state_version != live.state_version
    ):
        raise TranscriptPortBindingError("audit_schedule_identity_mismatch")


def _assignment_for(
    stored: StoredWindowMaterial,
    assignment_id: str,
) -> TranscriptAssignment:
    values = [item for item in stored.plan.assignments if item.assignment_id == assignment_id]
    if len(values) != 1:
        raise TranscriptPortBindingError("transcript_assignment_not_authoritative")
    return values[0]


def _transport_failure(prepared: PreparedRequestAttempt, code: str) -> QueryOutcome:
    return QueryOutcome(
        request=prepared.request,
        auth_headers=dict(prepared.auth_headers),
        received_at_unix_ns=None,
        envelope_bytes=None,
        envelope=None,
        response_signature=None,
        sealed_response=None,
        failure_code=code,
    )


def _validate_transcript_work(work: StageWorkItem, policy_hash: str) -> None:
    if not isinstance(work, StageWorkItem) or work.stage not in {
        WindowStage.ASSIGNMENT,
        WindowStage.REQUEST_TRANSCRIPT,
        WindowStage.SEALED_RESPONSE,
    }:
        raise TranscriptPortBindingError("transcript_port_wrong_stage")
    if work.window.plan.scoring_policy_hash != policy_hash:
        raise TranscriptPortBindingError("transcript_port_policy_mismatch")


def _live_shadow_policy(policy: ScoringPolicy) -> None:
    if not isinstance(policy, ScoringPolicy):
        raise TypeError("policy must be ScoringPolicy")
    if policy.translation_weights_active:
        raise ValueError("live transcript ports are shadow-only")
    if policy.implementation_pins.pin_profile != "live_shadow_calibration":
        raise ValueError("production transcript ports require live-shadow pins")


def _parse_canonical_model(data: bytes, model, reason_code: str):
    try:
        value = model.model_validate_json(data)
    except (ValueError, TypeError) as error:
        raise TranscriptResourceStoreError(reason_code) from error
    if canonical_json_bytes(value) != data:
        raise TranscriptResourceStoreError(reason_code)
    return value


def _parse_exact_json_model(data: bytes, model, reason_code: str):
    if not isinstance(data, bytes):
        raise TypeError("canonical protocol object must be exact bytes")
    try:
        value = model.model_validate_json(data)
    except (ValueError, TypeError) as error:
        raise TranscriptPortBindingError(reason_code) from error
    if canonical_json_bytes(value) != data:
        raise TranscriptPortBindingError(reason_code)
    return value


def _bounded_sum(values, label: str) -> int:
    total = 0
    for value in values:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise TranscriptPortBindingError(f"{label} contains an invalid byte count")
        total += value
        if total > _MAX_SQLITE_INTEGER:
            raise TranscriptPortBindingError(f"{label} byte count overflows")
    return total


def _bounded_product(left: int, right: int, label: str) -> int:
    if (
        isinstance(left, bool)
        or not isinstance(left, int)
        or left < 0
        or isinstance(right, bool)
        or not isinstance(right, int)
        or right < 0
        or (right and left > _MAX_SQLITE_INTEGER // right)
    ):
        raise TranscriptPortBindingError(f"{label} byte count overflows")
    return left * right


def _hex32(value: object, label: str) -> str:
    if not isinstance(value, str) or _HEX32_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be lowercase SHA-256 hexadecimal")
    return value


def _ensure_real_directory(path: Path) -> None:
    if os.path.lexists(path):
        metadata = os.lstat(path)
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise TranscriptPortError("unsafe_state_directory")
        return
    path.mkdir(parents=True, mode=0o700)
    if path.is_symlink() or not path.is_dir():
        raise TranscriptPortError("unsafe_state_directory")


__all__ = [
    "RESOURCE_BASELINE_SCHEMA",
    "RESOURCE_DERIVATION_SCHEMA",
    "RESOURCE_PREFLIGHT_SCHEMA",
    "VALIDATOR_CAPACITY_SCHEMA",
    "VALIDATOR_CAPACITY_SET_EVIDENCE_SCHEMA",
    "BoundedHttpTranscriptTransport",
    "DurableBtauthNonceStore",
    "DurableTranscriptResourceStore",
    "DurableWindowResourceLedger",
    "FinalizedTranscriptObservationPort",
    "LiveBtauthAttemptPort",
    "ObservedScheduleAuditReleasePort",
    "ProductionTranscriptPorts",
    "ReceiptReplayTranscriptResourceBaseline",
    "SignedValidatorCapacityStatement",
    "TranscriptPortBindingError",
    "TranscriptPortError",
    "TranscriptPreflightPlanPort",
    "TranscriptResourceBaseline",
    "TranscriptResourceBaselinePort",
    "TranscriptResourceDerivationEvidence",
    "TranscriptResourcePreflightReceipt",
    "TranscriptResourceStoreError",
    "ValidatorCapacitySetEvidence",
    "ValidatorCapacityStatement",
    "ValidatorResourceCapacities",
    "VerifiedTranscriptResourceBaseline",
    "VerifiedValidatorCapacitySet",
    "build_production_transcript_ports",
    "validator_capacity_set_root",
]
