"""Immutable handoff from pool selection to the transcript effects.

The pool/selection stage is the only code allowed to create a
``TranscriptExecutionPlan``.  The later transcript stages must replay that exact
plan: regenerating a nonce, authentication header, request body, or miner origin
would change the assignment commitment.  This module provides the narrow durable
handoff between those stages without owning a wallet, network client, or chain
write capability.

Each plan is stored as bounded RFC 8785 JSON in an fsynced content-addressed
object.  SQLite (WAL + FULL synchronization) records the immutable window index,
policy hash, object digest, and receipt digest.  A second insert-only table can
bind the material to the exact pool-stage journal receipt after that receipt has
been persisted.  The binding is accepted only when the canonical stage receipt
references both the material receipt and the pool selection evidence object.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator
from typing_extensions import Self

from .anchors import AuthRecord, VerifiedAuthEvidence
from .protocol import (
    PROTOCOL_VERSION,
    StrictProtocolModel,
    TranslationRequest,
    base64url_decode,
    base64url_encode,
    canonical_json_bytes,
)
from .validator import PreparedRequestAttempt
from .validator_assignments import (
    MAX_ASSIGNMENTS_PER_WINDOW,
    MAX_REQUEST_BODY_BYTES,
    AuthHeader,
    TranscriptWindowSpec,
    deterministic_assignment_id,
)
from .validator_journal import MAX_STAGE_RECEIPT_BYTES, StageReceipt
from .validator_state import StageWorkItem, WindowPlan, WindowStage
from .validator_transcript_effects import (
    TranscriptAssignment,
    TranscriptExecutionPlan,
)

WINDOW_MATERIAL_SCHEMA = "umi-validator-window-material/1"
WINDOW_MATERIAL_RECEIPT_SCHEMA = "umi-validator-window-material-receipt/1"

MAX_WINDOW_MATERIAL_BYTES = 384 * 1024 * 1024
MAX_WINDOW_MATERIAL_WINDOWS = 65_536
MAX_AUTH_HEADERS = 64
MAX_MINER_URL_BYTES = 2_048
MAX_WINDOW_MATERIAL_STORE_BYTES = 1 << 40
DEFAULT_WINDOW_MATERIAL_STORE_BYTES = 8 * 1024 * 1024 * 1024
_MAX_SQLITE_INTEGER = (1 << 63) - 1
_READ_CHUNK_BYTES = 64 * 1024
_SCHEMA_VERSION = "1"
_OBJECT_NAME_RE = re.compile(r"^[0-9a-f]{64}$")
_HEX32_RE = re.compile(r"^[0-9a-f]{64}$")


class WindowMaterialStoreError(RuntimeError):
    """Base class for fail-closed window-material persistence errors."""


class WindowMaterialConflict(WindowMaterialStoreError):
    """An immutable window identity is already bound to different material."""


class WindowMaterialBindingError(WindowMaterialStoreError):
    """Plan material is not bound to the authoritative pool-stage receipt."""


Hex32 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class StoredWindowPlan(StrictProtocolModel):
    """Canonical JSON representation of :class:`~umi.validator_state.WindowPlan`."""

    window_id: Hex32
    window_index: Annotated[int, Field(ge=0, le=_MAX_SQLITE_INTEGER)]
    scoring_policy_hash: Hex32
    announcement_block: Annotated[int, Field(ge=0, le=_MAX_SQLITE_INTEGER)]
    proposal_close_block: Annotated[int, Field(ge=0, le=_MAX_SQLITE_INTEGER)]
    closing_block: Annotated[int, Field(ge=0, le=_MAX_SQLITE_INTEGER)]
    selection_round: Annotated[int, Field(ge=0, le=_MAX_SQLITE_INTEGER)]
    issue_close_round: Annotated[int, Field(ge=0, le=_MAX_SQLITE_INTEGER)]
    response_close_round: Annotated[int, Field(ge=0, le=_MAX_SQLITE_INTEGER)]
    reveal_round: Annotated[int, Field(ge=0, le=_MAX_SQLITE_INTEGER)]

    @classmethod
    def from_plan(cls, plan: WindowPlan) -> StoredWindowPlan:
        if not isinstance(plan, WindowPlan):
            raise TypeError("window must be a WindowPlan")
        return cls.model_validate(
            {
                "window_id": plan.window_id,
                "window_index": plan.window_index,
                "scoring_policy_hash": plan.scoring_policy_hash,
                "announcement_block": plan.announcement_block,
                "proposal_close_block": plan.proposal_close_block,
                "closing_block": plan.closing_block,
                "selection_round": plan.selection_round,
                "issue_close_round": plan.issue_close_round,
                "response_close_round": plan.response_close_round,
                "reveal_round": plan.reveal_round,
            }
        )

    def to_plan(self) -> WindowPlan:
        return WindowPlan(**self.model_dump())


class StoredInitialAttempt(StrictProtocolModel):
    """Every byte needed to reproduce one initial prepared request attempt."""

    assignment_id: Hex32
    miner_url: Annotated[str, Field(min_length=1, max_length=MAX_MINER_URL_BYTES)]
    request_bytes_base64url: Annotated[
        str,
        Field(min_length=1, max_length=((MAX_REQUEST_BODY_BYTES + 2) // 3) * 4),
    ]
    validator_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    miner_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    auth_headers: Annotated[list[AuthHeader], Field(min_length=1, max_length=MAX_AUTH_HEADERS)]
    auth_record: AuthRecord
    request_digest: Hex32
    validator_account_id32: Hex32
    miner_account_id32: Hex32

    @field_validator("miner_url")
    @classmethod
    def validate_miner_url(cls, value: str) -> str:
        return _miner_origin(value)

    @field_validator("request_bytes_base64url")
    @classmethod
    def validate_request_bytes(cls, value: str) -> str:
        request_bytes = base64url_decode(value)
        if not request_bytes or len(request_bytes) > MAX_REQUEST_BODY_BYTES:
            raise ValueError("stored request bytes exceed their hard ceiling")
        return value

    @model_validator(mode="after")
    def validate_headers(self) -> Self:
        pairs = [(item.name, item.value) for item in self.auth_headers]
        if pairs != sorted(pairs) or len({name for name, _value in pairs}) != len(pairs):
            raise ValueError("stored authentication headers are not canonical")
        if self.auth_record.sender != self.validator_hotkey:
            raise ValueError("stored authentication record binds another validator")
        if self.auth_record.receiver != self.miner_hotkey:
            raise ValueError("stored authentication record binds another miner")
        return self


class WindowMaterial(StrictProtocolModel):
    """Canonical immutable object containing one full transcript execution plan."""

    schema_: Literal[WINDOW_MATERIAL_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    window: StoredWindowPlan
    source_evidence_sha256: Hex32
    transcript_spec: TranscriptWindowSpec
    assignments: Annotated[
        list[StoredInitialAttempt],
        Field(min_length=1, max_length=MAX_ASSIGNMENTS_PER_WINDOW),
    ]

    @model_validator(mode="after")
    def validate_bindings(self) -> Self:
        if self.transcript_spec.window_id != self.window.window_id:
            raise ValueError("transcript spec binds another material window")
        if self.transcript_spec.issue_close_round != self.window.issue_close_round:
            raise ValueError("transcript spec changes the issue-close round")
        if self.transcript_spec.response_close_round != self.window.response_close_round:
            raise ValueError("transcript spec changes the response-close round")
        if self.transcript_spec.reveal_round != self.window.reveal_round:
            raise ValueError("transcript spec changes the reveal round")
        if len(self.assignments) != self.transcript_spec.expected_assignment_count:
            raise ValueError("material assignment count disagrees with transcript spec")
        identifiers = [item.assignment_id for item in self.assignments]
        if identifiers != sorted(set(identifiers)):
            raise ValueError("material assignments must be unique and sorted by ID")
        return self


class WindowMaterialReceipt(StrictProtocolModel):
    """Small pool-stage object binding a material object to its source evidence."""

    schema_: Literal[WINDOW_MATERIAL_RECEIPT_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    window_id: Hex32
    window_index: Annotated[int, Field(ge=0, le=_MAX_SQLITE_INTEGER)]
    scoring_policy_hash: Hex32
    source_evidence_sha256: Hex32
    material_sha256: Hex32
    material_size_bytes: Annotated[int, Field(gt=0, le=MAX_WINDOW_MATERIAL_BYTES)]
    assignment_count: Annotated[int, Field(gt=0, le=MAX_ASSIGNMENTS_PER_WINDOW)]


@dataclass(frozen=True, slots=True)
class StoredWindowMaterial:
    """Loaded plan plus the exact receipt the pool stage must publish."""

    window: WindowPlan
    plan: TranscriptExecutionPlan
    material_bytes: bytes
    receipt: WindowMaterialReceipt
    receipt_bytes: bytes
    receipt_sha256: str
    pool_stage_evidence_sha256: str | None

    def __post_init__(self) -> None:
        if not isinstance(self.window, WindowPlan):
            raise TypeError("stored window must be WindowPlan")
        if not isinstance(self.plan, TranscriptExecutionPlan):
            raise TypeError("stored plan must be TranscriptExecutionPlan")
        if not isinstance(self.material_bytes, bytes):
            raise TypeError("stored material must be exact bytes")
        if not isinstance(self.receipt, WindowMaterialReceipt):
            raise TypeError("material receipt must be WindowMaterialReceipt")
        if (
            hashlib.sha256(self.material_bytes).hexdigest() != self.receipt.material_sha256
            or len(self.material_bytes) != self.receipt.material_size_bytes
        ):
            raise ValueError("material bytes do not reproduce their receipt")
        if canonical_json_bytes(self.receipt) != self.receipt_bytes:
            raise ValueError("material receipt bytes are not canonical")
        if hashlib.sha256(self.receipt_bytes).hexdigest() != self.receipt_sha256:
            raise ValueError("material receipt digest does not reproduce")
        if self.pool_stage_evidence_sha256 is not None:
            _hex32(self.pool_stage_evidence_sha256, "pool-stage evidence digest")


@dataclass(frozen=True, slots=True)
class PoolStageMaterialBinding:
    """One-time link from plan material to a canonical stage-journal receipt."""

    window_id: str
    material_receipt_sha256: str
    pool_stage_evidence_sha256: str

    def __post_init__(self) -> None:
        _hex32(self.window_id, "window ID")
        _hex32(self.material_receipt_sha256, "material receipt digest")
        _hex32(self.pool_stage_evidence_sha256, "pool-stage evidence digest")


class ValidatorWindowMaterialStore:
    """Durably persist and replay exact pool-selected transcript plans.

    The class deliberately exposes no generic callable or client supplied by the
    caller.  Its only callable behavior is the read-only ``TranscriptPlanPort``
    shape implemented by :meth:`__call__`.
    """

    def __init__(
        self,
        root: str | Path,
        *,
        maximum_material_bytes: int = MAX_WINDOW_MATERIAL_BYTES,
        maximum_assignments_per_window: int = MAX_ASSIGNMENTS_PER_WINDOW,
        maximum_windows: int = 4_096,
        maximum_store_bytes: int = DEFAULT_WINDOW_MATERIAL_STORE_BYTES,
        busy_timeout_ms: int = 5_000,
    ) -> None:
        self.maximum_material_bytes = _bounded_int(
            maximum_material_bytes,
            1,
            MAX_WINDOW_MATERIAL_BYTES,
            "material byte ceiling",
        )
        self.maximum_assignments_per_window = _bounded_int(
            maximum_assignments_per_window,
            1,
            MAX_ASSIGNMENTS_PER_WINDOW,
            "assignment-count ceiling",
        )
        self.maximum_windows = _bounded_int(
            maximum_windows,
            1,
            MAX_WINDOW_MATERIAL_WINDOWS,
            "window-count ceiling",
        )
        self.maximum_store_bytes = _bounded_int(
            maximum_store_bytes,
            self.maximum_material_bytes,
            MAX_WINDOW_MATERIAL_STORE_BYTES,
            "material-store byte ceiling",
        )
        self._busy_timeout_ms = _bounded_int(busy_timeout_ms, 1, 60_000, "busy timeout")
        self.root = Path(root)
        _ensure_real_directory(self.root)
        self.database_path = self.root / "window-material.sqlite3"
        self._reject_database_paths()
        self._objects = _MaterialObjectStore(
            self.root / "objects",
            maximum_object_bytes=max(self.maximum_material_bytes, MAX_STAGE_RECEIPT_BYTES),
            maximum_total_bytes=self.maximum_store_bytes,
            maximum_objects=self.maximum_windows * 4,
        )
        self._initialize()
        self._audit_persisted_state()

    def put(
        self,
        window: WindowPlan,
        plan: TranscriptExecutionPlan,
        *,
        source_evidence_sha256: str,
    ) -> StoredWindowMaterial:
        """Persist one exact plan, idempotently, before the pool stage completes."""

        if not isinstance(window, WindowPlan):
            raise TypeError("window must be a WindowPlan")
        if not isinstance(plan, TranscriptExecutionPlan):
            raise TypeError("plan must be a TranscriptExecutionPlan")
        source_evidence_sha256 = _hex32(
            source_evidence_sha256,
            "pool selection source evidence digest",
        )
        material = self._material_from_plan(window, plan, source_evidence_sha256)
        material_bytes = canonical_json_bytes(material)
        if len(material_bytes) > self.maximum_material_bytes:
            raise WindowMaterialStoreError("window material exceeds its per-window byte ceiling")
        if len(material.assignments) > self.maximum_assignments_per_window:
            raise WindowMaterialStoreError("window material exceeds its assignment-count ceiling")
        material_ref = _ObjectRef(
            hashlib.sha256(material_bytes).hexdigest(),
            len(material_bytes),
        )
        receipt = WindowMaterialReceipt(
            schema=WINDOW_MATERIAL_RECEIPT_SCHEMA,
            protocol=PROTOCOL_VERSION,
            window_id=window.window_id,
            window_index=window.window_index,
            scoring_policy_hash=window.scoring_policy_hash,
            source_evidence_sha256=source_evidence_sha256,
            material_sha256=material_ref.sha256,
            material_size_bytes=material_ref.size_bytes,
            assignment_count=len(material.assignments),
        )
        receipt_bytes = canonical_json_bytes(receipt)
        receipt_ref = _ObjectRef(
            hashlib.sha256(receipt_bytes).hexdigest(),
            len(receipt_bytes),
        )

        values = (
            window.window_id,
            window.window_index,
            window.scoring_policy_hash,
            source_evidence_sha256,
            material_ref.sha256,
            material_ref.size_bytes,
            len(material.assignments),
            receipt_ref.sha256,
            receipt_ref.size_bytes,
        )
        with self._transaction() as connection:
            existing = connection.execute(
                "SELECT * FROM materials WHERE window_id = ?",
                (window.window_id,),
            ).fetchone()
            if existing is not None:
                if self._row_values(existing) != values:
                    raise WindowMaterialConflict(
                        "window ID is already bound to different execution material"
                    )
            else:
                count = connection.execute("SELECT COUNT(*) FROM materials").fetchone()[0]
                if count >= self.maximum_windows:
                    raise WindowMaterialStoreError("window-material count ceiling reached")
                # BEGIN IMMEDIATE serializes this refresh/write sequence across
                # processes. Files land durably before the row that references
                # them; a crash may leave an auditable orphan, never a dangling
                # committed reference.
                self._objects.refresh()
                if self._objects.add(material_bytes) != material_ref:
                    raise WindowMaterialStoreError("stored material reference changed")
                if self._objects.add(receipt_bytes) != receipt_ref:
                    raise WindowMaterialStoreError("stored material receipt reference changed")
                try:
                    connection.execute(
                        """
                        INSERT INTO materials (
                            window_id, window_index, scoring_policy_hash,
                            source_evidence_sha256, material_sha256,
                            material_size_bytes, assignment_count,
                            material_receipt_sha256, material_receipt_size_bytes
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        values,
                    )
                except sqlite3.IntegrityError as error:
                    raise WindowMaterialConflict(
                        "window material violates an immutable database identity"
                    ) from error
        return self.load(window.window_id)

    def attach_pool_stage_receipt(
        self,
        window_id: str,
        receipt_bytes: bytes,
    ) -> PoolStageMaterialBinding:
        """Bind material once to the exact authoritative pool-stage receipt.

        The stage receipt must be canonical, use the deterministic pool operation
        ID, and reference both the returned material receipt and the source
        evidence digest supplied to :meth:`put`.
        """

        window_id = _hex32(window_id, "window ID")
        if not isinstance(receipt_bytes, bytes):
            raise TypeError("pool-stage receipt must be exact bytes")
        if len(receipt_bytes) > MAX_STAGE_RECEIPT_BYTES:
            raise WindowMaterialBindingError("pool-stage receipt exceeds its byte ceiling")
        stage_receipt = _parse_canonical_model(
            receipt_bytes,
            StageReceipt,
            "pool-stage receipt",
        )
        with self._transaction() as connection:
            material = self._require_material(connection, window_id)
            self._validate_pool_stage_receipt(stage_receipt, material)
            pool_ref = _ObjectRef(
                hashlib.sha256(receipt_bytes).hexdigest(),
                len(receipt_bytes),
            )
            existing = connection.execute(
                "SELECT * FROM pool_stage_bindings WHERE window_id = ?",
                (window_id,),
            ).fetchone()
            if existing is not None:
                if (
                    existing["receipt_sha256"] != pool_ref.sha256
                    or existing["receipt_size_bytes"] != pool_ref.size_bytes
                ):
                    raise WindowMaterialConflict(
                        "window material is already bound to another pool-stage receipt"
                    )
            else:
                self._objects.refresh()
                if self._objects.add(receipt_bytes) != pool_ref:
                    raise WindowMaterialStoreError("stored pool receipt reference changed")
                connection.execute(
                    """
                    INSERT INTO pool_stage_bindings (
                        window_id, receipt_sha256, receipt_size_bytes
                    ) VALUES (?, ?, ?)
                    """,
                    (window_id, pool_ref.sha256, pool_ref.size_bytes),
                )
        return PoolStageMaterialBinding(
            window_id=window_id,
            material_receipt_sha256=material["material_receipt_sha256"],
            pool_stage_evidence_sha256=pool_ref.sha256,
        )

    def load(self, window_id: str) -> StoredWindowMaterial:
        """Load and fully reverify one exact persisted execution plan."""

        window_id = _hex32(window_id, "window ID")
        with self._connection() as connection:
            row = self._require_material(connection, window_id)
            binding = connection.execute(
                "SELECT * FROM pool_stage_bindings WHERE window_id = ?",
                (window_id,),
            ).fetchone()
            return self._load_row(row, binding)

    def __call__(self, work: StageWorkItem) -> TranscriptExecutionPlan:
        """Implement the deterministic read-only ``TranscriptPlanPort`` shape."""

        return self.load_for_work(work).plan

    def load_for_work(self, work: StageWorkItem) -> StoredWindowMaterial:
        """Return a work-bound plan together with both canonical material digests.

        Transcript effects that need to evidence the handoff can record
        ``result.receipt.material_sha256`` and ``result.receipt_sha256`` without
        duplicating or reserializing the plan.  The exact validated miner origins
        remain in ``result.plan.assignments``.
        """

        if not isinstance(work, StageWorkItem):
            raise TypeError("work must be a StageWorkItem")
        if work.stage not in {
            WindowStage.ASSIGNMENT,
            WindowStage.REQUEST_TRANSCRIPT,
            WindowStage.SEALED_RESPONSE,
        }:
            raise WindowMaterialBindingError("window material was requested outside transcripts")
        stored = self.load(work.window.plan.window_id)
        if stored.pool_stage_evidence_sha256 is None:
            raise WindowMaterialBindingError(
                "window material has no authoritative pool-stage receipt binding"
            )
        if work.window.plan != stored.window:
            raise WindowMaterialBindingError("pending work disagrees with stored window material")
        pool_evidence = tuple(
            evidence
            for evidence in work.completed_evidence
            if evidence.stage is WindowStage.POOL_AND_SELECTION
        )
        if len(pool_evidence) != 1:
            raise WindowMaterialBindingError(
                "pending work lacks one authoritative pool-stage evidence digest"
            )
        evidence = pool_evidence[0]
        if evidence.window_id != stored.receipt.window_id:
            raise WindowMaterialBindingError("pool-stage evidence binds another window")
        if evidence.evidence_sha256 != stored.pool_stage_evidence_sha256:
            raise WindowMaterialBindingError(
                "pool-stage evidence disagrees with the material binding"
            )
        return stored

    def _material_from_plan(
        self,
        window: WindowPlan,
        plan: TranscriptExecutionPlan,
        source_evidence_sha256: str,
    ) -> WindowMaterial:
        self._validate_plan_window(plan, window)
        stored_assignments: list[StoredInitialAttempt] = []
        for assignment in plan.assignments:
            prepared = assignment.initial_attempt
            evidence = prepared.auth_evidence
            stored_assignments.append(
                StoredInitialAttempt(
                    assignment_id=assignment.assignment_id,
                    miner_url=assignment.miner_url,
                    request_bytes_base64url=base64url_encode(prepared.request_bytes),
                    validator_hotkey=prepared.validator_hotkey,
                    miner_hotkey=prepared.miner_hotkey,
                    auth_headers=[
                        AuthHeader(name=name, value=value) for name, value in prepared.auth_headers
                    ],
                    auth_record=evidence.auth_record,
                    request_digest=evidence.request_digest_bytes.hex(),
                    validator_account_id32=evidence.validator_account_id32.hex(),
                    miner_account_id32=evidence.miner_account_id32.hex(),
                )
            )
        return WindowMaterial(
            schema=WINDOW_MATERIAL_SCHEMA,
            protocol=PROTOCOL_VERSION,
            window=StoredWindowPlan.from_plan(window),
            source_evidence_sha256=source_evidence_sha256,
            transcript_spec=plan.spec,
            assignments=stored_assignments,
        )

    def _validate_plan_window(
        self,
        plan: TranscriptExecutionPlan,
        window: WindowPlan,
    ) -> None:
        spec = plan.spec
        if spec.window_id != window.window_id:
            raise WindowMaterialConflict("execution plan binds another window")
        if spec.issue_close_round != window.issue_close_round:
            raise WindowMaterialConflict("execution plan changes the issue-close round")
        if spec.response_close_round != window.response_close_round:
            raise WindowMaterialConflict("execution plan changes the response-close round")
        if spec.reveal_round != window.reveal_round:
            raise WindowMaterialConflict("execution plan changes the reveal round")
        if len(plan.assignments) > self.maximum_assignments_per_window:
            raise WindowMaterialStoreError("execution plan exceeds the assignment-count ceiling")
        for assignment in plan.assignments:
            request = assignment.initial_attempt.request
            if request.scoring_policy_hash != window.scoring_policy_hash:
                raise WindowMaterialConflict("execution plan request binds another scoring policy")
            _miner_origin(assignment.miner_url)

    def _load_row(
        self,
        row: sqlite3.Row,
        binding: sqlite3.Row | None,
    ) -> StoredWindowMaterial:
        material_bytes = self._objects.read(
            _ObjectRef(row["material_sha256"], row["material_size_bytes"])
        )
        material = _parse_canonical_model(
            material_bytes,
            WindowMaterial,
            "window material",
        )
        receipt_bytes = self._objects.read(
            _ObjectRef(
                row["material_receipt_sha256"],
                row["material_receipt_size_bytes"],
            )
        )
        receipt = _parse_canonical_model(
            receipt_bytes,
            WindowMaterialReceipt,
            "window-material receipt",
        )
        expected_receipt = WindowMaterialReceipt(
            schema=WINDOW_MATERIAL_RECEIPT_SCHEMA,
            protocol=PROTOCOL_VERSION,
            window_id=material.window.window_id,
            window_index=material.window.window_index,
            scoring_policy_hash=material.window.scoring_policy_hash,
            source_evidence_sha256=material.source_evidence_sha256,
            material_sha256=hashlib.sha256(material_bytes).hexdigest(),
            material_size_bytes=len(material_bytes),
            assignment_count=len(material.assignments),
        )
        if receipt != expected_receipt:
            raise WindowMaterialStoreError("material receipt does not reproduce")
        if self._row_values(row) != (
            receipt.window_id,
            receipt.window_index,
            receipt.scoring_policy_hash,
            receipt.source_evidence_sha256,
            receipt.material_sha256,
            receipt.material_size_bytes,
            receipt.assignment_count,
            hashlib.sha256(receipt_bytes).hexdigest(),
            len(receipt_bytes),
        ):
            raise WindowMaterialStoreError("material database row disagrees with its objects")
        if receipt.material_size_bytes > self.maximum_material_bytes:
            raise WindowMaterialStoreError("persisted material exceeds its configured byte ceiling")
        if receipt.assignment_count > self.maximum_assignments_per_window:
            raise WindowMaterialStoreError(
                "persisted material exceeds its configured assignment-count ceiling"
            )
        plan = self._plan_from_material(material)
        pool_digest: str | None = None
        if binding is not None:
            pool_receipt_bytes = self._objects.read(
                _ObjectRef(binding["receipt_sha256"], binding["receipt_size_bytes"])
            )
            pool_receipt = _parse_canonical_model(
                pool_receipt_bytes,
                StageReceipt,
                "bound pool-stage receipt",
            )
            self._validate_pool_stage_receipt(pool_receipt, row)
            pool_digest = hashlib.sha256(pool_receipt_bytes).hexdigest()
            if (
                pool_digest != binding["receipt_sha256"]
                or len(pool_receipt_bytes) != binding["receipt_size_bytes"]
            ):
                raise WindowMaterialStoreError("pool-stage binding columns do not reproduce")
        return StoredWindowMaterial(
            window=material.window.to_plan(),
            plan=plan,
            material_bytes=material_bytes,
            receipt=receipt,
            receipt_bytes=receipt_bytes,
            receipt_sha256=hashlib.sha256(receipt_bytes).hexdigest(),
            pool_stage_evidence_sha256=pool_digest,
        )

    def _plan_from_material(self, material: WindowMaterial) -> TranscriptExecutionPlan:
        assignments: list[TranscriptAssignment] = []
        for item in material.assignments:
            request_bytes = base64url_decode(item.request_bytes_base64url)
            try:
                request = TranslationRequest.model_validate_json(request_bytes)
            except ValueError as error:
                raise WindowMaterialStoreError("stored translation request is invalid") from error
            if canonical_json_bytes(request) != request_bytes:
                raise WindowMaterialStoreError("stored translation request is not canonical")
            headers = tuple((header.name, header.value) for header in item.auth_headers)
            try:
                evidence = VerifiedAuthEvidence.from_headers(
                    dict(headers),
                    request=request,
                    expected_validator_hotkey=item.validator_hotkey,
                    expected_miner_hotkey=item.miner_hotkey,
                )
            except (TypeError, ValueError) as error:
                raise WindowMaterialStoreError(
                    "stored initial authentication evidence is invalid"
                ) from error
            if (
                evidence.auth_record != item.auth_record
                or evidence.request_digest_bytes.hex() != item.request_digest
                or evidence.validator_account_id32.hex() != item.validator_account_id32
                or evidence.miner_account_id32.hex() != item.miner_account_id32
            ):
                raise WindowMaterialStoreError("stored authentication evidence does not reproduce")
            prepared = PreparedRequestAttempt(
                request=request,
                request_bytes=request_bytes,
                validator_hotkey=item.validator_hotkey,
                miner_hotkey=item.miner_hotkey,
                auth_headers=headers,
                auth_evidence=evidence,
            )
            if deterministic_assignment_id(prepared) != item.assignment_id:
                raise WindowMaterialStoreError("stored assignment ID does not reproduce")
            assignments.append(
                TranscriptAssignment(initial_attempt=prepared, miner_url=item.miner_url)
            )
        try:
            plan = TranscriptExecutionPlan(
                spec=material.transcript_spec,
                assignments=tuple(assignments),
            )
        except (TypeError, ValueError) as error:
            raise WindowMaterialStoreError("stored execution plan is invalid") from error
        self._validate_plan_window(plan, material.window.to_plan())
        return plan

    def _validate_pool_stage_receipt(
        self,
        receipt: StageReceipt,
        material: sqlite3.Row,
    ) -> None:
        window_id = material["window_id"]
        if receipt.window_id != window_id or receipt.stage != WindowStage.POOL_AND_SELECTION.value:
            raise WindowMaterialBindingError("stage receipt does not bind this pool window")
        expected_operation = f"umi-stage-v1/{window_id}/{WindowStage.POOL_AND_SELECTION.value}"
        if receipt.operation_id != expected_operation:
            raise WindowMaterialBindingError("pool-stage receipt has a noncanonical operation ID")
        objects = {item.sha256: item for item in receipt.objects}
        material_object = objects.get(material["material_receipt_sha256"])
        if (
            material_object is None
            or material_object.media_type != "application/json"
            or material_object.size_bytes != material["material_receipt_size_bytes"]
        ):
            raise WindowMaterialBindingError(
                "pool-stage receipt does not contain the exact material receipt"
            )
        plan_object = objects.get(material["material_sha256"])
        if (
            plan_object is None
            or plan_object.media_type != "application/json"
            or plan_object.size_bytes != material["material_size_bytes"]
        ):
            raise WindowMaterialBindingError(
                "pool-stage receipt does not contain the exact window material"
            )
        if material["source_evidence_sha256"] not in objects:
            raise WindowMaterialBindingError(
                "pool-stage receipt does not contain the plan source evidence"
            )

    def _audit_persisted_state(self) -> None:
        with self._connection() as connection:
            quick = connection.execute("PRAGMA quick_check").fetchone()[0]
            if quick != "ok":
                raise WindowMaterialStoreError(
                    f"window-material database quick_check failed: {quick}"
                )
            version = connection.execute(
                "SELECT value FROM metadata WHERE key = 'schema_version'"
            ).fetchone()
            if version is None or version[0] != _SCHEMA_VERSION:
                raise WindowMaterialStoreError("unsupported window-material database schema")
            rows = connection.execute("SELECT * FROM materials ORDER BY window_id").fetchall()
            if len(rows) > self.maximum_windows:
                raise WindowMaterialStoreError("persisted material exceeds window-count ceiling")
            for row in rows:
                binding = connection.execute(
                    "SELECT * FROM pool_stage_bindings WHERE window_id = ?",
                    (row["window_id"],),
                ).fetchone()
                self._load_row(row, binding)
            dangling = connection.execute(
                """
                SELECT 1 FROM pool_stage_bindings AS binding
                LEFT JOIN materials AS material ON material.window_id = binding.window_id
                WHERE material.window_id IS NULL LIMIT 1
                """
            ).fetchone()
            if dangling is not None:
                raise WindowMaterialStoreError("pool-stage binding has no material row")

    def _initialize(self) -> None:
        with self._connection() as connection:
            mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]
            if str(mode).lower() != "wal":
                raise WindowMaterialStoreError("SQLite WAL mode is unavailable")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                ) STRICT;
                INSERT OR IGNORE INTO metadata (key, value)
                    VALUES ('schema_version', '1');

                CREATE TABLE IF NOT EXISTS materials (
                    window_id TEXT PRIMARY KEY,
                    window_index INTEGER NOT NULL,
                    scoring_policy_hash TEXT NOT NULL,
                    source_evidence_sha256 TEXT NOT NULL,
                    material_sha256 TEXT NOT NULL,
                    material_size_bytes INTEGER NOT NULL,
                    assignment_count INTEGER NOT NULL,
                    material_receipt_sha256 TEXT NOT NULL UNIQUE,
                    material_receipt_size_bytes INTEGER NOT NULL
                ) STRICT;

                CREATE TABLE IF NOT EXISTS pool_stage_bindings (
                    window_id TEXT PRIMARY KEY REFERENCES materials(window_id),
                    receipt_sha256 TEXT NOT NULL UNIQUE,
                    receipt_size_bytes INTEGER NOT NULL
                ) STRICT;
                """
            )

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        self._reject_database_paths()
        connection = sqlite3.connect(
            self.database_path,
            timeout=self._busy_timeout_ms / 1_000,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute(f"PRAGMA busy_timeout = {self._busy_timeout_ms}")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("PRAGMA fullfsync = ON")
        connection.execute("PRAGMA trusted_schema = OFF")
        self._reject_database_paths()
        with suppress(OSError):
            os.chmod(self.database_path, 0o600, follow_symlinks=False)
        if connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
            connection.close()
            raise WindowMaterialStoreError("SQLite foreign keys are unavailable")
        if connection.execute("PRAGMA synchronous").fetchone()[0] != 2:
            connection.close()
            raise WindowMaterialStoreError("SQLite FULL synchronization is unavailable")
        try:
            yield connection
        finally:
            connection.close()

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
            except BaseException:
                with suppress(sqlite3.Error):
                    connection.execute("ROLLBACK")
                raise
            else:
                connection.execute("COMMIT")

    @staticmethod
    def _require_material(connection: sqlite3.Connection, window_id: str) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM materials WHERE window_id = ?",
            (window_id,),
        ).fetchone()
        if row is None:
            raise WindowMaterialStoreError("unknown window material")
        return row

    def _reject_database_paths(self) -> None:
        for suffix, label in (
            ("", "window-material database"),
            ("-wal", "window-material WAL"),
            ("-shm", "window-material shared-memory file"),
            ("-journal", "window-material rollback journal"),
        ):
            _reject_symlink(Path(f"{self.database_path}{suffix}"), label)

    @staticmethod
    def _row_values(row: sqlite3.Row) -> tuple[Any, ...]:
        return (
            row["window_id"],
            row["window_index"],
            row["scoring_policy_hash"],
            row["source_evidence_sha256"],
            row["material_sha256"],
            row["material_size_bytes"],
            row["assignment_count"],
            row["material_receipt_sha256"],
            row["material_receipt_size_bytes"],
        )


@dataclass(frozen=True, slots=True)
class _ObjectRef:
    sha256: str
    size_bytes: int


class _MaterialObjectStore:
    def __init__(
        self,
        root: Path,
        *,
        maximum_object_bytes: int,
        maximum_total_bytes: int,
        maximum_objects: int,
    ) -> None:
        self.root = root
        self.maximum_object_bytes = maximum_object_bytes
        self.maximum_total_bytes = maximum_total_bytes
        self.maximum_objects = maximum_objects
        _ensure_real_directory(root)
        self._sizes: dict[str, int] = {}
        self._audit()

    def add(self, data: bytes) -> _ObjectRef:
        if not isinstance(data, bytes):
            raise TypeError("material object must be exact bytes")
        if len(data) > self.maximum_object_bytes:
            raise WindowMaterialStoreError("material object exceeds its byte ceiling")
        digest = hashlib.sha256(data).hexdigest()
        existing = self._sizes.get(digest)
        if existing is not None:
            if existing != len(data) or self.read(_ObjectRef(digest, existing)) != data:
                raise WindowMaterialStoreError("content-addressed material collision")
            return _ObjectRef(digest, existing)
        if len(self._sizes) >= self.maximum_objects:
            raise WindowMaterialStoreError("material object-count ceiling reached")
        if sum(self._sizes.values()) + len(data) > self.maximum_total_bytes:
            raise WindowMaterialStoreError("material-store byte ceiling reached")
        _write_content_addressed(self.root / digest, data)
        self._sizes[digest] = len(data)
        return _ObjectRef(digest, len(data))

    def read(self, reference: _ObjectRef) -> bytes:
        data = _read_bounded(self.root / reference.sha256, self.maximum_object_bytes)
        if len(data) != reference.size_bytes:
            raise WindowMaterialStoreError("material object has the wrong byte length")
        if hashlib.sha256(data).hexdigest() != reference.sha256:
            raise WindowMaterialStoreError("material object failed SHA-256 verification")
        return data

    def refresh(self) -> None:
        """Refresh aggregate ceilings while the caller holds the DB write lock."""

        self._sizes.clear()
        self._audit()

    def _audit(self) -> None:
        children = tuple(self.root.iterdir())
        if len(children) > self.maximum_objects:
            raise WindowMaterialStoreError("material object-count ceiling is exceeded")
        total = 0
        for child in children:
            if _OBJECT_NAME_RE.fullmatch(child.name) is None:
                raise WindowMaterialStoreError(
                    "material object directory contains an invalid file name"
                )
            data = _read_bounded(child, self.maximum_object_bytes)
            if hashlib.sha256(data).hexdigest() != child.name:
                raise WindowMaterialStoreError("material object name does not match its bytes")
            self._sizes[child.name] = len(data)
            total += len(data)
            if total > self.maximum_total_bytes:
                raise WindowMaterialStoreError("material-store byte ceiling is exceeded")


def _parse_canonical_model(data: bytes, model: type[Any], label: str) -> Any:
    try:
        decoded = json.loads(data)
        parsed = model.model_validate(decoded)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise WindowMaterialStoreError(f"{label} is invalid") from error
    if canonical_json_bytes(parsed) != data:
        raise WindowMaterialStoreError(f"{label} is not exact canonical JSON")
    return parsed


def _miner_origin(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("miner URL must be a nonempty serving origin")
    if len(value.encode("utf-8")) > MAX_MINER_URL_BYTES or any(
        ord(character) < 0x20 or ord(character) == 0x7F for character in value
    ):
        raise ValueError("miner URL exceeds its bounded text domain")
    try:
        parsed = urlsplit(value)
        _ = parsed.port
    except ValueError as error:
        raise ValueError("miner URL has an invalid origin") from error
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.hostname is None:
        raise ValueError("miner URL must be an absolute HTTP(S) origin")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("miner URL must not contain a path, query, or fragment")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("miner URL must not contain user information")
    return value


def _write_content_addressed(path: Path, data: bytes) -> None:
    descriptor: int | None = None
    temporary: str | None = None
    try:
        descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise OSError("material write made no progress")
            offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError:
            if _read_bounded(path, len(data)) != data:
                raise WindowMaterialStoreError("content-addressed material collision") from None
        _fsync_directory(path.parent)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary is not None:
            with suppress(FileNotFoundError):
                os.unlink(temporary)


def _read_bounded(path: Path, maximum_bytes: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise WindowMaterialStoreError(
            f"material object cannot be opened safely: {path.name}"
        ) from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum_bytes:
            raise WindowMaterialStoreError("material object is not a bounded regular file")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(_READ_CHUNK_BYTES, maximum_bytes - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > maximum_bytes:
                raise WindowMaterialStoreError("material object exceeds its byte ceiling")
            chunks.append(chunk)
        if total != metadata.st_size:
            raise WindowMaterialStoreError("material object changed while being read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _ensure_real_directory(path: Path) -> None:
    absolute = path.absolute()
    missing: list[Path] = []
    cursor = absolute
    try:
        while not os.path.lexists(cursor):
            missing.append(cursor)
            if cursor.parent == cursor:
                break
            cursor = cursor.parent
        for component in (cursor, *cursor.parents):
            metadata = component.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise WindowMaterialStoreError("material path contains a symbolic link")
            if not stat.S_ISDIR(metadata.st_mode):
                raise WindowMaterialStoreError("material path ancestor is not a directory")
        for component in reversed(missing):
            component.mkdir(mode=0o700)
            metadata = component.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise WindowMaterialStoreError("material directory creation was redirected")
            _fsync_directory(component.parent)
        metadata = absolute.lstat()
    except WindowMaterialStoreError:
        raise
    except OSError as error:
        raise WindowMaterialStoreError(
            f"material directory cannot be created safely: {path.name}"
        ) from error
    if not stat.S_ISDIR(metadata.st_mode):
        raise WindowMaterialStoreError("window-material path must be a real directory")


def _reject_symlink(path: Path, label: str) -> None:
    if not os.path.lexists(path):
        return
    try:
        metadata = path.lstat()
    except OSError as error:
        raise WindowMaterialStoreError(f"{label} cannot be inspected safely") from error
    if stat.S_ISLNK(metadata.st_mode):
        raise WindowMaterialStoreError(f"{label} must not be a symbolic link")
    if not stat.S_ISREG(metadata.st_mode):
        raise WindowMaterialStoreError(f"{label} must be a regular file")


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _hex32(value: str, label: str) -> str:
    if not isinstance(value, str) or _HEX32_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be lowercase SHA-256 hexadecimal")
    return value


def _bounded_int(value: Any, minimum: int, maximum: int, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum or value > maximum:
        raise ValueError(f"{label} must be an integer in [{minimum}, {maximum}]")
    return value


__all__ = [
    "DEFAULT_WINDOW_MATERIAL_STORE_BYTES",
    "MAX_WINDOW_MATERIAL_BYTES",
    "WINDOW_MATERIAL_RECEIPT_SCHEMA",
    "WINDOW_MATERIAL_SCHEMA",
    "PoolStageMaterialBinding",
    "StoredWindowMaterial",
    "ValidatorWindowMaterialStore",
    "WindowMaterialBindingError",
    "WindowMaterialConflict",
    "WindowMaterialReceipt",
    "WindowMaterialStoreError",
]
