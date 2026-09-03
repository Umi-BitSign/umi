"""Crash-safe prepared-extrinsic journal for validator chain effects.

The journal deliberately knows nothing about wallets, RPC endpoints, or runtime
metadata.  Those capabilities are injected as small ports.  Its only job is to
make the externally-signed Bittensor flow restart-safe:

* persist the SDK ``UnsignedExtrinsic.to_dict()`` record before signing;
* sign exactly ``UnsignedExtrinsic.payload`` and persist that exact signature;
* reconcile finalized evidence before every submission or resubmission; and
* only ever submit the persisted unsigned record and signature.

Receipts are immutable RFC 8785 objects named by their SHA-256 digest.  A process
crash can leave a fully-fsynced ``.pending-*`` file; startup promotes that file to
its content-addressed name before replaying the operation.
"""

from __future__ import annotations

import asyncio
import fcntl
import hashlib
import inspect
import json
import os
import re
import stat
import tempfile
from collections.abc import Awaitable, Callable, Mapping
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Annotated, Any, Literal, Protocol, TypeVar

from bittensor import UnsignedExtrinsic
from pydantic import Field, JsonValue, model_validator
from typing_extensions import Self

from .protocol import PROTOCOL_VERSION, StrictProtocolModel, canonical_json_bytes

OPERATION_SCHEMA = "umi-validator-extrinsic-operation/1"
ANCHOR_INTENT_SCHEMA = "umi-validator-anchor-intent/1"
PREPARED_CALL_SCHEMA = "umi-validator-prepared-call/1"
RECEIPT_SCHEMA = "umi-validator-extrinsic-receipt/1"
RECONCILIATION_SCHEMA = "umi-validator-extrinsic-reconciliation/1"
SUBMISSION_SCHEMA = "umi-validator-extrinsic-submission/1"

MAX_OPERATION_REQUEST_BYTES = 64 * 1024
MAX_UNSIGNED_RECORD_BYTES = 256 * 1024
MAX_RECONCILIATION_SCAN_BYTES = 256 * 1024
MAX_RECEIPT_BYTES = 512 * 1024
MAX_RECEIPTS_PER_OPERATION = 64
MAX_OPERATIONS = 16_384
MAX_VALIDATOR_ADDRESS_BYTES = 256
MAX_SIGNATURE_BYTES = 65
DEFAULT_PORT_TIMEOUT_SECONDS = 30.0
MAX_PORT_TIMEOUT_SECONDS = 300.0
_READ_CHUNK_BYTES = 64 * 1024

_OPERATION_DOMAIN = b"umi-validator-extrinsic-operation-v1\0"
_HEX32_RE = re.compile(r"^[0-9a-f]{64}$")
_CHAIN_HASH_RE = re.compile(r"^0x[0-9a-f]{64}$")
_RECEIPT_NAME_RE = re.compile(r"^([0-9a-f]{64})\.json$")
_PENDING_NAME_RE = re.compile(r"^\.pending-([0-9a-f]{64})-[A-Za-z0-9_-]+$")


class ExtrinsicJournalError(RuntimeError):
    """Base class for a fail-closed prepared-extrinsic journal error."""


class ExtrinsicJournalConflict(ExtrinsicJournalError):
    """Persisted and requested operation material disagree."""


class ExtrinsicPortTimeout(ExtrinsicJournalError):
    """An injected chain or wallet capability missed its hard deadline."""


class ExtrinsicState(str, Enum):
    PREPARED = "prepared"
    SIGNED = "signed"
    SUBMITTED = "submitted"
    FINALIZED_SUCCESS = "finalized_success"
    FINALIZED_FAILURE = "finalized_failure"
    EXPIRED = "expired"
    UNKNOWN = "unknown"


class ReconcileOutcome(str, Enum):
    NOT_FOUND = "not_found"
    FINALIZED_SUCCESS = "finalized_success"
    FINALIZED_FAILURE = "finalized_failure"
    UNKNOWN = "unknown"


Hex32 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
ChainHash = Annotated[str, Field(pattern=r"^0x[0-9a-f]{64}$")]
AnchorKind = Literal["assignment_set", "request_set", "response_set", "publisher_pool"]
AnchorOperation = Literal[
    "assignment_anchor",
    "request_anchor",
    "response_anchor",
    "publisher_pool_anchor",
]


class AnchorField(StrictProtocolModel):
    """The only commitment field a shadow validator may put on chain."""

    type_: Literal["Data::Sha256"] = Field(alias="type")
    sha256: Hex32


class AnchorIntent(StrictProtocolModel):
    """Closed semantic intent for one pre-reveal transcript anchor."""

    schema_: Literal[ANCHOR_INTENT_SCHEMA] = Field(alias="schema")
    call: Literal["Commitments.set_commitment"]
    netuid: Literal[78] = 78
    anchor_kind: AnchorKind
    field: AnchorField


class PreparedCallEvidence(StrictProtocolModel):
    """Pinned-runtime decoding of the exact call bytes before signing.

    The verifier port must decode ``UnsignedExtrinsic.call_data`` with the
    policy-pinned metadata.  The journal independently binds that decoding to
    the raw bytes, SDK runtime fields, and closed anchor intent.  These bytes
    remain in every receipt so an auditor can repeat the decode.
    """

    schema_: Literal[PREPARED_CALL_SCHEMA] = Field(alias="schema")
    operation_id: Hex32
    call_data_sha256: Hex32
    call_data_size_bytes: Annotated[int, Field(gt=0, le=MAX_UNSIGNED_RECORD_BYTES)]
    module: Literal["Commitments"]
    function: Literal["set_commitment"]
    netuid: Literal[78]
    anchor_kind: AnchorKind
    field_sha256: Hex32
    runtime_spec_version: Annotated[int, Field(gt=0)]
    transaction_version: Annotated[int, Field(gt=0)]
    runtime_metadata_sha256: Hex32


class ExtrinsicOperation(StrictProtocolModel):
    """Canonical intent whose bytes determine the operation ID.

    ``request`` is the exact JSON-domain description supplied by the stage
    adapter (call inputs, pinned block, and any protocol bindings).  The
    prepared SDK record remains authoritative for the actual chain payload.
    """

    schema_: Literal[OPERATION_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    operation: AnchorOperation
    window_id: Hex32
    validator_hotkey: Annotated[
        str,
        Field(min_length=1, max_length=MAX_VALIDATOR_ADDRESS_BYTES),
    ]
    request: AnchorIntent

    @model_validator(mode="after")
    def validate_request_bound(self) -> Self:
        if len(canonical_json_bytes(self.request)) > MAX_OPERATION_REQUEST_BYTES:
            raise ValueError("operation request exceeds its byte ceiling")
        expected_kind = {
            "assignment_anchor": "assignment_set",
            "request_anchor": "request_set",
            "response_anchor": "response_set",
            "publisher_pool_anchor": "publisher_pool",
        }[self.operation]
        if self.request.anchor_kind != expected_kind:
            raise ValueError("anchor operation and intent kind disagree")
        return self

    @property
    def operation_id(self) -> str:
        return hashlib.sha256(_OPERATION_DOMAIN + canonical_json_bytes(self)).hexdigest()


class SubmissionEvidence(StrictProtocolModel):
    """Result returned by the injected ``Client.submit_signature`` adapter."""

    schema_: Literal[SUBMISSION_SCHEMA] = Field(alias="schema")
    operation_id: Hex32
    extrinsic_hash: ChainHash
    unsigned_record_sha256: Hex32
    payload_sha256: Hex32
    signature_sha256: Hex32


class ReconciliationEvidence(StrictProtocolModel):
    """One finalized-chain scan, bound to the persisted signing material."""

    schema_: Literal[RECONCILIATION_SCHEMA] = Field(alias="schema")
    operation_id: Hex32
    outcome: Literal[
        "not_found",
        "finalized_success",
        "finalized_failure",
        "unknown",
    ]
    unsigned_record_sha256: Hex32
    payload_sha256: Hex32
    signature_sha256: Hex32
    finalized_head_block: Annotated[int, Field(ge=0)]
    finalized_head_hash: ChainHash
    scan_start_block: Annotated[int, Field(ge=0)]
    scan_end_block: Annotated[int, Field(ge=0)]
    scan: dict[str, JsonValue]
    scan_sha256: Hex32
    extrinsic_hash: ChainHash | None = None
    inclusion_block: Annotated[int, Field(ge=0)] | None = None
    inclusion_block_hash: ChainHash | None = None

    @model_validator(mode="after")
    def validate_outcome_fields(self) -> Self:
        outcome = ReconcileOutcome(self.outcome)
        inclusion_fields = (self.inclusion_block, self.inclusion_block_hash)
        if not self.scan_start_block <= self.scan_end_block <= self.finalized_head_block:
            raise ValueError("reconciliation scan range is outside the finalized head")
        scan_bytes = canonical_json_bytes(self.scan)
        if len(scan_bytes) > MAX_RECONCILIATION_SCAN_BYTES:
            raise ValueError("reconciliation scan exceeds its byte ceiling")
        if hashlib.sha256(scan_bytes).hexdigest() != self.scan_sha256:
            raise ValueError("reconciliation scan digest does not reproduce")
        if outcome in {
            ReconcileOutcome.FINALIZED_SUCCESS,
            ReconcileOutcome.FINALIZED_FAILURE,
        }:
            if self.extrinsic_hash is None or any(value is None for value in inclusion_fields):
                raise ValueError("a finalized reconciliation requires inclusion evidence")
            if (
                self.inclusion_block is not None
                and self.inclusion_block > self.finalized_head_block
            ):
                raise ValueError("inclusion block is above the finalized head")
        elif any(value is not None for value in inclusion_fields):
            raise ValueError("a non-final reconciliation cannot claim inclusion")
        return self


class ExtrinsicReceipt(StrictProtocolModel):
    """One immutable state transition in an operation's receipt chain."""

    schema_: Literal[RECEIPT_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    operation_id: Hex32
    sequence: Annotated[int, Field(ge=0)]
    previous_receipt_sha256: Hex32 | None
    state: Literal[
        "prepared",
        "signed",
        "submitted",
        "finalized_success",
        "finalized_failure",
        "expired",
        "unknown",
    ]
    operation: ExtrinsicOperation
    unsigned_record: dict[str, JsonValue]
    unsigned_record_sha256: Hex32
    prepared_call: PreparedCallEvidence
    prepared_call_sha256: Hex32
    payload_hex: Annotated[str, Field(pattern=r"^0x(?:[0-9a-f]{2})+$")]
    payload_sha256: Hex32
    era_birth_block: Annotated[int, Field(ge=0)]
    era_death_block: Annotated[int, Field(gt=0)]
    signature_hex: Annotated[str, Field(pattern=r"^0x(?:[0-9a-f]{2})+$")] | None = None
    signature_sha256: Hex32 | None = None
    expected_signed_extrinsic_hash: ChainHash | None = None
    submitted_extrinsic_hash: ChainHash | None = None
    submission: SubmissionEvidence | None = None
    submission_sha256: Hex32 | None = None
    reconciliation: ReconciliationEvidence | None = None
    reconciliation_sha256: Hex32 | None = None
    reason_code: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9_.-]*$", max_length=96)] | None = (
        None
    )

    @model_validator(mode="after")
    def validate_state_shape(self) -> Self:
        state = ExtrinsicState(self.state)
        if self.operation.operation_id != self.operation_id:
            raise ValueError("operation bytes do not reproduce operation_id")
        if self.era_death_block <= self.era_birth_block:
            raise ValueError("mortal era death must follow its birth")
        if self.sequence == 0:
            if self.previous_receipt_sha256 is not None or state is not ExtrinsicState.PREPARED:
                raise ValueError("receipt zero must be the unchained prepared receipt")
        elif self.previous_receipt_sha256 is None:
            raise ValueError("a successor receipt requires its predecessor digest")

        unsigned_bytes = canonical_json_bytes(self.unsigned_record)
        if len(unsigned_bytes) > MAX_UNSIGNED_RECORD_BYTES:
            raise ValueError("unsigned record exceeds its byte ceiling")
        if hashlib.sha256(unsigned_bytes).hexdigest() != self.unsigned_record_sha256:
            raise ValueError("unsigned record digest does not reproduce")
        if (
            hashlib.sha256(canonical_json_bytes(self.prepared_call)).hexdigest()
            != self.prepared_call_sha256
        ):
            raise ValueError("prepared-call evidence digest does not reproduce")
        payload = bytes.fromhex(self.payload_hex.removeprefix("0x"))
        if hashlib.sha256(payload).hexdigest() != self.payload_sha256:
            raise ValueError("payload digest does not reproduce")
        _validate_prepared_call(
            self.operation,
            _restore_unsigned(self.unsigned_record),
            self.prepared_call,
        )

        if state is ExtrinsicState.PREPARED:
            if any(
                value is not None
                for value in (
                    self.signature_hex,
                    self.signature_sha256,
                    self.expected_signed_extrinsic_hash,
                    self.submitted_extrinsic_hash,
                    self.submission,
                    self.submission_sha256,
                    self.reconciliation,
                    self.reconciliation_sha256,
                    self.reason_code,
                )
            ):
                raise ValueError("prepared receipt carries post-prepare fields")
            return self

        if self.signature_hex is None or self.signature_sha256 is None:
            raise ValueError("a post-prepare receipt requires the exact signature")
        signature = bytes.fromhex(self.signature_hex.removeprefix("0x"))
        if len(signature) not in {64, MAX_SIGNATURE_BYTES}:
            raise ValueError("signature must be the SDK's 64- or 65-byte form")
        if hashlib.sha256(signature).hexdigest() != self.signature_sha256:
            raise ValueError("signature digest does not reproduce")

        self._validate_evidence_digest(self.submission, self.submission_sha256, "submission")
        self._validate_evidence_digest(
            self.reconciliation,
            self.reconciliation_sha256,
            "reconciliation",
        )
        if self.submission is not None:
            _validate_evidence_binding(self, self.submission)
            if self.submitted_extrinsic_hash != self.submission.extrinsic_hash:
                raise ValueError("submission hash is not the persisted submitted hash")
        if self.reconciliation is not None:
            _validate_evidence_binding(self, self.reconciliation)
            if (
                self.reconciliation.extrinsic_hash is not None
                and self.submitted_extrinsic_hash is not None
                and self.reconciliation.extrinsic_hash != self.submitted_extrinsic_hash
            ):
                raise ValueError("reconciliation names another signed extrinsic")
        known_extrinsic_hash = self.submitted_extrinsic_hash or self.expected_signed_extrinsic_hash
        if (
            self.expected_signed_extrinsic_hash is not None
            and self.submitted_extrinsic_hash is not None
            and self.expected_signed_extrinsic_hash != self.submitted_extrinsic_hash
        ):
            raise ValueError("derived and submitted extrinsic hashes disagree")
        if (
            self.reconciliation is not None
            and known_extrinsic_hash is not None
            and self.reconciliation.extrinsic_hash != known_extrinsic_hash
        ):
            raise ValueError("reconciliation is not bound to the known extrinsic hash")

        if state is ExtrinsicState.SUBMITTED:
            if (
                self.submission is None
                or self.reconciliation is not None
                or self.reason_code is not None
            ):
                raise ValueError("submitted receipt requires submission evidence only")
        elif state in {
            ExtrinsicState.FINALIZED_SUCCESS,
            ExtrinsicState.FINALIZED_FAILURE,
        }:
            required = ReconcileOutcome(state.value)
            if (
                self.reconciliation is None
                or ReconcileOutcome(self.reconciliation.outcome) is not required
                or self.submission is not None
                or self.reason_code is not None
                or self.submitted_extrinsic_hash != self.reconciliation.extrinsic_hash
            ):
                raise ValueError("finalized receipt requires matching reconciliation evidence")
        elif state is ExtrinsicState.EXPIRED:
            if (
                self.reconciliation is None
                or self.reconciliation.outcome != ReconcileOutcome.NOT_FOUND.value
                or self.reconciliation.finalized_head_block < self.era_death_block
                or self.submission is not None
                or self.reason_code != "mortal_era_expired"
            ):
                raise ValueError("expired receipt requires a post-era not-found scan")
        elif state is ExtrinsicState.UNKNOWN:
            if self.submission is not None:
                raise ValueError("unknown receipt cannot claim a completed submission")
            if self.reason_code not in {"reconcile_outcome_unknown", "submit_outcome_unknown"}:
                raise ValueError("unknown receipt requires its canonical reason code")
            if (
                self.reason_code == "reconcile_outcome_unknown"
                and self.reconciliation is not None
                and self.reconciliation.outcome != ReconcileOutcome.UNKNOWN.value
            ):
                raise ValueError("unknown reconciliation receipt has a definitive outcome")
        elif state is ExtrinsicState.SIGNED:
            if self.submission is not None or self.reason_code is not None:
                raise ValueError("signed receipt cannot carry submission or a reason code")
            if (
                self.reconciliation is not None
                and self.reconciliation.outcome != ReconcileOutcome.NOT_FOUND.value
            ):
                raise ValueError("pre-submit reconciliation must be a definitive not-found scan")
        return self

    @staticmethod
    def _validate_evidence_digest(
        evidence: StrictProtocolModel | None,
        digest: str | None,
        label: str,
    ) -> None:
        if (evidence is None) != (digest is None):
            raise ValueError(f"{label} and its digest must appear together")
        if (
            evidence is not None
            and digest != hashlib.sha256(canonical_json_bytes(evidence)).hexdigest()
        ):
            raise ValueError(f"{label} evidence digest does not reproduce")


@dataclass(frozen=True, slots=True)
class ReconcileQuery:
    operation: ExtrinsicOperation
    unsigned: UnsignedExtrinsic
    signature: bytes
    expected_extrinsic_hash: str | None
    era_birth_block: int
    era_death_block: int


@dataclass(frozen=True, slots=True)
class JournalEntry:
    receipt: ExtrinsicReceipt
    receipt_sha256: str
    path: Path

    @property
    def state(self) -> ExtrinsicState:
        return ExtrinsicState(self.receipt.state)

    @property
    def unsigned(self) -> UnsignedExtrinsic:
        return _restore_unsigned(self.receipt.unsigned_record)

    @property
    def signature(self) -> bytes | None:
        if self.receipt.signature_hex is None:
            return None
        return bytes.fromhex(self.receipt.signature_hex.removeprefix("0x"))


class PreparePort(Protocol):
    def __call__(
        self,
        operation: ExtrinsicOperation,
    ) -> UnsignedExtrinsic | Awaitable[UnsignedExtrinsic]: ...


class VerifyPreparedCallPort(Protocol):
    def __call__(
        self,
        operation: ExtrinsicOperation,
        unsigned: UnsignedExtrinsic,
    ) -> PreparedCallEvidence | Awaitable[PreparedCallEvidence]: ...


class SignPort(Protocol):
    def __call__(self, payload: bytes, operation_id: str) -> bytes | Awaitable[bytes]: ...


class SubmitPort(Protocol):
    def __call__(
        self,
        unsigned: UnsignedExtrinsic,
        signature: bytes,
    ) -> SubmissionEvidence | Awaitable[SubmissionEvidence]: ...


class ReconcilePort(Protocol):
    def __call__(
        self,
        query: ReconcileQuery,
    ) -> ReconciliationEvidence | Awaitable[ReconciliationEvidence]: ...


class SignedHashPort(Protocol):
    def __call__(
        self,
        unsigned: UnsignedExtrinsic,
        signature: bytes,
    ) -> str | Awaitable[str]: ...


@dataclass(frozen=True, slots=True)
class ExtrinsicPorts:
    prepare: PreparePort
    verify_prepared_call: VerifyPreparedCallPort
    sign: SignPort
    submit: SubmitPort
    reconcile: ReconcilePort
    derive_signed_hash: SignedHashPort | None = None

    def __post_init__(self) -> None:
        for name in (
            "prepare",
            "verify_prepared_call",
            "sign",
            "submit",
            "reconcile",
        ):
            if not callable(getattr(self, name)):
                raise TypeError(f"{name} port must be callable")
        if self.derive_signed_hash is not None and not callable(self.derive_signed_hash):
            raise TypeError("derive_signed_hash port must be callable or None")


CrashHook = Callable[[str], None]
T = TypeVar("T")


class ValidatorExtrinsicJournal:
    """Durable state machine around externally signed validator extrinsics."""

    def __init__(
        self,
        root: str | Path,
        *,
        maximum_receipt_bytes: int = MAX_RECEIPT_BYTES,
        maximum_receipts_per_operation: int = MAX_RECEIPTS_PER_OPERATION,
        maximum_operations: int = MAX_OPERATIONS,
        port_timeout_seconds: float = DEFAULT_PORT_TIMEOUT_SECONDS,
        crash_hook: CrashHook | None = None,
    ) -> None:
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value <= 0
            for value in (
                maximum_receipt_bytes,
                maximum_receipts_per_operation,
                maximum_operations,
            )
        ):
            raise ValueError("journal ceilings must be positive integers")
        if maximum_receipt_bytes > MAX_RECEIPT_BYTES:
            raise ValueError("receipt ceiling cannot exceed the protocol hard maximum")
        if maximum_receipts_per_operation > MAX_RECEIPTS_PER_OPERATION:
            raise ValueError("receipt-count ceiling cannot exceed the protocol hard maximum")
        if maximum_operations > MAX_OPERATIONS:
            raise ValueError("operation-count ceiling cannot exceed the protocol hard maximum")
        if (
            isinstance(port_timeout_seconds, bool)
            or not isinstance(port_timeout_seconds, (int, float))
            or not 0 < port_timeout_seconds <= MAX_PORT_TIMEOUT_SECONDS
        ):
            raise ValueError("port timeout must be positive and no greater than the hard maximum")
        self.root = Path(root)
        self.operations = self.root / "operations"
        self.lock_path = self.root / ".lock"
        self.maximum_receipt_bytes = maximum_receipt_bytes
        self.maximum_receipts_per_operation = maximum_receipts_per_operation
        self.maximum_operations = maximum_operations
        self.port_timeout_seconds = float(port_timeout_seconds)
        self.crash_hook = crash_hook
        self._async_lock = asyncio.Lock()
        _ensure_directory(self.root)
        _ensure_directory(self.operations)
        with self._locked():
            self._audit_all_unlocked()

    async def advance(
        self,
        operation: ExtrinsicOperation,
        ports: ExtrinsicPorts,
        *,
        expected_operation_id: str | None = None,
    ) -> JournalEntry:
        """Serialize same-process callers before taking the cross-process lock.

        Injected ports run while both locks are held and therefore must have a
        bounded deadline.  This preserves prepare/sign/submit exclusivity
        across processes without letting a second coroutine synchronously
        block the event loop in ``flock``.
        """

        async with self._async_lock:
            return await self._advance_serialized(
                operation,
                ports,
                expected_operation_id=expected_operation_id,
            )

    async def _advance_serialized(
        self,
        operation: ExtrinsicOperation,
        ports: ExtrinsicPorts,
        *,
        expected_operation_id: str | None,
    ) -> JournalEntry:
        """Advance at most one durable lifecycle action.

        Preparing and signing each consume one call.  A later call reconciles,
        durably records that scan, and (only for a definitive live-era
        ``not_found`` result) submits the exact persisted bytes.  Submission is
        never itself treated as finalization.
        """

        if not isinstance(operation, ExtrinsicOperation):
            raise TypeError("operation must be an ExtrinsicOperation")
        if not isinstance(ports, ExtrinsicPorts):
            raise TypeError("ports must be ExtrinsicPorts")
        operation_id = operation.operation_id
        if expected_operation_id is not None and expected_operation_id != operation_id:
            raise ExtrinsicJournalConflict("expected operation ID does not match request bytes")

        with self._locked():
            entries = self._load_entries_unlocked(operation_id)
            if entries:
                self._assert_operation(entries[-1].receipt, operation)
            else:
                unsigned = await self._call_port("prepare", ports.prepare, operation)
                if not isinstance(unsigned, UnsignedExtrinsic):
                    raise ExtrinsicJournalError("prepare port did not return UnsignedExtrinsic")
                if unsigned.address != operation.validator_hotkey:
                    raise ExtrinsicJournalConflict(
                        "prepared unsigned record is bound to another validator"
                    )
                prepared_call = await self._call_port(
                    "verify_prepared_call",
                    ports.verify_prepared_call,
                    operation,
                    unsigned,
                )
                if not isinstance(prepared_call, PreparedCallEvidence):
                    raise ExtrinsicJournalError(
                        "prepared-call verifier did not return PreparedCallEvidence"
                    )
                _validate_prepared_call(operation, unsigned, prepared_call)
                material = _unsigned_material(unsigned)
                entry = self._append_unlocked(
                    _new_receipt(
                        operation=operation,
                        sequence=0,
                        previous=None,
                        state=ExtrinsicState.PREPARED,
                        material=material,
                        prepared_call=prepared_call,
                    )
                )
                self._crash("after_prepared_receipt")
                return entry

            latest = entries[-1]
            if latest.state in {
                ExtrinsicState.FINALIZED_SUCCESS,
                ExtrinsicState.FINALIZED_FAILURE,
                ExtrinsicState.EXPIRED,
            }:
                return latest

            if latest.state is ExtrinsicState.PREPARED:
                return await self._sign_unlocked(operation, latest, ports)
            return await self._reconcile_and_maybe_submit_unlocked(operation, latest, ports)

    async def _call_port(
        self,
        name: str,
        port: Callable[..., T | Awaitable[T]],
        *args: object,
    ) -> T:
        """Invoke one injected capability under a total wall-clock deadline.

        Native coroutine ports run on this event loop.  Synchronous adapters run
        in a worker thread so a stuck SDK call cannot freeze every validator
        coroutine while the cross-process journal lock is held.  A timed-out
        submission remains ambiguous and is durably classified by the caller;
        it is never retried merely because the transport did not return.
        """

        async def invoke() -> T:
            call_method = type(port).__call__
            if inspect.iscoroutinefunction(port) or inspect.iscoroutinefunction(call_method):
                return await _await_port(port(*args))
            value = await asyncio.to_thread(port, *args)
            return await _await_port(value)

        try:
            return await asyncio.wait_for(invoke(), timeout=self.port_timeout_seconds)
        except TimeoutError as error:
            raise ExtrinsicPortTimeout(f"{name} port exceeded its hard deadline") from error

    def load(self, operation: ExtrinsicOperation) -> JournalEntry | None:
        if not isinstance(operation, ExtrinsicOperation):
            raise TypeError("operation must be an ExtrinsicOperation")
        with self._locked():
            entries = self._load_entries_unlocked(operation.operation_id)
            if not entries:
                return None
            self._assert_operation(entries[-1].receipt, operation)
            return entries[-1]

    def history(self, operation: ExtrinsicOperation) -> tuple[JournalEntry, ...]:
        if not isinstance(operation, ExtrinsicOperation):
            raise TypeError("operation must be an ExtrinsicOperation")
        with self._locked():
            entries = self._load_entries_unlocked(operation.operation_id)
            if entries:
                self._assert_operation(entries[-1].receipt, operation)
            return entries

    async def _sign_unlocked(
        self,
        operation: ExtrinsicOperation,
        latest: JournalEntry,
        ports: ExtrinsicPorts,
    ) -> JournalEntry:
        unsigned = latest.unsigned
        # This is the exact SDK contract: never sign payload_json or reconstructed call bytes.
        signature = await self._call_port(
            "sign",
            ports.sign,
            bytes(unsigned.payload),
            operation.operation_id,
        )
        if not isinstance(signature, bytes) or len(signature) not in {64, MAX_SIGNATURE_BYTES}:
            raise ExtrinsicJournalError("sign port must return the exact 64- or 65-byte signature")
        if len(signature) == MAX_SIGNATURE_BYTES and signature[0] != unsigned.crypto_type:
            raise ExtrinsicJournalConflict(
                "versioned signature scheme differs from the prepared unsigned record"
            )
        expected_hash: str | None = None
        if ports.derive_signed_hash is not None:
            expected_hash = await self._call_port(
                "derive_signed_hash",
                ports.derive_signed_hash,
                unsigned,
                signature,
            )
            _chain_hash(expected_hash, "derived signed extrinsic hash")
        entry = self._append_successor_unlocked(
            latest,
            state=ExtrinsicState.SIGNED,
            signature=signature,
            expected_signed_extrinsic_hash=expected_hash,
        )
        self._crash("after_signed_receipt")
        return entry

    async def _reconcile_and_maybe_submit_unlocked(
        self,
        operation: ExtrinsicOperation,
        latest: JournalEntry,
        ports: ExtrinsicPorts,
    ) -> JournalEntry:
        signature = latest.signature
        if signature is None:
            raise ExtrinsicJournalConflict("post-prepare state lost its signature")
        unsigned = latest.unsigned
        query = ReconcileQuery(
            operation=operation,
            unsigned=unsigned,
            signature=signature,
            expected_extrinsic_hash=(
                latest.receipt.submitted_extrinsic_hash
                or latest.receipt.expected_signed_extrinsic_hash
            ),
            era_birth_block=latest.receipt.era_birth_block,
            era_death_block=latest.receipt.era_death_block,
        )
        try:
            reconciliation = await self._call_port("reconcile", ports.reconcile, query)
        except ExtrinsicJournalError:
            raise
        except Exception:
            if (
                latest.state is ExtrinsicState.UNKNOWN
                and latest.receipt.reason_code == "reconcile_outcome_unknown"
            ):
                return latest
            entry = self._append_successor_unlocked(
                latest,
                state=ExtrinsicState.UNKNOWN,
                reason_code="reconcile_outcome_unknown",
            )
            self._crash("after_unknown_receipt")
            return entry
        if not isinstance(reconciliation, ReconciliationEvidence):
            raise ExtrinsicJournalError("reconcile port did not return ReconciliationEvidence")
        self._validate_reconciliation(latest.receipt, reconciliation)
        outcome = ReconcileOutcome(reconciliation.outcome)
        submitted_hash = (
            latest.receipt.submitted_extrinsic_hash
            or latest.receipt.expected_signed_extrinsic_hash
            or reconciliation.extrinsic_hash
        )

        if outcome in {
            ReconcileOutcome.FINALIZED_SUCCESS,
            ReconcileOutcome.FINALIZED_FAILURE,
        }:
            state = ExtrinsicState(outcome.value)
            entry = self._append_successor_unlocked(
                latest,
                state=state,
                reconciliation=reconciliation,
                submitted_extrinsic_hash=submitted_hash,
            )
            self._crash("after_terminal_receipt")
            return entry
        if outcome is ReconcileOutcome.UNKNOWN:
            if latest.state is ExtrinsicState.UNKNOWN:
                return latest
            entry = self._append_successor_unlocked(
                latest,
                state=ExtrinsicState.UNKNOWN,
                reconciliation=reconciliation,
                submitted_extrinsic_hash=submitted_hash,
                reason_code="reconcile_outcome_unknown",
            )
            self._crash("after_unknown_receipt")
            return entry
        if reconciliation.finalized_head_block >= latest.receipt.era_death_block:
            entry = self._append_successor_unlocked(
                latest,
                state=ExtrinsicState.EXPIRED,
                reconciliation=reconciliation,
                submitted_extrinsic_hash=submitted_hash,
                reason_code="mortal_era_expired",
            )
            self._crash("after_terminal_receipt")
            return entry

        history = self._load_entries_unlocked(operation.operation_id)
        crossed_submit_boundary = any(
            entry.receipt.submission is not None
            or entry.receipt.reason_code == "submit_outcome_unknown"
            for entry in history
        )
        if crossed_submit_boundary:
            # Once the exact signed extrinsic has crossed the submit boundary,
            # a live-era not-found poll is only a pending observation.  Do not
            # create an unbounded receipt chain or rebroadcast on every head;
            # a later full-era reconciliation proves finalization or expiry.
            return latest

        # Persist the definitive not-found scan before crossing the network boundary.
        reconciled = self._append_successor_unlocked(
            latest,
            state=ExtrinsicState.SIGNED,
            reconciliation=reconciliation,
            submitted_extrinsic_hash=submitted_hash,
        )
        self._crash("after_reconciliation_receipt")
        exact_unsigned = reconciled.unsigned
        exact_signature = reconciled.signature
        if exact_signature is None:
            raise ExtrinsicJournalConflict("reconciled state lost its signature")
        try:
            submission = await self._call_port(
                "submit",
                ports.submit,
                exact_unsigned,
                exact_signature,
            )
        except ExtrinsicPortTimeout:
            entry = self._append_successor_unlocked(
                reconciled,
                state=ExtrinsicState.UNKNOWN,
                reason_code="submit_outcome_unknown",
            )
            self._crash("after_unknown_receipt")
            return entry
        except ExtrinsicJournalError:
            raise
        except Exception:
            entry = self._append_successor_unlocked(
                reconciled,
                state=ExtrinsicState.UNKNOWN,
                reason_code="submit_outcome_unknown",
            )
            self._crash("after_unknown_receipt")
            return entry
        self._crash("after_submit_return_before_receipt")
        if not isinstance(submission, SubmissionEvidence):
            raise ExtrinsicJournalError("submit port did not return SubmissionEvidence")
        self._validate_submission(reconciled.receipt, submission)
        entry = self._append_successor_unlocked(
            reconciled,
            state=ExtrinsicState.SUBMITTED,
            submission=submission,
            submitted_extrinsic_hash=submission.extrinsic_hash,
        )
        self._crash("after_submitted_receipt")
        return entry

    def _validate_reconciliation(
        self,
        receipt: ExtrinsicReceipt,
        evidence: ReconciliationEvidence,
    ) -> None:
        _validate_evidence_binding(receipt, evidence)
        if evidence.finalized_head_block < receipt.era_birth_block:
            raise ExtrinsicJournalConflict("reconciliation predates the mortal era")
        expected_scan_end = min(
            evidence.finalized_head_block,
            receipt.era_death_block - 1,
        )
        if (
            evidence.scan_start_block != receipt.era_birth_block
            or evidence.scan_end_block != expected_scan_end
        ):
            raise ExtrinsicJournalConflict(
                "reconciliation does not cover the complete finalized mortal era"
            )
        prior_reconciliations = [
            entry.receipt.reconciliation
            for entry in self._load_entries_unlocked(receipt.operation_id)
            if entry.receipt.reconciliation is not None
        ]
        if prior_reconciliations:
            prior = prior_reconciliations[-1]
            if evidence.finalized_head_block < prior.finalized_head_block:
                raise ExtrinsicJournalConflict("finalized reconciliation head regresses")
            if (
                evidence.finalized_head_block == prior.finalized_head_block
                and evidence.finalized_head_hash != prior.finalized_head_hash
            ):
                raise ExtrinsicJournalConflict("one finalized height has conflicting block hashes")
        known_hash = receipt.submitted_extrinsic_hash or receipt.expected_signed_extrinsic_hash
        if known_hash is not None and evidence.extrinsic_hash != known_hash:
            raise ExtrinsicJournalConflict("reconciliation does not bind the signed extrinsic")
        if (
            known_hash is None
            and evidence.outcome
            in {
                ReconcileOutcome.FINALIZED_SUCCESS.value,
                ReconcileOutcome.FINALIZED_FAILURE.value,
            }
            and evidence.extrinsic_hash is None
        ):
            raise ExtrinsicJournalConflict("finalized evidence omitted the signed extrinsic hash")
        if evidence.inclusion_block is not None and not (
            receipt.era_birth_block <= evidence.inclusion_block < receipt.era_death_block
        ):
            raise ExtrinsicJournalConflict("reconciled inclusion is outside the mortal era")

    def _validate_submission(
        self,
        receipt: ExtrinsicReceipt,
        evidence: SubmissionEvidence,
    ) -> None:
        _validate_evidence_binding(receipt, evidence)
        known_hash = receipt.submitted_extrinsic_hash or receipt.expected_signed_extrinsic_hash
        if known_hash is not None and evidence.extrinsic_hash != known_hash:
            raise ExtrinsicJournalConflict("submit result names another signed extrinsic")

    def _append_successor_unlocked(
        self,
        latest: JournalEntry,
        *,
        state: ExtrinsicState,
        signature: bytes | None = None,
        expected_signed_extrinsic_hash: str | None = None,
        submitted_extrinsic_hash: str | None = None,
        submission: SubmissionEvidence | None = None,
        reconciliation: ReconciliationEvidence | None = None,
        reason_code: str | None = None,
    ) -> JournalEntry:
        previous = latest.receipt
        inherited_signature = signature if signature is not None else latest.signature
        receipt = _new_receipt(
            operation=previous.operation,
            sequence=previous.sequence + 1,
            previous=latest.receipt_sha256,
            state=state,
            material=_material_from_receipt(previous),
            prepared_call=previous.prepared_call,
            signature=inherited_signature,
            expected_signed_extrinsic_hash=(
                expected_signed_extrinsic_hash
                if expected_signed_extrinsic_hash is not None
                else previous.expected_signed_extrinsic_hash
            ),
            submitted_extrinsic_hash=(
                submitted_extrinsic_hash
                if submitted_extrinsic_hash is not None
                else previous.submitted_extrinsic_hash
            ),
            submission=submission,
            reconciliation=reconciliation,
            reason_code=reason_code,
        )
        return self._append_unlocked(receipt)

    def _append_unlocked(self, receipt: ExtrinsicReceipt) -> JournalEntry:
        operation_dir = self.operations / receipt.operation_id
        if not os.path.lexists(operation_dir):
            if len(tuple(self.operations.iterdir())) >= self.maximum_operations:
                raise ExtrinsicJournalError("journal operation-count ceiling reached")
            operation_dir.mkdir(mode=0o700)
            _fsync_directory(self.operations)
        _require_real_directory(operation_dir, "operation receipt directory")
        existing = self._load_entries_unlocked(receipt.operation_id)
        if len(existing) >= self.maximum_receipts_per_operation:
            raise ExtrinsicJournalError("operation receipt-count ceiling reached")
        if receipt.sequence != len(existing):
            raise ExtrinsicJournalConflict("receipt sequence conflicts with journal history")
        if existing and receipt.previous_receipt_sha256 != existing[-1].receipt_sha256:
            raise ExtrinsicJournalConflict("receipt predecessor conflicts with journal history")
        if not existing and receipt.previous_receipt_sha256 is not None:
            raise ExtrinsicJournalConflict("first receipt unexpectedly has a predecessor")
        encoded = canonical_json_bytes(receipt)
        if len(encoded) > self.maximum_receipt_bytes:
            raise ExtrinsicJournalError("extrinsic receipt exceeds its byte ceiling")
        digest = hashlib.sha256(encoded).hexdigest()
        path = operation_dir / f"{digest}.json"
        if os.path.lexists(path):
            if _read_bounded_regular_file(path, self.maximum_receipt_bytes) != encoded:
                raise ExtrinsicJournalConflict("receipt digest path contains different bytes")
        else:
            _write_content_addressed(path, encoded, digest)
        entries = self._load_entries_unlocked(receipt.operation_id)
        if not entries or entries[-1].receipt_sha256 != digest:
            raise ExtrinsicJournalConflict("new receipt did not become the unique chain head")
        return entries[-1]

    def _load_entries_unlocked(self, operation_id: str) -> tuple[JournalEntry, ...]:
        _hex32(operation_id, "operation ID")
        operation_dir = self.operations / operation_id
        if not os.path.lexists(operation_dir):
            return ()
        _require_real_directory(operation_dir, "operation receipt directory")
        self._recover_pending_unlocked(operation_dir)
        paths = tuple(operation_dir.iterdir())
        if len(paths) > self.maximum_receipts_per_operation:
            raise ExtrinsicJournalError("operation exceeds its receipt-count ceiling")
        by_sequence: dict[int, JournalEntry] = {}
        for path in paths:
            match = _RECEIPT_NAME_RE.fullmatch(path.name)
            if match is None:
                raise ExtrinsicJournalError("operation directory contains an unknown file")
            encoded = _read_bounded_regular_file(path, self.maximum_receipt_bytes)
            digest = hashlib.sha256(encoded).hexdigest()
            if digest != match.group(1):
                raise ExtrinsicJournalError("receipt filename does not match its content")
            try:
                decoded = json.loads(encoded)
                receipt = ExtrinsicReceipt.model_validate(decoded)
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
                raise ExtrinsicJournalError("extrinsic receipt is invalid") from error
            if canonical_json_bytes(receipt) != encoded:
                raise ExtrinsicJournalError("extrinsic receipt is not exact canonical JSON")
            if receipt.operation_id != operation_id:
                raise ExtrinsicJournalConflict("receipt directory and operation ID disagree")
            if receipt.sequence in by_sequence:
                raise ExtrinsicJournalConflict("operation receipt history forks")
            by_sequence[receipt.sequence] = JournalEntry(receipt, digest, path)
        if set(by_sequence) != set(range(len(by_sequence))):
            raise ExtrinsicJournalConflict("operation receipt sequence is not contiguous")
        entries = tuple(by_sequence[index] for index in range(len(by_sequence)))
        self._validate_history(entries)
        return entries

    def _validate_history(self, entries: tuple[JournalEntry, ...]) -> None:
        if not entries:
            return
        first = entries[0].receipt
        operation_bytes = canonical_json_bytes(first.operation)
        unsigned_bytes = canonical_json_bytes(first.unsigned_record)
        prepared_call_bytes = canonical_json_bytes(first.prepared_call)
        payload_hex = first.payload_hex
        expected_signature_hex: str | None = None
        expected_hash: str | None = None
        submitted_hash: str | None = None
        last_finalized_head: int | None = None
        finalized_hashes: dict[int, str] = {}
        terminal_seen = False
        for index, entry in enumerate(entries):
            receipt = entry.receipt
            if receipt.sequence != index:
                raise ExtrinsicJournalConflict("receipt sequence does not match chain position")
            expected_previous = None if index == 0 else entries[index - 1].receipt_sha256
            if receipt.previous_receipt_sha256 != expected_previous:
                raise ExtrinsicJournalConflict("receipt predecessor chain is broken")
            if terminal_seen:
                raise ExtrinsicJournalConflict("terminal receipt has a successor")
            if canonical_json_bytes(receipt.operation) != operation_bytes:
                raise ExtrinsicJournalConflict("operation request changes within its history")
            if canonical_json_bytes(receipt.unsigned_record) != unsigned_bytes:
                raise ExtrinsicJournalConflict("unsigned record changes within its history")
            if canonical_json_bytes(receipt.prepared_call) != prepared_call_bytes:
                raise ExtrinsicJournalConflict("prepared-call evidence changes within its history")
            if receipt.payload_hex != payload_hex:
                raise ExtrinsicJournalConflict("signing payload changes within its history")
            _validate_unsigned_against_receipt(receipt)
            if receipt.signature_hex is not None:
                if expected_signature_hex is None:
                    expected_signature_hex = receipt.signature_hex
                elif receipt.signature_hex != expected_signature_hex:
                    raise ExtrinsicJournalConflict("signature changes within its history")
            elif expected_signature_hex is not None:
                raise ExtrinsicJournalConflict("signature disappears within its history")
            if receipt.expected_signed_extrinsic_hash is not None:
                if expected_hash is None:
                    expected_hash = receipt.expected_signed_extrinsic_hash
                elif receipt.expected_signed_extrinsic_hash != expected_hash:
                    raise ExtrinsicJournalConflict("expected extrinsic hash changes")
            elif expected_hash is not None:
                raise ExtrinsicJournalConflict("expected extrinsic hash disappears")
            if receipt.submitted_extrinsic_hash is not None:
                if submitted_hash is None:
                    submitted_hash = receipt.submitted_extrinsic_hash
                elif receipt.submitted_extrinsic_hash != submitted_hash:
                    raise ExtrinsicJournalConflict("submitted extrinsic hash changes")
            elif submitted_hash is not None:
                raise ExtrinsicJournalConflict("submitted extrinsic hash disappears")
            if (
                expected_hash is not None
                and submitted_hash is not None
                and expected_hash != submitted_hash
            ):
                raise ExtrinsicJournalConflict("derived and submitted extrinsic hashes disagree")
            state = ExtrinsicState(receipt.state)
            if receipt.reconciliation is not None:
                head = receipt.reconciliation.finalized_head_block
                head_hash = receipt.reconciliation.finalized_head_hash
                if last_finalized_head is not None and head < last_finalized_head:
                    raise ExtrinsicJournalConflict("finalized reconciliation head regresses")
                previous_hash = finalized_hashes.setdefault(head, head_hash)
                if previous_hash != head_hash:
                    raise ExtrinsicJournalConflict(
                        "one finalized height has conflicting block hashes"
                    )
                last_finalized_head = head
            if index >= 2:
                previous = entries[index - 1].receipt
                if state is ExtrinsicState.SIGNED:
                    if (
                        receipt.reconciliation is None
                        or receipt.reconciliation.outcome != ReconcileOutcome.NOT_FOUND.value
                        or receipt.reconciliation.finalized_head_block >= receipt.era_death_block
                    ):
                        raise ExtrinsicJournalConflict(
                            "signed successor lacks a live-era not-found reconciliation"
                        )
                elif state is ExtrinsicState.SUBMITTED:
                    if (
                        previous.state != ExtrinsicState.SIGNED.value
                        or previous.reconciliation is None
                        or previous.reconciliation.outcome != ReconcileOutcome.NOT_FOUND.value
                        or previous.reconciliation.finalized_head_block >= previous.era_death_block
                    ):
                        raise ExtrinsicJournalConflict(
                            "submission lacks its durable pre-broadcast reconciliation"
                        )
                elif (
                    state is ExtrinsicState.UNKNOWN
                    and receipt.reason_code == "submit_outcome_unknown"
                    and (
                        previous.state != ExtrinsicState.SIGNED.value
                        or previous.reconciliation is None
                        or previous.reconciliation.outcome != ReconcileOutcome.NOT_FOUND.value
                    )
                ):
                    raise ExtrinsicJournalConflict(
                        "unknown submission lacks its pre-broadcast reconciliation"
                    )
            terminal_seen = state in {
                ExtrinsicState.FINALIZED_SUCCESS,
                ExtrinsicState.FINALIZED_FAILURE,
                ExtrinsicState.EXPIRED,
            }
            if index == 1 and state is not ExtrinsicState.SIGNED:
                raise ExtrinsicJournalConflict("prepared receipt must transition to signed")

    def _recover_pending_unlocked(self, operation_dir: Path) -> None:
        for path in tuple(operation_dir.iterdir()):
            match = _PENDING_NAME_RE.fullmatch(path.name)
            if match is None:
                continue
            encoded = _read_bounded_regular_file(path, self.maximum_receipt_bytes)
            digest = hashlib.sha256(encoded).hexdigest()
            if digest != match.group(1):
                raise ExtrinsicJournalError("pending receipt name does not match its content")
            final = operation_dir / f"{digest}.json"
            try:
                os.link(path, final, follow_symlinks=False)
                _fsync_directory(operation_dir)
            except FileExistsError:
                if _read_bounded_regular_file(final, self.maximum_receipt_bytes) != encoded:
                    raise ExtrinsicJournalConflict(
                        "pending receipt conflicts with final receipt"
                    ) from None
            os.unlink(path)
            _fsync_directory(operation_dir)

    def _audit_all_unlocked(self) -> None:
        children = tuple(self.operations.iterdir())
        if len(children) > self.maximum_operations:
            raise ExtrinsicJournalError("journal exceeds its operation-count ceiling")
        for child in children:
            if _HEX32_RE.fullmatch(child.name) is None:
                raise ExtrinsicJournalError("operations directory contains an invalid entry")
            _require_real_directory(child, "operation receipt directory")
            self._load_entries_unlocked(child.name)

    def _assert_operation(
        self,
        receipt: ExtrinsicReceipt,
        operation: ExtrinsicOperation,
    ) -> None:
        if receipt.operation_id != operation.operation_id or receipt.operation != operation:
            raise ExtrinsicJournalConflict("operation ID is already bound to another request")

    def _crash(self, point: str) -> None:
        if self.crash_hook is not None:
            self.crash_hook(point)

    @contextmanager
    def _locked(self):
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.lock_path, flags, 0o600)
        except OSError as error:
            raise ExtrinsicJournalError("journal lock cannot be opened safely") from error
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise ExtrinsicJournalError("journal lock is not a regular file")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            with suppress(OSError):
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)


@dataclass(frozen=True, slots=True)
class _UnsignedMaterial:
    record: dict[str, JsonValue]
    record_sha256: str
    payload: bytes
    payload_sha256: str
    era_birth_block: int
    era_death_block: int


def _unsigned_material(unsigned: UnsignedExtrinsic) -> _UnsignedMaterial:
    try:
        record = unsigned.to_dict()
        encoded = canonical_json_bytes(record)
    except (TypeError, ValueError) as error:
        raise ExtrinsicJournalError("unsigned SDK record is not canonical JSON") from error
    if len(encoded) > MAX_UNSIGNED_RECORD_BYTES:
        raise ExtrinsicJournalError("unsigned SDK record exceeds its byte ceiling")
    restored = _restore_unsigned(record)
    if restored.to_dict() != record:
        raise ExtrinsicJournalConflict("UnsignedExtrinsic.to_dict/from_dict does not round-trip")
    if not isinstance(restored.payload, bytes) or not 0 < len(restored.payload) <= 256:
        raise ExtrinsicJournalError("unsigned signing payload has an invalid size")
    if not restored.call_data:
        raise ExtrinsicJournalError("unsigned SDK record has empty call data")
    if len(restored.public_key) != 32:
        raise ExtrinsicJournalError("unsigned SDK record has an invalid public key")
    if restored.crypto_type not in {0, 1}:
        raise ExtrinsicJournalError("only SDK ed25519 and sr25519 signatures are supported")
    _chain_hash(restored.genesis_hash, "unsigned genesis hash")
    _chain_hash(restored.era_block_hash, "unsigned era block hash")
    birth, death = mortal_era_bounds(restored)
    return _UnsignedMaterial(
        record=record,
        record_sha256=hashlib.sha256(encoded).hexdigest(),
        payload=bytes(restored.payload),
        payload_sha256=hashlib.sha256(restored.payload).hexdigest(),
        era_birth_block=birth,
        era_death_block=death,
    )


def _material_from_receipt(receipt: ExtrinsicReceipt) -> _UnsignedMaterial:
    return _UnsignedMaterial(
        record=receipt.unsigned_record,
        record_sha256=receipt.unsigned_record_sha256,
        payload=bytes.fromhex(receipt.payload_hex.removeprefix("0x")),
        payload_sha256=receipt.payload_sha256,
        era_birth_block=receipt.era_birth_block,
        era_death_block=receipt.era_death_block,
    )


def mortal_era_bounds(unsigned: UnsignedExtrinsic) -> tuple[int, int]:
    """Return the SDK mortal era's inclusive birth and exclusive death blocks."""

    era = unsigned.era
    if not isinstance(era, Mapping):
        raise ExtrinsicJournalError("validator effects must use a mortal SDK era")
    if "period" not in era or "current" not in era:
        raise ExtrinsicJournalError("mortal SDK era must contain period and current")
    period = era["period"]
    current = era["current"]
    if (
        isinstance(period, bool)
        or not isinstance(period, int)
        or period < 4
        or period > 65_536
        or period & (period - 1)
    ):
        raise ExtrinsicJournalError("mortal SDK era period is invalid")
    if isinstance(current, bool) or not isinstance(current, int) or current < 0:
        raise ExtrinsicJournalError("mortal SDK era current block is invalid")
    quantize = max(period >> 12, 1)
    phase = (current % period) // quantize * quantize
    birth = current - ((current - phase) % period)
    return birth, birth + period


def _new_receipt(
    *,
    operation: ExtrinsicOperation,
    sequence: int,
    previous: str | None,
    state: ExtrinsicState,
    material: _UnsignedMaterial,
    prepared_call: PreparedCallEvidence,
    signature: bytes | None = None,
    expected_signed_extrinsic_hash: str | None = None,
    submitted_extrinsic_hash: str | None = None,
    submission: SubmissionEvidence | None = None,
    reconciliation: ReconciliationEvidence | None = None,
    reason_code: str | None = None,
) -> ExtrinsicReceipt:
    return ExtrinsicReceipt(
        schema=RECEIPT_SCHEMA,
        protocol=PROTOCOL_VERSION,
        operation_id=operation.operation_id,
        sequence=sequence,
        previous_receipt_sha256=previous,
        state=state.value,
        operation=operation,
        unsigned_record=material.record,
        unsigned_record_sha256=material.record_sha256,
        prepared_call=prepared_call,
        prepared_call_sha256=hashlib.sha256(canonical_json_bytes(prepared_call)).hexdigest(),
        payload_hex="0x" + material.payload.hex(),
        payload_sha256=material.payload_sha256,
        era_birth_block=material.era_birth_block,
        era_death_block=material.era_death_block,
        signature_hex=None if signature is None else "0x" + signature.hex(),
        signature_sha256=None if signature is None else hashlib.sha256(signature).hexdigest(),
        expected_signed_extrinsic_hash=expected_signed_extrinsic_hash,
        submitted_extrinsic_hash=submitted_extrinsic_hash,
        submission=submission,
        submission_sha256=(
            None
            if submission is None
            else hashlib.sha256(canonical_json_bytes(submission)).hexdigest()
        ),
        reconciliation=reconciliation,
        reconciliation_sha256=(
            None
            if reconciliation is None
            else hashlib.sha256(canonical_json_bytes(reconciliation)).hexdigest()
        ),
        reason_code=reason_code,
    )


def _validate_prepared_call(
    operation: ExtrinsicOperation,
    unsigned: UnsignedExtrinsic,
    evidence: PreparedCallEvidence,
) -> None:
    """Bind a pinned-runtime decode to the only calls shadow mode may sign."""

    if evidence.operation_id != operation.operation_id:
        raise ExtrinsicJournalConflict("prepared-call evidence binds another operation")
    call_data = bytes(unsigned.call_data)
    if not call_data:
        raise ExtrinsicJournalConflict("prepared anchor call data is empty")
    if evidence.call_data_size_bytes != len(call_data):
        raise ExtrinsicJournalConflict("prepared-call evidence has another byte length")
    if evidence.call_data_sha256 != hashlib.sha256(call_data).hexdigest():
        raise ExtrinsicJournalConflict("prepared-call evidence binds other call bytes")
    method = unsigned.payload_json.get("method")
    if method != "0x" + call_data.hex():
        raise ExtrinsicJournalConflict(
            "SDK signing payload does not bind the exact prepared call bytes"
        )
    request = operation.request
    if (
        evidence.module != "Commitments"
        or evidence.function != "set_commitment"
        or evidence.netuid != request.netuid
        or evidence.anchor_kind != request.anchor_kind
        or evidence.field_sha256 != request.field.sha256
    ):
        raise ExtrinsicJournalConflict(
            "decoded prepared call disagrees with the closed anchor intent"
        )
    if evidence.runtime_spec_version != unsigned.spec_version:
        raise ExtrinsicJournalConflict("prepared-call runtime spec version disagrees")
    if evidence.transaction_version != unsigned.transaction_version:
        raise ExtrinsicJournalConflict("prepared-call transaction version disagrees")


def _validate_unsigned_against_receipt(receipt: ExtrinsicReceipt) -> None:
    restored = _restore_unsigned(receipt.unsigned_record)
    if restored.to_dict() != receipt.unsigned_record:
        raise ExtrinsicJournalConflict("persisted unsigned SDK record no longer round-trips")
    if "0x" + restored.payload.hex() != receipt.payload_hex:
        raise ExtrinsicJournalConflict("persisted SDK payload differs from signed payload")
    if receipt.signature_hex is not None:
        signature = bytes.fromhex(receipt.signature_hex.removeprefix("0x"))
        if len(signature) == MAX_SIGNATURE_BYTES and signature[0] != restored.crypto_type:
            raise ExtrinsicJournalConflict(
                "persisted versioned signature scheme differs from the unsigned record"
            )
    birth, death = mortal_era_bounds(restored)
    if (birth, death) != (receipt.era_birth_block, receipt.era_death_block):
        raise ExtrinsicJournalConflict("persisted mortal era bounds do not reproduce")
    _validate_prepared_call(receipt.operation, restored, receipt.prepared_call)


def _validate_evidence_binding(
    receipt: ExtrinsicReceipt,
    evidence: SubmissionEvidence | ReconciliationEvidence,
) -> None:
    if evidence.operation_id != receipt.operation_id:
        raise ExtrinsicJournalConflict("chain evidence is bound to another operation")
    if evidence.unsigned_record_sha256 != receipt.unsigned_record_sha256:
        raise ExtrinsicJournalConflict("chain evidence is bound to another unsigned record")
    if evidence.payload_sha256 != receipt.payload_sha256:
        raise ExtrinsicJournalConflict("chain evidence is bound to another payload")
    if evidence.signature_sha256 != receipt.signature_sha256:
        raise ExtrinsicJournalConflict("chain evidence is bound to another signature")


def _restore_unsigned(record: Mapping[str, JsonValue]) -> UnsignedExtrinsic:
    try:
        return UnsignedExtrinsic.from_dict(dict(record))
    except (TypeError, ValueError, KeyError) as error:
        raise ExtrinsicJournalError("persisted unsigned SDK record is invalid") from error


async def _await_port(value: T | Awaitable[T]) -> T:
    if inspect.isawaitable(value):
        return await value
    return value


def _hex32(value: str, label: str) -> str:
    if not isinstance(value, str) or _HEX32_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be lowercase SHA-256 hexadecimal")
    return value


def _chain_hash(value: Any, label: str) -> str:
    if not isinstance(value, str) or _CHAIN_HASH_RE.fullmatch(value) is None:
        raise ExtrinsicJournalError(f"{label} must be a 0x-prefixed 32-byte hash")
    return value


def _ensure_directory(path: Path) -> None:
    try:
        path.mkdir(parents=True, mode=0o700, exist_ok=True)
    except OSError as error:
        raise ExtrinsicJournalError(f"journal directory cannot be created: {path.name}") from error
    _require_real_directory(path, "journal directory")


def _require_real_directory(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ExtrinsicJournalError(f"{label} cannot be inspected") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ExtrinsicJournalError(f"{label} must be a real directory")


def _write_content_addressed(path: Path, data: bytes, digest: str) -> None:
    descriptor: int | None = None
    temporary: str | None = None
    try:
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".pending-{digest}-",
            dir=path.parent,
        )
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(data):
            offset += os.write(descriptor, data[offset:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError:
            if _read_bounded_regular_file(path, MAX_RECEIPT_BYTES) != data:
                raise ExtrinsicJournalConflict("content-addressed receipt path conflicts") from None
        _fsync_directory(path.parent)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary is not None:
            with suppress(FileNotFoundError):
                os.unlink(temporary)
            with suppress(OSError):
                _fsync_directory(path.parent)


def _read_bounded_regular_file(path: Path, maximum_bytes: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ExtrinsicJournalError(f"journal file cannot be opened safely: {path.name}") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum_bytes:
            raise ExtrinsicJournalError("journal file is not a bounded regular file")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(_READ_CHUNK_BYTES, maximum_bytes - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > maximum_bytes:
                raise ExtrinsicJournalError("journal file exceeds its byte ceiling")
            chunks.append(chunk)
        if total != metadata.st_size:
            raise ExtrinsicJournalError("journal file changed while it was read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


__all__ = [
    "ANCHOR_INTENT_SCHEMA",
    "DEFAULT_PORT_TIMEOUT_SECONDS",
    "MAX_OPERATION_REQUEST_BYTES",
    "MAX_RECEIPTS_PER_OPERATION",
    "MAX_RECEIPT_BYTES",
    "MAX_RECONCILIATION_SCAN_BYTES",
    "MAX_UNSIGNED_RECORD_BYTES",
    "OPERATION_SCHEMA",
    "PREPARED_CALL_SCHEMA",
    "RECEIPT_SCHEMA",
    "RECONCILIATION_SCHEMA",
    "SUBMISSION_SCHEMA",
    "AnchorField",
    "AnchorIntent",
    "ExtrinsicJournalConflict",
    "ExtrinsicJournalError",
    "ExtrinsicOperation",
    "ExtrinsicPortTimeout",
    "ExtrinsicPorts",
    "ExtrinsicReceipt",
    "ExtrinsicState",
    "JournalEntry",
    "PreparedCallEvidence",
    "ReconcileOutcome",
    "ReconcileQuery",
    "ReconciliationEvidence",
    "SubmissionEvidence",
    "ValidatorExtrinsicJournal",
    "mortal_era_bounds",
]
