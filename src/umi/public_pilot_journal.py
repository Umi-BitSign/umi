"""Durable, non-feed evidence for one public-endpoint pilot attempt.

The journal exists to make a contacted miner attempt non-repeatable even when the
later drand reveal, scoring, attachment, or publication step fails.  It is not a
component bundle and cannot be used as score, activation, or validator evidence.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator
from typing_extensions import Self

from .audit import EvidenceStore, ObjectRef
from .chain import FinalizedMinerEndpoint
from .config import Limits
from .encoding import account_id32
from .protocol import (
    Hex32,
    NonEmptyText,
    StrictProtocolModel,
    TranslationRequest,
    canonical_json_bytes,
    request_digest,
)
from .public_pilot_campaign import CAMPAIGN_ID, validate_public_pilot_request
from .public_pilot_evidence import SDKFinalizedObservation, validate_public_endpoint_origin
from .validator import PreparedRequestAttempt, QueryOutcome

ATTEMPT_JOURNAL_SCHEMA = "umi-public-endpoint-attempt-journal/1"
QUERY_OUTCOME_SCHEMA = "umi-public-endpoint-attempt-outcome/1"

_CompletedPhase = Literal[
    "attempt_started",
    "outcome_recorded",
    "base_component_complete",
]
_FailureStage = Literal[
    "request_send",
    "reveal_and_scoring",
    "attachment",
    "publication",
]


class JournalObjectReference(StrictProtocolModel):
    sha256: Hex32
    media_type: Literal["application/json", "application/octet-stream"]
    size_bytes: Annotated[int, Field(ge=0, le=4 * 1024 * 1024)]

    def object_ref(self) -> ObjectRef:
        return ObjectRef(self.sha256, self.media_type, self.size_bytes)


class AttemptQueryOutcome(StrictProtocolModel):
    """Bounded pre-reveal outcome material; plaintext is intentionally absent."""

    schema_: Literal[QUERY_OUTCOME_SCHEMA] = Field(alias="schema")
    challenge_id: NonEmptyText
    request_digest: Hex32
    authentication_record: JournalObjectReference
    received_at_unix_ns: NonEmptyText | None
    response_body: JournalObjectReference | None
    response_signature: JournalObjectReference | None
    received_body_prefix: JournalObjectReference | None
    failure_code: NonEmptyText | None
    received_bytes_sha256: Hex32 | None
    response_plaintext_retained: Literal[False] = False

    @field_validator("received_at_unix_ns")
    @classmethod
    def validate_receipt_time(cls, value: str | None) -> str | None:
        if value is not None and (
            not value.isdecimal() or value != str(int(value)) or int(value) < 0
        ):
            raise ValueError("journal response receipt time is not canonical")
        return value

    @model_validator(mode="after")
    def validate_evidence_shape(self) -> Self:
        if self.response_signature is not None and self.response_body is None:
            raise ValueError("journal response signature has no complete response body")
        if self.response_body is not None and self.received_body_prefix is None:
            raise ValueError("journal complete response body has no retained body prefix")
        if self.received_bytes_sha256 is None and self.received_body_prefix is not None:
            raise ValueError("journal retained body prefix has no byte digest")
        return self


class AttemptJournalManifest(StrictProtocolModel):
    """Monotonic state for a durable one-shot attempt journal."""

    schema_: Literal[ATTEMPT_JOURNAL_SCHEMA] = Field(alias="schema")
    evidence_class: Literal["incomplete_public_endpoint_attempt"] = (
        "incomplete_public_endpoint_attempt"
    )
    feed_eligible: Literal[False] = False
    replayable_score: Literal[False] = False
    translation_weights_active: Literal[False] = False
    protocol_conformance: Literal[False] = False
    activation_evidence: Literal[False] = False
    validator_input_eligible: Literal[False] = False
    campaign_id: Literal[CAMPAIGN_ID] = CAMPAIGN_ID
    attempt_count: Literal[1] = 1
    phase: Literal[
        "attempt_started",
        "outcome_recorded",
        "base_component_complete",
        "incomplete",
    ]
    completed_through: _CompletedPhase
    failure_stage: _FailureStage | None
    case_manifest_sha256: Hex32
    coordinator_hotkey: NonEmptyText
    expected_miner_uid: Annotated[int, Field(ge=0, le=65_535)]
    miner_hotkey: NonEmptyText
    validator_permit: Literal[False] = False
    announced_origin: NonEmptyText
    chain_observation: SDKFinalizedObservation
    request_digest: Hex32
    prepared_request: JournalObjectReference
    authentication_record: JournalObjectReference
    query_outcome: JournalObjectReference | None
    base_component_manifest_sha256: Hex32 | None

    @field_validator("coordinator_hotkey", "miner_hotkey")
    @classmethod
    def validate_hotkey(cls, value: str) -> str:
        try:
            account_id32(value)
        except ValueError as error:
            raise ValueError("journal hotkey is not a valid SS58 account") from error
        return value

    @field_validator("announced_origin")
    @classmethod
    def validate_announced_origin(cls, value: str) -> str:
        return validate_public_endpoint_origin(value)

    @model_validator(mode="after")
    def validate_state(self) -> Self:
        phase = self.completed_through if self.phase == "incomplete" else self.phase
        if self.phase == "incomplete":
            if self.failure_stage is None:
                raise ValueError("incomplete journal has no failure stage")
        elif self.failure_stage is not None or self.completed_through != self.phase:
            raise ValueError("active journal phase is inconsistent")
        if phase == "attempt_started":
            if self.query_outcome is not None or self.base_component_manifest_sha256 is not None:
                raise ValueError("attempt-started journal contains later evidence")
        elif phase == "outcome_recorded":
            if self.query_outcome is None or self.base_component_manifest_sha256 is not None:
                raise ValueError("outcome-recorded journal is inconsistent")
        elif self.query_outcome is None or self.base_component_manifest_sha256 is None:
            raise ValueError("base-component-complete journal is inconsistent")
        if account_id32(self.coordinator_hotkey) == account_id32(self.miner_hotkey):
            raise ValueError("journal coordinator and miner must be distinct")
        return self


@dataclass(frozen=True, slots=True)
class VerifiedAttemptJournal:
    root: Path
    manifest: AttemptJournalManifest
    manifest_sha256: str
    request: TranslationRequest
    authentication_record: dict[str, str]
    query_outcome: AttemptQueryOutcome | None


def _reference(reference: ObjectRef) -> JournalObjectReference:
    return JournalObjectReference.model_validate(reference.as_dict())


def _json_string_map(data: bytes, label: str) -> dict[str, str]:
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"journal {label} is not JSON") from error
    if (
        not isinstance(value, dict)
        or not value
        or any(not isinstance(key, str) or not isinstance(item, str) for key, item in value.items())
        or canonical_json_bytes(value) != data
    ):
        raise ValueError(f"journal {label} is not a canonical string map")
    return value


def load_attempt_journal(root: Path) -> VerifiedAttemptJournal:
    """Strictly verify a durable journal without treating it as score evidence."""

    resolved = root.expanduser().resolve(strict=True)
    store = EvidenceStore(resolved)
    raw_manifest, manifest_bytes = store.load_manifest_with_bytes()
    manifest = AttemptJournalManifest.model_validate(raw_manifest)

    request_bytes = store.read(manifest.prepared_request.object_ref())
    try:
        request = TranslationRequest.model_validate_json(request_bytes)
    except ValueError as error:
        raise ValueError("journal prepared request is invalid") from error
    if canonical_json_bytes(request) != request_bytes:
        raise ValueError("journal prepared request is not canonical JSON")
    validate_public_pilot_request(request)
    if request_digest(request) != manifest.request_digest:
        raise ValueError("journal prepared request digest is inconsistent")

    auth_bytes = store.read(manifest.authentication_record.object_ref())
    authentication_record = _json_string_map(auth_bytes, "authentication record")
    from .anchors import VerifiedAuthEvidence

    VerifiedAuthEvidence.from_headers(
        authentication_record,
        request=request,
        expected_validator_hotkey=manifest.coordinator_hotkey,
        expected_miner_hotkey=manifest.miner_hotkey,
    )

    parsed_outcome: AttemptQueryOutcome | None = None
    if manifest.query_outcome is not None:
        outcome_bytes = store.read(manifest.query_outcome.object_ref())
        try:
            parsed_outcome = AttemptQueryOutcome.model_validate_json(outcome_bytes)
        except ValueError as error:
            raise ValueError("journal query outcome is invalid") from error
        if canonical_json_bytes(parsed_outcome) != outcome_bytes:
            raise ValueError("journal query outcome is not canonical JSON")
        if (
            parsed_outcome.challenge_id != request.challenge_id
            or parsed_outcome.request_digest != manifest.request_digest
        ):
            raise ValueError("journal query outcome binds another request")
        outcome_auth = _json_string_map(
            store.read(parsed_outcome.authentication_record.object_ref()),
            "query authentication record",
        )
        if outcome_auth != authentication_record:
            raise ValueError("journal query used different authentication material")
        response_body = (
            None
            if parsed_outcome.response_body is None
            else store.read(parsed_outcome.response_body.object_ref())
        )
        prefix = (
            None
            if parsed_outcome.received_body_prefix is None
            else store.read(parsed_outcome.received_body_prefix.object_ref())
        )
        if response_body is not None and response_body != prefix:
            raise ValueError("journal complete response differs from its retained prefix")
        if prefix is not None and hashlib.sha256(prefix).hexdigest() != (
            parsed_outcome.received_bytes_sha256
        ):
            raise ValueError("journal received-byte digest is inconsistent")
        if parsed_outcome.response_signature is not None:
            signature = _json_string_map(
                store.read(parsed_outcome.response_signature.object_ref()),
                "response signature",
            )
            if set(signature) != {"signature"}:
                raise ValueError("journal response signature record is malformed")

    return VerifiedAttemptJournal(
        root=resolved,
        manifest=manifest,
        manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        request=request,
        authentication_record=authentication_record,
        query_outcome=parsed_outcome,
    )


class PublicPilotAttemptJournal:
    """Create and monotonically advance one fsynced one-shot attempt journal."""

    def __init__(self, root: Path, manifest: AttemptJournalManifest) -> None:
        self.root = root
        self.store = EvidenceStore(root)
        self.manifest = manifest

    @classmethod
    def start(
        cls,
        root: Path,
        *,
        prepared: PreparedRequestAttempt,
        endpoint: FinalizedMinerEndpoint,
        case_manifest_sha256: str,
    ) -> PublicPilotAttemptJournal:
        if root.exists():
            raise FileExistsError("public pilot attempt journal already exists")
        if account_id32(prepared.miner_hotkey) != account_id32(endpoint.hotkey):
            raise ValueError("attempt journal endpoint binds another miner hotkey")
        if endpoint.validator_permit:
            raise ValueError("attempt journal endpoint has a validator permit")
        announced_origin = validate_public_endpoint_origin(endpoint.origin)
        observation = SDKFinalizedObservation.model_validate(
            {
                "observation_class": "sdk_finalized_block_without_storage_proofs",
                "network": endpoint.network,
                "genesis_block_hash": endpoint.genesis_block_hash,
                "block_number": endpoint.finalized_block_number,
                "block_hash": endpoint.finalized_block_hash,
                "block_timestamp_unix_ms": endpoint.finalized_block_timestamp_ms,
                "storage_proofs_verified": False,
            }
        )
        root.mkdir(parents=True, mode=0o700)
        store = EvidenceStore(root)
        request_ref = store.add_bytes(prepared.request_bytes, "application/json")
        authentication_ref = store.add_json(dict(prepared.auth_headers))
        manifest = AttemptJournalManifest.model_validate(
            {
                "schema": ATTEMPT_JOURNAL_SCHEMA,
                "evidence_class": "incomplete_public_endpoint_attempt",
                "feed_eligible": False,
                "replayable_score": False,
                "translation_weights_active": False,
                "protocol_conformance": False,
                "activation_evidence": False,
                "validator_input_eligible": False,
                "campaign_id": CAMPAIGN_ID,
                "attempt_count": 1,
                "phase": "attempt_started",
                "completed_through": "attempt_started",
                "failure_stage": None,
                "case_manifest_sha256": case_manifest_sha256,
                "coordinator_hotkey": prepared.validator_hotkey,
                "expected_miner_uid": endpoint.uid,
                "miner_hotkey": prepared.miner_hotkey,
                "validator_permit": endpoint.validator_permit,
                "announced_origin": announced_origin,
                "chain_observation": observation.model_dump(mode="json"),
                "request_digest": request_digest(prepared.request),
                "prepared_request": request_ref.as_dict(),
                "authentication_record": authentication_ref.as_dict(),
                "query_outcome": None,
                "base_component_manifest_sha256": None,
            }
        )
        store.write_manifest(manifest.model_dump(mode="json", by_alias=True))
        journal = cls(root, manifest)
        journal._verify_current()
        return journal

    def _write(self, manifest: AttemptJournalManifest) -> None:
        self.store.write_manifest(manifest.model_dump(mode="json", by_alias=True))
        self.manifest = manifest
        self._verify_current()

    def _verify_current(self) -> None:
        verified = load_attempt_journal(self.root)
        if verified.manifest != self.manifest:
            raise RuntimeError("attempt journal durable readback did not match")

    def _updated(self, **updates: object) -> AttemptJournalManifest:
        material = self.manifest.model_dump(mode="json", by_alias=True)
        material.update(updates)
        return AttemptJournalManifest.model_validate(material)

    def record_outcome(self, outcome: QueryOutcome, *, limits: Limits) -> None:
        if self.manifest.phase != "attempt_started":
            raise RuntimeError("attempt journal cannot record another query outcome")
        if canonical_json_bytes(outcome.request) != self.store.read(
            self.manifest.prepared_request.object_ref()
        ):
            raise ValueError("query outcome binds another prepared request")
        if outcome.auth_headers != json.loads(
            self.store.read(self.manifest.authentication_record.object_ref())
        ):
            raise ValueError("query outcome used different authentication material")
        if outcome.plaintext_bytes is not None or outcome.plaintext is not None:
            raise ValueError("pre-reveal attempt journal cannot retain response plaintext")
        for label, data in (
            ("response body", outcome.envelope_bytes),
            ("response prefix", outcome.received_body_prefix),
        ):
            if data is not None and len(data) > limits.maximum_response_body_bytes:
                raise ValueError(f"journal {label} exceeds the response-body ceiling")
        if (
            outcome.response_signature is not None
            and len(outcome.response_signature.encode("utf-8")) > limits.maximum_http_header_bytes
        ):
            raise ValueError("journal response signature exceeds the header ceiling")

        authentication_ref = self.store.add_json(outcome.auth_headers)
        response_ref = (
            None
            if outcome.envelope_bytes is None
            else self.store.add_bytes(outcome.envelope_bytes, "application/octet-stream")
        )
        signature_ref = (
            None
            if outcome.response_signature is None
            else self.store.add_json({"signature": outcome.response_signature})
        )
        prefix_ref = (
            None
            if outcome.received_body_prefix is None
            else self.store.add_bytes(outcome.received_body_prefix, "application/octet-stream")
        )
        outcome_record = AttemptQueryOutcome.model_validate(
            {
                "schema": QUERY_OUTCOME_SCHEMA,
                "challenge_id": outcome.request.challenge_id,
                "request_digest": request_digest(outcome.request),
                "authentication_record": authentication_ref.as_dict(),
                "received_at_unix_ns": outcome.received_at_unix_ns,
                "response_body": None if response_ref is None else response_ref.as_dict(),
                "response_signature": (None if signature_ref is None else signature_ref.as_dict()),
                "received_body_prefix": None if prefix_ref is None else prefix_ref.as_dict(),
                "failure_code": outcome.failure_code,
                "received_bytes_sha256": outcome.received_bytes_sha256,
                "response_plaintext_retained": False,
            }
        )
        outcome_ref = self.store.add_json(outcome_record)
        updated = self._updated(
            phase="outcome_recorded",
            completed_through="outcome_recorded",
            query_outcome=_reference(outcome_ref).model_dump(mode="json"),
        )
        self._write(updated)

    def record_base_component(self, manifest_path: Path) -> None:
        if self.manifest.phase != "outcome_recorded":
            raise RuntimeError("attempt journal cannot record a base component yet")
        if manifest_path.name != "manifest.json":
            raise ValueError("base component manifest path is invalid")
        _manifest, manifest_bytes = EvidenceStore(manifest_path.parent).load_manifest_with_bytes()
        updated = self._updated(
            phase="base_component_complete",
            completed_through="base_component_complete",
            base_component_manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        )
        self._write(updated)

    def mark_incomplete(self, failure_stage: _FailureStage) -> None:
        if self.manifest.phase == "incomplete":
            return
        completed = self.manifest.completed_through
        updated = self._updated(
            phase="incomplete",
            completed_through=completed,
            failure_stage=failure_stage,
        )
        self._write(updated)


__all__ = [
    "ATTEMPT_JOURNAL_SCHEMA",
    "QUERY_OUTCOME_SCHEMA",
    "AttemptJournalManifest",
    "AttemptQueryOutcome",
    "PublicPilotAttemptJournal",
    "VerifiedAttemptJournal",
    "load_attempt_journal",
]
