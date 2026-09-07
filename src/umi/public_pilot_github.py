"""Typed coordinator contract for the public-pilot GitHub boundary."""

from __future__ import annotations

import re
import time
from typing import Annotated, Literal, TypeAlias
from urllib.parse import urlsplit

from pydantic import Field, ValidationError, field_validator, model_validator
from typing_extensions import Self

from .encoding import account_id32
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes
from .public_pilot_evidence import validate_public_endpoint_origin
from .public_pilot_github_wire import (
    AUTHORIZATION_SCHEMA,
    MAX_JSON_SAFE_INTEGER,
    RESULT_ENVELOPE_SCHEMA,
    RESULT_PAYLOAD_SCHEMA,
    PublicPilotWireError,
    build_authorization_marker,
    build_authorization_payload,
    build_result_envelope,
    parse_authorization_marker,
    parse_result_envelope,
    validate_authorization_payload,
)

MAX_PUBLIC_PILOT_ARCHIVE_BYTES = 96 * 1024 * 1024

_UTC_TIMESTAMP_RE = re.compile(
    r"^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$"
)


def _timestamp(value: str, field: str) -> str:
    if _UTC_TIMESTAMP_RE.fullmatch(value) is None:
        raise ValueError(f"{field} must be second-precision UTC RFC 3339")
    try:
        time.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise ValueError(f"{field} is not a calendar-valid UTC timestamp") from error
    return value


def _visible_ascii(value: str, field: str) -> str:
    if not value.isascii() or any(
        character.isspace() or not character.isprintable() for character in value
    ):
        raise ValueError(f"{field} must contain visible ASCII without whitespace")
    return value


class PublicPilotGithubAuthorization(StrictProtocolModel):
    """One HMAC-authorized transition emitted by the GitHub boundary."""

    schema_: Literal[AUTHORIZATION_SCHEMA] = Field(alias="schema")
    authorization_id: Hex32
    action: Literal["ready_for_case", "ready_to_issue"]
    repository_id: Annotated[int, Field(ge=1, le=MAX_JSON_SAFE_INTEGER)]
    repository_full_name: Annotated[str, Field(min_length=3, max_length=201)]
    issue_id: Annotated[int, Field(ge=1, le=MAX_JSON_SAFE_INTEGER)]
    issue_node_id: Annotated[str, Field(min_length=1, max_length=256)]
    issue_number: Annotated[int, Field(ge=1, le=MAX_JSON_SAFE_INTEGER)]
    issue_body_sha256: Hex32
    command_comment_id: Annotated[int, Field(ge=1, le=MAX_JSON_SAFE_INTEGER)]
    command_node_id: Annotated[str, Field(min_length=1, max_length=256)]
    command_created_at: Annotated[str, Field(min_length=20, max_length=20)]
    actor_id: Annotated[int, Field(ge=1, le=MAX_JSON_SAFE_INTEGER)]
    actor_login: Annotated[str, Field(min_length=1, max_length=39)]
    command_body_sha256: Hex32
    challenge_nonce: Hex32
    campaign_id: Hex32
    umi_revision: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
    predecessor_authorization_id: Hex32 | None

    @field_validator("issue_node_id", "command_node_id")
    @classmethod
    def validate_node_id(cls, value: str, info: object) -> str:
        field_name = getattr(info, "field_name", "node_id")
        return _visible_ascii(value, field_name)

    @field_validator("command_created_at")
    @classmethod
    def validate_created_at(cls, value: str) -> str:
        return _timestamp(value, "command_created_at")

    @model_validator(mode="after")
    def validate_wire_contract(self) -> Self:
        try:
            validate_authorization_payload(self.model_dump(mode="json", by_alias=True))
        except PublicPilotWireError as error:
            raise ValueError("GitHub authorization violates its wire contract") from error
        return self


class _PublicPilotResultBase(StrictProtocolModel):
    schema_: Literal[RESULT_PAYLOAD_SCHEMA] = Field(alias="schema")
    authorization_id: Hex32
    action: Literal["ready_for_case", "ready_to_issue"]
    repository_id: Annotated[int, Field(ge=1, le=MAX_JSON_SAFE_INTEGER)]
    repository_full_name: Annotated[str, Field(min_length=3, max_length=201)]
    issue_id: Annotated[int, Field(ge=1, le=MAX_JSON_SAFE_INTEGER)]
    issue_node_id: Annotated[str, Field(min_length=1, max_length=256)]
    issue_number: Annotated[int, Field(ge=1, le=MAX_JSON_SAFE_INTEGER)]
    campaign_id: Hex32
    umi_revision: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
    coordinator_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    miner_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    expected_miner_uid: Annotated[int, Field(ge=0, le=65_535)]
    completed_at: Annotated[str, Field(min_length=20, max_length=20)]

    @field_validator("issue_node_id")
    @classmethod
    def validate_issue_node_id(cls, value: str) -> str:
        return _visible_ascii(value, "issue_node_id")

    @field_validator("coordinator_hotkey", "miner_hotkey")
    @classmethod
    def validate_hotkey(cls, value: str) -> str:
        try:
            account_id32(value)
        except ValueError as error:
            raise ValueError("result hotkey is not an AccountId32 SS58 address") from error
        return value

    @field_validator("completed_at")
    @classmethod
    def validate_completed_at(cls, value: str) -> str:
        return _timestamp(value, "completed_at")


class PublicPilotCaseReadyResult(_PublicPilotResultBase):
    """Terminal result of a READY_FOR_CASE authorization."""

    action: Literal["ready_for_case"]
    status: Literal["case_ready"]
    case_manifest_sha256: Hex32
    case_archive_sha256: Hex32
    case_archive_size_bytes: Annotated[int, Field(ge=1, le=MAX_PUBLIC_PILOT_ARCHIVE_BYTES)]
    case_archive_url: Annotated[str, Field(min_length=1, max_length=2_048)]
    expected_origin: Annotated[str, Field(min_length=1, max_length=128)]
    response_close_round: Annotated[int, Field(ge=1, le=MAX_JSON_SAFE_INTEGER)]
    reveal_round: Annotated[int, Field(ge=1, le=MAX_JSON_SAFE_INTEGER)]
    response_close_at: Annotated[str, Field(min_length=20, max_length=20)]
    reveal_at: Annotated[str, Field(min_length=20, max_length=20)]

    @field_validator("expected_origin")
    @classmethod
    def validate_origin(cls, value: str) -> str:
        return validate_public_endpoint_origin(value)

    @field_validator("response_close_at", "reveal_at")
    @classmethod
    def validate_schedule_time(cls, value: str, info: object) -> str:
        field_name = getattr(info, "field_name", "schedule time")
        return _timestamp(value, field_name)

    @model_validator(mode="after")
    def validate_case_result(self) -> Self:
        _require_archive_url(
            self.case_archive_url,
            f"/public-pilot-cases/{self.case_archive_sha256}/sealed-case.tar.gz",
        )
        if self.reveal_round <= self.response_close_round:
            raise ValueError("reveal_round must follow response_close_round")
        if self.reveal_at <= self.response_close_at:
            raise ValueError("reveal_at must follow response_close_at")
        return self


class PublicPilotTerminalResult(_PublicPilotResultBase):
    """Terminal published result of a READY_TO_ISSUE authorization."""

    action: Literal["ready_to_issue"]
    status: Literal["pilot_complete"]
    evidence_manifest_sha256: Hex32
    evidence_archive_sha256: Hex32
    evidence_archive_size_bytes: Annotated[int, Field(ge=1, le=MAX_PUBLIC_PILOT_ARCHIVE_BYTES)]
    evidence_archive_url: Annotated[str, Field(min_length=1, max_length=2_048)]
    outcome_classification: Literal["ok", "signed_error", "failed"]
    failure_code: Annotated[str, Field(pattern=r"^[a-z0-9_]{1,64}$")] | None
    request_digest: Hex32

    @model_validator(mode="after")
    def validate_terminal_result(self) -> Self:
        _require_archive_url(
            self.evidence_archive_url,
            f"/public-pilot-evidence/{self.evidence_archive_sha256}/evidence.tar.gz",
        )
        if self.outcome_classification == "failed" and self.failure_code is None:
            raise ValueError("failed outcome must carry a failure_code")
        return self


class PublicPilotIncompleteResult(_PublicPilotResultBase):
    """Terminal non-feed journal retained after a possible one-shot contact."""

    action: Literal["ready_to_issue"]
    status: Literal["pilot_incomplete"]
    attempt_journal_manifest_sha256: Hex32
    attempt_archive_sha256: Hex32
    attempt_archive_size_bytes: Annotated[int, Field(ge=1, le=MAX_PUBLIC_PILOT_ARCHIVE_BYTES)]
    attempt_archive_url: Annotated[str, Field(min_length=1, max_length=2_048)]
    completed_through: Literal[
        "attempt_started",
        "outcome_recorded",
        "base_component_complete",
    ]
    failure_stage: Literal[
        "request_send",
        "reveal_and_scoring",
        "attachment",
        "publication",
    ]
    failure_code: Annotated[str, Field(pattern=r"^[a-z0-9_]{1,64}$")]
    request_digest: Hex32

    @model_validator(mode="after")
    def validate_incomplete_result(self) -> Self:
        _require_archive_url(
            self.attempt_archive_url,
            f"/public-pilot-attempts/{self.attempt_archive_sha256}/attempt-journal.tar.gz",
        )
        return self


PublicPilotAutomationResult: TypeAlias = (
    PublicPilotCaseReadyResult | PublicPilotTerminalResult | PublicPilotIncompleteResult
)


class PublicPilotAutomationResultEnvelope(StrictProtocolModel):
    """A parsed canonical result envelope and its authenticated payload."""

    schema_: Literal[RESULT_ENVELOPE_SCHEMA] = Field(alias="schema")
    payload: PublicPilotCaseReadyResult | PublicPilotTerminalResult | PublicPilotIncompleteResult
    hmac_sha256: Hex32


def create_public_pilot_github_authorization(
    fields_without_id: dict[str, object],
) -> PublicPilotGithubAuthorization:
    """Build a typed authorization with its deterministic identifier."""

    try:
        payload = build_authorization_payload(fields_without_id)
        return PublicPilotGithubAuthorization.model_validate(payload)
    except (PublicPilotWireError, ValidationError) as error:
        raise ValueError("invalid public-pilot GitHub authorization") from error


def public_pilot_github_authorization_marker(
    authorization: PublicPilotGithubAuthorization,
    *,
    hmac_key: bytes,
) -> str:
    """Encode one typed authorization as the exact coordinator marker."""

    if not isinstance(authorization, PublicPilotGithubAuthorization):
        raise TypeError("authorization must be a PublicPilotGithubAuthorization")
    try:
        return build_authorization_marker(
            authorization.model_dump(mode="json", by_alias=True),
            hmac_key,
        )
    except PublicPilotWireError as error:
        raise ValueError("invalid public-pilot GitHub authorization marker") from error


def parse_public_pilot_github_authorization_marker(
    marker: str,
    *,
    hmac_key: bytes,
) -> PublicPilotGithubAuthorization:
    """Authenticate and parse one exact coordinator marker."""

    try:
        return PublicPilotGithubAuthorization.model_validate(
            parse_authorization_marker(marker, hmac_key)
        )
    except (PublicPilotWireError, ValidationError) as error:
        raise ValueError("invalid public-pilot GitHub authorization marker") from error


def public_pilot_automation_result_envelope(
    payload: PublicPilotAutomationResult,
    *,
    hmac_key: bytes,
) -> bytes:
    """Encode and authenticate a typed terminal coordinator result."""

    if not isinstance(
        payload,
        (PublicPilotCaseReadyResult, PublicPilotTerminalResult, PublicPilotIncompleteResult),
    ):
        raise TypeError("payload must be a public-pilot automation result")
    try:
        return build_result_envelope(payload.model_dump(mode="json", by_alias=True), hmac_key)
    except PublicPilotWireError as error:
        raise ValueError("invalid public-pilot automation result") from error


def parse_public_pilot_automation_result_envelope(
    raw: bytes,
    *,
    hmac_key: bytes,
) -> PublicPilotAutomationResultEnvelope:
    """Authenticate exact canonical bytes and return their typed result envelope."""

    try:
        payload_document = parse_result_envelope(raw, hmac_key)
        action = payload_document.get("action")
        if action == "ready_for_case":
            payload: PublicPilotAutomationResult = PublicPilotCaseReadyResult.model_validate(
                payload_document
            )
        elif action == "ready_to_issue":
            if payload_document.get("status") == "pilot_incomplete":
                payload = PublicPilotIncompleteResult.model_validate(payload_document)
            else:
                payload = PublicPilotTerminalResult.model_validate(payload_document)
        else:
            raise ValueError("result action is invalid")
        document = {
            "schema": RESULT_ENVELOPE_SCHEMA,
            "payload": payload,
            "hmac_sha256": _extract_result_hmac(raw),
        }
        envelope = PublicPilotAutomationResultEnvelope.model_validate(document)
    except (PublicPilotWireError, ValidationError, ValueError) as error:
        raise ValueError("invalid public-pilot automation result envelope") from error
    if canonical_json_bytes(envelope) != raw:
        raise ValueError("public-pilot automation result envelope is not canonical")
    return envelope


def _extract_result_hmac(raw: bytes) -> str:
    # The wire parser has already authenticated and structurally constrained
    # the envelope.  Avoid a second general-purpose JSON implementation here.
    import json

    value = json.loads(raw)
    return str(value["hmac_sha256"])


def _require_archive_url(value: str, expected_path: str) -> None:
    if (
        not value.isascii()
        or not value.isprintable()
        or any(character.isspace() for character in value)
        or len(value) > 2_048
    ):
        raise ValueError("archive URL must be bounded ASCII")
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError("archive URL port is invalid") from error
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path != expected_path
        or parsed.netloc.endswith(".")
        or (port is not None and not 1 <= port <= 65_535)
    ):
        raise ValueError("archive URL does not match the immutable public path")


__all__ = [
    "MAX_PUBLIC_PILOT_ARCHIVE_BYTES",
    "PublicPilotAutomationResult",
    "PublicPilotAutomationResultEnvelope",
    "PublicPilotCaseReadyResult",
    "PublicPilotGithubAuthorization",
    "PublicPilotIncompleteResult",
    "PublicPilotTerminalResult",
    "create_public_pilot_github_authorization",
    "parse_public_pilot_automation_result_envelope",
    "parse_public_pilot_github_authorization_marker",
    "public_pilot_automation_result_envelope",
    "public_pilot_github_authorization_marker",
]
