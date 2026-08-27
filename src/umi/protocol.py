"""Pure UMI protocol schemas, canonicalization, and digest helpers."""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

import rfc8785
from pydantic import AfterValidator, BaseModel, ConfigDict, Field, field_validator, model_validator
from typing_extensions import Self

from .scoring import grapheme_clusters, normalize_text

PROTOCOL_VERSION = "umi-asl/0.1"
RESPONSE_PLAINTEXT_SCHEMA = "umi-response-plaintext/1"
RESPONSE_ENVELOPE_SCHEMA = "umi-response-envelope/1"
GROUND_TRUTH_SCHEMA = "umi-ground-truth/1"
GROUND_TRUTH_TLE_PROFILE = "umi-tle/1"
RESPONSE_TLE_PROFILE = "umi-response-tle/1"

_REQUEST_DOMAIN = b"umi-request-v1\0"
_RESPONSE_DOMAIN = b"umi-response-envelope-v1\0"
_HEX_32_RE = re.compile(r"^[0-9a-f]{64}$")
_BLOCK_HASH_RE = re.compile(r"^0x[0-9a-f]{64}$")
_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")


def _validate_hex_32(value: str) -> str:
    if not _HEX_32_RE.fullmatch(value):
        raise ValueError("must be exactly 32 bytes encoded as 64 lowercase hexadecimal characters")
    return value


def _validate_block_hash(value: str) -> str:
    if not _BLOCK_HASH_RE.fullmatch(value):
        raise ValueError("must be a 0x-prefixed 32-byte lowercase hexadecimal block hash")
    return value


def base64url_encode(data: bytes) -> str:
    """Encode bytes as canonical, unpadded base64url text."""

    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def base64url_decode(value: str) -> bytes:
    """Decode only canonical, unpadded base64url text."""

    if not isinstance(value, str):
        raise TypeError("value must be a string")
    if "=" in value or not _BASE64URL_RE.fullmatch(value) or len(value) % 4 == 1:
        raise ValueError("value must be canonical unpadded base64url")

    padded = value + "=" * ((-len(value)) % 4)
    try:
        decoded = base64.b64decode(padded, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("value must be canonical unpadded base64url") from exc

    if base64url_encode(decoded) != value:
        raise ValueError("value must be canonical unpadded base64url")
    return decoded


def _validate_opaque_id(value: str) -> str:
    if len(base64url_decode(value)) != 16:
        raise ValueError("must encode exactly 16 opaque bytes")
    return value


def _validate_nonempty_text(value: str) -> str:
    if not value or value.isspace():
        raise ValueError("must not be empty or whitespace-only")
    return value


def normalized_token_count(value: str) -> int:
    normalized = normalize_text(value)
    return 0 if not normalized else normalized.count(" ") + 1


def normalized_grapheme_count(value: str) -> int:
    normalized = normalize_text(value).replace(" ", "")
    return len(grapheme_clusters(normalized))


def _validate_reference(value: str) -> str:
    _validate_nonempty_text(value)
    if not normalize_text(value):
        raise ValueError("reference must contain at least one canonical scoring unit")
    if len(value.encode("utf-8")) > 4096:
        raise ValueError("reference exceeds 4096 UTF-8 bytes")
    if normalized_token_count(value) > 128:
        raise ValueError("reference exceeds 128 normalized tokens")
    if normalized_grapheme_count(value) > 512:
        raise ValueError("reference exceeds 512 normalized graphemes")
    return value


Hex32 = Annotated[str, AfterValidator(_validate_hex_32)]
BlockHash = Annotated[str, AfterValidator(_validate_block_hash)]
OpaqueId = Annotated[str, AfterValidator(_validate_opaque_id)]
NonEmptyText = Annotated[str, AfterValidator(_validate_nonempty_text)]
ReferenceText = Annotated[str, AfterValidator(_validate_reference)]


class StrictProtocolModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    @model_validator(mode="after")
    def validate_canonical_json_domain(self) -> Self:
        """Ensure every accepted protocol model has an RFC 8785 representation."""

        try:
            rfc8785.dumps(self.model_dump(mode="json", by_alias=True))
        except rfc8785.CanonicalizationError as error:
            raise ValueError("protocol model is outside the RFC 8785 JSON domain") from error
        return self


class Video(StrictProtocolModel):
    url: str
    sha256: Hex32
    size_bytes: Annotated[int, Field(gt=0)]
    media_type: Literal["video/mp4"]

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("url must be an absolute HTTP(S) URL")
        return value


class Task(StrictProtocolModel):
    source_language: Literal["ase"]
    target_language: Literal["en"]
    stratum: Literal["fingerspelling", "short_utterance", "continuous"]


class TranslationRequest(StrictProtocolModel):
    protocol: Literal[PROTOCOL_VERSION]
    window_id: Hex32
    batch_id: OpaqueId
    challenge_id: OpaqueId
    issued_block: Annotated[int, Field(ge=0)]
    issued_block_hash: BlockHash
    deadline_block: Annotated[int, Field(ge=0)]
    response_close_round: Annotated[int, Field(gt=0)]
    reveal_round: Annotated[int, Field(gt=0)]
    video: Video
    task: Task
    scoring_policy_hash: Hex32

    @model_validator(mode="after")
    def validate_ordering(self) -> Self:
        if self.deadline_block <= self.issued_block:
            raise ValueError("deadline_block must be greater than issued_block")
        if self.reveal_round <= self.response_close_round:
            raise ValueError("reveal_round must be greater than response_close_round")
        return self


class ResponsePlaintext(StrictProtocolModel):
    schema_: Literal[RESPONSE_PLAINTEXT_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    window_id: Hex32
    batch_id: OpaqueId
    challenge_id: OpaqueId
    request_digest: Hex32
    issued_block_hash: BlockHash
    validator_hotkey: NonEmptyText
    serving_hotkey: NonEmptyText
    status: Literal["ok", "error"]
    received_video_sha256: Hex32 | None
    hypothesis: str | None
    model_revision: Hex32 | None
    error_code: NonEmptyText | None

    @model_validator(mode="after")
    def validate_status_fields(self) -> Self:
        if self.status == "ok":
            if self.received_video_sha256 is None:
                raise ValueError("an ok response requires received_video_sha256")
            if self.hypothesis is None:
                raise ValueError("an ok response requires hypothesis")
            if self.error_code is not None:
                raise ValueError("an ok response requires error_code to be null")
            if normalized_token_count(self.hypothesis) > 128:
                raise ValueError("hypothesis exceeds 128 normalized tokens")
            try:
                encoded_hypothesis = self.hypothesis.encode("utf-8")
            except UnicodeEncodeError as error:
                raise ValueError("hypothesis is not valid UTF-8 text") from error
            if len(encoded_hypothesis) > 4096:
                raise ValueError("hypothesis exceeds 4096 UTF-8 bytes")
            if normalized_grapheme_count(self.hypothesis) > 512:
                raise ValueError("hypothesis exceeds 512 normalized graphemes")
        else:
            if self.hypothesis is not None or self.model_revision is not None:
                raise ValueError(
                    "an error response requires hypothesis and model_revision to be null"
                )
            if self.error_code is None:
                raise ValueError("an error response requires error_code")
        return self


class ResponseEnvelope(StrictProtocolModel):
    schema_: Literal[RESPONSE_ENVELOPE_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    window_id: Hex32
    batch_id: OpaqueId
    challenge_id: OpaqueId
    request_digest: Hex32
    issued_block_hash: BlockHash
    validator_hotkey: NonEmptyText
    serving_hotkey: NonEmptyText
    response_tle_profile: Literal[RESPONSE_TLE_PROFILE]
    response_reveal_round: Annotated[int, Field(gt=0)]
    encrypted_response: str
    encrypted_response_sha256: Hex32
    signature_scheme: Literal["sr25519", "ed25519"]

    @field_validator("encrypted_response")
    @classmethod
    def validate_encrypted_response(cls, value: str) -> str:
        if not base64url_decode(value):
            raise ValueError("encrypted_response must not be empty")
        return value


class CanaryEvidence(StrictProtocolModel):
    actual_references: Annotated[list[ReferenceText], Field(min_length=3, max_length=5)]
    actual_script_sha256: Hex32
    reserved_script_sha256: Hex32
    mismatched_references: Annotated[list[ReferenceText], Field(min_length=3, max_length=5)]


class GroundTruthItem(StrictProtocolModel):
    challenge_id: OpaqueId
    metric: Literal["wer", "cer"]
    canary: bool
    references: Annotated[list[ReferenceText], Field(min_length=3, max_length=5)]
    canary_evidence: CanaryEvidence | None
    normalized_script_sha256: Hex32
    retirement_script_sha256s: Annotated[list[Hex32], Field(min_length=1)]
    consent_manifest_sha256: Hex32

    @model_validator(mode="after")
    def validate_canary_and_retirement(self) -> Self:
        if self.canary != (self.canary_evidence is not None):
            raise ValueError("canary_evidence must be present exactly when canary is true")
        if len(set(self.retirement_script_sha256s)) != len(self.retirement_script_sha256s):
            raise ValueError("retirement_script_sha256s must be unique")
        if not self.canary and self.retirement_script_sha256s != [self.normalized_script_sha256]:
            raise ValueError("an ordinary item retires exactly its normalized script hash")
        if self.canary:
            evidence = self.canary_evidence
            if evidence is None:
                raise ValueError("a canary requires canary evidence")
            if evidence.actual_script_sha256 == evidence.reserved_script_sha256:
                raise ValueError("canary actual and reserved script hashes must differ")
            if self.normalized_script_sha256 != evidence.actual_script_sha256:
                raise ValueError("canary normalized script hash must be its actual script hash")
            if self.references != evidence.mismatched_references:
                raise ValueError("canary scoring references must equal its mismatched references")
            expected_retirement = sorted(
                {evidence.actual_script_sha256, evidence.reserved_script_sha256}
            )
            if self.retirement_script_sha256s != expected_retirement:
                raise ValueError(
                    "canary retirement hashes must be sorted actual and reserved hashes"
                )
        return self


class GroundTruthPayload(StrictProtocolModel):
    schema_: Literal[GROUND_TRUTH_SCHEMA] = Field(alias="schema")
    window_id: Hex32
    batch_id: OpaqueId
    scoring_policy_hash: Hex32
    tle_profile: Literal[GROUND_TRUTH_TLE_PROFILE]
    response_close_round: Annotated[int, Field(gt=0)]
    reveal_round: Annotated[int, Field(gt=0)]
    items: Annotated[list[GroundTruthItem], Field(min_length=1)]

    @model_validator(mode="after")
    def validate_payload(self) -> Self:
        if self.reveal_round <= self.response_close_round:
            raise ValueError("reveal_round must be greater than response_close_round")
        challenge_ids = [base64url_decode(item.challenge_id) for item in self.items]
        if len(set(challenge_ids)) != len(challenge_ids):
            raise ValueError("ground-truth challenge IDs must be unique")
        if challenge_ids != sorted(challenge_ids):
            raise ValueError("ground-truth items must be ordered by decoded challenge_id")
        return self


def canonical_json_bytes(value: BaseModel | Any) -> bytes:
    """Return RFC 8785 canonical JSON bytes for a model or JSON-compatible value."""

    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json", by_alias=True)
    return rfc8785.dumps(value)


def sha256_hex(data: bytes) -> str:
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    return hashlib.sha256(data).hexdigest()


def request_digest(request: TranslationRequest) -> str:
    if not isinstance(request, TranslationRequest):
        raise TypeError("request must be a TranslationRequest")
    return sha256_hex(_REQUEST_DOMAIN + canonical_json_bytes(request))


def response_digest(envelope: ResponseEnvelope) -> str:
    if not isinstance(envelope, ResponseEnvelope):
        raise TypeError("envelope must be a ResponseEnvelope without a signature field")
    return sha256_hex(_RESPONSE_DOMAIN + canonical_json_bytes(envelope))


__all__ = [
    "CanaryEvidence",
    "GroundTruthItem",
    "GroundTruthPayload",
    "ResponseEnvelope",
    "ResponsePlaintext",
    "Task",
    "TranslationRequest",
    "Video",
    "base64url_decode",
    "base64url_encode",
    "canonical_json_bytes",
    "normalize_text",
    "normalized_grapheme_count",
    "normalized_token_count",
    "request_digest",
    "response_digest",
    "sha256_hex",
]
