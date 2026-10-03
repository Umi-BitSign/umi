"""Signed contracts for direct multipart model delivery.

These records bind one byte stream to one retained model submission. Presigned
URLs and provider upload IDs are transient bearer capabilities and deliberately
do not appear in durable public protocol records.
"""

from __future__ import annotations

import math
import re
from typing import Annotated, Literal
from urllib.parse import urlsplit

from pydantic import Field, StrictBool, field_validator, model_serializer, model_validator
from typing_extensions import Self

from .competition_cohort_participation import CohortParticipationRequest
from .open_competition import Signature, digest, identity, verify_signature
from .protocol import Hex32, StrictProtocolModel
from .r2_limits import (
    R2_MAXIMUM_MULTIPART_BYTES,
    R2_MAXIMUM_PART_BYTES,
    R2_MAXIMUM_PARTS,
    R2_MINIMUM_PART_BYTES,
)

_ETAG = re.compile(r'^(?:[0-9A-Fa-f]{32}|"[0-9A-Fa-f]{32}")$')
_R2_HOST = re.compile(r"^[0-9a-f]{32}\.r2\.cloudflarestorage\.com$")


def direct_model_object_key(cohort_sha256: str, upload_sha256: str, attempt_id: str) -> str:
    """Derive the private object name bound by an owner-signed reservation."""

    for value in (cohort_sha256, upload_sha256, attempt_id):
        if (
            type(value) is not str
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise ValueError("direct model object identity differs")
    return f"incoming/v2/{cohort_sha256}/{upload_sha256}/{attempt_id}/payload"


def preserved_model_object_key(cohort_sha256: str, model_sha256: str, payload_sha256: str) -> str:
    """Derive the immutable content-addressed key used after acceptance."""

    for value in (cohort_sha256, model_sha256, payload_sha256):
        if (
            type(value) is not str
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise ValueError("preserved model object identity differs")
    return f"preservation/v1/{cohort_sha256}/{model_sha256}/{payload_sha256}/payload"


class DirectModelPayload(StrictProtocolModel):
    """The exact concatenation of model files in signed manifest order."""

    schema_: Literal["umi-direct-model-payload/1"] = Field(alias="schema")
    upload_sha256: Hex32
    model_sha256: Hex32
    payload_sha256: Hex32
    total_bytes: Annotated[int, Field(ge=1, le=R2_MAXIMUM_MULTIPART_BYTES)]
    file_count: Annotated[int, Field(ge=1, le=4096)]
    part_size_bytes: Annotated[int, Field(ge=R2_MINIMUM_PART_BYTES, le=R2_MAXIMUM_PART_BYTES)]
    total_parts: Annotated[int, Field(ge=1, le=R2_MAXIMUM_PARTS)]

    @model_validator(mode="after")
    def exact_part_geometry(self) -> Self:
        if self.total_parts != math.ceil(self.total_bytes / self.part_size_bytes):
            raise ValueError("direct model payload part geometry differs")
        return self


class SignedDirectModelPayload(StrictProtocolModel):
    """Miner authorization for one exact stream derived from its signed bundle."""

    schema_: Literal["umi-signed-direct-model-payload/1"] = Field(alias="schema")
    payload: DirectModelPayload
    signature: Signature

    @model_validator(mode="after")
    def signature_matches(self) -> Self:
        verify_signature(self.payload, self.signature)
        return self


class DirectModelUploadReservationRequest(StrictProtocolModel):
    schema_: Literal["umi-direct-model-upload-reservation-request/1"] = Field(alias="schema")
    request: CohortParticipationRequest
    payload: SignedDirectModelPayload


class DirectModelUploadReservation(StrictProtocolModel):
    """Durable issuer decision retained before any capability is returned."""

    schema_: Literal["umi-direct-model-upload-reservation/1"] = Field(alias="schema")
    cohort_sha256: Hex32
    hotkey: Annotated[str, Field(min_length=1, max_length=128)]
    payload: DirectModelPayload
    attempt_id: Hex32
    generation: Annotated[int, Field(ge=1, le=2**32 - 1)]
    object_key_sha256: Hex32
    provider_upload_id_sha256: Hex32
    created_at_unix_ms: Annotated[int, Field(ge=0, le=2**63 - 1)]


class SignedDirectModelUploadReservation(StrictProtocolModel):
    schema_: Literal["umi-signed-direct-model-upload-reservation/1"] = Field(alias="schema")
    reservation: DirectModelUploadReservation
    signature: Signature

    @model_validator(mode="after")
    def signature_matches(self) -> Self:
        verify_signature(self.reservation, self.signature)
        return self


class DirectModelUploadPartCapability(StrictProtocolModel):
    """Transient response; callers must redact the URL and never journal it."""

    schema_: Literal["umi-direct-model-upload-part-capability/1"] = Field(alias="schema")
    reservation_sha256: Hex32
    generation: Annotated[int, Field(ge=1, le=2**32 - 1)]
    part_number: Annotated[int, Field(ge=1, le=R2_MAXIMUM_PARTS)]
    size_bytes: Annotated[int, Field(ge=1, le=R2_MAXIMUM_PART_BYTES)]
    expires_at_unix_ms: Annotated[int, Field(ge=0, le=2**63 - 1)]
    url: Annotated[str, Field(min_length=1, max_length=8192)]

    @field_validator("url")
    @classmethod
    def https_bearer_url(cls, value: str) -> str:
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or parsed.hostname is None
            or _R2_HOST.fullmatch(parsed.hostname) is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or not parsed.path
            or "X-Amz-Signature=" not in parsed.query
        ):
            raise ValueError("multipart capability must be a signed R2 HTTPS URL")
        return value


class DirectModelUploadPartRequest(StrictProtocolModel):
    schema_: Literal["umi-direct-model-upload-part-request/1"] = Field(alias="schema")
    reservation_sha256: Hex32
    generation: Annotated[int, Field(ge=1, le=2**32 - 1)]
    part_numbers: Annotated[tuple[int, ...], Field(min_length=1, max_length=16)]

    @model_validator(mode="after")
    def ordered_unique_parts(self) -> Self:
        if self.part_numbers != tuple(sorted(set(self.part_numbers))) or any(
            not 1 <= value <= R2_MAXIMUM_PARTS for value in self.part_numbers
        ):
            raise ValueError("direct upload requested parts must be unique and ordered")
        return self


class SignedDirectModelUploadPartRequest(StrictProtocolModel):
    schema_: Literal["umi-signed-direct-model-upload-part-request/1"] = Field(alias="schema")
    request: DirectModelUploadPartRequest
    signature: Signature

    @model_validator(mode="after")
    def signature_matches(self) -> Self:
        verify_signature(self.request, self.signature)
        return self


class DirectModelUploadRestartRequest(StrictProtocolModel):
    """Miner request to replace one provider-expired multipart generation."""

    schema_: Literal["umi-direct-model-upload-restart-request/1"] = Field(alias="schema")
    reservation_sha256: Hex32
    generation: Annotated[int, Field(ge=1, le=2**32 - 1)]
    reason_code: Literal["provider_upload_unavailable"]


class SignedDirectModelUploadRestartRequest(StrictProtocolModel):
    schema_: Literal["umi-signed-direct-model-upload-restart-request/1"] = Field(alias="schema")
    request: DirectModelUploadRestartRequest
    signature: Signature

    @model_validator(mode="after")
    def signature_matches(self) -> Self:
        verify_signature(self.request, self.signature)
        return self


class DirectModelUploadPartCapabilities(StrictProtocolModel):
    schema_: Literal["umi-direct-model-upload-part-capabilities/1"] = Field(alias="schema")
    reservation_sha256: Hex32
    generation: Annotated[int, Field(ge=1, le=2**32 - 1)]
    capabilities: Annotated[
        tuple[DirectModelUploadPartCapability, ...], Field(min_length=1, max_length=16)
    ]


class DirectModelUploadPart(StrictProtocolModel):
    part_number: Annotated[int, Field(ge=1, le=R2_MAXIMUM_PARTS)]
    size_bytes: Annotated[int, Field(ge=1, le=R2_MAXIMUM_PART_BYTES)]
    etag: Annotated[str, Field(min_length=32, max_length=34)]

    @field_validator("etag")
    @classmethod
    def provider_etag(cls, value: str) -> str:
        if _ETAG.fullmatch(value) is None:
            raise ValueError("multipart part ETag differs")
        return value.strip('"').lower()


class DirectModelUploadCompletion(StrictProtocolModel):
    schema_: Literal["umi-direct-model-upload-completion/1"] = Field(alias="schema")
    reservation_sha256: Hex32
    generation: Annotated[int, Field(ge=1, le=2**32 - 1)]
    parts: Annotated[
        tuple[DirectModelUploadPart, ...], Field(min_length=1, max_length=R2_MAXIMUM_PARTS)
    ]

    @model_validator(mode="after")
    def ordered_unique_parts(self) -> Self:
        if tuple(part.part_number for part in self.parts) != tuple(range(1, len(self.parts) + 1)):
            raise ValueError("multipart completion parts must be complete and ordered")
        return self


class SignedDirectModelUploadCompletion(StrictProtocolModel):
    schema_: Literal["umi-signed-direct-model-upload-completion/1"] = Field(alias="schema")
    completion: DirectModelUploadCompletion
    signature: Signature

    @model_validator(mode="after")
    def signature_matches(self) -> Self:
        verify_signature(self.completion, self.signature)
        return self


class DirectModelUploadObject(StrictProtocolModel):
    """Provider completion retained before independent byte verification."""

    schema_: Literal["umi-direct-model-upload-object/1"] = Field(alias="schema")
    reservation_sha256: Hex32
    generation: Annotated[int, Field(ge=1, le=2**32 - 1)]
    object_key_sha256: Hex32
    provider_etag: Annotated[str, Field(min_length=1, max_length=256)]
    completed_at_unix_ms: Annotated[int, Field(ge=0, le=2**63 - 1)]


class DirectModelUploadVerification(StrictProtocolModel):
    """Full stream and per-file verification required before admission."""

    schema_: Literal["umi-direct-model-upload-verification/1"] = Field(alias="schema")
    reservation_sha256: Hex32
    generation: Annotated[int, Field(ge=1, le=2**32 - 1)]
    object_key_sha256: Hex32
    upload_sha256: Hex32
    model_sha256: Hex32
    payload_sha256: Hex32
    total_bytes: Annotated[int, Field(ge=1, le=R2_MAXIMUM_MULTIPART_BYTES)]
    file_count: Annotated[int, Field(ge=1, le=4096)]
    verified_at_unix_ms: Annotated[int, Field(ge=0, le=2**63 - 1)]


class DirectModelUploadStatus(StrictProtocolModel):
    schema_: Literal["umi-direct-model-upload-status/1"] = Field(alias="schema")
    upload_sha256: Hex32
    model_sha256: Hex32
    reservation: SignedDirectModelUploadReservation
    object_complete: StrictBool
    payload_verified: StrictBool
    verification: DirectModelUploadVerification | None
    hold_reason_code: (
        Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[a-z0-9][a-z0-9_]*$")] | None
    ) = None

    @model_serializer(mode="wrap")
    def omit_absent_hold(self, handler):
        value = handler(self)
        if self.hold_reason_code is None:
            value.pop("hold_reason_code", None)
        return value

    @model_validator(mode="after")
    def exact_status(self) -> Self:
        body = self.reservation.reservation
        if (
            self.upload_sha256 != body.payload.upload_sha256
            or self.model_sha256 != body.payload.model_sha256
            or self.payload_verified != (self.verification is not None)
            or (self.payload_verified and not self.object_complete)
            or (self.hold_reason_code is not None and not self.object_complete)
            or (
                self.verification is not None
                and (
                    self.verification.reservation_sha256 != digest_reservation(body)
                    or self.verification.upload_sha256 != self.upload_sha256
                    or self.verification.model_sha256 != self.model_sha256
                )
            )
        ):
            raise ValueError("direct model upload status differs")
        return self


def digest_reservation(value: DirectModelUploadReservation) -> str:
    """Name the reservation digest used by capabilities and completion."""

    return digest(value)


def require_part_request_signer(
    value: SignedDirectModelUploadPartRequest, reservation: DirectModelUploadReservation
) -> None:
    """Bind a capability request to the submitting hotkey and reservation."""

    if (
        value.request.reservation_sha256 != digest_reservation(reservation)
        or value.request.generation != reservation.generation
        or identity(value.signature.hotkey) != identity(reservation.hotkey)
    ):
        raise ValueError("direct upload capability signer or reservation differs")


def require_restart_request_signer(
    value: SignedDirectModelUploadRestartRequest, reservation: DirectModelUploadReservation
) -> None:
    """Bind provider-expiry recovery to the original submitting hotkey."""

    if (
        value.request.reservation_sha256 != digest_reservation(reservation)
        or value.request.generation != reservation.generation
        or identity(value.signature.hotkey) != identity(reservation.hotkey)
    ):
        raise ValueError("direct upload restart signer or reservation differs")
