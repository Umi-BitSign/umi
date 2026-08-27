"""Pre-reveal assignment, request, and sealed-response anchor construction."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Annotated, Any, Literal

from pydantic import AfterValidator, Field, model_validator
from typing_extensions import Self

from .auth import verify_historical_auth_record
from .encoding import account_id32, raw_sha256, sha256_domain, u32be
from .protocol import (
    StrictProtocolModel,
    TranslationRequest,
    canonical_json_bytes,
    request_digest,
)

_HEX_32_RE = re.compile(r"^[0-9a-f]{64}$")
_SIGNATURE_RE = re.compile(r"^0x[0-9a-f]{128}$")
_TRANSLATE_METHOD = "POST"
_TRANSLATE_TARGET = "/v1/translate"
_VERIFIED_EVIDENCE_TOKEN = object()


def _hex32(value: str) -> str:
    if _HEX_32_RE.fullmatch(value) is None:
        raise ValueError("value must be 32 bytes encoded as lowercase hexadecimal")
    return value


def _signature(value: str) -> str:
    if _SIGNATURE_RE.fullmatch(value) is None:
        raise ValueError("signature must be 64 bytes encoded as 0x-prefixed lowercase hex")
    return value


Hex32 = Annotated[str, AfterValidator(_hex32)]
SignatureHex = Annotated[str, AfterValidator(_signature)]
CanonicalNonce = Annotated[
    str,
    Field(pattern=r"^(0|[1-9][0-9]*)$", min_length=1, max_length=20),
]


class AuthRecord(StrictProtocolModel):
    """Canonical authentication object committed by the anchor formulas."""

    version: Literal["btauth/1"]
    scheme: Literal["sr25519", "ed25519"]
    method: Literal["POST"]
    wire_request_target: Literal["/v1/translate"]
    raw_body_sha256: Hex32
    nonce: CanonicalNonce
    sender: Annotated[str, Field(min_length=1)]
    receiver: Annotated[str, Field(min_length=1)]
    signature: SignatureHex

    @property
    def nonce_int(self) -> int:
        """Return the numeric nonce used for ordering and signature replay."""

        return int(self.nonce)


@dataclass(frozen=True, slots=True)
class VerifiedAuthEvidence:
    """A canonical auth record verified against one exact translation request."""

    auth_record: AuthRecord
    request: TranslationRequest
    request_bytes: bytes
    request_digest_bytes: bytes
    validator_account_id32: bytes
    miner_account_id32: bytes
    _verification_token: object

    def __post_init__(self) -> None:
        if self._verification_token is not _VERIFIED_EVIDENCE_TOKEN:
            raise TypeError("VerifiedAuthEvidence must be created with from_headers()")

    @classmethod
    def from_headers(
        cls,
        headers: Mapping[str, str],
        *,
        request: TranslationRequest,
        expected_validator_hotkey: str,
        expected_miner_hotkey: str,
    ) -> VerifiedAuthEvidence:
        """Verify stored ``btauth/1`` headers and construct anchor evidence.

        UMI translation anchors always bind ``POST /v1/translate``. The signed
        body is the exact RFC 8785 encoding of ``request``.
        """

        if not isinstance(request, TranslationRequest):
            raise TypeError("request must be a TranslationRequest")
        if not isinstance(expected_validator_hotkey, str):
            raise TypeError("expected validator hotkey must be an SS58 string")
        if not isinstance(expected_miner_hotkey, str):
            raise TypeError("expected miner hotkey must be an SS58 string")
        lowered = _canonical_header_lookup(headers)
        body = canonical_json_bytes(request)
        verified = verify_historical_auth_record(
            lowered,
            body,
            method=_TRANSLATE_METHOD,
            path=_TRANSLATE_TARGET,
            receiver_ss58=expected_miner_hotkey,
        )
        if verified.sender_ss58 != expected_validator_hotkey:
            raise ValueError("historical auth record binds a different validator sender")
        if verified.receiver_ss58 != expected_miner_hotkey:
            raise ValueError("historical auth record binds a different miner receiver")

        validator_account = account_id32(expected_validator_hotkey)
        miner_account = account_id32(expected_miner_hotkey)
        if account_id32(verified.sender_ss58) != validator_account:
            raise ValueError("historical auth sender account does not reproduce")
        if account_id32(verified.receiver_ss58) != miner_account:
            raise ValueError("historical auth receiver account does not reproduce")

        signature = _required_header(lowered, "x-bittensor-signature")
        nonce = _required_header(lowered, "x-bittensor-nonce")
        if int(nonce) != verified.nonce:
            raise ValueError("historical auth nonce does not reproduce")
        record = AuthRecord.model_validate(
            {
                "version": "btauth/1",
                "scheme": verified.scheme,
                "method": _TRANSLATE_METHOD,
                "wire_request_target": _TRANSLATE_TARGET,
                "raw_body_sha256": hashlib.sha256(body).hexdigest(),
                "nonce": nonce,
                "sender": verified.sender_ss58,
                "receiver": verified.receiver_ss58,
                "signature": signature,
            }
        )
        return cls(
            auth_record=record,
            request=request,
            request_bytes=body,
            request_digest_bytes=bytes.fromhex(request_digest(request)),
            validator_account_id32=validator_account,
            miner_account_id32=miner_account,
            _verification_token=_VERIFIED_EVIDENCE_TOKEN,
        )


class SealedResponseRecord(StrictProtocolModel):
    disposition: Literal["sealed", "missing", "late", "outer_invalid", "resource_limit"]
    receipt_metadata: dict[str, Any]
    wire_envelope_sha256: Hex32 | None = None
    signature_scheme: Literal["sr25519", "ed25519"] | None = None
    serving_hotkey: Annotated[str, Field(min_length=1)] | None = None
    signature: SignatureHex | None = None
    received_bytes_sha256: Hex32 | None = None

    @model_validator(mode="after")
    def validate_disposition(self) -> Self:
        sealed_fields = (
            self.wire_envelope_sha256,
            self.signature_scheme,
            self.serving_hotkey,
            self.signature,
        )
        if self.disposition == "sealed":
            if any(value is None for value in sealed_fields):
                raise ValueError("sealed disposition requires envelope and signature evidence")
            if self.received_bytes_sha256 is not None:
                raise ValueError("sealed disposition uses wire_envelope_sha256")
        elif any(value is not None for value in sealed_fields):
            raise ValueError("outer failure dispositions cannot carry sealed-envelope fields")
        return self


def _canonical_header_lookup(headers: Mapping[str, str]) -> dict[str, str]:
    if not isinstance(headers, Mapping):
        raise TypeError("historical auth headers must be a mapping")
    lowered: dict[str, str] = {}
    for name, value in headers.items():
        if not isinstance(name, str) or not isinstance(value, str):
            raise TypeError("historical auth header names and values must be strings")
        canonical_name = name.lower()
        if canonical_name in lowered:
            raise ValueError("historical auth headers contain a case-insensitive duplicate")
        lowered[canonical_name] = value
    return lowered


def _required_header(headers: Mapping[str, str], name: str) -> str:
    try:
        return headers[name]
    except KeyError as error:
        raise ValueError(f"historical auth record is missing {name}") from error


def canonical_auth_records(
    records: Sequence[VerifiedAuthEvidence],
) -> tuple[VerifiedAuthEvidence, ...]:
    """Order verified attempts by nonce and reject nonce reuse."""

    if not records:
        raise ValueError("authentication evidence array must not be empty")
    if any(not isinstance(record, VerifiedAuthEvidence) for record in records):
        raise TypeError("authentication evidence must be VerifiedAuthEvidence")
    ordered = tuple(sorted(records, key=lambda record: record.auth_record.nonce_int))
    nonces = [record.auth_record.nonce_int for record in ordered]
    if len(set(nonces)) != len(nonces):
        raise ValueError("authentication evidence array reuses a nonce")
    return ordered


@dataclass(frozen=True, slots=True)
class AssignmentAnchorRecord:
    initial_auth_evidence: VerifiedAuthEvidence

    def __post_init__(self) -> None:
        if not isinstance(self.initial_auth_evidence, VerifiedAuthEvidence):
            raise TypeError("initial_auth_evidence must be VerifiedAuthEvidence")

    @property
    def miner_hotkey(self) -> str:
        return self.initial_auth_evidence.auth_record.receiver

    @property
    def request_digest(self) -> bytes:
        return self.initial_auth_evidence.request_digest_bytes

    @property
    def initial_auth_record(self) -> AuthRecord:
        return self.initial_auth_evidence.auth_record

    @property
    def key(self) -> tuple[bytes, bytes]:
        return (
            self.initial_auth_evidence.miner_account_id32,
            self.initial_auth_evidence.request_digest_bytes,
        )

    @property
    def leaf(self) -> bytes:
        miner, digest = self.key
        return sha256_domain(
            b"umi-assignment-leaf-v1\0",
            miner,
            digest,
            hashlib.sha256(canonical_json_bytes(self.initial_auth_record)).digest(),
        )


@dataclass(frozen=True, slots=True)
class RequestAnchorRecord:
    auth_evidence: Sequence[VerifiedAuthEvidence]

    def __post_init__(self) -> None:
        ordered = canonical_auth_records(self.auth_evidence)
        first = ordered[0]
        for evidence in ordered[1:]:
            if evidence.request_bytes != first.request_bytes:
                raise ValueError("request transcript combines different request bytes")
            if evidence.request_digest_bytes != first.request_digest_bytes:
                raise ValueError("request transcript combines different request digests")
            if evidence.validator_account_id32 != first.validator_account_id32:
                raise ValueError("request transcript combines different validator senders")
            if evidence.miner_account_id32 != first.miner_account_id32:
                raise ValueError("request transcript combines different miner receivers")
        object.__setattr__(self, "auth_evidence", ordered)

    @property
    def miner_hotkey(self) -> str:
        return self.ordered_auth_evidence[0].auth_record.receiver

    @property
    def request_digest(self) -> bytes:
        return self.ordered_auth_evidence[0].request_digest_bytes

    @property
    def key(self) -> tuple[bytes, bytes]:
        first = self.ordered_auth_evidence[0]
        return (first.miner_account_id32, first.request_digest_bytes)

    @property
    def ordered_auth_evidence(self) -> tuple[VerifiedAuthEvidence, ...]:
        return tuple(self.auth_evidence)

    @property
    def ordered_auth_records(self) -> tuple[dict[str, Any], ...]:
        return tuple(
            evidence.auth_record.model_dump(mode="json", by_alias=True)
            for evidence in self.ordered_auth_evidence
        )

    @property
    def leaf(self) -> bytes:
        miner, digest = self.key
        return sha256_domain(
            b"umi-request-leaf-v1\0",
            miner,
            digest,
            hashlib.sha256(canonical_json_bytes(list(self.ordered_auth_records))).digest(),
        )


@dataclass(frozen=True, slots=True)
class ResponseAnchorRecord:
    request_leaf: str | bytes
    sealed_response_record: SealedResponseRecord

    def __post_init__(self) -> None:
        raw_sha256(self.request_leaf, field="request leaf")
        if type(self.sealed_response_record) is not SealedResponseRecord:
            raise TypeError("sealed_response_record must be an exact SealedResponseRecord")

    @property
    def leaf(self) -> bytes:
        return sha256_domain(
            b"umi-response-leaf-v1\0",
            raw_sha256(self.request_leaf, field="request leaf"),
            hashlib.sha256(canonical_json_bytes(self.sealed_response_record)).digest(),
        )


def assignment_set_root(
    records: Sequence[AssignmentAnchorRecord],
    *,
    window_id: str | bytes,
    validator_hotkey: str | bytes,
) -> bytes:
    _validate_anchor_context(records, window_id=window_id, validator_hotkey=validator_hotkey)
    _unique_keys(tuple(record.key for record in records), "assignment")
    return _set_root(
        b"umi-assignment-set-v1\0",
        tuple(record.leaf for record in records),
        window_id,
        validator_hotkey,
    )


def request_set_root(
    records: Sequence[RequestAnchorRecord],
    *,
    assignments: Sequence[AssignmentAnchorRecord],
    window_id: str | bytes,
    validator_hotkey: str | bytes,
) -> bytes:
    _validate_anchor_context(records, window_id=window_id, validator_hotkey=validator_hotkey)
    _validate_anchor_context(assignments, window_id=window_id, validator_hotkey=validator_hotkey)
    request_keys = tuple(record.key for record in records)
    assignment_keys = tuple(record.key for record in assignments)
    _unique_keys(request_keys, "request")
    _unique_keys(assignment_keys, "assignment")
    if set(request_keys) != set(assignment_keys):
        raise ValueError("request leaves are not a bijection with assignment leaves")
    initial_by_key = {record.key: record.initial_auth_record for record in assignments}
    for record in records:
        if canonical_json_bytes(record.ordered_auth_records[0]) != canonical_json_bytes(
            initial_by_key[record.key]
        ):
            raise ValueError("request transcript does not begin with the anchored initial attempt")
    return _set_root(
        b"umi-request-set-v1\0",
        tuple(record.leaf for record in records),
        window_id,
        validator_hotkey,
    )


def response_set_root(
    records: Sequence[ResponseAnchorRecord],
    *,
    request_records: Sequence[RequestAnchorRecord],
    window_id: str | bytes,
    validator_hotkey: str | bytes,
) -> bytes:
    _validate_anchor_context(
        request_records,
        window_id=window_id,
        validator_hotkey=validator_hotkey,
    )
    request_leaves = tuple(record.leaf for record in request_records)
    response_request_leaves = tuple(
        raw_sha256(record.request_leaf, field="request leaf") for record in records
    )
    _unique_keys(request_leaves, "request leaf")
    _unique_keys(response_request_leaves, "response request leaf")
    if set(request_leaves) != set(response_request_leaves):
        raise ValueError("sealed responses are not a bijection with request leaves")
    return _set_root(
        b"umi-response-set-v1\0",
        tuple(record.leaf for record in records),
        window_id,
        validator_hotkey,
    )


def _validate_anchor_context(
    records: Sequence[AssignmentAnchorRecord] | Sequence[RequestAnchorRecord],
    *,
    window_id: str | bytes,
    validator_hotkey: str | bytes,
) -> None:
    expected_window = raw_sha256(window_id, field="window ID").hex()
    expected_validator = account_id32(validator_hotkey)
    for record in records:
        if isinstance(record, AssignmentAnchorRecord):
            evidence = (record.initial_auth_evidence,)
        elif isinstance(record, RequestAnchorRecord):
            evidence = record.ordered_auth_evidence
        else:
            raise TypeError("anchor records have an unsupported type")
        for attempt in evidence:
            if attempt.request.window_id != expected_window:
                raise ValueError("anchor request binds a different window")
            if attempt.validator_account_id32 != expected_validator:
                raise ValueError("anchor authentication binds a different validator")


def _unique_keys(values: Sequence[Any], label: str) -> None:
    if not values:
        raise ValueError(f"{label} set must not be empty")
    if len(set(values)) != len(values):
        raise ValueError(f"{label} set contains duplicate keys")


def _set_root(
    domain: bytes,
    leaves: Sequence[bytes],
    window_id: str | bytes,
    validator_hotkey: str | bytes,
) -> bytes:
    _unique_keys(leaves, "anchor leaf")
    return sha256_domain(
        domain,
        raw_sha256(window_id, field="window ID"),
        account_id32(validator_hotkey),
        u32be(len(leaves)),
        b"".join(sorted(leaves)),
    )


__all__ = [
    "AssignmentAnchorRecord",
    "AuthRecord",
    "CanonicalNonce",
    "RequestAnchorRecord",
    "ResponseAnchorRecord",
    "SealedResponseRecord",
    "VerifiedAuthEvidence",
    "assignment_set_root",
    "canonical_auth_records",
    "request_set_root",
    "response_set_root",
]
