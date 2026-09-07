"""Hotkey-signed, issue-bound authorization for the public miner pilot."""

from __future__ import annotations

import calendar
import hashlib
import hmac
import json
import re
import time
from typing import Annotated, Any, Literal, TypeAlias

from pydantic import Field, ValidationError, field_validator, model_validator
from typing_extensions import Self

from .crypto import sign_response_digest, verify_response_signature
from .encoding import account_id32
from .protocol import (
    Hex32,
    StrictProtocolModel,
    base64url_decode,
    base64url_encode,
    canonical_json_bytes,
)
from .public_pilot_campaign import CAMPAIGN_ID
from .public_pilot_evidence import validate_public_endpoint_origin

PUBLIC_PILOT_READINESS_SCHEMA = "umi-public-pilot-readiness/1"
PUBLIC_PILOT_READINESS_MARKER_PREFIX = "UMI-PILOT-READINESS-V1"
PUBLIC_PILOT_READINESS_SIGNATURE_DOMAIN = b"umi-public-pilot-readiness-v1\0"
MAX_PUBLIC_PILOT_READINESS_PAYLOAD_BYTES = 4_096
MAX_PUBLIC_PILOT_READINESS_MARKER_CHARS = (
    len(PUBLIC_PILOT_READINESS_MARKER_PREFIX)
    + 1
    + (MAX_PUBLIC_PILOT_READINESS_PAYLOAD_BYTES * 4 + 2) // 3
    + 1
    + len("sr25519")
    + 1
    + 130
)

_MAX_JSON_SAFE_INTEGER = (1 << 53) - 1
_UTC_TIMESTAMP_RE = re.compile(
    r"^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$"
)
_MARKER_RE = re.compile(
    rf"^{re.escape(PUBLIC_PILOT_READINESS_MARKER_PREFIX)} "
    r"(?P<payload>[A-Za-z0-9_-]+) "
    r"(?P<scheme>sr25519|ed25519) "
    r"(?P<signature>0x[0-9a-f]{128})$"
)


def _validate_utc_timestamp(value: str) -> str:
    if _UTC_TIMESTAMP_RE.fullmatch(value) is None:
        raise ValueError("expires_at must be second-precision UTC text ending in Z")
    try:
        # The expression fixes the wire syntax; the standard library checks
        # calendar details such as month lengths and leap years.
        time.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise ValueError("expires_at is not a valid UTC timestamp") from error
    return value


class _PublicPilotReadinessPayloadBase(StrictProtocolModel):
    """Bindings common to both public-pilot readiness transitions."""

    schema_: Literal[PUBLIC_PILOT_READINESS_SCHEMA] = Field(alias="schema")
    repository_id: Annotated[int, Field(ge=1, le=_MAX_JSON_SAFE_INTEGER)]
    issue_id: Annotated[int, Field(ge=1, le=_MAX_JSON_SAFE_INTEGER)]
    issue_node_id: Annotated[str, Field(min_length=1, max_length=256)]
    issue_number: Annotated[int, Field(ge=1, le=_MAX_JSON_SAFE_INTEGER)]
    campaign_id: Hex32
    challenge_nonce: Hex32
    miner_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    miner_account_id32: Hex32
    expected_uid: Annotated[int, Field(ge=0, le=65_535)]
    expires_at: Annotated[str, Field(min_length=20, max_length=20)]

    @field_validator("issue_node_id")
    @classmethod
    def validate_issue_node_id(cls, value: str) -> str:
        if not value.isascii() or any(
            character.isspace() or not character.isprintable() for character in value
        ):
            raise ValueError("issue_node_id must contain only visible ASCII without whitespace")
        return value

    @field_validator("campaign_id")
    @classmethod
    def validate_campaign_id(cls, value: str) -> str:
        if not hmac.compare_digest(value, CAMPAIGN_ID):
            raise ValueError("campaign_id does not identify the public endpoint pilot")
        return value

    @field_validator("miner_hotkey")
    @classmethod
    def validate_miner_hotkey(cls, value: str) -> str:
        try:
            account_id32(value)
        except ValueError as error:
            raise ValueError("miner_hotkey is not a valid AccountId32 SS58 address") from error
        return value

    @field_validator("expires_at")
    @classmethod
    def validate_expires_at(cls, value: str) -> str:
        return _validate_utc_timestamp(value)

    @model_validator(mode="after")
    def validate_account_binding(self) -> Self:
        actual = account_id32(self.miner_hotkey).hex()
        if not hmac.compare_digest(actual, self.miner_account_id32):
            raise ValueError("miner_account_id32 does not match miner_hotkey")
        return self


class ReadyForCasePayload(_PublicPilotReadinessPayloadBase):
    """Authorization for the coordinator to prepare, but not issue, one case."""

    action: Literal["ready_for_case"]


class ReadyToIssuePayload(_PublicPilotReadinessPayloadBase):
    """Authorization for one exact prepared case and contacted origin."""

    action: Literal["ready_to_issue"]
    predecessor_authorization_id: Hex32
    case_manifest_sha256: Hex32
    expected_origin: Annotated[str, Field(min_length=1, max_length=128)]

    @field_validator("expected_origin")
    @classmethod
    def validate_expected_origin(cls, value: str) -> str:
        return validate_public_endpoint_origin(value)


PublicPilotReadinessPayload: TypeAlias = ReadyForCasePayload | ReadyToIssuePayload


class PublicPilotReadinessProof(StrictProtocolModel):
    """A decoded marker carrying the payload, scheme, and signature."""

    payload: ReadyForCasePayload | ReadyToIssuePayload
    signature_scheme: Literal["sr25519", "ed25519"]
    signature: Annotated[str, Field(pattern=r"^0x[0-9a-f]{128}$")]


def public_pilot_readiness_digest(payload: PublicPilotReadinessPayload) -> bytes:
    """Return the domain-separated digest signed by the miner hotkey."""

    _require_payload(payload)
    return hashlib.sha256(
        PUBLIC_PILOT_READINESS_SIGNATURE_DOMAIN + canonical_json_bytes(payload)
    ).digest()


def sign_public_pilot_readiness(
    payload: PublicPilotReadinessPayload,
    *,
    wallet: Any,
    now_unix_s: int | None = None,
) -> PublicPilotReadinessProof:
    """Sign one still-live payload after matching it to the selected wallet."""

    _require_payload(payload)
    _require_live_expiry(payload.expires_at, now_unix_s=now_unix_s)
    hotkey, expected_scheme = _wallet_identity(wallet)
    if hotkey != payload.miner_hotkey or not hmac.compare_digest(
        account_id32(hotkey).hex(), payload.miner_account_id32
    ):
        raise ValueError("wallet hotkey does not match the readiness payload")
    scheme, signature = sign_response_digest(wallet, public_pilot_readiness_digest(payload))
    if scheme != expected_scheme:
        raise ValueError("wallet signature scheme changed while signing readiness")
    proof = PublicPilotReadinessProof(
        payload=payload,
        signature_scheme=scheme,
        signature=signature,
    )
    _verify_signature(proof)
    return proof


def public_pilot_readiness_marker(proof: PublicPilotReadinessProof) -> str:
    """Encode one proof as the exact single-line marker accepted by automation."""

    if not isinstance(proof, PublicPilotReadinessProof):
        raise TypeError("proof must be a PublicPilotReadinessProof")
    token = public_pilot_readiness_payload_token(proof.payload)
    marker = (
        f"{PUBLIC_PILOT_READINESS_MARKER_PREFIX} {token} {proof.signature_scheme} {proof.signature}"
    )
    if len(marker) > MAX_PUBLIC_PILOT_READINESS_MARKER_CHARS:
        raise ValueError("public-pilot readiness marker exceeds its character ceiling")
    return marker


def public_pilot_readiness_payload_token(payload: PublicPilotReadinessPayload) -> str:
    """Encode one canonical challenge payload for transfer to the signing CLI."""

    _require_payload(payload)
    encoded = canonical_json_bytes(payload)
    if len(encoded) > MAX_PUBLIC_PILOT_READINESS_PAYLOAD_BYTES:
        raise ValueError("public-pilot readiness payload exceeds its byte ceiling")
    return base64url_encode(encoded)


def parse_public_pilot_readiness_payload_token(token: str) -> PublicPilotReadinessPayload:
    """Strictly decode one canonical challenge payload token."""

    if not isinstance(token, str):
        raise TypeError("public-pilot readiness payload token must be text")
    maximum_token_chars = (MAX_PUBLIC_PILOT_READINESS_PAYLOAD_BYTES * 4 + 2) // 3
    if not token or len(token) > maximum_token_chars:
        raise ValueError("invalid public-pilot readiness payload token size")
    try:
        raw = base64url_decode(token)
    except (TypeError, ValueError) as error:
        raise ValueError("invalid public-pilot readiness payload token encoding") from error
    if not raw or len(raw) > MAX_PUBLIC_PILOT_READINESS_PAYLOAD_BYTES:
        raise ValueError("invalid public-pilot readiness payload size")
    try:
        document = _strict_json_object(raw)
        action = document.get("action")
        if action == "ready_for_case":
            payload: PublicPilotReadinessPayload = ReadyForCasePayload.model_validate(document)
        elif action == "ready_to_issue":
            payload = ReadyToIssuePayload.model_validate(document)
        else:
            raise ValueError("public-pilot readiness action is invalid")
    except (ValidationError, ValueError) as error:
        raise ValueError("invalid public-pilot readiness payload") from error
    if not hmac.compare_digest(canonical_json_bytes(payload), raw):
        raise ValueError("public-pilot readiness payload is not canonical RFC 8785 JSON")
    return payload


def parse_public_pilot_readiness_marker(marker: str) -> PublicPilotReadinessProof:
    """Strictly decode one canonical readiness marker without authorizing it."""

    if not isinstance(marker, str):
        raise TypeError("public-pilot readiness marker must be text")
    if len(marker) > MAX_PUBLIC_PILOT_READINESS_MARKER_CHARS:
        raise ValueError("invalid public-pilot readiness marker")
    match = _MARKER_RE.fullmatch(marker)
    if match is None:
        raise ValueError("invalid public-pilot readiness marker")
    payload = parse_public_pilot_readiness_payload_token(match.group("payload"))
    return PublicPilotReadinessProof(
        payload=payload,
        signature_scheme=match.group("scheme"),
        signature=match.group("signature"),
    )


def verify_public_pilot_readiness(
    proof: PublicPilotReadinessProof,
    *,
    expected_payload: PublicPilotReadinessPayload,
    now_unix_s: int | None = None,
) -> PublicPilotReadinessProof:
    """Verify the signature, freshness, and exact caller-supplied payload."""

    if not isinstance(proof, PublicPilotReadinessProof):
        raise TypeError("proof must be a PublicPilotReadinessProof")
    _require_payload(expected_payload)
    if proof.payload != expected_payload:
        raise ValueError("public-pilot readiness proof does not match the expected payload")
    _require_live_expiry(proof.payload.expires_at, now_unix_s=now_unix_s)
    _verify_signature(proof)
    return proof


def parse_and_verify_public_pilot_readiness_marker(
    marker: str,
    *,
    expected_payload: PublicPilotReadinessPayload,
    now_unix_s: int | None = None,
) -> PublicPilotReadinessProof:
    """Strictly parse and context-verify one marker."""

    return verify_public_pilot_readiness(
        parse_public_pilot_readiness_marker(marker),
        expected_payload=expected_payload,
        now_unix_s=now_unix_s,
    )


def _strict_json_object(raw: bytes) -> dict[str, Any]:
    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise ValueError("public-pilot readiness payload contains a duplicate JSON key")
            result[key] = value
        return result

    try:
        document = json.loads(raw, object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError("public-pilot readiness payload is not strict JSON") from error
    if not isinstance(document, dict):
        raise ValueError("public-pilot readiness payload must be a JSON object")
    return document


def _require_payload(payload: object) -> None:
    if not isinstance(payload, (ReadyForCasePayload, ReadyToIssuePayload)):
        raise TypeError("payload must be a public-pilot readiness payload")


def _expiry_unix_s(expires_at: str) -> int:
    _validate_utc_timestamp(expires_at)
    return calendar.timegm(time.strptime(expires_at, "%Y-%m-%dT%H:%M:%SZ"))


def _require_live_expiry(expires_at: str, *, now_unix_s: int | None) -> None:
    if now_unix_s is None:
        now_unix_s = int(time.time())
    if (
        isinstance(now_unix_s, bool)
        or not isinstance(now_unix_s, int)
        or not 0 <= now_unix_s <= _MAX_JSON_SAFE_INTEGER
    ):
        raise ValueError("now_unix_s must be a nonnegative JSON-safe integer")
    if _expiry_unix_s(expires_at) <= now_unix_s:
        raise ValueError("public-pilot readiness proof is expired")


def _verify_signature(proof: PublicPilotReadinessProof) -> None:
    if not verify_response_signature(
        public_pilot_readiness_digest(proof.payload),
        hotkey_ss58=proof.payload.miner_hotkey,
        scheme=proof.signature_scheme,
        signature=proof.signature,
    ):
        raise ValueError("public-pilot readiness signature is invalid")


def _wallet_identity(wallet: Any) -> tuple[str, str]:
    import bittensor as bt

    signer = bt.resolve_signer(wallet, role="hotkey")
    scheme = bt.wallets.format_crypto_type(signer.crypto_type)
    if scheme not in {"sr25519", "ed25519"}:
        raise ValueError(f"unsupported miner hotkey signature scheme: {scheme}")
    return signer.ss58_address, scheme


__all__ = [
    "MAX_PUBLIC_PILOT_READINESS_MARKER_CHARS",
    "MAX_PUBLIC_PILOT_READINESS_PAYLOAD_BYTES",
    "PUBLIC_PILOT_READINESS_MARKER_PREFIX",
    "PUBLIC_PILOT_READINESS_SCHEMA",
    "PUBLIC_PILOT_READINESS_SIGNATURE_DOMAIN",
    "PublicPilotReadinessPayload",
    "PublicPilotReadinessProof",
    "ReadyForCasePayload",
    "ReadyToIssuePayload",
    "parse_and_verify_public_pilot_readiness_marker",
    "parse_public_pilot_readiness_marker",
    "parse_public_pilot_readiness_payload_token",
    "public_pilot_readiness_digest",
    "public_pilot_readiness_marker",
    "public_pilot_readiness_payload_token",
    "sign_public_pilot_readiness",
    "verify_public_pilot_readiness",
]
