"""Canonical post-selection video delivery issuance material.

Validators retrieve candidate video through an authenticated mirror path before
selection.  Miners receive a separate, credential-free, short-lived URL issued
only for the selected batch items.  This module defines the shared schemas and
pure validation used by the live effect and offline replay.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Annotated, Literal
from urllib.parse import urlsplit

from pydantic import Field, model_validator
from typing_extensions import Self

from .policy import ScoringPolicy, scoring_policy_hash
from .protocol import (
    PROTOCOL_VERSION,
    StrictProtocolModel,
    base64url_decode,
    base64url_encode,
    canonical_json_bytes,
)
from .validator_state import WindowPlan
from .window import QUICKNET_GENESIS_MS, QUICKNET_PERIOD_MS

MIRROR_DISCOVERY_SCHEMA = "umi-mirror-discovery/1"
DEFAULT_MIRROR_INDEX_PATH = "/v1/umi/windows/{window_id}/pool-source.json"
DEFAULT_DELIVERY_ISSUANCE_PATH = "/v1/umi/video-deliveries"
DEFAULT_DELIVERY_OBJECT_PATH_PREFIX = "/v1/umi/deliveries/"
DELIVERY_ISSUANCE_REQUEST_SCHEMA = "umi-video-delivery-issuance-request/1"
DELIVERY_ISSUANCE_RESPONSE_SCHEMA = "umi-video-delivery-issuance-response/1"
DELIVERY_ISSUANCE_EVIDENCE_SCHEMA = "umi-video-delivery-issuance-evidence/1"

MAX_MIRROR_ORIGINS = 16
MAX_MIRROR_URL_BYTES = 8_192
MAX_DELIVERY_ITEMS = 65_535
_MAX_INTEGER = (1 << 53) - 1
_HEX32_PATTERN = r"^[0-9a-f]{64}$"
_DELIVERY_TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{32}$")
_DELIVERY_TOKEN_BYTES = 24
_DELIVERY_TOKEN_SEED_BYTES = 32
Hex32 = Annotated[str, Field(pattern=_HEX32_PATTERN)]


def normalized_https_origin(value: str, *, allow_http_for_tests: bool = False) -> str:
    """Return one normalized origin and reject URL components outside the authority."""

    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > MAX_MIRROR_URL_BYTES
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise ValueError("mirror origin has an invalid size or character")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise ValueError("mirror origin port is invalid") from error
    schemes = {"https"} | ({"http"} if allow_http_for_tests else set())
    if parsed.scheme not in schemes or parsed.hostname is None:
        raise ValueError("mirror origin must use HTTPS")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("mirror origin cannot contain user information")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("mirror origin cannot contain a path, query, or fragment")
    hostname = parsed.hostname.lower().rstrip(".")
    default_port = 443 if parsed.scheme == "https" else 80
    authority = f"[{hostname}]" if ":" in hostname else hostname
    if port is not None and port != default_port:
        authority += f":{port}"
    return f"{parsed.scheme}://{authority}"


class MirrorDiscoveryRule(StrictProtocolModel):
    """Policy-pinned retrieval and post-selection delivery endpoints."""

    schema_: Literal[MIRROR_DISCOVERY_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    authentication_profile: Annotated[str, Field(min_length=1, max_length=128)]
    index_path_template: Literal[DEFAULT_MIRROR_INDEX_PATH]
    delivery_issuance_path: Literal[DEFAULT_DELIVERY_ISSUANCE_PATH]
    origins: Annotated[list[str], Field(min_length=1, max_length=MAX_MIRROR_ORIGINS)]
    delivery_origins: Annotated[list[str], Field(min_length=1, max_length=MAX_MIRROR_ORIGINS)]

    @model_validator(mode="after")
    def validate_origins(self) -> Self:
        retrieval = [normalized_https_origin(value) for value in self.origins]
        delivery = [normalized_https_origin(value) for value in self.delivery_origins]
        if retrieval != sorted(retrieval) or len(set(retrieval)) != len(retrieval):
            raise ValueError("mirror origins must be normalized, unique, and sorted")
        if delivery != sorted(delivery) or len(set(delivery)) != len(delivery):
            raise ValueError("delivery origins must be normalized, unique, and sorted")
        if not set(retrieval).isdisjoint(delivery):
            raise ValueError("delivery origins must be separate from mirror origins")
        retrieval_hosts = [urlsplit(value).hostname for value in retrieval]
        delivery_hosts = [urlsplit(value).hostname for value in delivery]
        if len(set(retrieval_hosts)) != len(retrieval_hosts):
            raise ValueError("mirror origins must use distinct hostnames")
        if len(set(delivery_hosts)) != len(delivery_hosts):
            raise ValueError("delivery origins must use distinct hostnames")
        if not set(retrieval_hosts).isdisjoint(delivery_hosts):
            raise ValueError("retrieval and delivery origins must use separate hostnames")
        return self


def required_availability_quorum(policy: ScoringPolicy) -> int:
    """Return the launch quorum implied by the complete policy validator registry."""

    if not isinstance(policy, ScoringPolicy):
        raise TypeError("mirror quorum policy must be ScoringPolicy")
    validator_count = len(policy.validator_registry)
    return max(3, (2 * validator_count) // 3 + 1)


def validate_mirror_discovery_quorum(
    policy: ScoringPolicy,
    discovery: MirrorDiscoveryRule,
) -> int:
    """Require enough distinct retrieval/delivery pairs for one signer quorum."""

    if not isinstance(discovery, MirrorDiscoveryRule):
        raise TypeError("mirror discovery must be MirrorDiscoveryRule")
    required = required_availability_quorum(policy)
    if len(discovery.origins) != len(discovery.delivery_origins):
        raise ValueError("mirror retrieval and delivery origin counts must match")
    if len(discovery.origins) < required:
        raise ValueError("mirror discovery does not provide one origin pair per quorum signer")
    return required


class VideoDeliveryCommitment(StrictProtocolModel):
    """Selected public media identity, without a validator-only source URL."""

    batch_id: Annotated[str, Field(min_length=1, max_length=64)]
    challenge_id: Annotated[str, Field(min_length=1, max_length=64)]
    sha256: Hex32
    size_bytes: Annotated[int, Field(gt=0, le=_MAX_INTEGER)]

    @model_validator(mode="after")
    def validate_ids(self) -> Self:
        _opaque_id(self.batch_id, "delivery batch ID")
        _opaque_id(self.challenge_id, "delivery challenge ID")
        return self


class VideoDeliveryIssuanceRequest(StrictProtocolModel):
    """Canonical authenticated request for all selected delivery URLs."""

    schema_: Literal[DELIVERY_ISSUANCE_REQUEST_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    window_id: Hex32
    window_index: Annotated[int, Field(ge=0, le=_MAX_INTEGER)]
    scoring_policy_hash: Hex32
    response_close_round: Annotated[int, Field(gt=0, le=_MAX_INTEGER)]
    delivery_token_seed: Annotated[str, Field(min_length=43, max_length=43)]
    items: Annotated[
        list[VideoDeliveryCommitment],
        Field(min_length=1, max_length=MAX_DELIVERY_ITEMS),
    ]

    @model_validator(mode="after")
    def validate_items(self) -> Self:
        try:
            seed = base64url_decode(self.delivery_token_seed)
        except (TypeError, ValueError) as error:
            raise ValueError("delivery token seed is not canonical base64url") from error
        if len(seed) != _DELIVERY_TOKEN_SEED_BYTES:
            raise ValueError("delivery token seed must encode exactly 256 bits")
        _canonical_delivery_rows(self.items)
        return self


class IssuedVideoDelivery(StrictProtocolModel):
    """Credential-free miner-facing URL for one selected media commitment."""

    batch_id: Annotated[str, Field(min_length=1, max_length=64)]
    challenge_id: Annotated[str, Field(min_length=1, max_length=64)]
    sha256: Hex32
    size_bytes: Annotated[int, Field(gt=0, le=_MAX_INTEGER)]
    url: Annotated[str, Field(min_length=1, max_length=MAX_MIRROR_URL_BYTES)]
    expires_at_unix_ms: Annotated[int, Field(gt=0, le=_MAX_INTEGER)]

    @model_validator(mode="after")
    def validate_ids(self) -> Self:
        _opaque_id(self.batch_id, "issued delivery batch ID")
        _opaque_id(self.challenge_id, "issued delivery challenge ID")
        return self


class VideoDeliveryIssuanceResponse(StrictProtocolModel):
    """Canonical mirror response for one complete selected delivery set."""

    schema_: Literal[DELIVERY_ISSUANCE_RESPONSE_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    window_id: Hex32
    window_index: Annotated[int, Field(ge=0, le=_MAX_INTEGER)]
    scoring_policy_hash: Hex32
    response_close_round: Annotated[int, Field(gt=0, le=_MAX_INTEGER)]
    deliveries: Annotated[
        list[IssuedVideoDelivery],
        Field(min_length=1, max_length=MAX_DELIVERY_ITEMS),
    ]

    @model_validator(mode="after")
    def validate_deliveries(self) -> Self:
        _canonical_delivery_rows(self.deliveries)
        return self


class VideoDeliveryAttemptEvidence(StrictProtocolModel):
    """One durable delivery-issuance attempt, including bounded failed bodies."""

    attempt_index: Annotated[int, Field(ge=0, le=255)]
    url_sha256: Hex32
    status: Literal["pending_after_restart", "failed", "success"]
    observed_wire_bytes: Annotated[int, Field(ge=0, le=_MAX_INTEGER)]
    accounted_wire_bytes: Annotated[int, Field(gt=0, le=_MAX_INTEGER)]
    error_code: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9_.-]*$")] | None
    response_body_sha256: Hex32 | None
    response_body_size_bytes: Annotated[int, Field(ge=0, le=_MAX_INTEGER)]

    @model_validator(mode="after")
    def validate_attempt(self) -> Self:
        if (self.status == "success") != (self.error_code is None):
            raise ValueError("delivery attempt status and error code disagree")
        if self.observed_wire_bytes > self.accounted_wire_bytes:
            raise ValueError("delivery attempt observed bytes exceed its reservation")
        if self.response_body_sha256 is None and self.response_body_size_bytes != 0:
            raise ValueError("delivery attempt body size lacks its digest")
        return self


class VideoDeliveryIssuanceEvidence(StrictProtocolModel):
    """Public transcript binding an authenticated issuance exchange to exact bytes."""

    schema_: Literal[DELIVERY_ISSUANCE_EVIDENCE_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    window_id: Hex32
    window_index: Annotated[int, Field(ge=0, le=_MAX_INTEGER)]
    scoring_policy_hash: Hex32
    discovery_rule_sha256: Hex32
    authentication_profile: Annotated[str, Field(min_length=1, max_length=128)]
    issuance_origin: Annotated[str, Field(min_length=1, max_length=MAX_MIRROR_URL_BYTES)]
    issuance_path: Literal[DEFAULT_DELIVERY_ISSUANCE_PATH]
    request_sha256: Hex32
    request_size_bytes: Annotated[int, Field(gt=0, le=_MAX_INTEGER)]
    response_sha256: Hex32
    response_size_bytes: Annotated[int, Field(gt=0, le=_MAX_INTEGER)]
    attempts: Annotated[list[VideoDeliveryAttemptEvidence], Field(min_length=1, max_length=255)]
    delivery_observed_wire_bytes: Annotated[int, Field(gt=0, le=_MAX_INTEGER)]
    delivery_accounted_wire_bytes: Annotated[int, Field(gt=0, le=_MAX_INTEGER)]
    observed_window_wire_bytes: Annotated[int, Field(gt=0, le=_MAX_INTEGER)]
    accounted_window_wire_bytes: Annotated[int, Field(gt=0, le=_MAX_INTEGER)]

    @model_validator(mode="after")
    def validate_accounting(self) -> Self:
        indices = [item.attempt_index for item in self.attempts]
        if indices != list(range(len(self.attempts))):
            raise ValueError("delivery attempts must be contiguous and ordered")
        successes = [item for item in self.attempts if item.status == "success"]
        if len(successes) != 1 or self.attempts[-1].status != "success":
            raise ValueError("delivery attempts must end in exactly one success")
        if successes[0].response_body_sha256 != self.response_sha256:
            raise ValueError("successful delivery attempt has another response digest")
        if successes[0].response_body_size_bytes != self.response_size_bytes:
            raise ValueError("successful delivery attempt has another response size")
        if self.delivery_observed_wire_bytes != sum(
            item.observed_wire_bytes for item in self.attempts
        ):
            raise ValueError("delivery observed-byte total does not reproduce")
        if self.delivery_accounted_wire_bytes != sum(
            item.accounted_wire_bytes for item in self.attempts
        ):
            raise ValueError("delivery accounted-byte total does not reproduce")
        if self.delivery_observed_wire_bytes > self.delivery_accounted_wire_bytes:
            raise ValueError("delivery observed bytes exceed reserved accounting")
        if self.observed_window_wire_bytes < self.delivery_observed_wire_bytes:
            raise ValueError("window observed bytes omit delivery attempts")
        if self.accounted_window_wire_bytes < self.delivery_accounted_wire_bytes:
            raise ValueError("window accounted bytes omit delivery attempts")
        if self.observed_window_wire_bytes > self.accounted_window_wire_bytes:
            raise ValueError("window observed bytes exceed reserved accounting")
        return self


@dataclass(frozen=True, slots=True)
class IssuedVideoDeliverySet:
    """Exact bytes and typed URLs returned by a delivery issuance port."""

    deliveries: tuple[IssuedVideoDelivery, ...]
    discovery_rule_bytes: bytes
    request_bytes: bytes
    response_bytes: bytes
    evidence_bytes: bytes

    def __post_init__(self) -> None:
        if not self.deliveries or any(
            not isinstance(item, IssuedVideoDelivery) for item in self.deliveries
        ):
            raise TypeError("issued delivery set must contain typed deliveries")
        for name in (
            "discovery_rule_bytes",
            "request_bytes",
            "response_bytes",
            "evidence_bytes",
        ):
            value = getattr(self, name)
            if not isinstance(value, bytes) or not value:
                raise TypeError(f"{name} must be nonempty exact bytes")


def parse_canonical_model(data: bytes, model_type: type, *, maximum_bytes: int, label: str):
    """Parse one bounded model and require its exact RFC 8785 representation."""

    if not isinstance(data, bytes) or not data or len(data) > maximum_bytes:
        raise ValueError(f"{label} has an invalid byte length")
    try:
        value = model_type.model_validate_json(data)
    except Exception as error:
        raise ValueError(f"{label} is invalid") from error
    if canonical_json_bytes(value) != data:
        raise ValueError(f"{label} is not canonical JSON")
    return value


def validate_delivery_issuance(
    *,
    policy: ScoringPolicy,
    window: WindowPlan,
    expected_commitments: tuple[VideoDeliveryCommitment, ...],
    result: IssuedVideoDeliverySet,
    private_source_urls: tuple[str, ...] = (),
) -> tuple[IssuedVideoDelivery, ...]:
    """Reproduce the complete issuance exchange and return its bound deliveries."""

    if not isinstance(policy, ScoringPolicy) or not isinstance(window, WindowPlan):
        raise TypeError("delivery validation requires a scoring policy and window plan")
    if not expected_commitments:
        raise ValueError("delivery validation requires selected media commitments")
    _canonical_delivery_rows(expected_commitments)
    if not isinstance(result, IssuedVideoDeliverySet):
        raise TypeError("delivery issuance result has another type")
    maximum = policy.limits.maximum_manifest_bytes
    discovery = parse_canonical_model(
        result.discovery_rule_bytes,
        MirrorDiscoveryRule,
        maximum_bytes=maximum,
        label="mirror discovery rule",
    )
    discovery_hash = hashlib.sha256(result.discovery_rule_bytes).hexdigest()
    if (
        discovery_hash != policy.implementation_pins.rules.mirror_discovery_rule_sha256
        or discovery.authentication_profile
        != policy.implementation_pins.rules.mirror_authentication_profile
    ):
        raise ValueError("delivery discovery rule disagrees with the scoring policy")
    request = parse_canonical_model(
        result.request_bytes,
        VideoDeliveryIssuanceRequest,
        maximum_bytes=maximum,
        label="video delivery issuance request",
    )
    response = parse_canonical_model(
        result.response_bytes,
        VideoDeliveryIssuanceResponse,
        maximum_bytes=maximum,
        label="video delivery issuance response",
    )
    evidence = parse_canonical_model(
        result.evidence_bytes,
        VideoDeliveryIssuanceEvidence,
        maximum_bytes=maximum,
        label="video delivery issuance evidence",
    )
    deliveries = validate_delivery_response(
        policy=policy,
        window=window,
        discovery=discovery,
        request=request,
        response=response,
        expected_commitments=expected_commitments,
        private_source_urls=private_source_urls,
    )
    if deliveries != result.deliveries:
        raise ValueError("delivery issuance response and result tuple disagree")
    policy_hash = scoring_policy_hash(policy)
    if (
        evidence.window_id != window.window_id
        or evidence.window_index != window.window_index
        or evidence.scoring_policy_hash != policy_hash
        or evidence.discovery_rule_sha256 != discovery_hash
        or evidence.authentication_profile != discovery.authentication_profile
        or evidence.issuance_origin not in discovery.origins
        or evidence.issuance_path != discovery.delivery_issuance_path
        or evidence.request_sha256 != hashlib.sha256(result.request_bytes).hexdigest()
        or evidence.request_size_bytes != len(result.request_bytes)
        or evidence.response_sha256 != hashlib.sha256(result.response_bytes).hexdigest()
        or evidence.response_size_bytes != len(result.response_bytes)
    ):
        raise ValueError("delivery issuance evidence does not reproduce")
    if (
        len(evidence.attempts) > policy.limits.maximum_video_fetch_attempts_per_actor
        or evidence.accounted_window_wire_bytes > policy.limits.maximum_validator_window_wire_bytes
    ):
        raise ValueError("delivery issuance evidence exceeds a policy ceiling")
    attempted_origins = discovery.origins[: len(evidence.attempts)]
    if (
        len(attempted_origins) != len(evidence.attempts)
        or [item.url_sha256 for item in evidence.attempts]
        != [
            hashlib.sha256((origin + discovery.delivery_issuance_path).encode("utf-8")).hexdigest()
            for origin in attempted_origins
        ]
        or evidence.issuance_origin != attempted_origins[-1]
    ):
        raise ValueError("delivery attempt evidence does not follow pinned origin order")
    return result.deliveries


def validate_delivery_response(
    *,
    policy: ScoringPolicy,
    window: WindowPlan,
    discovery: MirrorDiscoveryRule,
    request: VideoDeliveryIssuanceRequest,
    response: VideoDeliveryIssuanceResponse,
    expected_commitments: tuple[VideoDeliveryCommitment, ...],
    private_source_urls: tuple[str, ...] = (),
) -> tuple[IssuedVideoDelivery, ...]:
    """Validate a candidate response before it can become durable success."""

    if not isinstance(policy, ScoringPolicy) or not isinstance(window, WindowPlan):
        raise TypeError("delivery response validation requires policy and window models")
    if not isinstance(discovery, MirrorDiscoveryRule):
        raise TypeError("delivery response validation requires a discovery rule")
    if not isinstance(request, VideoDeliveryIssuanceRequest) or not isinstance(
        response, VideoDeliveryIssuanceResponse
    ):
        raise TypeError("delivery response validation requires canonical request/response models")
    _canonical_delivery_rows(expected_commitments)
    policy_hash = scoring_policy_hash(policy)
    common = (
        window.window_id,
        window.window_index,
        policy_hash,
        window.response_close_round,
    )
    if (
        (
            request.window_id,
            request.window_index,
            request.scoring_policy_hash,
            request.response_close_round,
        )
        != common
        or (
            response.window_id,
            response.window_index,
            response.scoring_policy_hash,
            response.response_close_round,
        )
        != common
        or tuple(request.items) != expected_commitments
    ):
        raise ValueError("delivery issuance changes its window or selected commitments")
    deliveries = tuple(response.deliveries)
    expected_by_key = {(item.batch_id, item.challenge_id): item for item in expected_commitments}
    if len(expected_by_key) != len(expected_commitments):
        raise ValueError("selected delivery commitments are duplicated")
    delivery_by_key = {(item.batch_id, item.challenge_id): item for item in deliveries}
    if len(delivery_by_key) != len(deliveries) or set(delivery_by_key) != set(expected_by_key):
        raise ValueError("issued delivery set is incomplete or duplicated")
    if len({item.url for item in deliveries}) != len(deliveries):
        raise ValueError("issued delivery URLs must be unique")
    response_close_ms = QUICKNET_GENESIS_MS + (window.response_close_round - 1) * QUICKNET_PERIOD_MS
    latest_expiry_ms = response_close_ms + policy.clock.delivery_grace_seconds * 1_000
    private_urls = set(private_source_urls)
    for key, delivery in delivery_by_key.items():
        commitment = expected_by_key[key]
        if delivery.sha256 != commitment.sha256 or delivery.size_bytes != commitment.size_bytes:
            raise ValueError("issued delivery changes its selected media commitment")
        _origin, token = _validate_delivery_url(delivery.url, discovery.delivery_origins)
        if token != derive_delivery_token(request, commitment):
            raise ValueError("issued delivery URL does not bind the validator token seed")
        if delivery.url in private_urls:
            raise ValueError("issued delivery exposes a validator-only source URL")
        if not response_close_ms <= delivery.expires_at_unix_ms <= latest_expiry_ms:
            raise ValueError("issued delivery expiry is outside the policy window")
    return deliveries


def build_delivery_request(
    window: WindowPlan,
    commitments: tuple[VideoDeliveryCommitment, ...],
    *,
    delivery_token_seed: str,
) -> VideoDeliveryIssuanceRequest:
    """Build the only canonical request accepted by the post-selection port."""

    _canonical_delivery_rows(commitments)
    return VideoDeliveryIssuanceRequest(
        schema=DELIVERY_ISSUANCE_REQUEST_SCHEMA,
        protocol=PROTOCOL_VERSION,
        window_id=window.window_id,
        window_index=window.window_index,
        scoring_policy_hash=window.scoring_policy_hash,
        response_close_round=window.response_close_round,
        delivery_token_seed=delivery_token_seed,
        items=list(commitments),
    )


def derive_delivery_token(
    request: VideoDeliveryIssuanceRequest,
    commitment: VideoDeliveryCommitment,
) -> str:
    """Derive one miner-facing bearer token from validator-chosen random seed."""

    if not isinstance(request, VideoDeliveryIssuanceRequest) or not isinstance(
        commitment, VideoDeliveryCommitment
    ):
        raise TypeError("delivery token derivation requires canonical protocol models")
    digest = hashlib.sha256(
        b"umi-video-delivery-token-v1\0"
        + base64url_decode(request.delivery_token_seed)
        + bytes.fromhex(request.window_id)
        + request.window_index.to_bytes(8, "big")
        + bytes.fromhex(request.scoring_policy_hash)
        + request.response_close_round.to_bytes(8, "big")
        + base64url_decode(commitment.batch_id)
        + base64url_decode(commitment.challenge_id)
        + bytes.fromhex(commitment.sha256)
        + commitment.size_bytes.to_bytes(8, "big")
    ).digest()
    return base64url_encode(digest[:_DELIVERY_TOKEN_BYTES])


def _validate_delivery_url(value: str, allowed_origins: list[str]) -> tuple[str, str]:
    origin, token = _validate_delivery_url_shape(value)
    if origin not in allowed_origins:
        raise ValueError("issued delivery URL origin is not policy-pinned")
    return origin, token


def _validate_delivery_url_shape(value: str) -> tuple[str, str]:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > MAX_MIRROR_URL_BYTES
        or "\\" in value
        or any(ord(character) < 0x20 or ord(character) > 0x7E for character in value)
    ):
        raise ValueError("issued delivery URL contains an invalid character")
    if "%" in value:
        raise ValueError("issued delivery URL cannot contain percent encoding")
    try:
        parsed = urlsplit(value)
        _ = parsed.port
    except ValueError as error:
        raise ValueError("issued delivery URL is invalid") from error
    if parsed.scheme != "https" or parsed.hostname is None or not parsed.path.startswith("/"):
        raise ValueError("issued delivery URL must be absolute HTTPS")
    if (
        parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("issued delivery URL cannot contain credentials, a query, or a fragment")
    origin = normalized_https_origin(f"{parsed.scheme}://{parsed.netloc}")
    if value != origin + parsed.path:
        raise ValueError("issued delivery URL must use its canonical origin spelling")
    if not parsed.path.startswith(DEFAULT_DELIVERY_OBJECT_PATH_PREFIX):
        raise ValueError("issued delivery URL path is outside the fixed delivery namespace")
    token = parsed.path.removeprefix(DEFAULT_DELIVERY_OBJECT_PATH_PREFIX)
    if _DELIVERY_TOKEN_PATTERN.fullmatch(token) is None:
        raise ValueError("issued delivery URL must contain one opaque 192-bit token")
    try:
        decoded = base64url_decode(token)
    except (TypeError, ValueError) as error:
        raise ValueError("issued delivery URL token is not canonical base64url") from error
    if len(decoded) != _DELIVERY_TOKEN_BYTES:
        raise ValueError("issued delivery URL token must encode exactly 192 bits")
    return origin, token


def _canonical_delivery_rows(rows) -> None:
    keys = [(base64url_decode(item.batch_id), base64url_decode(item.challenge_id)) for item in rows]
    if keys != sorted(keys) or len(set(keys)) != len(keys):
        raise ValueError("delivery rows must be unique and sorted by batch/challenge ID")


def _opaque_id(value: str, label: str) -> bytes:
    try:
        decoded = base64url_decode(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{label} is invalid") from error
    if len(decoded) != 16:
        raise ValueError(f"{label} must encode exactly 16 bytes")
    return decoded


__all__ = [
    "DEFAULT_DELIVERY_ISSUANCE_PATH",
    "DEFAULT_DELIVERY_OBJECT_PATH_PREFIX",
    "DEFAULT_MIRROR_INDEX_PATH",
    "DELIVERY_ISSUANCE_EVIDENCE_SCHEMA",
    "DELIVERY_ISSUANCE_REQUEST_SCHEMA",
    "DELIVERY_ISSUANCE_RESPONSE_SCHEMA",
    "MIRROR_DISCOVERY_SCHEMA",
    "IssuedVideoDelivery",
    "IssuedVideoDeliverySet",
    "MirrorDiscoveryRule",
    "VideoDeliveryAttemptEvidence",
    "VideoDeliveryCommitment",
    "VideoDeliveryIssuanceEvidence",
    "VideoDeliveryIssuanceRequest",
    "VideoDeliveryIssuanceResponse",
    "build_delivery_request",
    "derive_delivery_token",
    "normalized_https_origin",
    "parse_canonical_model",
    "validate_delivery_issuance",
    "validate_delivery_response",
]
