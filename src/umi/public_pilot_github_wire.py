"""Canonical wire encoding for the public-pilot GitHub automation boundary.

This module deliberately uses only the Python standard library.  The GitHub
Actions entry point imports it directly from ``src`` without installing UMI's
runtime dependencies, while the coordinator-facing Pydantic models use the
same functions for identifiers, markers, and result-envelope authentication.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from collections.abc import Mapping
from typing import Any

AUTHORIZATION_SCHEMA = "umi-public-pilot-github-authorization/1"
AUTHORIZATION_DOMAIN = b"umi-public-pilot-github-authorization-v1\0"
AUTHORIZATION_MARKER_PREFIX = "<!-- umi-public-pilot-authorization-v1:"

CHALLENGE_SCHEMA = "umi-public-pilot-github-challenge/1"
CHALLENGE_DOMAIN = b"umi-public-pilot-github-challenge-v1\0"
CHALLENGE_MARKER_PREFIX = "<!-- umi-public-pilot-challenge-v1:"

RESULT_ENVELOPE_SCHEMA = "umi-public-pilot-automation-result-envelope/1"
RESULT_PAYLOAD_SCHEMA = "umi-public-pilot-automation-result/1"
RESULT_DOMAIN = b"umi-public-pilot-automation-result-v1\0"
RESULT_MARKER_PREFIX = "<!-- umi-public-pilot-result-v1:"

MAX_JSON_SAFE_INTEGER = (1 << 53) - 1
MAX_MARKER_PAYLOAD_BYTES = 16 * 1024
MAX_RESULT_ENVELOPE_BYTES = 64 * 1024
MAX_ARCHIVE_BYTES = 96 * 1024 * 1024

PUBLIC_PILOT_READINESS_CONFIRMATIONS = (
    "My hotkey is registered on SN78, has no validator permit, and I control the wallet "
    "needed to publish its axon endpoint.",
    "Before I report ready, the endpoint will have a valid certificate for its literal IP "
    "and will forward only to my loopback UMI pilot service.",
    "Before I report ready, I will test my stable globally routable IP from another network "
    "and configure renewal for its short-lived IP certificate.",
    "I recorded any previous axon endpoint and understand that serve/reset writes are "
    "rate-limited and may interrupt or delay restoration of a production service.",
    "I understand this uses one known public clip and measures protocol and endpoint "
    "interoperability, not benchmark quality or weight eligibility.",
    "I understand enrollment starts no request traffic. I will sign the bot's fresh `READY "
    "FOR CASE` payload only when I can load a fresh case promptly and stay online through "
    "reveal. The coordinator may briefly serialize issuance when several miners are ready.",
    "I understand UMI publishes a completed outcome, or reports a verified non-feed journal "
    "after a later local failure, and will not rerun after possible issuance.",
)
_LEGACY_SCHEDULED_READINESS_CONFIRMATION = (
    "I understand enrollment starts no request traffic. I will wait for UMI's scheduling "
    "comment and post `READY FOR CASE` only when I can load the case promptly and stay "
    "online through reveal."
)
_LEGACY_OPEN_READINESS_CONFIRMATION = (
    "I understand enrollment starts no request traffic. I will post `READY FOR CASE` only "
    "when I can load a fresh case promptly and stay online through reveal. The coordinator "
    "may briefly serialize issuance when several miners are ready."
)
PUBLIC_PILOT_READINESS_CONFIRMATION_PROFILES = (
    PUBLIC_PILOT_READINESS_CONFIRMATIONS,
    (*PUBLIC_PILOT_READINESS_CONFIRMATIONS[:5], PUBLIC_PILOT_READINESS_CONFIRMATIONS[6]),
    (
        "My hotkey is registered on SN78 and has no validator permit.",
        "My HTTPS endpoint is announced on chain and serves a publicly trusted certificate "
        "for the announced IP.",
        PUBLIC_PILOT_READINESS_CONFIRMATIONS[4],
        _LEGACY_SCHEDULED_READINESS_CONFIRMATION,
        PUBLIC_PILOT_READINESS_CONFIRMATIONS[6],
    ),
    (
        *PUBLIC_PILOT_READINESS_CONFIRMATIONS[:5],
        _LEGACY_OPEN_READINESS_CONFIRMATION,
        PUBLIC_PILOT_READINESS_CONFIRMATIONS[6],
    ),
)

_HEX32_RE = re.compile(r"^[0-9a-f]{64}$")
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]+$")

AUTHORIZATION_FIELDS = frozenset(
    {
        "schema",
        "authorization_id",
        "action",
        "repository_id",
        "repository_full_name",
        "issue_id",
        "issue_node_id",
        "issue_number",
        "issue_body_sha256",
        "command_comment_id",
        "command_node_id",
        "command_created_at",
        "actor_id",
        "actor_login",
        "command_body_sha256",
        "challenge_nonce",
        "campaign_id",
        "umi_revision",
        "predecessor_authorization_id",
    }
)

RESULT_COMMON_FIELDS = frozenset(
    {
        "schema",
        "authorization_id",
        "action",
        "repository_id",
        "repository_full_name",
        "issue_id",
        "issue_node_id",
        "issue_number",
        "campaign_id",
        "umi_revision",
        "coordinator_hotkey",
        "miner_hotkey",
        "expected_miner_uid",
        "completed_at",
        "status",
    }
)
RESULT_CASE_FIELDS = frozenset(
    {
        "case_manifest_sha256",
        "case_archive_sha256",
        "case_archive_size_bytes",
        "case_archive_url",
        "expected_origin",
        "response_close_round",
        "reveal_round",
        "response_close_at",
        "reveal_at",
    }
)
RESULT_EVIDENCE_FIELDS = frozenset(
    {
        "evidence_manifest_sha256",
        "evidence_archive_sha256",
        "evidence_archive_size_bytes",
        "evidence_archive_url",
        "outcome_classification",
        "failure_code",
        "request_digest",
    }
)
RESULT_ATTEMPT_FIELDS = frozenset(
    {
        "attempt_journal_manifest_sha256",
        "attempt_archive_sha256",
        "attempt_archive_size_bytes",
        "attempt_archive_url",
        "completed_through",
        "failure_stage",
        "failure_code",
        "request_digest",
    }
)


class PublicPilotWireError(ValueError):
    """A public-pilot wire value is malformed or unauthenticated."""


def canonical_json_bytes(value: Any) -> bytes:
    """Encode the JSON subset used by this protocol in RFC 8785 form.

    Protocol objects contain only JSON-safe integers, strings, nulls, lists,
    and dictionaries with string keys.  For that deliberately constrained
    subset, Python's sorted compact encoder produces the RFC 8785 byte form.
    Rejecting floats also avoids cross-runtime number-format differences.
    """

    _validate_json_subset(value)
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, UnicodeEncodeError, ValueError) as error:
        raise PublicPilotWireError("value is not canonicalizable JSON") from error


def readiness_confirmation_lines_match(lines: tuple[str, ...]) -> bool:
    """Accept only one exact, versioned issue-form confirmation profile."""

    if not isinstance(lines, tuple) or any(not isinstance(line, str) for line in lines):
        return False
    return any(
        len(lines) == len(profile)
        and all(
            line in {f"- [x] {label}", f"- [X] {label}"}
            for line, label in zip(lines, profile, strict=True)
        )
        for profile in PUBLIC_PILOT_READINESS_CONFIRMATION_PROFILES
    )


def parse_canonical_json_bytes(raw: bytes, *, maximum_bytes: int) -> Any:
    """Decode bounded canonical JSON, rejecting duplicate object keys."""

    if not isinstance(raw, bytes) or not raw or len(raw) > maximum_bytes:
        raise PublicPilotWireError("canonical JSON has an invalid size")
    try:
        text = raw.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, PublicPilotWireError) as error:
        raise PublicPilotWireError("canonical JSON is invalid") from error
    if not hmac.compare_digest(canonical_json_bytes(value), raw):
        raise PublicPilotWireError("JSON is not canonical RFC 8785 bytes")
    return value


def base64url_encode(raw: bytes) -> str:
    """Return unpadded RFC 4648 base64url."""

    if not isinstance(raw, bytes):
        raise TypeError("raw must be bytes")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def base64url_decode(token: str, *, maximum_bytes: int) -> bytes:
    """Strictly decode canonical, unpadded base64url."""

    if (
        not isinstance(token, str)
        or not token
        or len(token) > ((maximum_bytes * 4 + 2) // 3)
        or _TOKEN_RE.fullmatch(token) is None
    ):
        raise PublicPilotWireError("base64url token is invalid")
    try:
        raw = base64.b64decode(
            token + "=" * ((-len(token)) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, base64.binascii.Error) as error:
        raise PublicPilotWireError("base64url token is invalid") from error
    if not raw or len(raw) > maximum_bytes or not hmac.compare_digest(base64url_encode(raw), token):
        raise PublicPilotWireError("base64url token is not canonical")
    return raw


def authorization_id(payload_without_id: Mapping[str, Any]) -> str:
    """Derive the immutable authorization identifier from its unsigned fields."""

    if "authorization_id" in payload_without_id:
        raise PublicPilotWireError("authorization_id input must omit authorization_id")
    encoded = canonical_json_bytes(dict(payload_without_id))
    return hashlib.sha256(AUTHORIZATION_DOMAIN + encoded).hexdigest()


def build_authorization_payload(fields_without_id: Mapping[str, Any]) -> dict[str, Any]:
    """Insert and validate the deterministic authorization identifier."""

    payload = dict(fields_without_id)
    payload["authorization_id"] = authorization_id(payload)
    validate_authorization_payload(payload)
    return payload


def validate_authorization_payload(payload: Any) -> dict[str, Any]:
    """Validate the exact GitHub authorization payload field contract."""

    if not isinstance(payload, dict) or set(payload) != AUTHORIZATION_FIELDS:
        raise PublicPilotWireError("authorization payload fields are invalid")
    if payload.get("schema") != AUTHORIZATION_SCHEMA:
        raise PublicPilotWireError("authorization schema is invalid")
    if payload.get("action") not in {"ready_for_case", "ready_to_issue"}:
        raise PublicPilotWireError("authorization action is invalid")
    for field in (
        "repository_id",
        "issue_id",
        "issue_number",
        "command_comment_id",
        "actor_id",
    ):
        _require_positive_json_integer(payload.get(field), field)
    for field in ("issue_node_id", "command_node_id"):
        _require_visible_ascii(payload.get(field), field, maximum_bytes=256)
    _require_repository_full_name(payload.get("repository_full_name"))
    _require_github_login(payload.get("actor_login"))
    _require_rfc3339_seconds(payload.get("command_created_at"), "command_created_at")
    for field in (
        "authorization_id",
        "issue_body_sha256",
        "command_body_sha256",
        "challenge_nonce",
        "campaign_id",
    ):
        _require_hex32(payload.get(field), field)
    revision = payload.get("umi_revision")
    if not isinstance(revision, str) or re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        raise PublicPilotWireError("umi_revision must be 40 lowercase hexadecimal characters")
    predecessor = payload.get("predecessor_authorization_id")
    if payload["action"] == "ready_for_case":
        if predecessor is not None:
            raise PublicPilotWireError("ready_for_case must not have a predecessor")
    else:
        _require_hex32(predecessor, "predecessor_authorization_id")
    without_id = {key: value for key, value in payload.items() if key != "authorization_id"}
    expected_id = authorization_id(without_id)
    if not hmac.compare_digest(payload["authorization_id"], expected_id):
        raise PublicPilotWireError("authorization_id does not match its payload")
    return payload


def build_authorization_marker(payload: Mapping[str, Any], key: bytes) -> str:
    """Create the coordinator-consumed, HMAC-authenticated authorization line."""

    checked = validate_authorization_payload(dict(payload))
    encoded = canonical_json_bytes(checked)
    mac = _hmac_hex(key, AUTHORIZATION_DOMAIN + encoded)
    return f"{AUTHORIZATION_MARKER_PREFIX}{base64url_encode(encoded)}:{mac} -->"


def parse_authorization_marker(marker: str, key: bytes) -> dict[str, Any]:
    """Parse and authenticate one exact authorization comment line."""

    token, supplied_mac = _split_authenticated_marker(
        marker,
        prefix=AUTHORIZATION_MARKER_PREFIX,
    )
    raw = base64url_decode(token, maximum_bytes=MAX_MARKER_PAYLOAD_BYTES)
    expected_mac = _hmac_hex(key, AUTHORIZATION_DOMAIN + raw)
    if not hmac.compare_digest(supplied_mac, expected_mac):
        raise PublicPilotWireError("authorization marker HMAC is invalid")
    return validate_authorization_payload(
        parse_canonical_json_bytes(raw, maximum_bytes=MAX_MARKER_PAYLOAD_BYTES)
    )


def build_challenge_marker(payload: Mapping[str, Any], key: bytes) -> str:
    """Create an authenticated hidden marker for an issued challenge."""

    encoded = canonical_json_bytes(dict(payload))
    if len(encoded) > MAX_MARKER_PAYLOAD_BYTES:
        raise PublicPilotWireError("challenge marker payload is too large")
    mac = _hmac_hex(key, CHALLENGE_DOMAIN + encoded)
    return f"{CHALLENGE_MARKER_PREFIX}{base64url_encode(encoded)}:{mac} -->"


def parse_challenge_marker(marker: str, key: bytes) -> dict[str, Any]:
    """Parse and authenticate one exact hidden challenge marker."""

    token, supplied_mac = _split_authenticated_marker(marker, prefix=CHALLENGE_MARKER_PREFIX)
    raw = base64url_decode(token, maximum_bytes=MAX_MARKER_PAYLOAD_BYTES)
    expected_mac = _hmac_hex(key, CHALLENGE_DOMAIN + raw)
    if not hmac.compare_digest(supplied_mac, expected_mac):
        raise PublicPilotWireError("challenge marker HMAC is invalid")
    payload = parse_canonical_json_bytes(raw, maximum_bytes=MAX_MARKER_PAYLOAD_BYTES)
    if not isinstance(payload, dict) or payload.get("schema") != CHALLENGE_SCHEMA:
        raise PublicPilotWireError("challenge marker payload is invalid")
    return payload


def build_result_envelope(payload: Mapping[str, Any], key: bytes) -> bytes:
    """Create the canonical, independently authenticated result envelope."""

    checked = validate_result_payload(dict(payload))
    payload_bytes = canonical_json_bytes(checked)
    envelope = {
        "schema": RESULT_ENVELOPE_SCHEMA,
        "payload": checked,
        "hmac_sha256": _hmac_hex(key, RESULT_DOMAIN + payload_bytes),
    }
    encoded = canonical_json_bytes(envelope)
    if len(encoded) > MAX_RESULT_ENVELOPE_BYTES:
        raise PublicPilotWireError("result envelope is too large")
    return encoded


def parse_result_envelope(raw: bytes, key: bytes) -> dict[str, Any]:
    """Parse canonical result bytes and authenticate their payload."""

    envelope = parse_canonical_json_bytes(raw, maximum_bytes=MAX_RESULT_ENVELOPE_BYTES)
    if not isinstance(envelope, dict) or set(envelope) != {"schema", "payload", "hmac_sha256"}:
        raise PublicPilotWireError("result envelope fields are invalid")
    if envelope.get("schema") != RESULT_ENVELOPE_SCHEMA:
        raise PublicPilotWireError("result envelope schema is invalid")
    payload = envelope.get("payload")
    if not isinstance(payload, dict) or payload.get("schema") != RESULT_PAYLOAD_SCHEMA:
        raise PublicPilotWireError("result payload is invalid")
    supplied_mac = envelope.get("hmac_sha256")
    _require_hex32(supplied_mac, "hmac_sha256")
    expected_mac = _hmac_hex(key, RESULT_DOMAIN + canonical_json_bytes(payload))
    if not hmac.compare_digest(supplied_mac, expected_mac):
        raise PublicPilotWireError("result envelope HMAC is invalid")
    return validate_result_payload(payload)


def validate_result_payload(payload: Any) -> dict[str, Any]:
    """Validate exact result variant fields and dependency-neutral wire types."""

    if not isinstance(payload, dict):
        raise PublicPilotWireError("result payload must be an object")
    action = payload.get("action")
    if action == "ready_for_case":
        if set(payload) != RESULT_COMMON_FIELDS | RESULT_CASE_FIELDS:
            raise PublicPilotWireError("case result fields are invalid")
        if payload.get("status") != "case_ready":
            raise PublicPilotWireError("case result status is invalid")
        for field in ("case_manifest_sha256", "case_archive_sha256"):
            _require_hex32(payload.get(field), field)
        _require_positive_json_integer(
            payload.get("case_archive_size_bytes"), "case_archive_size_bytes"
        )
        if payload["case_archive_size_bytes"] > MAX_ARCHIVE_BYTES:
            raise PublicPilotWireError("case archive exceeds its byte ceiling")
        for field in ("response_close_round", "reveal_round"):
            _require_positive_json_integer(payload.get(field), field)
        for field in ("response_close_at", "reveal_at"):
            _require_rfc3339_seconds(payload.get(field), field)
        for field in ("case_archive_url", "expected_origin"):
            _require_ascii_text(payload.get(field), field, maximum_bytes=2_048)
    elif action == "ready_to_issue":
        status = payload.get("status")
        variant_fields = (
            RESULT_ATTEMPT_FIELDS if status == "pilot_incomplete" else RESULT_EVIDENCE_FIELDS
        )
        if set(payload) != RESULT_COMMON_FIELDS | variant_fields:
            raise PublicPilotWireError("terminal result fields are invalid")
        if status not in {"pilot_complete", "pilot_incomplete"}:
            raise PublicPilotWireError("terminal result status is invalid")
        if status == "pilot_incomplete":
            for field in (
                "attempt_journal_manifest_sha256",
                "attempt_archive_sha256",
                "request_digest",
            ):
                _require_hex32(payload.get(field), field)
            _require_positive_json_integer(
                payload.get("attempt_archive_size_bytes"), "attempt_archive_size_bytes"
            )
            if payload["attempt_archive_size_bytes"] > MAX_ARCHIVE_BYTES:
                raise PublicPilotWireError("attempt archive exceeds its byte ceiling")
            _require_ascii_text(
                payload.get("attempt_archive_url"),
                "attempt_archive_url",
                maximum_bytes=2_048,
            )
            if payload.get("completed_through") not in {
                "attempt_started",
                "outcome_recorded",
                "base_component_complete",
            }:
                raise PublicPilotWireError("completed_through is invalid")
            if payload.get("failure_stage") not in {
                "request_send",
                "reveal_and_scoring",
                "attachment",
                "publication",
            }:
                raise PublicPilotWireError("failure_stage is invalid")
        else:
            for field in (
                "evidence_manifest_sha256",
                "evidence_archive_sha256",
                "request_digest",
            ):
                _require_hex32(payload.get(field), field)
            _require_positive_json_integer(
                payload.get("evidence_archive_size_bytes"), "evidence_archive_size_bytes"
            )
            if payload["evidence_archive_size_bytes"] > MAX_ARCHIVE_BYTES:
                raise PublicPilotWireError("evidence archive exceeds its byte ceiling")
            _require_ascii_text(
                payload.get("evidence_archive_url"),
                "evidence_archive_url",
                maximum_bytes=2_048,
            )
            if payload.get("outcome_classification") not in {"ok", "signed_error", "failed"}:
                raise PublicPilotWireError("outcome_classification is invalid")
        failure_code = payload.get("failure_code")
        if (status == "pilot_incomplete" and failure_code is None) or (
            failure_code is not None
            and (
                not isinstance(failure_code, str)
                or re.fullmatch(r"[a-z0-9_]{1,64}", failure_code) is None
            )
        ):
            raise PublicPilotWireError("failure_code is invalid")
        if (
            status == "pilot_complete"
            and payload.get("outcome_classification") == "failed"
            and failure_code is None
        ):
            raise PublicPilotWireError("failed outcome must carry a failure_code")
    else:
        raise PublicPilotWireError("result action is invalid")

    if payload.get("schema") != RESULT_PAYLOAD_SCHEMA:
        raise PublicPilotWireError("result payload schema is invalid")
    for field in ("repository_id", "issue_id", "issue_number"):
        _require_positive_json_integer(payload.get(field), field)
    expected_uid = payload.get("expected_miner_uid")
    if (
        isinstance(expected_uid, bool)
        or not isinstance(expected_uid, int)
        or not 0 <= expected_uid <= 65_535
    ):
        raise PublicPilotWireError("expected_miner_uid is invalid")
    _require_repository_full_name(payload.get("repository_full_name"))
    _require_visible_ascii(payload.get("issue_node_id"), "issue_node_id", maximum_bytes=256)
    for field in ("authorization_id", "campaign_id"):
        _require_hex32(payload.get(field), field)
    revision = payload.get("umi_revision")
    if not isinstance(revision, str) or re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        raise PublicPilotWireError("umi_revision is invalid")
    for field in ("coordinator_hotkey", "miner_hotkey"):
        _require_visible_ascii(payload.get(field), field, maximum_bytes=256)
    _require_rfc3339_seconds(payload.get("completed_at"), "completed_at")
    return payload


def build_result_marker(authorization_id_value: str, result_sha256: str) -> str:
    """Build the exact marker placed in a sanitized result comment."""

    _require_hex32(authorization_id_value, "authorization_id")
    _require_hex32(result_sha256, "result_sha256")
    return f"{RESULT_MARKER_PREFIX}{authorization_id_value}:{result_sha256} -->"


def parse_result_marker(marker: str) -> tuple[str, str]:
    """Parse one exact result marker line."""

    if not isinstance(marker, str) or not marker.startswith(RESULT_MARKER_PREFIX):
        raise PublicPilotWireError("result marker is invalid")
    suffix = marker[len(RESULT_MARKER_PREFIX) :]
    if not suffix.endswith(" -->"):
        raise PublicPilotWireError("result marker is invalid")
    parts = suffix[:-4].split(":")
    if len(parts) != 2:
        raise PublicPilotWireError("result marker is invalid")
    _require_hex32(parts[0], "authorization_id")
    _require_hex32(parts[1], "result_sha256")
    return parts[0], parts[1]


def _split_authenticated_marker(marker: str, *, prefix: str) -> tuple[str, str]:
    if not isinstance(marker, str) or not marker.startswith(prefix) or not marker.endswith(" -->"):
        raise PublicPilotWireError("authenticated marker is invalid")
    parts = marker[len(prefix) : -4].split(":")
    if len(parts) != 2 or _TOKEN_RE.fullmatch(parts[0]) is None:
        raise PublicPilotWireError("authenticated marker is invalid")
    _require_hex32(parts[1], "marker_hmac")
    return parts[0], parts[1]


def _hmac_hex(key: bytes, message: bytes) -> str:
    if not isinstance(key, bytes) or len(key) < 32:
        raise PublicPilotWireError("HMAC key must contain at least 32 bytes")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def _validate_json_subset(value: Any) -> None:
    if value is None or isinstance(value, str):
        return
    if isinstance(value, (bool, float)):
        raise PublicPilotWireError("booleans and floating-point values are not in the wire subset")
    if isinstance(value, int):
        if not -MAX_JSON_SAFE_INTEGER <= value <= MAX_JSON_SAFE_INTEGER:
            raise PublicPilotWireError("integer is outside the JSON interoperable range")
        return
    if isinstance(value, list):
        for item in value:
            _validate_json_subset(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise PublicPilotWireError("JSON object keys must be strings")
            _validate_json_subset(item)
        return
    raise PublicPilotWireError("value is outside the canonical JSON subset")


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PublicPilotWireError("JSON object contains a duplicate key")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise PublicPilotWireError(f"invalid JSON constant: {value}")


def _require_positive_json_integer(value: Any, field: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= MAX_JSON_SAFE_INTEGER
    ):
        raise PublicPilotWireError(f"{field} must be a positive JSON-safe integer")
    return value


def _require_visible_ascii(value: Any, field: str, *, maximum_bytes: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum_bytes
        or not value.isascii()
        or any(character.isspace() or not character.isprintable() for character in value)
    ):
        raise PublicPilotWireError(f"{field} must be bounded visible ASCII without whitespace")
    return value


def _require_ascii_text(value: Any, field: str, *, maximum_bytes: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum_bytes
        or not value.isascii()
        or any(not character.isprintable() for character in value)
    ):
        raise PublicPilotWireError(f"{field} must be bounded printable ASCII")
    return value


def _require_repository_full_name(value: Any) -> str:
    if (
        not isinstance(value, str)
        or re.fullmatch(
            r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})/[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})",
            value,
        )
        is None
    ):
        raise PublicPilotWireError("repository_full_name is invalid")
    return value


def _require_github_login(value: Any) -> str:
    if (
        not isinstance(value, str)
        or re.fullmatch(
            r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?",
            value,
        )
        is None
    ):
        raise PublicPilotWireError("actor_login is invalid")
    return value


def _require_hex32(value: Any, field: str) -> str:
    if not isinstance(value, str) or _HEX32_RE.fullmatch(value) is None:
        raise PublicPilotWireError(f"{field} must be 64 lowercase hexadecimal characters")
    return value


def _require_rfc3339_seconds(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or re.fullmatch(
            r"[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T"
            r"(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z",
            value,
        )
        is None
    ):
        raise PublicPilotWireError(f"{field} must be second-precision UTC RFC 3339")
    return value


__all__ = [
    "AUTHORIZATION_DOMAIN",
    "AUTHORIZATION_FIELDS",
    "AUTHORIZATION_MARKER_PREFIX",
    "AUTHORIZATION_SCHEMA",
    "CHALLENGE_DOMAIN",
    "CHALLENGE_MARKER_PREFIX",
    "CHALLENGE_SCHEMA",
    "MAX_ARCHIVE_BYTES",
    "MAX_JSON_SAFE_INTEGER",
    "MAX_MARKER_PAYLOAD_BYTES",
    "MAX_RESULT_ENVELOPE_BYTES",
    "PUBLIC_PILOT_READINESS_CONFIRMATIONS",
    "PUBLIC_PILOT_READINESS_CONFIRMATION_PROFILES",
    "RESULT_ATTEMPT_FIELDS",
    "RESULT_CASE_FIELDS",
    "RESULT_COMMON_FIELDS",
    "RESULT_DOMAIN",
    "RESULT_ENVELOPE_SCHEMA",
    "RESULT_EVIDENCE_FIELDS",
    "RESULT_MARKER_PREFIX",
    "RESULT_PAYLOAD_SCHEMA",
    "PublicPilotWireError",
    "authorization_id",
    "base64url_decode",
    "base64url_encode",
    "build_authorization_marker",
    "build_authorization_payload",
    "build_challenge_marker",
    "build_result_envelope",
    "build_result_marker",
    "canonical_json_bytes",
    "parse_authorization_marker",
    "parse_canonical_json_bytes",
    "parse_challenge_marker",
    "parse_result_envelope",
    "parse_result_marker",
    "readiness_confirmation_lines_match",
    "validate_authorization_payload",
    "validate_result_payload",
]
