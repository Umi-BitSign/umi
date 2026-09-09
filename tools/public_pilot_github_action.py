#!/usr/bin/env python3
"""Dependency-free GitHub boundary for UMI's one-shot public miner pilots.

The workflow never treats a GitHub account as proof of hotkey control.  It only
accepts an exact, issue-bound readiness marker and emits an HMAC-authenticated
authorization for the coordinator, which independently verifies the signature
and finalized SN78 state before preparing or issuing anything.
"""

from __future__ import annotations

import base64
import calendar
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT / "src"))

from umi.public_pilot_github_wire import (  # noqa: E402
    AUTHORIZATION_MARKER_PREFIX,
    AUTHORIZATION_SCHEMA,
    CHALLENGE_MARKER_PREFIX,
    CHALLENGE_SCHEMA,
    MAX_JSON_SAFE_INTEGER,
    RESULT_MARKER_PREFIX,
    PublicPilotWireError,
    base64url_decode,
    base64url_encode,
    build_authorization_marker,
    build_authorization_payload,
    build_challenge_marker,
    build_result_marker,
    canonical_json_bytes,
    parse_authorization_marker,
    parse_canonical_json_bytes,
    parse_challenge_marker,
    parse_result_envelope,
    parse_result_marker,
    readiness_confirmation_lines_match,
)

PILOT_LABEL = "public-miner-pilot"
READINESS_SCHEMA = "umi-public-pilot-readiness/1"
READINESS_PREFIX = "UMI-PILOT-READINESS-V1"
CHALLENGE_TTL_SECONDS = 24 * 60 * 60
ISSUE_BODY_MAX_BYTES = 128 * 1024
COMMENT_BODY_MAX_BYTES = 128 * 1024
ARCHIVE_MAX_BYTES = 96 * 1024 * 1024
RESULT_POLL_DEFAULT_SECONDS = 30
RESULT_POLL_INTERVAL_DEFAULT_SECONDS = 5
RESULT_MAX_ATTEMPTS_PER_RECONCILE = 10

_HEX32_RE = re.compile(r"^[0-9a-f]{64}$")
_REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
_READINESS_RE = re.compile(
    rf"^{READINESS_PREFIX} (?P<token>[A-Za-z0-9_-]+) "
    r"(?P<scheme>sr25519|ed25519) (?P<signature>0x[0-9a-f]{128})$"
)
_UTC_RE = re.compile(
    r"^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$"
)
_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BASE58_INDEX = {character: index for index, character in enumerate(_BASE58_ALPHABET)}
_ACTIONS_BOT_LOGIN = "github-actions[bot]"
_EXPIRED_NOTICE_PREFIX = "<!-- umi-public-pilot-case-expired-v1:"
_AUTHORIZATION_EXPIRED_NOTICE_PREFIX = "<!-- umi-public-pilot-authorization-expired-v1:"

_CHALLENGE_FIELDS = frozenset(
    {
        "schema",
        "action",
        "repository_id",
        "repository_full_name",
        "issue_id",
        "issue_node_id",
        "issue_number",
        "issue_author_id",
        "issue_body_sha256",
        "miner_hotkey",
        "miner_account_id32",
        "expected_uid",
        "challenge_nonce",
        "campaign_id",
        "umi_revision",
        "expires_at",
        "predecessor_authorization_id",
        "case_manifest_sha256",
        "expected_origin",
    }
)
_READINESS_COMMON_FIELDS = frozenset(
    {
        "schema",
        "action",
        "repository_id",
        "issue_id",
        "issue_node_id",
        "issue_number",
        "campaign_id",
        "challenge_nonce",
        "miner_hotkey",
        "miner_account_id32",
        "expected_uid",
        "expires_at",
    }
)
_READINESS_ISSUE_FIELDS = frozenset(
    {"predecessor_authorization_id", "case_manifest_sha256", "expected_origin"}
)


class BoundaryError(ValueError):
    """A bounded, user-safe boundary failure."""

    def __init__(self, code: str):
        if re.fullmatch(r"[a-z0-9_]{1,80}", code) is None:
            raise ValueError("boundary error codes must be bounded lowercase tokens")
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class Config:
    repository_id: int
    repository_full_name: str
    github_token: str
    authorization_hmac_key: bytes
    result_hmac_key: bytes
    public_origin: str
    coordinator_hotkey: str
    campaign_id: str
    umi_revision: str
    challenge_ttl_seconds: int = CHALLENGE_TTL_SECONDS
    direct_poll_seconds: int = RESULT_POLL_DEFAULT_SECONDS
    poll_interval_seconds: int = RESULT_POLL_INTERVAL_DEFAULT_SECONDS


@dataclass(frozen=True, slots=True)
class IssueIdentity:
    repository_id: int
    repository_full_name: str
    issue_id: int
    issue_node_id: str
    issue_number: int
    issue_author_id: int
    issue_author_login: str
    issue_body: str
    issue_body_sha256: str
    miner_hotkey: str
    miner_account_id32: str
    expected_uid: int
    state: str


@dataclass(frozen=True, slots=True)
class ParsedReadiness:
    marker: str
    token: str
    payload: dict[str, Any]
    signature_scheme: str
    signature: str


@dataclass(frozen=True, slots=True)
class AuthorizationState:
    payload: dict[str, Any]
    challenge: dict[str, Any]


@dataclass(frozen=True, slots=True)
class ChallengeState:
    payload: dict[str, Any]
    comment_id: int


@dataclass(frozen=True, slots=True)
class CommentState:
    comments: tuple[dict[str, Any], ...]
    challenges: tuple[ChallengeState, ...]
    authorizations: tuple[AuthorizationState, ...]
    result_markers: dict[str, str]
    expired_case_authorizations: frozenset[str]
    expired_authorizations: frozenset[str]


@dataclass(frozen=True, slots=True)
class ReconcileOutcome:
    issue_number: int
    status: str
    comments_posted: int = 0


def sha256_text(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("value must be text")
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def format_utc(unix_seconds: int) -> str:
    if isinstance(unix_seconds, bool) or not isinstance(unix_seconds, int):
        raise BoundaryError("invalid_unix_time")
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(unix_seconds))


def parse_utc(value: Any, *, field: str) -> int:
    if not isinstance(value, str) or _UTC_RE.fullmatch(value) is None:
        raise BoundaryError(f"invalid_{field}")
    try:
        return calendar.timegm(time.strptime(value, "%Y-%m-%dT%H:%M:%SZ"))
    except (OverflowError, ValueError) as error:
        raise BoundaryError(f"invalid_{field}") from error


def decode_secret(value: str, *, field: str) -> bytes:
    """Decode a canonical 32-byte standard-base64 Actions secret."""

    if not isinstance(value, str) or not value or any(character.isspace() for character in value):
        raise BoundaryError(f"invalid_{field}")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise BoundaryError(f"invalid_{field}") from error
    if len(decoded) != 32 or base64.b64encode(decoded).decode("ascii") != value:
        raise BoundaryError(f"invalid_{field}")
    return decoded


def account_id32_from_ss58(address: Any) -> str:
    """Validate a canonical AccountId32 SS58 address using only stdlib."""

    if (
        not isinstance(address, str)
        or not 3 <= len(address) <= 64
        or not address.isascii()
        or any(character not in _BASE58_INDEX for character in address)
    ):
        raise BoundaryError("invalid_miner_hotkey")
    number = 0
    for character in address:
        number = number * 58 + _BASE58_INDEX[character]
    body = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    leading_zeroes = len(address) - len(address.lstrip("1"))
    decoded = b"\0" * leading_zeroes + body
    if not decoded:
        raise BoundaryError("invalid_miner_hotkey")
    first = decoded[0]
    if first <= 63:
        prefix_length = 1
        prefix = first
    elif 64 <= first <= 127 and len(decoded) >= 2:
        prefix_length = 2
        prefix = ((first & 0x3F) << 2) | (decoded[1] >> 6) | ((decoded[1] & 0x3F) << 8)
    else:
        raise BoundaryError("invalid_miner_hotkey")
    if prefix in {46, 47} or prefix > 16_383 or len(decoded) != prefix_length + 32 + 2:
        raise BoundaryError("invalid_miner_hotkey")
    payload = decoded[: prefix_length + 32]
    expected = hashlib.blake2b(b"SS58PRE" + payload, digest_size=64).digest()[:2]
    if not hmac.compare_digest(decoded[-2:], expected):
        raise BoundaryError("invalid_miner_hotkey")
    if _base58_encode(decoded) != address:
        raise BoundaryError("invalid_miner_hotkey")
    return decoded[prefix_length : prefix_length + 32].hex()


def _base58_encode(raw: bytes) -> str:
    number = int.from_bytes(raw, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = _BASE58_ALPHABET[remainder] + encoded
    leading_zeroes = len(raw) - len(raw.lstrip(b"\0"))
    return "1" * leading_zeroes + encoded


def parse_issue(issue: Any, config: Config) -> IssueIdentity:
    if not isinstance(issue, dict) or "pull_request" in issue:
        raise BoundaryError("not_a_pilot_issue")
    labels = issue.get("labels")
    if not isinstance(labels, list) or PILOT_LABEL not in {
        item.get("name") if isinstance(item, dict) else item for item in labels
    }:
        raise BoundaryError("not_a_pilot_issue")
    issue_id = _positive_int(issue.get("id"), "issue_id")
    issue_number = _positive_int(issue.get("number"), "issue_number")
    issue_node_id = _visible_ascii(issue.get("node_id"), "issue_node_id", maximum=256)
    user = issue.get("user")
    if not isinstance(user, dict) or user.get("type") != "User":
        raise BoundaryError("invalid_issue_author")
    author_id = _positive_int(user.get("id"), "issue_author_id")
    author_login = _github_login(user.get("login"), "issue_author_login")
    body = issue.get("body")
    if not isinstance(body, str) or len(body.encode("utf-8")) > ISSUE_BODY_MAX_BYTES:
        raise BoundaryError("invalid_issue_body")
    expected_uid, hotkey = parse_issue_form(body)
    account_hex = account_id32_from_ss58(hotkey)
    state = issue.get("state")
    if state not in {"open", "closed"}:
        raise BoundaryError("invalid_issue_state")
    return IssueIdentity(
        repository_id=config.repository_id,
        repository_full_name=config.repository_full_name,
        issue_id=issue_id,
        issue_node_id=issue_node_id,
        issue_number=issue_number,
        issue_author_id=author_id,
        issue_author_login=author_login,
        issue_body=body,
        issue_body_sha256=sha256_text(body),
        miner_hotkey=hotkey,
        miner_account_id32=account_hex,
        expected_uid=expected_uid,
        state=state,
    )


def parse_issue_form(body: str) -> tuple[int, str]:
    uid_text = _issue_form_value(body, "SN78 UID")
    hotkey = _issue_form_value(body, "Miner hotkey")
    model_revision = _issue_form_value(body, "Model revision")
    confirmations = _issue_form_value(body, "Readiness confirmations")
    if re.fullmatch(r"0|[1-9][0-9]{0,4}", uid_text) is None:
        raise BoundaryError("invalid_expected_uid")
    uid = int(uid_text)
    if uid > 65_535:
        raise BoundaryError("invalid_expected_uid")
    if "\n" in hotkey or "\r" in hotkey:
        raise BoundaryError("invalid_miner_hotkey")
    _hex32(model_revision, "model_revision")
    checklist = tuple(confirmations.splitlines())
    if not readiness_confirmation_lines_match(checklist):
        raise BoundaryError("incomplete_readiness_confirmations")
    return uid, hotkey


def _issue_form_value(body: str, heading: str) -> str:
    expression = re.compile(
        rf"(?m)^### {re.escape(heading)}[ \t]*\r?\n+(?P<value>.*?)(?=\r?\n### |\Z)",
        re.DOTALL,
    )
    matches = list(expression.finditer(body))
    if len(matches) != 1:
        raise BoundaryError("invalid_issue_form")
    value = matches[0].group("value").strip()
    if not value or value == "_No response_":
        raise BoundaryError("invalid_issue_form")
    return value


def build_readiness_payload(challenge: dict[str, Any]) -> dict[str, Any]:
    """Return the exact payload token the miner signs."""

    checked = validate_challenge(challenge)
    payload = {
        "schema": READINESS_SCHEMA,
        "action": checked["action"],
        "repository_id": checked["repository_id"],
        "issue_id": checked["issue_id"],
        "issue_node_id": checked["issue_node_id"],
        "issue_number": checked["issue_number"],
        "campaign_id": checked["campaign_id"],
        "challenge_nonce": checked["challenge_nonce"],
        "miner_hotkey": checked["miner_hotkey"],
        "miner_account_id32": checked["miner_account_id32"],
        "expected_uid": checked["expected_uid"],
        "expires_at": checked["expires_at"],
    }
    if checked["action"] == "ready_to_issue":
        payload.update(
            {
                "predecessor_authorization_id": checked["predecessor_authorization_id"],
                "case_manifest_sha256": checked["case_manifest_sha256"],
                "expected_origin": checked["expected_origin"],
            }
        )
    return payload


def readiness_payload_token(challenge: dict[str, Any]) -> str:
    return base64url_encode(canonical_json_bytes(build_readiness_payload(challenge)))


def parse_readiness_marker(marker: Any, *, now_unix_s: int) -> ParsedReadiness:
    if not isinstance(marker, str) or len(marker.encode("utf-8")) > COMMENT_BODY_MAX_BYTES:
        raise BoundaryError("invalid_readiness_marker")
    # GitHub returns a pasted command with a terminal Enter as one LF. Accept
    # that transport artifact while keeping every other prefix, suffix, blank
    # line, and CRLF shape invalid. Preserve the raw body for its binding hash.
    marker_for_parse = marker[:-1] if marker.endswith("\n") else marker
    match = _READINESS_RE.fullmatch(marker_for_parse)
    if match is None:
        raise BoundaryError("invalid_readiness_marker")
    token = match.group("token")
    try:
        raw = base64url_decode(token, maximum_bytes=4_096)
        payload = parse_canonical_json_bytes(raw, maximum_bytes=4_096)
    except PublicPilotWireError as error:
        raise BoundaryError("invalid_readiness_payload") from error
    validate_readiness_payload(payload, now_unix_s=now_unix_s)
    return ParsedReadiness(
        marker=marker,
        token=token,
        payload=payload,
        signature_scheme=match.group("scheme"),
        signature=match.group("signature"),
    )


def validate_readiness_payload(payload: Any, *, now_unix_s: int) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise BoundaryError("invalid_readiness_payload")
    action = payload.get("action")
    expected_fields = _READINESS_COMMON_FIELDS
    if action == "ready_to_issue":
        expected_fields |= _READINESS_ISSUE_FIELDS
    elif action != "ready_for_case":
        raise BoundaryError("invalid_readiness_action")
    if set(payload) != expected_fields or payload.get("schema") != READINESS_SCHEMA:
        raise BoundaryError("invalid_readiness_fields")
    for field in ("repository_id", "issue_id", "issue_number"):
        _positive_int(payload.get(field), field)
    _visible_ascii(payload.get("issue_node_id"), "issue_node_id", maximum=256)
    for field in ("campaign_id", "challenge_nonce", "miner_account_id32"):
        _hex32(payload.get(field), field)
    expected_uid = payload.get("expected_uid")
    if (
        isinstance(expected_uid, bool)
        or not isinstance(expected_uid, int)
        or not 0 <= expected_uid <= 65_535
    ):
        raise BoundaryError("invalid_expected_uid")
    account_hex = account_id32_from_ss58(payload.get("miner_hotkey"))
    if not hmac.compare_digest(account_hex, payload["miner_account_id32"]):
        raise BoundaryError("readiness_account_mismatch")
    expires = parse_utc(payload.get("expires_at"), field="expires_at")
    if now_unix_s >= expires:
        raise BoundaryError("readiness_expired")
    if action == "ready_to_issue":
        _hex32(payload.get("predecessor_authorization_id"), "predecessor_authorization_id")
        _hex32(payload.get("case_manifest_sha256"), "case_manifest_sha256")
        normalize_miner_origin(payload.get("expected_origin"))
    return payload


def validate_challenge(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != _CHALLENGE_FIELDS:
        raise BoundaryError("invalid_challenge_fields")
    if payload.get("schema") != CHALLENGE_SCHEMA:
        raise BoundaryError("invalid_challenge_schema")
    if payload.get("action") not in {"ready_for_case", "ready_to_issue"}:
        raise BoundaryError("invalid_challenge_action")
    for field in ("repository_id", "issue_id", "issue_number", "issue_author_id"):
        _positive_int(payload.get(field), field)
    _repository_name(payload.get("repository_full_name"))
    _visible_ascii(payload.get("issue_node_id"), "issue_node_id", maximum=256)
    for field in (
        "issue_body_sha256",
        "miner_account_id32",
        "challenge_nonce",
        "campaign_id",
    ):
        _hex32(payload.get(field), field)
    revision = payload.get("umi_revision")
    if not isinstance(revision, str) or _REVISION_RE.fullmatch(revision) is None:
        raise BoundaryError("invalid_umi_revision")
    expected_uid = payload.get("expected_uid")
    if (
        isinstance(expected_uid, bool)
        or not isinstance(expected_uid, int)
        or not 0 <= expected_uid <= 65_535
    ):
        raise BoundaryError("invalid_expected_uid")
    account_hex = account_id32_from_ss58(payload.get("miner_hotkey"))
    if not hmac.compare_digest(account_hex, payload["miner_account_id32"]):
        raise BoundaryError("challenge_account_mismatch")
    parse_utc(payload.get("expires_at"), field="expires_at")
    if payload["action"] == "ready_for_case":
        if any(
            payload.get(field) is not None
            for field in (
                "predecessor_authorization_id",
                "case_manifest_sha256",
                "expected_origin",
            )
        ):
            raise BoundaryError("invalid_case_challenge_context")
    else:
        _hex32(payload.get("predecessor_authorization_id"), "predecessor_authorization_id")
        _hex32(payload.get("case_manifest_sha256"), "case_manifest_sha256")
        normalize_miner_origin(payload.get("expected_origin"))
    return payload


def new_challenge(
    issue: IssueIdentity,
    config: Config,
    *,
    action: str,
    expires_at_unix_s: int,
    predecessor_authorization_id: str | None = None,
    case_manifest_sha256: str | None = None,
    expected_origin: str | None = None,
    nonce: str | None = None,
) -> dict[str, Any]:
    payload = {
        "schema": CHALLENGE_SCHEMA,
        "action": action,
        "repository_id": issue.repository_id,
        "repository_full_name": issue.repository_full_name,
        "issue_id": issue.issue_id,
        "issue_node_id": issue.issue_node_id,
        "issue_number": issue.issue_number,
        "issue_author_id": issue.issue_author_id,
        "issue_body_sha256": issue.issue_body_sha256,
        "miner_hotkey": issue.miner_hotkey,
        "miner_account_id32": issue.miner_account_id32,
        "expected_uid": issue.expected_uid,
        "challenge_nonce": nonce or secrets.token_hex(32),
        "campaign_id": config.campaign_id,
        "umi_revision": config.umi_revision,
        "expires_at": format_utc(expires_at_unix_s),
        "predecessor_authorization_id": predecessor_authorization_id,
        "case_manifest_sha256": case_manifest_sha256,
        "expected_origin": expected_origin,
    }
    return validate_challenge(payload)


def challenge_matches_issue(
    challenge: dict[str, Any], issue: IssueIdentity, config: Config
) -> bool:
    try:
        checked = validate_challenge(challenge)
    except BoundaryError:
        return False
    expected = {
        "repository_id": issue.repository_id,
        "repository_full_name": issue.repository_full_name,
        "issue_id": issue.issue_id,
        "issue_node_id": issue.issue_node_id,
        "issue_number": issue.issue_number,
        "issue_author_id": issue.issue_author_id,
        "issue_body_sha256": issue.issue_body_sha256,
        "miner_hotkey": issue.miner_hotkey,
        "miner_account_id32": issue.miner_account_id32,
        "expected_uid": issue.expected_uid,
        "campaign_id": config.campaign_id,
        "umi_revision": config.umi_revision,
    }
    return all(checked.get(field) == value for field, value in expected.items())


def readiness_matches_challenge(readiness: ParsedReadiness, challenge: dict[str, Any]) -> bool:
    return hmac.compare_digest(
        canonical_json_bytes(readiness.payload),
        canonical_json_bytes(build_readiness_payload(challenge)),
    )


def normalize_miner_origin(value: Any) -> str:
    if not isinstance(value, str) or not value.isascii() or len(value) > 128:
        raise BoundaryError("invalid_expected_origin")
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
        address = ipaddress.ip_address(parsed.hostname or "")
    except (ValueError, TypeError) as error:
        raise BoundaryError("invalid_expected_origin") from error
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or port is None
        or not 1 <= port <= 65_535
        or not address.is_global
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
        or address.is_link_local
        or address.is_loopback
    ):
        raise BoundaryError("invalid_expected_origin")
    host = f"[{address.compressed}]" if address.version == 6 else address.compressed
    normalized = f"https://{host}:{port}"
    if value != normalized:
        raise BoundaryError("invalid_expected_origin")
    return value


def validate_public_origin(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value.isascii()
        or not value.isprintable()
        or any(character.isspace() for character in value)
        or len(value) > 512
    ):
        raise BoundaryError("invalid_public_origin")
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise BoundaryError("invalid_public_origin") from error
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or parsed.hostname.endswith(".")
        or (port is not None and not 1 <= port <= 65_535)
    ):
        raise BoundaryError("invalid_public_origin")
    hostname = parsed.hostname.lower()
    if hostname != parsed.hostname:
        raise BoundaryError("invalid_public_origin")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        if len(hostname) > 253 or any(
            re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) is None
            for label in hostname.split(".")
        ):
            raise BoundaryError("invalid_public_origin") from None
        normalized_host = hostname
    else:
        normalized_host = f"[{address.compressed}]" if address.version == 6 else address.compressed
    expected_netloc = normalized_host if port is None else f"{normalized_host}:{port}"
    if parsed.netloc != expected_netloc:
        raise BoundaryError("invalid_public_origin")
    return value


def render_challenge_comment(challenge: dict[str, Any], key: bytes) -> str:
    checked = validate_challenge(challenge)
    marker = build_challenge_marker(checked, key)
    token = readiness_payload_token(checked)
    if checked["action"] == "ready_for_case":
        title = "### UMI public-pilot READY FOR CASE challenge"
        scope = "prepare one fresh sealed case; it does not authorize a miner request"
    else:
        title = "### UMI public-pilot READY TO ISSUE challenge"
        scope = (
            "issue exactly one authenticated request for case manifest "
            f"`{checked['case_manifest_sha256']}` to `{checked['expected_origin']}`"
        )
    return "\n".join(
        (
            marker,
            title,
            "",
            f"This challenge authorizes the coordinator to {scope}.",
            f"UMI revision: `{checked['umi_revision']}`",
            f"Campaign ID: `{checked['campaign_id']}`",
            f"It expires at `{checked['expires_at']}`.",
            "",
            f"Challenge payload: `{token}`",
            "",
            "Sign it with the enrolled miner hotkey:",
            "",
            "```text",
            f"umi-public-pilot-miner authorize --payload-token '{token}' "
            "--wallet-name WALLET --hotkey HOTKEY",
            "```",
            "",
            "Post the command's exact single-line `UMI-PILOT-READINESS-V1 ...` output here. "
            "Do not edit that comment or this enrollment issue while the authorization is pending.",
            "",
            "GitHub account matching is only an issue-control check. The coordinator independently "
            "verifies the miner-hotkey signature and finalized SN78 state before acting.",
        )
    )


def build_authorization(
    issue: IssueIdentity,
    challenge: dict[str, Any],
    comment: dict[str, Any],
    readiness: ParsedReadiness,
    config: Config,
) -> dict[str, Any]:
    user = comment.get("user")
    if not isinstance(user, dict):
        raise BoundaryError("invalid_command_actor")
    fields: dict[str, Any] = {
        "schema": AUTHORIZATION_SCHEMA,
        "action": challenge["action"],
        "repository_id": issue.repository_id,
        "repository_full_name": issue.repository_full_name,
        "issue_id": issue.issue_id,
        "issue_node_id": issue.issue_node_id,
        "issue_number": issue.issue_number,
        "issue_body_sha256": challenge["issue_body_sha256"],
        "command_comment_id": _positive_int(comment.get("id"), "command_comment_id"),
        "command_node_id": _visible_ascii(comment.get("node_id"), "command_node_id", maximum=256),
        "command_created_at": _github_timestamp(comment.get("created_at"), "command_created_at"),
        "actor_id": _positive_int(user.get("id"), "actor_id"),
        "actor_login": _github_login(user.get("login"), "actor_login"),
        "command_body_sha256": sha256_text(readiness.marker),
        "challenge_nonce": challenge["challenge_nonce"],
        "campaign_id": config.campaign_id,
        "umi_revision": config.umi_revision,
        "predecessor_authorization_id": challenge["predecessor_authorization_id"],
    }
    try:
        return build_authorization_payload(fields)
    except PublicPilotWireError as error:
        raise BoundaryError("invalid_authorization_payload") from error


def collect_comment_state(
    issue: IssueIdentity,
    comments: list[dict[str, Any]],
    config: Config,
) -> CommentState:
    ordered = tuple(sorted(comments, key=lambda item: _comment_id(item)))
    by_id = {_comment_id(comment): comment for comment in ordered}
    challenges: list[ChallengeState] = []
    raw_authorizations: list[dict[str, Any]] = []
    result_markers: dict[str, str] = {}
    expired_notices: set[str] = set()
    expired_authorizations: set[str] = set()

    for comment in ordered:
        body = comment.get("body")
        if not isinstance(body, str) or len(body.encode("utf-8")) > COMMENT_BODY_MAX_BYTES:
            continue
        if not _is_actions_bot(comment.get("user")):
            continue
        first_line = body.split("\n", 1)[0]
        if first_line.startswith(
            (
                CHALLENGE_MARKER_PREFIX,
                AUTHORIZATION_MARKER_PREFIX,
                RESULT_MARKER_PREFIX,
                _EXPIRED_NOTICE_PREFIX,
                _AUTHORIZATION_EXPIRED_NOTICE_PREFIX,
            )
        ) and comment.get("created_at") != comment.get("updated_at"):
            raise BoundaryError("edited_bot_state_comment")
        if first_line.startswith(CHALLENGE_MARKER_PREFIX):
            try:
                payload = parse_challenge_marker(first_line, config.authorization_hmac_key)
                validate_challenge(payload)
            except (BoundaryError, PublicPilotWireError) as error:
                raise BoundaryError("invalid_bot_challenge_marker") from error
            if _challenge_belongs_to_issue(payload, issue):
                challenges.append(ChallengeState(payload=payload, comment_id=_comment_id(comment)))
        elif body.startswith(AUTHORIZATION_MARKER_PREFIX):
            if "\n" in body or "\r" in body:
                raise BoundaryError("invalid_bot_authorization_marker")
            try:
                payload = parse_authorization_marker(body, config.authorization_hmac_key)
            except PublicPilotWireError as error:
                raise BoundaryError("invalid_bot_authorization_marker") from error
            if _authorization_belongs_to_issue(payload, issue):
                raw_authorizations.append(payload)
        elif first_line.startswith(RESULT_MARKER_PREFIX):
            try:
                authorization_id, result_sha = parse_result_marker(first_line)
            except PublicPilotWireError as error:
                raise BoundaryError("invalid_bot_result_marker") from error
            existing = result_markers.setdefault(authorization_id, result_sha)
            if not hmac.compare_digest(existing, result_sha):
                raise BoundaryError("conflicting_result_markers")
        elif first_line.startswith(_EXPIRED_NOTICE_PREFIX):
            authorization_id = _parse_expired_notice(first_line)
            expired_notices.add(authorization_id)
        elif first_line.startswith(_AUTHORIZATION_EXPIRED_NOTICE_PREFIX):
            authorization_id = _parse_authorization_expired_notice(first_line)
            expired_authorizations.add(authorization_id)

    challenge_by_nonce: dict[str, ChallengeState] = {}
    for challenge_state in challenges:
        nonce = challenge_state.payload["challenge_nonce"]
        previous = challenge_by_nonce.setdefault(nonce, challenge_state)
        if previous.payload != challenge_state.payload:
            raise BoundaryError("conflicting_challenge_nonce")

    authorizations: list[AuthorizationState] = []
    consumed_nonces: dict[str, str] = {}
    seen_authorization_ids: set[str] = set()
    for payload in sorted(raw_authorizations, key=lambda item: item["command_comment_id"]):
        authorization_id = payload["authorization_id"]
        if authorization_id in seen_authorization_ids:
            continue
        seen_authorization_ids.add(authorization_id)
        source = by_id.get(payload["command_comment_id"])
        challenge_state = challenge_by_nonce.get(payload["challenge_nonce"])
        if challenge_state is None:
            raise BoundaryError("authorization_challenge_missing")
        _validate_authorization_binding(issue, payload, challenge_state)
        if source is not None:
            _validate_authorized_source(issue, source, payload, challenge_state)
        prior = consumed_nonces.setdefault(payload["challenge_nonce"], authorization_id)
        if not hmac.compare_digest(prior, authorization_id):
            raise BoundaryError("challenge_nonce_reused")
        authorizations.append(
            AuthorizationState(
                payload=payload,
                challenge=challenge_state.payload,
            )
        )

    valid_ids = {authorization.payload["authorization_id"] for authorization in authorizations}
    unknown_results = set(result_markers) - valid_ids
    if unknown_results:
        raise BoundaryError("result_marker_without_authorization")
    return CommentState(
        comments=ordered,
        challenges=tuple(sorted(challenge_by_nonce.values(), key=lambda item: item.comment_id)),
        authorizations=tuple(authorizations),
        result_markers=result_markers,
        expired_case_authorizations=frozenset(expired_notices),
        expired_authorizations=frozenset(expired_authorizations),
    )


def _validate_authorized_source(
    issue: IssueIdentity,
    comment: dict[str, Any],
    authorization: dict[str, Any],
    challenge_state: ChallengeState,
) -> None:
    challenge = challenge_state.payload
    body = comment.get("body")
    created_at = _github_timestamp(comment.get("created_at"), "command_created_at")
    updated_at = _github_timestamp(comment.get("updated_at"), "command_updated_at")
    user = comment.get("user")
    if (
        not isinstance(body, str)
        or created_at != updated_at
        or not isinstance(user, dict)
        or user.get("type") != "User"
        or user.get("id") != issue.issue_author_id
        or user.get("login") != issue.issue_author_login
        or authorization["command_node_id"] != comment.get("node_id")
        or authorization["command_created_at"] != created_at
        or authorization["command_body_sha256"] != sha256_text(body)
    ):
        raise BoundaryError("authorization_source_mismatch")
    command_time = parse_utc(created_at, field="command_created_at")
    readiness = parse_readiness_marker(body, now_unix_s=command_time)
    if not readiness_matches_challenge(readiness, challenge):
        raise BoundaryError("authorization_challenge_mismatch")


def _validate_authorization_binding(
    issue: IssueIdentity,
    authorization: dict[str, Any],
    challenge_state: ChallengeState,
) -> None:
    challenge = challenge_state.payload
    if (
        authorization["actor_id"] != issue.issue_author_id
        or authorization["action"] != challenge["action"]
        or authorization["repository_id"] != challenge["repository_id"]
        or authorization["repository_full_name"] != challenge["repository_full_name"]
        or authorization["issue_id"] != challenge["issue_id"]
        or authorization["issue_node_id"] != challenge["issue_node_id"]
        or authorization["issue_number"] != challenge["issue_number"]
        or authorization["issue_body_sha256"] != challenge["issue_body_sha256"]
        or authorization["challenge_nonce"] != challenge["challenge_nonce"]
        or authorization["campaign_id"] != challenge["campaign_id"]
        or authorization["umi_revision"] != challenge["umi_revision"]
        or authorization["predecessor_authorization_id"]
        != challenge["predecessor_authorization_id"]
        or challenge_state.comment_id >= authorization["command_comment_id"]
    ):
        raise BoundaryError("authorization_challenge_mismatch")


def find_readiness_candidate(
    issue: IssueIdentity,
    state: CommentState,
    challenge_state: ChallengeState,
    *,
    now_unix_s: int,
) -> tuple[dict[str, Any], ParsedReadiness] | None:
    challenge = challenge_state.payload
    consumed = {authorization.payload["challenge_nonce"] for authorization in state.authorizations}
    if (
        challenge["challenge_nonce"] in consumed
        or parse_utc(challenge["expires_at"], field="expires_at") <= now_unix_s
    ):
        return None
    for comment in state.comments:
        comment_id = _comment_id(comment)
        if comment_id <= challenge_state.comment_id:
            continue
        body = comment.get("body")
        user = comment.get("user")
        if (
            not isinstance(body, str)
            or not body.startswith(f"{READINESS_PREFIX} ")
            or not isinstance(user, dict)
            or user.get("type") != "User"
            or user.get("id") != issue.issue_author_id
            or user.get("login") != issue.issue_author_login
            or comment.get("created_at") != comment.get("updated_at")
        ):
            continue
        try:
            command_time = parse_utc(
                _github_timestamp(comment.get("created_at"), "command_created_at"),
                field="command_created_at",
            )
            if command_time > now_unix_s:
                continue
            readiness = parse_readiness_marker(body, now_unix_s=command_time)
        except BoundaryError:
            continue
        if readiness_matches_challenge(readiness, challenge):
            return comment, readiness
    return None


def validate_result(
    raw: bytes,
    authorization: AuthorizationState,
    issue: IssueIdentity,
    config: Config,
) -> dict[str, Any]:
    try:
        payload = parse_result_envelope(raw, config.result_hmac_key)
    except PublicPilotWireError as error:
        raise BoundaryError("invalid_result_envelope") from error
    auth = authorization.payload
    expected_common = {
        "authorization_id": auth["authorization_id"],
        "action": auth["action"],
        "repository_id": auth["repository_id"],
        "repository_full_name": auth["repository_full_name"],
        "issue_id": auth["issue_id"],
        "issue_node_id": auth["issue_node_id"],
        "issue_number": auth["issue_number"],
        "campaign_id": auth["campaign_id"],
        "umi_revision": auth["umi_revision"],
        "coordinator_hotkey": config.coordinator_hotkey,
        "miner_hotkey": authorization.challenge["miner_hotkey"],
        "expected_miner_uid": authorization.challenge["expected_uid"],
    }
    if any(payload.get(field) != value for field, value in expected_common.items()):
        raise BoundaryError("result_authorization_mismatch")
    if issue.issue_id != auth["issue_id"]:
        raise BoundaryError("result_issue_mismatch")
    account_id32_from_ss58(payload.get("coordinator_hotkey"))
    account_id32_from_ss58(payload.get("miner_hotkey"))
    parse_utc(payload.get("completed_at"), field="completed_at")
    if payload["action"] == "ready_for_case":
        if payload["case_archive_size_bytes"] > ARCHIVE_MAX_BYTES:
            raise BoundaryError("case_archive_too_large")
        _require_exact_archive_url(
            payload["case_archive_url"],
            config.public_origin,
            f"/public-pilot-cases/{payload['case_archive_sha256']}/sealed-case.tar.gz",
        )
        normalize_miner_origin(payload["expected_origin"])
        close_at = parse_utc(payload["response_close_at"], field="response_close_at")
        reveal_at = parse_utc(payload["reveal_at"], field="reveal_at")
        if payload["reveal_round"] <= payload["response_close_round"] or reveal_at <= close_at:
            raise BoundaryError("invalid_case_schedule")
    elif payload["status"] == "pilot_incomplete":
        if payload["attempt_archive_size_bytes"] > ARCHIVE_MAX_BYTES:
            raise BoundaryError("attempt_archive_too_large")
        _require_exact_archive_url(
            payload["attempt_archive_url"],
            config.public_origin,
            f"/public-pilot-attempts/{payload['attempt_archive_sha256']}/attempt-journal.tar.gz",
        )
    else:
        if payload["evidence_archive_size_bytes"] > ARCHIVE_MAX_BYTES:
            raise BoundaryError("evidence_archive_too_large")
        _require_exact_archive_url(
            payload["evidence_archive_url"],
            config.public_origin,
            f"/public-pilot-evidence/{payload['evidence_archive_sha256']}/evidence.tar.gz",
        )
        if payload["outcome_classification"] == "failed" and payload["failure_code"] is None:
            raise BoundaryError("failed_result_without_code")
    return payload


def render_result_comment(payload: dict[str, Any], raw: bytes) -> str:
    result_sha256 = hashlib.sha256(raw).hexdigest()
    marker = build_result_marker(payload["authorization_id"], result_sha256)
    if payload["action"] == "ready_for_case":
        lines = (
            marker,
            "### UMI public-pilot case ready",
            "",
            f"Authorization: `{payload['authorization_id']}`",
            f"Case manifest SHA-256: `{payload['case_manifest_sha256']}`",
            f"Sealed archive: {payload['case_archive_url']}",
            f"Archive SHA-256: `{payload['case_archive_sha256']}`",
            f"Archive size: `{payload['case_archive_size_bytes']}` bytes",
            f"Expected endpoint: `{payload['expected_origin']}`",
            f"Response close: round `{payload['response_close_round']}` at "
            f"`{payload['response_close_at']}`",
            f"Reveal: round `{payload['reveal_round']}` at `{payload['reveal_at']}`",
            "",
            "A separate READY TO ISSUE signing challenge follows. Loading this archive alone "
            "does not authorize a request.",
        )
    elif payload["status"] == "pilot_incomplete":
        lines = (
            marker,
            "### UMI public-pilot attempt incomplete",
            "",
            f"Authorization: `{payload['authorization_id']}`",
            f"Completed through: `{payload['completed_through']}`",
            f"Failure stage: `{payload['failure_stage']}`",
            f"Failure code: `{payload['failure_code']}`",
            f"Request digest: `{payload['request_digest']}`",
            f"Attempt journal manifest SHA-256: `{payload['attempt_journal_manifest_sha256']}`",
            f"Non-feed attempt archive: {payload['attempt_archive_url']}",
            f"Archive SHA-256: `{payload['attempt_archive_sha256']}`",
            f"Archive size: `{payload['attempt_archive_size_bytes']}` bytes",
            "",
            "The one-shot boundary may have contacted the miner. This journal is not "
            "feed-eligible evidence, carries no replayable score, and the pilot will not retry.",
        )
    else:
        failure = payload["failure_code"] if payload["failure_code"] is not None else "none"
        lines = (
            marker,
            f"### UMI public-pilot {payload['status'].replace('_', ' ')}",
            "",
            f"Authorization: `{payload['authorization_id']}`",
            f"Outcome classification: `{payload['outcome_classification']}`",
            f"Failure code: `{failure}`",
            f"Request digest: `{payload['request_digest']}`",
            f"Evidence manifest SHA-256: `{payload['evidence_manifest_sha256']}`",
            f"Replayable evidence archive: {payload['evidence_archive_url']}",
            f"Archive SHA-256: `{payload['evidence_archive_sha256']}`",
            f"Archive size: `{payload['evidence_archive_size_bytes']}` bytes",
            "",
            "This is the terminal result for the one-shot authorization. It is a public "
            "component test and does not activate translation weights.",
        )
    return "\n".join(lines)


def render_case_expired_notice(authorization_id: str) -> str:
    _hex32(authorization_id, "authorization_id")
    return "\n".join(
        (
            f"{_EXPIRED_NOTICE_PREFIX}{authorization_id} -->",
            "### UMI public-pilot case expired before issuance authorization",
            "",
            "The prepared case no longer has the required five-minute response headroom. "
            "It will not be reused.",
            "",
            "A fresh READY FOR CASE challenge follows. Sign and post that new payload when "
            "you can remain online through reveal. If the coordinator already recorded a "
            "request attempt, its durable no-retry guard takes precedence and no new case "
            "will be prepared.",
        )
    )


def render_authorization_expired_notice(authorization_id: str) -> str:
    _hex32(authorization_id, "authorization_id")
    return "\n".join(
        (
            f"{_AUTHORIZATION_EXPIRED_NOTICE_PREFIX}{authorization_id} -->",
            "### UMI public-pilot case authorization expired",
            "",
            "No immutable case result arrived before this readiness authorization expired. "
            "The authorization will not be reused.",
            "",
            "A fresh READY FOR CASE challenge follows. If the coordinator already prepared "
            "a case, its durable active-case guard prevents a second case from being prepared "
            "at the same time.",
        )
    )


def result_url(config: Config, authorization_id: str) -> str:
    _hex32(authorization_id, "authorization_id")
    return f"{config.public_origin}/public-pilot-automation/results/{authorization_id}.json"


def reconcile_issue(
    issue_document: dict[str, Any],
    *,
    api: Any,
    results: Any,
    config: Config,
    now_unix_s: int,
    direct_comment_id: int | None = None,
) -> ReconcileOutcome:
    issue = parse_issue(issue_document, config)
    comments = api.list_issue_comments(issue.issue_number)
    state = collect_comment_state(issue, comments, config)
    posted = 0
    loaded_results: dict[str, tuple[bytes, dict[str, Any]]] = {}

    for authorization in state.authorizations:
        auth_id = authorization.payload["authorization_id"]
        poll_seconds = (
            config.direct_poll_seconds
            if direct_comment_id == authorization.payload["command_comment_id"]
            else 0
        )
        raw = _fetch_result_with_poll(
            results,
            result_url(config, auth_id),
            poll_seconds=poll_seconds,
            interval_seconds=config.poll_interval_seconds,
        )
        if raw is None:
            if auth_id in state.result_markers:
                raise BoundaryError("published_result_disappeared")
            continue
        payload = validate_result(raw, authorization, issue, config)
        result_sha = hashlib.sha256(raw).hexdigest()
        existing_sha = state.result_markers.get(auth_id)
        if existing_sha is not None and not hmac.compare_digest(existing_sha, result_sha):
            raise BoundaryError("published_result_changed")
        if existing_sha is None:
            api.post_issue_comment(issue.issue_number, render_result_comment(payload, raw))
            posted += 1
        loaded_results[auth_id] = (raw, payload)

    completed_issue_authorizations = [
        item
        for item in state.authorizations
        if item.payload["action"] == "ready_to_issue"
        and item.payload["authorization_id"] in loaded_results
    ]
    if completed_issue_authorizations:
        return ReconcileOutcome(issue.issue_number, "terminal", posted)

    latest_authorization = state.authorizations[-1] if state.authorizations else None
    if latest_authorization is not None and (
        latest_authorization.payload["campaign_id"] != config.campaign_id
        or latest_authorization.payload["umi_revision"] != config.umi_revision
    ):
        # A rollout must not reinterpret or advance work authorized for another
        # coordinator revision or campaign. Missing result comments above are
        # still reconciled using their original authenticated bindings.
        return ReconcileOutcome(
            issue.issue_number,
            "revision_transition_pending",
            posted,
        )
    if latest_authorization is not None and latest_authorization.payload["action"] == (
        "ready_to_issue"
    ):
        # A missing result cannot prove that the coordinator did not contact
        # the miner. Never infer a safe retry from time or a public 404. The
        # operator must recover and publish the authenticated terminal or
        # incomplete result before this issue can advance.
        return ReconcileOutcome(
            issue.issue_number,
            "awaiting_terminal_result",
            posted,
        )

    latest_case_authorization = latest_authorization
    if latest_case_authorization is not None:
        case_auth_id = latest_case_authorization.payload["authorization_id"]
        loaded = loaded_results.get(case_auth_id)
        if loaded is None:
            authorization_expiry = parse_utc(
                latest_case_authorization.challenge["expires_at"],
                field="expires_at",
            )
            if now_unix_s >= authorization_expiry:
                if case_auth_id not in state.expired_authorizations:
                    api.post_issue_comment(
                        issue.issue_number,
                        render_authorization_expired_notice(case_auth_id),
                    )
                    posted += 1
                if issue.state == "open":
                    posted += _ensure_or_accept_challenge(
                        issue,
                        state,
                        api=api,
                        results=results,
                        config=config,
                        now_unix_s=now_unix_s,
                        action="ready_for_case",
                        minimum_comment_id=latest_case_authorization.payload["command_comment_id"],
                        direct_comment_id=direct_comment_id,
                    )
                return ReconcileOutcome(
                    issue.issue_number,
                    "case_authorization_expired",
                    posted,
                )
            return ReconcileOutcome(issue.issue_number, "awaiting_case_result", posted)
        case_result = loaded[1]
        cutoff = parse_utc(case_result["response_close_at"], field="response_close_at") - 300
        case_body_unchanged = hmac.compare_digest(
            issue.issue_body_sha256,
            latest_case_authorization.payload["issue_body_sha256"],
        )
        if now_unix_s >= cutoff:
            if case_auth_id not in state.expired_case_authorizations:
                api.post_issue_comment(issue.issue_number, render_case_expired_notice(case_auth_id))
                posted += 1
            if issue.state == "open":
                posted += _ensure_or_accept_challenge(
                    issue,
                    state,
                    api=api,
                    results=results,
                    config=config,
                    now_unix_s=now_unix_s,
                    action="ready_for_case",
                    minimum_comment_id=latest_case_authorization.payload["command_comment_id"],
                    direct_comment_id=direct_comment_id,
                )
            return ReconcileOutcome(issue.issue_number, "case_expired", posted)
        if not case_body_unchanged:
            return ReconcileOutcome(issue.issue_number, "case_binding_changed", posted)
        if issue.state == "open":
            posted += _ensure_or_accept_challenge(
                issue,
                state,
                api=api,
                results=results,
                config=config,
                now_unix_s=now_unix_s,
                action="ready_to_issue",
                expires_at_unix_s=min(now_unix_s + config.challenge_ttl_seconds, cutoff),
                predecessor_authorization_id=case_auth_id,
                case_manifest_sha256=case_result["case_manifest_sha256"],
                expected_origin=case_result["expected_origin"],
                minimum_comment_id=latest_case_authorization.payload["command_comment_id"],
                direct_comment_id=direct_comment_id,
            )
        return ReconcileOutcome(issue.issue_number, "case_ready", posted)

    if issue.state == "open":
        posted += _ensure_or_accept_challenge(
            issue,
            state,
            api=api,
            results=results,
            config=config,
            now_unix_s=now_unix_s,
            action="ready_for_case",
            minimum_comment_id=0,
            direct_comment_id=direct_comment_id,
        )
    return ReconcileOutcome(issue.issue_number, "awaiting_ready_for_case", posted)


def _ensure_or_accept_challenge(
    issue: IssueIdentity,
    state: CommentState,
    *,
    api: Any,
    results: Any,
    config: Config,
    now_unix_s: int,
    action: str,
    minimum_comment_id: int,
    direct_comment_id: int | None,
    expires_at_unix_s: int | None = None,
    predecessor_authorization_id: str | None = None,
    case_manifest_sha256: str | None = None,
    expected_origin: str | None = None,
) -> int:
    candidates = [
        item
        for item in state.challenges
        if item.comment_id > minimum_comment_id
        and item.payload["action"] == action
        and challenge_matches_issue(item.payload, issue, config)
        and item.payload["predecessor_authorization_id"] == predecessor_authorization_id
        and item.payload["case_manifest_sha256"] == case_manifest_sha256
        and item.payload["expected_origin"] == expected_origin
        and parse_utc(item.payload["expires_at"], field="expires_at") > now_unix_s
        and item.payload["challenge_nonce"]
        not in {authorization.payload["challenge_nonce"] for authorization in state.authorizations}
    ]
    if not candidates:
        expiry = expires_at_unix_s or now_unix_s + config.challenge_ttl_seconds
        if expiry <= now_unix_s:
            return 0
        challenge = new_challenge(
            issue,
            config,
            action=action,
            expires_at_unix_s=expiry,
            predecessor_authorization_id=predecessor_authorization_id,
            case_manifest_sha256=case_manifest_sha256,
            expected_origin=expected_origin,
        )
        api.post_issue_comment(
            issue.issue_number,
            render_challenge_comment(challenge, config.authorization_hmac_key),
        )
        return 1

    challenge_state = candidates[-1]
    found = find_readiness_candidate(
        issue,
        state,
        challenge_state,
        now_unix_s=now_unix_s,
    )
    if found is None:
        return 0
    comment, readiness = found
    authorization_payload = build_authorization(
        issue, challenge_state.payload, comment, readiness, config
    )
    marker = build_authorization_marker(authorization_payload, config.authorization_hmac_key)
    api.post_issue_comment(issue.issue_number, marker)
    # The authorization marker is the durable handoff. Reconciliation will
    # recover its result even if this short opportunistic poll is interrupted.
    authorization_state = AuthorizationState(
        payload=authorization_payload,
        challenge=challenge_state.payload,
    )
    poll_seconds = (
        config.direct_poll_seconds
        if direct_comment_id == authorization_payload["command_comment_id"]
        else 0
    )
    raw = _fetch_result_with_poll(
        results,
        result_url(config, authorization_payload["authorization_id"]),
        poll_seconds=poll_seconds,
        interval_seconds=config.poll_interval_seconds,
    )
    if raw is not None:
        result_payload = validate_result(raw, authorization_state, issue, config)
        api.post_issue_comment(issue.issue_number, render_result_comment(result_payload, raw))
        return 2
    return 1


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


class GitHubAPI:
    def __init__(self, config: Config) -> None:
        self._config = config
        self._opener = urllib.request.build_opener(_NoRedirect)
        owner, repository = config.repository_full_name.split("/", 1)
        self._base = (
            "https://api.github.com/repos/"
            f"{urllib.parse.quote(owner, safe='')}/{urllib.parse.quote(repository, safe='')}"
        )

    def list_pilot_issues(self) -> list[dict[str, Any]]:
        path = (
            "/issues?state=all&labels="
            f"{urllib.parse.quote(PILOT_LABEL, safe='')}&sort=updated&direction=asc"
        )
        return self._paginated(path, kind="issues")

    def list_issue_comments(self, issue_number: int) -> list[dict[str, Any]]:
        _positive_int(issue_number, "issue_number")
        return self._paginated(f"/issues/{issue_number}/comments", kind="comments")

    def post_issue_comment(self, issue_number: int, body: str) -> dict[str, Any]:
        _positive_int(issue_number, "issue_number")
        if (
            not isinstance(body, str)
            or not body
            or len(body.encode("utf-8")) > COMMENT_BODY_MAX_BYTES
        ):
            raise BoundaryError("invalid_outbound_comment")
        raw = canonical_json_bytes({"body": body})
        value = self._request(
            "POST",
            f"/issues/{issue_number}/comments",
            body=raw,
            maximum_bytes=2 * 1024 * 1024,
        )
        if not isinstance(value, dict):
            raise BoundaryError("invalid_github_comment_response")
        return value

    def _paginated(self, path: str, *, kind: str) -> list[dict[str, Any]]:
        collected: list[dict[str, Any]] = []
        separator = "&" if "?" in path else "?"
        for page in range(1, 11):
            value = self._request(
                "GET",
                f"{path}{separator}per_page=100&page={page}",
                body=None,
                maximum_bytes=8 * 1024 * 1024,
            )
            if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
                raise BoundaryError(f"invalid_github_{kind}_response")
            collected.extend(value)
            if len(value) < 100:
                return collected
        raise BoundaryError(f"github_{kind}_pagination_limit")

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: bytes | None,
        maximum_bytes: int,
    ) -> Any:
        request = urllib.request.Request(
            self._base + path,
            data=body,
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self._config.github_token}",
                "User-Agent": "umi-public-pilot-boundary/1",
                "X-GitHub-Api-Version": "2022-11-28",
                **({"Content-Type": "application/json"} if body is not None else {}),
            },
        )
        try:
            with self._opener.open(request, timeout=30) as response:
                raw = response.read(maximum_bytes + 1)
                if len(raw) > maximum_bytes:
                    raise BoundaryError("github_response_too_large")
        except urllib.error.HTTPError as error:
            raise BoundaryError(f"github_http_{error.code}") from error
        except (TimeoutError, urllib.error.URLError) as error:
            raise BoundaryError("github_transport_error") from error
        try:
            return json.loads(raw, object_pairs_hook=_json_object_without_duplicates)
        except (UnicodeDecodeError, json.JSONDecodeError, BoundaryError) as error:
            raise BoundaryError("invalid_github_json") from error


class PublicResultFetcher:
    def __init__(self) -> None:
        self._opener = urllib.request.build_opener(_NoRedirect)

    def fetch(self, url: str) -> bytes | None:
        request = urllib.request.Request(
            url,
            method="GET",
            headers={
                "Accept": "application/json",
                "User-Agent": "umi-public-pilot-boundary/1",
            },
        )
        try:
            with self._opener.open(request, timeout=30) as response:
                content_type = response.headers.get("Content-Type", "").split(";", 1)[0].lower()
                if content_type != "application/json":
                    raise BoundaryError("invalid_result_content_type")
                raw = response.read(64 * 1024 + 1)
                if len(raw) > 64 * 1024:
                    raise BoundaryError("result_response_too_large")
                return raw
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return None
            raise BoundaryError(f"result_http_{error.code}") from error
        except (TimeoutError, urllib.error.URLError) as error:
            raise BoundaryError("result_transport_error") from error


def _fetch_result_with_poll(
    fetcher: Any,
    url: str,
    *,
    poll_seconds: int,
    interval_seconds: int,
) -> bytes | None:
    attempts = 1
    if poll_seconds > 0:
        attempts += min(
            RESULT_MAX_ATTEMPTS_PER_RECONCILE - 1,
            (poll_seconds + interval_seconds - 1) // interval_seconds,
        )
    for attempt in range(attempts):
        raw = fetcher.fetch(url)
        if raw is not None:
            return raw
        if attempt + 1 < attempts:
            time.sleep(interval_seconds)
    return None


def config_from_environment(environment: dict[str, str] | None = None) -> Config:
    env = os.environ if environment is None else environment
    repository_id = _positive_int_text(env.get("GITHUB_REPOSITORY_ID"), "repository_id")
    repository_name = _repository_name(env.get("GITHUB_REPOSITORY"))
    github_token = env.get("GITHUB_TOKEN")
    if not isinstance(github_token, str) or not github_token or len(github_token) > 1_024:
        raise BoundaryError("invalid_github_token")
    campaign_id = _hex32(env.get("UMI_CAMPAIGN_ID"), "campaign_id")
    revision = env.get("UMI_REVISION")
    if not isinstance(revision, str) or _REVISION_RE.fullmatch(revision) is None:
        raise BoundaryError("invalid_umi_revision")
    coordinator_hotkey = env.get("PUBLIC_PILOT_COORDINATOR_HOTKEY")
    account_id32_from_ss58(coordinator_hotkey)
    config = Config(
        repository_id=repository_id,
        repository_full_name=repository_name,
        github_token=github_token,
        authorization_hmac_key=decode_secret(
            env.get("PUBLIC_PILOT_AUTH_HMAC_KEY_B64", ""),
            field="authorization_hmac_key",
        ),
        result_hmac_key=decode_secret(
            env.get("PUBLIC_PILOT_RESULT_HMAC_KEY_B64", ""),
            field="result_hmac_key",
        ),
        public_origin=validate_public_origin(env.get("PUBLIC_PILOT_PUBLIC_ORIGIN")),
        coordinator_hotkey=coordinator_hotkey,
        campaign_id=campaign_id,
        umi_revision=revision,
        challenge_ttl_seconds=_bounded_environment_int(
            env.get("PUBLIC_PILOT_CHALLENGE_TTL_SECONDS"),
            default=CHALLENGE_TTL_SECONDS,
            minimum=300,
            maximum=7 * 24 * 60 * 60,
            field="challenge_ttl_seconds",
        ),
        direct_poll_seconds=_bounded_environment_int(
            env.get("PUBLIC_PILOT_DIRECT_POLL_SECONDS"),
            default=RESULT_POLL_DEFAULT_SECONDS,
            minimum=0,
            maximum=60,
            field="direct_poll_seconds",
        ),
        poll_interval_seconds=_bounded_environment_int(
            env.get("PUBLIC_PILOT_POLL_INTERVAL_SECONDS"),
            default=RESULT_POLL_INTERVAL_DEFAULT_SECONDS,
            minimum=1,
            maximum=15,
            field="poll_interval_seconds",
        ),
    )
    return config


def run(
    event_name: str,
    event: dict[str, Any],
    *,
    api: Any,
    results: Any,
    config: Config,
    now_unix_s: int,
) -> tuple[ReconcileOutcome, ...]:
    repository = event.get("repository")
    if not isinstance(repository, dict):
        raise BoundaryError("event_repository_missing")
    if (
        repository.get("id") != config.repository_id
        or repository.get("full_name") != config.repository_full_name
    ):
        raise BoundaryError("event_repository_mismatch")
    if event_name in {"schedule", "workflow_dispatch"}:
        issues = api.list_pilot_issues()
        outcomes: list[ReconcileOutcome] = []
        for issue in issues:
            if "pull_request" in issue:
                continue
            try:
                outcomes.append(
                    reconcile_issue(
                        issue,
                        api=api,
                        results=results,
                        config=config,
                        now_unix_s=now_unix_s,
                    )
                )
            except BoundaryError as error:
                issue_number = issue.get("number")
                if isinstance(issue_number, bool) or not isinstance(issue_number, int):
                    issue_number = 0
                outcomes.append(ReconcileOutcome(issue_number, f"error_{error.code}"))
        return tuple(outcomes)
    if event_name not in {"issues", "issue_comment"}:
        raise BoundaryError("unsupported_event")
    issue = event.get("issue")
    if not isinstance(issue, dict):
        raise BoundaryError("event_issue_missing")
    direct_comment_id: int | None = None
    if event_name == "issue_comment":
        comment = event.get("comment")
        if not isinstance(comment, dict):
            raise BoundaryError("event_comment_missing")
        if _is_actions_bot(comment.get("user")):
            return ()
        direct_comment_id = _comment_id(comment)
    try:
        return (
            reconcile_issue(
                issue,
                api=api,
                results=results,
                config=config,
                now_unix_s=now_unix_s,
                direct_comment_id=direct_comment_id,
            ),
        )
    except BoundaryError as error:
        if error.code == "not_a_pilot_issue":
            return ()
        raise


def _load_event(path: str) -> dict[str, Any]:
    event_path = Path(path)
    try:
        if not event_path.is_file() or event_path.stat().st_size > 2 * 1024 * 1024:
            raise BoundaryError("invalid_event_file")
        raw = event_path.read_bytes()
        value = json.loads(raw, object_pairs_hook=_json_object_without_duplicates)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BoundaryError("invalid_event_file") from error
    if not isinstance(value, dict):
        raise BoundaryError("invalid_event_document")
    return value


def main() -> int:
    try:
        config = config_from_environment()
        event_name = os.environ.get("GITHUB_EVENT_NAME", "")
        event_path = os.environ.get("GITHUB_EVENT_PATH", "")
        if not event_name or not event_path:
            raise BoundaryError("missing_github_event")
        outcomes = run(
            event_name,
            _load_event(event_path),
            api=GitHubAPI(config),
            results=PublicResultFetcher(),
            config=config,
            now_unix_s=int(time.time()),
        )
        document = {
            "schema": "umi-public-pilot-github-action-report/1",
            "outcomes": [
                {
                    "issue_number": outcome.issue_number,
                    "status": outcome.status,
                    "comments_posted": outcome.comments_posted,
                }
                for outcome in outcomes
            ],
        }
        print(canonical_json_bytes(document).decode("utf-8"))
        if any(outcome.status.startswith("error_") for outcome in outcomes):
            return 1
        return 0
    except BoundaryError as error:
        print(f"::error title=Public pilot boundary::{error.code}")
        return 1
    except Exception:
        # Do not let urllib exception representations or untrusted event text
        # reach the Actions log.
        print("::error title=Public pilot boundary::internal_error")
        return 1


def _positive_int(value: Any, field: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= MAX_JSON_SAFE_INTEGER
    ):
        raise BoundaryError(f"invalid_{field}")
    return value


def _positive_int_text(value: Any, field: str) -> int:
    if not isinstance(value, str) or re.fullmatch(r"[1-9][0-9]{0,15}", value) is None:
        raise BoundaryError(f"invalid_{field}")
    return _positive_int(int(value), field)


def _bounded_environment_int(
    value: Any,
    *,
    default: int,
    minimum: int,
    maximum: int,
    field: str,
) -> int:
    if value in {None, ""}:
        return default
    if not isinstance(value, str) or re.fullmatch(r"0|[1-9][0-9]{0,9}", value) is None:
        raise BoundaryError(f"invalid_{field}")
    parsed = int(value)
    if not minimum <= parsed <= maximum:
        raise BoundaryError(f"invalid_{field}")
    return parsed


def _visible_ascii(value: Any, field: str, *, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or not value.isascii()
        or any(character.isspace() or not character.isprintable() for character in value)
    ):
        raise BoundaryError(f"invalid_{field}")
    return value


def _hex32(value: Any, field: str) -> str:
    if not isinstance(value, str) or _HEX32_RE.fullmatch(value) is None:
        raise BoundaryError(f"invalid_{field}")
    return value


def _repository_name(value: Any) -> str:
    if (
        not isinstance(value, str)
        or re.fullmatch(
            r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})/[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})",
            value,
        )
        is None
    ):
        raise BoundaryError("invalid_repository_full_name")
    return value


def _github_login(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or re.fullmatch(
            r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?",
            value,
        )
        is None
    ):
        raise BoundaryError(f"invalid_{field}")
    return value


def _github_timestamp(value: Any, field: str) -> str:
    parse_utc(value, field=field)
    return value


def _comment_id(comment: Any) -> int:
    if not isinstance(comment, dict):
        raise BoundaryError("invalid_comment")
    return _positive_int(comment.get("id"), "comment_id")


def _is_actions_bot(user: Any) -> bool:
    return (
        isinstance(user, dict)
        and user.get("id") == 41_898_282
        and user.get("login") == _ACTIONS_BOT_LOGIN
        and user.get("type") == "Bot"
    )


def _challenge_belongs_to_issue(payload: dict[str, Any], issue: IssueIdentity) -> bool:
    return (
        payload["repository_id"] == issue.repository_id
        and payload["repository_full_name"] == issue.repository_full_name
        and payload["issue_id"] == issue.issue_id
        and payload["issue_node_id"] == issue.issue_node_id
        and payload["issue_number"] == issue.issue_number
        and payload["issue_author_id"] == issue.issue_author_id
    )


def _authorization_belongs_to_issue(payload: dict[str, Any], issue: IssueIdentity) -> bool:
    return (
        payload["repository_id"] == issue.repository_id
        and payload["repository_full_name"] == issue.repository_full_name
        and payload["issue_id"] == issue.issue_id
        and payload["issue_node_id"] == issue.issue_node_id
        and payload["issue_number"] == issue.issue_number
        and payload["actor_id"] == issue.issue_author_id
    )


def _parse_expired_notice(line: str) -> str:
    if not line.startswith(_EXPIRED_NOTICE_PREFIX) or not line.endswith(" -->"):
        raise BoundaryError("invalid_expired_notice")
    authorization_id = line[len(_EXPIRED_NOTICE_PREFIX) : -4]
    return _hex32(authorization_id, "expired_authorization_id")


def _parse_authorization_expired_notice(line: str) -> str:
    if not line.startswith(_AUTHORIZATION_EXPIRED_NOTICE_PREFIX) or not line.endswith(" -->"):
        raise BoundaryError("invalid_authorization_expired_notice")
    authorization_id = line[len(_AUTHORIZATION_EXPIRED_NOTICE_PREFIX) : -4]
    return _hex32(authorization_id, "expired_authorization_id")


def _require_exact_archive_url(value: Any, origin: str, path: str) -> None:
    if not isinstance(value, str) or not hmac.compare_digest(value, origin + path):
        raise BoundaryError("invalid_archive_url")


def _json_object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise BoundaryError("duplicate_json_key")
        value[key] = item
    return value


if __name__ == "__main__":
    raise SystemExit(main())
