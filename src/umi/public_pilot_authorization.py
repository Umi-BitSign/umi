"""End-to-end verification of GitHub-authorized public-pilot transitions."""

from __future__ import annotations

import hmac
import time
from dataclasses import dataclass
from datetime import datetime, timezone

from .encoding import account_id32
from .public_pilot_campaign import CAMPAIGN_ID
from .public_pilot_github import (
    PublicPilotGithubAuthorization,
    parse_public_pilot_github_authorization_marker,
)
from .public_pilot_github_client import (
    GithubComment,
    GithubIssue,
    PublicPilotEnrollment,
    PublicPilotGithubClient,
    github_body_sha256,
    parse_public_pilot_enrollment,
)
from .public_pilot_readiness import (
    PublicPilotReadinessProof,
    ReadyToIssuePayload,
    parse_public_pilot_readiness_marker,
    verify_public_pilot_readiness,
)

PUBLIC_MINER_PILOT_LABEL = "public-miner-pilot"
GITHUB_ACTIONS_BOT_ID = 41_898_282
GITHUB_ACTIONS_BOT_LOGIN = "github-actions[bot]"
_AUTHORIZATION_MARKER_START = "<!-- umi-public-pilot-authorization-v1:"
_MAX_JSON_SAFE_INTEGER = (1 << 53) - 1


@dataclass(frozen=True, slots=True)
class VerifiedPublicPilotAuthorization:
    authorization: PublicPilotGithubAuthorization
    bot_comment: GithubComment
    command_comment: GithubComment
    issue: GithubIssue
    enrollment: PublicPilotEnrollment
    readiness: PublicPilotReadinessProof


def extract_public_pilot_authorization_marker(body: str) -> str:
    """Extract exactly one standalone authorization marker from a bot comment."""

    matches = [
        line
        for line in body.splitlines()
        if line.startswith(_AUTHORIZATION_MARKER_START) and line.endswith(" -->")
    ]
    if len(matches) != 1:
        raise ValueError("GitHub bot comment does not contain one authorization marker")
    return matches[0]


def verify_public_pilot_github_authorization(
    bot_comment: GithubComment,
    *,
    github: PublicPilotGithubClient,
    hmac_key: bytes,
    expected_repository_id: int,
    expected_repository_full_name: str,
    expected_umi_revision: str,
    expected_campaign_id: str = CAMPAIGN_ID,
    now_unix_s: int | None = None,
) -> VerifiedPublicPilotAuthorization:
    """Re-fetch and verify every GitHub, enrollment, and miner-signature binding.

    ``now_unix_s`` is the observation time used to reject a future-dated GitHub
    command. Readiness expiry is evaluated at the command's immutable creation
    time, so queueing cannot expire an authorization the bot already accepted.
    """

    current_bot_comment = github.comment(bot_comment.id)
    if current_bot_comment != bot_comment:
        raise ValueError("GitHub authorization comment changed after it was listed")
    if (
        current_bot_comment.user.id != GITHUB_ACTIONS_BOT_ID
        or current_bot_comment.user.login != GITHUB_ACTIONS_BOT_LOGIN
        or current_bot_comment.user.type != "Bot"
        or current_bot_comment.updated_at != current_bot_comment.created_at
    ):
        raise ValueError("authorization marker was not emitted by the fixed GitHub Actions bot")
    marker = extract_public_pilot_authorization_marker(current_bot_comment.body)
    authorization = parse_public_pilot_github_authorization_marker(marker, hmac_key=hmac_key)
    if (
        authorization.repository_id != expected_repository_id
        or authorization.repository_full_name != expected_repository_full_name
        or not hmac.compare_digest(authorization.umi_revision, expected_umi_revision)
        or not hmac.compare_digest(authorization.campaign_id, expected_campaign_id)
    ):
        raise ValueError("GitHub authorization does not bind the configured release")

    issue = github.issue(authorization.issue_number)
    command = github.comment(authorization.command_comment_id)
    if (
        issue.id != authorization.issue_id
        or issue.node_id != authorization.issue_node_id
        or issue.number != authorization.issue_number
        or issue.state != "open"
        or PUBLIC_MINER_PILOT_LABEL not in issue.labels
        or github_body_sha256(issue.body) != authorization.issue_body_sha256
    ):
        raise ValueError("current GitHub issue does not match the authorized enrollment snapshot")
    if (
        command.id != authorization.command_comment_id
        or command.node_id != authorization.command_node_id
        or command.created_at != authorization.command_created_at
        or command.updated_at != command.created_at
        or command.user.id != authorization.actor_id
        or command.user.type != "User"
        or command.user.id != issue.user.id
        or github_body_sha256(command.body) != authorization.command_body_sha256
    ):
        raise ValueError("current GitHub command comment does not match its authorization")

    enrollment = parse_public_pilot_enrollment(issue.body)
    try:
        readiness = parse_public_pilot_readiness_marker(command.body)
    except ValueError as error:
        raise ValueError("GitHub command comment is not one exact readiness proof") from error
    command_created_unix_s = int(
        datetime.strptime(command.created_at, "%Y-%m-%dT%H:%M:%SZ")
        .replace(tzinfo=timezone.utc)
        .timestamp()
    )
    if now_unix_s is None:
        now_unix_s = int(time.time())
    if (
        isinstance(now_unix_s, bool)
        or not isinstance(now_unix_s, int)
        or not 0 <= now_unix_s <= _MAX_JSON_SAFE_INTEGER
    ):
        raise ValueError("now_unix_s must be a nonnegative JSON-safe integer")
    if command_created_unix_s > now_unix_s:
        raise ValueError("GitHub command comment was created after the observation time")
    # The bot already bound this immutable GitHub timestamp into the
    # authorization. A later queue claim must not make an accepted proof expire.
    verify_public_pilot_readiness(
        readiness,
        expected_payload=readiness.payload,
        now_unix_s=command_created_unix_s,
    )
    payload = readiness.payload
    if (
        payload.repository_id != authorization.repository_id
        or payload.issue_id != authorization.issue_id
        or payload.issue_node_id != authorization.issue_node_id
        or payload.issue_number != authorization.issue_number
        or payload.action != authorization.action
        or not hmac.compare_digest(payload.campaign_id, authorization.campaign_id)
        or not hmac.compare_digest(payload.challenge_nonce, authorization.challenge_nonce)
        or account_id32(payload.miner_hotkey) != account_id32(enrollment.miner_hotkey)
        or payload.expected_uid != enrollment.uid
    ):
        raise ValueError("miner readiness proof does not match the GitHub authorization")
    if authorization.action == "ready_for_case":
        if authorization.predecessor_authorization_id is not None:
            raise ValueError("case authorization unexpectedly has a predecessor")
    elif not isinstance(payload, ReadyToIssuePayload) or not hmac.compare_digest(
        payload.predecessor_authorization_id,
        authorization.predecessor_authorization_id or "",
    ):
        raise ValueError("issue authorization does not bind the prepared-case predecessor")
    return VerifiedPublicPilotAuthorization(
        authorization=authorization,
        bot_comment=current_bot_comment,
        command_comment=command,
        issue=issue,
        enrollment=enrollment,
        readiness=readiness,
    )


__all__ = [
    "GITHUB_ACTIONS_BOT_ID",
    "GITHUB_ACTIONS_BOT_LOGIN",
    "PUBLIC_MINER_PILOT_LABEL",
    "VerifiedPublicPilotAuthorization",
    "extract_public_pilot_authorization_marker",
    "verify_public_pilot_github_authorization",
]
