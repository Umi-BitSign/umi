from __future__ import annotations

from dataclasses import replace

import pytest

from umi.public_pilot_authorization import verify_public_pilot_github_authorization
from umi.public_pilot_campaign import CAMPAIGN_ID
from umi.public_pilot_github import (
    create_public_pilot_github_authorization,
    public_pilot_github_authorization_marker,
)
from umi.public_pilot_github_client import (
    GithubActor,
    GithubComment,
    GithubIssue,
    github_body_sha256,
)
from umi.public_pilot_github_wire import PUBLIC_PILOT_READINESS_CONFIRMATIONS
from umi.public_pilot_readiness import (
    PUBLIC_PILOT_READINESS_SCHEMA,
    ReadyForCasePayload,
    public_pilot_readiness_marker,
    sign_public_pilot_readiness,
)

from .factories import dev_wallet

_REVISION = "ab" * 20
_OBSERVED_AFTER_EXPIRY = 1_788_900_000
_ISSUE_BODY_TEMPLATE = """### SN78 UID

249

### Miner hotkey

{hotkey}

### Host platform

Linux x86_64

### Inference device

GPU

### Model revision

{model_revision}

### Readiness confirmations

{confirmations}

### Operator notes

Ready.
"""


class _Github:
    def __init__(self, issue: GithubIssue, command: GithubComment, bot: GithubComment) -> None:
        self._issue = issue
        self._command = command
        self._bot = bot

    def issue(self, _number: int) -> GithubIssue:
        return self._issue

    def comment(self, comment_id: int) -> GithubComment:
        if comment_id == self._command.id:
            return self._command
        if comment_id == self._bot.id:
            return self._bot
        raise AssertionError("unexpected comment ID")


def _fixture(
    *,
    command_created_at: str = "2026-09-07T20:00:00Z",
    bot_created_at: str = "2026-09-07T20:00:02Z",
) -> tuple[GithubComment, _Github, bytes]:
    wallet = dev_wallet("//PublicPilotGithubMiner")
    hotkey = wallet.hotkey.ss58_address
    issue_body = _ISSUE_BODY_TEMPLATE.format(
        hotkey=hotkey,
        model_revision="cd" * 32,
        confirmations="\n".join(f"- [X] {label}" for label in PUBLIC_PILOT_READINESS_CONFIRMATIONS),
    )
    user = GithubActor(id=77, login="pilot-miner", type="User")
    issue = GithubIssue(
        id=1_234,
        node_id="I_node",
        number=8,
        state="open",
        title="[Miner pilot] UID 249",
        body=issue_body,
        user=user,
        labels=("public-miner-pilot",),
    )
    payload = ReadyForCasePayload(
        schema=PUBLIC_PILOT_READINESS_SCHEMA,
        repository_id=1_348_567_807,
        issue_id=issue.id,
        issue_node_id=issue.node_id,
        issue_number=issue.number,
        campaign_id=CAMPAIGN_ID,
        action="ready_for_case",
        challenge_nonce="11" * 32,
        miner_hotkey=hotkey,
        miner_account_id32=wallet.hotkey.public_key.hex(),
        expected_uid=249,
        expires_at="2026-09-08T20:00:00Z",
    )
    proof = sign_public_pilot_readiness(payload, wallet=wallet, now_unix_s=1_788_700_000)
    command_body = public_pilot_readiness_marker(proof)
    command = GithubComment(
        id=5_678,
        node_id="IC_command",
        body=command_body,
        created_at=command_created_at,
        updated_at=command_created_at,
        user=user,
    )
    authorization = create_public_pilot_github_authorization(
        {
            "schema": "umi-public-pilot-github-authorization/1",
            "action": "ready_for_case",
            "repository_id": 1_348_567_807,
            "repository_full_name": "Umi-BitSign/umi",
            "issue_id": issue.id,
            "issue_node_id": issue.node_id,
            "issue_number": issue.number,
            "issue_body_sha256": github_body_sha256(issue.body),
            "command_comment_id": command.id,
            "command_node_id": command.node_id,
            "command_created_at": command.created_at,
            "actor_id": user.id,
            "actor_login": user.login,
            "command_body_sha256": github_body_sha256(command.body),
            "challenge_nonce": payload.challenge_nonce,
            "campaign_id": CAMPAIGN_ID,
            "umi_revision": _REVISION,
            "predecessor_authorization_id": None,
        }
    )
    key = bytes.fromhex("22" * 32)
    marker = public_pilot_github_authorization_marker(authorization, hmac_key=key)
    bot = GithubComment(
        id=9_999,
        node_id="IC_bot",
        body=f"Authorization accepted.\n\n{marker}",
        created_at=bot_created_at,
        updated_at=bot_created_at,
        user=GithubActor(id=41_898_282, login="github-actions[bot]", type="Bot"),
    )
    return bot, _Github(issue, command, bot), key


def test_public_pilot_authorization_rechecks_github_and_hotkey_signature() -> None:
    bot, github, key = _fixture()
    verified = verify_public_pilot_github_authorization(
        bot,
        github=github,  # type: ignore[arg-type]
        hmac_key=key,
        expected_repository_id=1_348_567_807,
        expected_repository_full_name="Umi-BitSign/umi",
        expected_umi_revision=_REVISION,
        now_unix_s=_OBSERVED_AFTER_EXPIRY,
    )
    assert verified.authorization.action == "ready_for_case"
    assert verified.enrollment.uid == 249

    # GitHub logins are mutable display names. Numeric actor IDs remain the
    # authorization boundary if the account is renamed before execution.
    renamed = replace(github._issue.user, login="renamed-pilot-miner")
    github._issue = replace(github._issue, user=renamed)
    github._command = replace(github._command, user=renamed)
    verified = verify_public_pilot_github_authorization(
        bot,
        github=github,  # type: ignore[arg-type]
        hmac_key=key,
        expected_repository_id=1_348_567_807,
        expected_repository_full_name="Umi-BitSign/umi",
        expected_umi_revision=_REVISION,
        now_unix_s=_OBSERVED_AFTER_EXPIRY,
    )
    assert verified.command_comment.user.id == 77

    github._issue = replace(github._issue, body=github._issue.body + "edited")
    with pytest.raises(ValueError, match="enrollment snapshot"):
        verify_public_pilot_github_authorization(
            bot,
            github=github,  # type: ignore[arg-type]
            hmac_key=key,
            expected_repository_id=1_348_567_807,
            expected_repository_full_name="Umi-BitSign/umi",
            expected_umi_revision=_REVISION,
            now_unix_s=_OBSERVED_AFTER_EXPIRY,
        )


def test_queued_authorization_remains_valid_after_readiness_expiry() -> None:
    bot, github, key = _fixture()

    verified = verify_public_pilot_github_authorization(
        bot,
        github=github,  # type: ignore[arg-type]
        hmac_key=key,
        expected_repository_id=1_348_567_807,
        expected_repository_full_name="Umi-BitSign/umi",
        expected_umi_revision=_REVISION,
        now_unix_s=_OBSERVED_AFTER_EXPIRY,
    )

    assert verified.authorization.action == "ready_for_case"
    assert verified.command_comment.created_at == "2026-09-07T20:00:00Z"


def test_authorization_rejects_command_created_after_observation_time() -> None:
    bot, github, key = _fixture()

    with pytest.raises(ValueError, match="created after the observation time"):
        verify_public_pilot_github_authorization(
            bot,
            github=github,  # type: ignore[arg-type]
            hmac_key=key,
            expected_repository_id=1_348_567_807,
            expected_repository_full_name="Umi-BitSign/umi",
            expected_umi_revision=_REVISION,
            now_unix_s=0,
        )


@pytest.mark.parametrize(
    ("command_created_at", "bot_created_at"),
    [
        ("2026-09-08T20:00:00Z", "2026-09-08T20:00:02Z"),
        ("2026-09-08T20:00:01Z", "2026-09-08T20:00:03Z"),
    ],
)
def test_authorization_rejects_command_created_at_or_after_readiness_expiry(
    command_created_at: str,
    bot_created_at: str,
) -> None:
    bot, github, key = _fixture(
        command_created_at=command_created_at,
        bot_created_at=bot_created_at,
    )

    with pytest.raises(ValueError, match="readiness proof is expired"):
        verify_public_pilot_github_authorization(
            bot,
            github=github,  # type: ignore[arg-type]
            hmac_key=key,
            expected_repository_id=1_348_567_807,
            expected_repository_full_name="Umi-BitSign/umi",
            expected_umi_revision=_REVISION,
            now_unix_s=_OBSERVED_AFTER_EXPIRY,
        )
