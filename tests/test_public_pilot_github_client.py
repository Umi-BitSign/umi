from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import httpx
import pytest

from umi.public_pilot_github_client import (
    GithubNotFoundError,
    GithubRateLimitError,
    PublicPilotGithubClient,
    github_body_sha256,
    load_github_token,
    parse_public_pilot_enrollment,
)
from umi.public_pilot_github_wire import (
    PUBLIC_PILOT_READINESS_CONFIRMATION_PROFILES,
    PUBLIC_PILOT_READINESS_CONFIRMATIONS,
)

_CHECKLIST = "\n".join(
    f"- {'[X]' if index % 2 == 0 else '[x]'} {label}"
    for index, label in enumerate(PUBLIC_PILOT_READINESS_CONFIRMATIONS)
)

_BODY = f"""### SN78 UID

249

### Miner hotkey

5CY4Y4S1AJpbj87CJpy7hyMrw1E4RZ8XKX7cszRpBHLzyqqK

### Host platform

Linux x86_64

### Inference device

GPU

### Model revision

abababababababababababababababababababababababababababababababab

### Readiness confirmations

{_CHECKLIST}

### Operator notes

No private material.
"""


def _actor(identifier: int, login: str, kind: str = "User") -> dict[str, Any]:
    return {"id": identifier, "login": login, "type": kind}


def test_public_pilot_enrollment_parser_extracts_only_fixed_fields() -> None:
    enrollment = parse_public_pilot_enrollment(_BODY)
    assert enrollment.uid == 249
    assert enrollment.miner_hotkey == "5CY4Y4S1AJpbj87CJpy7hyMrw1E4RZ8XKX7cszRpBHLzyqqK"
    assert enrollment.model_revision == "ab" * 32
    assert github_body_sha256(_BODY) == hashlib.sha256(_BODY.encode()).hexdigest()

    with pytest.raises(ValueError, match="confirmations"):
        parse_public_pilot_enrollment(_BODY.replace("- [X] My hotkey", "- [ ] My hotkey"))
    with pytest.raises(ValueError, match="confirmations"):
        parse_public_pilot_enrollment(_BODY.replace("literal IP", "some hostname"))
    with pytest.raises(ValueError, match="repeats"):
        parse_public_pilot_enrollment(_BODY + "\n### SN78 UID\n\n250\n")


@pytest.mark.parametrize("profile", PUBLIC_PILOT_READINESS_CONFIRMATION_PROFILES[1:])
def test_public_pilot_enrollment_parser_accepts_only_known_legacy_profiles(
    profile: tuple[str, ...],
) -> None:
    legacy_checklist = "\n".join(f"- [X] {label}" for label in profile)
    body = _BODY.replace(_CHECKLIST, legacy_checklist)
    assert parse_public_pilot_enrollment(body).uid == 249
    with pytest.raises(ValueError, match="confirmations"):
        parse_public_pilot_enrollment(body.replace(profile[-1], "I agree to something else."))


def test_public_pilot_github_client_reads_bounded_issue_and_comments() -> None:
    issue = {
        "id": 1234,
        "node_id": "I_node",
        "number": 8,
        "state": "open",
        "title": "[Miner pilot] UID 249",
        "body": _BODY,
        "user": _actor(44, "miner"),
        "labels": [{"name": "public-miner-pilot"}],
    }
    comment = {
        "id": 5678,
        "node_id": "IC_node",
        "body": "authorization",
        "created_at": "2026-09-07T20:00:00Z",
        "updated_at": "2026-09-07T20:00:00Z",
        "user": _actor(41898282, "github-actions[bot]", "Bot"),
    }

    def handle(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "Bearer github_pat_read_only_test"
        assert request.headers["X-GitHub-Api-Version"] == "2022-11-28"
        if request.url.path.endswith("/issues/8"):
            payload: Any = issue
        elif request.url.path.endswith("/issues/comments/5678"):
            payload = comment
        else:
            assert request.url.params["since"] == "2026-09-07T19:00:00Z"
            payload = [comment]
        return httpx.Response(
            200,
            json=payload,
            headers={"Content-Type": "application/json; charset=utf-8"},
        )

    with (
        httpx.Client(transport=httpx.MockTransport(handle)) as http,
        PublicPilotGithubClient(
            "Umi-BitSign/umi",
            client=http,
            user_agent_revision="ab" * 20,
            token="github_pat_read_only_test",
        ) as github,
    ):
        assert github.issue(8).id == 1234
        assert github.comment(5678).user.login == "github-actions[bot]"
        assert [item.id for item in github.comments_since("2026-09-07T19:00:00Z")] == [5678]


def test_public_pilot_github_token_loader_accepts_one_newline_and_rejects_bad_tokens(
    tmp_path: Path,
) -> None:
    credential = tmp_path / "github-api-token"
    credential.write_bytes(b"github_pat_read_only_test\n")
    credential.chmod(0o600)
    assert load_github_token(credential) == "github_pat_read_only_test"

    for invalid in (b"", b" \n", b"token\nsecond", b"\xff", b"x" * 1_025):
        credential.write_bytes(invalid)
        with pytest.raises(ValueError, match=r"GitHub read token|byte ceiling"):
            load_github_token(credential)

    credential.write_bytes(b"github_pat_read_only_test\n")
    credential.chmod(0o640)
    with pytest.raises(ValueError, match="credential file is unsafe"):
        load_github_token(credential)

    credential.chmod(0o600)
    link = tmp_path / "github-api-token-link"
    link.symlink_to(credential)
    with pytest.raises(ValueError, match="credential file is unsafe"):
        load_github_token(link)

    with pytest.raises(ValueError, match="GitHub read token"):
        PublicPilotGithubClient(
            "Umi-BitSign/umi",
            user_agent_revision="ab" * 20,
            token="",
        )


def test_public_pilot_github_client_allows_slow_unauthenticated_reads() -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        assert "Authorization" not in request.headers
        return httpx.Response(200, json=[], headers={"Content-Type": "application/json"})

    with (
        httpx.Client(transport=httpx.MockTransport(handle)) as http,
        PublicPilotGithubClient(
            "Umi-BitSign/umi",
            client=http,
            user_agent_revision="ab" * 20,
        ) as github,
    ):
        assert github.comments_since("2026-09-07T19:00:00Z") == ()


def test_public_pilot_github_client_reports_bounded_rate_limit_backoff() -> None:
    token = "github_pat_rate_limit_test"
    responses = iter(
        (
            httpx.Response(
                429,
                content=b"rate limited",
                headers={"Retry-After": "17"},
            ),
            httpx.Response(
                403,
                json={"message": "You have exceeded a secondary rate limit."},
            ),
        )
    )

    def handle(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == f"Bearer {token}"
        return next(responses)

    with (
        httpx.Client(transport=httpx.MockTransport(handle)) as http,
        PublicPilotGithubClient(
            "Umi-BitSign/umi",
            client=http,
            user_agent_revision="ab" * 20,
            token=token,
        ) as github,
    ):
        with pytest.raises(GithubRateLimitError) as first:
            github.issue(8)
        assert first.value.retry_after_seconds == 17
        assert first.value.status_code == 429
        assert token not in str(first.value)

        with pytest.raises(GithubRateLimitError) as second:
            github.issue(8)
        assert second.value.retry_after_seconds == 120
        assert second.value.status_code == 403


def test_public_pilot_github_client_honors_primary_limit_reset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("umi.public_pilot_github_client.time.time", lambda: 1_000)

    def handle(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            403,
            json={"message": "API rate limit exceeded."},
            headers={
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": "1060",
            },
        )

    with (
        httpx.Client(transport=httpx.MockTransport(handle)) as http,
        PublicPilotGithubClient(
            "Umi-BitSign/umi",
            client=http,
            user_agent_revision="ab" * 20,
        ) as github,
        pytest.raises(GithubRateLimitError) as limited,
    ):
        github.issue(8)

    assert limited.value.retry_after_seconds == 61
    assert limited.value.status_code == 403


def test_public_pilot_github_client_classifies_only_not_found_as_permanent() -> None:
    responses = iter(
        (
            httpx.Response(404, json={"message": "Not Found"}),
            httpx.Response(503, json={"message": "Service Unavailable"}),
        )
    )

    def handle(_request: httpx.Request) -> httpx.Response:
        return next(responses)

    with (
        httpx.Client(transport=httpx.MockTransport(handle)) as http,
        PublicPilotGithubClient(
            "Umi-BitSign/umi",
            client=http,
            user_agent_revision="ab" * 20,
        ) as github,
    ):
        with pytest.raises(GithubNotFoundError) as missing:
            github.comment(5_678)
        assert isinstance(missing.value, ValueError)
        assert missing.value.status_code == 404

        with pytest.raises(httpx.HTTPStatusError) as transient:
            github.comment(5_678)
        assert transient.value.response.status_code == 503
