from __future__ import annotations

import hashlib
import importlib.util
import re
import sys
from pathlib import Path
from typing import Any

import pytest

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility
    import tomli as tomllib

from umi.public_pilot_github import (
    PublicPilotGithubAuthorization,
    PublicPilotIncompleteResult,
    parse_public_pilot_automation_result_envelope,
    parse_public_pilot_github_authorization_marker,
    public_pilot_automation_result_envelope,
)
from umi.public_pilot_github_wire import (
    PUBLIC_PILOT_READINESS_CONFIRMATIONS,
    RESULT_PAYLOAD_SCHEMA,
    PublicPilotWireError,
    build_result_envelope,
    parse_authorization_marker,
    parse_result_envelope,
)

_ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location(
    "public_pilot_github_action",
    _ROOT / "tools" / "public_pilot_github_action.py",
)
assert _SPEC is not None and _SPEC.loader is not None
bot = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = bot
_SPEC.loader.exec_module(bot)

_MINER = "5CY4Y4S1AJpbj87CJpy7hyMrw1E4RZ8XKX7cszRpBHLzyqqK"
_COORDINATOR = "5GsPXiSyzpK3rRoeAmjT4F5Cqa1RmP1CyBvNpwNDsDejyNZ4"
_CAMPAIGN = "48" * 32
_REVISION = "d7" * 20
_NOW = 1_788_796_800  # 2026-09-07T20:00:00Z
_AUTH_KEY = bytes(range(32))
_RESULT_KEY = bytes(range(32, 64))

_CHECKLIST = "\n".join(f"- [X] {label}" for label in PUBLIC_PILOT_READINESS_CONFIRMATIONS)

_BODY = f"""### SN78 UID

249

### Miner hotkey

{_MINER}

### Host platform

Linux x86_64

### Model revision

{"ab" * 32}

### Readiness confirmations

{_CHECKLIST}
"""


def _user(identifier: int, login: str, kind: str = "User") -> dict[str, Any]:
    return {"id": identifier, "login": login, "type": kind}


def _issue() -> dict[str, Any]:
    return {
        "id": 1_234,
        "node_id": "I_kwDOExample",
        "number": 8,
        "state": "open",
        "body": _BODY,
        "user": _user(44, "miner-owner"),
        "labels": [{"name": bot.PILOT_LABEL}],
    }


def _config(*, revision: str = _REVISION) -> Any:
    return bot.Config(
        repository_id=99,
        repository_full_name="Umi-BitSign/umi",
        github_token="token",
        authorization_hmac_key=_AUTH_KEY,
        result_hmac_key=_RESULT_KEY,
        public_origin="https://objects.example",
        coordinator_hotkey=_COORDINATOR,
        campaign_id=_CAMPAIGN,
        umi_revision=revision,
        direct_poll_seconds=0,
        poll_interval_seconds=1,
    )


def _event(issue: dict[str, Any]) -> dict[str, Any]:
    return {
        "repository": {"id": 99, "full_name": "Umi-BitSign/umi"},
        "issue": issue,
    }


class FakeAPI:
    def __init__(self, issue: dict[str, Any]) -> None:
        self.issue = issue
        self.comments: list[dict[str, Any]] = []
        self._next_id = 10_000

    def list_pilot_issues(self) -> list[dict[str, Any]]:
        return [self.issue]

    def list_issue_comments(self, issue_number: int) -> list[dict[str, Any]]:
        assert issue_number == self.issue["number"]
        return list(self.comments)

    def post_issue_comment(self, issue_number: int, body: str) -> dict[str, Any]:
        assert issue_number == self.issue["number"]
        comment = {
            "id": self._next_id,
            "node_id": f"IC_{self._next_id}",
            "body": body,
            "created_at": bot.format_utc(_NOW),
            "updated_at": bot.format_utc(_NOW),
            "user": _user(41_898_282, "github-actions[bot]", "Bot"),
        }
        self._next_id += 1
        self.comments.append(comment)
        return comment

    def add_user_comment(
        self,
        body: str,
        *,
        user_id: int = 44,
        created_at_unix_s: int = _NOW,
    ) -> dict[str, Any]:
        comment = {
            "id": self._next_id,
            "node_id": f"IC_{self._next_id}",
            "body": body,
            "created_at": bot.format_utc(created_at_unix_s),
            "updated_at": bot.format_utc(created_at_unix_s),
            "user": _user(user_id, "miner-owner" if user_id == 44 else "attacker"),
        }
        self._next_id += 1
        self.comments.append(comment)
        return comment


class FakeResults:
    def __init__(self) -> None:
        self.documents: dict[str, bytes] = {}

    def fetch(self, url: str) -> bytes | None:
        return self.documents.get(url)


def _challenge_from_comment(comment: dict[str, Any]) -> dict[str, Any]:
    first_line = comment["body"].splitlines()[0]
    return bot.parse_challenge_marker(first_line, _AUTH_KEY)


def _proof(challenge: dict[str, Any]) -> str:
    return f"{bot.READINESS_PREFIX} {bot.readiness_payload_token(challenge)} sr25519 0x{'01' * 64}"


def _authorize_case(api: FakeAPI, results: FakeResults) -> dict[str, Any]:
    config = _config()
    issue = api.issue
    bot.run(
        "issues",
        _event(issue),
        api=api,
        results=results,
        config=config,
        now_unix_s=_NOW,
    )
    challenge = _challenge_from_comment(api.comments[-1])
    command = api.add_user_comment(_proof(challenge))
    comment_event = {**_event(issue), "comment": command}
    bot.run(
        "issue_comment",
        comment_event,
        api=api,
        results=results,
        config=config,
        now_unix_s=_NOW,
    )
    authorization_comment = api.comments[-1]
    return parse_authorization_marker(authorization_comment["body"], _AUTH_KEY)


def _case_result(authorization: dict[str, Any]) -> dict[str, Any]:
    archive_sha = "ab" * 32
    return {
        "schema": RESULT_PAYLOAD_SCHEMA,
        "authorization_id": authorization["authorization_id"],
        "action": "ready_for_case",
        "repository_id": authorization["repository_id"],
        "repository_full_name": authorization["repository_full_name"],
        "issue_id": authorization["issue_id"],
        "issue_node_id": authorization["issue_node_id"],
        "issue_number": authorization["issue_number"],
        "campaign_id": authorization["campaign_id"],
        "umi_revision": authorization["umi_revision"],
        "coordinator_hotkey": _COORDINATOR,
        "miner_hotkey": _MINER,
        "expected_miner_uid": 249,
        "completed_at": bot.format_utc(_NOW + 10),
        "status": "case_ready",
        "case_manifest_sha256": "cd" * 32,
        "case_archive_sha256": archive_sha,
        "case_archive_size_bytes": 12_345,
        "case_archive_url": (
            f"https://objects.example/public-pilot-cases/{archive_sha}/sealed-case.tar.gz"
        ),
        "expected_origin": "https://8.8.8.8:443",
        "response_close_round": 100,
        "reveal_round": 101,
        "response_close_at": bot.format_utc(_NOW + 1_800),
        "reveal_at": bot.format_utc(_NOW + 1_860),
    }


def _terminal_result(authorization: dict[str, Any]) -> dict[str, Any]:
    archive_sha = "de" * 32
    return {
        "schema": RESULT_PAYLOAD_SCHEMA,
        "authorization_id": authorization["authorization_id"],
        "action": "ready_to_issue",
        "repository_id": authorization["repository_id"],
        "repository_full_name": authorization["repository_full_name"],
        "issue_id": authorization["issue_id"],
        "issue_node_id": authorization["issue_node_id"],
        "issue_number": authorization["issue_number"],
        "campaign_id": authorization["campaign_id"],
        "umi_revision": authorization["umi_revision"],
        "coordinator_hotkey": _COORDINATOR,
        "miner_hotkey": _MINER,
        "expected_miner_uid": 249,
        "completed_at": bot.format_utc(_NOW + 2_000),
        "status": "pilot_complete",
        "evidence_manifest_sha256": "bc" * 32,
        "evidence_archive_sha256": archive_sha,
        "evidence_archive_size_bytes": 54_321,
        "evidence_archive_url": (
            f"https://objects.example/public-pilot-evidence/{archive_sha}/evidence.tar.gz"
        ),
        "outcome_classification": "ok",
        "failure_code": None,
        "request_digest": "98" * 32,
    }


def test_issue_event_emits_one_authenticated_random_challenge() -> None:
    issue = _issue()
    api = FakeAPI(issue)
    results = FakeResults()

    outcome = bot.run(
        "issues",
        _event(issue),
        api=api,
        results=results,
        config=_config(),
        now_unix_s=_NOW,
    )
    assert outcome[0].comments_posted == 1
    challenge = _challenge_from_comment(api.comments[0])
    assert challenge["action"] == "ready_for_case"
    assert re.fullmatch(r"[0-9a-f]{64}", challenge["challenge_nonce"])
    assert "Challenge payload: `" in api.comments[0]["body"]

    second = bot.run(
        "issues",
        _event(issue),
        api=api,
        results=results,
        config=_config(),
        now_unix_s=_NOW,
    )
    assert second[0].comments_posted == 0
    assert len(api.comments) == 1


def test_only_exact_immutable_issue_author_proof_becomes_authorization() -> None:
    issue = _issue()
    api = FakeAPI(issue)
    results = FakeResults()
    config = _config()
    bot.run("issues", _event(issue), api=api, results=results, config=config, now_unix_s=_NOW)
    challenge = _challenge_from_comment(api.comments[-1])
    api.add_user_comment(_proof(challenge), user_id=55)
    outcome = bot.run(
        "issue_comment",
        {**_event(issue), "comment": api.comments[-1]},
        api=api,
        results=results,
        config=config,
        now_unix_s=_NOW,
    )
    assert outcome[0].comments_posted == 0

    command = api.add_user_comment(_proof(challenge))
    outcome = bot.run(
        "issue_comment",
        {**_event(issue), "comment": command},
        api=api,
        results=results,
        config=config,
        now_unix_s=_NOW,
    )
    assert outcome[0].comments_posted == 1
    marker = api.comments[-1]["body"]
    assert "\n" not in marker
    authorization = parse_authorization_marker(marker, _AUTH_KEY)
    assert authorization["command_comment_id"] == command["id"]
    assert (
        authorization["command_body_sha256"] == hashlib.sha256(command["body"].encode()).hexdigest()
    )
    assert authorization["predecessor_authorization_id"] is None
    assert isinstance(
        parse_public_pilot_github_authorization_marker(marker, hmac_key=_AUTH_KEY),
        PublicPilotGithubAuthorization,
    )
    again = bot.run(
        "issue_comment",
        {**_event(issue), "comment": command},
        api=api,
        results=results,
        config=config,
        now_unix_s=_NOW,
    )
    assert again[0].comments_posted == 0

    replacement = "0" if marker[-5] != "0" else "1"
    tampered_marker = marker[:-5] + replacement + marker[-4:]
    with pytest.raises(PublicPilotWireError, match="HMAC"):
        parse_authorization_marker(tampered_marker, _AUTH_KEY)


def test_proof_comment_created_at_challenge_expiry_is_not_authorized() -> None:
    issue = _issue()
    api = FakeAPI(issue)
    results = FakeResults()
    config = _config()
    bot.run("issues", _event(issue), api=api, results=results, config=config, now_unix_s=_NOW)
    challenge = _challenge_from_comment(api.comments[-1])
    expires_at = bot.parse_utc(challenge["expires_at"], field="expires_at")
    command = api.add_user_comment(
        _proof(challenge),
        created_at_unix_s=expires_at,
    )
    parsed_issue = bot.parse_issue(issue, config)
    state = bot.collect_comment_state(parsed_issue, api.comments, config)
    assert (
        bot.find_readiness_candidate(
            parsed_issue,
            state,
            state.challenges[-1],
            now_unix_s=expires_at,
        )
        is None
    )

    outcome = bot.run(
        "issue_comment",
        {**_event(issue), "comment": command},
        api=api,
        results=results,
        config=config,
        now_unix_s=expires_at,
    )

    assert outcome[0].status == "awaiting_ready_for_case"
    assert outcome[0].comments_posted == 1
    assert not any(
        "umi-public-pilot-authorization-v1" in comment["body"] for comment in api.comments
    )
    replacement = _challenge_from_comment(api.comments[-1])
    assert replacement["challenge_nonce"] != challenge["challenge_nonce"]


def test_case_result_is_authenticated_sanitized_and_advances_to_issue_challenge() -> None:
    issue = _issue()
    api = FakeAPI(issue)
    results = FakeResults()
    authorization = _authorize_case(api, results)
    payload = _case_result(authorization)
    raw = build_result_envelope(payload, _RESULT_KEY)
    results.documents[bot.result_url(_config(), authorization["authorization_id"])] = raw

    outcome = bot.run(
        "schedule",
        {"repository": _event(issue)["repository"]},
        api=api,
        results=results,
        config=_config(),
        now_unix_s=_NOW + 20,
    )
    assert outcome[0].comments_posted == 2
    result_comment, challenge_comment = api.comments[-2:]
    assert result_comment["body"].startswith(bot.RESULT_MARKER_PREFIX)
    assert payload["case_archive_url"] in result_comment["body"]
    next_challenge = _challenge_from_comment(challenge_comment)
    assert next_challenge["action"] == "ready_to_issue"
    assert next_challenge["predecessor_authorization_id"] == authorization["authorization_id"]
    assert next_challenge["case_manifest_sha256"] == payload["case_manifest_sha256"]
    assert next_challenge["expected_origin"] == payload["expected_origin"]
    assert next_challenge["expires_at"] == bot.format_utc(_NOW + 1_500)
    parsed = parse_public_pilot_automation_result_envelope(raw, hmac_key=_RESULT_KEY)
    assert parsed.payload.status == "case_ready"

    again = bot.run(
        "schedule",
        {"repository": _event(issue)["repository"]},
        api=api,
        results=results,
        config=_config(),
        now_unix_s=_NOW + 21,
    )
    assert again[0].comments_posted == 0


def test_authenticated_authorization_survives_deleted_user_proof_for_result_posting() -> None:
    issue = _issue()
    api = FakeAPI(issue)
    results = FakeResults()
    authorization = _authorize_case(api, results)
    api.comments = [
        comment for comment in api.comments if comment["id"] != authorization["command_comment_id"]
    ]
    payload = _case_result(authorization)
    results.documents[bot.result_url(_config(), authorization["authorization_id"])] = (
        build_result_envelope(payload, _RESULT_KEY)
    )

    outcome = bot.run(
        "schedule",
        {"repository": _event(issue)["repository"]},
        api=api,
        results=results,
        config=_config(),
        now_unix_s=_NOW + 20,
    )
    assert outcome[0].status == "case_ready"
    assert outcome[0].comments_posted == 2
    assert api.comments[-2]["body"].startswith(bot.RESULT_MARKER_PREFIX)
    assert _challenge_from_comment(api.comments[-1])["action"] == "ready_to_issue"


def test_resultless_case_authorization_gets_one_fresh_challenge_after_expiry() -> None:
    issue = _issue()
    api = FakeAPI(issue)
    results = FakeResults()
    authorization = _authorize_case(api, results)

    outcome = bot.run(
        "schedule",
        {"repository": _event(issue)["repository"]},
        api=api,
        results=results,
        config=_config(),
        now_unix_s=_NOW + 86_400,
    )
    assert outcome[0].status == "case_authorization_expired"
    assert outcome[0].comments_posted == 2
    assert "case authorization expired" in api.comments[-2]["body"]
    replacement = _challenge_from_comment(api.comments[-1])
    assert replacement["action"] == "ready_for_case"
    assert replacement["challenge_nonce"] != authorization["challenge_nonce"]

    again = bot.run(
        "schedule",
        {"repository": _event(issue)["repository"]},
        api=api,
        results=results,
        config=_config(),
        now_unix_s=_NOW + 86_401,
    )
    assert again[0].comments_posted == 0


def test_revision_rollover_reconciles_result_but_does_not_advance_old_work() -> None:
    issue = _issue()
    api = FakeAPI(issue)
    results = FakeResults()
    authorization = _authorize_case(api, results)
    payload = _case_result(authorization)
    results.documents[bot.result_url(_config(), authorization["authorization_id"])] = (
        build_result_envelope(payload, _RESULT_KEY)
    )

    outcome = bot.run(
        "schedule",
        {"repository": _event(issue)["repository"]},
        api=api,
        results=results,
        config=_config(revision="ef" * 20),
        now_unix_s=_NOW + 20,
    )
    assert outcome[0].status == "revision_transition_pending"
    assert outcome[0].comments_posted == 1
    assert api.comments[-1]["body"].startswith(bot.RESULT_MARKER_PREFIX)


def test_resultless_issue_authorization_never_creates_a_retry_authorization() -> None:
    issue = _issue()
    api = FakeAPI(issue)
    results = FakeResults()
    case_authorization = _authorize_case(api, results)
    case_payload = _case_result(case_authorization)
    results.documents[bot.result_url(_config(), case_authorization["authorization_id"])] = (
        build_result_envelope(case_payload, _RESULT_KEY)
    )
    bot.run(
        "schedule",
        {"repository": _event(issue)["repository"]},
        api=api,
        results=results,
        config=_config(),
        now_unix_s=_NOW + 20,
    )

    issue_challenge = _challenge_from_comment(api.comments[-1])
    issue_command = api.add_user_comment(_proof(issue_challenge))
    bot.run(
        "issue_comment",
        {**_event(issue), "comment": issue_command},
        api=api,
        results=results,
        config=_config(),
        now_unix_s=_NOW + 30,
    )
    issue_authorization = parse_authorization_marker(api.comments[-1]["body"], _AUTH_KEY)
    assert issue_authorization["action"] == "ready_to_issue"

    cutoff = bot.parse_utc(case_payload["response_close_at"], field="response_close_at") - 300
    waiting = bot.run(
        "schedule",
        {"repository": _event(issue)["repository"]},
        api=api,
        results=results,
        config=_config(),
        now_unix_s=cutoff,
    )
    assert waiting[0].status == "awaiting_terminal_result"
    assert waiting[0].comments_posted == 0

    again = bot.run(
        "schedule",
        {"repository": _event(issue)["repository"]},
        api=api,
        results=results,
        config=_config(),
        now_unix_s=cutoff + 1,
    )
    assert again[0].comments_posted == 0

    results.documents[bot.result_url(_config(), issue_authorization["authorization_id"])] = (
        build_result_envelope(_terminal_result(issue_authorization), _RESULT_KEY)
    )
    late_terminal = bot.run(
        "schedule",
        {"repository": _event(issue)["repository"]},
        api=api,
        results=results,
        config=_config(),
        now_unix_s=cutoff + 2,
    )
    assert late_terminal[0].status == "terminal"
    assert late_terminal[0].comments_posted == 1
    assert "public-pilot pilot complete" in api.comments[-1]["body"]


def test_result_rejects_wrong_path_binding_and_hmac() -> None:
    issue = _issue()
    api = FakeAPI(issue)
    results = FakeResults()
    authorization_payload = _authorize_case(api, results)
    state = bot.collect_comment_state(bot.parse_issue(issue, _config()), api.comments, _config())
    authorization = state.authorizations[0]
    payload = _case_result(authorization_payload)
    payload["case_archive_url"] = "https://objects.example/not-the-bound-object"
    raw = build_result_envelope(payload, _RESULT_KEY)
    with pytest.raises(bot.BoundaryError, match="invalid_archive_url"):
        bot.validate_result(raw, authorization, bot.parse_issue(issue, _config()), _config())
    tampered = raw.replace(b"case_ready", b"case_reedy")
    with pytest.raises(PublicPilotWireError):
        parse_result_envelope(tampered, _RESULT_KEY)


def test_public_origin_rejects_non_dns_and_control_characters() -> None:
    assert bot.validate_public_origin("https://objects.example") == "https://objects.example"
    assert bot.validate_public_origin("https://[2001:4860:4860::8888]:443") == (
        "https://[2001:4860:4860::8888]:443"
    )
    for origin in (
        "https://objects.example\n",
        "https://objects example",
        "https://objects_example",
        "https://Objects.example",
    ):
        with pytest.raises(bot.BoundaryError, match="invalid_public_origin"):
            bot.validate_public_origin(origin)
    for origin in ("https://224.0.0.1:443", "https://[ff02::1]:443"):
        with pytest.raises(bot.BoundaryError, match="invalid_expected_origin"):
            bot.normalize_miner_origin(origin)


def test_incomplete_attempt_is_a_terminal_non_feed_envelope() -> None:
    archive_sha = "ef" * 32
    payload = PublicPilotIncompleteResult(
        schema=RESULT_PAYLOAD_SCHEMA,
        authorization_id="12" * 32,
        action="ready_to_issue",
        repository_id=99,
        repository_full_name="Umi-BitSign/umi",
        issue_id=1_234,
        issue_node_id="I_kwDOExample",
        issue_number=8,
        campaign_id=_CAMPAIGN,
        umi_revision=_REVISION,
        coordinator_hotkey=_COORDINATOR,
        miner_hotkey=_MINER,
        expected_miner_uid=249,
        completed_at=bot.format_utc(_NOW + 2_000),
        status="pilot_incomplete",
        attempt_journal_manifest_sha256="34" * 32,
        attempt_archive_sha256=archive_sha,
        attempt_archive_size_bytes=4_096,
        attempt_archive_url=(
            f"https://objects.example/public-pilot-attempts/{archive_sha}/attempt-journal.tar.gz"
        ),
        completed_through="outcome_recorded",
        failure_stage="reveal_and_scoring",
        failure_code="reveal_timeout",
        request_digest="56" * 32,
    )
    raw = public_pilot_automation_result_envelope(payload, hmac_key=_RESULT_KEY)
    parsed = parse_public_pilot_automation_result_envelope(raw, hmac_key=_RESULT_KEY)
    assert isinstance(parsed.payload, PublicPilotIncompleteResult)
    assert parsed.payload.status == "pilot_incomplete"
    assert "evidence_archive_url" not in parsed.payload.model_dump()


def test_readiness_parser_accepts_one_github_terminal_lf_only() -> None:
    challenge = bot.new_challenge(
        bot.parse_issue(_issue(), _config()),
        _config(),
        action="ready_for_case",
        expires_at_unix_s=_NOW + 60,
        nonce="12" * 32,
    )
    marker = _proof(challenge)
    parsed = bot.parse_readiness_marker(marker, now_unix_s=_NOW)
    assert parsed.payload == bot.build_readiness_payload(challenge)
    parsed_with_lf = bot.parse_readiness_marker(marker + "\n", now_unix_s=_NOW)
    assert parsed_with_lf.payload == parsed.payload
    assert parsed_with_lf.marker == marker + "\n"
    for invalid in (marker + "\n\n", marker + "\r\n", marker + " \n", marker + "\n "):
        with pytest.raises(bot.BoundaryError, match="invalid_readiness_marker"):
            bot.parse_readiness_marker(invalid, now_unix_s=_NOW)
    with pytest.raises(bot.BoundaryError, match="readiness_expired"):
        bot.parse_readiness_marker(marker, now_unix_s=_NOW + 60)


def test_retired_campaign_has_no_github_workflow() -> None:
    assert not (_ROOT / ".github" / "workflows" / "public-pilot-bot.yml").exists()


def test_retired_campaign_has_no_enrollment_form() -> None:
    assert not (_ROOT / ".github" / "ISSUE_TEMPLATE" / "public-miner-pilot.yml").exists()
    operator_guide = (_ROOT / "docs" / "PUBLIC_ENDPOINT_MINER_PILOT.md").read_text()
    with (_ROOT / "pyproject.toml").open("rb") as handle:
        scripts = tomllib.load(handle)["project"]["scripts"]

    assert "This campaign closed on 2026-09-11" in operator_guide
    assert "Enrollment is closed" in operator_guide
    assert "The enrollment issue form has been removed" in operator_guide
    assert "outstanding" in operator_guide
    assert "challenges authorize no work" in operator_guide
    assert operator_guide.count('umi-public-pilot-miner" authorize') == 2
    assert scripts["umi-public-pilot-miner"] == "umi.public_pilot_miner:main"
    assert scripts["umi-public-pilot-controller"] == "umi.public_pilot_controller:main"
