from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

import umi.public_pilot_controller as controller_module
from umi.public_pilot_campaign import CAMPAIGN_ID
from umi.public_pilot_controller import (
    PublicPilotAutomationConfig,
    PublicPilotController,
    _run_forever,
)
from umi.public_pilot_github import (
    PublicPilotCaseReadyResult,
    public_pilot_automation_result_envelope,
)
from umi.public_pilot_github_client import (
    GithubActor,
    GithubComment,
    GithubNotFoundError,
    GithubRateLimitError,
)

from .test_public_pilot_authorization import _REVISION, _fixture

_COORDINATOR = "5GsPXiSyzpK3rRoeAmjT4F5Cqa1RmP1CyBvNpwNDsDejyNZ4"


class _Github:
    def __init__(self, comments: tuple[GithubComment, ...]) -> None:
        self.comments = comments
        self.calls: list[tuple[str, int]] = []

    def comments_page(self, since: str, *, page: int) -> tuple[GithubComment, ...]:
        self.calls.append((since, page))
        if page == 1:
            return self.comments
        return ()


def _config(tmp_path: Path) -> PublicPilotAutomationConfig:
    return PublicPilotAutomationConfig.model_validate(
        {
            "schema": "umi-public-pilot-automation-config/1",
            "repository_id": 1_348_567_807,
            "repository_full_name": "Umi-BitSign/umi",
            "campaign_id": CAMPAIGN_ID,
            "umi_revision": "ab" * 20,
            "coordinator_hotkey": _COORDINATOR,
            "wallet_name": "coordinator",
            "wallet_hotkey": "default",
            "wallet_path": str(tmp_path / "wallets"),
            "data_root": str(tmp_path / "automation"),
            "spool_incoming_dir": str(tmp_path / "spool"),
            "upload_origin": "https://upload.example",
            "public_r2_origin": "https://objects.example",
            "observer_origin": "https://api.example",
            "initial_github_since": "2026-09-07T00:00:00Z",
        }
    )


def test_controller_requires_slow_polling_only_without_a_read_token(tmp_path: Path) -> None:
    config = _config(tmp_path)
    fast_config = config.model_copy(update={"poll_seconds": 60})
    arguments = {
        "github_hmac_key": bytes.fromhex("11" * 32),
        "result_hmac_key": bytes.fromhex("22" * 32),
        "upload_hmac_key": bytes.fromhex("33" * 32),
        "wallet": object(),
    }

    with pytest.raises(ValueError, match="at least 300"):
        PublicPilotController(fast_config, **arguments)

    with PublicPilotController(config, **arguments):
        pass

    with PublicPilotController(
        fast_config,
        github_token="github_pat_read_only_test",
        **arguments,
    ):
        pass


@pytest.mark.asyncio
async def test_controller_paginates_without_stalling_on_a_full_page(tmp_path: Path) -> None:
    actor = GithubActor(id=99, login="ordinary-user", type="User")
    comments = tuple(
        GithubComment(
            id=index + 1,
            node_id=f"IC_{index + 1}",
            body="not an authorization",
            created_at="2026-09-07T00:01:00Z",
            updated_at="2026-09-07T00:01:00Z",
            user=actor,
        )
        for index in range(100)
    )
    github = _Github(comments)
    config = _config(tmp_path)
    with PublicPilotController(
        config,
        github_hmac_key=bytes.fromhex("11" * 32),
        result_hmac_key=bytes.fromhex("22" * 32),
        upload_hmac_key=bytes.fromhex("33" * 32),
        github=github,  # type: ignore[arg-type]
        wallet=object(),
    ) as controller:
        assert await controller.process_once() is False
        assert controller.state.runtime_value("github_page", default="") == "2"
        assert await controller.process_once() is False
        assert controller.state.runtime_value("github_page", default="") == "1"
        assert controller.state.runtime_value("github_since", default="") == (
            "2026-09-07T00:01:00Z"
        )
    assert github.calls == [
        ("2026-09-07T00:00:00Z", 1),
        ("2026-09-07T00:00:00Z", 2),
    ]


@pytest.mark.asyncio
async def test_controller_waits_for_github_rate_limit_backoff(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    delays: list[float] = []

    class StopLoop(Exception):
        pass

    class RateLimitedController:
        config = SimpleNamespace(poll_seconds=60)

        @staticmethod
        async def process_once() -> bool:
            raise GithubRateLimitError(137, status_code=429)

    async def stop_after_delay(delay: float) -> None:
        delays.append(delay)
        raise StopLoop

    monkeypatch.setattr(controller_module.asyncio, "sleep", stop_after_delay)
    with pytest.raises(StopLoop):
        await _run_forever(RateLimitedController())  # type: ignore[arg-type]

    assert delays == [137]


def test_controller_systemd_token_credential_is_explicitly_opt_in() -> None:
    root = Path(__file__).resolve().parents[1]
    service = (
        root / "deploy/public-pilot-automation/systemd/umi-public-pilot-controller.service"
    ).read_text(encoding="utf-8")
    drop_in = (
        root / "deploy/public-pilot-automation/systemd/"
        "umi-public-pilot-controller-token.conf.example"
    ).read_text(encoding="utf-8")
    example = json.loads(
        (
            root / "deploy/public-pilot-automation/systemd/public-pilot-automation.json.example"
        ).read_bytes()
    )

    assert "LoadCredential=github-api-token:" not in service
    assert "--github-token-file" not in service
    assert "LoadCredential=github-api-token:" in drop_in
    assert "--github-token-file %d/github-api-token" in drop_in
    assert "Environment=GITHUB_TOKEN=" not in service
    assert example["poll_seconds"] == 300


@pytest.mark.asyncio
async def test_deterministically_invalid_authorization_is_superseded(
    tmp_path: Path,
) -> None:
    bot_comment, github, key = _fixture()
    config = _config(tmp_path).model_copy(update={"umi_revision": _REVISION})
    with PublicPilotController(
        config,
        github_hmac_key=key,
        result_hmac_key=bytes.fromhex("22" * 32),
        upload_hmac_key=bytes.fromhex("33" * 32),
        github=github,  # type: ignore[arg-type]
        wallet=object(),
    ) as controller:
        verified = controller._verify_bot_comment(bot_comment)
        assert controller.state.enqueue(verified) is True
        github._issue = replace(github._issue, state="closed")
        controller.poll_github = lambda: 0  # type: ignore[method-assign]

        assert await controller.process_once() is True
        stored = controller.state.get(verified.authorization.authorization_id)
        assert stored is not None and stored.state == "superseded"
        assert controller.state.claim_next() is None


@pytest.mark.asyncio
async def test_deleted_authorization_comment_is_superseded_without_retry(
    tmp_path: Path,
) -> None:
    bot_comment, github, key = _fixture()
    config = _config(tmp_path).model_copy(update={"umi_revision": _REVISION})
    with PublicPilotController(
        config,
        github_hmac_key=key,
        result_hmac_key=bytes.fromhex("22" * 32),
        upload_hmac_key=bytes.fromhex("33" * 32),
        github=github,  # type: ignore[arg-type]
        wallet=object(),
    ) as controller:
        verified = controller._verify_bot_comment(bot_comment)
        assert controller.state.enqueue(verified) is True
        controller.poll_github = lambda: 0  # type: ignore[method-assign]

        def missing_comment(_comment_id: int) -> GithubComment:
            raise GithubNotFoundError()

        github.comment = missing_comment  # type: ignore[method-assign]
        assert await controller.process_once() is True

        stored = controller.state.get(verified.authorization.authorization_id)
        assert stored is not None and stored.state == "superseded"
        assert controller.state.claim_next() is None


@pytest.mark.asyncio
async def test_case_recovery_republishes_preserved_result_before_state_transition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bot_comment, github, key = _fixture()
    result_key = bytes.fromhex("22" * 32)
    config = _config(tmp_path).model_copy(update={"umi_revision": _REVISION})
    with PublicPilotController(
        config,
        github_hmac_key=key,
        result_hmac_key=result_key,
        upload_hmac_key=bytes.fromhex("33" * 32),
        github=github,  # type: ignore[arg-type]
        wallet=object(),
    ) as controller:
        verified = controller._verify_bot_comment(bot_comment)
        assert controller.state.enqueue(verified) is True
        claimed = controller.state.claim_next()
        assert claimed is not None
        assert claimed.action == "ready_for_case"
        assert claimed.state == "processing"

        root = controller._authorization_root(claimed.authorization_id)
        case_root = root / "sealed-case"
        case_root.mkdir(mode=0o700)
        manifest_bytes = b"canonical manifest snapshot"
        archive_bytes = b"sealed case archive"
        archive_sha256 = hashlib.sha256(archive_bytes).hexdigest()
        (root / "sealed-case.tar.gz").write_bytes(archive_bytes)
        payload = PublicPilotCaseReadyResult.model_validate(
            controller._result_common(claimed)
            | {
                "status": "case_ready",
                "case_manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
                "case_archive_sha256": archive_sha256,
                "case_archive_size_bytes": len(archive_bytes),
                "case_archive_url": (
                    "https://objects.example/public-pilot-cases/"
                    f"{archive_sha256}/sealed-case.tar.gz"
                ),
                "expected_origin": "https://8.8.8.8:443",
                "response_close_round": 100,
                "reveal_round": 101,
                "response_close_at": "2026-09-07T21:00:00Z",
                "reveal_at": "2026-09-07T21:05:00Z",
            }
        )
        body = public_pilot_automation_result_envelope(payload, hmac_key=result_key)
        (root / "automation-result.json").write_bytes(body)

        def load_campaign(_root: Path) -> SimpleNamespace:
            return SimpleNamespace(
                expected_miner_uid=claimed.expected_miner_uid,
                expected_miner_hotkey=claimed.miner_hotkey,
                coordinator_hotkey=_COORDINATOR,
            )

        class FakeEvidenceStore:
            def __init__(self, _root: Path) -> None:
                pass

            @staticmethod
            def load_manifest_with_bytes() -> tuple[object, bytes]:
                return object(), manifest_bytes

        uploads: list[str] = []

        def save_and_upload_result(
            root_argument: Path,
            authorization_id: str,
            recovered_payload: PublicPilotCaseReadyResult,
        ) -> str:
            current = controller.state.get(authorization_id)
            assert current is not None and current.state == "processing"
            assert controller.state.active_case() is None
            assert root_argument == root
            assert authorization_id == claimed.authorization_id
            assert recovered_payload == payload
            uploads.append(authorization_id)
            return hashlib.sha256(body).hexdigest()

        monkeypatch.setattr(controller_module, "load_public_pilot_campaign", load_campaign)
        monkeypatch.setattr(controller_module, "EvidenceStore", FakeEvidenceStore)
        monkeypatch.setattr(controller, "_save_and_upload_result", save_and_upload_result)

        assert await controller.recover_durable_work() is True
        assert uploads == [claimed.authorization_id]
        stored = controller.state.get(claimed.authorization_id)
        assert stored is not None and stored.state == "case_ready"
        active_case = controller.state.active_case()
        assert active_case is not None
        assert active_case.authorization_id == claimed.authorization_id
