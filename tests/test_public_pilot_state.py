from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from umi.public_pilot_authorization import verify_public_pilot_github_authorization
from umi.public_pilot_readiness import ReadyToIssuePayload
from umi.public_pilot_state import PreparedCaseState, PublicPilotAutomationState

from .test_public_pilot_authorization import _REVISION, _fixture


def _ready_to_issue(verified: object, case: PreparedCaseState, *, suffix: int = 1):
    authorization = verified.authorization.model_copy(  # type: ignore[attr-defined]
        update={
            "authorization_id": f"{suffix + 8:02x}" * 32,
            "action": "ready_to_issue",
            "command_comment_id": 6_000 + suffix,
            "command_node_id": f"IC_issue_{suffix}",
            "command_body_sha256": f"{suffix + 16:02x}" * 32,
            "predecessor_authorization_id": case.authorization_id,
        }
    )
    base_payload = verified.readiness.payload.model_dump(  # type: ignore[attr-defined]
        mode="json", by_alias=True
    )
    base_payload.update(
        {
            "action": "ready_to_issue",
            "predecessor_authorization_id": case.authorization_id,
            "case_manifest_sha256": case.case_manifest_sha256,
            "expected_origin": case.expected_origin,
        }
    )
    payload = ReadyToIssuePayload.model_validate(base_payload)
    return replace(
        verified,
        authorization=authorization,
        readiness=verified.readiness.model_copy(update={"payload": payload}),  # type: ignore[attr-defined]
        bot_comment=replace(
            verified.bot_comment,  # type: ignore[attr-defined]
            id=10_000 + suffix,
            node_id=f"IC_bot_{suffix}",
        ),
        command_comment=replace(
            verified.command_comment,  # type: ignore[attr-defined]
            id=6_000 + suffix,
            node_id=f"IC_issue_{suffix}",
        ),
    )


def test_public_pilot_state_claims_and_expires_one_global_case(tmp_path: Path) -> None:
    bot, github, key = _fixture()
    verified = verify_public_pilot_github_authorization(
        bot,
        github=github,  # type: ignore[arg-type]
        hmac_key=key,
        expected_repository_id=1_348_567_807,
        expected_repository_full_name="Umi-BitSign/umi",
        expected_umi_revision=_REVISION,
        now_unix_s=1_788_700_000,
    )
    state_root = tmp_path / "state"
    state_root.mkdir(mode=0o700)
    metadata = {
        "repository": "Umi-BitSign/umi",
        "campaign": verified.authorization.campaign_id,
        "revision": _REVISION,
    }
    with PublicPilotAutomationState(state_root / "automation.sqlite3", metadata=metadata) as state:
        assert state.enqueue(verified) is True
        assert state.enqueue(verified) is False
        claimed = state.claim_next()
        assert claimed is not None
        assert claimed.authorization_id == verified.authorization.authorization_id
        assert claimed.state == "processing"
        case = PreparedCaseState(
            authorization_id=claimed.authorization_id,
            miner_hotkey=claimed.miner_hotkey,
            miner_account_id32=claimed.miner_account_id32,
            expected_miner_uid=claimed.expected_miner_uid,
            case_root=str(tmp_path / "case"),
            case_manifest_sha256="11" * 32,
            case_archive_sha256="22" * 32,
            case_archive_size_bytes=123,
            case_archive_url=(
                f"https://public.example/public-pilot-cases/{'22' * 32}/sealed-case.tar.gz"
            ),
            expected_origin="https://8.8.8.8:443",
            response_close_round=100,
            reveal_round=200,
            response_close_unix_s=1_788_700_600,
            reveal_unix_s=1_788_700_900,
            active=True,
        )
        state.record_case_ready(case, result_sha256="33" * 32)
        assert state.active_case() == case
        assert state.claim_next() is None
        assert state.expire_active_case(now_unix_s=1_788_700_299) is False
        assert state.expire_active_case(now_unix_s=1_788_700_300) is True
        assert state.active_case() is None
        assert state.get(claimed.authorization_id).state == "superseded"  # type: ignore[union-attr]

    with PublicPilotAutomationState(state_root / "automation.sqlite3", metadata=metadata):
        pass

    try:
        PublicPilotAutomationState(
            state_root / "automation.sqlite3",
            metadata={**metadata, "revision": "cd" * 20},
        )
    except ValueError as error:
        assert "another deployment" in str(error)
    else:
        raise AssertionError("state metadata mismatch was accepted")


def test_issue_claim_requires_exact_active_case_and_is_single_writer(tmp_path: Path) -> None:
    bot, github, key = _fixture()
    verified = verify_public_pilot_github_authorization(
        bot,
        github=github,  # type: ignore[arg-type]
        hmac_key=key,
        expected_repository_id=1_348_567_807,
        expected_repository_full_name="Umi-BitSign/umi",
        expected_umi_revision=_REVISION,
        now_unix_s=1_788_700_000,
    )
    root = tmp_path / "state"
    root.mkdir(mode=0o700)
    database = root / "automation.sqlite3"
    metadata = {"deployment": "test"}
    with (
        PublicPilotAutomationState(database, metadata=metadata) as first,
        PublicPilotAutomationState(database, metadata=metadata) as second,
    ):
        first.enqueue(verified)
        case_authorization = first.claim_next()
        assert case_authorization is not None
        case = PreparedCaseState(
            authorization_id=case_authorization.authorization_id,
            miner_hotkey=case_authorization.miner_hotkey,
            miner_account_id32=case_authorization.miner_account_id32,
            expected_miner_uid=case_authorization.expected_miner_uid,
            case_root=str(tmp_path / "case"),
            case_manifest_sha256="11" * 32,
            case_archive_sha256="22" * 32,
            case_archive_size_bytes=123,
            case_archive_url=(
                f"https://public.example/public-pilot-cases/{'22' * 32}/sealed-case.tar.gz"
            ),
            expected_origin="https://8.8.8.8:443",
            response_close_round=100,
            reveal_round=200,
            response_close_unix_s=1_788_700_600,
            reveal_unix_s=1_788_700_900,
            active=True,
        )
        first.record_case_ready(case, result_sha256="33" * 32)

        valid_issue = _ready_to_issue(verified, case)
        assert first.enqueue(valid_issue) is True
        claimed = first.claim_next()
        assert claimed is not None and claimed.action == "ready_to_issue"
        assert second.claim_next() is None
        first.record_attempt_started(claimed.authorization_id)
        first.finish_attempt(
            claimed.authorization_id,
            state="complete",
            result_sha256="44" * 32,
        )
        duplicate_case = replace(
            verified,
            authorization=verified.authorization.model_copy(
                update={
                    "authorization_id": "55" * 32,
                    "command_comment_id": 6_055,
                    "command_node_id": "IC_duplicate_case",
                }
            ),
            bot_comment=replace(
                verified.bot_comment,
                id=10_055,
                node_id="IC_duplicate_case_bot",
            ),
            command_comment=replace(
                verified.command_comment,
                id=6_055,
                node_id="IC_duplicate_case",
            ),
        )
        first.enqueue(duplicate_case)
        assert first.claim_next() is None


def test_issue_claim_rejects_miner_signed_case_mismatch(tmp_path: Path) -> None:
    bot, github, key = _fixture()
    verified = verify_public_pilot_github_authorization(
        bot,
        github=github,  # type: ignore[arg-type]
        hmac_key=key,
        expected_repository_id=1_348_567_807,
        expected_repository_full_name="Umi-BitSign/umi",
        expected_umi_revision=_REVISION,
        now_unix_s=1_788_700_000,
    )
    root = tmp_path / "state"
    root.mkdir(mode=0o700)
    with PublicPilotAutomationState(
        root / "automation.sqlite3", metadata={"deployment": "test"}
    ) as state:
        state.enqueue(verified)
        case_authorization = state.claim_next()
        assert case_authorization is not None
        case = PreparedCaseState(
            authorization_id=case_authorization.authorization_id,
            miner_hotkey=case_authorization.miner_hotkey,
            miner_account_id32=case_authorization.miner_account_id32,
            expected_miner_uid=case_authorization.expected_miner_uid,
            case_root=str(tmp_path / "case"),
            case_manifest_sha256="11" * 32,
            case_archive_sha256="22" * 32,
            case_archive_size_bytes=123,
            case_archive_url=(
                f"https://public.example/public-pilot-cases/{'22' * 32}/sealed-case.tar.gz"
            ),
            expected_origin="https://8.8.8.8:443",
            response_close_round=100,
            reveal_round=200,
            response_close_unix_s=1_788_700_600,
            reveal_unix_s=1_788_700_900,
            active=True,
        )
        state.record_case_ready(case, result_sha256="33" * 32)
        invalid = _ready_to_issue(verified, case)
        invalid = replace(
            invalid,
            readiness=invalid.readiness.model_copy(
                update={
                    "payload": invalid.readiness.payload.model_copy(
                        update={"case_manifest_sha256": "99" * 32}
                    )
                }
            ),
        )
        state.enqueue(invalid)
        assert state.claim_next() is None
