"""Always-on coordinator for GitHub-authorized public miner pilots."""

from __future__ import annotations

import argparse
import asyncio
import fcntl
import hashlib
import hmac
import logging
import os
import re
import stat
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator
from typing_extensions import Self

from .audit import EvidenceStore, _read_bounded_regular_file
from .chain import discover_miner_finalized
from .encoding import account_id32
from .protocol import StrictProtocolModel, canonical_json_bytes
from .public_pilot_archive import (
    MAX_PUBLIC_PILOT_ARCHIVE_BYTES,
    create_evidence_archive,
)
from .public_pilot_authorization import (
    GITHUB_ACTIONS_BOT_ID,
    GITHUB_ACTIONS_BOT_LOGIN,
    VerifiedPublicPilotAuthorization,
    verify_public_pilot_github_authorization,
)
from .public_pilot_campaign import CAMPAIGN_ID, load_public_pilot_campaign
from .public_pilot_coordinator import (
    prepare_public_endpoint_pilot_case,
    replay_public_endpoint_pilot,
    run_public_endpoint_pilot,
)
from .public_pilot_github import (
    PublicPilotCaseReadyResult,
    PublicPilotIncompleteResult,
    PublicPilotTerminalResult,
    parse_public_pilot_automation_result_envelope,
    public_pilot_automation_result_envelope,
)
from .public_pilot_github_client import (
    GithubRateLimitError,
    PublicPilotGithubClient,
    load_github_token,
)
from .public_pilot_journal import PublicPilotAttemptJournal, load_attempt_journal
from .public_pilot_readiness import ReadyToIssuePayload
from .public_pilot_spool import enqueue_publication_archive
from .public_pilot_state import (
    PreparedCaseState,
    PublicPilotAutomationState,
    QueuedAuthorization,
)
from .public_pilot_upload import (
    load_hex_secret,
    upload_public_pilot_file,
    upload_public_pilot_result,
)

LOGGER = logging.getLogger("umi.public_pilot_controller")
PUBLIC_PILOT_AUTOMATION_CONFIG_SCHEMA = "umi-public-pilot-automation-config/1"
MAX_PUBLIC_PILOT_AUTOMATION_CONFIG_BYTES = 64 * 1024
MAX_CASE_ARCHIVE_BYTES = MAX_PUBLIC_PILOT_ARCHIVE_BYTES

_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_RFC3339_SECONDS = re.compile(
    r"^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$"
)
_AUTHORIZATION_MARKER_START = "<!-- umi-public-pilot-authorization-v1:"


def _origin(value: str, field: str) -> str:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise ValueError(f"{field} is not a valid HTTPS origin") from error
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or value.endswith("/")
        or (port is not None and not 1 <= port <= 65_535)
    ):
        raise ValueError(f"{field} is not a valid HTTPS origin")
    return value


def _absolute_path(value: str, field: str) -> str:
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError(f"{field} must be an absolute normalized path")
    return str(path)


class PublicPilotAutomationConfig(StrictProtocolModel):
    schema_: Literal[PUBLIC_PILOT_AUTOMATION_CONFIG_SCHEMA] = Field(alias="schema")
    repository_id: Annotated[int, Field(ge=1, le=(1 << 53) - 1)]
    repository_full_name: Literal["Umi-BitSign/umi"] = "Umi-BitSign/umi"
    github_actions_bot_id: Literal[GITHUB_ACTIONS_BOT_ID] = GITHUB_ACTIONS_BOT_ID
    github_actions_bot_login: Literal[GITHUB_ACTIONS_BOT_LOGIN] = GITHUB_ACTIONS_BOT_LOGIN
    campaign_id: Literal[CAMPAIGN_ID] = CAMPAIGN_ID
    umi_revision: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
    coordinator_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    wallet_name: Annotated[str, Field(min_length=1, max_length=128)]
    wallet_hotkey: Annotated[str, Field(min_length=1, max_length=128)]
    wallet_path: Annotated[str, Field(min_length=1, max_length=1_024)]
    data_root: Annotated[str, Field(min_length=1, max_length=1_024)]
    spool_incoming_dir: Annotated[str, Field(min_length=1, max_length=1_024)]
    upload_origin: Annotated[str, Field(min_length=1, max_length=512)]
    public_r2_origin: Annotated[str, Field(min_length=1, max_length=512)]
    observer_origin: Annotated[str, Field(min_length=1, max_length=512)]
    initial_github_since: Annotated[str, Field(min_length=20, max_length=20)]
    poll_seconds: Annotated[int, Field(ge=15, le=3_600)] = 300
    request_timeout_seconds: Annotated[int, Field(ge=1, le=240)] = 240

    @field_validator("coordinator_hotkey")
    @classmethod
    def validate_coordinator(cls, value: str) -> str:
        try:
            account_id32(value)
        except ValueError as error:
            raise ValueError("coordinator_hotkey is not an AccountId32 SS58 address") from error
        return value

    @field_validator("wallet_path", "data_root", "spool_incoming_dir")
    @classmethod
    def validate_path(cls, value: str, info: object) -> str:
        return _absolute_path(value, getattr(info, "field_name", "path"))

    @field_validator("upload_origin", "public_r2_origin", "observer_origin")
    @classmethod
    def validate_origin(cls, value: str, info: object) -> str:
        return _origin(value, getattr(info, "field_name", "origin"))

    @field_validator("initial_github_since")
    @classmethod
    def validate_since(cls, value: str) -> str:
        if _RFC3339_SECONDS.fullmatch(value) is None:
            raise ValueError("initial_github_since must be second-precision UTC")
        try:
            time.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError as error:
            raise ValueError("initial_github_since is not calendar-valid") from error
        return value

    @model_validator(mode="after")
    def validate_origins(self) -> Self:
        if len({self.upload_origin, self.public_r2_origin, self.observer_origin}) != 3:
            raise ValueError("upload, public R2, and observer origins must be distinct")
        return self


def load_public_pilot_automation_config(path: Path) -> PublicPilotAutomationConfig:
    raw = _read_bounded_regular_file(path, MAX_PUBLIC_PILOT_AUTOMATION_CONFIG_BYTES)
    try:
        config = PublicPilotAutomationConfig.model_validate_json(raw)
    except ValueError as error:
        raise ValueError("public-pilot automation config is invalid") from error
    if canonical_json_bytes(config) != raw:
        raise ValueError("public-pilot automation config is not canonical JSON")
    return config


def _utc_text(unix_seconds: int | None = None) -> str:
    value = int(time.time()) if unix_seconds is None else unix_seconds
    return datetime.fromtimestamp(value, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _timelock_unix_seconds(round_number: int) -> int:
    import bittensor as bt

    return int(bt.timelock.reveal_time(round_number).timestamp())


def _require_private_directory(path: Path, *, create: bool = False) -> Path:
    resolved = path.expanduser().resolve(strict=False)
    if create:
        resolved.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(resolved, 0o700)
    metadata = resolved.lstat()
    if (
        resolved.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_mode & 0o077
    ):
        raise ValueError("public-pilot automation directory is unsafe")
    return resolved


def _write_new(path: Path, data: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise OSError("public-pilot automation write made no progress")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


@contextmanager
def _controller_lock(path: Path) -> Iterator[None]:
    descriptor = os.open(
        path,
        os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid():
            raise ValueError("public-pilot controller lock is unsafe")
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(descriptor)


class PublicPilotController:
    """Poll authorizations and advance one globally serialized pilot at a time."""

    def __init__(
        self,
        config: PublicPilotAutomationConfig,
        *,
        github_hmac_key: bytes,
        result_hmac_key: bytes,
        upload_hmac_key: bytes,
        github_token: str | None = None,
        github: PublicPilotGithubClient | None = None,
        wallet: Any | None = None,
    ) -> None:
        self.config = config
        self.data_root = _require_private_directory(Path(config.data_root), create=True)
        for name in ("authorizations", "archives"):
            _require_private_directory(self.data_root / name, create=True)
        self.github_hmac_key = github_hmac_key
        self.result_hmac_key = result_hmac_key
        self.upload_hmac_key = upload_hmac_key
        if github is None:
            if github_token is None and config.poll_seconds < 300:
                raise ValueError(
                    "unauthenticated GitHub polling requires poll_seconds of at least 300"
                )
            self._github = PublicPilotGithubClient(
                config.repository_full_name,
                user_agent_revision=config.umi_revision,
                token=github_token,
            )
        else:
            self._github = github
        self._owns_github = github is None
        if wallet is None:
            import bittensor as bt

            wallet = bt.Wallet(
                name=config.wallet_name,
                hotkey=config.wallet_hotkey,
                path=config.wallet_path,
            )
        self.wallet = wallet
        self.state = PublicPilotAutomationState(
            self.data_root / "automation.sqlite3",
            metadata={
                "campaign_id": config.campaign_id,
                "coordinator_hotkey": config.coordinator_hotkey,
                "repository_full_name": config.repository_full_name,
                "repository_id": str(config.repository_id),
            },
        )

    def close(self) -> None:
        self.state.close()
        if self._owns_github:
            self._github.close()

    def __enter__(self) -> PublicPilotController:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def _verify_bot_comment(self, comment: Any) -> VerifiedPublicPilotAuthorization:
        return verify_public_pilot_github_authorization(
            comment,
            github=self._github,
            hmac_key=self.github_hmac_key,
            expected_repository_id=self.config.repository_id,
            expected_repository_full_name=self.config.repository_full_name,
            expected_umi_revision=self.config.umi_revision,
            expected_campaign_id=self.config.campaign_id,
        )

    def poll_github(self) -> int:
        since = self.state.runtime_value("github_since", default=self.config.initial_github_since)
        page_text = self.state.runtime_value("github_page", default="1")
        if not page_text.isdecimal() or page_text == "0":
            raise RuntimeError("durable GitHub page cursor is invalid")
        page = int(page_text)
        comments = self._github.comments_page(since, page=page)
        accepted = 0
        for comment in comments:
            if self.state.bot_comment_seen(comment.id):
                continue
            if (
                comment.user.id != self.config.github_actions_bot_id
                or comment.user.login != self.config.github_actions_bot_login
                or _AUTHORIZATION_MARKER_START not in comment.body
            ):
                continue
            try:
                verified = self._verify_bot_comment(comment)
                self.state.enqueue(verified)
            except ValueError:
                LOGGER.warning(
                    "ignored invalid public-pilot authorization comment id=%d", comment.id
                )
                self.state.record_bot_comment(
                    comment.id,
                    disposition="ignored",
                    reason_code="authorization_invalid",
                )
            else:
                accepted += 1
                self.state.record_bot_comment(
                    comment.id,
                    disposition="accepted",
                    reason_code="authorization_accepted",
                )
        if len(comments) == 100:
            self.state.set_runtime_value(
                "github_scan_last_created_at",
                comments[-1].created_at,
            )
            self.state.set_runtime_value("github_page", str(page + 1))
        else:
            completed_through = (
                comments[-1].created_at
                if comments
                else self.state.runtime_value(
                    "github_scan_last_created_at",
                    default=since,
                )
            )
            self.state.set_runtime_value("github_since", completed_through)
            self.state.set_runtime_value(
                "github_scan_last_created_at",
                completed_through,
            )
            self.state.set_runtime_value("github_page", "1")
        return accepted

    def _authorization_root(self, authorization_id: str) -> Path:
        if re.fullmatch(r"[0-9a-f]{64}", authorization_id) is None:
            raise ValueError("public-pilot authorization ID is invalid")
        return _require_private_directory(
            self.data_root / "authorizations" / authorization_id,
            create=True,
        )

    def _result_common(self, authorization: QueuedAuthorization) -> dict[str, object]:
        return {
            "schema": "umi-public-pilot-automation-result/1",
            "authorization_id": authorization.authorization_id,
            "action": authorization.action,
            "repository_id": self.config.repository_id,
            "repository_full_name": self.config.repository_full_name,
            "issue_id": authorization.issue_id,
            "issue_node_id": authorization.issue_node_id,
            "issue_number": authorization.issue_number,
            "campaign_id": self.config.campaign_id,
            "umi_revision": authorization.umi_revision,
            "coordinator_hotkey": self.config.coordinator_hotkey,
            "miner_hotkey": authorization.miner_hotkey,
            "expected_miner_uid": authorization.expected_miner_uid,
            "completed_at": _utc_text(),
        }

    def _save_and_upload_result(
        self,
        root: Path,
        authorization_id: str,
        payload: (
            PublicPilotCaseReadyResult | PublicPilotTerminalResult | PublicPilotIncompleteResult
        ),
    ) -> str:
        result_path = root / "automation-result.json"
        if result_path.exists():
            body = _read_bounded_regular_file(result_path, 256 * 1024)
            existing = parse_public_pilot_automation_result_envelope(
                body,
                hmac_key=self.result_hmac_key,
            ).payload
            expected_fields = payload.model_dump(mode="json", by_alias=True)
            existing_fields = existing.model_dump(mode="json", by_alias=True)
            expected_fields.pop("completed_at")
            existing_fields.pop("completed_at")
            if type(existing) is not type(payload) or existing_fields != expected_fields:
                raise ValueError("local automation result conflicts with its immutable bytes")
        else:
            body = public_pilot_automation_result_envelope(
                payload,
                hmac_key=self.result_hmac_key,
            )
            _write_new(result_path, body)
            _fsync_directory(root)
        digest, _size, _url = upload_public_pilot_result(
            body,
            authorization_id=authorization_id,
            result_hmac_key=self.result_hmac_key,
            upload_origin=self.config.upload_origin,
            public_origin=self.config.public_r2_origin,
            secret=self.upload_hmac_key,
        )
        return digest

    async def _prepare_case(self, verified: VerifiedPublicPilotAuthorization) -> None:
        authorization = verified.authorization
        queued = self.state.get(authorization.authorization_id)
        if queued is None or queued.state != "processing" or queued.action != "ready_for_case":
            raise ValueError("case authorization is not in its durable processing state")
        root = self._authorization_root(authorization.authorization_id)
        endpoint = await discover_miner_finalized(
            verified.enrollment.miner_hotkey,
            network="finney",
            netuid=78,
        )
        if (
            account_id32(endpoint.hotkey) != account_id32(verified.enrollment.miner_hotkey)
            or endpoint.uid != verified.enrollment.uid
            or endpoint.validator_permit
        ):
            raise ValueError("finalized chain enrollment is not an eligible miner endpoint")

        case_root = root / "sealed-case"
        if not case_root.exists():
            prepare_public_endpoint_pilot_case(
                case_root,
                wallet=self.wallet,
                expected_coordinator_hotkey=self.config.coordinator_hotkey,
                expected_miner_uid=verified.enrollment.uid,
                expected_miner_hotkey=verified.enrollment.miner_hotkey,
            )
        campaign = load_public_pilot_campaign(case_root)
        if (
            campaign.expected_miner_uid != verified.enrollment.uid
            or account_id32(campaign.expected_miner_hotkey)
            != account_id32(verified.enrollment.miner_hotkey)
            or account_id32(campaign.coordinator_hotkey)
            != account_id32(self.config.coordinator_hotkey)
        ):
            raise ValueError("prepared case does not match its GitHub authorization")
        _manifest, manifest_bytes = EvidenceStore(case_root).load_manifest_with_bytes()
        manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
        archive = root / "sealed-case.tar.gz"
        if not archive.exists():
            create_evidence_archive(case_root, archive, archive_root="sealed-case")
        archive_bytes = _read_bounded_regular_file(archive, MAX_CASE_ARCHIVE_BYTES)
        archive_sha256 = hashlib.sha256(archive_bytes).hexdigest()
        uploaded_sha256, archive_size, archive_url = upload_public_pilot_file(
            archive,
            path=f"/public-pilot-cases/{archive_sha256}/sealed-case.tar.gz",
            content_type="application/gzip",
            maximum_bytes=MAX_CASE_ARCHIVE_BYTES,
            upload_origin=self.config.upload_origin,
            public_origin=self.config.public_r2_origin,
            secret=self.upload_hmac_key,
        )
        if uploaded_sha256 != archive_sha256:
            raise RuntimeError("case archive upload returned another digest")
        close_unix = _timelock_unix_seconds(campaign.response_close_round)
        reveal_unix = _timelock_unix_seconds(campaign.reveal_round)
        payload = PublicPilotCaseReadyResult.model_validate(
            self._result_common(queued)
            | {
                "status": "case_ready",
                "case_manifest_sha256": manifest_sha256,
                "case_archive_sha256": archive_sha256,
                "case_archive_size_bytes": archive_size,
                "case_archive_url": archive_url,
                "expected_origin": endpoint.origin,
                "response_close_round": campaign.response_close_round,
                "reveal_round": campaign.reveal_round,
                "response_close_at": _utc_text(close_unix),
                "reveal_at": _utc_text(reveal_unix),
            }
        )
        result_sha256 = self._save_and_upload_result(
            root,
            authorization.authorization_id,
            payload,
        )
        self.state.record_case_ready(
            PreparedCaseState(
                authorization_id=authorization.authorization_id,
                miner_hotkey=verified.enrollment.miner_hotkey,
                miner_account_id32=account_id32(verified.enrollment.miner_hotkey).hex(),
                expected_miner_uid=verified.enrollment.uid,
                case_root=str(case_root),
                case_manifest_sha256=manifest_sha256,
                case_archive_sha256=archive_sha256,
                case_archive_size_bytes=archive_size,
                case_archive_url=archive_url,
                expected_origin=endpoint.origin,
                response_close_round=campaign.response_close_round,
                reveal_round=campaign.reveal_round,
                response_close_unix_s=close_unix,
                reveal_unix_s=reveal_unix,
                active=True,
            ),
            result_sha256=result_sha256,
        )

    async def _finish_completed_attempt(
        self,
        authorization: QueuedAuthorization,
        output: Path,
    ) -> None:
        replay = replay_public_endpoint_pilot(output)
        if (
            replay["miner_uid"] != authorization.expected_miner_uid
            or account_id32(str(replay["miner_hotkey"])) != account_id32(authorization.miner_hotkey)
            or replay["announced_origin"] != authorization.expected_origin
            or account_id32(str(replay["coordinator_hotkey"]))
            != account_id32(self.config.coordinator_hotkey)
        ):
            raise ValueError("completed pilot does not match its durable authorization")
        root = self._authorization_root(authorization.authorization_id)
        archive = root / "evidence.tar.gz"
        if not archive.exists():
            create_evidence_archive(output, archive, archive_root="bundle")
        archive_bytes = _read_bounded_regular_file(archive, MAX_PUBLIC_PILOT_ARCHIVE_BYTES)
        archive_sha256 = hashlib.sha256(archive_bytes).hexdigest()
        uploaded_sha256, archive_size, archive_url = upload_public_pilot_file(
            archive,
            path=f"/public-pilot-evidence/{archive_sha256}/evidence.tar.gz",
            content_type="application/gzip",
            maximum_bytes=MAX_PUBLIC_PILOT_ARCHIVE_BYTES,
            upload_origin=self.config.upload_origin,
            public_origin=self.config.public_r2_origin,
            secret=self.upload_hmac_key,
        )
        if uploaded_sha256 != archive_sha256:
            raise RuntimeError("evidence archive upload returned another digest")
        enqueue_publication_archive(archive, Path(self.config.spool_incoming_dir))
        payload = PublicPilotTerminalResult.model_validate(
            self._result_common(authorization)
            | {
                "status": "pilot_complete",
                "evidence_manifest_sha256": replay["bundle_manifest_sha256"],
                "evidence_archive_sha256": archive_sha256,
                "evidence_archive_size_bytes": archive_size,
                "evidence_archive_url": archive_url,
                "outcome_classification": replay["outcome"],
                "failure_code": replay["failure_code"],
                "request_digest": replay["request_digest"],
            }
        )
        result_sha256 = self._save_and_upload_result(
            root,
            authorization.authorization_id,
            payload,
        )
        self.state.finish_attempt(
            authorization.authorization_id,
            state="complete",
            result_sha256=result_sha256,
        )

    async def _finish_incomplete_attempt(
        self,
        authorization: QueuedAuthorization,
        journal_root: Path,
    ) -> None:
        verified_journal = load_attempt_journal(journal_root)
        manifest = verified_journal.manifest
        if manifest.phase != "incomplete":
            inferred_stage: Literal[
                "request_send",
                "reveal_and_scoring",
                "attachment",
                "publication",
            ]
            if manifest.completed_through == "attempt_started":
                inferred_stage = "request_send"
            elif manifest.completed_through == "outcome_recorded":
                inferred_stage = "reveal_and_scoring"
            else:
                inferred_stage = "attachment"
            PublicPilotAttemptJournal(journal_root, manifest).mark_incomplete(inferred_stage)
            verified_journal = load_attempt_journal(journal_root)
            manifest = verified_journal.manifest
        if (
            manifest.failure_stage is None
            or manifest.expected_miner_uid != authorization.expected_miner_uid
            or account_id32(manifest.miner_hotkey) != account_id32(authorization.miner_hotkey)
            or manifest.announced_origin != authorization.expected_origin
            or account_id32(manifest.coordinator_hotkey)
            != account_id32(self.config.coordinator_hotkey)
            or manifest.case_manifest_sha256 != authorization.case_manifest_sha256
        ):
            raise ValueError("attempt journal does not match its durable authorization")

        root = self._authorization_root(authorization.authorization_id)
        archive = root / "attempt-journal.tar.gz"
        if not archive.exists():
            create_evidence_archive(
                journal_root,
                archive,
                archive_root="attempt-journal",
            )
        archive_bytes = _read_bounded_regular_file(archive, MAX_PUBLIC_PILOT_ARCHIVE_BYTES)
        archive_sha256 = hashlib.sha256(archive_bytes).hexdigest()
        uploaded_sha256, archive_size, archive_url = upload_public_pilot_file(
            archive,
            path=(f"/public-pilot-attempts/{archive_sha256}/attempt-journal.tar.gz"),
            content_type="application/gzip",
            maximum_bytes=MAX_PUBLIC_PILOT_ARCHIVE_BYTES,
            upload_origin=self.config.upload_origin,
            public_origin=self.config.public_r2_origin,
            secret=self.upload_hmac_key,
        )
        if uploaded_sha256 != archive_sha256:
            raise RuntimeError("attempt-journal upload returned another digest")
        payload = PublicPilotIncompleteResult.model_validate(
            self._result_common(authorization)
            | {
                "status": "pilot_incomplete",
                "attempt_journal_manifest_sha256": verified_journal.manifest_sha256,
                "attempt_archive_sha256": archive_sha256,
                "attempt_archive_size_bytes": archive_size,
                "attempt_archive_url": archive_url,
                "completed_through": manifest.completed_through,
                "failure_stage": manifest.failure_stage,
                "failure_code": "coordinator_incomplete_after_contact",
                "request_digest": manifest.request_digest,
            }
        )
        result_sha256 = self._save_and_upload_result(
            root,
            authorization.authorization_id,
            payload,
        )
        self.state.finish_attempt(
            authorization.authorization_id,
            state="incomplete",
            result_sha256=result_sha256,
        )

    async def _run_case(self, verified: VerifiedPublicPilotAuthorization) -> None:
        authorization = verified.authorization
        if not isinstance(verified.readiness.payload, ReadyToIssuePayload):
            raise ValueError("READY_TO_ISSUE authorization has no issue payload")
        case = self.state.case(authorization.predecessor_authorization_id or "")
        if case is None or not case.active:
            raise ValueError("READY_TO_ISSUE authorization has no active prepared case")
        payload = verified.readiness.payload
        if (
            account_id32(case.miner_hotkey) != account_id32(verified.enrollment.miner_hotkey)
            or case.expected_miner_uid != verified.enrollment.uid
            or not hmac.compare_digest(payload.case_manifest_sha256, case.case_manifest_sha256)
            or payload.expected_origin != case.expected_origin
        ):
            raise ValueError("miner issue authorization does not match the exact prepared case")
        root = self._authorization_root(authorization.authorization_id)
        output = root / "result"

        def attempt_started(_journal_root: Path) -> None:
            self.state.record_attempt_started(authorization.authorization_id)

        await run_public_endpoint_pilot(
            Path(case.case_root),
            output,
            wallet=self.wallet,
            network="finney",
            request_timeout_seconds=self.config.request_timeout_seconds,
            expected_case_manifest_sha256=case.case_manifest_sha256,
            expected_origin=case.expected_origin,
            on_attempt_started=attempt_started,
        )
        current = self.state.get(authorization.authorization_id)
        if current is None or current.state != "attempt_started":
            raise RuntimeError("completed pilot lost its durable attempt state")
        await self._finish_completed_attempt(current, output)

    def _recover_case_ready(self, authorization: QueuedAuthorization, body: bytes) -> None:
        envelope = parse_public_pilot_automation_result_envelope(
            body,
            hmac_key=self.result_hmac_key,
        )
        payload = envelope.payload
        if (
            not isinstance(payload, PublicPilotCaseReadyResult)
            or payload.authorization_id != authorization.authorization_id
            or payload.miner_hotkey != authorization.miner_hotkey
            or payload.expected_miner_uid != authorization.expected_miner_uid
            or payload.coordinator_hotkey != self.config.coordinator_hotkey
        ):
            raise ValueError("preserved case result does not match durable authorization")
        root = self._authorization_root(authorization.authorization_id)
        case_root = root / "sealed-case"
        campaign = load_public_pilot_campaign(case_root)
        _manifest, manifest_bytes = EvidenceStore(case_root).load_manifest_with_bytes()
        archive = root / "sealed-case.tar.gz"
        archive_bytes = _read_bounded_regular_file(archive, MAX_CASE_ARCHIVE_BYTES)
        if (
            hashlib.sha256(manifest_bytes).hexdigest() != payload.case_manifest_sha256
            or hashlib.sha256(archive_bytes).hexdigest() != payload.case_archive_sha256
            or len(archive_bytes) != payload.case_archive_size_bytes
            or campaign.expected_miner_uid != payload.expected_miner_uid
            or account_id32(campaign.expected_miner_hotkey) != account_id32(payload.miner_hotkey)
            or account_id32(campaign.coordinator_hotkey) != account_id32(payload.coordinator_hotkey)
        ):
            raise ValueError("preserved case artifacts do not match their result")
        result_sha256 = self._save_and_upload_result(
            root,
            authorization.authorization_id,
            payload,
        )
        if not hmac.compare_digest(result_sha256, hashlib.sha256(body).hexdigest()):
            raise RuntimeError("recovered case result upload returned another digest")
        self.state.record_case_ready(
            PreparedCaseState(
                authorization_id=authorization.authorization_id,
                miner_hotkey=payload.miner_hotkey,
                miner_account_id32=account_id32(payload.miner_hotkey).hex(),
                expected_miner_uid=payload.expected_miner_uid,
                case_root=str(case_root),
                case_manifest_sha256=payload.case_manifest_sha256,
                case_archive_sha256=payload.case_archive_sha256,
                case_archive_size_bytes=payload.case_archive_size_bytes,
                case_archive_url=payload.case_archive_url,
                expected_origin=payload.expected_origin,
                response_close_round=payload.response_close_round,
                reveal_round=payload.reveal_round,
                response_close_unix_s=int(
                    datetime.strptime(
                        payload.response_close_at,
                        "%Y-%m-%dT%H:%M:%SZ",
                    )
                    .replace(tzinfo=timezone.utc)
                    .timestamp()
                ),
                reveal_unix_s=int(
                    datetime.strptime(
                        payload.reveal_at,
                        "%Y-%m-%dT%H:%M:%SZ",
                    )
                    .replace(tzinfo=timezone.utc)
                    .timestamp()
                ),
                active=True,
            ),
            result_sha256=result_sha256,
        )

    async def recover_durable_work(self) -> bool:
        """Recover one interrupted transition without ever repeating contact."""

        processing = self.state.in_states("processing")
        if processing:
            authorization = processing[0]
            root = self._authorization_root(authorization.authorization_id)
            if authorization.action == "ready_for_case":
                result_path = root / "automation-result.json"
                if result_path.exists():
                    body = _read_bounded_regular_file(result_path, 256 * 1024)
                    self._recover_case_ready(authorization, body)
                else:
                    self.state.requeue_precontact(authorization.authorization_id)
                return True

            output = root / "result"
            journal_root = root / "result.incomplete" / "attempt-journal"
            if output.exists() or journal_root.exists():
                self.state.record_attempt_started(authorization.authorization_id)
                authorization = self.state.get(authorization.authorization_id)
                if authorization is None:
                    raise RuntimeError("recovered attempt disappeared from durable state")
                if output.exists():
                    await self._finish_completed_attempt(authorization, output)
                else:
                    await self._finish_incomplete_attempt(authorization, journal_root)
            else:
                self.state.requeue_precontact(authorization.authorization_id)
            return True

        attempts = self.state.in_states("attempt_started")
        if not attempts:
            return False
        authorization = attempts[0]
        root = self._authorization_root(authorization.authorization_id)
        output = root / "result"
        journal_root = root / "result.incomplete" / "attempt-journal"
        if output.exists():
            await self._finish_completed_attempt(authorization, output)
        elif journal_root.exists():
            await self._finish_incomplete_attempt(authorization, journal_root)
        else:
            raise RuntimeError(
                "durable attempt-started state has no result or preserved journal; "
                "manual incident recovery is required and the request must not be retried"
            )
        return True

    async def process_once(self) -> bool:
        if await self.recover_durable_work():
            return True
        self.poll_github()
        self.state.expire_active_case(now_unix_s=int(time.time()))
        authorization = self.state.claim_next()
        if authorization is None:
            return False
        try:
            bot_comment = self._github.comment(authorization.bot_comment_id)
            verified = self._verify_bot_comment(bot_comment)
            if verified.authorization.authorization_id != authorization.authorization_id:
                raise ValueError("claimed authorization changed during re-verification")
            if authorization.action == "ready_for_case":
                await self._prepare_case(verified)
            else:
                await self._run_case(verified)
        except ValueError as error:
            current = self.state.get(authorization.authorization_id)
            if current is not None and current.state == "processing":
                self.state.supersede_precontact(authorization.authorization_id)
                LOGGER.warning(
                    "superseded invalid pre-contact authorization id=%s (%s)",
                    authorization.authorization_id,
                    type(error).__name__,
                )
                return True
            raise
        except BaseException:
            current = self.state.get(authorization.authorization_id)
            if current is not None and current.state == "processing":
                self.state.requeue_precontact(authorization.authorization_id)
            raise
        return True


async def _run_forever(controller: PublicPilotController) -> None:
    while True:
        try:
            progressed = await controller.process_once()
        except GithubRateLimitError as error:
            delay = max(controller.config.poll_seconds, error.retry_after_seconds)
            LOGGER.warning("GitHub API rate limited; retrying in %d seconds", delay)
        except Exception:
            LOGGER.exception("public-pilot automation iteration failed")
            delay = controller.config.poll_seconds
        else:
            delay = 0 if progressed else controller.config.poll_seconds
        await asyncio.sleep(delay)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the UMI public-pilot coordinator")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--github-token-file", type=Path)
    parser.add_argument("--github-hmac-secret-file", type=Path, required=True)
    parser.add_argument("--result-hmac-secret-file", type=Path, required=True)
    parser.add_argument("--upload-hmac-secret-file", type=Path, required=True)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--log-level", default="INFO")
    return parser


def main() -> None:
    args = _parser().parse_args()
    logging.basicConfig(level=getattr(logging, str(args.log_level).upper(), logging.INFO))
    config = load_public_pilot_automation_config(args.config)
    lock = Path(config.data_root) / "controller.lock"
    with (
        _controller_lock(lock),
        PublicPilotController(
            config,
            github_token=(
                None
                if args.github_token_file is None
                else load_github_token(args.github_token_file)
            ),
            github_hmac_key=load_hex_secret(args.github_hmac_secret_file),
            result_hmac_key=load_hex_secret(args.result_hmac_secret_file),
            upload_hmac_key=load_hex_secret(args.upload_hmac_secret_file),
        ) as controller,
    ):
        if args.once:
            asyncio.run(controller.process_once())
        else:
            asyncio.run(_run_forever(controller))


if __name__ == "__main__":
    main()
