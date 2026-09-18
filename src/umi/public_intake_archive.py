"""Atomic, content-addressed archive for public intake monitor captures."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, Literal

from pydantic import Field, ValidationError, model_validator
from typing_extensions import Self

from .open_competition import Hex32, StrictProtocolModel
from .protocol import canonical_json_bytes
from .public_intake_monitor import (
    MonitorIssue,
    PublicIntakeMonitorConfig,
    PublicIntakeMonitorError,
    PublicIntakeMonitorState,
    PublicRouteCapture,
    ValidatedPublicCapture,
    ValidatorAgeObservation,
    document_sha256,
    validate_public_capture,
)

_SNAPSHOT_RE = re.compile(r"^[0-9]{16}-[0-9]{16}-[0-9a-f]{16}-[0-9a-f]{16}$")
_REJECTED_RE = re.compile(r"^[0-9]{16}-[0-9a-f]{16}-[0-9a-f]{16}$")
_STAGING_RE = re.compile(r"^\.(?:snapshot|rejected)-[0-9a-f]{32}$")
_OBJECT_TEMP_RE = re.compile(r"^\.[0-9a-f]{64}\.[0-9a-f]{32}\.tmp$")
_LATEST_TEMP_RE = re.compile(r"^\.latest\.json\.[0-9a-f]{32}\.tmp$")
_MAXIMUM_ARCHIVE_FILE_BYTES = 128 * 1024 * 1024
_LOCK_NAME = "monitor.lock"
_LATEST_NAME = "latest.json"


class PublicIntakeArchiveError(RuntimeError):
    """The local audit archive is unavailable, unsafe, or inconsistent."""


class ArchiveFile(StrictProtocolModel):
    path: Annotated[str, Field(min_length=1, max_length=512)]
    sha256: Hex32
    size_bytes: Annotated[int, Field(ge=0, le=_MAXIMUM_ARCHIVE_FILE_BYTES)]

    @model_validator(mode="after")
    def safe_relative_path(self) -> Self:
        path = PurePosixPath(self.path)
        if path.is_absolute() or ".." in path.parts or str(path) != self.path:
            raise ValueError("archive file path must be canonical and relative")
        return self


class PublicIntakeArchiveManifest(StrictProtocolModel):
    schema_: Literal["umi-public-intake-audit-archive/1"] = Field(alias="schema")
    archived_at_utc: Annotated[
        str,
        Field(pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"),
    ]
    archived_at_unix_ms: Annotated[int, Field(ge=0, le=2**63 - 1)]
    identity_name: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")]
    identity_index: Annotated[int, Field(ge=0, le=31)]
    policy_sha256: Hex32
    deployment_document_sha256: Hex32
    monitor_config_sha256: Hex32
    predecessor_snapshot: Annotated[str, Field(pattern=_SNAPSHOT_RE.pattern)] | None
    predecessor_manifest_sha256: Hex32 | None
    admission_checked_block: Annotated[int, Field(ge=0, le=2**53 - 1)]
    observer_finalized_block: Annotated[int, Field(ge=0, le=2**53 - 1)]
    accepted_submission_count: Annotated[int, Field(ge=0, le=65_536)]
    retained_head_sha256: Hex32
    severity: Literal["ok", "warning", "investigate", "critical", "stale"]
    issues: tuple[MonitorIssue, ...]
    validator_observations: tuple[ValidatorAgeObservation, ...]
    files: tuple[ArchiveFile, ...]

    @model_validator(mode="after")
    def canonical_files(self) -> Self:
        paths = [item.path for item in self.files]
        if paths != sorted(set(paths)):
            raise ValueError("archive manifest files must be sorted and unique")
        if (self.predecessor_snapshot is None) != (self.predecessor_manifest_sha256 is None):
            raise ValueError("archive predecessor name and digest must appear together")
        return self


class LatestArchive(StrictProtocolModel):
    schema_: Literal["umi-public-intake-audit-latest/1"] = Field(alias="schema")
    snapshot: Annotated[str, Field(pattern=_SNAPSHOT_RE.pattern)]
    manifest_sha256: Hex32


class RejectedPublicIntakeCaptureManifest(StrictProtocolModel):
    schema_: Literal["umi-public-intake-rejected-capture/1"] = Field(alias="schema")
    captured_at_utc: Annotated[
        str,
        Field(pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"),
    ]
    captured_at_unix_ms: Annotated[int, Field(ge=0, le=2**63 - 1)]
    reason: Annotated[str, Field(min_length=1, max_length=1024)]
    monitor_config_sha256: Hex32
    last_accepted_snapshot: Annotated[str, Field(pattern=_SNAPSHOT_RE.pattern)] | None
    last_accepted_manifest_sha256: Hex32 | None
    files: tuple[ArchiveFile, ...]

    @model_validator(mode="after")
    def canonical_files_and_context(self) -> Self:
        paths = [item.path for item in self.files]
        if paths != sorted(set(paths)):
            raise ValueError("rejected capture manifest files must be sorted and unique")
        if (self.last_accepted_snapshot is None) != (self.last_accepted_manifest_sha256 is None):
            raise ValueError("rejected capture context name and digest must appear together")
        return self


@dataclass(frozen=True)
class ArchivePollContext:
    latest: LatestArchive | None
    manifest: PublicIntakeArchiveManifest | None
    state: PublicIntakeMonitorState | None
    archived_config: PublicIntakeMonitorConfig | None


def _hash(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _directory_descriptor(path: Path) -> int:
    return os.open(
        path,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )


def _check_private_directory(path: Path, *, modes: set[int]) -> int:
    try:
        details = path.lstat()
    except OSError as error:
        raise PublicIntakeArchiveError("archive_directory_unavailable") from error
    if (
        not stat.S_ISDIR(details.st_mode)
        or path.is_symlink()
        or details.st_uid != os.geteuid()
        or stat.S_IMODE(details.st_mode) not in modes
    ):
        raise PublicIntakeArchiveError("archive_directory_not_private_and_owned")
    return stat.S_IMODE(details.st_mode)


def _check_regular(path: Path, *, modes: set[int]) -> os.stat_result:
    try:
        details = path.lstat()
    except OSError as error:
        raise PublicIntakeArchiveError("archive_file_unavailable") from error
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_uid != os.geteuid()
        or stat.S_IMODE(details.st_mode) not in modes
    ):
        raise PublicIntakeArchiveError("archive_file_not_private_owned_regular")
    return details


def _read_bounded(path: Path, maximum: int = _MAXIMUM_ARCHIVE_FILE_BYTES) -> bytes:
    details = _check_regular(path, modes={0o400, 0o600})
    if details.st_size > maximum:
        raise PublicIntakeArchiveError("archive_file_too_large")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        body = bytearray()
        while len(body) <= maximum:
            chunk = os.read(descriptor, min(65_536, maximum + 1 - len(body)))
            if not chunk:
                return bytes(body)
            body.extend(chunk)
    finally:
        os.close(descriptor)
    raise PublicIntakeArchiveError("archive_file_too_large")


def _write_new(path: Path, payload: bytes, *, final_mode: int = 0o400) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short archive write")
            view = view[written:]
        os.fchmod(descriptor, final_mode)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = _directory_descriptor(path)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_replace(path: Path, payload: bytes) -> None:
    temporary = path.parent / f".{path.name}.{secrets.token_hex(16)}.tmp"
    try:
        _write_new(temporary, payload, final_mode=0o600)
        if path.exists() or path.is_symlink():
            _check_regular(path, modes={0o600})
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        with suppress(FileNotFoundError):
            temporary.unlink()


def _parse_json_model(path: Path, model, code: str):
    payload = _read_bounded(path)
    try:
        value = model.model_validate_json(payload)
    except (ValidationError, ValueError):
        raise PublicIntakeArchiveError(code) from None
    if canonical_json_bytes(value) != payload:
        raise PublicIntakeArchiveError(f"{code}_not_canonical")
    return value


class PublicIntakeArchive:
    """One private local archive with a non-blocking process lock."""

    def __init__(self, root: Path) -> None:
        if not root.is_absolute() or root == Path(root.anchor):
            raise ValueError("archive root must be one dedicated absolute directory")
        _check_private_directory(root, modes={0o700})
        self.root = root.resolve(strict=True)
        self.objects = self.root / "objects"
        self.snapshots = self.root / "snapshots"
        self.rejected = self.root / "rejected"
        self.staging = self.root / ".staging"
        for path in (self.objects, self.snapshots, self.rejected, self.staging):
            with suppress(FileExistsError):
                path.mkdir(mode=0o700)
            _check_private_directory(path, modes={0o700})
        _fsync_directory(self.root)

    @contextmanager
    def locked(self) -> Iterator[None]:
        path = self.root / _LOCK_NAME
        descriptor = os.open(
            path,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        try:
            details = os.fstat(descriptor)
            if (
                not stat.S_ISREG(details.st_mode)
                or details.st_uid != os.geteuid()
                or details.st_nlink != 1
                or stat.S_IMODE(details.st_mode) != 0o600
            ):
                raise PublicIntakeArchiveError("archive_lock_not_private_owned_regular")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise PublicIntakeArchiveError("archive_monitor_already_running") from None
            self._recover_staging()
            self._recover_temporary_files()
            self._recover_rejected_captures()
            yield
        finally:
            with suppress(OSError):
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _snapshot_path(self, name: str) -> Path:
        if _SNAPSHOT_RE.fullmatch(name) is None:
            raise PublicIntakeArchiveError("invalid_snapshot_name")
        return self.snapshots / name

    def _rejected_path(self, name: str) -> Path:
        if _REJECTED_RE.fullmatch(name) is None:
            raise PublicIntakeArchiveError("invalid_rejected_capture_name")
        return self.rejected / name

    def _valid_snapshot_names(self) -> list[str]:
        names = []
        for entry in self.snapshots.iterdir():
            if _SNAPSHOT_RE.fullmatch(entry.name) is None:
                raise PublicIntakeArchiveError("unexpected_archive_snapshot_entry")
            if not entry.is_dir() or entry.is_symlink():
                raise PublicIntakeArchiveError("archive_snapshot_not_directory")
            names.append(entry.name)
        return sorted(names)

    def _latest_with_manifest(
        self,
    ) -> tuple[LatestArchive, PublicIntakeArchiveManifest] | None:
        path = self.root / _LATEST_NAME
        pointed: LatestArchive | None = None
        pointed_manifest: PublicIntakeArchiveManifest | None = None
        if path.exists() or path.is_symlink():
            pointed = _parse_json_model(path, LatestArchive, "invalid_latest_archive_pointer")
            pointed_manifest = self.verify_snapshot(pointed.snapshot)
            if document_sha256(pointed_manifest) != pointed.manifest_sha256:
                raise PublicIntakeArchiveError("latest_archive_manifest_mismatch")
        names = self._valid_snapshot_names()
        if not names:
            if pointed is not None:
                raise PublicIntakeArchiveError("latest_archive_snapshot_missing")
            return None
        name = names[-1]
        manifest = (
            pointed_manifest
            if pointed is not None and pointed.snapshot == name
            else self.verify_snapshot(name)
        )
        if manifest is None:
            raise AssertionError("latest manifest was not loaded")
        manifest_sha = document_sha256(manifest)
        latest = LatestArchive(
            schema="umi-public-intake-audit-latest/1",
            snapshot=name,
            manifest_sha256=manifest_sha,
        )
        if pointed != latest:
            _atomic_replace(path, canonical_json_bytes(latest))
        return latest, manifest

    def latest(self) -> LatestArchive | None:
        resolved = self._latest_with_manifest()
        return None if resolved is None else resolved[0]

    def load_state(self) -> PublicIntakeMonitorState | None:
        latest = self.latest()
        return None if latest is None else self.snapshot_state(latest.snapshot)

    @staticmethod
    def _require_config_extension(
        config: PublicIntakeMonitorConfig,
        archived_config: PublicIntakeMonitorConfig,
    ) -> None:
        retained_identities = len(archived_config.expected_identities)
        current_with_archived_identities = config.model_copy(
            update={"expected_identities": archived_config.expected_identities}
        )
        if (
            len(config.expected_identities) < retained_identities
            or tuple(config.expected_identities[:retained_identities])
            != archived_config.expected_identities
            or current_with_archived_identities != archived_config
        ):
            raise PublicIntakeArchiveError("monitor_config_is_not_an_append_only_extension")

    def _require_predecessor_manifest_chain(
        self,
        latest: LatestArchive,
        manifest: PublicIntakeArchiveManifest,
    ) -> None:
        seen = {latest.snapshot}
        child_timestamp = manifest.archived_at_unix_ms
        predecessor = manifest.predecessor_snapshot
        expected_sha256 = manifest.predecessor_manifest_sha256
        while predecessor is not None:
            if predecessor in seen:
                raise PublicIntakeArchiveError("archive_predecessor_cycle")
            seen.add(predecessor)
            root = self._snapshot_path(predecessor)
            _check_private_directory(root, modes={0o500, 0o700})
            predecessor_manifest = _parse_json_model(
                root / "manifest.json",
                PublicIntakeArchiveManifest,
                "invalid_archive_predecessor_manifest",
            )
            if document_sha256(predecessor_manifest) != expected_sha256:
                raise PublicIntakeArchiveError("archive_predecessor_manifest_mismatch")
            if predecessor_manifest.archived_at_unix_ms > child_timestamp:
                raise PublicIntakeArchiveError("archive_predecessor_time_regressed")
            child_timestamp = predecessor_manifest.archived_at_unix_ms
            predecessor = predecessor_manifest.predecessor_snapshot
            expected_sha256 = predecessor_manifest.predecessor_manifest_sha256

    def ensure_config_extension(self, config: PublicIntakeMonitorConfig) -> None:
        self.poll_context(config)

    def poll_context(self, config: PublicIntakeMonitorConfig) -> ArchivePollContext:
        resolved = self._latest_with_manifest()
        if resolved is None:
            return ArchivePollContext(None, None, None, None)
        latest, manifest = resolved
        self._require_predecessor_manifest_chain(latest, manifest)
        archived_config = _parse_json_model(
            self._snapshot_path(latest.snapshot) / "monitor-config.json",
            PublicIntakeMonitorConfig,
            "invalid_archived_monitor_config",
        )
        if document_sha256(archived_config) != manifest.monitor_config_sha256:
            raise PublicIntakeArchiveError("archived_monitor_config_mismatch")
        self._require_config_extension(config, archived_config)
        return ArchivePollContext(
            latest=latest,
            manifest=manifest,
            state=self.snapshot_state(latest.snapshot),
            archived_config=archived_config,
        )

    def snapshot_state(self, name: str) -> PublicIntakeMonitorState:
        path = self._snapshot_path(name)
        return _parse_json_model(
            path / "monitor-state.json",
            PublicIntakeMonitorState,
            "invalid_archived_monitor_state",
        )

    def _ensure_object(self, payload: bytes) -> Path:
        object_id = _hash(payload)
        path = self.objects / f"{object_id}.json"
        if path.exists() or path.is_symlink():
            details = _check_regular(path, modes={0o400, 0o600})
            if details.st_size != len(payload) or _hash(_read_bounded(path)) != object_id:
                raise PublicIntakeArchiveError("content_addressed_object_mismatch")
            path.chmod(0o400)
            return path
        temporary = self.objects / f".{object_id}.{secrets.token_hex(16)}.tmp"
        try:
            _write_new(temporary, payload)
            with suppress(FileExistsError):
                os.link(temporary, path, follow_symlinks=False)
            _fsync_directory(self.objects)
        finally:
            with suppress(FileNotFoundError):
                temporary.unlink()
        details = _check_regular(path, modes={0o400})
        if details.st_size != len(payload) or _hash(_read_bounded(path)) != object_id:
            raise PublicIntakeArchiveError("content_addressed_object_mismatch")
        return path

    @staticmethod
    def _route_files(
        capture: PublicRouteCapture, config: PublicIntakeMonitorConfig
    ) -> tuple[dict[str, bytes], dict[str, bytes]]:
        ordinary = {
            "status-before.json": canonical_json_bytes(capture.status_before),
            "readiness-before.json": canonical_json_bytes(capture.readiness_before),
            "status.json": canonical_json_bytes(capture.status),
            "readiness.json": canonical_json_bytes(capture.readiness),
            "monitor-config.json": canonical_json_bytes(config),
        }
        for index, page in enumerate(capture.submission_pages):
            ordinary[f"submission-pages/{index:06d}.json"] = canonical_json_bytes(page)
        for index, page in enumerate(capture.participant_pages):
            ordinary[f"participant-pages/{index:06d}.json"] = canonical_json_bytes(page)
        records = {
            f"submission-records/{submission_sha256}.json": canonical_json_bytes(record)
            for submission_sha256, record in capture.submission_records.items()
        }
        return ordinary, records

    @classmethod
    def _capture_files(
        cls,
        capture: PublicRouteCapture,
        state: PublicIntakeMonitorState,
        config: PublicIntakeMonitorConfig,
    ) -> tuple[dict[str, bytes], dict[str, bytes]]:
        ordinary, records = cls._route_files(capture, config)
        ordinary["monitor-state.json"] = canonical_json_bytes(state)
        return ordinary, records

    def _cleanup_staging(self, path: Path) -> None:
        if _STAGING_RE.fullmatch(path.name) is None or path.parent != self.staging:
            raise PublicIntakeArchiveError("refused_unsafe_staging_cleanup")
        try:
            root_details = path.lstat()
        except FileNotFoundError:
            return
        if (
            not stat.S_ISDIR(root_details.st_mode)
            or path.is_symlink()
            or root_details.st_uid != os.geteuid()
            or stat.S_IMODE(root_details.st_mode) != 0o700
        ):
            raise PublicIntakeArchiveError("unsafe_abandoned_staging_entry")
        directories = [path]
        for entry in path.rglob("*"):
            details = entry.lstat()
            mode = stat.S_IMODE(details.st_mode)
            if details.st_uid != os.geteuid() or entry.is_symlink():
                raise PublicIntakeArchiveError("unsafe_abandoned_staging_entry")
            if stat.S_ISDIR(details.st_mode):
                if mode not in {0o500, 0o700}:
                    raise PublicIntakeArchiveError("unsafe_abandoned_staging_entry")
                directories.append(entry)
            elif stat.S_ISREG(details.st_mode):
                if mode not in {0o400, 0o600}:
                    raise PublicIntakeArchiveError("unsafe_abandoned_staging_entry")
            else:
                raise PublicIntakeArchiveError("unsafe_abandoned_staging_entry")
        for directory in sorted(directories, key=lambda item: len(item.parts), reverse=True):
            directory.chmod(0o700)
        shutil.rmtree(path)
        _fsync_directory(self.staging)

    def _recover_staging(self) -> None:
        _check_private_directory(self.staging, modes={0o700})
        for entry in sorted(self.staging.iterdir(), key=lambda item: item.name):
            self._cleanup_staging(entry)

    @staticmethod
    def _remove_temporary_files(directory: Path, *, prefix: str, pattern: re.Pattern[str]) -> None:
        removed = False
        for entry in sorted(directory.iterdir(), key=lambda item: item.name):
            if not entry.name.startswith(prefix):
                continue
            if pattern.fullmatch(entry.name) is None:
                raise PublicIntakeArchiveError("unsafe_abandoned_archive_temporary_file")
            _check_regular(entry, modes={0o400, 0o600})
            entry.unlink()
            removed = True
        if removed:
            _fsync_directory(directory)

    def _recover_temporary_files(self) -> None:
        self._remove_temporary_files(
            self.objects,
            prefix=".",
            pattern=_OBJECT_TEMP_RE,
        )
        self._remove_temporary_files(
            self.root,
            prefix=".latest.json.",
            pattern=_LATEST_TEMP_RE,
        )

    def _recover_rejected_captures(self) -> None:
        _check_private_directory(self.rejected, modes={0o700})
        for entry in sorted(self.rejected.iterdir(), key=lambda item: item.name):
            if _REJECTED_RE.fullmatch(entry.name) is None:
                raise PublicIntakeArchiveError("unexpected_rejected_capture_entry")
            mode = _check_private_directory(entry, modes={0o500, 0o700})
            if mode == 0o700:
                self.verify_rejected(entry.name)

    def commit(
        self,
        capture: PublicRouteCapture,
        validated: ValidatedPublicCapture,
        config: PublicIntakeMonitorConfig,
        *,
        context: ArchivePollContext | None = None,
    ) -> tuple[str, PublicIntakeArchiveManifest]:
        context = self.poll_context(config) if context is None else context
        if context.archived_config is not None:
            self._require_config_extension(config, context.archived_config)
        predecessor = context.latest
        ordinary, records = self._capture_files(capture, validated.next_state, config)
        stage = self.staging / f".snapshot-{secrets.token_hex(16)}"
        stage.mkdir(mode=0o700)
        file_entries: list[ArchiveFile] = []
        try:
            for relative in ("submission-pages", "participant-pages", "submission-records"):
                (stage / relative).mkdir(mode=0o700)
            for relative, payload in sorted(ordinary.items()):
                destination = stage / relative
                _write_new(destination, payload)
                file_entries.append(
                    ArchiveFile(path=relative, sha256=_hash(payload), size_bytes=len(payload))
                )
            for relative, payload in sorted(records.items()):
                source = self._ensure_object(payload)
                destination = stage / relative
                os.link(source, destination, follow_symlinks=False)
                file_entries.append(
                    ArchiveFile(path=relative, sha256=_hash(payload), size_bytes=len(payload))
                )
            for relative in ("submission-pages", "participant-pages", "submission-records"):
                _fsync_directory(stage / relative)
                (stage / relative).chmod(0o500)
            timestamp = datetime.fromtimestamp(
                validated.next_state.last_success_at_unix_ms / 1000, tz=timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%SZ")
            manifest = PublicIntakeArchiveManifest(
                schema="umi-public-intake-audit-archive/1",
                archived_at_utc=timestamp,
                archived_at_unix_ms=validated.next_state.last_success_at_unix_ms,
                identity_name=validated.identity.name,
                identity_index=validated.identity_index,
                policy_sha256=validated.status.policy_sha256,
                deployment_document_sha256=validated.identity.deployment_document_sha256,
                monitor_config_sha256=document_sha256(config),
                predecessor_snapshot=(None if predecessor is None else predecessor.snapshot),
                predecessor_manifest_sha256=(
                    None if predecessor is None else predecessor.manifest_sha256
                ),
                admission_checked_block=validated.status.admission_checked_block,
                observer_finalized_block=validated.observer_finalized_block,
                accepted_submission_count=validated.status.accepted_submission_count,
                retained_head_sha256=validated.status.retained_submission_head.head_sha256,
                severity=validated.severity,
                issues=validated.issues,
                validator_observations=validated.validator_observations,
                files=tuple(sorted(file_entries, key=lambda item: item.path)),
            )
            manifest_body = canonical_json_bytes(manifest)
            _write_new(stage / "manifest.json", manifest_body)
            _fsync_directory(stage)
            manifest_sha = _hash(manifest_body)
            snapshot_name = (
                f"{validated.next_state.last_success_at_unix_ms:016d}-"
                f"{validated.status.admission_checked_block:016d}-"
                f"{validated.status.retained_submission_head.head_sha256[:16]}-"
                f"{manifest_sha[:16]}"
            )
            destination = self._snapshot_path(snapshot_name)
            if destination.exists():
                existing = _read_bounded(destination / "manifest.json")
                if existing != manifest_body:
                    raise PublicIntakeArchiveError("archive_snapshot_name_collision")
                self._cleanup_staging(stage)
            else:
                os.replace(stage, destination)
                destination.chmod(0o500)
                _fsync_directory(destination)
                _fsync_directory(self.snapshots)
            latest = LatestArchive(
                schema="umi-public-intake-audit-latest/1",
                snapshot=snapshot_name,
                manifest_sha256=manifest_sha,
            )
            _atomic_replace(self.root / _LATEST_NAME, canonical_json_bytes(latest))
            return snapshot_name, manifest
        except BaseException:
            if stage.exists():
                self._cleanup_staging(stage)
            raise

    def commit_rejected(
        self,
        capture: PublicRouteCapture,
        config: PublicIntakeMonitorConfig,
        previous_state: PublicIntakeMonitorState | None,
        *,
        reason: str,
        captured_at_unix_ms: int,
        context: ArchivePollContext | None = None,
    ) -> tuple[str, RejectedPublicIntakeCaptureManifest]:
        if not reason or len(reason) > 1024 or captured_at_unix_ms < 0:
            raise ValueError("invalid rejected capture metadata")
        context = self.poll_context(config) if context is None else context
        if context.archived_config is not None:
            self._require_config_extension(config, context.archived_config)
        last_accepted = context.latest
        ordinary, records = self._route_files(capture, config)
        if previous_state is not None:
            ordinary["previous-monitor-state.json"] = canonical_json_bytes(previous_state)
        stage = self.staging / f".rejected-{secrets.token_hex(16)}"
        stage.mkdir(mode=0o700)
        file_entries: list[ArchiveFile] = []
        try:
            for relative in ("submission-pages", "participant-pages", "submission-records"):
                (stage / relative).mkdir(mode=0o700)
            for relative, payload in sorted(ordinary.items()):
                destination = stage / relative
                _write_new(destination, payload)
                file_entries.append(
                    ArchiveFile(path=relative, sha256=_hash(payload), size_bytes=len(payload))
                )
            for relative, payload in sorted(records.items()):
                source = self._ensure_object(payload)
                destination = stage / relative
                os.link(source, destination, follow_symlinks=False)
                file_entries.append(
                    ArchiveFile(path=relative, sha256=_hash(payload), size_bytes=len(payload))
                )
            for relative in ("submission-pages", "participant-pages", "submission-records"):
                _fsync_directory(stage / relative)
                (stage / relative).chmod(0o500)
            timestamp = datetime.fromtimestamp(
                captured_at_unix_ms / 1000, tz=timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%SZ")
            manifest = RejectedPublicIntakeCaptureManifest(
                schema="umi-public-intake-rejected-capture/1",
                captured_at_utc=timestamp,
                captured_at_unix_ms=captured_at_unix_ms,
                reason=reason,
                monitor_config_sha256=document_sha256(config),
                last_accepted_snapshot=(None if last_accepted is None else last_accepted.snapshot),
                last_accepted_manifest_sha256=(
                    None if last_accepted is None else last_accepted.manifest_sha256
                ),
                files=tuple(sorted(file_entries, key=lambda item: item.path)),
            )
            manifest_body = canonical_json_bytes(manifest)
            _write_new(stage / "manifest.json", manifest_body)
            _fsync_directory(stage)
            rejected_name = (
                f"{captured_at_unix_ms:016d}-{_hash(reason.encode())[:16]}-"
                f"{_hash(manifest_body)[:16]}"
            )
            destination = self._rejected_path(rejected_name)
            if destination.exists():
                existing = _read_bounded(destination / "manifest.json")
                if existing != manifest_body:
                    raise PublicIntakeArchiveError("rejected_capture_name_collision")
                self._cleanup_staging(stage)
            else:
                os.replace(stage, destination)
                destination.chmod(0o500)
                _fsync_directory(destination)
                _fsync_directory(self.rejected)
            return rejected_name, manifest
        except BaseException:
            if stage.exists():
                self._cleanup_staging(stage)
            raise

    def verify_rejected(self, name: str) -> RejectedPublicIntakeCaptureManifest:
        root = self._rejected_path(name)
        observed_mode = _check_private_directory(root, modes={0o500, 0o700})
        manifest = _parse_json_model(
            root / "manifest.json",
            RejectedPublicIntakeCaptureManifest,
            "invalid_rejected_capture_manifest",
        )
        manifest_body = _read_bounded(root / "manifest.json")
        expected_name = (
            f"{manifest.captured_at_unix_ms:016d}-"
            f"{_hash(manifest.reason.encode())[:16]}-{_hash(manifest_body)[:16]}"
        )
        if name != expected_name:
            raise PublicIntakeArchiveError("rejected_capture_name_mismatch")
        allowed = {item.path for item in manifest.files} | {"manifest.json"}
        observed = {
            str(path.relative_to(root))
            for path in root.rglob("*")
            if path.is_file() or path.is_symlink()
        }
        expected_directories = {
            "participant-pages",
            "submission-pages",
            "submission-records",
        }
        observed_directories = {
            str(path.relative_to(root))
            for path in root.rglob("*")
            if path.is_dir() and not path.is_symlink()
        }
        if observed != allowed or observed_directories != expected_directories:
            raise PublicIntakeArchiveError("rejected_capture_file_inventory_mismatch")
        for relative in expected_directories:
            _check_private_directory(root / relative, modes={0o500})
        for item in manifest.files:
            path = root / item.path
            details = _check_regular(path, modes={0o400})
            if (
                details.st_size != item.size_bytes
                or _hash(_read_bounded(path, item.size_bytes + 1)) != item.sha256
            ):
                raise PublicIntakeArchiveError("rejected_capture_file_digest_mismatch")
        expected_timestamp = datetime.fromtimestamp(
            manifest.captured_at_unix_ms / 1000, tz=timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        if manifest.captured_at_utc != expected_timestamp:
            raise PublicIntakeArchiveError("rejected_capture_timestamp_mismatch")
        listed = {item.path for item in manifest.files}
        required = {
            "status-before.json",
            "readiness-before.json",
            "status.json",
            "readiness.json",
            "monitor-config.json",
        }
        submission_pages = sorted(path for path in listed if path.startswith("submission-pages/"))
        participant_pages = sorted(path for path in listed if path.startswith("participant-pages/"))
        record_paths = sorted(path for path in listed if path.startswith("submission-records/"))
        if (
            not required.issubset(listed)
            or submission_pages
            != [f"submission-pages/{index:06d}.json" for index in range(len(submission_pages))]
            or participant_pages
            != [f"participant-pages/{index:06d}.json" for index in range(len(participant_pages))]
            or not submission_pages
            or not participant_pages
            or any(
                re.fullmatch(r"submission-records/[0-9a-f]{64}\.json", path) is None
                for path in record_paths
            )
        ):
            raise PublicIntakeArchiveError("rejected_capture_route_inventory_invalid")

        def load(path: str) -> dict[str, Any]:
            payload = _read_bounded(root / path)
            try:
                value = json.loads(payload)
                canonical = canonical_json_bytes(value)
            except (TypeError, UnicodeDecodeError, ValueError):
                raise PublicIntakeArchiveError("rejected_capture_json_invalid") from None
            if not isinstance(value, dict) or canonical != payload:
                raise PublicIntakeArchiveError("rejected_capture_json_not_canonical_object")
            return value

        archived_config = _parse_json_model(
            root / "monitor-config.json",
            PublicIntakeMonitorConfig,
            "invalid_rejected_capture_monitor_config",
        )
        if document_sha256(archived_config) != manifest.monitor_config_sha256:
            raise PublicIntakeArchiveError("rejected_capture_monitor_config_mismatch")
        previous_state: PublicIntakeMonitorState | None = None
        if manifest.last_accepted_snapshot is not None:
            accepted_config = _parse_json_model(
                self._snapshot_path(manifest.last_accepted_snapshot) / "monitor-config.json",
                PublicIntakeMonitorConfig,
                "invalid_archived_monitor_config",
            )
            self._require_config_extension(archived_config, accepted_config)
            accepted_manifest = self.verify_with_config(
                manifest.last_accepted_snapshot, archived_config
            )
            if document_sha256(accepted_manifest) != manifest.last_accepted_manifest_sha256:
                raise PublicIntakeArchiveError("rejected_capture_context_mismatch")
            if "previous-monitor-state.json" not in listed:
                raise PublicIntakeArchiveError("rejected_capture_previous_state_missing")
            previous_state = _parse_json_model(
                root / "previous-monitor-state.json",
                PublicIntakeMonitorState,
                "invalid_rejected_capture_previous_state",
            )
            if previous_state != self.snapshot_state(manifest.last_accepted_snapshot):
                raise PublicIntakeArchiveError("rejected_capture_previous_state_mismatch")
        elif "previous-monitor-state.json" in listed:
            raise PublicIntakeArchiveError("rejected_capture_previous_state_unexpected")
        capture = PublicRouteCapture(
            status_before=load("status-before.json"),
            readiness_before=load("readiness-before.json"),
            submission_pages=tuple(load(path) for path in submission_pages),
            submission_records={Path(path).stem: load(path) for path in record_paths},
            participant_pages=tuple(load(path) for path in participant_pages),
            readiness=load("readiness.json"),
            status=load("status.json"),
        )
        try:
            validate_public_capture(
                capture,
                archived_config,
                previous_state=previous_state,
                now_unix_ms=manifest.captured_at_unix_ms,
            )
        except PublicIntakeMonitorError as error:
            if str(error) != manifest.reason:
                raise PublicIntakeArchiveError("rejected_capture_reason_mismatch") from None
        else:
            raise PublicIntakeArchiveError("rejected_capture_no_longer_rejects")
        if observed_mode == 0o700:
            root.chmod(0o500)
            _fsync_directory(root)
            _fsync_directory(self.rejected)
        return manifest

    def verify_snapshot(self, name: str) -> PublicIntakeArchiveManifest:
        root = self._snapshot_path(name)
        observed_mode = _check_private_directory(root, modes={0o500, 0o700})
        manifest = _parse_json_model(
            root / "manifest.json",
            PublicIntakeArchiveManifest,
            "invalid_archive_manifest",
        )
        manifest_body = _read_bounded(root / "manifest.json")
        expected_name = (
            f"{manifest.archived_at_unix_ms:016d}-"
            f"{manifest.admission_checked_block:016d}-"
            f"{manifest.retained_head_sha256[:16]}-{_hash(manifest_body)[:16]}"
        )
        if name != expected_name:
            raise PublicIntakeArchiveError("archive_snapshot_name_mismatch")
        allowed = {item.path for item in manifest.files} | {"manifest.json"}
        observed = {
            str(path.relative_to(root))
            for path in root.rglob("*")
            if path.is_file() or path.is_symlink()
        }
        expected_directories = {
            "participant-pages",
            "submission-pages",
            "submission-records",
        }
        observed_directories = {
            str(path.relative_to(root))
            for path in root.rglob("*")
            if path.is_dir() and not path.is_symlink()
        }
        if observed != allowed or observed_directories != expected_directories:
            raise PublicIntakeArchiveError("archive_file_inventory_mismatch")
        for relative in expected_directories:
            _check_private_directory(root / relative, modes={0o500})
        for item in manifest.files:
            path = root / item.path
            details = _check_regular(path, modes={0o400})
            if (
                details.st_size != item.size_bytes
                or _hash(_read_bounded(path, item.size_bytes + 1)) != item.sha256
            ):
                raise PublicIntakeArchiveError("archived_file_digest_mismatch")
        if observed_mode == 0o700:
            root.chmod(0o500)
            _fsync_directory(root)
            _fsync_directory(self.snapshots)
        return manifest

    def load_capture(self, name: str) -> PublicRouteCapture:
        manifest = self.verify_snapshot(name)
        return self._load_capture_verified(name, manifest)

    def _load_capture_verified(
        self, name: str, manifest: PublicIntakeArchiveManifest
    ) -> PublicRouteCapture:
        root = self._snapshot_path(name)
        listed = {item.path for item in manifest.files}

        def load(path: str) -> dict[str, Any]:
            if path not in listed:
                raise PublicIntakeArchiveError("archive_capture_file_missing")
            try:
                payload = _read_bounded(root / path)
                value = json.loads(payload)
                canonical = canonical_json_bytes(value)
            except (TypeError, UnicodeDecodeError, ValueError):
                raise PublicIntakeArchiveError("archive_capture_json_invalid") from None
            if not isinstance(value, dict) or canonical != payload:
                raise PublicIntakeArchiveError("archive_capture_json_not_canonical_object")
            return value

        submission_pages = tuple(
            load(item.path) for item in manifest.files if item.path.startswith("submission-pages/")
        )
        participant_pages = tuple(
            load(item.path) for item in manifest.files if item.path.startswith("participant-pages/")
        )
        records = {
            Path(item.path).stem: load(item.path)
            for item in manifest.files
            if item.path.startswith("submission-records/")
        }
        return PublicRouteCapture(
            status_before=load("status-before.json"),
            readiness_before=load("readiness-before.json"),
            submission_pages=submission_pages,
            submission_records=records,
            participant_pages=participant_pages,
            readiness=load("readiness.json"),
            status=load("status.json"),
        )

    def verify_with_config(
        self, name: str, config: PublicIntakeMonitorConfig
    ) -> PublicIntakeArchiveManifest:
        chain: list[tuple[str, PublicIntakeArchiveManifest]] = []
        seen: set[str] = set()
        current = name
        expected_manifest_sha256: str | None = None
        child_timestamp: int | None = None
        while True:
            if current in seen:
                raise PublicIntakeArchiveError("archive_predecessor_cycle")
            seen.add(current)
            manifest = self.verify_snapshot(current)
            manifest_sha256 = document_sha256(manifest)
            if expected_manifest_sha256 is not None and manifest_sha256 != expected_manifest_sha256:
                raise PublicIntakeArchiveError("archive_predecessor_manifest_mismatch")
            if child_timestamp is not None and manifest.archived_at_unix_ms > child_timestamp:
                raise PublicIntakeArchiveError("archive_predecessor_time_regressed")
            chain.append((current, manifest))
            if manifest.predecessor_snapshot is None:
                break
            expected_manifest_sha256 = manifest.predecessor_manifest_sha256
            child_timestamp = manifest.archived_at_unix_ms
            current = manifest.predecessor_snapshot

        previous_state: PublicIntakeMonitorState | None = None
        target_manifest: PublicIntakeArchiveManifest | None = None
        for snapshot_name, manifest in reversed(chain):
            state = self.snapshot_state(snapshot_name)
            capture = self._load_capture_verified(snapshot_name, manifest)
            archived_config = _parse_json_model(
                self._snapshot_path(snapshot_name) / "monitor-config.json",
                PublicIntakeMonitorConfig,
                "invalid_archived_monitor_config",
            )
            if document_sha256(archived_config) != manifest.monitor_config_sha256:
                raise PublicIntakeArchiveError("archived_monitor_config_mismatch")
            self._require_config_extension(config, archived_config)
            try:
                validated = validate_public_capture(
                    capture,
                    archived_config,
                    previous_state=previous_state,
                    now_unix_ms=state.last_success_at_unix_ms,
                )
            except PublicIntakeMonitorError as error:
                raise PublicIntakeArchiveError(
                    f"archive_semantic_validation_failed:{error}"
                ) from None
            if validated.next_state != state:
                raise PublicIntakeArchiveError("archived_monitor_state_mismatch")
            expected_timestamp = datetime.fromtimestamp(
                state.last_success_at_unix_ms / 1000, tz=timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%SZ")
            if (
                manifest.archived_at_unix_ms != state.last_success_at_unix_ms
                or manifest.archived_at_utc != expected_timestamp
            ):
                raise PublicIntakeArchiveError("archived_monitor_timestamp_mismatch")
            expected_manifest = (
                validated.identity.name,
                validated.identity_index,
                validated.status.policy_sha256,
                validated.identity.deployment_document_sha256,
                validated.status.admission_checked_block,
                validated.observer_finalized_block,
                validated.status.accepted_submission_count,
                validated.status.retained_submission_head.head_sha256,
                validated.severity,
                validated.issues,
                validated.validator_observations,
            )
            archived_manifest = (
                manifest.identity_name,
                manifest.identity_index,
                manifest.policy_sha256,
                manifest.deployment_document_sha256,
                manifest.admission_checked_block,
                manifest.observer_finalized_block,
                manifest.accepted_submission_count,
                manifest.retained_head_sha256,
                manifest.severity,
                manifest.issues,
                manifest.validator_observations,
            )
            if expected_manifest != archived_manifest:
                raise PublicIntakeArchiveError("archived_monitor_manifest_mismatch")
            previous_state = state
            if snapshot_name == name:
                target_manifest = manifest
        if target_manifest is None:
            raise AssertionError("target archive manifest was not replayed")
        return target_manifest


__all__ = (
    "LatestArchive",
    "PublicIntakeArchive",
    "PublicIntakeArchiveError",
    "PublicIntakeArchiveManifest",
    "RejectedPublicIntakeCaptureManifest",
)
