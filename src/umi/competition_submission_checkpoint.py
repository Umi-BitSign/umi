"""Independent durable checkpoint for the public intake admission ledger."""

from __future__ import annotations

import errno
import fcntl
import hashlib
import math
import os
import secrets
import stat
import time
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, ValidationError, model_validator
from typing_extensions import Self

from .open_competition import Hex32, StrictProtocolModel
from .protocol import canonical_json_bytes

_CHECKPOINT_NAME = "submission-head.json"
_LOCK_NAME = "submission-head.lock"
_MAXIMUM_CHECKPOINT_BYTES = 16 * 1024 * 1024
MAXIMUM_CHECKPOINT_SUBMISSIONS = 65_536


class SubmissionCheckpointError(RuntimeError):
    """The independent submission checkpoint is unsafe or inconsistent."""


class SubmissionHeadCheckpoint(StrictProtocolModel):
    """Canonical independent commitment to every admitted submission identity."""

    schema_: Literal["umi-competition-submission-head-checkpoint/1"] = Field(alias="schema")
    policy_sha256: Hex32
    public_launch_sha256: Hex32
    submission_sha256s: Annotated[
        tuple[Hex32, ...], Field(max_length=MAXIMUM_CHECKPOINT_SUBMISSIONS)
    ]
    admission_record_sha256s: Annotated[
        tuple[Hex32, ...], Field(max_length=MAXIMUM_CHECKPOINT_SUBMISSIONS)
    ]
    record_count: Annotated[int, Field(ge=0, le=MAXIMUM_CHECKPOINT_SUBMISSIONS)]
    submission_set_sha256: Hex32
    head_sha256: Hex32

    @model_validator(mode="after")
    def canonical_head(self) -> Self:
        if tuple(sorted(set(self.submission_sha256s))) != self.submission_sha256s:
            raise ValueError("checkpoint submission digests must be sorted and unique")
        if self.record_count != len(self.submission_sha256s):
            raise ValueError("checkpoint record count is inconsistent")
        if len(self.admission_record_sha256s) != self.record_count:
            raise ValueError("checkpoint admission-record commitments are inconsistent")
        ordered_records = tuple(
            sorted(
                zip(self.submission_sha256s, self.admission_record_sha256s, strict=True),
                key=lambda item: item[0],
            )
        )
        if ordered_records != tuple(
            zip(self.submission_sha256s, self.admission_record_sha256s, strict=True)
        ):
            raise ValueError("checkpoint admission-record commitments are not canonically ordered")
        head = submission_head_body(self.policy_sha256, self.submission_sha256s)
        exact_head = _exact_head_body(
            self.policy_sha256,
            self.public_launch_sha256,
            self.submission_sha256s,
            self.admission_record_sha256s,
        )
        if self.submission_set_sha256 != head[
            "submission_set_sha256"
        ] or self.head_sha256 != _sha256(canonical_json_bytes(exact_head)):
            raise ValueError("checkpoint head commitment is inconsistent")
        return self


def submission_head_body(policy_sha256: str, submission_sha256s: tuple[str, ...]) -> dict:
    """Return the compact SQLite head body committed by the external checkpoint."""

    return {
        "schema": "umi-competition-submission-head/1",
        "policy_sha256": policy_sha256,
        "record_count": len(submission_sha256s),
        "submission_set_sha256": _sha256(canonical_json_bytes(list(submission_sha256s))),
    }


def build_submission_checkpoint(
    *,
    policy_sha256: str,
    public_launch_sha256: str,
    submission_sha256s: tuple[str, ...],
    admission_record_sha256s: tuple[str, ...],
) -> SubmissionHeadCheckpoint:
    head = submission_head_body(policy_sha256, submission_sha256s)
    exact_head = _exact_head_body(
        policy_sha256,
        public_launch_sha256,
        submission_sha256s,
        admission_record_sha256s,
    )
    return SubmissionHeadCheckpoint(
        schema="umi-competition-submission-head-checkpoint/1",
        policy_sha256=policy_sha256,
        public_launch_sha256=public_launch_sha256,
        submission_sha256s=submission_sha256s,
        admission_record_sha256s=admission_record_sha256s,
        record_count=head["record_count"],
        submission_set_sha256=head["submission_set_sha256"],
        head_sha256=_sha256(canonical_json_bytes(exact_head)),
    )


def _exact_head_body(
    policy_sha256: str,
    public_launch_sha256: str,
    submission_sha256s: tuple[str, ...],
    admission_record_sha256s: tuple[str, ...],
) -> dict:
    return {
        "schema": "umi-competition-exact-admission-head/1",
        "policy_sha256": policy_sha256,
        "public_launch_sha256": public_launch_sha256,
        "admission_records": list(zip(submission_sha256s, admission_record_sha256s, strict=True)),
    }


class SubmissionHeadCheckpointFile:
    """Atomic checkpoint file and independent compound-operation lock."""

    def __init__(
        self,
        directory: Path,
        *,
        policy_sha256: str,
        public_launch_sha256: str,
        lock_timeout_seconds: float = 5.0,
    ):
        if isinstance(lock_timeout_seconds, bool) or not isinstance(
            lock_timeout_seconds, (int, float)
        ):
            raise ValueError("submission checkpoint lock timeout must be finite and positive")
        try:
            timeout = float(lock_timeout_seconds)
        except OverflowError as error:
            raise ValueError(
                "submission checkpoint lock timeout must be finite and positive"
            ) from error
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("submission checkpoint lock timeout must be finite and positive")
        self.lock_timeout_seconds = timeout
        if not directory.is_absolute() or directory == Path(directory.anchor):
            raise ValueError("submission checkpoint needs a dedicated absolute directory")
        if directory.is_symlink():
            raise ValueError("submission checkpoint directory cannot be a symlink")
        self.directory = directory.resolve(strict=True)
        self.policy_sha256 = policy_sha256
        self.public_launch_sha256 = public_launch_sha256
        try:
            self._check_directory()
        except SubmissionCheckpointError as error:
            raise ValueError(
                "submission checkpoint directory must pre-exist, be private, owned, "
                "and not be a symlink"
            ) from error
        location = {
            "schema": "umi-competition-submission-checkpoint-location/1",
            "directory": str(self.directory),
            "policy_sha256": policy_sha256,
        }
        self.binding_sha256 = _sha256(canonical_json_bytes(location))

    @property
    def path(self) -> Path:
        return self.directory / _CHECKPOINT_NAME

    @contextmanager
    def locked(self) -> Iterator[None]:
        """Serialize DB commit plus checkpoint persistence across intake processes."""

        directory = self._open_directory()
        descriptor = -1
        try:
            descriptor, created = _open_lock(directory)
            if created:
                os.fsync(descriptor)
                os.fsync(directory)
            deadline = time.monotonic() + self.lock_timeout_seconds
            while True:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError as error:
                    if error.errno not in {errno.EACCES, errno.EAGAIN}:
                        raise
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise SubmissionCheckpointError(
                            "submission checkpoint lock timed out"
                        ) from None
                    time.sleep(min(0.05, remaining))
            self._check_directory_fd(directory)
            _check_named_identity(directory, _LOCK_NAME, descriptor)
            yield
        except SubmissionCheckpointError:
            raise
        except OSError as error:
            raise SubmissionCheckpointError("submission checkpoint lock is unavailable") from error
        finally:
            if descriptor >= 0:
                with suppress(OSError):
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)
            os.close(directory)

    def load(self) -> SubmissionHeadCheckpoint | None:
        """Read and authenticate the canonical checkpoint while holding ``locked``."""

        directory = self._open_directory()
        try:
            try:
                descriptor = os.open(
                    _CHECKPOINT_NAME,
                    os.O_RDONLY | _no_follow() | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=directory,
                )
            except FileNotFoundError:
                return None
            try:
                _check_private_regular(os.fstat(descriptor), "submission checkpoint")
                payload = _read_bounded(descriptor)
            finally:
                os.close(descriptor)
        except SubmissionCheckpointError:
            raise
        except OSError as error:
            raise SubmissionCheckpointError("submission checkpoint cannot be read") from error
        finally:
            os.close(directory)
        try:
            checkpoint = SubmissionHeadCheckpoint.model_validate_json(payload)
        except (ValidationError, ValueError) as error:
            raise SubmissionCheckpointError("submission checkpoint is invalid") from error
        if canonical_json_bytes(checkpoint) != payload:
            raise SubmissionCheckpointError("submission checkpoint is not canonical")
        if checkpoint.policy_sha256 != self.policy_sha256:
            raise SubmissionCheckpointError("submission checkpoint belongs to another policy")
        return checkpoint

    def replace(self, checkpoint: SubmissionHeadCheckpoint) -> None:
        """Atomically replace and fsync the checkpoint while holding ``locked``."""

        checkpoint = SubmissionHeadCheckpoint.model_validate_json(canonical_json_bytes(checkpoint))
        if (
            checkpoint.policy_sha256 != self.policy_sha256
            or checkpoint.public_launch_sha256 != self.public_launch_sha256
        ):
            raise SubmissionCheckpointError(
                "submission checkpoint belongs to another policy or public launch"
            )
        payload = canonical_json_bytes(checkpoint)
        if len(payload) > _MAXIMUM_CHECKPOINT_BYTES:
            raise SubmissionCheckpointError("submission checkpoint exceeds its byte bound")
        directory = self._open_directory()
        temporary_name = f".submission-head.{secrets.token_hex(16)}.tmp"
        descriptor = -1
        try:
            _check_existing_destination(directory)
            descriptor = os.open(
                temporary_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | _no_follow() | getattr(os, "O_CLOEXEC", 0),
                0o600,
                dir_fd=directory,
            )
            _write_all(descriptor, payload)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            os.replace(
                temporary_name,
                _CHECKPOINT_NAME,
                src_dir_fd=directory,
                dst_dir_fd=directory,
            )
            os.fsync(directory)
        except SubmissionCheckpointError:
            raise
        except OSError as error:
            raise SubmissionCheckpointError("submission checkpoint cannot be persisted") from error
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            with suppress(OSError):
                os.unlink(temporary_name, dir_fd=directory)
            os.close(directory)

    def status(self, checkpoint: SubmissionHeadCheckpoint) -> dict:
        body = canonical_json_bytes(checkpoint)
        return {
            **submission_head_body(self.policy_sha256, checkpoint.submission_sha256s),
            "head_sha256": checkpoint.head_sha256,
            "public_launch_sha256": checkpoint.public_launch_sha256,
            "external_checkpoint_sha256": _sha256(body),
            "external_checkpoint_durable": True,
        }

    def _check_directory(self) -> None:
        descriptor = self._open_directory()
        os.close(descriptor)

    def _open_directory(self) -> int:
        try:
            descriptor = os.open(
                self.directory,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | _no_follow()
                | getattr(os, "O_CLOEXEC", 0),
            )
        except OSError as error:
            raise SubmissionCheckpointError(
                "submission checkpoint directory is unavailable"
            ) from error
        try:
            self._check_directory_fd(descriptor)
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor

    @staticmethod
    def _check_directory_fd(descriptor: int) -> None:
        details = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(details.st_mode)
            or details.st_uid != os.geteuid()
            or details.st_mode & 0o077
        ):
            raise SubmissionCheckpointError(
                "submission checkpoint directory must be private and owned"
            )


def _open_lock(directory: int) -> tuple[int, bool]:
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | _no_follow() | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(_LOCK_NAME, flags, 0o600, dir_fd=directory)
        created = True
    except OSError as error:
        if error.errno != errno.EEXIST:
            raise
        descriptor = os.open(
            _LOCK_NAME,
            os.O_RDWR | _no_follow() | getattr(os, "O_CLOEXEC", 0),
            dir_fd=directory,
        )
        created = False
    try:
        _check_private_regular(os.fstat(descriptor), "submission checkpoint lock")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor, created


def _check_named_identity(directory: int, name: str, descriptor: int) -> None:
    opened, current = os.fstat(descriptor), os.stat(name, dir_fd=directory, follow_symlinks=False)
    if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
        raise SubmissionCheckpointError("submission checkpoint lock identity changed")


def _check_existing_destination(directory: int) -> None:
    try:
        details = os.stat(_CHECKPOINT_NAME, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return
    _check_private_regular(details, "submission checkpoint")


def _check_private_regular(details: os.stat_result, label: str) -> None:
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_uid != os.geteuid()
        or details.st_nlink != 1
        or details.st_mode & 0o077
    ):
        raise SubmissionCheckpointError(f"{label} must be a private owned regular file")


def _read_bounded(descriptor: int) -> bytes:
    payload = bytearray()
    while len(payload) <= _MAXIMUM_CHECKPOINT_BYTES:
        chunk = os.read(
            descriptor,
            min(64 * 1024, _MAXIMUM_CHECKPOINT_BYTES + 1 - len(payload)),
        )
        if not chunk:
            break
        payload.extend(chunk)
    if not payload or len(payload) > _MAXIMUM_CHECKPOINT_BYTES:
        raise SubmissionCheckpointError("submission checkpoint has an invalid size")
    return bytes(payload)


def _write_all(descriptor: int, payload: bytes) -> None:
    remaining = memoryview(payload)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise OSError("short checkpoint write")
        remaining = remaining[written:]


def _no_follow() -> int:
    return getattr(os, "O_NOFOLLOW", 0)


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


__all__ = (
    "MAXIMUM_CHECKPOINT_SUBMISSIONS",
    "SubmissionCheckpointError",
    "SubmissionHeadCheckpoint",
    "SubmissionHeadCheckpointFile",
    "build_submission_checkpoint",
    "submission_head_body",
)
