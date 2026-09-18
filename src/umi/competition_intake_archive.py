"""Content-addressed, read-only history for a superseded intake policy."""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Annotated, Literal

from pydantic import Field, model_validator
from typing_extensions import Self

from .competition_client import AdmissionReceipt
from .competition_store import CompetitionStore
from .competition_submission_checkpoint import (
    MAXIMUM_CHECKPOINT_SUBMISSIONS,
    build_submission_checkpoint,
)
from .open_competition import (
    CompetitionPolicy,
    Hex32,
    SignedSubmission,
    StrictProtocolModel,
    digest,
    identity,
    validate_admission,
)
from .protocol import canonical_json_bytes

_MANIFEST_NAME = "manifest.json"
_RECORDS_NAME = "records"
_MAXIMUM_MANIFEST_BYTES = 16 * 1024 * 1024
_MAXIMUM_RECORD_BYTES = 3 * 1024 * 1024
_MAXIMUM_ARCHIVE_BYTES = 512 * 1024 * 1024


class ArchivedAdmissionRecord(StrictProtocolModel):
    signed_submission: SignedSubmission
    receipt: AdmissionReceipt


class IntakeArchiveRecordReference(StrictProtocolModel):
    submission_sha256: Hex32
    record_sha256: Hex32
    checkpoint_record_sha256: Hex32
    accepted_block: Annotated[int, Field(ge=0)]


class IntakeArchiveManifest(StrictProtocolModel):
    schema_: Literal["umi-competition-intake-archive/1"] = Field(alias="schema")
    policy: CompetitionPolicy
    public_launch_sha256: Hex32
    submission_set_sha256: Hex32
    source_head_sha256: Hex32
    source_checkpoint_sha256: Hex32
    records: Annotated[
        tuple[IntakeArchiveRecordReference, ...],
        Field(min_length=1, max_length=MAXIMUM_CHECKPOINT_SUBMISSIONS),
    ]

    @model_validator(mode="after")
    def canonical_records(self) -> Self:
        ordered = tuple(
            sorted(self.records, key=lambda item: (item.accepted_block, item.submission_sha256))
        )
        if ordered != self.records or len({item.submission_sha256 for item in self.records}) != len(
            self.records
        ):
            raise ValueError("archive records must be uniquely ordered by acceptance and digest")
        expected_set = hashlib.sha256(
            canonical_json_bytes(sorted(item.submission_sha256 for item in self.records))
        ).hexdigest()
        if self.submission_set_sha256 != expected_set:
            raise ValueError("archive submission-set commitment is inconsistent")
        return self


class IntakeArchiveConfig(StrictProtocolModel):
    schema_: Literal["umi-competition-intake-archive-config/1"] = Field(alias="schema")
    directory: Annotated[str, Field(min_length=1, max_length=4096)]
    manifest_sha256: Hex32

    @model_validator(mode="after")
    def dedicated_directory(self) -> Self:
        path = Path(self.directory)
        if not path.is_absolute() or path == Path(path.anchor):
            raise ValueError("intake archive needs a dedicated absolute directory")
        return self


@dataclass(frozen=True)
class LoadedIntakeArchive:
    manifest: IntakeArchiveManifest
    manifest_sha256: str
    _ordered: tuple[ArchivedAdmissionRecord, ...]
    _by_digest: Mapping[str, ArchivedAdmissionRecord]

    def summary(self) -> dict:
        return {
            "schema": "umi-competition-intake-archive-summary/1",
            "policy_sha256": digest(self.manifest.policy),
            "public_launch_sha256": self.manifest.public_launch_sha256,
            "manifest_sha256": self.manifest_sha256,
            "record_count": len(self._ordered),
            "submission_set_sha256": self.manifest.submission_set_sha256,
            "source_head_sha256": self.manifest.source_head_sha256,
            "source_checkpoint_sha256": self.manifest.source_checkpoint_sha256,
        }

    def canonical_manifest_bytes(self) -> bytes:
        """Return the exact public bytes named by ``manifest_sha256``."""

        payload = canonical_json_bytes(self.manifest)
        if hashlib.sha256(payload).hexdigest() != self.manifest_sha256:
            raise ValueError("loaded intake archive manifest digest changed")
        return payload

    def admission_summaries(self, *, offset: int, limit: int) -> list[dict]:
        if not 0 <= offset <= 1_000_000 or not 1 <= limit <= 100:
            raise ValueError("invalid archived admission-log page")
        return [_admission_summary(record) for record in self._ordered[offset : offset + limit]]

    def submission_by_digest(self, submission_sha256: str) -> dict | None:
        if not _is_hex32(submission_sha256):
            raise ValueError("invalid archived submission digest")
        record = self._by_digest.get(submission_sha256)
        return None if record is None else record.model_dump(mode="json", by_alias=True)

    def canonical_submission_bytes(self, submission_sha256: str) -> bytes | None:
        if not _is_hex32(submission_sha256):
            raise ValueError("invalid archived submission digest")
        record = self._by_digest.get(submission_sha256)
        return None if record is None else canonical_json_bytes(record)


def _is_hex32(value: str) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _admission_summary(record: ArchivedAdmissionRecord) -> dict:
    submission, receipt = record.signed_submission.submission, record.receipt
    return {
        "submission_sha256": digest(submission),
        "hotkey_account_id32": identity(submission.hotkey),
        "track": submission.track,
        "sequence": submission.sequence,
        "accepted_block": receipt.accepted_block,
        "valid_through_block": submission.valid_through_block,
    }


def _checkpoint_record_sha256(record: ArchivedAdmissionRecord) -> str:
    submission, receipt = record.signed_submission.submission, record.receipt
    commitment = {
        "schema": "umi-competition-admission-record-commitment/1",
        "submission_sha256": digest(submission),
        "hotkey": identity(submission.hotkey),
        "track": submission.track,
        "sequence": submission.sequence,
        "accepted_block": receipt.accepted_block,
        "expires_block": submission.valid_through_block,
        "body_sha256": hashlib.sha256(canonical_json_bytes(record.signed_submission)).hexdigest(),
        "receipt_sha256": hashlib.sha256(canonical_json_bytes(receipt)).hexdigest(),
        "writer_generation": 2,
    }
    return hashlib.sha256(canonical_json_bytes(commitment)).hexdigest()


def _validate_record(
    record: ArchivedAdmissionRecord, policy: CompetitionPolicy
) -> ArchivedAdmissionRecord:
    record = ArchivedAdmissionRecord.model_validate_json(canonical_json_bytes(record))
    submission, receipt = record.signed_submission.submission, record.receipt
    policy_sha256 = digest(policy)
    if (
        submission.policy_sha256 != policy_sha256
        or submission.accepted_terms_sha256 != policy.contribution_terms_sha256
        or receipt.policy_sha256 != policy_sha256
        or receipt.submission_sha256 != digest(submission)
        or receipt.registration_snapshot_sha256 != digest(receipt.registration_snapshot)
        or receipt.registration_source != "verifier_attested_finality"
    ):
        raise ValueError("archived admission does not bind its policy or receipt")
    try:
        observed_uid = validate_admission(
            record.signed_submission,
            policy,
            receipt.registration_snapshot,
            receipt.accepted_block,
        )
    except ValueError as error:
        raise ValueError("archived admission cannot be replayed") from error
    if observed_uid != receipt.observed_uid:
        raise ValueError("archived admission receipt names another UID")
    return record


def export_intake_archive(
    store: CompetitionStore,
    destination: Path,
    *,
    confirmed_quiesced: bool,
) -> dict:
    """Export a verified store without changing its policy-bound state."""

    if not confirmed_quiesced:
        raise ValueError("archive export requires a stopped intake and verified backup")
    destination = destination.absolute()
    if destination == Path(destination.anchor) or destination.exists() or destination.is_symlink():
        raise ValueError("archive destination must be a new dedicated directory")
    if store.public_launch_id is None:
        raise ValueError("archive export requires a public-launch-bound intake")

    head = store.retained_submission_head()
    records: list[tuple[str, bytes, ArchivedAdmissionRecord]] = []
    offset = 0
    while True:
        page = store.submissions(offset=offset, limit=100)
        if not page:
            break
        for raw in page:
            record = _validate_record(
                ArchivedAdmissionRecord.model_validate_json(canonical_json_bytes(raw)),
                store.policy,
            )
            submission_sha256 = digest(record.signed_submission.submission)
            records.append((submission_sha256, canonical_json_bytes(record), record))
        offset += len(page)
        if len(records) > MAXIMUM_CHECKPOINT_SUBMISSIONS:
            raise ValueError("archive exceeds the supported submission count")

    if not records:
        raise ValueError("archive export requires retained admissions")
    submission_ids = tuple(sorted(submission_id for submission_id, _, _ in records))
    submission_set_sha256 = hashlib.sha256(canonical_json_bytes(submission_ids)).hexdigest()
    if (
        head.get("policy_sha256") != digest(store.policy)
        or head.get("record_count") != len(records)
        or head.get("submission_set_sha256") != submission_set_sha256
        or not _is_hex32(head.get("head_sha256"))
    ):
        raise ValueError("retained submission head differs from the export")

    references = tuple(
        IntakeArchiveRecordReference(
            submission_sha256=submission_sha256,
            record_sha256=hashlib.sha256(payload).hexdigest(),
            checkpoint_record_sha256=_checkpoint_record_sha256(record),
            accepted_block=record.receipt.accepted_block,
        )
        for submission_sha256, payload, record in sorted(
            records, key=lambda item: (item[2].receipt.accepted_block, item[0])
        )
    )
    checkpoint_references = tuple(sorted(references, key=lambda item: item.submission_sha256))
    checkpoint = build_submission_checkpoint(
        policy_sha256=digest(store.policy),
        public_launch_sha256=store.public_launch_id,
        submission_sha256s=tuple(item.submission_sha256 for item in checkpoint_references),
        admission_record_sha256s=tuple(
            item.checkpoint_record_sha256 for item in checkpoint_references
        ),
    )
    checkpoint_sha256 = hashlib.sha256(canonical_json_bytes(checkpoint)).hexdigest()
    if (
        head.get("head_sha256") != checkpoint.head_sha256
        or head.get("public_launch_sha256") != store.public_launch_id
        or head.get("external_checkpoint_sha256") != checkpoint_sha256
        or head.get("external_checkpoint_durable") is not True
    ):
        raise ValueError("retained submission checkpoint differs from the export")
    manifest = IntakeArchiveManifest(
        schema="umi-competition-intake-archive/1",
        policy=store.policy,
        public_launch_sha256=store.public_launch_id,
        submission_set_sha256=submission_set_sha256,
        source_head_sha256=head["head_sha256"],
        source_checkpoint_sha256=checkpoint_sha256,
        records=references,
    )
    manifest_bytes = canonical_json_bytes(manifest)
    if len(manifest_bytes) > _MAXIMUM_MANIFEST_BYTES:
        raise ValueError("archive manifest exceeds its byte bound")

    destination.mkdir(mode=0o700, parents=False)
    records_directory = destination / _RECORDS_NAME
    try:
        records_directory.mkdir(mode=0o700)
        by_digest = {submission_id: payload for submission_id, payload, _ in records}
        for reference in manifest.records:
            _write_new_file(
                records_directory / f"{reference.submission_sha256}.json",
                by_digest[reference.submission_sha256],
            )
        _write_new_file(destination / _MANIFEST_NAME, manifest_bytes)
        _fsync_directory(records_directory)
        _fsync_directory(destination)
        _fsync_directory(destination.parent)
    except BaseException:
        shutil.rmtree(destination)
        raise
    return {
        "status": "intake_archive_exported",
        "directory": str(destination),
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "policy_sha256": digest(store.policy),
        "record_count": len(records),
        "source_checkpoint_durable": manifest.source_checkpoint_sha256 is not None,
    }


def load_intake_archive(config: IntakeArchiveConfig) -> LoadedIntakeArchive:
    config = IntakeArchiveConfig.model_validate_json(canonical_json_bytes(config))
    directory = Path(config.directory)
    _check_private_directory(directory)
    manifest_bytes = _read_private_file(directory / _MANIFEST_NAME, _MAXIMUM_MANIFEST_BYTES)
    if hashlib.sha256(manifest_bytes).hexdigest() != config.manifest_sha256:
        raise ValueError("intake archive manifest differs from its pinned digest")
    manifest = IntakeArchiveManifest.model_validate_json(manifest_bytes)
    if canonical_json_bytes(manifest) != manifest_bytes:
        raise ValueError("intake archive manifest is not canonical")

    records_directory = directory / _RECORDS_NAME
    _check_private_directory(records_directory)
    ordered: list[ArchivedAdmissionRecord] = []
    by_digest: dict[str, ArchivedAdmissionRecord] = {}
    total_bytes = len(manifest_bytes)
    for reference in manifest.records:
        payload = _read_private_file(
            records_directory / f"{reference.submission_sha256}.json", _MAXIMUM_RECORD_BYTES
        )
        total_bytes += len(payload)
        if total_bytes > _MAXIMUM_ARCHIVE_BYTES:
            raise ValueError("intake archive exceeds its aggregate byte bound")
        if hashlib.sha256(payload).hexdigest() != reference.record_sha256:
            raise ValueError("archived admission differs from its pinned digest")
        record = ArchivedAdmissionRecord.model_validate_json(payload)
        if canonical_json_bytes(record) != payload:
            raise ValueError("archived admission is not canonical")
        record = _validate_record(record, manifest.policy)
        submission_sha256 = digest(record.signed_submission.submission)
        if (
            submission_sha256 != reference.submission_sha256
            or record.receipt.accepted_block != reference.accepted_block
            or submission_sha256 in by_digest
        ):
            raise ValueError("archive record index differs from its admission")
        ordered.append(record)
        by_digest[submission_sha256] = record
    checkpoint_references = tuple(sorted(manifest.records, key=lambda item: item.submission_sha256))
    checkpoint = build_submission_checkpoint(
        policy_sha256=digest(manifest.policy),
        public_launch_sha256=manifest.public_launch_sha256,
        submission_sha256s=tuple(item.submission_sha256 for item in checkpoint_references),
        admission_record_sha256s=tuple(
            item.checkpoint_record_sha256 for item in checkpoint_references
        ),
    )
    if (
        any(
            item.checkpoint_record_sha256
            != _checkpoint_record_sha256(by_digest[item.submission_sha256])
            for item in checkpoint_references
        )
        or manifest.source_head_sha256 != checkpoint.head_sha256
        or manifest.source_checkpoint_sha256
        != hashlib.sha256(canonical_json_bytes(checkpoint)).hexdigest()
    ):
        raise ValueError("intake archive differs from its durable checkpoint")
    return LoadedIntakeArchive(
        manifest=manifest,
        manifest_sha256=config.manifest_sha256,
        _ordered=tuple(ordered),
        _by_digest=MappingProxyType(by_digest),
    )


def _write_new_file(path: Path, payload: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("archive file write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _read_private_file(path: Path, maximum_bytes: int) -> bytes:
    if path.is_symlink():
        raise ValueError("intake archive files cannot be symlinks")
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        details = os.fstat(descriptor)
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_uid != os.geteuid()
            or details.st_mode & 0o077
            or details.st_size > maximum_bytes
        ):
            raise ValueError("intake archive file is not a bounded private regular file")
        payload = bytearray()
        while len(payload) <= maximum_bytes:
            chunk = os.read(descriptor, min(1024 * 1024, maximum_bytes + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        if len(payload) > maximum_bytes:
            raise ValueError("intake archive file exceeds its byte bound")
        return bytes(payload)
    finally:
        os.close(descriptor)


def _check_private_directory(path: Path) -> None:
    details = path.lstat()
    if (
        not stat.S_ISDIR(details.st_mode)
        or details.st_uid != os.geteuid()
        or details.st_mode & 0o077
    ):
        raise ValueError("intake archive directory must be private and owned")


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


__all__ = (
    "ArchivedAdmissionRecord",
    "IntakeArchiveConfig",
    "IntakeArchiveManifest",
    "LoadedIntakeArchive",
    "export_intake_archive",
    "load_intake_archive",
)
