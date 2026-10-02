"""Retain byte-verified model delivery before public cohort participation.

An upload reservation is not an admission or a rights/quality certificate.
Completed files survive retries. Interrupted files can be retransmitted without
changing the manifest; neither coordinator downtime nor a target block removes
an accepted delivery reservation. Only native intake can admit the entry.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import sqlite3
import stat
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_serializer, model_validator

from .competition_artifacts import (
    _artifact,
    _copy_verified,
    _directory,
    preserve_bundle,
    verify_preserved_bundle,
)
from .competition_cohort_intake import CohortIntake, history_tip
from .competition_cohort_model_acceptance import ModelArtifactReviewInputs
from .competition_cohort_model_static_review import (
    StandingModelReviewPolicy,
    StaticModelReviewHeld,
    build_standing_model_review,
    verify_standing_review_policy,
)
from .competition_cohort_participation import (
    CohortParticipationRequest,
    admit_recovery_participant,
)
from .competition_execution import execution_boundary
from .competition_round_journal import RoundJournal
from .open_competition import (
    ModelBundle,
    Signature,
    digest,
    identity,
    validate_bundle_policy,
    verify_signature,
)
from .private_files import (
    Directory,
    ensure_private_directory,
    lock_private_file,
    publish_private_model,
    read_private_model,
)
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


class ModelUploadConfig(StrictProtocolModel):
    directory: Directory
    admission_reviews_directory: Directory | None = None
    standing_review_policy: StandingModelReviewPolicy | None = None
    maximum_models: Annotated[int, Field(ge=1, le=4096)] = 1024
    # Reserve space for staging and the verified native archive before delivery.
    maximum_reserved_bytes: Annotated[int, Field(ge=1, le=16 * 1024**4)]
    maximum_metadata_bytes: Annotated[int, Field(ge=1024, le=16 * 1024**3)] = 1024**3
    maximum_concurrent_uploads: Annotated[int, Field(ge=1, le=32)] = 2
    idle_timeout_seconds: Annotated[int, Field(ge=1, le=300)] = 60

    @model_serializer(mode="wrap")
    def serialize(self, handler):
        value = handler(self)
        if self.admission_reviews_directory is None:
            value.pop("admission_reviews_directory", None)
        if self.standing_review_policy is None:
            value.pop("standing_review_policy", None)
        return value

    @model_validator(mode="after")
    def automatic_review_store(self):
        if self.standing_review_policy is not None and self.admission_reviews_directory is None:
            raise ValueError("standing model review requires an admission review directory")
        return self


class IncompleteModelUpload(OSError):
    """The signed model still needs all of its original files."""


class PendingModelReview(OSError):
    """The preserved model still needs its bounded pre-admission review."""


CHUNK_BYTES = 8 * 1024**2


class ModelUploadChunk(StrictProtocolModel):
    schema_: Literal["umi-cohort-model-upload-chunk/1"] = Field(alias="schema")
    upload_sha256: Hex32
    file_index: Annotated[int, Field(ge=0, lt=4096)]
    offset: Annotated[int, Field(ge=0, le=1024**4)]
    size_bytes: Annotated[int, Field(ge=0, le=CHUNK_BYTES)]
    sha256: Hex32


class CohortModelUploads:
    def __init__(self, config: ModelUploadConfig, intake: CohortIntake, archive: Path):
        self.config = ModelUploadConfig.model_validate_json(canonical_json_bytes(config))
        self.intake, self.archive = intake, Path(archive)
        self.root = Path(config.directory)
        reviews = (
            ()
            if self.config.admission_reviews_directory is None
            else (Path(self.config.admission_reviews_directory),)
        )
        roots = (self.root, self.archive, Path(intake.config.directory), *reviews)
        if any(
            a == b or a in b.parents or b in a.parents
            for i, a in enumerate(roots)
            for b in roots[i + 1 :]
        ):
            raise ValueError("model upload, archive and intake stores must be disjoint")
        ensure_private_directory(self.root)
        ensure_private_directory(self.archive)
        for review_root in reviews:
            ensure_private_directory(review_root)
        if self.config.standing_review_policy is not None:
            verify_standing_review_policy(self.config.standing_review_policy, intake.policy)
        self.journal = RoundJournal(
            self.root / "journal",
            {
                "schema": "umi-cohort-model-delivery/1",
                "policy_sha256": digest(intake.policy),
                "cohorts": [b.model_dump(mode="json") for b in intake.config.cohorts],
                "archive": str(archive),
            },
            maximum_bytes=config.maximum_metadata_bytes,
        )
        ensure_private_directory(self.root / "files")

    def reserve(self, request: CohortParticipationRequest, capture) -> str:
        request = CohortParticipationRequest.model_validate_json(canonical_json_bytes(request))
        key, sub = digest(request), request.signed_submission.submission
        if sub.track != "model" or sub.model_bundle is None or "model" not in self.intake.tracks:
            raise ValueError("model delivery requires the model track")
        cohort = request.consent.consent.cohort_sha256
        self.intake._allowed(cohort)
        validate_bundle_policy(sub.model_bundle, self.intake.policy)
        with self.journal.locked():
            prior = self.journal.get("upload", key)
            if prior is not None:
                if prior != request.model_dump(mode="json", by_alias=True):
                    raise ValueError("model delivery retry changes its signed request")
                return key
            # Validation alone: do not add an incomplete model to the roster.
            with self.intake._connection() as (db, store):
                history = store.published_history(cohort)
                if self.intake._seal(db, history, history_tip(history)) is not None:
                    raise ValueError("model delivery cannot start after intake is sealed")
                admit_recovery_participant(
                    request.signed_submission,
                    request.consent,
                    history,
                    self.intake.policy,
                    capture.snapshot,
                    expected_tip_sha256=history_tip(history),
                    current_block=execution_boundary(capture).block,
                )
            models = self.journal.keys("bundle")
            if sub.model_revision not in models:
                reserved = sum(
                    2
                    * sum(
                        f.size_bytes
                        for f in ModelBundle.model_validate_json(
                            canonical_json_bytes(self.journal.get("bundle", model))
                        ).files
                    )
                    for model in models
                )
                if len(models) >= self.config.maximum_models or (
                    reserved + 2 * sum(f.size_bytes for f in sub.model_bundle.files)
                    > self.config.maximum_reserved_bytes
                ):
                    raise OSError("model delivery needs additional durable capacity")
            self.journal.put_many(
                (
                    ("bundle", sub.model_revision, sub.model_bundle),
                    ("upload", key, request),
                )
            )
        return key

    def retained(self, key: str) -> CohortParticipationRequest:
        if len(key) != 64 or any(c not in "0123456789abcdef" for c in key):
            raise ValueError("invalid model delivery identity")
        value = self.journal.get("upload", key)
        if value is None:
            raise FileNotFoundError("model delivery is not reserved")
        request = CohortParticipationRequest.model_validate_json(canonical_json_bytes(value))
        if digest(request) != key:
            raise ValueError("retained model delivery changed")
        return request

    def retry(self, request: CohortParticipationRequest) -> str | None:
        key = digest(request)
        try:
            retained = self.retained(key)
        except FileNotFoundError:
            return None
        if retained != request:
            raise ValueError("model delivery retry differs")
        return key

    def _paths(self, key):
        request = self.retained(key)
        bundle = request.signed_submission.submission.model_bundle
        staging = self.root / "files" / digest(bundle)
        ensure_private_directory(staging)
        ensure_private_directory(staging / "model")
        return bundle, staging

    def _release_preserved_staging(self, bundle: ModelBundle, staging: Path) -> None:
        """Remove the redundant upload tree only after its archive fully verifies."""

        verify_preserved_bundle(bundle, self.archive, self.intake.policy)
        model = staging / "model"
        info = model.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise ValueError("unsafe completed model staging directory")
        shutil.rmtree(model)
        ensure_private_directory(model)
        with _directory(staging) as descriptor:
            os.fsync(descriptor)

    def put_chunk(self, chunk: ModelUploadChunk, signature: Signature, data: bytes):
        chunk = ModelUploadChunk.model_validate_json(canonical_json_bytes(chunk))
        request = self.retained(chunk.upload_sha256)
        if identity(signature.hotkey) != identity(request.signed_submission.submission.hotkey):
            raise ValueError("model chunk signer differs from its submitting hotkey")
        verify_signature(chunk, signature)
        if len(data) != chunk.size_bytes or hashlib.sha256(data).hexdigest() != chunk.sha256:
            raise ValueError("model chunk differs from its signed bytes")
        bundle, staging = self._paths(chunk.upload_sha256)
        if chunk.file_index >= len(bundle.files):
            raise ValueError("file is outside the signed model manifest")
        record = bundle.files[chunk.file_index]
        if chunk.offset + len(data) > record.size_bytes or (not data and record.size_bytes):
            raise ValueError("chunk is outside the declared file")
        lease = lock_private_file(staging / "upload.lock")
        try:
            for root in (self.archive / digest(bundle) / "model", staging / "model"):
                if (root / record.path).exists() or (root / record.path).is_symlink():
                    with _directory(root) as descriptor, _artifact(descriptor, record) as (f, _):
                        f.seek(chunk.offset)
                        if f.read(len(data)) != data:
                            raise ValueError("retry differs from the completed original file")
                    return
            destination = staging / "model" / record.path
            for parent in reversed(destination.parent.relative_to(staging).parents):
                ensure_private_directory(staging / parent)
            ensure_private_directory(destination.parent)
            partial = staging / ("partial-" + str(chunk.file_index))
            fd = os.open(partial, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
            with os.fdopen(fd, "r+b") as stream:
                before = os.fstat(stream.fileno())
                if (
                    not stat.S_ISREG(before.st_mode)
                    or before.st_nlink != 1
                    or before.st_uid != os.getuid()
                    or stat.S_IMODE(before.st_mode) != 0o600
                    or before.st_size > record.size_bytes
                ):
                    raise ValueError("unsafe interrupted model file")
                if chunk.offset > before.st_size:
                    raise ValueError("model chunk skips undelivered bytes")
                stream.seek(chunk.offset)
                overlap = min(len(data), before.st_size - chunk.offset)
                if stream.read(overlap) != data[:overlap]:
                    raise ValueError("model chunk changes retained bytes")
                # A process death may have retained only a prefix of this chunk.
                # Matching retries append its remainder; completed prefixes stay.
                stream.write(data[overlap:])
                stream.flush()
                os.fsync(stream.fileno())
                with _directory(staging) as descriptor:
                    os.fsync(descriptor)
        finally:
            os.close(lease)

    def complete(self, key: str) -> bool:
        bundle, staging = self._paths(key)
        lease = lock_private_file(staging / "upload.lock")
        try:
            if (self.archive / digest(bundle)).exists():
                self._release_preserved_staging(bundle, staging)
                return True
            for index, record in enumerate(bundle.files):
                destination = staging / "model" / record.path
                if destination.exists() or destination.is_symlink():
                    # A restart may follow rename but precede chmod/fsync.
                    with (
                        _directory(staging / "model") as descriptor,
                        _artifact(descriptor, record) as (stream, _),
                    ):
                        _copy_verified(stream, record, None)
                        os.fchmod(stream.fileno(), 0o400)
                        os.fsync(stream.fileno())
                    continue
                partial = staging / ("partial-" + str(index))
                try:
                    fd = os.open(partial, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
                except FileNotFoundError:
                    return False
                with os.fdopen(fd, "r+b") as stream:
                    info = os.fstat(stream.fileno())
                    if (
                        not stat.S_ISREG(info.st_mode)
                        or info.st_nlink != 1
                        or info.st_uid != os.getuid()
                        or stat.S_IMODE(info.st_mode) != 0o600
                        or info.st_size > record.size_bytes
                    ):
                        raise ValueError("unsafe interrupted model file")
                    if info.st_size < record.size_bytes:
                        return False
                    try:
                        _copy_verified(stream, record, None)
                    except ValueError:
                        # Only uncommitted bytes with a wrong full-file hash
                        # are discarded. A matching prefix can be sent again.
                        stream.truncate(0)
                        stream.flush()
                        os.fsync(stream.fileno())
                        raise
                    partial.rename(destination)
                    os.fchmod(stream.fileno(), 0o400)
                    os.fsync(stream.fileno())
                    with _directory(destination.parent) as descriptor:
                        os.fsync(descriptor)
                    with _directory(staging) as descriptor:
                        os.fsync(descriptor)
            preserve_bundle(bundle, staging / "model", self.archive, self.intake.policy)
            self._release_preserved_staging(bundle, staging)
            return True
        finally:
            os.close(lease)

    def poll_once(self):
        """Finalize delivery in the service worker, outside HTTP request deadlines."""
        ready = pending = 0
        reviews_ready = reviews_pending = reviews_held = 0
        review_hold_reason = ""
        error_type = ""
        seen = set()
        for key in self.journal.keys("upload"):
            try:
                bundle, staging = self._paths(key)
                model = digest(bundle)
                if model in seen:
                    continue
                seen.add(model)
                receipt = self.journal.get("preserved", model)
                if receipt is not None and (self.archive / model).is_dir():
                    if any((staging / "model").iterdir()):
                        self.complete(key)
                    ready += 1
                else:
                    if not self.complete(key):
                        pending += 1
                        continue
                    with self.journal.locked():
                        self.journal.put_many(
                            (
                                (
                                    "preserved",
                                    model,
                                    {
                                        "schema": "umi-cohort-model-delivery-preserved/1",
                                        "model_sha256": model,
                                    },
                                ),
                            )
                        )
                    ready += 1
                review_status, reason = self._ensure_review(bundle)
                if review_status == "ready":
                    reviews_ready += 1
                elif review_status == "held":
                    reviews_held += 1
                    review_hold_reason = reason
                elif review_status == "pending":
                    reviews_pending += 1
            except (OSError, ValueError, sqlite3.Error) as error:
                pending += 1
                error_type = type(error).__name__
        return {
            "models_preserved": ready,
            "models_pending": pending,
            "model_reviews_ready": reviews_ready,
            "model_reviews_pending": reviews_pending,
            "model_reviews_held": reviews_held,
            "last_review_hold_reason": review_hold_reason,
            "last_error_type": error_type,
            "artifact_review_certified": False,
        }

    def _ensure_review(self, bundle: ModelBundle) -> tuple[str, str]:
        """Retain one stable review or one stable hold for an exact model."""

        if self.config.admission_reviews_directory is None:
            return "disabled", ""
        model = digest(bundle)
        target = Path(self.config.admission_reviews_directory) / (model + ".json")
        try:
            retained = read_private_model(
                target,
                ModelArtifactReviewInputs,
                maximum_bytes=33 * 1024**2,
            )
        except FileNotFoundError:
            retained = None
        if retained is not None:
            if retained.model_sha256 != model:
                raise ValueError("pre-admission review differs from the preserved model")
            return "ready", ""
        standing = self.config.standing_review_policy
        if standing is None:
            return "pending", ""
        review_policy_sha256 = digest(standing)
        hold_key = model + "-" + review_policy_sha256
        hold = self.journal.get("review_hold", hold_key)
        if hold is not None:
            if (
                not isinstance(hold, dict)
                or hold.get("schema") != "umi-standing-model-artifact-review-hold/1"
                or hold.get("model_sha256") != model
                or hold.get("review_policy_sha256") != review_policy_sha256
                or not isinstance(hold.get("reason_code"), str)
            ):
                raise ValueError("retained model review hold differs")
            return "held", hold["reason_code"]
        try:
            review = build_standing_model_review(bundle, self.archive, self.intake.policy, standing)
        except StaticModelReviewHeld as error:
            hold = {
                "schema": "umi-standing-model-artifact-review-hold/1",
                "model_sha256": model,
                "review_policy_sha256": review_policy_sha256,
                "reason_code": error.reason_code,
            }
            with self.journal.locked():
                self.journal.put_many((("review_hold", hold_key, hold),))
            return "held", error.reason_code
        publish_private_model(target, review, maximum_bytes=33 * 1024**2)
        return "ready", ""

    def status(self, key: str):
        bundle, staging = self._paths(key)
        preserved = (self.archive / digest(bundle)).exists()
        root = self.archive / digest(bundle) / "model" if preserved else staging / "model"
        complete, offsets = [], []
        for index, record in enumerate(bundle.files):
            try:
                with _directory(root) as descriptor, _artifact(descriptor, record) as (_, info):
                    if not info.st_mode & 0o222:
                        complete.append(index)
                offsets.append(record.size_bytes)
            except FileNotFoundError:
                partial = staging / ("partial-" + str(index))
                try:
                    info = partial.lstat()
                except FileNotFoundError:
                    offsets.append(0)
                    continue
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_nlink != 1
                    or info.st_uid != os.getuid()
                    or info.st_mode & 0o077
                    or info.st_size > record.size_bytes
                ):
                    raise ValueError("unsafe interrupted model file") from None
                offsets.append(info.st_size)
        return {
            "upload_sha256": key,
            "model_sha256": digest(bundle),
            "complete_files": complete,
            "file_offsets": offsets,
            "total_files": len(bundle.files),
            "payload_preserved": preserved,
            "participation_admitted": False,
            "artifact_review_certified": False,
        }

    def require_payload(self, request: CohortParticipationRequest):
        sub = request.signed_submission.submission
        if sub.track != "model":
            return
        try:
            verify_preserved_bundle(sub.model_bundle, self.archive, self.intake.policy)
        except FileNotFoundError as error:
            raise IncompleteModelUpload(
                "deliver and verify the complete model before enrollment"
            ) from error
        if self.config.admission_reviews_directory is None:
            return
        try:
            review = read_private_model(
                Path(self.config.admission_reviews_directory) / (sub.model_revision + ".json"),
                ModelArtifactReviewInputs,
                maximum_bytes=33 * 1024**2,
            )
        except FileNotFoundError as error:
            reason = ""
            standing = self.config.standing_review_policy
            if standing is not None:
                hold = self.journal.get("review_hold", sub.model_revision + "-" + digest(standing))
                if isinstance(hold, dict) and isinstance(hold.get("reason_code"), str):
                    reason = ": " + hold["reason_code"]
            raise PendingModelReview(
                "model enrollment awaits its bounded rights and reconstruction review" + reason
            ) from error
        if review.model_sha256 != sub.model_revision:
            raise ValueError("pre-admission review differs from the preserved model")
