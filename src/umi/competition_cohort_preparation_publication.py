"""Owner-only prepared-round delivery, independent of mutable public readers.

The preparation owner supplies its verified canonical bytes after fresh history
and durable-row checks. A private completion receipt preserves successful output
publication across restart; it confers no phase, proof or signing authority.
"""

import fcntl
import logging
import os
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field

from .competition_public_results_directory import atomic_write
from .file_identity import delivery_file_identity
from .private_files import (
    _read_bounded_private_bytes,
    _write_private_bytes,
    ensure_private_directory,
    lock_private_file,
    private_path,
    read_private_model,
)
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class PreparedRoundPublication:
    """Internal snapshot minted only by the native preparation owner."""

    raw: bytes
    sha256: str
    round_sha256: str
    cohort_sha256: str
    sequence: int
    incumbent_model_sha256: str


class _Completion(StrictProtocolModel):
    schema_: Literal["umi-private-prepared-publication/1"] = Field(alias="schema")
    prepared_sha256: Hex32
    # Strings retain exact filesystem nanosecond timestamps in canonical JSON.
    stamp: Annotated[tuple[str, ...], Field(min_length=9, max_length=9)]


def _stamp(path):
    private_path(str(path))
    ensure_private_directory(path.parent)
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_nlink != 1
        or info.st_mode & 0o077
    ):
        raise ValueError("prepared output must be an owned private regular file")
    return tuple(str(v) for v in delivery_file_identity(info))


def _sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class PreparedRoundFiles:
    def __init__(self, root: Path, *, maximum_bytes: int):
        self.root, self.maximum_bytes = root, maximum_bytes

    def publish(self, cohort: str, snapshot: PreparedRoundPublication):
        """Never reread/reparse unchanged payloads; repair delivery, not proof work.

        A missing/corrupt receipt or changed output is an explicit counted repair.
        Existing bytes must still match the native snapshot. Conflicting bytes
        remain untouched; a missing output is restored from the original snapshot.
        The receipt is committed only after the output directory sync succeeds.
        """
        if type(snapshot) is not PreparedRoundPublication or snapshot.cohort_sha256 != cohort:
            raise ValueError("prepared publication requires the native cohort snapshot")
        # Validate the filename even for an internal caller before creating paths.
        if len(cohort) != 64 or any(c not in "0123456789abcdef" for c in cohort):
            raise ValueError("invalid prepared cohort identity")
        if not 1 <= len(snapshot.raw) <= self.maximum_bytes:
            raise ValueError("evaluator output exceeds its byte bound")
        started = time.monotonic()
        ensure_private_directory(self.root)
        records = self.root / ".prepared-publication"
        ensure_private_directory(records)
        path, record = self.root / (cohort + ".json"), records / (cohort + ".json")
        lock = lock_private_file(self.root / ".publish.lock")
        try:
            reason = "legacy_publication_receipt_initialization"
            completion = None
            try:
                _stamp(record)
            except FileNotFoundError:
                pass
            else:
                try:
                    completion = read_private_model(record, _Completion, maximum_bytes=4096)
                except (OSError, ValueError):
                    reason = "damaged_publication_receipt"
            if completion is not None and completion.prepared_sha256 != snapshot.sha256:
                raise ValueError("prepared publication differs from its retained completion")
            try:
                before = _stamp(path)
            except FileNotFoundError:
                before = None
            if completion is not None and before == completion.stamp:
                return
            if completion is not None:
                reason = "missing_output" if before is None else "changed_output_identity"
            self._progress(cohort, started, reason, False)
            if before is None:
                _write_private_bytes(path, snapshot.raw)
            else:
                existing = _read_bounded_private_bytes(path, maximum_bytes=self.maximum_bytes)
                if existing != snapshot.raw:
                    raise ValueError("prepared outbox already contains different bytes")
                if _stamp(path) != before:
                    raise OSError("prepared output changed during publication repair")
            _sync(path.parent)
            completion = _Completion(
                schema="umi-private-prepared-publication/1",
                prepared_sha256=snapshot.sha256,
                stamp=_stamp(path),
            )
            atomic_write(record, canonical_json_bytes(completion), immutable=False)
            self._progress(cohort, started, reason, True)
        finally:
            try:
                fcntl.flock(lock, fcntl.LOCK_UN)
            finally:
                os.close(lock)

    @staticmethod
    def _progress(cohort, started, reason, completed):
        logger.info(
            "prepared_publication cohort=%s stage=publication_repair completed=%s total=1 "
            "elapsed_seconds=%.3f eta_seconds=%s eta_basis=%s "
            "stalled_or_retrying=%s reason=%s planning_eta_seconds=%s "
            "eta_scope=one_prepared_output_delivery certification_authority=false",
            cohort,
            int(completed),
            time.monotonic() - started,
            0 if completed else "null",
            "completed" if completed else "bounded_metadata_delivery",
            not completed,
            reason,
            "[0,0]" if completed else "[0,30]",
        )
