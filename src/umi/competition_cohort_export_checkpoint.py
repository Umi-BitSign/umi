"""Private source facts for an already verified partial model export.

The owning journal freshly checks exact assignment and completed-step records;
the existing publication receipt separately checks delivered output files.
These facts never supply execution, closure or remote verification authority.
Older installations ignore this additive namespace and retain ordinary export.
"""

import hashlib
import logging
from collections import OrderedDict
from pathlib import Path
from threading import Lock
from typing import Annotated, Literal

from pydantic import ConfigDict, Field, model_validator

from .competition_public_results_directory import atomic_write
from .competition_verification_rules import runtime_identity
from .open_competition import digest
from .private_files import ensure_private_directory, private_path, read_private_model
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

MAX_CHECKPOINT_BYTES = 2 * 1024**2
MAX_CHECKPOINT_FILES = 2048
MAX_CHECKPOINT_TOTAL_BYTES = 64 * 1024**2
logger = logging.getLogger(__name__)


def legacy_publication_compatible():
    """Receipt /1 historically attests only native-verification ABI /1.

    This is a receipt-semantics identity, unrelated to live chain runtime/spec
    versions. A changed native ABI needs its own publication receipt migration.
    """
    return runtime_identity() == hashlib.sha256(b"umi-native-request-verification/1").hexdigest()


class PartialExportCheckpoint(StrictProtocolModel):
    model_config = ConfigDict(frozen=True)
    schema_: Literal["umi-private-model-partial-export/1"] = Field(alias="schema")
    context_sha256: Hex32
    owner_path: str
    owner_device: str
    owner_inode: str
    slot: Hex32
    cohort_sha256: Hex32
    assignment_sha256: Hex32
    job_sha256: Hex32
    step_keys: Annotated[tuple[Hex32, ...], Field(min_length=6, max_length=4096)]
    step_sha256s: Annotated[tuple[Hex32 | None, ...], Field(min_length=6, max_length=4096)]
    manifest_sha256: Hex32
    maximum_bytes: Annotated[int, Field(gt=0)]
    completed_by_block: Annotated[int, Field(ge=0)]
    checksum: Hex32 = "0" * 64

    @model_validator(mode="after")
    def paired_prefix(self):
        expected = tuple(
            digest(dict(schema="umi-cohort-execution-step/1", job=self.job_sha256, index=index))
            for index in range(len(self.step_keys))
        )
        if (
            len(self.step_keys) != len(self.step_sha256s)
            or len(self.step_keys) % 2
            or self.step_keys != expected
            or all(value is not None for value in self.step_sha256s)
        ):
            raise ValueError("partial export checkpoint requires unfinished paired model work")
        return self

    def sealed(self):
        raw = canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True, exclude={"checksum"})
        )
        return self.model_copy(update={"checksum": hashlib.sha256(raw).hexdigest()})

    def checked(self):
        if self.sealed().checksum != self.checksum:
            raise ValueError("partial export checkpoint checksum changed")
        return self


class ModelPartialExportCheckpoints:
    def __init__(self, root):
        self.root = Path(root) / ".model-partial-export"
        self.entries = OrderedDict()
        self.retained_bytes = 0
        self.lock = Lock()
        self.publish_lock = Lock()

    @staticmethod
    def key(owner, slot):
        return digest(["umi-private-model-partial-owner/1", str(owner.journal.path), slot])

    def load(self, owner, slot):
        key = self.key(owner, slot)
        with self.lock:
            value = self.entries.get(key)
            if value is not None:
                self.entries.move_to_end(key)
                return value[0]
        try:
            value = read_private_model(
                self.root / (key + ".json"),
                PartialExportCheckpoint,
                maximum_bytes=MAX_CHECKPOINT_BYTES,
            ).checked()
        except FileNotFoundError:
            return None
        self._remember(key, value)
        return value

    def _remember(self, key, value, size=None):
        size = len(canonical_json_bytes(value)) if size is None else size
        with self.lock:
            previous = self.entries.pop(key, None)
            if previous is not None:
                self.retained_bytes -= previous[1]
            if size > MAX_CHECKPOINT_TOTAL_BYTES:
                return
            while self.entries and (
                len(self.entries) >= MAX_CHECKPOINT_FILES
                or self.retained_bytes + size > MAX_CHECKPOINT_TOTAL_BYTES
            ):
                _, old = self.entries.popitem(last=False)
                self.retained_bytes -= old[1]
            self.entries[key] = value, size
            self.retained_bytes += size

    def remember(self, owner, checkpoint):
        checkpoint = checkpoint.sealed()
        raw = canonical_json_bytes(checkpoint)
        if len(raw) > MAX_CHECKPOINT_BYTES:
            logger.warning(
                "model_partial_export_checkpoint status=capacity_required "
                "reason=record_bytes bytes=%s maximum_bytes=%s",
                len(raw),
                MAX_CHECKPOINT_BYTES,
            )
            return
        key = self.key(owner, checkpoint.slot)
        self._remember(key, checkpoint, len(raw))
        path = self.root / (key + ".json")
        with self.publish_lock:
            ensure_private_directory(self.root)
            private_path(str(path))
            count = used = 0
            for entry in self.root.iterdir():
                if entry == path:
                    continue
                info = entry.lstat()
                if not entry.is_file() or entry.is_symlink() or info.st_nlink != 1:
                    raise ValueError("partial export checkpoint inventory changed")
                count += 1
                used += info.st_size
                if count >= MAX_CHECKPOINT_FILES or used + len(raw) > MAX_CHECKPOINT_TOTAL_BYTES:
                    logger.warning(
                        "model_partial_export_checkpoint status=capacity_required "
                        "reason=inventory files=%s bytes=%s maximum_files=%s "
                        "maximum_bytes=%s retained_in_memory=true",
                        count,
                        used + len(raw),
                        MAX_CHECKPOINT_FILES,
                        MAX_CHECKPOINT_TOTAL_BYTES,
                    )
                    return
            atomic_write(path, raw, immutable=False)
