"""Durable reuse of pure legacy-original verification, never current authority.

Only the native first resolver writes a result. Reuse checks every original's
owned file identity without reopening its bytes. Missing/damaged completed
records require explicit repair; changed dependencies reverify only that item.
"""

from __future__ import annotations

import fcntl
import os
import stat
from collections import OrderedDict
from copy import deepcopy
from pathlib import Path
from threading import RLock
from typing import Literal

from pydantic import Field

from .competition_chunked_model_backup import ChunkedBackupSelection
from .competition_cohort_legacy_model_storage import (
    LegacyModelOriginals,
    LegacyModelStorageRepairRequired,
    LegacyModelStorageResolution,
    LegacyModelUploadIncomplete,
    resolve_legacy_model_storage,
)
from .competition_transport_verification import TransferProgress
from .competition_verification_reuse import metadata_completion, remember_metadata_completion
from .competition_verification_rules import runtime_identity
from .file_identity import file_fingerprint
from .open_competition import digest
from .private_files import (
    _read_private_bytes,
    _write_private_bytes,
    ensure_private_directory,
    lock_private_file,
    private_path,
)
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

_MAXIMUM = 192 * 1024**2
_MEMORY = 16 * 1024**2


def original_identity(path):
    path = Path(path)
    private_path(str(path))
    ensure_private_directory(path.parent)
    value = path.lstat()
    if (
        not stat.S_ISREG(value.st_mode)
        or value.st_uid != os.getuid()
        or value.st_nlink != 1
        or value.st_mode & 0o077
    ):
        raise LegacyModelStorageRepairRequired("legacy original is unsafe; repair required")
    return tuple(str(v) for v in file_fingerprint(value))


class _OriginalDependency(StrictProtocolModel):
    sha256: Hex32
    identity: tuple[str, ...]


class _OriginalResult(StrictProtocolModel):
    source_kind: Literal["participant", "baseline", "incumbent"]
    selection: ChunkedBackupSelection | None
    originals: LegacyModelOriginals | None


class _Receipt(StrictProtocolModel):
    schema_: Literal["umi-legacy-original-verification/1"] = Field(alias="schema")
    context: Hex32
    dependencies: tuple[_OriginalDependency, ...]
    result: _OriginalResult
    checksum: Hex32

    def expected_checksum(self):
        return digest(
            [
                self.context,
                [d.model_dump(mode="json") for d in self.dependencies],
                self.result.model_dump(mode="json"),
            ]
        )


class LegacyModelOriginalReuse:
    def __init__(self, directory=None, *, repair_reason=None):
        if repair_reason is not None and (directory is None or not repair_reason.strip()):
            raise ValueError("legacy original repair needs a directory and explicit reason")
        self.directory = None if directory is None else Path(directory)
        configured_reserve = os.environ.get("UMI_LEGACY_ORIGINAL_RECEIPT_MIN_FREE_BYTES", "0")
        if not configured_reserve.isdecimal() or not 0 <= int(configured_reserve) < 2**63:
            raise ValueError("legacy original receipt free-space override is invalid")
        self.minimum_free_bytes = int(configured_reserve)
        if self.directory is not None:
            # Older supported hosts may not have created their role state yet.
            # mkdir(parents=True) would give intermediate directories 0755.
            private_path(str(self.directory))
            missing, current = [], self.directory
            while not current.exists():
                missing.append(current)
                current = current.parent
            for current in reversed(missing):
                ensure_private_directory(current)
            ensure_private_directory(self.directory)
        self.repair_reason = repair_reason
        self.memory = OrderedDict()
        self.memory_bytes = 0
        self.lock = RLock()
        self.pid = os.getpid()

    def _remember(self, key, receipt, stamp, size):
        previous = self.memory.pop(key, None)
        if previous is not None:
            self.memory_bytes -= previous[2]
        if size > _MEMORY:
            return
        while self.memory and self.memory_bytes + size > _MEMORY:
            _, old = self.memory.popitem(last=False)
            self.memory_bytes -= old[2]
        self.memory[key] = (receipt, stamp, size)
        self.memory_bytes += size

    def resolve(
        self,
        authenticated,
        *,
        load_original,
        identity,
        endpoint,
        bucket,
        request_sha256=None,
        baseline=False,
        incumbent_sha256=None,
    ):
        if os.getpid() != self.pid:
            raise RuntimeError("legacy original reuse cannot inherit a process lock")
        cohort = digest(authenticated.original_history.plan)
        slot = digest([request_sha256, baseline, incumbent_sha256])
        context = digest(
            [
                "umi-legacy-original-resolution/1",
                runtime_identity(),
                digest(authenticated.policy),
                digest(authenticated.original_history),
                authenticated.adoption_block,
                digest(authenticated.legacy),
                digest(authenticated.preservation),
                endpoint,
                bucket,
                request_sha256,
                baseline,
                incumbent_sha256,
            ]
        )
        path = None
        descriptor = None
        with (
            self.lock,
            TransferProgress(
                "legacy_model_original_verification",
                1,
                unit="originals",
                planning_unit_seconds=(0.001, 5),
            ) as progress,
        ):
            try:
                if self.directory is not None:
                    ensure_private_directory(self.directory / cohort)
                    parent = self.directory / cohort / slot[:2]
                    ensure_private_directory(parent)
                    path = parent / (slot + ".json")
                    descriptor = lock_private_file(path.with_suffix(".lock"))
                key = (cohort, slot)
                receipt = None
                stamp = None
                if path is not None:
                    try:
                        stamp = original_identity(path)
                    except FileNotFoundError as error:
                        if metadata_completion(path).exists():
                            if self.repair_reason is None:
                                raise LegacyModelStorageRepairRequired(
                                    "legacy original receipt missing; explicit repair required"
                                ) from error
                            progress.emit(
                                "repair_required", reason="legacy_original_receipt_missing"
                            )
                cached = self.memory.get(key)
                if cached is not None and cached[1] == stamp:
                    receipt = cached[0]
                elif stamp is not None:
                    try:
                        raw = _read_private_bytes(path, maximum_bytes=_MAXIMUM)
                        receipt = _Receipt.model_validate_json(raw)
                        if (
                            receipt.expected_checksum() != receipt.checksum
                            or canonical_json_bytes(receipt) != raw
                            or original_identity(path) != stamp
                        ):
                            raise ValueError("legacy original receipt changed")
                    except (OSError, ValueError) as error:
                        if self.repair_reason is None:
                            raise LegacyModelStorageRepairRequired(
                                "legacy original receipt damaged; explicit repair required"
                            ) from error
                        progress.emit("repair_required", reason="legacy_original_receipt_damaged")
                        receipt = None
                    else:
                        self._remember(key, receipt, stamp, len(raw))
                valid = receipt is not None and receipt.context == context
                if valid:
                    valid = all(identity(d.sha256) == d.identity for d in receipt.dependencies)
                if valid:
                    if path is not None:
                        remember_metadata_completion(path)
                    progress.set_completed(1, restored=True)
                    result = receipt.result
                else:
                    if receipt is not None:
                        progress.emit(
                            "repair_required", reason="legacy_original_dependencies_changed"
                        )
                    dependencies = {}

                    def source(sha):
                        before = identity(sha)
                        raw = load_original(sha)
                        if identity(sha) != before:
                            raise LegacyModelStorageRepairRequired(
                                "legacy original changed during verification"
                            )
                        dependencies[sha] = before
                        return raw

                    try:
                        native = resolve_legacy_model_storage(
                            authenticated,
                            load_original=source,
                            endpoint=endpoint,
                            bucket=bucket,
                            request_sha256=request_sha256,
                            baseline=baseline,
                            incumbent_sha256=incumbent_sha256,
                        )
                    except LegacyModelUploadIncomplete:
                        result = _OriginalResult(
                            source_kind="participant",
                            selection=None,
                            originals=next(
                                e
                                for e in authenticated.legacy.entries
                                if e.request_sha256 == request_sha256
                            ),
                        )
                    else:
                        result = _OriginalResult(
                            source_kind=native.source_kind,
                            selection=native.selection,
                            originals=native.originals,
                        )
                    if not all(identity(sha) == value for sha, value in dependencies.items()):
                        raise LegacyModelStorageRepairRequired(
                            "legacy originals changed during verification"
                        )
                    receipt = _Receipt(
                        schema="umi-legacy-original-verification/1",
                        context=context,
                        dependencies=tuple(
                            _OriginalDependency(sha256=sha, identity=value)
                            for sha, value in sorted(dependencies.items())
                        ),
                        result=result,
                        checksum="0" * 64,
                    )
                    receipt = receipt.model_copy(update={"checksum": receipt.expected_checksum()})
                    raw = canonical_json_bytes(receipt)
                    if len(raw) > _MAXIMUM:
                        raise ValueError(
                            "legacy original verification receipt exceeds native bounds"
                        )
                    if path is not None:
                        space = os.statvfs(path.parent)
                        needed = self.minimum_free_bytes + len(raw) + 4 * max(4096, space.f_frsize)
                        if space.f_bavail * space.f_frsize < needed:
                            progress.emit(
                                "retrying", reason="legacy_original_receipt_space_unavailable"
                            )
                            raise OSError("legacy original receipt waits for physical reserve")
                        _write_private_bytes(path, raw)
                        folder = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                        try:
                            os.fsync(folder)
                        finally:
                            os.close(folder)
                        remember_metadata_completion(path)
                        stamp = original_identity(path)
                    self._remember(key, receipt, stamp, len(raw))
                    progress.advance(1)
                if result.selection is None:
                    raise LegacyModelUploadIncomplete(
                        "legacy upload remains incomplete; resume original request"
                    )
                result = deepcopy(result)
                return LegacyModelStorageResolution(
                    result.source_kind, result.selection, result.originals
                )
            except LegacyModelStorageRepairRequired:
                progress.emit(
                    "repair_required", reason="legacy_original_receipt_or_source_repair_required"
                )
                raise
            finally:
                if descriptor is not None:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                    os.close(descriptor)
