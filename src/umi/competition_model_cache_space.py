"""Explicit shared boot-disk model cache with bounded allocation and free space.

Every cache on the selected filesystem must use the same private cache root.
Its nonblocking allocation mutex serializes transfers across processes; sandbox
candidate leases still own eviction and invocation lifetime. No files are
removed here, and no verification result is stored inside the disposable root.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import stat
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field

from .private_files import Directory, ensure_private_directory, lock_private_file, private_path
from .protocol import StrictProtocolModel, canonical_json_bytes

_LOG = logging.getLogger("umi.competition.progress")


class BootDiskModelCacheConfig(StrictProtocolModel):
    schema_: Literal["umi-boot-disk-model-cache/1"] = Field(alias="schema")
    directory: Directory
    maximum_allocated_bytes: Annotated[int, Field(ge=1024**2, le=1024**4)]


def disjoint(left: Path, right: Path) -> bool:
    return left != right and left not in right.parents and right not in left.parents


class BootDiskModelCache:
    def __init__(self, config, *, reserve_bytes):
        self.root = Path(config.directory)
        self.maximum_bytes = config.maximum_allocated_bytes
        self.reserve_bytes = reserve_bytes
        self.metadata_bytes = 0
        self.last_report = 0.0

    def validate_root(self, selected: Path):
        private_path(str(selected))
        if selected != self.root and self.root not in selected.parents:
            raise ValueError("boot-disk materialization is outside its shared cache root")
        ensure_private_directory(self.root)
        ensure_private_directory(selected)

    def _measure(self, selected=None):
        """Read metadata only; sparse files cannot hide their potential allocation."""
        root = self.root.stat()
        unit = max(4096, os.statvfs(self.root).f_frsize)
        total = selected_bytes = 0
        pending = [self.root]
        while pending:
            path = pending.pop()
            info = path.lstat()
            if (
                info.st_dev != root.st_dev
                or info.st_uid != os.getuid()
                or info.st_mode & 0o077
                or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))
                or (stat.S_ISREG(info.st_mode) and info.st_nlink != 1)
            ):
                raise ValueError("boot-disk cache contains an unsafe allocation")
            size = max(info.st_blocks * 512, ((info.st_size + unit - 1) // unit) * unit)
            total += size
            if selected is not None and (path == selected or selected in path.parents):
                selected_bytes += size
            if total > self.maximum_bytes:
                raise OSError("boot-disk model cache allocation exceeds its configured bound")
            if stat.S_ISDIR(info.st_mode):
                pending.extend(path.iterdir())
        return total, unit, selected_bytes

    def _allocation(self):
        total, unit, _ = self._measure()
        return total, unit

    @staticmethod
    def _metadata_bytes(bundle, unit):
        directories = {str(parent) for f in bundle.files for parent in Path(f.path).parents}
        return (
            (len(directories) + len(bundle.files) + 32) * unit
            + 4 * len(canonical_json_bytes(bundle))
            + 1024 * len(bundle.files)
        )

    def fits_materialization(self, bundle, archive):
        """Project a complete slot using one metadata scan, without reading payloads.

        Existing partial files count once. Other slots and unrelated entries keep
        their allocation; only the sandbox's lease owner may release a slot.
        Per-write checks still protect against subsequent external consumption.
        """
        archive = Path(archive)
        if not archive.is_relative_to(self.root) or archive == self.root:
            raise ValueError("model slot is outside its shared cache root")
        allocated, unit, selected = self._measure(archive)
        expected = self._metadata_bytes(bundle, unit) + sum(
            ((f.size_bytes + unit - 1) // unit) * unit for f in bundle.files
        )
        growth = max(0, expected - selected)
        return (
            allocated + growth <= self.maximum_bytes
            and shutil.disk_usage(self.root).free - self.reserve_bytes >= growth
        )

    def available_bytes(self, *, minimum_growth_bytes=0):
        started = time.monotonic()
        allocated, _ = self._allocation()
        usage = shutil.disk_usage(self.root)
        available = min(
            usage.free - self.reserve_bytes - self.metadata_bytes,
            self.maximum_bytes - allocated - self.metadata_bytes,
        )
        sufficient = available >= minimum_growth_bytes
        now = time.monotonic()
        if not sufficient or now - self.last_report >= 10:
            self.last_report = now
            _LOG.info(
                json.dumps(
                    {
                        "schema": "umi-model-cache-space-progress/1",
                        "stage": "model_cache_local_space",
                        "status": "completed" if sufficient else "retrying",
                        "completed_units": 1 if sufficient else 0,
                        "total_units": 1,
                        "unit": "space_checks",
                        "percent": 100 if sufficient else 0,
                        "elapsed_seconds": now - started,
                        "eta_seconds": 0 if sufficient else None,
                        "eta_basis": "completed_metadata_space_check"
                        if sufficient
                        else "withdrawn_capacity_unavailable",
                        "eta_scope": "space_check_only_not_materialization",
                        "allocated_bytes": allocated,
                        "maximum_allocated_bytes": self.maximum_bytes,
                        "filesystem_free_bytes": usage.free,
                        "filesystem_reserve_bytes": self.reserve_bytes,
                        "metadata_headroom_bytes": self.metadata_bytes,
                        "required_growth_bytes": minimum_growth_bytes,
                        "available_growth_bytes": max(0, available),
                        "certification_authority": False,
                    },
                    separators=(",", ":"),
                )
            )
        if not sufficient:
            raise OSError("boot-disk model cache capacity or filesystem reserve is unavailable")
        # The existing transfer interface subtracts the physical reserve itself.
        return available + self.reserve_bytes

    def prepare(self, bundle):
        # Direct R2 materialization splits the concatenated payload into signed
        # files. There is no compressed archive or second payload/extraction
        # copy. Charge path creation, manifest/receipt publication and filesystem
        # rounding as well as the exact file bytes, including empty files.
        _, unit = self._allocation()
        self.metadata_bytes = self._metadata_bytes(bundle, unit)

    def check_write(self, size):
        # Recheck actual free space immediately before every bounded write.
        # Independent non-cache activity can consume the boot filesystem during
        # a transfer; exhaustion is a retry, retaining completed file receipts.
        unit = max(4096, os.statvfs(self.root).f_frsize)
        required = ((size + unit - 1) // unit) * unit
        self.available_bytes(minimum_growth_bytes=required)

    @contextmanager
    def allocation_lease(self):
        ensure_private_directory(self.root)
        descriptor = lock_private_file(self.root / ".allocation.lock")
        try:
            yield self
        finally:
            os.close(descriptor)
