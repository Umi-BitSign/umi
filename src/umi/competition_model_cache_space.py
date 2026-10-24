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

from .open_competition import digest
from .private_files import Directory, ensure_private_directory, lock_private_file, private_path
from .protocol import StrictProtocolModel, canonical_json_bytes

_LOG = logging.getLogger("umi.competition.progress")


def managed_model_slot(path: Path, cache: Path) -> bool:
    """Fixed bounded roots, including the original two-slot layouts."""
    return path.parent == cache and (
        path.name in {"archive", "standby"}
        or path.name in {f"slot-{index:04d}" for index in range(2, 33)}
    )


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
        self.leased = False
        self.archive = None
        self.write_limits = {}
        self.allocations = None
        self.allocated = 0
        self.incremental = False

    def validate_root(self, selected: Path):
        private_path(str(selected))
        if selected != self.root and self.root not in selected.parents:
            raise ValueError("boot-disk materialization is outside its shared cache root")
        ensure_private_directory(self.root)
        ensure_private_directory(selected)

    @staticmethod
    def _entry_size(info, *, device, unit):
        if (
            info.st_dev != device
            or info.st_uid != os.getuid()
            or info.st_mode & 0o077
            or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))
            or (stat.S_ISREG(info.st_mode) and info.st_nlink != 1)
        ):
            raise ValueError("boot-disk cache contains an unsafe allocation")
        return max(info.st_blocks * 512, ((info.st_size + unit - 1) // unit) * unit)

    def _measure(self, selected=None, *, entries=None):
        """Read metadata only; sparse files cannot hide their potential allocation."""
        root = self.root.stat()
        unit = max(4096, os.statvfs(self.root).f_frsize)
        total = selected_bytes = 0
        pending = [self.root]
        while pending:
            path = pending.pop()
            info = path.lstat()
            size = self._entry_size(info, device=root.st_dev, unit=unit)
            if entries is not None:
                entries[path] = size
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

    def _managed_layout(self):
        # Only bounded managed slots have exclusive, allocation-lease-owned
        # writers and read-only CPU consumers. Older boot roots can also hold
        # invocation scratch or other consumers; retain full accounting there.
        cache = self.root / "direct-model-cache"
        return (
            self.archive is not None
            and managed_model_slot(self.archive, cache)
            and {p.name for p in self.root.iterdir()} <= {".allocation.lock", cache.name}
            and cache.is_dir()
            and all(managed_model_slot(p, cache) for p in cache.iterdir())
        )

    def _current_allocation(self):
        if not self.incremental or not self._managed_layout():
            self.incremental = False
            self.allocations = None
            return self._allocation()
        if self.allocations is None:
            entries = {}
            self.allocated, unit, _ = self._measure(entries=entries)
            self.allocations = entries
            return self.allocated, unit
        return self.allocated, max(4096, os.statvfs(self.root).f_frsize)

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
        return self.fits_materializations({Path(archive): bundle})

    def model_bytes(self, bundle):
        unit = max(4096, os.statvfs(self.root).f_frsize)
        return self._metadata_bytes(bundle, unit) + sum(
            ((f.size_bytes + unit - 1) // unit) * unit for f in bundle.files
        )

    def fits_materializations(self, models):
        """Project the complete working set before admitting partial transfers."""
        if not models or any(
            not path.is_relative_to(self.root) or path == self.root for path in models
        ):
            raise ValueError("model slot is outside its shared cache root")
        entries = {}
        allocated, _, _ = self._measure(entries=entries)
        growth = sum(
            max(
                0,
                self.model_bytes(bundle)
                - sum(
                    size for path, size in entries.items() if path == slot or slot in path.parents
                ),
            )
            for slot, bundle in models.items()
        )
        return (
            allocated + growth <= self.maximum_bytes
            and shutil.disk_usage(self.root).free - self.reserve_bytes >= growth
        )

    def available_bytes(self, *, minimum_growth_bytes=0):
        started = time.monotonic()
        allocated, _ = self._current_allocation()
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
                        "allocation_basis": "exclusive_transfer_path_accounting"
                        if self.incremental
                        else "complete_metadata_scan",
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

    def prepare(self, bundle, *, archive=None):
        # Direct R2 materialization splits the concatenated payload into signed
        # files. There is no compressed archive or second payload/extraction
        # copy. Charge path creation, manifest/receipt publication and filesystem
        # rounding as well as the exact file bytes, including empty files.
        unit = max(4096, os.statvfs(self.root).f_frsize)
        self.metadata_bytes = self._metadata_bytes(bundle, unit)
        self.archive = None if archive is None else Path(archive)
        self.write_limits = (
            {}
            if self.archive is None
            else {
                self.archive / digest(bundle) / "model" / f.path: f.size_bytes for f in bundle.files
            }
        )
        self.allocations = None
        # The first capacity read follows interrupted-file cleanup and captures
        # actual allocation once. No payload is read or rehashed for accounting.
        self.incremental = self.leased and self._managed_layout()

    def check_write(self, size):
        # Recheck actual free space immediately before every bounded write.
        # Independent non-cache activity can consume the boot filesystem during
        # a transfer; exhaustion is a retry, retaining completed file receipts.
        # This older port has no path identity, so it cannot charge the next
        # write incrementally. Preserve its existing complete-scan semantics.
        self.incremental = False
        self.allocations = None
        unit = max(4096, os.statvfs(self.root).f_frsize)
        required = ((size + unit - 1) // unit) * unit
        self.available_bytes(minimum_growth_bytes=required)

    def check_file_write(self, path, size):
        """Charge a signed file's next bounded append under the allocation lease.

        The native restorers alone write these managed slots. Each holds the
        same exclusive lease, enforces its signed paths/lengths, and reserves all
        publication metadata up front. Read-only CPU consumers cannot mutate a
        peer. Every write still checks real filesystem free space; older or
        shared-with-scratch layouts keep the complete scan above.
        """
        path = Path(path)
        if not self.leased or path not in self.write_limits or type(size) is not int or size < 1:
            raise ValueError("model file write lacks its prepared exclusive allocation lease")
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size + size > self.write_limits[path]:
            raise ValueError("model file write exceeds its signed allocation")
        if not self.incremental or not self._managed_layout():
            self.check_write(size)
            return
        self._current_allocation()
        root = self.root.stat()
        unit = max(4096, os.statvfs(self.root).f_frsize)
        # Reconcile only this writer's affected file and ancestors. A repaired
        # partial file can have a new inode/size; untouched peer files need no
        # repeated directory walk. Metadata publication has its full reserved
        # allowance, including new zero-length files and atomic temporary names.
        for selected in (path, *path.parents):
            if selected != self.root and self.root not in selected.parents:
                break
            current = info if selected == path else selected.lstat()
            amount = self._entry_size(current, device=root.st_dev, unit=unit)
            if selected != path and not stat.S_ISDIR(current.st_mode):
                raise ValueError("model file write traverses an unsafe allocation")
            self.allocated += amount - self.allocations.get(selected, 0)
            self.allocations[selected] = amount
        required = ((size + unit - 1) // unit) * unit
        self.available_bytes(minimum_growth_bytes=required)
        projected = max(info.st_blocks * 512, ((info.st_size + size + unit - 1) // unit) * unit)
        self.allocated += projected - self.allocations[path]
        self.allocations[path] = projected

    @contextmanager
    def allocation_lease(self):
        ensure_private_directory(self.root)
        descriptor = lock_private_file(self.root / ".allocation.lock")
        try:
            self.leased = True
            yield self
        finally:
            self.leased = self.incremental = False
            self.allocations = None
            self.write_limits = {}
            os.close(descriptor)
