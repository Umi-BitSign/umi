"""Owned bundle-cache conditioning using bounded kernel metadata only.

No payload is read or hashed. Restored files are already fsynced and their byte
verification remains owned by the existing artifact path. The observed condition
is an empty Linux bundle page cache, not an empty SSD or shared runtime cache.
"""

from __future__ import annotations

import asyncio
import ctypes
import fcntl
import json
import os
import stat
import sys
import time
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from threading import Event

from .competition_artifacts import _artifact, _directory
from .competition_cpu_cache import CpuBundleCacheEvidence
from .competition_cpu_timing import CpuTimingInfrastructureError
from .competition_transport_verification import TransferProgress
from .concurrency import run_owned_thread
from .open_competition import digest
from .protocol import canonical_json_bytes

WINDOW_BYTES = 64 * 1024**2
_MARKER_BYTES = 1024


def _fail(reason):
    raise CpuTimingInfrastructureError(reason)


def _identity(fd):
    info = os.fstat(fd)
    return info.st_dev, info.st_ino, info.st_uid


async def _lock(fd, operation, progress):
    while True:
        try:
            fcntl.flock(fd, operation | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            progress.emit("waiting", reason="model_cache_reader_lease")
            await asyncio.sleep(0.1)


def _root(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    info = os.fstat(fd)
    if info.st_uid != os.geteuid() or info.st_mode & 0o022:
        os.close(fd)
        _fail("model_cache_archive_owner_unqualified")
    return fd


@contextmanager
def _mincore_window(fd, offset, length):
    """PROT_NONE mappings do not fault model bytes into memory."""
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mmap.argtypes = (
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_longlong,
    )
    libc.mmap.restype = ctypes.c_void_p
    libc.mincore.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p)
    libc.mincore.restype = ctypes.c_int
    libc.munmap.argtypes = (ctypes.c_void_p, ctypes.c_size_t)
    libc.munmap.restype = ctypes.c_int
    address = libc.mmap(None, length, 0, 1, fd, offset)  # PROT_NONE, MAP_SHARED
    if address == ctypes.c_void_p(-1).value:
        raise OSError(ctypes.get_errno(), "bundle cache mapping failed")
    try:
        yield libc, address
    finally:
        if libc.munmap(address, length):
            raise OSError(ctypes.get_errno(), "bundle cache mapping cleanup failed")


def _evict_file(fd, size, page_size, stop, advance):
    if stop.is_set():
        raise InterruptedError("bundle cache preparation cancelled")
    rounded = (size + page_size - 1) // page_size * page_size
    if not rounded:
        return 0
    # Advising a complete page-aligned interval includes a partial EOF page.
    os.posix_fadvise(fd, 0, rounded, os.POSIX_FADV_DONTNEED)
    pages = 0
    for offset in range(0, size, WINDOW_BYTES):
        if stop.is_set():
            raise InterruptedError("bundle cache preparation cancelled")
        length = min(WINDOW_BYTES, size - offset)
        count = (length + page_size - 1) // page_size
        with _mincore_window(fd, offset, length) as (libc, address):
            vector = (ctypes.c_ubyte * count)()
            if libc.mincore(address, length, vector):
                raise OSError(ctypes.get_errno(), "bundle cache residency query failed")
            resident = sum(bit & 1 for bit in vector)
        if resident:
            _fail("cpu_bundle_cache_pages_remain")
        pages += count
        advance(count)
    return pages


class ModelCacheLease:
    def __init__(self, archive, model_sha256, root_fd, fd, *, exclusive, invocation_sha256):
        self.archive = Path(archive)
        self.model_sha256 = model_sha256
        self.root_fd, self.fd = root_fd, fd
        self.exclusive, self.invocation_sha256 = exclusive, invocation_sha256
        self.root_identity, self.lock_identity = _identity(root_fd), _identity(fd)
        self.pid, self.closed = os.getpid(), False
        self.conditioned = False

    def check(self, bundle=None):
        if (
            self.closed
            or self.pid != os.getpid()
            or (bundle is not None and digest(bundle) != self.model_sha256)
            or _identity(self.root_fd) != self.root_identity
            or _identity(self.fd) != self.lock_identity
        ):
            _fail("model_cache_lease_changed")
        path_info = self.archive.lstat()
        if (path_info.st_dev, path_info.st_ino, path_info.st_uid) != self.root_identity:
            _fail("model_cache_archive_replaced")
        lock_info = os.stat(
            ".cpu-cache-" + self.model_sha256 + ".lock", dir_fd=self.root_fd, follow_symlinks=False
        )
        if (
            lock_info.st_dev,
            lock_info.st_ino,
            lock_info.st_uid,
        ) != self.lock_identity or lock_info.st_nlink != 1:
            _fail("model_cache_lock_replaced")

    def _marker(self):
        info = os.fstat(self.fd)
        if info.st_size > _MARKER_BYTES:
            _fail("model_cache_recovery_marker_damaged")
        raw = os.pread(self.fd, _MARKER_BYTES + 1, 0)
        if not raw:
            return None
        try:
            value = json.loads(raw)
            invocation = value["invocation_sha256"]
            if (
                set(value) != {"schema", "model_sha256", "invocation_sha256"}
                or value["schema"] != "umi-model-cache-active-invocation/1"
                or value["model_sha256"] != self.model_sha256
                or type(invocation) is not str
                or len(invocation) != 64
                or any(c not in "0123456789abcdef" for c in invocation)
            ):
                raise ValueError("marker binding")
        except (KeyError, TypeError, ValueError) as error:
            raise CpuTimingInfrastructureError("model_cache_recovery_marker_damaged") from error
        return invocation

    def _arm(self):
        raw = canonical_json_bytes(
            {
                "schema": "umi-model-cache-active-invocation/1",
                "model_sha256": self.model_sha256,
                "invocation_sha256": self.invocation_sha256,
            }
        )
        if os.pwrite(self.fd, raw, 0) != len(raw):
            _fail("model_cache_recovery_marker_write_incomplete")
        os.ftruncate(self.fd, len(raw))
        os.fsync(self.fd)

    def cleaned(self):
        """Only call after the owned container and all descendants are gone."""
        if self.exclusive and not self.closed:
            self.check()
            os.ftruncate(self.fd, 0)
            os.fsync(self.fd)

    async def condition(self, bundle, invocation_sha256):
        self.check(bundle)
        if (
            not self.exclusive
            or self.conditioned
            or invocation_sha256 != self.invocation_sha256
            or self._marker() != invocation_sha256
        ):
            _fail("model_cache_conditioning_lacks_owned_invocation")
        if sys.platform != "linux" or not hasattr(os, "posix_fadvise"):
            _fail("model_cache_conditioning_host_unqualified")
        page_size = os.sysconf("SC_PAGE_SIZE")
        if page_size < 4096 or page_size > 65536 or page_size & (page_size - 1):
            _fail("model_cache_page_geometry_unqualified")
        total_bytes = sum(record.size_bytes for record in bundle.files)
        total_pages = sum(
            (record.size_bytes + page_size - 1) // page_size for record in bundle.files
        )
        started = time.monotonic_ns() // 1000
        stop = Event()
        with TransferProgress(
            "model_cache_conditioning",
            total_pages,
            unit="pages",
            total_operations=len(bundle.files),
            planning_unit_seconds=(0.000001, 0.0001),
        ) as progress:
            try:
                with _directory(self.archive / self.model_sha256 / "model") as root:
                    for record in bundle.files:
                        self.check()
                        with _artifact(root, record) as (stream, info):
                            # Linux may mask mincore results for a non-owner.
                            if info.st_uid != os.geteuid():
                                _fail("model_cache_mincore_owner_unqualified")
                            await run_owned_thread(
                                _evict_file,
                                stream.fileno(),
                                info.st_size,
                                page_size,
                                stop,
                                progress.advance,
                                on_cancel=stop.set,
                            )
                            after = os.fstat(stream.fileno())
                            if (
                                info.st_dev,
                                info.st_ino,
                                info.st_size,
                                info.st_mtime_ns,
                                info.st_ctime_ns,
                                info.st_nlink,
                            ) != (
                                after.st_dev,
                                after.st_ino,
                                after.st_size,
                                after.st_mtime_ns,
                                after.st_ctime_ns,
                                after.st_nlink,
                            ):
                                _fail("model_cache_file_identity_changed")
                        progress.advance_operations(1)
            except BaseException:
                progress.emit("repair_required", reason="bundle_cache_conditioning_incomplete")
                raise
        self.conditioned = True
        return CpuBundleCacheEvidence(
            schema="umi-cpu-bundle-cache-evidence/1",
            model_sha256=self.model_sha256,
            invocation_sha256=invocation_sha256,
            file_count=len(bundle.files),
            total_bytes=total_bytes,
            total_pages=total_pages,
            page_size=page_size,
            started_monotonic_us=started,
            finished_monotonic_us=time.monotonic_ns() // 1000,
        )


@asynccontextmanager
async def model_cache_lease(
    archive, bundle, *, exclusive=False, invocation_sha256=None, reconcile=None
):
    """Acquire before model-memory admission; kernel leases release on death.

    The archive guard protects lock-file lifetime during cache-slot eviction.
    The model lock lives beside, never inside, the signed bundle directory.
    """
    if exclusive and (invocation_sha256 is None or reconcile is None):
        _fail("timed_model_cache_lease_requires_retained_recovery")
    key = digest(bundle)
    root = fd = None
    lease = None
    try:
        with TransferProgress("model_cache_lease_wait", 1, unit="models") as progress:
            root = _root(archive)
            await _lock(root, fcntl.LOCK_SH, progress)
            fd = os.open(
                ".cpu-cache-" + key + ".lock",
                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=root,
            )
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid != os.geteuid()
                or info.st_mode & 0o077
            ):
                _fail("model_cache_lock_identity_changed")
            await _lock(fd, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH, progress)
            lease = ModelCacheLease(
                archive, key, root, fd, exclusive=exclusive, invocation_sha256=invocation_sha256
            )
            lease.check(bundle)
            prior = lease._marker()
            if prior is not None:
                if not exclusive:
                    _fail("model_cache_retained_invocation_needs_reconciliation")
                progress.emit("waiting", reason="retained_model_container_reconciliation")
                await reconcile(prior)
                lease.cleaned()
            if exclusive:
                lease._arm()
            progress.advance(1)
        yield lease
    finally:
        if lease is not None:
            lease.closed = True
        if fd is not None:
            os.close(fd)
        if root is not None:
            os.close(root)


@asynccontextmanager
async def model_cache_retirement(archive, *, reconcile=None):
    """Retire only after live readers and retained orphan containers are gone."""
    root = _root(archive)
    try:
        with TransferProgress("model_cache_lease_wait", 1, unit="models") as progress:
            await _lock(root, fcntl.LOCK_EX, progress)
            progress.advance(1)
        # Managed archive slots are bounded; metadata only, never model payloads.
        with os.scandir(root) as entries:
            names = sorted(entry.name for entry in entries if entry.name.startswith(".cpu-cache-"))
        with TransferProgress("model_cache_retirement", len(names), unit="models") as progress:
            for name in names:
                key = name[len(".cpu-cache-") : -len(".lock")]
                if (
                    not name.endswith(".lock")
                    or len(key) != 64
                    or any(c not in "0123456789abcdef" for c in key)
                ):
                    _fail("model_cache_recovery_marker_damaged")
                fd = os.open(name, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root)
                try:
                    info = os.fstat(fd)
                    if (
                        not stat.S_ISREG(info.st_mode)
                        or info.st_nlink != 1
                        or info.st_uid != os.geteuid()
                        or info.st_mode & 0o077
                    ):
                        _fail("model_cache_lock_identity_changed")
                    await _lock(fd, fcntl.LOCK_EX, progress)
                    lease = ModelCacheLease(
                        archive, key, root, fd, exclusive=True, invocation_sha256=None
                    )
                    prior = lease._marker()
                    if prior is not None:
                        if reconcile is None:
                            _fail("model_cache_retained_invocation_needs_reconciliation")
                        progress.emit("waiting", reason="retained_model_container_reconciliation")
                        await reconcile(prior)
                        lease.cleaned()
                    progress.advance(1)
                finally:
                    os.close(fd)
        yield
    finally:
        os.close(root)
