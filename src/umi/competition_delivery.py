"""Fixed HTTPS delivery routes for successor inputs, not activation authority.

The installed directive origin supplies versioned pages and hash-addressed
packages. Every accepted package is replayed under its signed target. Release
archives still pass the separate OCI verifier before loading. No URL, response,
cache file or delivery result authorizes a worker or a transaction.
"""

from __future__ import annotations

import asyncio
import ctypes
import fcntl
import hashlib
import os
import re
import secrets
import stat
import sys
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path

from .competition_host_activation import (
    SuccessorWorkerExecutionLimits,
    _legacy_state,
    _parse_worker_execution_config,
    _validate_worker_execution_bindings,
)
from .competition_package import (
    CompetitionPackageManifest,
    _limit_for,
    competition_package_digest,
)
from .competition_supervisor import (
    MAX_SUCCESSOR_DOCUMENT_BYTES,
    MAX_SUCCESSOR_HISTORY_BYTES,
    MAX_SUCCESSOR_HISTORY_RECORDS,
    SuccessorSupervisorOperatorConsent,
    load_bound_successor_replay_package,
    parse_canonical_successor_supervisor_directive_history,
    parse_canonical_successor_supervisor_directive_page,
    successor_initial_history_bytes,
    verify_bound_successor_chain_authorization,
    verify_signed_successor_supervisor_directive_history,
)
from .competition_supervisor_adapters import SuccessorArtifactFiles
from .competition_supervisor_runtime import SuccessorWorkerSelection
from .competition_worker import _open_directory_without_links
from .file_identity import delivery_file_identity as _identity
from .protocol import canonical_json_bytes
from .validator_supervisor import (
    MAX_JSON_SAFE_INTEGER,
    ValidatorSupervisorConfig,
    advance_supervisor_directive_history_state,
    parse_canonical_signed_supervisor_directive,
)
from .validator_supervisor_adapters import PinnedHTTPSClient, _canonical_https_url

_HEX = re.compile(r"^[0-9a-f]{64}$")
_OBJECT_NAME = re.compile(r"(?:package|release|controls)-[0-9a-f]{64}")
_MAX_CONTROL = 128 * 1024
_CHUNK = 1024 * 1024


class SuccessorDeliveryError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class SuccessorDeliveryLimits:
    maximum_cached_objects: int
    maximum_cache_bytes: int
    total_fetch_timeout_seconds: int

    def __post_init__(self):
        for value, lower, upper in (
            (self.maximum_cached_objects, 3, 65536),
            (self.maximum_cache_bytes, 1024, 1024**4),
            (self.total_fetch_timeout_seconds, 1, 86400),
        ):
            if type(value) is not int or not lower <= value <= upper:
                raise ValueError("successor delivery limits exceed supported bounds")


class HTTPSSuccessorDirectiveFetcher:
    """Fetch a bounded page; the runtime authenticates its cursor and history."""

    def __init__(self, config: ValidatorSupervisorConfig, *, client=None):
        self.config = config
        self.base = _canonical_https_url(config.directive_url) + "/successor"
        self.client = client or PinnedHTTPSClient()

    async def fetch_directive_page(
        self, *, after_version: int, after_sequence: int, after_directive_sha256: str
    ) -> bytes:
        if (
            type(after_version) is not int
            or after_version not in {3, 4}
            or type(after_sequence) is not int
            or not 1 <= after_sequence <= 2**53 - 1
            or not isinstance(after_directive_sha256, str)
            or _HEX.fullmatch(after_directive_sha256) is None
        ):
            raise SuccessorDeliveryError("invalid successor feed cursor")
        url = f"{self.base}/after/{after_version}/{after_sequence}/{after_directive_sha256}.json"
        return await self.client.fetch_bytes(url, maximum_bytes=MAX_SUCCESSOR_DOCUMENT_BYTES)

    async def fetch_initial_history(
        self,
        *,
        legacy_signed_bytes: bytes,
        operator_consent: SuccessorSupervisorOperatorConsent,
        finalized_block: int,
        maximum_records: int = MAX_SUCCESSOR_HISTORY_RECORDS,
        maximum_bytes: int = MAX_SUCCESSOR_HISTORY_BYTES,
        timeout_seconds: int = 300,
    ) -> bytes:
        """Collect authenticated preparation bytes; never authorize a host switch.

        The supplied block is a preparation bound, not owned finality evidence.
        Installation must still verify the history against its stopped checkpoint.
        """
        for value, lower, upper in (
            (finalized_block, 1, MAX_JSON_SAFE_INTEGER),
            (maximum_records, 1, MAX_SUCCESSOR_HISTORY_RECORDS),
            (maximum_bytes, 1024, MAX_SUCCESSOR_HISTORY_BYTES),
            (timeout_seconds, 1, 86400),
        ):
            if type(value) is not int or not lower <= value <= upper:
                raise SuccessorDeliveryError("initial history limits exceed supported bounds")
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout_seconds
        legacy = parse_canonical_signed_supervisor_directive(legacy_signed_bytes)
        state = _legacy_state(self.config, operator_consent, legacy)
        if finalized_block < state.accepted_at_finalized_block:
            raise SuccessorDeliveryError("initial history predates the retained legacy anchor")
        if (
            advance_supervisor_directive_history_state(
                legacy,
                config=self.config,
                finalized_block=state.accepted_at_finalized_block,
                prior_state=state,
            )
            != state
        ):
            raise SuccessorDeliveryError("legacy authority differs from retained consent")

        async def collect():
            cursor = (3, legacy.directive.sequence, legacy.directive_sha256)
            records = []
            received = 0
            while True:
                if loop.time() >= deadline:
                    raise TimeoutError("initial history collection timed out")
                body = await self.fetch_directive_page(
                    after_version=cursor[0],
                    after_sequence=cursor[1],
                    after_directive_sha256=cursor[2],
                )
                received += len(body)
                if received > maximum_bytes:
                    raise SuccessorDeliveryError("initial history exceeds byte budget")
                page = parse_canonical_successor_supervisor_directive_page(body)
                if (page.after_version, page.after_sequence, page.after_directive_sha256) != cursor:
                    raise SuccessorDeliveryError("initial history page cursor differs")
                if len(records) + len(page.directives) > maximum_records:
                    raise SuccessorDeliveryError("initial history exceeds record budget")
                for signed in page.directives:
                    if loop.time() >= deadline:
                        raise TimeoutError("initial history collection timed out")
                    verify_signed_successor_supervisor_directive_history(
                        signed,
                        config=self.config,
                        operator_consent=operator_consent,
                        finalized_block=finalized_block,
                    )
                    records.append(signed)
                if not page.more:
                    payload = successor_initial_history_bytes(legacy, records)
                    if len(payload) > maximum_bytes:
                        raise SuccessorDeliveryError("initial history exceeds byte budget")
                    if loop.time() >= deadline:
                        raise TimeoutError("initial history collection timed out")
                    return payload
                cursor = (4, page.head.directive.sequence, page.head.directive_sha256)

        try:
            return await asyncio.wait_for(collect(), timeout=max(0.0, deadline - loop.time()))
        except asyncio.TimeoutError as error:
            # asyncio's timeout type became a built-in alias in Python 3.11.
            raise TimeoutError("initial history collection timed out") from error


def _directory(path: Path, modes=(0o700,)):
    fd = _open_directory_without_links(path)
    info = os.fstat(fd)
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) not in modes:
        os.close(fd)
        raise SuccessorDeliveryError("delivery directory ownership or mode differs")
    return fd


def _read(path, maximum, *, expected_sha256=None, expected_size=None):
    parent = _directory(path.parent, modes=(0o700, 0o500))
    fd = -1
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o400
            or not 0 < before.st_size <= maximum
            or (expected_size is not None and before.st_size != expected_size)
        ):
            raise SuccessorDeliveryError("cached input is not a bounded sealed file")
        digest, result = hashlib.sha256(), bytearray()
        while len(result) <= maximum:
            chunk = os.read(fd, min(_CHUNK, maximum + 1 - len(result)))
            if not chunk:
                break
            digest.update(chunk)
            result.extend(chunk)
        if len(result) != before.st_size or _identity(before) != _identity(os.fstat(fd)):
            raise SuccessorDeliveryError("cached input changed during reading")
        if expected_sha256 is not None and digest.hexdigest() != expected_sha256:
            raise SuccessorDeliveryError("cached input hash differs")
        return bytes(result)
    finally:
        if fd >= 0:
            os.close(fd)
        os.close(parent)


def _verify_large_file(path, size, sha):
    parent = _directory(path.parent, modes=(0o700, 0o500))
    fd = -1
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o400
            or before.st_size != size
        ):
            raise SuccessorDeliveryError("cached archive metadata differs")
        digest, total = hashlib.sha256(), 0
        while chunk := os.read(fd, min(_CHUNK, size + 1 - total)):
            total += len(chunk)
            if total > size:
                raise SuccessorDeliveryError("cached archive grew")
            digest.update(chunk)
        if (
            total != size
            or digest.hexdigest() != sha
            or _identity(before) != _identity(os.fstat(fd))
        ):
            raise SuccessorDeliveryError("cached archive content differs")
    finally:
        if fd >= 0:
            os.close(fd)
        os.close(parent)


def _publish_noreplace(parent, source, destination):
    if sys.platform != "linux":
        raise SuccessorDeliveryError("atomic delivery publication requires Linux renameat2")
    function = getattr(ctypes.CDLL(None, use_errno=True), "renameat2", None)
    if function is None:
        raise SuccessorDeliveryError("Linux renameat2 is unavailable")
    function.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    function.restype = ctypes.c_int
    if function(parent, os.fsencode(source), parent, os.fsencode(destination), 1) != 0:
        raise OSError(ctypes.get_errno(), "delivery publication did not replace existing data")


def write_initial_history(path: Path, payload: bytes) -> None:
    """Publish one inert, sealed preparation file in an owned private directory."""
    if sys.platform != "linux" or not path.is_absolute():
        raise SuccessorDeliveryError("initial history output requires an absolute Linux path")
    history = parse_canonical_successor_supervisor_directive_history(payload)
    if history.after_version != 3 or history.more or not history.directives:
        raise SuccessorDeliveryError("initial history does not start at a v3 anchor")
    parent = _directory(path.parent)
    descriptor = -1
    temporary = ".initial-history-" + secrets.token_hex(16) + ".partial"
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=parent,
        )
        remaining = memoryview(payload)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("initial history write did not advance")
            remaining = remaining[written:]
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
        _publish_noreplace(parent, temporary, path.name)
        os.fsync(parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent)


def _allowed_object_names(name):
    if name.startswith("package-"):
        from .competition_package import _TREE_NAMES

        final = set(_TREE_NAMES)
    elif name.startswith("release-"):
        final = {"release.bundle"}
    elif name.startswith("controls-"):
        final = {
            "page.json",
            "history.json",
            "history-binding.json",
            "execution.json",
            "authorization.json",
        }
    else:
        raise SuccessorDeliveryError("unknown cache object profile")
    return final | {value + ".partial" for value in final}


class HTTPSSuccessorArtifactDelivery:
    """Fetch/reuse bounded immutable data; this class cannot select current.

    Fully received objects are retained and reverified. Failed or interrupted
    downloads leave only a fixed `.partial` file, which is never evidence and
    can be removed on retry after checking its exact inode/type/owner/mode.
    Completed files, packages and history are never overwritten or evicted.
    Capacity exhaustion holds for operator archival rather than deleting history.
    """

    def __init__(
        self,
        *,
        config: ValidatorSupervisorConfig,
        operator_consent: SuccessorSupervisorOperatorConsent,
        worker_limits: SuccessorWorkerExecutionLimits,
        limits: SuccessorDeliveryLimits,
        client=None,
    ):
        self.config = ValidatorSupervisorConfig.model_validate_json(canonical_json_bytes(config))
        self.consent = SuccessorSupervisorOperatorConsent.model_validate_json(
            canonical_json_bytes(operator_consent)
        )
        self.worker_limits = SuccessorWorkerExecutionLimits.model_validate_json(
            canonical_json_bytes(worker_limits)
        )
        self.limits = SuccessorDeliveryLimits(
            limits.maximum_cached_objects,
            limits.maximum_cache_bytes,
            limits.total_fetch_timeout_seconds,
        )
        self.client = client or PinnedHTTPSClient()
        self.base = _canonical_https_url(config.directive_url) + "/successor"
        self.root = Path(config.state_root) / "successor-v4" / "download-cache"
        self._lease = None

    @contextmanager
    def _locked(self):
        fd = _directory(Path(self.config.state_root))
        os.close(fd)
        for directory in (self.root.parent, self.root):
            with suppress(FileExistsError):
                directory.mkdir(mode=0o700)
            fd = _directory(directory)
            os.close(fd)
        root_fd = _directory(self.root)
        lock = -1
        claimed = False
        try:
            lock = os.open(
                ".lock",
                os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK,
                0o600,
                dir_fd=root_fd,
            )
            info = os.fstat(lock)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_nlink != 1
                or info.st_size != 0
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                raise SuccessorDeliveryError("unsafe delivery lock")
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if self._lease is not None:
                raise SuccessorDeliveryError("delivery instance already holds a cache lease")
            self._lease = (root_fd, lock, _identity(os.fstat(root_fd))[:5], _identity(info))
            claimed = True
            self._check_lease()
            self._usage()
            yield
            self._check_lease()
        finally:
            if claimed:
                self._lease = None
            if lock >= 0:
                os.close(lock)
            os.close(root_fd)

    def _check_lease(self):
        if self._lease is None:
            raise SuccessorDeliveryError("delivery cache lease is absent")
        root, lock, root_identity, lock_identity = self._lease
        check = _directory(self.root)
        try:
            if (
                _identity(os.fstat(check))[:5] != root_identity
                or _identity(os.fstat(root))[:5] != root_identity
                or _identity(os.fstat(lock)) != lock_identity
                or _identity(os.stat(".lock", dir_fd=check, follow_symlinks=False)) != lock_identity
            ):
                raise SuccessorDeliveryError("delivery cache lease identity changed")
        finally:
            os.close(check)

    def _usage(self, *, extra_bytes=0, extra_objects=0):
        self._check_lease()
        objects, total, entries = 0, 0, 0

        def walk(path, depth):
            nonlocal objects, total, entries
            fd = _directory(path, modes=(0o700, 0o500))
            try:
                with os.scandir(fd) as children:
                    for child in children:
                        entries += 1
                        if entries > self.limits.maximum_cached_objects * 16 + 1:
                            raise SuccessorDeliveryError("delivery cache entry limit")
                        before = os.stat(child.name, dir_fd=fd, follow_symlinks=False)
                        if depth == 0 and child.name == ".lock":
                            continue
                        if depth == 1 and child.name not in _allowed_object_names(path.name):
                            raise SuccessorDeliveryError("unexpected delivery object filename")
                        if depth == 0:
                            objects += 1
                            if not _OBJECT_NAME.fullmatch(child.name):
                                raise SuccessorDeliveryError("unexpected delivery cache object")
                        if stat.S_ISDIR(before.st_mode) and depth == 0:
                            nested = _directory(path / child.name, modes=(0o700, 0o500))
                            try:
                                if _identity(before) != _identity(os.fstat(nested)):
                                    raise SuccessorDeliveryError(
                                        "delivery object changed during scan"
                                    )
                            finally:
                                os.close(nested)
                            walk(path / child.name, depth + 1)
                        elif (
                            stat.S_ISREG(before.st_mode)
                            and before.st_uid == os.geteuid()
                            and before.st_nlink == 1
                            and depth == 1
                            and stat.S_IMODE(before.st_mode) in {0o400, 0o600}
                        ):
                            total += before.st_size
                        else:
                            raise SuccessorDeliveryError("unsafe delivery cache entry")
                        if total + extra_bytes > self.limits.maximum_cache_bytes:
                            raise SuccessorDeliveryError("delivery cache byte limit")
            finally:
                os.close(fd)

        walk(self.root, 0)
        if objects + extra_objects > self.limits.maximum_cached_objects:
            raise SuccessorDeliveryError("delivery cache object limit")
        if total + extra_bytes > self.limits.maximum_cache_bytes:
            raise SuccessorDeliveryError("delivery cache byte limit")

    def _object(self, name):
        self._check_lease()
        if not isinstance(name, str) or not _OBJECT_NAME.fullmatch(name):
            raise SuccessorDeliveryError("cache object name is not content addressed")
        path = self.root / name
        if not path.exists() and not path.is_symlink():
            self._usage(extra_objects=1)
            path.mkdir(mode=0o700)
        fd = _directory(path, modes=(0o700, 0o500))
        os.close(fd)
        return path

    def _check_object_path(self, path):
        if (
            not isinstance(path, Path)
            or path.parent.parent != self.root
            or not _OBJECT_NAME.fullmatch(path.parent.name)
            or path.name not in _allowed_object_names(path.parent.name)
        ):
            raise SuccessorDeliveryError("download path is outside its fixed cache object")

    def _discard_partial(self, path, maximum):
        self._check_lease()
        self._check_object_path(path)
        if not path.name.endswith(".partial") or path.name not in _allowed_object_names(
            path.parent.name
        ):
            raise SuccessorDeliveryError("partial cleanup target is not a fixed download name")
        if not path.exists() and not path.is_symlink():
            return
        parent = _directory(path.parent)
        fd = -1
        try:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) not in {0o400, 0o600}
                or info.st_size > maximum
                or _identity(info)
                != _identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False))
            ):
                raise SuccessorDeliveryError("unsafe interrupted download")
            os.unlink(path.name, dir_fd=parent)
            os.fsync(parent)
        finally:
            if fd >= 0:
                os.close(fd)
            os.close(parent)

    def _publish(self, part, path, *, size, sha256):
        self._check_lease()
        self._check_object_path(path)
        if part != path.with_name(path.name + ".partial"):
            raise SuccessorDeliveryError("publication does not use the fixed partial pair")
        parent = _directory(path.parent)
        fd = -1
        try:
            fd = os.open(part.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            before = os.fstat(fd)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != os.geteuid()
                or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) not in {0o400, 0o600}
                or before.st_size != size
            ):
                raise SuccessorDeliveryError("download partial metadata differs")
            digest, observed = hashlib.sha256(), 0
            while chunk := os.read(fd, min(_CHUNK, size + 1 - observed)):
                observed += len(chunk)
                if observed > size:
                    raise SuccessorDeliveryError("download partial grew")
                digest.update(chunk)
            if (
                observed != size
                or digest.hexdigest() != sha256
                or _identity(before) != _identity(os.fstat(fd))
                or _identity(before)
                != _identity(os.stat(part.name, dir_fd=parent, follow_symlinks=False))
            ):
                raise SuccessorDeliveryError("download partial content differs")
            os.fchmod(fd, 0o400)
            os.fsync(fd)
            self._check_lease()
            if _identity(os.fstat(fd)) != _identity(
                os.stat(part.name, dir_fd=parent, follow_symlinks=False)
            ):
                raise SuccessorDeliveryError("download partial identity changed before publication")
            _publish_noreplace(parent, part.name, path.name)
            os.fsync(parent)
        finally:
            if fd >= 0:
                os.close(fd)
            os.close(parent)

    async def _small(
        self, url, path, maximum, *, sha=None, size=None, validate=None, local_body=None
    ):
        self._check_lease()
        self._check_object_path(path)
        if local_body is not None and (
            not isinstance(local_body, bytes) or not 0 < len(local_body) <= maximum
        ):
            raise SuccessorDeliveryError("invalid bounded local continuation")
        if path.exists() or path.is_symlink():
            body = _read(path, maximum, expected_sha256=sha, expected_size=size)
            if local_body is not None and body != local_body:
                raise SuccessorDeliveryError("cached continuation differs from retained history")
            if validate is not None:
                validate(body)
            return body
        partial = path.with_name(path.name + ".partial")
        self._discard_partial(partial, maximum)
        self._usage(extra_bytes=maximum if local_body is None else len(local_body))
        body = (
            await self.client.fetch_bytes(url, maximum_bytes=maximum)
            if local_body is None
            else local_body
        )
        if not isinstance(body, bytes) or not 0 < len(body) <= maximum:
            raise SuccessorDeliveryError("invalid bounded delivery response")
        if (sha is not None and hashlib.sha256(body).hexdigest() != sha) or (
            size is not None and len(body) != size
        ):
            raise SuccessorDeliveryError("delivery response differs from signed target")
        if validate is not None:
            validate(body)
        self._usage(extra_bytes=len(body))
        parent = _directory(path.parent)
        fd = -1
        try:
            fd = os.open(
                partial.name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=parent,
            )
            view = memoryview(body)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise OSError("short delivery write")
                view = view[written:]
            os.fsync(fd)
        finally:
            if fd >= 0:
                os.close(fd)
            os.close(parent)
        self._publish(partial, path, size=len(body), sha256=hashlib.sha256(body).hexdigest())
        return _read(path, maximum, expected_sha256=sha, expected_size=size)

    def _validate_page(self, body, selection, *, local_history=False):
        parse = (
            parse_canonical_successor_supervisor_directive_history
            if local_history
            else parse_canonical_successor_supervisor_directive_page
        )
        page = parse(body)
        if page.more or page.head != selection.signed:
            raise SuccessorDeliveryError("delivery history does not end at the selected directive")
        for signed in (*page.directives, page.head):
            verify_signed_successor_supervisor_directive_history(
                signed,
                config=self.config,
                operator_consent=self.consent,
                finalized_block=max(
                    signed.directive.issued_at_block, self.consent.authorized_at_finalized_block
                ),
            )

    async def _retained_history(self, controls, selection):
        """Bind runtime-owned bytes without storing another full prefix per run."""
        body = selection.continuation_bytes
        self._validate_page(body, selection, local_history=True)
        history_sha = hashlib.sha256(body).hexdigest()
        # Preserve and check full histories written by older versions. New
        # entries need only a binding: the runtime and recovery registry retain
        # the signed records, and the host still verifies the supplied bytes.
        legacy = controls / "history.json"
        if legacy.exists() or legacy.is_symlink():
            _read(
                legacy,
                MAX_SUCCESSOR_HISTORY_BYTES,
                expected_sha256=history_sha,
                expected_size=len(body),
            )
        binding = canonical_json_bytes(
            {
                "schema": "umi-successor-delivery-history-binding/1",
                "directive_sha256": selection.directive_sha256,
                "history_sha256": history_sha,
                "history_size_bytes": len(body),
            }
        )
        await self._small(None, controls / "history-binding.json", 1024, local_body=binding)
        return body

    async def fetch(self, selection: SuccessorWorkerSelection) -> SuccessorArtifactFiles:
        directive = selection.signed.directive
        verify_signed_successor_supervisor_directive_history(
            selection.signed,
            config=self.config,
            operator_consent=self.consent,
            finalized_block=directive.issued_at_block,
        )
        with self._locked():
            return await asyncio.wait_for(
                self._fetch_locked(selection), timeout=self.limits.total_fetch_timeout_seconds
            )

    async def _fetch_locked(self, selection):
        directive = selection.signed.directive
        target, release = directive.replay_package, directive.release
        controls = self._object("controls-" + selection.directive_sha256)
        control_base = self.base + "/directives/" + selection.directive_sha256
        if selection.continuation_bytes is None:
            page_bytes = await self._small(
                control_base + "/page.json",
                controls / "page.json",
                MAX_SUCCESSOR_DOCUMENT_BYTES,
                validate=lambda body: self._validate_page(body, selection),
            )
        else:
            # The runtime supplies the complete signed continuation assembled
            # from its retained cursor history. No HTTP request can replace it.
            # The host later checks it against its own root-sealed anchor.
            page_bytes = await self._retained_history(controls, selection)
        package_path = self._object("package-" + target.package_sha256)
        package_base = self.base + "/packages/" + target.package_sha256
        manifest_bytes = await self._small(
            package_base + "/manifest.json",
            package_path / "manifest.json",
            target.limits.maximum_manifest_bytes,
            sha=target.manifest_sha256,
        )
        manifest = CompetitionPackageManifest.model_validate_json(manifest_bytes)
        if (
            canonical_json_bytes(manifest) != manifest_bytes
            or competition_package_digest(manifest) != target.package_sha256
        ):
            raise SuccessorDeliveryError("package manifest differs from signed target")
        if (
            len(manifest_bytes) + sum(item.size_bytes for item in manifest.files)
            > target.limits.maximum_aggregate_bytes
        ):
            raise SuccessorDeliveryError("package aggregate exceeds signed limit")
        for item in manifest.files:
            bound = _limit_for(item.name, target.limits)
            if item.size_bytes > bound:
                raise SuccessorDeliveryError("package object exceeds signed limit")
            await self._small(
                package_base + "/" + item.name,
                package_path / item.name,
                item.size_bytes,
                sha=item.sha256,
                size=item.size_bytes,
            )
        self._check_lease()
        package_fd = _directory(package_path, modes=(0o700, 0o500))
        try:
            os.fchmod(package_fd, 0o500)
            os.fsync(package_fd)
        finally:
            os.close(package_fd)
        package = load_bound_successor_replay_package(
            package_path, directive=directive, observed_release=release.replay_release_identity
        )
        authorization_bytes, body = None, None
        authorization = directive.chain_authorization
        if authorization is not None:
            if authorization.authorization_size_bytes > _MAX_CONTROL:
                raise SuccessorDeliveryError("authorization exceeds installed control profile")
            authorization_bytes = await self._small(
                self.base
                + "/authorizations/"
                + authorization.signed_authorization_sha256
                + ".json",
                controls / "authorization.json",
                authorization.authorization_size_bytes,
                sha=authorization.signed_authorization_sha256,
                size=authorization.authorization_size_bytes,
            )
            body = verify_bound_successor_chain_authorization(
                authorization_bytes, directive=directive, config=self.config, package=package
            )

        def validate_execution(payload):
            _validate_worker_execution_bindings(
                _parse_worker_execution_config(payload),
                directive=directive,
                release_identity=release.replay_release_identity,
                authorization_body=body,
                limits=self.worker_limits,
            )

        execution_bytes = await self._small(
            control_base + "/execution.json",
            controls / "execution.json",
            _MAX_CONTROL,
            validate=validate_execution,
        )
        release_path = self._object("release-" + release.release_bundle_sha256) / "release.bundle"
        if not release_path.exists() and not release_path.is_symlink():
            partial = release_path.with_name("release.bundle.partial")
            self._discard_partial(partial, release.release_bundle_size_bytes)
            self._usage(extra_bytes=release.release_bundle_size_bytes)
            await self.client.download_file(
                release.release_bundle_url,
                destination=partial,
                maximum_bytes=release.release_bundle_size_bytes,
                expected_size_bytes=release.release_bundle_size_bytes,
                expected_sha256=release.release_bundle_sha256,
            )
            self._publish(
                partial,
                release_path,
                size=release.release_bundle_size_bytes,
                sha256=release.release_bundle_sha256,
            )
        _verify_large_file(
            release_path, release.release_bundle_size_bytes, release.release_bundle_sha256
        )
        self._usage()
        return SuccessorArtifactFiles(
            release_bundle_path=release_path,
            package_path=package_path,
            worker_execution_bytes=execution_bytes,
            current_directive_page_bytes=page_bytes,
            authorization_bytes=authorization_bytes,
        )
