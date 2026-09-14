"""Stage successor inputs and exchange the stopped worker's current directory.

Staging and selection convey no activation authority. The runtime must hold its
process lock, confirm worker absence, reconcile transactions, select the inputs,
then reload the actual read-only activation mount. Stopped recovery may retire
redundant cached trees through competition_materialization_retention; current,
unbacked stages and the durable recovery sources remain intact.
"""

from __future__ import annotations

import ctypes
import fcntl
import hashlib
import os
import re
import stat
import sys
import uuid
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Annotated

from pydantic import Field

from .competition_host_activation import (
    CURRENT_SUCCESSOR_DIRECTIVE_PAGE_FILENAME,
    RELEASE_IDENTITY_FILENAME,
    WEIGHT_AUTHORIZATION_FILENAME,
    WORKER_EXECUTION_FILENAME,
    SuccessorWorkerExecutionLimits,
    _parse_worker_execution_config,
    _validate_worker_execution_bindings,
)
from .competition_package import _limit_for
from .competition_supervisor import (
    MAX_SUCCESSOR_HISTORY_BYTES,
    SuccessorSupervisorDirectivePage,
    SuccessorSupervisorOperatorConsent,
    load_bound_successor_replay_package,
    parse_canonical_successor_supervisor_directive_history,
    successor_source_config_sha256,
    verify_bound_successor_chain_authorization,
    verify_signed_successor_supervisor_directive_history,
)
from .competition_supervisor_runtime import SuccessorWorkerSelection
from .competition_worker import _open_directory_without_links
from .protocol import StrictProtocolModel, canonical_json_bytes
from .validator_supervisor import ValidatorSupervisorConfig

if TYPE_CHECKING:
    from .competition_host_anchor import MaterializedSuccessorAnchor
    from .competition_supervisor_adapters import SuccessorArtifactFiles

SOURCE_DIRECTORY_NAME = "activation-source"
CACHE_DIRECTORY_NAME = "input-cache"
_STAGE_NAME = re.compile(r"^stage-[0-9a-f]{32}$")
_RETIRING_NAME = re.compile(r"^retiring-([0-9a-f]{64})-[0-9a-f]{32}$")
_LOCK_NAME = ".materialization.lock"
_ISSUER = object()
_CHUNK = 1024 * 1024


class SuccessorMaterializationError(ValueError):
    pass


class SuccessorCurrentMaterializationLimits(StrictProtocolModel):
    maximum_stages: Annotated[int, Field(ge=1, le=1024)]
    maximum_cache_bytes: Annotated[int, Field(ge=1024, le=1024**4)]
    maximum_tree_entries: Annotated[int, Field(ge=16, le=65536)]
    maximum_tree_depth: Annotated[int, Field(ge=2, le=32)]


def successor_materialization_paths(config: ValidatorSupervisorConfig) -> tuple[Path, Path]:
    parent = Path(config.state_root) / "successor-v4"
    return parent / SOURCE_DIRECTORY_NAME, parent / CACHE_DIRECTORY_NAME


def _hash(payload):
    return hashlib.sha256(payload).hexdigest()


def _identity(info):
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
        info.st_nlink,
    )


def _directory(path, *, modes):
    fd = _open_directory_without_links(path)
    info = os.fstat(fd)
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) not in modes:
        os.close(fd)
        raise SuccessorMaterializationError("materialization directory ownership or mode differs")
    return fd


def _read_at(directory_fd, name, maximum, *, expected_sha256=None):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o400
            or not 0 < before.st_size <= maximum
        ):
            raise SuccessorMaterializationError("current input is not a bounded sealed file")
        body = bytearray()
        while len(body) <= maximum:
            part = os.read(fd, min(_CHUNK, maximum + 1 - len(body)))
            if not part:
                break
            body.extend(part)
        if len(body) != before.st_size or _identity(before) != _identity(os.fstat(fd)):
            raise SuccessorMaterializationError("current input changed during reading")
        result = bytes(body)
        if expected_sha256 is not None and _hash(result) != expected_sha256:
            raise SuccessorMaterializationError("current input hash differs")
        return result
    finally:
        os.close(fd)


def _tree(path, limits, *, sealed: bool, allow_owner_writable_root: bool = False):
    """Bounded descriptor walk, retaining file hashes and inode identities."""
    entries = total = 0
    records = {}
    root_modes = {0o555} if sealed else {0o555, 0o700, 0o755}
    if allow_owner_writable_root:
        root_modes.add(0o755)
    root = _directory(path, modes=root_modes)

    def walk(fd, prefix, depth):
        nonlocal entries, total
        info = os.fstat(fd)
        accepted = {0o555, 0o500} if sealed else {0o700, 0o555, 0o500}
        if depth == 0:
            accepted |= root_modes
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) not in accepted:
            raise SuccessorMaterializationError("cached directory ownership or mode differs")
        if depth > limits.maximum_tree_depth:
            raise SuccessorMaterializationError("materialization depth bound exceeded")
        records[prefix] = (_identity(info), None)
        with os.scandir(fd) as children:
            for child in children:
                entries += 1
                if entries > limits.maximum_tree_entries:
                    raise SuccessorMaterializationError("materialization entry bound exceeded")
                name = prefix + "/" + child.name
                before = os.stat(child.name, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISDIR(before.st_mode):
                    nested = os.open(
                        child.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd
                    )
                    try:
                        if _identity(before) != _identity(os.fstat(nested)):
                            raise SuccessorMaterializationError("materialization tree changed")
                        walk(nested, name, depth + 1)
                    finally:
                        os.close(nested)
                elif (
                    stat.S_ISREG(before.st_mode)
                    and before.st_uid == os.geteuid()
                    and before.st_nlink == 1
                ):
                    if stat.S_IMODE(before.st_mode) not in ({0o400} if sealed else {0o400, 0o600}):
                        raise SuccessorMaterializationError("cached input mode differs")
                    total += before.st_size
                    if total > limits.maximum_cache_bytes:
                        raise SuccessorMaterializationError("materialization byte bound exceeded")
                    stream = os.open(
                        child.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd
                    )
                    try:
                        digest, observed = hashlib.sha256(), 0
                        while True:
                            part = os.read(stream, min(_CHUNK, before.st_size + 1 - observed))
                            if not part:
                                break
                            observed += len(part)
                            if observed > before.st_size:
                                raise SuccessorMaterializationError("cached input grew")
                            digest.update(part)
                        if observed != before.st_size or _identity(before) != _identity(
                            os.fstat(stream)
                        ):
                            raise SuccessorMaterializationError("cached input changed")
                    finally:
                        os.close(stream)
                    records[name] = (_identity(before), digest.hexdigest())
                else:
                    raise SuccessorMaterializationError("cache contains a link or special file")
        if _identity(info) != _identity(os.fstat(fd)):
            raise SuccessorMaterializationError("cache directory changed during inspection")

    try:
        walk(root, "", 0)
    finally:
        os.close(root)
    return total, records


def _prepare_cache(config):
    source, cache = successor_materialization_paths(config)
    fd = _directory(Path(config.state_root), modes={0o700})
    os.close(fd)
    for path in (cache.parent, cache):
        with suppress(FileExistsError):
            path.mkdir(mode=0o700)
        fd = _directory(path, modes={0o700})
        os.close(fd)
    return source, cache


@contextmanager
def _cache_lock(cache):
    parent = _directory(cache, modes={0o700})
    lock = -1
    try:
        lock = os.open(_LOCK_NAME, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        info = os.fstat(lock)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_size != 0
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise SuccessorMaterializationError(
                "materialization lock is not the original private file"
            )
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise SuccessorMaterializationError("another materialization is in progress") from error
        if _identity(info) != _identity(os.stat(_LOCK_NAME, dir_fd=parent, follow_symlinks=False)):
            raise SuccessorMaterializationError("materialization lock identity changed")
        yield parent
    finally:
        if lock >= 0:
            os.close(lock)
        os.close(parent)


def _cache_usage(cache, cache_fd, limits):
    count = total = 0
    with os.scandir(cache_fd) as entries:
        for entry in entries:
            if entry.name == _LOCK_NAME:
                continue
            count += 1
            if count > limits.maximum_stages or not (
                _STAGE_NAME.fullmatch(entry.name) or _RETIRING_NAME.fullmatch(entry.name)
            ):
                raise SuccessorMaterializationError(
                    "materialization cache is full or has unknown entries"
                )
            size, _ = _tree(cache / entry.name, limits, sealed=False)
            total += size
            if total > limits.maximum_cache_bytes:
                raise SuccessorMaterializationError("materialization cache byte quota exceeded")
    return count, total


def _write_at(fd, name, payload):
    destination = os.open(
        name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd
    )
    try:
        pending = memoryview(payload)
        while pending:
            count = os.write(destination, pending)
            if count <= 0:
                raise SuccessorMaterializationError("materialization write stopped")
            pending = pending[count:]
        os.fchmod(destination, 0o400)
        os.fsync(destination)
    finally:
        os.close(destination)


def _copy_package(source, destination, package, directive):
    source_fd = _directory(source, modes={0o500})
    destination.mkdir(mode=0o700)
    destination_fd = _directory(destination, modes={0o700})
    try:
        _write_at(destination_fd, "manifest.json", canonical_json_bytes(package.manifest))
        for entry in package.manifest.files:
            # The loader checked canonical bytes, signatures and all declared hashes.
            # Read/copy one bounded object at a time, then reverify the complete copy.
            payload = _read_at(
                source_fd,
                entry.name,
                _limit_for(entry.name, directive.replay_package.limits),
                expected_sha256=entry.sha256,
            )
            if len(payload) != entry.size_bytes:
                raise SuccessorMaterializationError("package size changed during copying")
            _write_at(destination_fd, entry.name, payload)
        os.fchmod(destination_fd, 0o500)
        os.fsync(destination_fd)
    finally:
        os.close(source_fd)
        os.close(destination_fd)


def _controls(selection, files, config, consent, worker_limits):
    signed = selection.signed
    directive = signed.directive
    page_bytes = files.current_directive_page_bytes
    if not isinstance(page_bytes, bytes) or len(page_bytes) > MAX_SUCCESSOR_HISTORY_BYTES:
        raise SuccessorMaterializationError("current directive page exceeds its bound")
    page = parse_canonical_successor_supervisor_directive_history(page_bytes)
    if page.more or page.head != signed:
        raise SuccessorMaterializationError(
            "staging requires the exact complete selected page head"
        )
    for item in (*page.directives, page.head):
        verify_signed_successor_supervisor_directive_history(
            item,
            config=config,
            operator_consent=consent,
            finalized_block=max(
                item.directive.valid_from_block, consent.authorized_at_finalized_block
            ),
        )
    package = load_bound_successor_replay_package(
        files.package_path,
        directive=directive,
        observed_release=directive.release.replay_release_identity,
    )
    execution = _parse_worker_execution_config(files.worker_execution_bytes)
    authorization = None
    if directive.mode == "competition_weights":
        authorization = verify_bound_successor_chain_authorization(
            files.authorization_bytes, directive=directive, config=config, package=package
        )
    elif files.authorization_bytes is not None:
        raise SuccessorMaterializationError("replay inputs cannot carry chain authorization")
    _validate_worker_execution_bindings(
        execution,
        directive=directive,
        release_identity=directive.release.replay_release_identity,
        authorization_body=authorization,
        limits=worker_limits,
    )
    controls = {
        CURRENT_SUCCESSOR_DIRECTIVE_PAGE_FILENAME: page_bytes,
        WORKER_EXECUTION_FILENAME: files.worker_execution_bytes,
        RELEASE_IDENTITY_FILENAME: canonical_json_bytes(directive.release.replay_release_identity),
    }
    if files.authorization_bytes is not None:
        controls[WEIGHT_AUTHORIZATION_FILENAME] = files.authorization_bytes
    return controls, package, page


@dataclass(frozen=True, slots=True)
class StagedSuccessorCurrent:
    path: Path
    directive_sha256: str
    config: ValidatorSupervisorConfig
    operator_consent: SuccessorSupervisorOperatorConsent
    worker_limits: SuccessorWorkerExecutionLimits
    limits: SuccessorCurrentMaterializationLimits
    selection: SuccessorWorkerSelection
    _records: dict = field(repr=False, compare=False)
    _issuer: object = field(default=None, repr=False, compare=False)
    _binding: str = field(default="", repr=False, compare=False)

    def recheck(self):
        _validate_staged(self)


def _stage_binding(value):
    return _hash(
        canonical_json_bytes(
            {
                "path": str(value.path),
                "directive": value.directive_sha256,
                "config": successor_source_config_sha256(value.config),
                "consent": _hash(canonical_json_bytes(value.operator_consent)),
                "worker_limits": _hash(canonical_json_bytes(value.worker_limits)),
                "limits": _hash(canonical_json_bytes(value.limits)),
                "selection": _hash(canonical_json_bytes(value.selection.signed)),
                "records": {
                    name: ([str(part) for part in identity], digest)
                    for name, (identity, digest) in value._records.items()
                },
            }
        )
    )


def _validate_staged(value):
    if (
        type(value) is not StagedSuccessorCurrent
        or value._issuer is not _ISSUER
        or value._binding != _stage_binding(value)
    ):
        raise SuccessorMaterializationError("staged current capability is absent or altered")
    _, cache = successor_materialization_paths(value.config)
    if value.path.parent != cache or not _STAGE_NAME.fullmatch(value.path.name):
        raise SuccessorMaterializationError("staged current is outside its fixed cache")
    _, observed = _tree(value.path, value.limits, sealed=True)
    if observed != value._records:
        raise SuccessorMaterializationError("staged current bytes or identities changed")


def _staged_capability(path, selection, config, consent, worker_limits, limits):
    _, records = _tree(path, limits, sealed=True)
    value = StagedSuccessorCurrent(
        path,
        selection.directive_sha256,
        config,
        consent,
        worker_limits,
        limits,
        selection,
        records,
        _ISSUER,
    )
    object.__setattr__(value, "_binding", _stage_binding(value))
    _validate_staged(value)
    return value


def _reusable_stage(cache, cache_fd, controls, package, config, consent, worker_limits, limits):
    expected = {"/" + name: _hash(payload) for name, payload in controls.items()}
    expected |= {"": None, "/package": None}
    expected["/package/manifest.json"] = _hash(canonical_json_bytes(package.manifest))
    expected |= {"/package/" + item.name: item.sha256 for item in package.manifest.files}
    with os.scandir(cache_fd) as entries:
        count = 0
        for entry in entries:
            if entry.name == _LOCK_NAME:
                continue
            count += 1
            if count > limits.maximum_stages or not (
                _STAGE_NAME.fullmatch(entry.name) or _RETIRING_NAME.fullmatch(entry.name)
            ):
                raise SuccessorMaterializationError("reusable stage scan exceeded its bound")
            if _RETIRING_NAME.fullmatch(entry.name):
                continue
            info = os.stat(entry.name, dir_fd=cache_fd, follow_symlinks=False)
            if stat.S_IMODE(info.st_mode) != 0o555:
                # Interrupted stages remain private and are not promoted implicitly.
                continue
            path = cache / entry.name
            _, records = _tree(path, limits, sealed=True)
            if {name: digest for name, (_, digest) in records.items()} != expected:
                continue
            _read_current(
                path,
                config=config,
                consent=consent,
                worker_limits=worker_limits,
                limits=limits,
            )
            if _tree(path, limits, sealed=True)[1] != records:
                raise SuccessorMaterializationError("reusable stage changed during verification")
            return path
    return None


def stage_successor_current(
    *,
    selection: SuccessorWorkerSelection,
    files: SuccessorArtifactFiles,
    config: ValidatorSupervisorConfig,
    operator_consent: SuccessorSupervisorOperatorConsent,
    worker_limits: SuccessorWorkerExecutionLimits,
    limits: SuccessorCurrentMaterializationLimits,
) -> StagedSuccessorCurrent:
    config = ValidatorSupervisorConfig.model_validate_json(canonical_json_bytes(config))
    operator_consent = SuccessorSupervisorOperatorConsent.model_validate_json(
        canonical_json_bytes(operator_consent)
    )
    worker_limits = SuccessorWorkerExecutionLimits.model_validate_json(
        canonical_json_bytes(worker_limits)
    )
    limits = SuccessorCurrentMaterializationLimits.model_validate_json(canonical_json_bytes(limits))
    selection = SuccessorWorkerSelection(selection.signed)
    controls, package, _ = _controls(selection, files, config, operator_consent, worker_limits)
    projected = sum(map(len, controls.values())) + len(canonical_json_bytes(package.manifest))
    projected += sum(item.size_bytes for item in package.manifest.files)
    _, cache = _prepare_cache(config)
    with _cache_lock(cache) as cache_fd:
        count, used = _cache_usage(cache, cache_fd, limits)
        reusable = _reusable_stage(
            cache, cache_fd, controls, package, config, operator_consent, worker_limits, limits
        )
        if reusable is not None:
            return _staged_capability(
                reusable, selection, config, operator_consent, worker_limits, limits
            )
        if count >= limits.maximum_stages or used + projected > limits.maximum_cache_bytes:
            raise SuccessorMaterializationError(
                "materialization cache is full; retained inputs were not removed"
            )
        path = cache / ("stage-" + uuid.uuid4().hex)
        path.mkdir(mode=0o700)
        fd = _directory(path, modes={0o700})
        try:
            for name, payload in controls.items():
                _write_at(fd, name, payload)
            _copy_package(files.package_path, path / "package", package, selection.signed.directive)
            load_bound_successor_replay_package(
                path / "package",
                directive=selection.signed.directive,
                observed_release=selection.signed.directive.release.replay_release_identity,
            )
            os.fchmod(fd, 0o555)
            os.fsync(fd)
            os.fsync(cache_fd)
        finally:
            os.close(fd)
        return _staged_capability(path, selection, config, operator_consent, worker_limits, limits)


def _validate_anchor(anchor, config, *, allow_parent_repair=False):
    from .competition_host_anchor import MaterializedSuccessorAnchor

    if type(anchor) is not MaterializedSuccessorAnchor:
        raise SuccessorMaterializationError("root-sealed materialized anchor required")
    if allow_parent_repair:
        anchor.recheck_for_parent_repair()
    else:
        anchor.recheck()
    source, _ = successor_materialization_paths(config)
    if anchor.source_root != source or anchor.config != config:
        raise SuccessorMaterializationError(
            "materialized anchor differs from configured backing root"
        )
    for path in (Path(config.state_root), source.parent):
        fd = _directory(path, modes={0o700})
        os.close(fd)
    return source


def _read_current(path, *, config, consent, worker_limits, limits, allow_owner_writable=False):
    _, initial_records = _tree(
        path, limits, sealed=True, allow_owner_writable_root=allow_owner_writable
    )
    fd = _directory(path, modes={0o555, 0o755} if allow_owner_writable else {0o555})
    try:
        if _identity(os.fstat(fd)) != initial_records[""][0]:
            raise SuccessorMaterializationError("current identity changed before reading")
        names = set()
        with os.scandir(fd) as entries:
            for entry in entries:
                if len(names) == 5:
                    raise SuccessorMaterializationError("current has unexpected entries")
                names.add(entry.name)
        page_bytes = _read_at(
            fd, CURRENT_SUCCESSOR_DIRECTIVE_PAGE_FILENAME, MAX_SUCCESSOR_HISTORY_BYTES
        )
        page = parse_canonical_successor_supervisor_directive_history(page_bytes)
        expected = {
            CURRENT_SUCCESSOR_DIRECTIVE_PAGE_FILENAME,
            WORKER_EXECUTION_FILENAME,
            RELEASE_IDENTITY_FILENAME,
            "package",
        }
        if page.head.directive.mode == "competition_weights":
            expected.add(WEIGHT_AUTHORIZATION_FILENAME)
        if names != expected:
            raise SuccessorMaterializationError("current has an unexpected file set")
        execution = _read_at(fd, WORKER_EXECUTION_FILENAME, 1024 * 1024)
        identity = _read_at(fd, RELEASE_IDENTITY_FILENAME, 64 * 1024)
        if identity != canonical_json_bytes(page.head.directive.release.replay_release_identity):
            raise SuccessorMaterializationError(
                "current release identity differs from selected release"
            )
        authorization = None
        if WEIGHT_AUTHORIZATION_FILENAME in expected:
            authorization = _read_at(fd, WEIGHT_AUTHORIZATION_FILENAME, 4 * 1024 * 1024)
    finally:
        os.close(fd)
    from types import SimpleNamespace

    files = SimpleNamespace(
        package_path=path / "package",
        current_directive_page_bytes=page_bytes,
        worker_execution_bytes=execution,
        authorization_bytes=authorization,
    )
    _controls(SuccessorWorkerSelection(page.head), files, config, consent, worker_limits)
    _, observed = _tree(path, limits, sealed=True, allow_owner_writable_root=allow_owner_writable)
    if observed != initial_records:
        raise SuccessorMaterializationError("current changed during validation")
    return page


def _source_fd(source, *, modes):
    fd = _directory(source, modes=modes)
    try:
        names = set()
        with os.scandir(fd) as entries:
            for entry in entries:
                if len(names) == 2:
                    raise SuccessorMaterializationError("backing source has unexpected entries")
                names.add(entry.name)
        if names != {"anchor", "current"}:
            raise SuccessorMaterializationError("backing source is missing anchor or current")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _exchange(cache_fd, stage_name, source_fd):
    if sys.platform != "linux":
        raise SuccessorMaterializationError("atomic current selection requires Linux renameat2")
    function = getattr(ctypes.CDLL(None, use_errno=True), "renameat2", None)
    if function is None:
        raise SuccessorMaterializationError(
            "Linux renameat2 is unavailable; no fallback rename is permitted"
        )
    function.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    function.restype = ctypes.c_int
    if function(cache_fd, os.fsencode(stage_name), source_fd, b"current", 2) != 0:
        code = ctypes.get_errno()
        raise OSError(code, "atomic successor directory exchange failed")


def _install_noreplace(cache_fd, stage_name, source_fd):
    if sys.platform != "linux":
        raise SuccessorMaterializationError("initial current installation requires Linux renameat2")
    function = getattr(ctypes.CDLL(None, use_errno=True), "renameat2", None)
    if function is None:
        raise SuccessorMaterializationError(
            "Linux renameat2 is unavailable; no fallback rename is permitted"
        )
    function.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    function.restype = ctypes.c_int
    if function(cache_fd, os.fsencode(stage_name), source_fd, b"current", 1) != 0:
        raise OSError(ctypes.get_errno(), "initial successor current publication failed")


def _require_no_successor_history(config):
    # Even an empty directory, partial SQLite family or dangling link means
    # this is no longer an untouched installation. Never infer first use from
    # a missing database alone, or read a mutable report as recovery authority.
    state = Path(config.state_root)
    paths = (
        state / "successor-v4-initialization.json",
        state / "successor-adapter",
        state / "successor-v4" / "runtime",
        *(
            state / "successor-v4" / name
            for name in (
                "supervisor.sqlite3",
                "supervisor.sqlite3-journal",
                "supervisor.sqlite3-wal",
                "supervisor.sqlite3-shm",
            )
        ),
        Path(config.worker_state_root) / "competition",
    )
    for path in paths:
        try:
            parent = _directory(path.parent, modes={0o700})
        except FileNotFoundError:
            continue
        try:
            try:
                os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise SuccessorMaterializationError(
                "initial current refuses retained or partial successor history"
            )
        finally:
            os.close(parent)


@dataclass(frozen=True)
class InstalledInitialSuccessorCurrent:
    source_root: Path
    current_path: Path
    directive_sha256: str
    receipt_sha256: str


def install_initial_successor_current(
    staged: StagedSuccessorCurrent, *, anchor: MaterializedSuccessorAnchor
) -> InstalledInitialSuccessorCurrent:
    """Publish the sealed initial inputs once, without replacing any path.

    Like later selection, this service-owner filesystem operation grants no
    activation authority. The host upgrade must retain its original process
    lock and confirm exact host/worker absence throughout the call. It must
    reload the real read-only view before starting the successor. Any existing
    current or successor history requires the separate recovery path.
    """
    _validate_staged(staged)
    source = _validate_anchor(anchor, staged.config)
    if (
        anchor.operator_consent != staged.operator_consent
        or anchor.worker_execution_limits != staged.worker_limits
    ):
        raise SuccessorMaterializationError("initial inputs differ from root-sealed controls")
    initial_page = canonical_json_bytes(anchor.initial_page)
    if (
        _hash(initial_page) != anchor.receipt.initial_successor_page_sha256
        or len(initial_page) != anchor.receipt.initial_successor_page_size_bytes
        or anchor.initial_page.head != staged.selection.signed
    ):
        raise SuccessorMaterializationError("initial inputs differ from the sealed initial page")
    # The sealed transition page starts at v3; the rolling mount starts after
    # the accepted v4 head. Keep the exact signed head, deriving only its empty
    # continuation wrapper. No later head can initialize this installation.
    expected_page = canonical_json_bytes(
        SuccessorSupervisorDirectivePage(
            schema="umi-validator-supervisor-directive-page/4",
            after_version=4,
            after_sequence=anchor.initial_page.head.directive.sequence,
            after_directive_sha256=anchor.initial_page.head.directive_sha256,
            directives=[],
            more=False,
            head=anchor.initial_page.head,
        )
    )
    _, cache = successor_materialization_paths(staged.config)
    with _cache_lock(cache) as cache_fd:
        _cache_usage(cache, cache_fd, staged.limits)
        _validate_staged(staged)
        page = _read_current(
            staged.path,
            config=staged.config,
            consent=staged.operator_consent,
            worker_limits=staged.worker_limits,
            limits=staged.limits,
        )
        if canonical_json_bytes(page) != expected_page:
            raise SuccessorMaterializationError(
                "initial inputs differ from the sealed initial page"
            )
        _require_no_successor_history(staged.config)
        source_fd = _directory(source, modes={0o555})
        stage_fd = -1
        try:
            try:
                fcntl.flock(source_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise SuccessorMaterializationError("activation source is in use") from error
            with os.scandir(source_fd) as entries:
                first, second = next(entries, None), next(entries, None)
                if first is None or first.name != "anchor" or second is not None:
                    raise SuccessorMaterializationError(
                        "initial current requires only the root anchor"
                    )
            if os.fstat(source_fd).st_dev != os.fstat(cache_fd).st_dev:
                raise SuccessorMaterializationError(
                    "initial current and stage use different filesystems"
                )
            anchor.recheck()
            _validate_staged(staged)
            stage_fd = _directory(staged.path, modes={0o555})
            if _identity(os.fstat(stage_fd)) != staged._records[""][0]:
                raise SuccessorMaterializationError("initial stage identity changed")
            _require_no_successor_history(staged.config)
            try:
                os.fchmod(stage_fd, 0o755)
                os.fchmod(source_fd, 0o755)
                _install_noreplace(cache_fd, staged.path.name, source_fd)
                os.fsync(cache_fd)
                os.fsync(source_fd)
            finally:
                try:
                    os.fchmod(stage_fd, 0o555)
                    os.fsync(stage_fd)
                finally:
                    os.fchmod(source_fd, 0o555)
                    os.fsync(source_fd)
        finally:
            if stage_fd >= 0:
                os.close(stage_fd)
            os.close(source_fd)
        anchor.recheck()
        page = _read_current(
            source / "current",
            config=staged.config,
            consent=staged.operator_consent,
            worker_limits=staged.worker_limits,
            limits=staged.limits,
        )
        if canonical_json_bytes(page) != expected_page:
            raise SuccessorMaterializationError("initial current changed after publication")
        _require_no_successor_history(staged.config)
        return InstalledInitialSuccessorCurrent(
            source, source / "current", staged.directive_sha256, anchor.receipt_sha256
        )


@dataclass(frozen=True)
class SelectedSuccessorCurrent:
    source_root: Path
    current_path: Path
    retained_previous_path: Path
    directive_sha256: str


def select_staged_successor_current(
    staged: StagedSuccessorCurrent, *, anchor: MaterializedSuccessorAnchor
) -> SelectedSuccessorCurrent:
    """Exchange inputs after the runtime has stopped and recovered its worker."""
    _validate_staged(staged)
    source = _validate_anchor(anchor, staged.config)
    if (
        anchor.operator_consent != staged.operator_consent
        or anchor.worker_execution_limits != staged.worker_limits
    ):
        raise SuccessorMaterializationError("staged inputs exceed their root-sealed controls")
    from .competition_host_anchor import verify_materialized_current_history

    _, cache = successor_materialization_paths(staged.config)
    with _cache_lock(cache) as cache_fd:
        _validate_staged(staged)
        _, cache_bytes = _cache_usage(cache, cache_fd, staged.limits)
        new_bytes, _ = _tree(staged.path, staged.limits, sealed=True)
        old_bytes, old_records = _tree(source / "current", staged.limits, sealed=True)
        if cache_bytes - new_bytes + old_bytes > staged.limits.maximum_cache_bytes:
            raise SuccessorMaterializationError(
                "retaining previous current would exceed cache quota"
            )
        new_page = _read_current(
            staged.path,
            config=staged.config,
            consent=staged.operator_consent,
            worker_limits=staged.worker_limits,
            limits=staged.limits,
        )
        verify_materialized_current_history(anchor, new_page)
        old_page = _read_current(
            source / "current",
            config=staged.config,
            consent=staged.operator_consent,
            worker_limits=staged.worker_limits,
            limits=staged.limits,
        )
        verify_materialized_current_history(anchor, old_page)
        source_fd = _source_fd(source, modes={0o555})
        old_fd = new_fd = -1
        try:
            if os.fstat(source_fd).st_dev != os.fstat(cache_fd).st_dev:
                raise SuccessorMaterializationError(
                    "current and staged inputs are on different filesystems"
                )
            anchor.recheck()
            _validate_staged(staged)
            if _tree(source / "current", staged.limits, sealed=True)[1] != old_records:
                raise SuccessorMaterializationError("previous current changed before exchange")
            old_fd = _directory(source / "current", modes={0o555})
            new_fd = _directory(staged.path, modes={0o555})
            if (
                _identity(os.fstat(old_fd)) != old_records[""][0]
                or _identity(os.fstat(new_fd)) != staged._records[""][0]
            ):
                raise SuccessorMaterializationError("exchange directory identity changed")
            try:
                # Cross-parent exchange updates '..' and requires write access
                # to both directory inodes. Retained file modes stay sealed.
                os.fchmod(old_fd, 0o755)
                os.fchmod(new_fd, 0o755)
                os.fchmod(source_fd, 0o755)
                _exchange(cache_fd, staged.path.name, source_fd)
                os.fsync(cache_fd)
                os.fsync(source_fd)
            finally:
                try:
                    os.fchmod(old_fd, 0o555)
                    os.fsync(old_fd)
                finally:
                    try:
                        os.fchmod(new_fd, 0o555)
                        os.fsync(new_fd)
                    finally:
                        os.fchmod(source_fd, 0o555)
                        os.fsync(source_fd)
        finally:
            if old_fd >= 0:
                os.close(old_fd)
            if new_fd >= 0:
                os.close(new_fd)
            os.close(source_fd)
        anchor.recheck()
        selected = _read_current(
            source / "current",
            config=staged.config,
            consent=staged.operator_consent,
            worker_limits=staged.worker_limits,
            limits=staged.limits,
        )
        if selected.head.directive_sha256 != staged.directive_sha256:
            raise SuccessorMaterializationError("selected current differs after exchange")
        return SelectedSuccessorCurrent(
            source, source / "current", staged.path, staged.directive_sha256
        )


def repair_successor_source_permissions(
    *, anchor: MaterializedSuccessorAnchor, limits: SuccessorCurrentMaterializationLimits
) -> None:
    """Narrow verified owner-writable directories left by interrupted exchange.

    Exact anchor/current validation precedes narrowing permissions. The caller
    must reload the real read-only mount afterward to obtain any authority.
    """
    limits = SuccessorCurrentMaterializationLimits.model_validate_json(canonical_json_bytes(limits))
    source = _validate_anchor(anchor, anchor.config, allow_parent_repair=True)
    from .competition_host_anchor import verify_materialized_current_history_for_repair

    _, cache = successor_materialization_paths(anchor.config)
    with _cache_lock(cache) as cache_fd:
        _cache_usage(cache, cache_fd, limits)
        _, current_records = _tree(
            source / "current", limits, sealed=True, allow_owner_writable_root=True
        )
        page = _read_current(
            source / "current",
            config=anchor.config,
            consent=anchor.operator_consent,
            worker_limits=anchor.worker_execution_limits,
            limits=limits,
            allow_owner_writable=True,
        )
        verify_materialized_current_history_for_repair(anchor, page)
        fd = _source_fd(source, modes={0o555, 0o755})
        leaves = []
        records = [(source / "current", current_records)]
        try:
            leaves.append(_directory(source / "current", modes={0o555, 0o755}))
            if _identity(os.fstat(leaves[-1])) != current_records[""][0]:
                raise SuccessorMaterializationError("repair current changed during validation")
            with os.scandir(cache_fd) as entries:
                count = 0
                for entry in entries:
                    if entry.name == _LOCK_NAME:
                        continue
                    count += 1
                    if count > limits.maximum_stages or not (
                        _STAGE_NAME.fullmatch(entry.name) or _RETIRING_NAME.fullmatch(entry.name)
                    ):
                        raise SuccessorMaterializationError("repair cache bound exceeded")
                    if _RETIRING_NAME.fullmatch(entry.name):
                        continue
                    info = os.stat(entry.name, dir_fd=cache_fd, follow_symlinks=False)
                    if stat.S_IMODE(info.st_mode) != 0o755:
                        continue
                    _, retained_records = _tree(
                        cache / entry.name, limits, sealed=True, allow_owner_writable_root=True
                    )
                    retained = _read_current(
                        cache / entry.name,
                        config=anchor.config,
                        consent=anchor.operator_consent,
                        worker_limits=anchor.worker_execution_limits,
                        limits=limits,
                        allow_owner_writable=True,
                    )
                    verify_materialized_current_history_for_repair(anchor, retained)
                    leaf = _directory(cache / entry.name, modes={0o755})
                    if _identity(info) != _identity(os.fstat(leaf)):
                        os.close(leaf)
                        raise SuccessorMaterializationError("repair leaf changed during validation")
                    leaves.append(leaf)
                    records.append((cache / entry.name, retained_records))
            anchor.recheck_for_parent_repair()
            for path, expected in records:
                if _tree(path, limits, sealed=True, allow_owner_writable_root=True)[1] != expected:
                    raise SuccessorMaterializationError("repair input changed before resealing")
            for leaf in leaves:
                os.fchmod(leaf, 0o555)
                os.fsync(leaf)
            os.fchmod(fd, 0o555)
            os.fsync(fd)
        finally:
            for leaf in leaves:
                os.close(leaf)
            os.close(fd)
