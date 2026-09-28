"""Retire only materialized copies reconstructable from retained recovery inputs.

The runtime calls this after stopped transaction recovery. A private, fsynced
rename records retirement before unlinking. An interrupted retirement is resumed
only after rechecking its durable source and every surviving cached file. This
module never deletes current, the registry, delivery packages or partial stages.
"""

from __future__ import annotations

import os
import stat
import uuid

from . import competition_host_anchor as anchors
from . import competition_materialization as material
from .competition_progress import log_phase
from .protocol import canonical_json_bytes


def _expected(controls, package):
    result = {"": None, "/package": None}
    result.update({"/" + name: material._hash(body) for name, body in controls.items()})
    result["/package/manifest.json"] = material._hash(canonical_json_bytes(package.manifest))
    result.update({"/package/" + item.name: item.sha256 for item in package.manifest.files})
    return result


def _check_copy(path, limits, expected, *, partial):
    _, records = material._tree(path, limits, sealed=not partial)
    actual = {name: checksum for name, (_, checksum) in records.items()}
    if (not partial and actual != expected) or any(
        name not in expected or expected[name] != checksum for name, checksum in actual.items()
    ):
        raise material.SuccessorMaterializationError(
            "retired materialization differs from its durable recovery inputs"
        )
    return records


def _remove_verified_tree(cache_fd, name, records):
    """Unlink a verified, bounded tree using only held parent descriptors."""
    root = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=cache_fd)

    def remove(fd, prefix):
        if material._identity(os.fstat(fd)) != records[prefix][0]:
            raise material.SuccessorMaterializationError("retiring directory identity changed")
        children = {
            key[len(prefix) + 1 :]: key
            for key in records
            if key.startswith(prefix + "/") and "/" not in key[len(prefix) + 1 :]
        }
        observed = set()
        with os.scandir(fd) as entries:
            for entry in entries:
                if entry.name not in children or entry.name in observed:
                    raise material.SuccessorMaterializationError(
                        "retiring directory entries changed"
                    )
                observed.add(entry.name)
        if observed != set(children):
            raise material.SuccessorMaterializationError("retiring directory entries changed")
        os.fchmod(fd, 0o700)
        os.fsync(fd)
        for child, key in sorted(children.items()):
            before = os.stat(child, dir_fd=fd, follow_symlinks=False)
            if material._identity(before) != records[key][0]:
                raise material.SuccessorMaterializationError("retiring input identity changed")
            if records[key][1] is None:
                nested = os.open(child, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    remove(nested, key)
                    after = os.stat(child, dir_fd=fd, follow_symlinks=False)
                    if (after.st_dev, after.st_ino) != (
                        os.fstat(nested).st_dev,
                        os.fstat(nested).st_ino,
                    ):
                        raise material.SuccessorMaterializationError(
                            "retiring directory was replaced"
                        )
                    os.rmdir(child, dir_fd=fd)
                finally:
                    os.close(nested)
            else:
                os.unlink(child, dir_fd=fd)
            os.fsync(fd)

    try:
        remove(root, "")
        after = os.stat(name, dir_fd=cache_fd, follow_symlinks=False)
        if (after.st_dev, after.st_ino) != (os.fstat(root).st_dev, os.fstat(root).st_ino):
            raise material.SuccessorMaterializationError("retiring root was replaced")
        os.rmdir(name, dir_fd=cache_fd)
        os.fsync(cache_fd)
    finally:
        os.close(root)


def _require_separate_inodes(records, current_records, package_path, package):
    targets = {identity[:2] for identity, _ in records.values()}
    if targets & {identity[:2] for identity, _ in current_records.values()}:
        raise material.SuccessorMaterializationError("retiring copy aliases current inputs")
    package_fd = material._directory(package_path, modes={0o500})
    try:
        source = os.fstat(package_fd)
        if (source.st_dev, source.st_ino) in targets:
            raise material.SuccessorMaterializationError("retiring copy aliases recovery package")
        expected_names = {"manifest.json", *(item.name for item in package.manifest.files)}
        observed_names = set()
        with os.scandir(package_fd) as entries:
            for entry in entries:
                if entry.name not in expected_names or len(observed_names) >= len(expected_names):
                    raise material.SuccessorMaterializationError("recovery package entries changed")
                observed_names.add(entry.name)
                info = os.stat(entry.name, dir_fd=package_fd, follow_symlinks=False)
                if (info.st_dev, info.st_ino) in targets:
                    raise material.SuccessorMaterializationError(
                        "retiring input aliases recovery package"
                    )
        if observed_names != expected_names:
            raise material.SuccessorMaterializationError("recovery package entries disappeared")
    finally:
        os.close(package_fd)


def _cache_names(cache_fd, limits):
    names = set()
    with os.scandir(cache_fd) as entries:
        for entry in entries:
            if entry.name == material._LOCK_NAME:
                continue
            if (
                len(names) >= limits.maximum_stages
                or entry.name in names
                or not (
                    material._STAGE_NAME.fullmatch(entry.name)
                    or material._RETIRING_NAME.fullmatch(entry.name)
                )
            ):
                raise material.SuccessorMaterializationError(
                    "materialization cache changed after inspection"
                )
            names.add(entry.name)
    return sorted(names)


@log_phase("cache_retirement")
def retire_redundant_successor_inputs(*, anchor, limits, retained):
    """Retire exact cache copies backed by the adapter's audited run registry.

    ``retained`` is the lazy bounded registry mapping, not caller JSON. Each
    selected record and its package are independently verified again here.
    Unstarted or unmatched stages remain available for later activation.
    """
    source = material._validate_anchor(anchor, anchor.config)
    _, cache = material.successor_materialization_paths(anchor.config)
    current_path = source / "current"
    retired = 0
    with material._cache_lock(cache) as cache_fd:
        material._cache_usage(cache, cache_fd, limits)
        current = material._read_current(
            current_path,
            config=anchor.config,
            consent=anchor.operator_consent,
            worker_limits=anchor.worker_execution_limits,
            limits=limits,
        )
        anchors.verify_materialized_current_history(anchor, current)
        current_records = material._tree(current_path, limits, sealed=True)[1]
        names = _cache_names(cache_fd, limits)
        for name in names:
            interrupted = material._RETIRING_NAME.fullmatch(name)
            path = cache / name
            if interrupted:
                identity = interrupted[1]
                if identity not in retained:
                    raise material.SuccessorMaterializationError(
                        "interrupted retirement lost its durable recovery source"
                    )
            else:
                info = os.stat(name, dir_fd=cache_fd, follow_symlinks=False)
                if stat.S_IMODE(info.st_mode) != 0o555:
                    continue  # Partial stages and interrupted exchanges are preserved.
                page = material._read_current(
                    path,
                    config=anchor.config,
                    consent=anchor.operator_consent,
                    worker_limits=anchor.worker_execution_limits,
                    limits=limits,
                )
                identity = page.head.directive_sha256
                if identity not in retained:
                    continue
            selection, files = retained[identity]
            if selection.directive_sha256 != identity:
                raise material.SuccessorMaterializationError("retirement source identity differs")
            # A cache copy cannot vouch for itself. Recovery must remain usable
            # after removing this tree, including after process/host interruption.
            if files.package_path.is_relative_to(cache) or files.package_path.is_relative_to(
                source
            ):
                raise material.SuccessorMaterializationError(
                    "retirement requires a separate durable recovery package"
                )
            controls, package, page = material._controls(
                selection,
                files,
                anchor.config,
                anchor.operator_consent,
                anchor.worker_execution_limits,
            )
            anchors.verify_materialized_current_history(anchor, page)
            expected = _expected(controls, package)
            if not interrupted:
                records = material._tree(path, limits, sealed=True)[1]
                actual = {key: checksum for key, (_, checksum) in records.items()}
                if actual != expected:
                    # Equivalent signed histories may have different wrappers.
                    # Only the exact original recovery bytes permit retirement.
                    continue
                anchor.recheck()
                _check_copy(path, limits, expected, partial=False)
                retiring_name = f"retiring-{identity}-{uuid.uuid4().hex}"
                if os.path.lexists(cache / retiring_name):
                    raise material.SuccessorMaterializationError("retirement destination exists")
                os.rename(name, retiring_name, src_dir_fd=cache_fd, dst_dir_fd=cache_fd)
                os.fsync(cache_fd)
                name, path = retiring_name, cache / retiring_name
            anchor.recheck()
            records = _check_copy(path, limits, expected, partial=True)
            _require_separate_inodes(records, current_records, files.package_path, package)
            if material._tree(current_path, limits, sealed=True)[1] != current_records:
                raise material.SuccessorMaterializationError("current changed before retirement")
            os.fsync(cache_fd)  # Also seals an interrupted rename before its first unlink.
            _remove_verified_tree(cache_fd, name, records)
            retired += 1
        anchor.recheck()
        if material._tree(current_path, limits, sealed=True)[1] != current_records:
            raise material.SuccessorMaterializationError("current changed during cache retirement")
    return retired
