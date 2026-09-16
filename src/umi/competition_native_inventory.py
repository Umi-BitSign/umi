"""Inventory a reviewed native evaluator installation without importing it.

The manifest uses logical root names so the same files can be installed at
different absolute paths. Symlinks must resolve inside the inventoried roots.
"""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

MAX_ENTRIES = 48_000
MAX_BYTES = 8 * 1024**3
ROOT_NAMES = frozenset({"environment", "python", "overlay"})


def checked_roots(roots: dict[str, Path]) -> dict[str, Path]:
    if set(roots) != ROOT_NAMES:
        raise ValueError("native runtime needs environment, python and overlay roots")
    for path in roots.values():
        if not path.is_absolute() or path.resolve(strict=True) != path or not path.is_dir():
            raise ValueError("native runtime roots must be canonical absolute directories")
        if any(path != other and path.is_relative_to(other) for other in roots.values()):
            raise ValueError("native runtime roots overlap")
    if len(set(roots.values())) != len(roots):
        raise ValueError("native runtime roots overlap")
    return roots


def inventory(roots: dict[str, Path]) -> list[dict]:
    roots = checked_roots(roots)
    entries: list[dict] = []
    total = 0
    for label, root in sorted(roots.items()):
        pending = [root]
        while pending:
            path = pending.pop()
            before = path.lstat()
            if before.st_uid != os.getuid() or (
                not stat.S_ISLNK(before.st_mode) and before.st_mode & 0o022
            ):
                raise ValueError("native runtime ownership or permissions differ")
            entry = {
                "root": label,
                "path": path.relative_to(root).as_posix(),
                "mode": stat.S_IMODE(before.st_mode),
            }
            if stat.S_ISLNK(before.st_mode):
                target = path.resolve(strict=True)
                matches = [
                    (name, target.relative_to(base).as_posix())
                    for name, base in roots.items()
                    if target.is_relative_to(base)
                ]
                if len(matches) != 1:
                    raise ValueError("native runtime link escapes its installation")
                entry.update(kind="symlink", target_root=matches[0][0], target_path=matches[0][1])
            elif stat.S_ISDIR(before.st_mode):
                entry.update(kind="directory")
                pending.extend(sorted(path.iterdir(), reverse=True))
            elif stat.S_ISREG(before.st_mode) and before.st_nlink == 1:
                if total + before.st_size > MAX_BYTES:
                    raise ValueError("native runtime exceeds its byte budget")
                checksum = hashlib.sha256()
                size = 0
                descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(descriptor, "rb") as stream:
                    opened = os.fstat(stream.fileno())
                    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                        size += len(chunk)
                        if total + size > MAX_BYTES or size > before.st_size:
                            raise ValueError("native runtime grew during verification")
                        checksum.update(chunk)
                    after = os.fstat(stream.fileno())
                attributes = (
                    "st_dev",
                    "st_ino",
                    "st_uid",
                    "st_mode",
                    "st_nlink",
                    "st_size",
                    "st_mtime_ns",
                    "st_ctime_ns",
                )
                linked = path.lstat()
                if size != before.st_size or any(
                    getattr(before, name) != getattr(info, name)
                    for info in (opened, after, linked)
                    for name in attributes
                ):
                    raise ValueError("native runtime changed during verification")
                total += size
                entry.update(kind="file", sha256=checksum.hexdigest(), size_bytes=size)
            else:
                raise ValueError("native runtime contains special or hardlinked files")
            entries.append(entry)
            if len(entries) > MAX_ENTRIES:
                raise ValueError("native runtime contains too many entries")
    return sorted(entries, key=lambda entry: (entry["root"], entry["path"]))
