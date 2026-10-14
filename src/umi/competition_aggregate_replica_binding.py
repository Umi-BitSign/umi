"""Opaque byte-only replica binding issued after a native stable file check.

A binding is not semantic package verification or reward authority. It lets an
existing native snapshot attach its objects to an independently checked copy.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path

from .file_identity import file_fingerprint
from .private_files import private_path

_ISSUER = object()


@dataclass(frozen=True, init=False, eq=False)
class VerifiedAggregateReplica:
    path: Path
    sha256: str
    stamp: tuple[str, ...]

    def __init__(self, path, sha256, stamp, *, issuer):
        if issuer is not _ISSUER:
            raise TypeError("replica bindings require native byte verification")
        object.__setattr__(self, "path", Path(path))
        object.__setattr__(self, "sha256", sha256)
        object.__setattr__(self, "stamp", tuple(stamp))

    def check(self, expected_sha256, maximum_bytes):
        private_path(str(self.path))
        info = self.path.lstat()
        if (
            expected_sha256 != self.sha256
            or tuple(str(value) for value in file_fingerprint(info)) != self.stamp
            or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.getuid()
            or info.st_mode & 0o077
            or not 1 <= info.st_size <= maximum_bytes
        ):
            raise ValueError("verified replica changed its selected immutable identity")
        # Snapshot descriptor ordering is a retained format, distinct from
        # file_fingerprint. Do not silently rewrite historical tuple formats.
        return self.path, tuple(self.stamp[i] for i in (0, 1, 3, 4, 2, 5, 6, 7, 8))


def _issue_verified_replica(path, sha256, stamp):
    return VerifiedAggregateReplica(path, sha256, stamp, issuer=_ISSUER)
