"""Bounded digest reuse for exact sealed materialization files.

This records SHA-256 computation only, never package acceptance or authority.
The caller still walks the complete tree, enforces its current bounds and modes,
and checks each held descriptor before and after using a digest.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections import OrderedDict
from collections.abc import Callable
from pathlib import Path
from threading import RLock

from .competition_verification_reuse import VerificationReuse
from .protocol import canonical_json_bytes

_SEMANTICS = "umi-sealed-materialization-file-sha256/1"
_MAXIMUM_DIGESTS = 4096


def sealed_materialization_identity(info: os.stat_result) -> tuple[int, ...]:
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


class MaterializationDigestReuse:
    def __init__(self, directory: Path | None) -> None:
        self._directory = directory
        self._store: VerificationReuse | None = None
        self._digests: OrderedDict[str, str] = OrderedDict()
        self._pid = os.getpid()
        self._lock = RLock()

    def digest(self, path: Path, identity: tuple[int, ...], read: Callable[[], str]) -> str:
        if os.getpid() != self._pid:
            return read()
        # Integer strings preserve nanosecond identities outside canonical JSON's
        # interoperable numeric range. The digest semantics are release-stable.
        inode_key = [_SEMANTICS, "sealed-inode/1", [str(n) for n in identity]]
        key = hashlib.sha256(canonical_json_bytes(inode_key)).hexdigest()
        with self._lock:
            if key in self._digests:
                self._digests.move_to_end(key)
                return self._digests[key]
            if self._directory is not None and self._store is None:
                self._store = VerificationReuse(
                    self._directory, owner=(_SEMANTICS, str(self._directory))
                )
            if self._store is None:
                value = read()
            else:
                with self._store.exclusive():
                    receipt = self._store.load(key)
                    if receipt is None:
                        # Existing path-bound hash facts remain valid for the
                        # same exact sealed inode; migrate without reading bytes.
                        legacy = hashlib.sha256(
                            canonical_json_bytes(
                                [_SEMANTICS, str(path), [str(n) for n in identity]]
                            )
                        ).hexdigest()
                        receipt = self._store.load(legacy)
                    if receipt is None:
                        value = read()
                        self._store.remember(key, (), json.dumps(value))
                    else:
                        value = json.loads(receipt.result_json)
                        if (
                            receipt.dependencies
                            or not isinstance(value, str)
                            or re.fullmatch(r"[0-9a-f]{64}", value) is None
                        ):
                            raise ValueError("sealed file digest receipt has an invalid result")
                        if receipt.identity != key:
                            self._store.remember(key, (), json.dumps(value))
            self._digests[key] = value
            while len(self._digests) > _MAXIMUM_DIGESTS:
                self._digests.popitem(last=False)
            return value

    def clear(self) -> None:
        if os.getpid() == self._pid:
            with self._lock:
                self._digests.clear()
