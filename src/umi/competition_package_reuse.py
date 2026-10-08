"""Reuse immutable package verification within one service and across restarts.

No journal receipt, authorization, finality observation or transaction result is
retained here. Callers bind lookup to exact sealed file identities and policy,
release and capacity bounds. Unchanged files need no repeated content verification.
An optional private receipt retains completed verification across restarts.
It binds the same exact metadata key; changed objects need fresh verification.
"""

from __future__ import annotations

import hashlib
import os
from contextlib import contextmanager
from contextvars import ContextVar
from copy import deepcopy
from pathlib import Path
from threading import RLock
from typing import TYPE_CHECKING, Literal

from pydantic import Field

from .private_files import ensure_private_directory, publish_private_model, read_private_model
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

if TYPE_CHECKING:
    from .competition_package import VerifiedCompetitionPackage


class PackageVerificationReceipt(StrictProtocolModel):
    schema_: Literal["umi-private-package-verification/1"] = Field(alias="schema")
    metadata_sha256: Hex32
    manifest_sha256: Hex32


def _metadata_digest(key: tuple) -> str:
    def stable(value):
        if isinstance(value, tuple):
            return [stable(item) for item in value]
        if isinstance(value, bytes):
            return {"bytes": value.hex()}
        if type(value) is int:
            return {"integer": str(value)}
        if isinstance(value, str):
            return value
        raise TypeError("unsupported package verification identity")

    return hashlib.sha256(
        b"umi-private-package-verification-v1\0" + canonical_json_bytes(stable(key))
    ).hexdigest()


class PackageVerificationReuse:
    """Keep one private verified object; never expose it to callers for mutation."""

    def __init__(self, maximum_input_bytes: int = 512 * 1024**2, *, directory: Path | None = None):
        if type(maximum_input_bytes) is not int or maximum_input_bytes < 1:
            raise ValueError("package reuse requires a positive byte capacity")
        self.maximum_input_bytes = maximum_input_bytes
        self.directory = directory
        if directory is not None:
            ensure_private_directory(directory)
        self._pid = os.getpid()
        self._lock = RLock()
        self._key: tuple | None = None
        self._value: VerifiedCompetitionPackage | None = None

    def lookup(self, key: tuple) -> VerifiedCompetitionPackage | None:
        # A forked process must start with its own verification; do not take a
        # potentially inherited lock before rejecting that process identity.
        if os.getpid() != self._pid:
            return None
        with self._lock:
            return deepcopy(self._value) if key == self._key else None

    def remember(self, key: tuple, value: VerifiedCompetitionPackage, input_bytes: int) -> None:
        if os.getpid() != self._pid:
            return
        with self._lock:
            self._key, self._value = None, None
            if self.directory is not None:
                identity = _metadata_digest(key)
                publish_private_model(
                    self.directory / (identity + ".json"),
                    PackageVerificationReceipt(
                        schema="umi-private-package-verification/1",
                        metadata_sha256=identity,
                        manifest_sha256=value.manifest_sha256,
                    ),
                    maximum_bytes=1024,
                )
            if input_bytes <= self.maximum_input_bytes:
                private = deepcopy(value)
                self._key, self._value = key, private

    def verified_manifest(self, key: tuple) -> str | None:
        """A receipt proves immutable content only; it never authorizes a write."""
        if os.getpid() != self._pid or self.directory is None:
            return None
        identity = _metadata_digest(key)
        try:
            receipt = read_private_model(
                self.directory / (identity + ".json"),
                PackageVerificationReceipt,
                maximum_bytes=1024,
            )
        except FileNotFoundError:
            return None
        if receipt.metadata_sha256 != identity:
            raise ValueError("package verification receipt identity differs")
        return receipt.manifest_sha256

    def clear(self) -> None:
        if os.getpid() != self._pid:
            return
        with self._lock:
            self._key, self._value = None, None


_REUSE: ContextVar[PackageVerificationReuse | None] = ContextVar(
    "competition_package_verification_reuse", default=None
)


def current_package_reuse() -> PackageVerificationReuse | None:
    return _REUSE.get()


@contextmanager
def package_verification_session(
    *, maximum_input_bytes: int = 512 * 1024**2, directory: Path | None = None
):
    """Own parsed objects for this scope; optional private verdicts survive exit."""
    reuse = PackageVerificationReuse(maximum_input_bytes, directory=directory)
    token = _REUSE.set(reuse)
    try:
        yield reuse
    finally:
        _REUSE.reset(token)
        reuse.clear()
