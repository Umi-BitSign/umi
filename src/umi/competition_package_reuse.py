"""Reuse immutable package verification within one service and across restarts.

No journal receipt, authorization, finality observation or transaction result is
retained here. Callers bind lookup to exact sealed file identities and policy,
release and capacity bounds. Unchanged files need no repeated content verification.
An optional private receipt retains completed verification across restarts.
It binds the same exact metadata key; changed objects need fresh verification.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import logging
import os
import tempfile
from collections import OrderedDict
from contextlib import contextmanager
from contextvars import ContextVar
from copy import deepcopy
from pathlib import Path
from threading import RLock
from typing import TYPE_CHECKING, Literal

from pydantic import Field

from .competition_materialization_reuse import MaterializationDigestReuse
from .competition_verification_reuse import metadata_completion, remember_metadata_completion
from .competition_verification_rules import runtime_identity
from .competition_work_progress import WorkProgress
from .private_files import (
    ensure_private_directory,
    lock_private_file,
    publish_private_model,
    read_private_model,
)
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

if TYPE_CHECKING:
    from .competition_package import VerifiedCompetitionPackage

# Legacy path receipts predate an explicit semantics field. Their only qualified
# interpretation is this original ABI; never derive this value from the current
# ABI or let legacy metadata bypass a future semantic invalidation.
_LEGACY_PACKAGE_RUNTIME = hashlib.sha256(b"umi-native-request-verification/1").hexdigest()


class PackageVerificationReceipt(StrictProtocolModel):
    schema_: Literal["umi-private-package-verification/1"] = Field(alias="schema")
    metadata_sha256: Hex32
    manifest_sha256: Hex32


class PackageVerificationRepairRequired(ValueError):
    """Completed private verification metadata needs explicit owner repair."""


def _sealed_identity(key: tuple) -> tuple:
    # The package directory itself is unchanged when its parent stage is moved
    # or exposed through the fixed read-only mount. Path spelling is not content
    # authority; the loader still verifies every path component and sealed inode.
    if len(key) != 7:
        raise ValueError("complete package verification identity required")
    return ("sealed-package-inodes/1", runtime_identity(), *key[:4], *key[5:])


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

    def __init__(
        self,
        maximum_input_bytes: int = 512 * 1024**2,
        *,
        directory: Path | None = None,
        repair_reason: str | None = None,
    ):
        if type(maximum_input_bytes) is not int or maximum_input_bytes < 1:
            raise ValueError("package reuse requires a positive byte capacity")
        self.maximum_input_bytes = maximum_input_bytes
        self.directory = directory
        if repair_reason is not None and (not repair_reason.strip() or directory is None):
            raise ValueError("package verification repair requires a directory and reason")
        self.repair_reason = repair_reason
        self._damaged: set[Path] = set()
        self._verdicts: OrderedDict[tuple, str] = OrderedDict()
        if directory is not None:
            ensure_private_directory(directory)
        self._pid = os.getpid()
        self._lock = RLock()
        self._key: tuple | None = None
        self._value: VerifiedCompetitionPackage | None = None
        self.materialization = MaterializationDigestReuse(
            None if directory is None else directory / "sealed-file-digests"
        )

    def lookup(
        self, key: tuple, *, verified_manifest_sha256: str | None = None
    ) -> VerifiedCompetitionPackage | None:
        # A forked process must start with its own verification; do not take a
        # potentially inherited lock before rejecting that process identity.
        if os.getpid() != self._pid:
            return None
        with self._lock:
            if self._key is None or self._value is None:
                return None
            same_copy = _sealed_identity(key) == _sealed_identity(self._key)
            # A different stored copy must already have its own durable verdict
            # for its current exact file identities. Only the parsed content is
            # shared; expected package/policy/release and caller limits must match.
            verified_copy = (
                verified_manifest_sha256 is not None
                and verified_manifest_sha256 == self._value.manifest_sha256
                and len(key) == len(self._key) == 7
                and key[:4] == self._key[:4]
            )
            return deepcopy(self._value) if same_copy or verified_copy else None

    def remember(self, key: tuple, value: VerifiedCompetitionPackage, input_bytes: int) -> None:
        if os.getpid() != self._pid:
            return
        with self._lock:
            self._key, self._value = None, None
            self._remember_manifest(key, value.manifest_sha256)
            if input_bytes <= self.maximum_input_bytes:
                private = deepcopy(value)
                self._key, self._value = key, private

    def verified_manifest(self, key: tuple) -> str | None:
        """A receipt proves immutable content only; it never authorizes a write."""
        if os.getpid() != self._pid:
            return None
        sealed = _sealed_identity(key)
        if self.directory is None:
            return self._verdicts.get(sealed)
        identity = _metadata_digest(sealed)
        path = self.directory / (identity + ".json")
        found = self._read_receipt(path, identity)
        if found is not None or path in self._damaged:
            return found
        if sealed[1] != _LEGACY_PACKAGE_RUNTIME:
            return None
        # Compatibility with already-deployed path-bound receipts. A successful
        # exact legacy read is sufficient to publish the same inode-bound fact.
        legacy = _metadata_digest(key)
        found = self._read_receipt(self.directory / (legacy + ".json"), legacy)
        if found is not None:
            self._remember_manifest(key, found)
        return found

    def _read_receipt(self, path: Path, identity: str) -> str | None:
        try:
            receipt = read_private_model(
                path,
                PackageVerificationReceipt,
                maximum_bytes=1024,
            )
            if receipt.metadata_sha256 != identity:
                raise ValueError("package verification receipt identity differs")
        except (OSError, ValueError) as error:
            if isinstance(error, FileNotFoundError) and not metadata_completion(path).exists():
                return None
            logging.getLogger("umi.competition.progress").warning(
                json.dumps(
                    {
                        "schema": "umi-package-verification-reuse/1",
                        "stage": "package_verification_metadata",
                        "state": "repair_required",
                        "identity": identity,
                        "completed": 0,
                        "total": 1,
                        "percent": 0,
                        "elapsed_seconds": 0,
                        "eta_seconds": None,
                        "eta_basis": "explicit_native_repair_required",
                        "stalled": True,
                        "retrying": False,
                        "certification_authority": False,
                    },
                    separators=(",", ":"),
                )
            )
            if self.repair_reason is None:
                raise PackageVerificationRepairRequired(
                    "completed package verification metadata requires explicit repair: " + identity
                ) from error
            self._damaged.add(path)
            return None
        remember_metadata_completion(path)
        return receipt.manifest_sha256

    def _remember_manifest(self, key: tuple, manifest_sha256: str) -> None:
        """Called only after native replay or the authenticated copier's checks."""
        if os.getpid() != self._pid:
            raise ValueError("package verification owner process changed")
        sealed = _sealed_identity(key)
        identity = _metadata_digest(sealed)
        value = PackageVerificationReceipt(
            schema="umi-private-package-verification/1",
            metadata_sha256=identity,
            manifest_sha256=manifest_sha256,
        )
        if self.directory is not None:
            path = self.directory / (identity + ".json")
            if path in self._damaged:
                self._repair_receipt(path, value)
            else:
                publish_private_model(path, value, maximum_bytes=1024)
            remember_metadata_completion(path)
            # Repair an explicitly selected legacy record too, retaining its ABI.
            legacy = self.directory / (_metadata_digest(key) + ".json")
            if legacy in self._damaged:
                self._repair_receipt(
                    legacy, value.model_copy(update={"metadata_sha256": _metadata_digest(key)})
                )
        self._verdicts[sealed] = manifest_sha256
        self._verdicts.move_to_end(sealed)
        while len(self._verdicts) > 64:
            self._verdicts.popitem(last=False)

    def _repair_receipt(self, path, value):
        # Only explicit repair after complete native verification reaches here.
        # Replace derived metadata atomically; signed package bytes never change.
        with WorkProgress("package_verification_metadata_repair", 1, unit="receipts") as progress:
            lock = lock_private_file(path.parent / ".publish.lock")
            pending = None
            try:
                fd, pending = tempfile.mkstemp(prefix=".package-repair-", dir=path.parent)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(canonical_json_bytes(value))
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(pending, path)
                directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
                remember_metadata_completion(path)
                self._damaged.remove(path)
                progress.advance()
            finally:
                if pending is not None:
                    Path(pending).unlink(missing_ok=True)
                try:
                    fcntl.flock(lock, fcntl.LOCK_UN)
                finally:
                    os.close(lock)

    def clear(self) -> None:
        if os.getpid() != self._pid:
            return
        with self._lock:
            self._key, self._value = None, None
            self._verdicts.clear()
            self.materialization.clear()


_REUSE: ContextVar[PackageVerificationReuse | None] = ContextVar(
    "competition_package_verification_reuse", default=None
)


def current_package_reuse() -> PackageVerificationReuse | None:
    return _REUSE.get()


@contextmanager
def package_verification_session(
    *,
    maximum_input_bytes: int = 512 * 1024**2,
    directory: Path | None = None,
    repair_reason: str | None = None,
):
    """Own parsed objects for this scope; optional private verdicts survive exit."""
    reuse = PackageVerificationReuse(
        maximum_input_bytes, directory=directory, repair_reason=repair_reason
    )
    token = _REUSE.set(reuse)
    try:
        yield reuse
    finally:
        _REUSE.reset(token)
        reuse.clear()
