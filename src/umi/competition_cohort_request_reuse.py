"""Bounded private publication receipts; never evidence for a remote reviewer.

Only a successful native export can produce a receipt. The exporter may reuse
that local result while the policy, verification interval, capacity and every
published file identity still agree. Receipts are disposable; cache failures
fall back to native replay and cannot turn missing work into an accepted result.
"""

import os
import re
import stat
from contextlib import suppress
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field

from .private_files import (
    ensure_private_directory,
    lock_private_file,
    publish_private_model,
    read_private_model,
)
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

MAX_RECEIPT_BYTES = 16 * 1024**2
MAX_CACHE_BYTES = 64 * 1024**2
MAX_CACHE_FILES = 2048
StampNumber = Annotated[str, Field(pattern=r"^-?[0-9]{1,30}$")]


class PublicationFileStamp(StrictProtocolModel):
    relative_path: Annotated[
        str,
        Field(
            pattern=(
                r"^(objects/[0-9a-f]{64}|(orders|terminals)/[0-9a-f]{64}/[0-9a-f]{64}"
                r"|partials/[0-9a-f]{64}/[0-9a-f]{64}/[0-9a-f]{64}/[0-9]{5})\.json$"
            )
        ),
    ]
    # Nanosecond timestamps need decimal strings to remain exact canonical JSON.
    stamp: Annotated[tuple[StampNumber, ...], Field(min_length=9, max_length=9)]


class PublicationVerificationReceipt(StrictProtocolModel):
    schema_: Literal["umi-private-request-publication/1"] = Field(alias="schema")
    terminal_sha256: Hex32
    policy_sha256: Hex32
    maximum_bytes: Annotated[int, Field(gt=0)]
    opened_at_block: Annotated[int, Field(ge=0)]
    completed_by_block: Annotated[int, Field(ge=0)]
    files: Annotated[tuple[PublicationFileStamp, ...], Field(min_length=1, max_length=65536)]


def _path(root: Path, terminal_sha: str, policy_sha: str) -> Path:
    if any(re.fullmatch(r"[0-9a-f]{64}", key) is None for key in (terminal_sha, policy_sha)):
        raise ValueError("invalid private publication identity")
    return root / ".publication-verification" / (policy_sha + "-" + terminal_sha + ".json")


def load_publication_verification(root, terminal_sha, policy_sha):
    """A missing or unusable optimization is a miss, not a production hold."""
    try:
        receipt = read_private_model(
            _path(root, terminal_sha, policy_sha),
            PublicationVerificationReceipt,
            maximum_bytes=MAX_RECEIPT_BYTES,
        )
        if receipt.terminal_sha256 == terminal_sha and receipt.policy_sha256 == policy_sha:
            return receipt
    except (OSError, ValueError):
        pass
    return None


def remember_publication_verification(root: Path, receipt: PublicationVerificationReceipt):
    """Replace only disposable cache metadata, after durable original publication.

    The private file publisher performs the atomic write and directory sync.
    Losing a cache record between removal and replacement merely causes replay.
    No signed object, index, journal or original execution evidence is removed.
    """
    with suppress(OSError, ValueError):
        raw = canonical_json_bytes(receipt)
        if len(raw) > MAX_RECEIPT_BYTES:
            return
        path = _path(root, receipt.terminal_sha256, receipt.policy_sha256)
        ensure_private_directory(path.parent)
        lock = lock_private_file(path.parent / ".cache.lock")
        try:
            count = used = 0
            for entry in path.parent.iterdir():
                info = entry.lstat()
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_nlink != 1
                    or info.st_uid != os.getuid()
                    or info.st_mode & 0o077
                ):
                    return
                if entry != path:
                    count += 1
                    used += info.st_size
                if count >= MAX_CACHE_FILES or used + len(raw) > MAX_CACHE_BYTES:
                    return
            path.unlink(missing_ok=True)
            publish_private_model(path, receipt, maximum_bytes=MAX_RECEIPT_BYTES)
        finally:
            os.close(lock)
