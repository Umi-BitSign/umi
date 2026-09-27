"""Authenticate a fresh marker and the following legacy mortality interval.

This reader does not create markers, sign, submit, modify journals, or authorize
recovery. Its caller must establish that the marker was generated after all old
writers stopped, and that those writers used the audited eight-block mortality.
An operator-supplied marker or height alone establishes neither fact.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
from dataclasses import dataclass

from ..chain_evidence import FinalizedSnapshotRef
from ..concurrency import await_owned_task
from .policy import _require
from .receipts import BridgeReceiptReader, _Header

MARKER_DOMAIN = b"umi-legacy-bridge-drain-v1\0"
LEGACY_MORTALITY_BLOCKS = 8
_BLOCK_HASH = re.compile(r"0x[0-9a-f]{64}")


@dataclass(frozen=True)
class VerifiedLegacyDrain:
    """Inclusion and elapsed blocks only; not a recovery authorization."""

    marker_sha256: str
    included: FinalizedSnapshotRef
    extrinsic_indices: tuple[int, ...]
    owned_head: FinalizedSnapshotRef


class LegacyDrainReader:
    """Keep one bounded hash walk across timeouts and cancellation.

    The inclusion reference is an untrusted locator. Both it and the body are
    authenticated from the receipt reader's owned finality source. No RPC
    latest-head, transaction status, or timestamp can replace that source.
    """

    def __init__(self, receipts: BridgeReceiptReader):
        self._receipts = receipts
        self._lock = asyncio.Lock()
        self._identity: tuple[bytes, int, str] | None = None
        self._anchor: _Header | None = None
        self._cursor: _Header | None = None
        self._result: VerifiedLegacyDrain | None = None

    @property
    def progress(self) -> tuple:
        return self._identity, self._anchor, self._cursor, self._result is not None

    async def read(
        self, *, marker: bytes, block_number: int, block_hash: str
    ) -> VerifiedLegacyDrain:
        _require(
            type(marker) is bytes
            and len(marker) == len(MARKER_DOMAIN) + 32
            and marker.startswith(MARKER_DOMAIN),
            "legacy_drain_marker_invalid",
        )
        _require(
            type(block_number) is int
            and 0 < block_number <= 2**53 - 1 - LEGACY_MORTALITY_BLOCKS
            and type(block_hash) is str
            and _BLOCK_HASH.fullmatch(block_hash) is not None,
            "legacy_drain_locator_invalid",
        )
        task = asyncio.create_task(
            asyncio.wait_for(self._read(marker, block_number, block_hash), self._receipts._timeout)
        )
        return await await_owned_task(task, on_cancel=task.cancel)

    async def _read(self, marker, block_number, block_hash):
        async with self._lock:
            identity = marker, block_number, block_hash
            if identity != self._identity:
                self._identity = identity
                self._anchor = self._cursor = self._result = None
            if self._result is not None:
                return self._result
            if self._cursor is None:
                owned = await self._receipts._finality.read_finalized_identity()
                _require(
                    type(owned.number) is int
                    and owned.number >= block_number + LEGACY_MORTALITY_BLOCKS,
                    "legacy_drain_not_finalized",
                )
                anchor = await self._receipts._header(owned.block_hash, owned.number)
                self._anchor = self._cursor = anchor
            while self._cursor.snapshot.block_number > block_number:
                current = self._cursor.snapshot
                parent = await self._receipts._header(current.parent_hash, current.block_number - 1)
                self._cursor = parent
            _require(
                self._cursor.snapshot.block_hash == block_hash,
                "legacy_drain_inclusion_ancestry_mismatch",
            )
            body = await self._receipts._body(self._cursor)
            # A single extrinsic must contain the complete random challenge.
            # Joining body entries could manufacture a nonexistent marker.
            indices = tuple(index for index, raw in enumerate(body) if marker in raw)
            _require(bool(indices), "legacy_drain_marker_not_included")
            self._result = VerifiedLegacyDrain(
                hashlib.sha256(marker).hexdigest(),
                self._cursor.snapshot,
                indices,
                self._anchor.snapshot,
            )
            return self._result
