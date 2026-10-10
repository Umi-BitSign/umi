"""Resumable historical header walks rooted in an owned finalized descendant.

Durable header hints are untrusted bytes. After restart, every link is rehashed
from the owned anchor in bounded passes before a recovered identity is returned.
Neither hints nor progress cursors manufacture observer records or timestamps.
"""

from __future__ import annotations

import asyncio
import json
from collections import OrderedDict
from contextlib import closing
from dataclasses import dataclass

from .chain_evidence import FinalizedSnapshotRef
from .concurrency import run_owned_thread
from .finalized_ancestry import MAXIMUM_HEADER_BYTES, MAXIMUM_PATH_BYTES, encode_rpc_header
from .grandpa_finality import EVIDENCE_CLASS, _decode_header
from .validator_plans import VerifiedFinalizedBlock

MAXIMUM_VERIFIED_HEADER_BYTES = 8 * 1024**2


class HistoricalHeaderRecoveryPending(FileNotFoundError):
    """A bounded pass preserved progress; the next review should resume it."""


@dataclass(frozen=True)
class RecoveredHistoricalHeader:
    snapshot: FinalizedSnapshotRef
    encoded: str


class HistoricalHeaderRecovery:
    def __init__(self, connect, *, maximum_bytes=256 * 1024**2, batch_size=256):
        if type(maximum_bytes) is not int or maximum_bytes < 1:
            raise ValueError("historical header capacity must be positive")
        if type(batch_size) is not int or not 1 <= batch_size <= 4096:
            raise ValueError("historical header batch must be bounded")
        self.connect, self.maximum_bytes, self.batch_size = connect, maximum_bytes, batch_size
        self.progress = OrderedDict()
        self._progress_bytes = 0
        self._lock = asyncio.Lock()
        self._anchor = None
        self._verified = OrderedDict()
        self._verified_bytes = 0

    def _remember(self, height, encoded):
        old = self._verified.pop(height, None)
        if old is not None:
            self._verified_bytes -= len(old)
        self._verified[height] = encoded
        self._verified_bytes += len(encoded)
        limit = min(self.maximum_bytes, MAXIMUM_VERIFIED_HEADER_BYTES)
        while self._verified_bytes > limit:
            _, old = self._verified.popitem(last=False)
            self._verified_bytes -= len(old)

    def _forget_progress(self, key):
        old = self.progress.pop(key, None)
        if old is not None:
            self._progress_bytes -= len(old)

    def _remember_progress(self, key, encoded):
        self._forget_progress(key)
        self.progress[key] = encoded
        self._progress_bytes += len(encoded)
        while self._progress_bytes > min(self.maximum_bytes, MAXIMUM_VERIFIED_HEADER_BYTES):
            _, old = self.progress.popitem(last=False)
            self._progress_bytes -= len(old)

    def _open(self):
        db = self.connect()
        try:
            db.execute(
                "CREATE TABLE IF NOT EXISTS historical_header_hints "
                "(hash TEXT PRIMARY KEY, encoded TEXT NOT NULL)"
            )
            return db
        except BaseException:
            db.close()
            raise

    def _load(self, block_hash):
        with closing(self._open()) as db:
            row = db.execute(
                "SELECT substr(encoded,1,?) FROM historical_header_hints WHERE hash=?",
                (2 * MAXIMUM_HEADER_BYTES + 3, block_hash),
            ).fetchone()
        return None if row is None else row[0]

    def _save(self, block_hash, encoded):
        with closing(self._open()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                old = db.execute(
                    "SELECT substr(encoded,1,?) FROM historical_header_hints WHERE hash=?",
                    (2 * MAXIMUM_HEADER_BYTES + 3, block_hash),
                ).fetchone()
                if old is not None:
                    if old[0] != encoded:
                        raise ValueError("historical header hint changed")
                else:
                    used = db.execute(
                        "SELECT COALESCE(SUM(length(encoded)),0) FROM historical_header_hints"
                    ).fetchone()[0]
                    if used + len(encoded) > self.maximum_bytes:
                        raise HistoricalHeaderRecoveryPending(
                            "historical header cache needs capacity"
                        )
                    db.execute(
                        "INSERT INTO historical_header_hints VALUES (?,?)", (block_hash, encoded)
                    )
                db.commit()
            except BaseException:
                db.rollback()
                raise

    async def recover(self, anchor, target: FinalizedSnapshotRef, request):
        if not isinstance(target, FinalizedSnapshotRef):
            raise TypeError("historical recovery requires an exact target")
        async with self._lock:
            return await self._recover(anchor, target, request)

    async def recover_height(self, anchor, height: int, request):
        """Derive the historical identity from the owned anchor, never RPC height claims."""
        if type(height) is not int:
            raise TypeError("historical recovery requires an integer height")
        async with self._lock:
            return await self._recover(anchor, height, request)

    async def _recover(self, anchor, target, request):
        if not isinstance(anchor, VerifiedFinalizedBlock):
            raise TypeError("historical recovery requires an owned anchor")
        height = target.block_number if isinstance(target, FinalizedSnapshotRef) else target
        if not 1 <= height < anchor.height:
            raise ValueError("historical recovery target is not before its anchor")
        record = json.loads(anchor.finality_evidence)
        if record.get("evidence_class") != EVIDENCE_CLASS:
            raise ValueError("historical recovery needs an original observer anchor")
        encoded = record["block"]["scale_header"]
        first = _decode_header(encoded, maximum_bytes=MAXIMUM_HEADER_BYTES)
        if (first["number"], first["hash"], first["state_root"]) != (
            anchor.height,
            anchor.block_hash,
            anchor.state_root,
        ):
            raise ValueError("historical recovery anchor identity differs")
        identity = (anchor.finality_evidence_sha256, encoded)
        if identity != self._anchor:
            self._anchor = identity
            self._verified.clear()
            self._verified_bytes = 0
        # Each cursor was checked from its own exact anchor. Switching between
        # pending requests must not erase another request's bounded progress.
        key = (anchor.finality_evidence_sha256, height)
        # Only this process's completed ancestry checks are reusable. Durable
        # hints are still rehashed from the owned anchor after every restart.
        cached = self._verified.get(height)
        if cached is not None:
            self._verified.move_to_end(height)
        encoded = cached or self.progress.get(key, encoded)
        current = _decode_header(encoded, maximum_bytes=MAXIMUM_HEADER_BYTES)
        if cached is not None and current["number"] != height:
            raise ValueError("historical registration differs from finalized ancestry")
        # Another request may already have proved a closer descendant under
        # this exact anchor. Continue from that link instead of repeating the
        # entire walk when, for example, the next target is its parent.
        nearest = min(
            (number for number in self._verified if height < number < current["number"]),
            default=None,
        )
        if nearest is not None:
            encoded = self._verified[nearest]
            current = _decode_header(encoded, maximum_bytes=MAXIMUM_HEADER_BYTES)
            if current["number"] != nearest:
                raise ValueError("historical registration differs from finalized ancestry")
        used = 0
        for _ in range(self.batch_size):
            if current["number"] == height:
                break
            block_hash = current["parent_hash"]
            next_encoded = await run_owned_thread(self._load, block_hash)
            downloaded = next_encoded is None
            if downloaded:
                next_encoded = encode_rpc_header(await request("chain_getHeader", (block_hash,)))
            next_header = _decode_header(next_encoded, maximum_bytes=MAXIMUM_HEADER_BYTES)
            if (next_header["number"], next_header["hash"]) != (current["number"] - 1, block_hash):
                raise ValueError("historical header is not the committed parent")
            if downloaded:
                await run_owned_thread(self._save, block_hash, next_encoded)
            # Advance only after the exact hint is durable. Cancellation during
            # persistence leaves the old cursor; retry rechecks the stored hint.
            self._remember(next_header["number"], next_encoded)
            self._remember_progress(key, next_encoded)
            encoded = next_encoded
            current = next_header
            used += (len(encoded) - 2) // 2
            if used >= MAXIMUM_PATH_BYTES:
                break
        if current["number"] != height:
            raise HistoricalHeaderRecoveryPending("historical header recovery in progress")
        recovered = FinalizedSnapshotRef(
            current["number"], current["hash"], current["parent_hash"], current["state_root"]
        )
        if isinstance(target, FinalizedSnapshotRef) and recovered != target:
            raise ValueError("historical registration differs from finalized ancestry")
        self._forget_progress(key)
        return RecoveredHistoricalHeader(recovered, encoded)
