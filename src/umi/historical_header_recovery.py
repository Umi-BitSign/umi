"""Resumable historical header walks rooted in an owned finalized descendant.

Durable header hints are untrusted bytes. After restart, every link is rehashed
from the owned anchor in bounded passes before a recovered identity is returned.
Neither hints nor progress cursors manufacture observer records or timestamps.
"""

from __future__ import annotations

import asyncio
import json
from collections import OrderedDict
from contextlib import closing, suppress
from dataclasses import dataclass

from .chain_evidence import FinalizedSnapshotRef
from .concurrency import run_owned_thread
from .finalized_ancestry import MAXIMUM_HEADER_BYTES, MAXIMUM_PATH_BYTES, encode_rpc_header
from .grandpa_finality import EVIDENCE_CLASS, _decode_header
from .historical_header_progress import HeaderRecoveryTelemetry
from .validator_plans import VerifiedFinalizedBlock

# A link awaits its read/persistence individually, so the bounded pass can use
# the supported maximum without delaying cooperative cancellation. Small passes
# amplify caller ownership and checkpoint validation during long retained walks.
DEFAULT_HISTORICAL_HEADER_BATCH_SIZE = 4096


class HistoricalHeaderRecoveryPending(FileNotFoundError):
    """Recovery is unfinished; preserve its target and retry after backoff."""


class HistoricalHeaderRecoveryProgress(HistoricalHeaderRecoveryPending):
    """A bounded pass verified and retained links; the same target can continue."""


@dataclass(frozen=True)
class RecoveredHistoricalHeader:
    snapshot: FinalizedSnapshotRef
    encoded: str


class HistoricalHeaderRecovery:
    def __init__(
        self,
        connect,
        *,
        maximum_bytes=256 * 1024**2,
        batch_size=DEFAULT_HISTORICAL_HEADER_BATCH_SIZE,
    ):
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
        self.telemetry = HeaderRecoveryTelemetry()

    def _remember(self, height, encoded):
        old = self._verified.pop(height, None)
        if old is not None:
            self._verified_bytes -= len(old)
        self._verified[height] = encoded
        self._verified_bytes += len(encoded)
        # Keep the verified working set under the selected header budget.
        # A separate smaller cap makes ascending replay repeatedly rewalk a
        # cohort whose durable hints already fit that budget.
        limit = self.maximum_bytes
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
        while self._progress_bytes > self.maximum_bytes:
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

    async def recover(self, anchor, target: FinalizedSnapshotRef, request, *, target_header=None):
        """Use an optional exact target header only as an untrusted final-link hint."""
        if not isinstance(target, FinalizedSnapshotRef):
            raise TypeError("historical recovery requires an exact target")
        async with self._lock:
            return await self._observed_recover(
                anchor, target, request, target_header=target_header
            )

    async def recover_height(self, anchor, height: int, request):
        """Derive the historical identity from the owned anchor, never RPC height claims."""
        if type(height) is not int:
            raise TypeError("historical recovery requires an integer height")
        async with self._lock:
            return await self._observed_recover(anchor, height, request)

    async def _observed_recover(self, anchor, target, request, *, target_header=None):
        with self.telemetry.monitor():
            try:
                result = await self._recover(anchor, target, request, target_header=target_header)
            except BaseException as error:
                self.telemetry.finish(
                    "running"
                    if isinstance(error, HistoricalHeaderRecoveryProgress)
                    else "stopped"
                    if isinstance(error, asyncio.CancelledError)
                    else "repair_required"
                    if isinstance(error, ValueError)
                    else "retrying",
                    error_type=type(error).__name__,
                )
                # Diagnostic metadata is not an ancestry or verification capability.
                if self.telemetry.prepared:
                    with suppress(Exception):
                        error.ancestry_progress = dict(self.telemetry.latest)
                raise
            self.telemetry.finish("completed")
            return result

    async def _recover(self, anchor, target, request, *, target_header=None):
        if not isinstance(anchor, VerifiedFinalizedBlock):
            raise TypeError("historical recovery requires an owned anchor")
        height = target.block_number if isinstance(target, FinalizedSnapshotRef) else target
        if not 1 <= height < anchor.height:
            raise ValueError("historical recovery target is not before its anchor")
        if target_header is not None:
            hint = _decode_header(target_header, maximum_bytes=MAXIMUM_HEADER_BYTES)
            if (
                FinalizedSnapshotRef(
                    hint["number"], hint["hash"], hint["parent_hash"], hint["state_root"]
                )
                != target
            ):
                raise ValueError("historical header hint differs from the exact target")
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
        if cached is None:
            nearest = min(
                (number for number in self._verified if height < number < current["number"]),
                default=None,
            )
            if nearest is not None:
                encoded = self._verified[nearest]
                current = _decode_header(encoded, maximum_bytes=MAXIMUM_HEADER_BYTES)
                if current["number"] != nearest:
                    raise ValueError("historical registration differs from finalized ancestry")
        self.telemetry.begin(
            anchor.finality_evidence_sha256, anchor.height, height, current["number"]
        )
        used = 0
        for _ in range(self.batch_size):
            if current["number"] == height:
                break
            block_hash = current["parent_hash"]
            self.telemetry.phase("load_retained_hint")
            next_encoded = await run_owned_thread(self._load, block_hash)
            missing = next_encoded is None
            source = "retained"
            if missing:
                # Presence in an archive establishes no ancestry. Supply the
                # target bytes only when the walk reaches its committed edge;
                # the same hash/height checks below authenticate that link.
                # Existing durable hints must still be checked, including
                # corruption; an archive must not silently replace them.
                supplied = target_header is not None and current["number"] - 1 == height
                source = "supplied" if supplied else "rpc"
                self.telemetry.phase("supplied_target_hint" if supplied else "fetch_archive_header")
                next_encoded = (
                    target_header
                    if supplied
                    else encode_rpc_header(await request("chain_getHeader", (block_hash,)))
                )
            next_header = _decode_header(next_encoded, maximum_bytes=MAXIMUM_HEADER_BYTES)
            if (next_header["number"], next_header["hash"]) != (current["number"] - 1, block_hash):
                raise ValueError("historical header is not the committed parent")
            if missing:
                self.telemetry.phase("persist_verified_hint")
                await run_owned_thread(self._save, block_hash, next_encoded)
            # Advance only after the exact hint is durable. Cancellation during
            # persistence leaves the old cursor; retry rechecks the stored hint.
            self._remember(next_header["number"], next_encoded)
            self._remember_progress(key, next_encoded)
            encoded = next_encoded
            current = next_header
            self.telemetry.advance(current["number"], source)
            used += (len(encoded) - 2) // 2
            if used >= MAXIMUM_PATH_BYTES:
                break
        if current["number"] != height:
            raise HistoricalHeaderRecoveryProgress("historical header recovery in progress")
        recovered = FinalizedSnapshotRef(
            current["number"], current["hash"], current["parent_hash"], current["state_root"]
        )
        if isinstance(target, FinalizedSnapshotRef) and recovered != target:
            raise ValueError("historical registration differs from finalized ancestry")
        self._forget_progress(key)
        return RecoveredHistoricalHeader(recovered, encoded)
