"""Replay retained reward-control proofs against owned historical finality.

These observations establish past commitments. They cannot replace a current
control read, recipient proof or transaction preflight.
"""

from __future__ import annotations

import asyncio
import fcntl
import hashlib
import json
import os
import sqlite3
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .chain_evidence import FinalizedSnapshotRef
from .competition_chain import CompetitionChainConfig, _hotkey, _uint
from .competition_chain_state import _cache_usage
from .competition_reward_checkpoint_tip import OwnedCheckpointTip, validate_checkpoint_tip
from .competition_reward_control import (
    FinalizedRewardControlProvider,
    _control_evidence,
    _control_value,
)
from .competition_reward_control_evidence import (
    MAX_CONTROL_ARCHIVE_BYTES as MAX_CONTROL_ARCHIVE_BYTES,
)
from .competition_reward_control_evidence import (
    MAX_CONTROL_METADATA_BYTES as MAX_CONTROL_METADATA_BYTES,
)
from .competition_reward_control_evidence import (
    _Archive as _Archive,
)
from .competition_reward_history_verifier import HistoryProofTools, verify_slot_archive
from .competition_transport_verification import TransferProgress
from .competition_worker import (
    CompetitionReplayWorker,
    _canonical_absolute_path,
    _open_directory_without_links,
    _open_private_regular_file,
    _prepare_private_directory,
    _verify_private_directory,
    _verify_sqlite_family,
)
from .concurrency import run_owned_thread
from .encoding import account_id32
from .finalized_ancestry import MAXIMUM_HEADER_BYTES, encode_rpc_header
from .grandpa_finality import _decode_header
from .historical_header_recovery import (
    DEFAULT_HISTORICAL_HEADER_BATCH_SIZE,
    HistoricalHeaderRecovery,
    HistoricalHeaderRecoveryPending,
)
from .open_competition import digest
from .sqlite_contention import is_sqlite_full
from .validator_chain import PinnedRuntimeContext, StorageReadSpec, ValidatorChainError
from .validator_plans import VerifiedFinalizedBlock

_ISSUER = object()


@dataclass(frozen=True, slots=True)
class _OwnedControlRuntime:
    owner: HistoricalRewardControlProvider
    runtime: PinnedRuntimeContext
    evidence: bytes = field(repr=False)
    metadata: bytes = field(repr=False)
    binding: str
    encoded_header: str
    issuer: object = field(repr=False)


@dataclass(frozen=True, slots=True)
class OwnedHistoricalRewardControl:
    snapshot: FinalizedSnapshotRef
    control_hotkey: str
    control_sha256: str | None
    committed_at_block: int | None
    evidence_sha256: str
    metadata_sha256: str
    chain_config_sha256: str
    timestamp_ms: int
    evidence: bytes = field(repr=False)
    metadata: bytes = field(repr=False)
    _issuer: object = field(default=None, repr=False, compare=False)
    _binding: str = field(default="", repr=False, compare=False)
    _runtime_context: _OwnedControlRuntime | None = field(default=None, repr=False, compare=False)


def _binding(value: OwnedHistoricalRewardControl) -> str:
    return digest(
        {
            "snapshot": {
                "block": value.snapshot.block_number,
                "hash": value.snapshot.block_hash,
                "parent": value.snapshot.parent_hash,
                "root": value.snapshot.state_root,
            },
            "hotkey": value.control_hotkey,
            "control": value.control_sha256,
            "committed": value.committed_at_block,
            "evidence": value.evidence_sha256,
            "metadata": value.metadata_sha256,
            "config": value.chain_config_sha256,
            "timestamp_ms": value.timestamp_ms,
        }
    )


def validate_historical_reward_control(
    observation: OwnedHistoricalRewardControl,
    *,
    expected_control_hotkey: str,
    expected_chain_config_sha256: str,
) -> None:
    if (
        type(observation) is not OwnedHistoricalRewardControl
        or observation._issuer is not _ISSUER
        or observation._binding != _binding(observation)
        or type(observation.evidence) is not bytes
        or type(observation.metadata) is not bytes
        or account_id32(observation.control_hotkey) != account_id32(expected_control_hotkey)
        or observation.chain_config_sha256 != expected_chain_config_sha256
        or type(observation.timestamp_ms) is not int
        or observation.timestamp_ms <= 0
    ):
        raise ValueError("historical reward control lacks the selected owned proof")
    context = observation._runtime_context
    if context is not None:
        if (
            type(context) is not _OwnedControlRuntime
            or context.issuer is not _ISSUER
            or not isinstance(context.owner, HistoricalRewardControlProvider)
            or not isinstance(context.runtime, PinnedRuntimeContext)
            or context.binding != observation._binding
            or context.evidence is not observation.evidence
            or context.metadata is not observation.metadata
            or context.runtime.snapshot != observation.snapshot
            or context.runtime.metadata_sha256 != observation.metadata_sha256
        ):
            raise ValueError("historical reward control runtime context changed")
    elif (
        hashlib.sha256(observation.evidence).hexdigest() != observation.evidence_sha256
        or hashlib.sha256(observation.metadata).hexdigest() != observation.metadata_sha256
    ):
        # Older in-process observations lack the private reuse capability.
        # Wire archives still take the ordinary native verification path.
        raise ValueError("historical reward control lacks the selected owned proof")


class HistoricalRewardControlProvider(FinalizedRewardControlProvider):
    """Keep historical hints in a separately owned, disjoint private directory.

    The database ceiling includes SQLite pages, indexes and free pages; the
    payload ceiling separately limits encoded headers. Provision additional
    space for transient DELETE rollback journals, including SQLite framing:
    journal bytes are not included in the database ceiling.
    """

    def __init__(
        self,
        *args: Any,
        historical_header_directory: Path,
        historical_header_maximum_bytes: int = 256 * 1024**2,
        historical_header_database_maximum_bytes: int = 512 * 1024**2,
        historical_header_batch_size: int = DEFAULT_HISTORICAL_HEADER_BATCH_SIZE,
        **kwargs: Any,
    ) -> None:
        if (
            type(historical_header_database_maximum_bytes) is not int
            or historical_header_database_maximum_bytes < 1
        ):
            raise ValueError("historical header database capacity must be positive")
        self._hint_directory = _canonical_absolute_path(
            historical_header_directory, "historical header directory"
        )
        self._hint_path = self._hint_directory / "historical-headers.sqlite3"
        self._hint_database_maximum_bytes = historical_header_database_maximum_bytes
        self._hint_lock: int | None = None
        self._checkpoint_hint_window = None
        self._historical_headers = HistoricalHeaderRecovery(
            self._hint_connect,
            maximum_bytes=historical_header_maximum_bytes,
            batch_size=historical_header_batch_size,
        )
        try:
            super().__init__(*args, **kwargs)
        except BaseException:
            self._release_hint_lock()
            raise

    def _cache_directory(self, config: CompetitionChainConfig) -> Path:
        root = _canonical_absolute_path(
            Path(self.resources.state_directory), "weight finality state"
        )
        if self._hint_directory.is_relative_to(root) or root.is_relative_to(self._hint_directory):
            raise ValueError("historical header directory must be disjoint from current cache")
        _prepare_private_directory(self._hint_directory, "historical header directory")
        directory = _open_directory_without_links(self._hint_directory)
        try:
            CompetitionReplayWorker._prepare_state_file(directory, "owner.lock")
            self._hint_lock = _open_private_regular_file(
                self._hint_directory / "owner.lock", "historical header owner lock"
            )
            fcntl.flock(self._hint_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            CompetitionReplayWorker._prepare_state_file(directory, self._hint_path.name)
            self._hint_connect().close()
        finally:
            os.close(directory)
        return super()._cache_directory(config)

    def _hint_connect(self) -> sqlite3.Connection:
        if self._hint_lock is None:
            raise ValueError("historical header owner is closed")
        _verify_private_directory(self._hint_directory, "historical header directory")
        _verify_sqlite_family(self._hint_path, "historical header database")
        db = sqlite3.connect(self._hint_path, timeout=2, isolation_level=None)
        try:
            # Install the physical bound before recovery can create its schema
            # or write a hint. SQLite's page limit is connection-local.
            page_size = db.execute("PRAGMA page_size").fetchone()[0]
            page_count = db.execute("PRAGMA page_count").fetchone()[0]
            pages = self._hint_database_maximum_bytes // page_size
            if pages < 1 or page_count * page_size > self._hint_database_maximum_bytes:
                raise ValueError("historical header database exceeds its physical byte ceiling")
            if db.execute(f"PRAGMA max_page_count={pages}").fetchone()[0] != pages:
                raise ValueError("historical header database physical ceiling could not be set")
            if db.execute("PRAGMA journal_mode=DELETE").fetchone()[0] != "delete":
                raise ValueError("historical header database requires DELETE journal mode")
            db.execute("PRAGMA synchronous=FULL")
            if db.execute("PRAGMA synchronous").fetchone()[0] != 2:
                raise ValueError("historical header database requires FULL synchronization")
            return db
        except BaseException:
            db.close()
            raise

    def _release_hint_lock(self) -> None:
        if self._hint_lock is not None:
            os.close(self._hint_lock)
            self._hint_lock = None

    async def _close_resources(self) -> None:
        # Base close holds the collection lock until owned hint writes drain.
        try:
            await super()._close_resources()
        finally:
            self._release_hint_lock()

    async def review_control(self, raw: bytes, metadata: bytes) -> OwnedHistoricalRewardControl:
        """Reprove immutable history; elapsed wall time does not invalidate it.

        Individual RPC/proof operations retain their bounds. An interrupted
        ancestry walk resumes from durable hints. Fresh current control remains
        a separate requirement after this potentially slow historical work.
        """
        async with self._lock:
            return await self._review_control_locked(raw, metadata)

    async def _review_control_locked(self, raw, metadata):
        result, _ = await self._review_control_runtime_locked(raw, metadata)
        return result

    async def _review_control_runtime_locked(self, raw, metadata):
        """Retain the independently checked historical codec for recovery callers."""
        if self._closed:
            raise ValueError("historical reward control provider is closed")
        archive = await run_owned_thread(_Archive, raw, metadata)
        _cache_usage(self._cache_root, self.config.maximum_cache_bytes)
        ref = archive.snapshot
        if archive.body["finality"].get("genesis_hash") != (
            "0x" + self.config.chain_pin.genesis_block_hash
        ):
            raise ValueError("reward control archive names another chain")
        timestamp, ceiling = await self._resolve_control_header(ref, archive.encoded)
        runtime, actual_time, control, committed = await verify_slot_archive(
            archive, self._history_proof_tools(), timestamp=timestamp, ceiling=ceiling
        )
        _cache_usage(self._cache_root, self.config.maximum_cache_bytes)
        return self._issue_control(
            archive, runtime, raw, metadata, control, committed, actual_time
        ), runtime

    async def _runtime_for_owned_control_locked(
        self, observation: OwnedHistoricalRewardControl
    ) -> tuple[OwnedHistoricalRewardControl, PinnedRuntimeContext]:
        """Reuse this owner's checked immutable control; recheck owned ancestry.

        The codec remains under the same provider lock. A different provider or
        older observation must independently replay the original archive. This
        does not create a current observation, refresh a clock, or confer any
        authority through a serialized verification summary.
        """
        if self._closed or not self._lock.locked():
            raise ValueError("owned control runtime requires the running locked provider")
        if type(observation) is not OwnedHistoricalRewardControl:
            raise ValueError("owned control runtime requires the original native observation")
        if digest(self.policy) != self.config.policy_sha256:
            raise ValueError("owned control runtime policy differs from its configuration")
        validate_historical_reward_control(
            observation,
            expected_control_hotkey=observation.control_hotkey,
            expected_chain_config_sha256=digest(self.config),
        )
        context = observation._runtime_context
        if context is None or context.owner is not self:
            return await self._review_control_runtime_locked(
                observation.evidence, observation.metadata
            )
        _cache_usage(self._cache_root, self.config.maximum_cache_bytes)
        self._validate_runtime_context(context.runtime, observation.snapshot)
        await self._resolve_control_header(observation.snapshot, context.encoded_header)
        _cache_usage(self._cache_root, self.config.maximum_cache_bytes)
        return observation, context.runtime

    def _history_proof_tools(self):
        return HistoryProofTools(
            self._proofs,
            self._runtime_proofs,
            self._runtime_executor,
            self._runtime_pin,
            self._storage_codec is not None,
            self.config.runtime_metadata_binary_sha256,
        )

    def _issue_control(self, archive, runtime, raw, metadata, control, committed, timestamp_ms):
        """Issue only after capture or external replay has proved these inputs."""
        result = OwnedHistoricalRewardControl(
            archive.snapshot,
            archive.hotkey,
            control,
            committed,
            archive.evidence_sha256,
            runtime.metadata_sha256,
            digest(self.config),
            timestamp_ms,
            raw,
            metadata,
            _issuer=_ISSUER,
        )
        object.__setattr__(result, "_binding", _binding(result))
        object.__setattr__(
            result,
            "_runtime_context",
            _OwnedControlRuntime(
                self, runtime, raw, metadata, result._binding, archive.encoded, _ISSUER
            ),
        )
        return result

    async def _resolve_control_header(
        self, ref, encoded, *, retained_headers=None, completed_checkpoint=None
    ):
        # Single historical reads and checkpoint restoration always acquire a
        # current owned head. Only an explicit bounded worker batch shares it.
        options = {} if retained_headers is None else {"retained_headers": retained_headers}
        if completed_checkpoint is not None:
            options["completed_checkpoint"] = completed_checkpoint
        async with self._control_header_window(**options) as resolve:
            return await resolve(ref, encoded)

    async def _retain_checkpoint_header_window(self, source, first, last):
        if first > last:
            return
        saved = self._checkpoint_hint_window
        low = first
        if saved is not None and saved[0] == source and saved[1] <= first <= saved[2] + 1:
            low = max(low, saved[2] + 1)
        if low > last:
            return
        with TransferProgress(
            "historical_retained_header_import",
            last - low + 1,
            unit="headers",
            planning_unit_seconds=(0.0001, 0.05),
        ) as progress:
            begin = low
            while low <= last:
                high = min(last, low + 4095)
                expected = high - low + 1
                headers = await run_owned_thread(source, low, high)
                if type(headers) is not tuple or len(headers) > expected:
                    raise ValueError("completed header source returned an invalid batch")
                if not headers:
                    break
                for height, encoded in enumerate(headers, low):
                    if (
                        _decode_header(encoded, maximum_bytes=MAXIMUM_HEADER_BYTES)["number"]
                        != height
                    ):
                        raise ValueError("completed header source has a gap or wrong height")
                await self._historical_headers.retain_hints(headers)
                low += len(headers)
                progress.advance(len(headers))
                left = begin
                if saved is not None and saved[0] == source and saved[1] <= begin <= saved[2] + 1:
                    left = min(begin, saved[1])
                self._checkpoint_hint_window = (source, left, low - 1)
                if len(headers) != expected:
                    break

    @asynccontextmanager
    async def _control_header_window(
        self,
        *,
        retained_headers=None,
        completed_checkpoint=None,
    ) -> AsyncIterator[Callable[[FinalizedSnapshotRef, str], Awaitable[tuple[int | None, int]]]]:
        """Resolve historical headers against one genuinely owned finalized head.

        The caller holds the provider lock for its bounded batch. The resolver
        stays in that task and scope; it cannot be serialized, supplied as a
        proof, or reused by a later batch/current-control/transaction read.
        Every target still checks its exact header and owned finality/ancestry.
        The owned verifier already authenticated this head; historical replay
        does not need an external RPC to repeat that identity check. Current
        control and transaction reads retain their separate fresh proof checks.
        """
        owner = asyncio.current_task()
        if self._closed or not self._lock.locked():
            raise ValueError("historical header window requires the running locked provider")
        if completed_checkpoint is not None:
            if not self._owned or type(completed_checkpoint) is not OwnedCheckpointTip:
                raise ValueError("checkpoint tip requires the original native owner result")
            validate_checkpoint_tip(
                completed_checkpoint,
                snapshot=completed_checkpoint.snapshot,
                encoded_header=completed_checkpoint.encoded_header,
                chain_config_sha256=digest(self.config),
            )
        try:
            head = await self._finality.verified_finalized_snapshot()
        except Exception as error:
            raise ValidatorChainError("owned_finality_unavailable") from error
        if not isinstance(head, FinalizedSnapshotRef):
            raise ValidatorChainError("owned_finalized_snapshot_invalid")
        head_block = await self._finality.verified_block_at(head.block_number)
        self._check_finality(head, head_block)
        encoded_head = json.loads(head_block.finality_evidence)["block"]["scale_header"]
        decoded_head = _decode_header(encoded_head, maximum_bytes=MAXIMUM_HEADER_BYTES)
        if (
            decoded_head["number"],
            decoded_head["hash"],
            decoded_head["parent_hash"],
            decoded_head["state_root"],
        ) != (head.block_number, head.block_hash, head.parent_hash, head.state_root):
            raise ValueError("owned historical window head identity mismatch")
        active = True

        async def resolve(ref, encoded):
            if (
                not active
                or self._closed
                or not self._lock.locked()
                or asyncio.current_task() is not owner
            ):
                raise ValueError("historical header resolver escaped its owned window")
            if ref.block_number > head.block_number:
                raise ValueError("historical reward control is ahead of owned finality")
            if completed_checkpoint is not None and (
                completed_checkpoint.snapshot,
                completed_checkpoint.encoded_header,
            ) != (ref, encoded):
                raise ValueError("checkpoint tip differs from the selected history boundary")
            original = await self._finality.verified_block_at(ref.block_number)
            timestamp = None
            if original is not None:
                self._check_finality(ref, original)
                if json.loads(original.finality_evidence)["block"]["scale_header"] != encoded:
                    raise ValueError("reward control header differs from owned history")
                timestamp = original.timestamp_ms
                ceiling = head_block.timestamp_ms
            elif completed_checkpoint is not None:
                # The original private success record already proved this
                # immutable historical identity. A new owned head refreshes the
                # finality ceiling, not the old ancestry/proof work. The history
                # owner rechecks source generations after this await, before
                # applying the checked batch in order. Raw archives and hints
                # never reach this branch.
                if ref.block_number == head.block_number and (
                    ref != head or encoded != encoded_head
                ):
                    raise ValueError("completed checkpoint differs from the owned head")
                ceiling = head_block.timestamp_ms
            else:
                if not self._owned or self._registration_rpc is None:
                    raise FileNotFoundError("owned reward admission header is unavailable")
                anchor = await self._finality.verified_block_after(
                    ref.block_number, maximum_distance=None
                )
                if not isinstance(anchor, VerifiedFinalizedBlock):
                    raise FileNotFoundError("owned reward admission anchor is unavailable")
                self._check_finality_context(anchor)
                if (
                    anchor.height > head.block_number
                    or anchor.timestamp_ms > head_block.timestamp_ms
                ):
                    raise ValueError("reward admission anchor exceeds owned head")
                if retained_headers is not None:
                    await self._retain_checkpoint_header_window(
                        retained_headers, ref.block_number + 1, anchor.height - 1
                    )
                try:
                    recovered = await self._historical_headers.recover(
                        anchor, ref, self._registration_rpc.request, target_header=encoded
                    )
                except sqlite3.Error as error:
                    if not is_sqlite_full(error):
                        raise
                    raise HistoricalHeaderRecoveryPending(
                        "historical header database needs capacity"
                    ) from error
                if recovered.encoded != encoded:
                    raise ValueError("reward admission header differs from owned ancestry")
                ceiling = anchor.timestamp_ms
            return timestamp, ceiling

        try:
            yield resolve
        finally:
            active = False

    async def capture_control_at(
        self, control_hotkey: str, height: int
    ) -> OwnedHistoricalRewardControl:
        """Capture a past slot from chain proofs, even without an original archive.

        RPC supplies only header hints. The owned finalized descendant and
        durable ancestry walk authenticate the target before any state is read.
        Each pass can remain pending; elapsed time never expires the request.
        The result records ancestry provenance, never an invented observer event.
        """
        hotkey = _hotkey(control_hotkey)
        height = _uint(height, 2**53 - 1)
        if height < 1:
            raise ValueError("historical reward control height must be positive")
        async with self._lock:
            if self._closed or not self._owned or self._registration_rpc is None:
                raise ValueError("historical capture requires the owned chain provider")
            _cache_usage(self._cache_root, self.config.maximum_cache_bytes)
            original = await self._finality.verified_block_at(height)
            if original is not None:
                if not isinstance(original, VerifiedFinalizedBlock):
                    raise ValueError("owned finality evidence is unavailable")
                self._check_finality_context(original)
                block_hash = original.block_hash
                try:
                    encoded = json.loads(original.finality_evidence)["block"]["scale_header"]
                except (KeyError, TypeError) as error:
                    raise ValueError("owned finality header is unavailable") from error
            else:
                request = self._registration_rpc.request
                block_hash = await request("chain_getBlockHash", (height,))
                if (
                    type(block_hash) is not str
                    or len(block_hash) != 66
                    or not block_hash.startswith("0x")
                    or any(c not in "0123456789abcdef" for c in block_hash[2:])
                ):
                    raise ValueError("historical control header hint is invalid")
                encoded = encode_rpc_header(await request("chain_getHeader", (block_hash,)))
            header = _decode_header(encoded, maximum_bytes=MAXIMUM_HEADER_BYTES)
            if (header["number"], header["hash"]) != (height, block_hash):
                raise ValueError("historical control header differs from the requested identity")
            ref = FinalizedSnapshotRef(
                height, block_hash, header["parent_hash"], header["state_root"]
            )
            if original is not None:
                self._check_finality(ref, original)
            timestamp, ceiling = await self._resolve_control_header(ref, encoded)
            runtime = await self._runtime_context(ref)
            self._validate_runtime_context(runtime, ref)
            specs = (
                StorageReadSpec("Timestamp", "Now"),
                StorageReadSpec("SubtensorModule", "NetworksAdded", (78,)),
                StorageReadSpec("Commitments", "CommitmentOf", (78, hotkey)),
            )
            batch = await self._weight_read(runtime, specs)
            values = {r.spec: r.decoded_value for r in batch.reads}
            actual_time = _uint(values[specs[0]], 2**53 - 1)
            if (
                not 0 < actual_time <= ceiling
                or (timestamp is not None and actual_time != timestamp)
                or values[specs[1]] is not True
            ):
                raise ValueError("historical control timestamp or subnet differs")
            control, committed = _control_value(values[specs[2]], height)
            raw = _control_evidence(
                config=self.config,
                ref=ref,
                hotkey=hotkey,
                control=control,
                committed=committed,
                runtime=runtime,
                batch=batch,
                schema="umi-historical-reward-control-observation/1",
                finality={
                    "evidence_class": "owned_finalized_ancestry",
                    "genesis_hash": "0x" + self.config.chain_pin.genesis_block_hash,
                    "offline_finality_proof": False,
                    "block": {"scale_header": encoded},
                },
            )
            # The owned collector already proved the runtime and every claim.
            # Check the exact archive envelope and current ancestry again, but
            # do not repeat native proofs or construct another mutable codec.
            # Externally supplied archives still take the full replay path.
            archive = await run_owned_thread(_Archive, raw, runtime.metadata_bytes)
            if (
                archive.snapshot,
                archive.hotkey,
                archive.body["control_sha256"],
                archive.body["committed_at_block"],
            ) != (ref, hotkey, control, committed):
                raise ValueError("captured control archive differs from proved storage")
            timestamp, ceiling = await self._resolve_control_header(ref, encoded)
            if not 0 < actual_time <= ceiling or (
                timestamp is not None and actual_time != timestamp
            ):
                raise ValueError("historical control timestamp or subnet differs")
            _cache_usage(self._cache_root, self.config.maximum_cache_bytes)
            return self._issue_control(
                archive, runtime, raw, runtime.metadata_bytes, control, committed, actual_time
            )
