"""Replay retained reward-control proofs against owned historical finality.

These observations establish past commitments. They cannot replace a current
control read, recipient proof or transaction preflight.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .chain_evidence import FinalizedSnapshotRef
from .competition_chain import CompetitionChainConfig, _hotkey, _uint
from .competition_chain_state import _cache_usage
from .competition_reward_control import (
    FinalizedRewardControlProvider,
    _control_evidence,
    _control_value,
)
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
from .historical_header_recovery import HistoricalHeaderRecovery, HistoricalHeaderRecoveryPending
from .open_competition import digest
from .protocol import canonical_json_bytes
from .runtime_metadata import collect_executed_runtime
from .sqlite_contention import is_sqlite_full
from .validator_chain import StorageReadSpec, VerifiedStorageBatch
from .validator_plans import VerifiedFinalizedBlock

MAX_CONTROL_ARCHIVE_BYTES = 32 * 1024**2
MAX_CONTROL_METADATA_BYTES = 16 * 1024**2
_ISSUER = object()


@dataclass(frozen=True, slots=True)
class OwnedHistoricalRewardControl:
    snapshot: FinalizedSnapshotRef
    control_hotkey: str
    control_sha256: str | None
    committed_at_block: int | None
    evidence_sha256: str
    metadata_sha256: str
    chain_config_sha256: str
    evidence: bytes = field(repr=False)
    metadata: bytes = field(repr=False)
    _issuer: object = field(default=None, repr=False, compare=False)
    _binding: str = field(default="", repr=False, compare=False)


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
        or hashlib.sha256(observation.evidence).hexdigest() != observation.evidence_sha256
        or hashlib.sha256(observation.metadata).hexdigest() != observation.metadata_sha256
        or account_id32(observation.control_hotkey) != account_id32(expected_control_hotkey)
        or observation.chain_config_sha256 != expected_chain_config_sha256
    ):
        raise ValueError("historical reward control lacks the selected owned proof")


class _Archive:
    """Exact bounded answers for proof replay, with no network fallback."""

    def __init__(self, raw: bytes, metadata: bytes):
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_CONTROL_ARCHIVE_BYTES:
            raise ValueError("reward control archive exceeds its byte bound")
        if type(metadata) is not bytes or not 0 < len(metadata) <= MAX_CONTROL_METADATA_BYTES:
            raise ValueError("reward control metadata exceeds its byte bound")
        body = json.loads(raw)
        required = {
            "schema",
            "config_sha256",
            "block",
            "block_hash",
            "state_root",
            "control_hotkey",
            "control_sha256",
            "committed_at_block",
            "finality",
            "runtime_metadata_sha256",
            "runtime_version",
            "storage_codec_mode",
            "runtime_execution",
            "claims",
            "proof",
            "chain_submission_authorized",
        }
        if (
            not isinstance(body, dict)
            or set(body) != required
            or type(body["schema"]) is not str
            or body["schema"]
            not in {
                "umi-reward-control-observation/1",
                "umi-historical-reward-control-observation/1",
            }
            or body["chain_submission_authorized"] is not False
            or canonical_json_bytes(body) != raw
            or hashlib.sha256(metadata).hexdigest() != body["runtime_metadata_sha256"]
        ):
            raise ValueError("reward control archive is not exact native evidence")
        finality = body["finality"]
        if (
            not isinstance(finality, dict)
            or finality.get("evidence_class")
            != (
                "verifier_attested_finality"
                if body["schema"] == "umi-reward-control-observation/1"
                else "owned_finalized_ancestry"
            )
            or finality.get("offline_finality_proof") is not False
            or not isinstance(finality.get("block"), dict)
        ):
            raise ValueError("reward control archive has no original finalized header")
        encoded = finality["block"].get("scale_header")
        header = _decode_header(encoded, maximum_bytes=MAXIMUM_HEADER_BYTES)
        _uint(body["block"], 2**53 - 1)
        if body["committed_at_block"] is not None:
            _uint(body["committed_at_block"], body["block"])
        self.snapshot = FinalizedSnapshotRef(
            header["number"], header["hash"], header["parent_hash"], header["state_root"]
        )
        if (body["block"], body["block_hash"], body["state_root"]) != (
            self.snapshot.block_number,
            self.snapshot.block_hash,
            self.snapshot.state_root,
        ):
            raise ValueError("reward control archive differs from its header")
        self.body, self.metadata, self.encoded = body, metadata, encoded
        self.evidence_sha256 = hashlib.sha256(raw).hexdigest()
        self.hotkey = _hotkey(body["control_hotkey"])
        claims = body["claims"]
        if not isinstance(claims, list) or len(claims) != 3:
            raise ValueError("reward control archive must contain exactly three claims")
        self.values = {}
        for claim in claims:
            if not isinstance(claim, dict) or set(claim) != {"key", "value"}:
                raise ValueError("reward control archive claim is malformed")
            key = claim["key"]
            if type(key) is not str or not 2 < len(key) <= 8194 or key in self.values:
                raise ValueError("reward control archive repeats or misnames a claim")
            self.values[key] = claim["value"]
        if list(self.values) != sorted(self.values):
            raise ValueError("reward control archive claims are not ordered")
        self.proofs = {tuple(self.values): body["proof"]}
        execution = body["runtime_execution"]
        if execution is not None:
            if (
                not isinstance(execution, dict)
                or set(execution)
                != {
                    "executor_sha256",
                    "block",
                    "block_hash",
                    "parent_hash",
                    "state_root",
                    "key",
                    "value",
                    "proof",
                }
                or (
                    execution["block"],
                    execution["block_hash"],
                    execution["parent_hash"],
                    execution["state_root"],
                    execution["key"],
                )
                != (
                    self.snapshot.block_number,
                    self.snapshot.block_hash,
                    self.snapshot.parent_hash,
                    self.snapshot.state_root,
                    "0x3a636f6465",
                )
                or execution["key"] in self.values
            ):
                raise ValueError("archived runtime execution binds a different block or key")
            self.values[execution["key"]] = execution["value"]
            self.proofs[(execution["key"],)] = execution["proof"]
        self.used_keys, self.used_batches = set(), set()

    async def request(self, method, params):
        if not params or params[-1] != self.snapshot.block_hash:
            raise ValueError("reward control replay requested another block")
        if method == "state_getRuntimeVersion" and len(params) == 1:
            return self.body["runtime_version"]
        if method == "state_getMetadata" and len(params) == 1:
            return "0x" + self.metadata.hex()
        if method == "state_getStorageAt" and len(params) == 2:
            key = params[0]
            if key not in self.values:
                raise ValueError("reward control archive omits a requested claim")
            self.used_keys.add(key)
            return self.values[key]
        if method == "state_getReadProof" and len(params) == 2:
            keys = tuple(params[0])
            if keys not in self.proofs:
                raise ValueError("reward control archive omits the requested proof batch")
            self.used_batches.add(keys)
            return {"at": self.snapshot.block_hash, "proof": self.proofs[keys]}
        raise ValueError("reward control archive cannot make this RPC request")

    def consumed(self) -> None:
        if self.used_keys != set(self.values) or self.used_batches != set(self.proofs):
            raise ValueError("reward control archive contains unused proof evidence")


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
        historical_header_batch_size: int = 256,
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
        collector = self._proofs.with_evidence_rpc(archive)
        if self._runtime_executor is not None:
            execution = archive.body["runtime_execution"]
            if not isinstance(execution, dict) or execution["executor_sha256"] != (
                self.config.runtime_metadata_binary_sha256
            ):
                raise ValueError("reward archive runtime executor differs from selection")
            runtime = await collect_executed_runtime(
                self._runtime_proofs.with_evidence_rpc(archive), self._runtime_executor, ref
            )
        else:
            runtime = (
                await collector.storage_codec_runtime(ref, self._runtime_pin, metadata)
                if self._storage_codec is not None
                else await collector.pinned_runtime(ref, self._runtime_pin)
            )
        self._validate_runtime_context(runtime, ref)
        if (
            runtime.storage_codec_mode != archive.body["storage_codec_mode"]
            or runtime.metadata_sha256 != archive.body["runtime_metadata_sha256"]
            or json.loads(runtime.runtime_version_bytes) != archive.body["runtime_version"]
        ):
            raise ValueError("replayed runtime differs from archived control evidence")
        specs = (
            StorageReadSpec("Timestamp", "Now"),
            StorageReadSpec("SubtensorModule", "NetworksAdded", (78,)),
            StorageReadSpec("Commitments", "CommitmentOf", (78, archive.hotkey)),
        )
        batch = await collector.storage_reads(runtime, specs)
        if (
            not isinstance(batch, VerifiedStorageBatch)
            or batch.runtime != runtime
            or len(batch.reads) != len(specs)
            or {read.spec for read in batch.reads} != set(specs)
        ):
            raise ValueError("historical control proof binding or coverage differs")
        values = {r.spec: r.decoded_value for r in batch.reads}
        actual_time = _uint(values[specs[0]], 2**53 - 1)
        if (
            not 0 < actual_time <= ceiling
            or (timestamp is not None and actual_time != timestamp)
            or values[specs[1]] is not True
        ):
            raise ValueError("historical control timestamp or subnet differs")
        control, committed = _control_value(values[specs[2]], ref.block_number)
        if (control, committed) != (
            archive.body["control_sha256"],
            archive.body["committed_at_block"],
        ):
            raise ValueError("historical control digest differs from proved storage")
        archive.consumed()
        _cache_usage(self._cache_root, self.config.maximum_cache_bytes)
        return self._issue_control(archive, runtime, raw, metadata, control, committed), runtime

    def _issue_control(self, archive, runtime, raw, metadata, control, committed):
        """Issue only after capture or external replay has proved these inputs."""
        result = OwnedHistoricalRewardControl(
            archive.snapshot,
            archive.hotkey,
            control,
            committed,
            archive.evidence_sha256,
            runtime.metadata_sha256,
            digest(self.config),
            raw,
            metadata,
            _issuer=_ISSUER,
        )
        object.__setattr__(result, "_binding", _binding(result))
        return result

    async def _resolve_control_header(self, ref, encoded):
        head = await self._proofs.finalized_snapshot()
        head_block = await self._finality.verified_block_at(head.block_number)
        self._check_finality(head, head_block)
        if ref.block_number > head.block_number:
            raise ValueError("historical reward control is ahead of owned finality")
        original = await self._finality.verified_block_at(ref.block_number)
        timestamp = None
        if original is not None:
            self._check_finality(ref, original)
            if json.loads(original.finality_evidence)["block"]["scale_header"] != encoded:
                raise ValueError("reward control header differs from owned history")
            timestamp = original.timestamp_ms
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
            if anchor.height > head.block_number or anchor.timestamp_ms > head_block.timestamp_ms:
                raise ValueError("reward admission anchor exceeds owned head")
            try:
                recovered = await self._historical_headers.recover(
                    anchor, ref, self._registration_rpc.request
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
                archive, runtime, raw, runtime.metadata_bytes, control, committed
            )
