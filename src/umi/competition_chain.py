"""Owned-finality registration reads for successor intake; no chain writes."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import shutil
import sqlite3
import stat
import threading
import time
from collections.abc import Callable, Sequence
from contextlib import AsyncExitStack, asynccontextmanager, suppress
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from types import SimpleNamespace
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_serializer, model_validator
from typing_extensions import Self
from websockets.asyncio.client import connect as websocket_connect

from .chain_evidence import FinalizedSnapshotRef
from .competition_policy_lineage import admitted_policy_sha256s
from .competition_proof_rpc import FailoverProofRpc
from .concurrency import await_owned_task, run_owned_thread
from .encoding import account_id32
from .finalized_ancestry import MAXIMUM_DISTANCE, HeaderPathCache, recover_header_path
from .grandpa_finality import EVIDENCE_CLASS, FINNEY_GENESIS_HASH, GrandpaFinalityObserver
from .grandpa_finality_supervisor import (
    DurableGrandpaFinalityPort,
    GrandpaFinalitySupervisorError,
)
from .open_competition import (
    BurnDestination,
    CompetitionPolicy,
    Hex32,
    Registration,
    RegistrationSnapshot,
    StrictProtocolModel,
    digest,
)
from .policy import FinalityVerifierPin, LiveChainObservationPin
from .protocol import canonical_json_bytes
from .substrate_proof import SubprocessStorageProofVerifier
from .validator_chain import (
    BittensorRawJsonRpc,
    FinalizedProofCollector,
    FinalizedRuntimePin,
    PinnedRuntimeContext,
    ProofCollectionLimits,
    StorageReadSpec,
    ValidatorChainError,
    VerifiedStorageBatch,
)
from .validator_chain_scan import VerifiedFinalizedBlockIdentity
from .validator_plans import VerifiedFinalizedBlock

_MAX_EVIDENCE_BYTES = 64 * 1024 * 1024
_STARTUP_POLL_SECONDS = 0.25
# Reconnect silent follow streams before consuming the full freshness budget.
# Publication journals require observations younger than 60 seconds. Headers
# already have network/finality age when accepted; restart also takes time.
# Bootstrap keeps its separate allowance, and stale heads stay rejected.
_OBSERVER_RECORD_TIMEOUT_SECONDS = 15.0
_LOGGER = logging.getLogger(__name__)


def model_burn_storage_reads(policy):
    if policy.unallocated_model_burn is None:
        return ()
    return (
        StorageReadSpec("SubtensorModule", "SubnetOwnerHotkey", (78,)),
        StorageReadSpec("SubtensorModule", "RecycleOrBurn", (78,)),
    )


def verified_model_burn_destination(policy, values, registrations):
    """Use only decoded storage claims proved against the caller's owned root."""
    destination = policy.unallocated_model_burn
    if destination is None:
        return None
    owner = _hotkey(values[StorageReadSpec("SubtensorModule", "SubnetOwnerHotkey", (78,))])
    mode = values[StorageReadSpec("SubtensorModule", "RecycleOrBurn", (78,))]
    if mode != "Burn" or account_id32(owner) != account_id32(destination.hotkey):
        raise ValueError("model burn owner or mode differs from signed policy")
    if not any(
        r.uid == destination.uid and account_id32(r.hotkey) == account_id32(owner)
        for r in registrations
    ):
        raise ValueError("model burn destination registration changed")
    return BurnDestination(uid=destination.uid, hotkey=destination.hotkey, mode="Burn")


class _AwaitingFinality(ValueError):
    """The owned source has not yet reached the configured startup head."""


class OwnedFinalityStale(ValueError):
    """The owned observer is running, but its verified head is too old."""


class RegistrationCacheFull(ValueError):
    """The working registration cache exhausts its configured byte budget."""


class CompetitionChainConfig(StrictProtocolModel):
    schema_: Literal["umi-competition-chain-config/1"] = Field(alias="schema")
    policy_sha256: Hex32
    network: Literal["finney"] = "finney"
    netuid: Literal[78] = 78
    rpc_url: Annotated[str, Field(min_length=1, max_length=2048)]
    proof_rpc_fallback_urls: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=2048)], ...], Field(max_length=2)
    ] = ()
    chain_pin: LiveChainObservationPin
    finality_pin: FinalityVerifierPin
    target_triple: Annotated[str, Field(min_length=1, max_length=100)]
    finality_binary: Annotated[str, Field(min_length=1, max_length=4096)]
    chain_spec: Annotated[str, Field(min_length=1, max_length=4096)]
    proof_binary: Annotated[str, Field(min_length=1, max_length=4096)]
    proof_binary_sha256: Hex32
    state_directory: Annotated[str, Field(min_length=1, max_length=4096)]
    minimum_finalized_block: Annotated[int, Field(ge=1, le=2**53 - 1)]
    maximum_head_age_ms: Annotated[int, Field(ge=1, le=120_000)] = 120_000
    maximum_future_skew_ms: Annotated[int, Field(ge=0, le=30_000)] = 30_000
    collection_timeout_seconds: Annotated[int, Field(ge=1, le=120)] = 15
    startup_timeout_seconds: Annotated[int, Field(ge=1, le=900)] = 600
    maximum_cache_bytes: Annotated[int, Field(ge=1024, le=20 * 1024**3)] = 256 * 1024**2
    storage_codec_metadata_path: Annotated[str, Field(min_length=1, max_length=4096)] | None = None
    runtime_metadata_binary: Annotated[str, Field(min_length=1, max_length=4096)] | None = None
    runtime_metadata_binary_sha256: Hex32 | None = None

    @model_serializer(mode="wrap")
    def serialize_legacy_config(self, handler):
        value = handler(self)
        # Preserve existing config/journal digests when this mode is not enabled.
        if self.storage_codec_metadata_path is None:
            value.pop("storage_codec_metadata_path", None)
        if self.runtime_metadata_binary is None:
            value.pop("runtime_metadata_binary", None)
        if self.runtime_metadata_binary_sha256 is None:
            value.pop("runtime_metadata_binary_sha256", None)
        if not self.proof_rpc_fallback_urls:
            value.pop("proof_rpc_fallback_urls", None)
        return value

    @field_validator("storage_codec_metadata_path", "runtime_metadata_binary")
    @classmethod
    def codec_path(cls, value):
        if value is None:
            return value
        path = Path(value)
        if (
            not path.is_absolute()
            or path == Path(path.anchor)
            or "\x00" in value
            or ".." in path.parts
        ):
            raise ValueError("storage codec metadata requires an explicit absolute file path")
        return value

    @field_validator("finality_binary", "chain_spec", "proof_binary", "state_directory")
    @classmethod
    def absolute_paths(cls, value: str) -> str:
        if not Path(value).is_absolute() or "\x00" in value:
            raise ValueError("chain adapter paths must be explicit absolute paths")
        return value

    @field_validator("rpc_url")
    @classmethod
    def read_only_rpc(cls, value: str) -> str:
        parsed = urlsplit(value)
        if (
            parsed.scheme != "wss"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or any(ord(character) < 33 for character in value)
        ):
            raise ValueError("chain proof RPC must be an explicit credential-free wss URL")
        return value

    @model_validator(mode="after")
    def pinned_finney(self) -> Self:
        endpoints = (self.rpc_url, *self.proof_rpc_fallback_urls)
        if self.proof_rpc_fallback_urls and len(self.proof_rpc_fallback_urls) != 2:
            raise ValueError("proof RPC failover requires exactly two explicit backups")
        for endpoint in endpoints:
            self.read_only_rpc(endpoint)
        if len(set(endpoints)) != len(endpoints):
            raise ValueError("proof RPC endpoints must be unique and ordered")
        if (self.runtime_metadata_binary is None) != (self.runtime_metadata_binary_sha256 is None):
            raise ValueError("runtime metadata execution requires both an executable and its hash")
        if (
            self.runtime_metadata_binary is not None
            and self.storage_codec_metadata_path is not None
        ):
            raise ValueError("runtime execution and storage-only decoding are mutually exclusive")
        if (
            self.chain_pin.genesis_block_hash != FINNEY_GENESIS_HASH
            or self.finality_pin.expected_genesis_hash != FINNEY_GENESIS_HASH
        ):
            raise ValueError("registration intake is pinned to Finney genesis")
        if self.minimum_finalized_block < self.finality_pin.bootstrap_block_number:
            raise ValueError("minimum finalized block precedes the finality bootstrap")
        if self.target_triple not in self.finality_pin.release_sha256_by_target:
            raise ValueError("finality release lacks the configured target")
        return self


@dataclass(frozen=True, slots=True)
class RegistrationCapture:
    snapshot: RegistrationSnapshot
    provenance: dict[str, Any]


class _SocketLease:
    def __init__(self, connection=None):
        self.connection = connection

    @asynccontextmanager
    async def connect(self, *args, **kwargs):
        if self.connection is None:
            context = websocket_connect(*args, **kwargs)
            socket = await context.__aenter__()
            self.connection = (context, socket)
        yield self.connection[1]


class _BatchConnections:
    """Exclusive leases keep the existing single-request RPC ID unambiguous."""

    def __init__(self, capacity: int = 8):
        self.idle: list[tuple[Any, Any]] = []
        self.capacity = asyncio.Semaphore(capacity)
        self.closed = False

    @asynccontextmanager
    async def lease(self):
        async with self.capacity:
            if self.closed:
                raise ValueError("registration connection pool is closed")
            lease = _SocketLease(self.idle.pop() if self.idle else None)
            try:
                yield lease
            except BaseException:
                if lease.connection is not None:
                    # The outer request scope includes JSON/protocol validation.
                    # A failed connection never returns to the idle pool.
                    await lease.connection[0].__aexit__(None, None, None)
                raise
            else:
                if lease.connection is not None:
                    if self.closed:
                        await lease.connection[0].__aexit__(None, None, None)
                    else:
                        self.idle.append(lease.connection)

    async def close(self):
        self.closed = True
        connections, self.idle = self.idle, []
        await asyncio.gather(
            *(context.__aexit__(None, None, None) for context, _ in connections),
            return_exceptions=True,
        )


class _RegistrationRpc:
    def __init__(
        self,
        config: CompetitionChainConfig,
        *,
        persistent: bool = False,
        bulk_storage_reads: bool = False,
    ):
        self.config = config
        self.bulk_storage_reads = bulk_storage_reads
        self._pool: _BatchConnections | None = None
        # Separate method pools preserve the websocket receive ceiling of each
        # request. A large metadata socket must not become a storage-value socket.
        self._persistent_pools = (
            {
                method: _BatchConnections(8 if method == "state_getStorageAt" else 1)
                for method in (
                    "state_getStorageAt",
                    "state_queryStorageAt",
                    "state_getReadProof",
                    "state_getMetadata",
                    "state_getRuntimeVersion",
                    "chain_getHeader",
                    "chain_getBlockHash",
                )
            }
            if persistent
            else {}
        )
        self._closed = False

    async def storage_values(self, block_hash: str, keys: Sequence[bytes]):
        if not 1 <= len(keys) <= 256 or any(
            not isinstance(key, bytes) or not 1 <= len(key) <= 512 for key in keys
        ):
            raise ValueError("registration bulk keys exceed bounds")
        encoded = tuple("0x" + key.hex() for key in keys)
        if len(set(encoded)) != len(encoded):
            raise ValueError("registration bulk keys are duplicated")
        result = await self.request("state_queryStorageAt", (encoded, block_hash))
        if (
            not isinstance(result, list)
            or len(result) != 1
            or not isinstance(result[0], dict)
            or set(result[0]) != {"block", "changes"}
            or result[0]["block"] != block_hash
        ):
            raise ValueError("registration bulk result belongs to another block")
        changes = result[0]["changes"]
        if not isinstance(changes, list) or len(changes) != len(encoded):
            raise ValueError("registration bulk result is incomplete")
        expected = set(encoded)
        values = {}
        for change in changes:
            if not isinstance(change, list) or len(change) != 2:
                raise ValueError("registration bulk entry is malformed")
            key, value = change
            if not isinstance(key, str) or key not in expected or (key, block_hash) in values:
                raise ValueError("registration bulk key is unexpected or duplicated")
            if value is not None and (not isinstance(value, str) or len(value) > 1026):
                raise ValueError("registration storage value exceeds its bound")
            values[key, block_hash] = value
        # These are untrusted claims. The collector still verifies their complete
        # trie multiproof against the owned finalized state root before use.
        return values

    async def aclose(self):
        self._closed = True
        await asyncio.gather(*(pool.close() for pool in self._persistent_pools.values()))

    @asynccontextmanager
    async def batch(self):
        if self._pool is not None:
            raise ValueError("registration RPC batch is already active")
        pool = self._persistent_pools.get("state_getStorageAt") or _BatchConnections()
        self._pool = pool
        try:
            yield
        finally:
            self._pool = None
            if not self._persistent_pools:
                await pool.close()

    async def request(self, method: str, params: Sequence[Any]) -> Any:
        if self._closed:
            raise ValueError("registration RPC is closed")
        ceiling = {
            "state_getStorageAt": 2048,
            "state_getReadProof": 17 * 1024**2,
            "state_getMetadata": 33 * 1024**2,
        }.get(method, 1024**2)

        async with AsyncExitStack() as stack:
            lease = None
            pool = self._persistent_pools.get(method)
            if pool is None and method == "state_getStorageAt":
                pool = self._pool
            if pool is not None:
                lease = await stack.enter_async_context(pool.lease())

            def bounded_connect(*args, **kwargs):
                kwargs["max_size"] = min(kwargs["max_size"], ceiling)
                if lease is not None:
                    return lease.connect(*args, **kwargs)
                return websocket_connect(*args, **kwargs)

            rpc = BittensorRawJsonRpc(
                SimpleNamespace(endpoint=self.config.rpc_url),
                connect_factory=bounded_connect,
                request_timeout_seconds=self.config.collection_timeout_seconds,
                open_timeout_seconds=min(15, self.config.collection_timeout_seconds),
            )
            return await rpc.request(method, params)


class _PrefetchRpc:
    """Bound concurrent value reads while leaving proof verification to the collector."""

    def __init__(self, rpc: Any):
        self.rpc = rpc
        self.values: dict[tuple[str, str], Any] = {}

    async def request(self, method: str, params: Sequence[Any]) -> Any:
        if method == "state_getStorageAt" and tuple(params) in self.values:
            return self.values[tuple(params)]
        return await self.rpc.request(method, params)

    async def prefetch(self, block_hash: str, keys: Sequence[bytes]) -> None:
        self.values.clear()
        if getattr(self.rpc, "bulk_storage_reads", False):
            self.values = await self.rpc.storage_values(block_hash, keys)
            return
        semaphore = asyncio.Semaphore(8)

        async def read(key: bytes) -> tuple[tuple[str, str], Any]:
            params = ("0x" + key.hex(), block_hash)
            async with semaphore:
                value = await self.rpc.request("state_getStorageAt", params)
            if value is not None and (not isinstance(value, str) or len(value) > 1026):
                raise ValueError("registration storage value exceeds its bound")
            return params, value

        async with AsyncExitStack() as stack:
            batch = getattr(self.rpc, "batch", None)
            if callable(batch):
                await stack.enter_async_context(batch())
            tasks = [asyncio.create_task(read(key)) for key in keys]
            pending = asyncio.gather(*tasks)
            try:
                # Cancel children once below, allowing their socket cleanup to
                # finish instead of interrupting it with a second cancellation.
                self.values = dict(await asyncio.shield(pending))
            finally:
                for task in tasks:
                    if not task.done():
                        task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
                await asyncio.gather(pending, return_exceptions=True)


class FinalizedRegistrationProvider:
    """Collect complete SN78 membership under one owned-finality state root.

    Injected ports are a test boundary. Production construction always uses the
    hash-pinned GRANDPA sidecar and storage verifier, never an RPC finality label.
    """

    _supports_executed_runtime = False

    def __init__(
        self,
        config: CompetitionChainConfig,
        policy: CompetitionPolicy,
        *,
        finality: Any = None,
        proofs: Any = None,
        now_ms: Callable[[], int] | None = None,
        retained_capture_blocks: Callable[[], frozenset[int]] | None = None,
    ):
        self.config = CompetitionChainConfig.model_validate_json(canonical_json_bytes(config))
        if self.config.runtime_metadata_binary is not None and not self._supports_executed_runtime:
            raise ValueError("runtime metadata execution is only supported by the weight provider")
        self.policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
        if self.config.policy_sha256 != digest(self.policy):
            raise ValueError("chain configuration belongs to another competition policy")
        if (finality is None) != (proofs is None):
            raise ValueError("test ports must be supplied together")
        self._now_ms = now_ms or (lambda: time.time_ns() // 1_000_000)
        self._retained_capture_blocks = retained_capture_blocks
        self._capacity_warning_state: tuple[bool, bool] | None = None
        self._lock = asyncio.Lock()
        self._stop = asyncio.Event()
        self._task: asyncio.Task | None = None
        self._close_task: asyncio.Task[None] | None = None
        self._closed = False
        self._prefetch: _PrefetchRpc | None = None
        self._registration_rpc: _RegistrationRpc | FailoverProofRpc | None = None
        self._latest: RegistrationCapture | None = None
        self._registration_ancestry_headers = HeaderPathCache()
        self._runtime_pin = FinalizedRuntimePin(
            metadata_sha256=config.chain_pin.metadata_sha256,
            spec_version=config.chain_pin.runtime_spec_version,
            transaction_version=config.chain_pin.transaction_version,
            state_version=config.chain_pin.state_version,
        )
        self._storage_codec = self._load_storage_codec()
        directory = self._cache_directory(config)
        if directory.is_symlink():
            raise ValueError("chain cache directory cannot be a symlink")
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if directory.stat().st_mode & 0o077:
            raise ValueError("chain cache directory must be private")
        self._path = directory / "registrations.sqlite3"
        self._initialize_cache()
        self._owned = finality is None
        if self._owned:
            observer = GrandpaFinalityObserver.from_policy_pin(
                config.finality_pin,
                target_triple=config.target_triple,
                binary_path=config.finality_binary,
                chain_spec_path=config.chain_spec,
                record_timeout_seconds=min(
                    _OBSERVER_RECORD_TIMEOUT_SECONDS, config.maximum_head_age_ms / 2000
                ),
                first_record_timeout_seconds=config.startup_timeout_seconds,
            )
            finality = DurableGrandpaFinalityPort(
                observer=observer,
                state_path=directory / "finality.sqlite3",
                scoring_policy_digest=self._finality_policy_hash(),
                accepted_predecessor_policy_digests=self._predecessor_finality_policy_hashes(),
                chain_observation=config.chain_pin,
                finality_verifier_sha256=config.finality_pin.release_sha256_by_target[
                    config.target_triple
                ],
                initial_minimum_finalized_block=config.minimum_finalized_block,
                startup_timeout_seconds=config.startup_timeout_seconds,
                limits=self._finality_storage_limits(),
            )
            head = finality.persisted_head()
            self._startup_floor = (
                config.minimum_finalized_block - 1 if head is None else head.height
            )
            verifier = SubprocessStorageProofVerifier(
                binary_path=config.proof_binary,
                expected_sha256=config.proof_binary_sha256,
            )
            if config.proof_rpc_fallback_urls:
                self._registration_rpc = FailoverProofRpc(
                    tuple(
                        _RegistrationRpc(
                            config.model_copy(update={"rpc_url": endpoint}),
                            persistent=True,
                            bulk_storage_reads=True,
                        )
                        for endpoint in (config.rpc_url, *config.proof_rpc_fallback_urls)
                    ),
                    timeout_seconds=config.collection_timeout_seconds,
                )
            else:
                self._registration_rpc = _RegistrationRpc(
                    config, persistent=True, bulk_storage_reads=True
                )
            self._prefetch = _PrefetchRpc(self._registration_rpc)
            proofs = FinalizedProofCollector(
                self._prefetch,
                finality=finality,
                verifier=verifier,
                limits=ProofCollectionLimits(
                    maximum_storage_value_bytes=512,
                    maximum_storage_values_bytes=256 * 512,
                    maximum_proof_node_bytes=2 * 1024**2,
                    maximum_proof_bytes=8 * 1024**2,
                ),
            )
        self._finality = finality
        self._proofs = proofs

    def _load_storage_codec(self):
        value = self.config.storage_codec_metadata_path
        if value is None:
            return None
        path = Path(value)
        if any(parent.is_symlink() for parent in (path, *path.parents)):
            raise ValueError("storage codec metadata must not traverse symlinks")
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 4 * 1024**2:
                raise ValueError("storage codec metadata is not a bounded regular file")
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                metadata = stream.read(4 * 1024**2 + 1)
            if (
                len(metadata) != info.st_size
                or hashlib.sha256(metadata).hexdigest() != self._runtime_pin.metadata_sha256
            ):
                raise ValueError("storage codec metadata does not match the approved chain pin")
            return metadata
        finally:
            os.close(descriptor)

    async def _runtime_context(self, ref):
        if self._storage_codec is not None:
            return await self._proofs.storage_codec_runtime(
                ref, self._runtime_pin, self._storage_codec
            )
        return await self._proofs.pinned_runtime(ref, self._runtime_pin)

    def _cache_directory(self, config: CompetitionChainConfig) -> Path:
        return Path(config.state_directory)

    def _finality_policy_hash(self) -> str:
        return digest(self.policy)

    def _predecessor_finality_policy_hashes(self) -> tuple[str, ...]:
        """Deal-preserving predecessors whose finality store this provider may adopt."""
        return tuple(admitted_policy_sha256s(self.policy)[1:])

    def _cache_binding_hash(self) -> str:
        """Bind the registration cache to the chain configuration, not the policy.

        The cache holds verified registrations and finality heads, none of which
        depend on the competition policy, so a deal-preserving policy successor must
        not invalidate it. ``policy_sha256`` is bound separately at construction.
        """
        return self._config_binding_hash(self.config)

    @staticmethod
    def _config_binding_hash(config: CompetitionChainConfig) -> str:
        body = config.model_dump(mode="json", by_alias=True)
        body.pop("policy_sha256", None)
        return digest({"chain_config_without_policy": body})

    def _acceptable_cache_bindings(self) -> frozenset[str]:
        """The current binding, plus the legacy per-policy binding this cache would
        have carried under the live policy or any honored predecessor."""
        accepted = {self._cache_binding_hash()}
        configs = [self.config]
        if self.config.proof_rpc_fallback_urls:
            # Explicit addition only: preserve the original primary RPC, every
            # chain/proof pin and every other field. Never adopt another primary.
            previous = self.config.model_copy(update={"proof_rpc_fallback_urls": ()})
            configs.append(previous)
            accepted.add(self._config_binding_hash(previous))
        for config in configs:
            for policy_sha256 in admitted_policy_sha256s(self.policy):
                legacy = config.model_copy(update={"policy_sha256": policy_sha256})
                accepted.add(digest(legacy))
        return frozenset(accepted)

    def _finality_storage_limits(self):
        return None

    def _connect(self) -> sqlite3.Connection:
        if self._path.is_symlink():
            raise ValueError("registration cache cannot be a symlink")
        connection = sqlite3.connect(self._path, timeout=2, isolation_level=None)
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def _initialize_cache(self) -> None:
        connection = self._connect()
        try:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS binding (digest TEXT PRIMARY KEY);
                CREATE TABLE IF NOT EXISTS captures (
                    block INTEGER PRIMARY KEY, hash TEXT NOT NULL, snapshot TEXT NOT NULL,
                    evidence_sha256 TEXT NOT NULL, evidence BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS artifacts (
                    digest TEXT PRIMARY KEY, body BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS observed_head (
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    block INTEGER NOT NULL, hash TEXT NOT NULL
                );
            """)
            connection.execute("BEGIN IMMEDIATE")
            bound = connection.execute("SELECT digest FROM binding").fetchone()
            expected = self._cache_binding_hash()
            if bound is None:
                connection.execute("INSERT INTO binding VALUES (?)", (expected,))
            elif bound[0] != expected:
                if bound[0] not in self._acceptable_cache_bindings():
                    raise ValueError("registration cache belongs to another chain configuration")
                # Legacy per-policy binding from before this release, or from a
                # deal-preserving predecessor: move it to the policy-free binding.
                connection.execute("UPDATE binding SET digest=?", (expected,))
            if self.config.proof_rpc_fallback_urls:
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS proof_rpc_transport_bindings "
                    "(digest TEXT PRIMARY KEY, previous TEXT, body BLOB NOT NULL)"
                )
                body = canonical_json_bytes(
                    {
                        "schema": "umi-registration-proof-rpc-transport/1",
                        "configuration_sha256": expected,
                        "rpc_url": self.config.rpc_url,
                        "proof_rpc_fallback_urls": self.config.proof_rpc_fallback_urls,
                    }
                )
                old = connection.execute(
                    "SELECT body FROM proof_rpc_transport_bindings WHERE digest=?", (expected,)
                ).fetchone()
                if old is None:
                    connection.execute(
                        "INSERT INTO proof_rpc_transport_bindings VALUES (?,?,?)",
                        (expected, bound[0] if bound else None, body),
                    )
                elif old != (body,):
                    raise ValueError("registration proof RPC transport binding changed")
            from .competition_chain_capacity import verify_cache_capacity_history

            verify_cache_capacity_history(connection, self.config, expected_binding=expected)
            connection.commit()
        finally:
            connection.close()
        self._path.chmod(0o600)

    async def start(self) -> None:
        if self._closed:
            raise ValueError("registration provider is closed")
        if self._owned and self._task is None:
            self._task = asyncio.create_task(self._finality.run(self._stop))

    def ensure_observer_running(self) -> None:
        """Detect terminal observer failure without treating stale heads as exit."""
        if self._closed:
            raise RuntimeError("owned_finality_provider_closed")
        if self._owned and (self._task is None or self._task.done()):
            if self._task is not None and not self._task.cancelled():
                self._task.exception()  # Retrieve it, but never expose its text.
            raise RuntimeError("owned_finality_observer_stopped")

    async def wait_ready(self) -> RegistrationCapture:
        """Wait for one complete owned capture after start(), without hiding faults.

        Only an absent first head or a head below the startup floor is retried.
        Proof, pin, transport, freshness and store failures remain fatal. The
        caller owns aclose(), including when startup times out or is cancelled.
        """

        async def retry_startup() -> RegistrationCapture:
            while True:
                if self._owned and self._task is not None and self._task.done():
                    # Preserve a failed observer's actual exception, including
                    # corruption, instead of treating it as normal warm-up.
                    self._task.result()
                try:
                    return await self.collect()
                except _AwaitingFinality:
                    pass
                except ValidatorChainError as error:
                    cause = error.__cause__
                    if not (
                        error.reason_code == "owned_finality_unavailable"
                        and type(cause) is GrandpaFinalitySupervisorError
                        and cause.reason_code == "no_verified_finalized_head"
                    ):
                        raise
                await asyncio.sleep(_STARTUP_POLL_SECONDS)

        try:
            return await asyncio.wait_for(
                retry_startup(), timeout=self.config.startup_timeout_seconds
            )
        except asyncio.TimeoutError as error:
            raise ValueError("registration startup timed out") from error

    async def aclose(self) -> None:
        self._closed = True
        self._stop.set()
        if self._close_task is None:
            self._close_task = asyncio.create_task(
                self._close(), name="competition-finality-provider-close"
            )
        await await_owned_task(self._close_task)

    async def _close(self) -> None:
        # Collection keeps this lock until its persistence thread has stopped.
        # Cleanup, including subclass leases, must not outlive close's owner.
        async with self._lock:
            await self._close_resources()

    async def _close_resources(self) -> None:
        try:
            if self._task is not None:
                with suppress(asyncio.TimeoutError, asyncio.CancelledError, RuntimeError):
                    await asyncio.wait_for(self._task, timeout=5)
        finally:
            self._latest = None
            if self._registration_rpc is not None:
                await self._registration_rpc.aclose()

    async def __call__(self) -> RegistrationSnapshot:
        return (await self.collect()).snapshot

    async def collect(self) -> RegistrationCapture:
        return await self._collect()

    async def collect_at(self, height: int) -> RegistrationCapture:
        """Reprove recent membership at an exact height from the owned verifier.

        Round signers can compare one snapshot despite different current heads.
        This does not accept coordinator headers or relax wall-clock freshness.
        """
        height = _uint(height, 2**53 - 1)
        if height < self.config.minimum_finalized_block:
            raise ValueError("requested registration block precedes configured minimum")
        return await self._collect(height)

    async def _collect(self, height: int | None = None) -> RegistrationCapture:
        if self._closed:
            raise ValueError("registration provider is closed")
        try:
            return await asyncio.wait_for(
                self._collect_locked(height), self.config.collection_timeout_seconds
            )
        except asyncio.TimeoutError as error:
            raise ValueError("registration collection timed out") from error

    async def _collect_locked(self, height: int | None = None) -> RegistrationCapture:
        async with self._lock:
            if self._closed:
                raise ValueError("registration provider is closed")
            if self._owned and (self._task is None or self._task.done()):
                raise ValueError("owned finality observer is not running")
            ref = await self._proofs.finalized_snapshot()
            if not isinstance(ref, FinalizedSnapshotRef):
                raise ValueError("owned finalized snapshot is invalid")
            if ref.block_number < self.config.minimum_finalized_block:
                raise _AwaitingFinality("finalized head precedes configured minimum")
            if self._owned and ref.block_number <= self._startup_floor:
                raise _AwaitingFinality("awaiting a head verified by this observer process")
            block = await self._finality.verified_block_at(ref.block_number)
            self._check_finality(ref, block)
            self._fresh(block.timestamp_ms)
            await run_owned_thread(self._check_prior, ref)
            head = ref
            ancestry = None
            if height is not None and height != head.block_number:
                if not 0 <= head.block_number - height <= self.policy.maximum_snapshot_age_blocks:
                    raise ValueError("requested registration block is future or stale")
                identity = await self._finality.verified_identity_at(height)
                if identity is None:
                    if not self._owned or self._registration_rpc is None:
                        raise ValueError("owned historical finalized identity is unavailable")
                    anchor = await self._finality.verified_block_after(
                        height,
                        maximum_distance=min(
                            MAXIMUM_DISTANCE, self.policy.maximum_snapshot_age_blocks
                        ),
                    )
                    if (
                        not isinstance(anchor, VerifiedFinalizedBlock)
                        or anchor.height > head.block_number
                    ):
                        raise ValueError("owned historical finalized anchor is unavailable")
                    self._check_finality_context(anchor)
                    ref, headers = await recover_header_path(
                        anchor,
                        height,
                        self._registration_rpc.request,
                        maximum_distance=min(
                            MAXIMUM_DISTANCE, self.policy.maximum_snapshot_age_blocks
                        ),
                        cache=self._registration_ancestry_headers,
                    )
                    block = anchor
                    ancestry = {
                        "schema": "umi-registration-finalized-ancestry/1",
                        "evidence_class": "verified_finalized_ancestry",
                        "offline_finality_proof": False,
                        "anchor": json.loads(anchor.finality_evidence),
                        "anchor_sha256": anchor.finality_evidence_sha256,
                        "headers": headers,
                        "snapshot": {
                            "block": ref.block_number,
                            "block_hash": ref.block_hash,
                            "parent_hash": ref.parent_hash,
                            "state_root": ref.state_root,
                        },
                    }
                elif (
                    not isinstance(identity, VerifiedFinalizedBlockIdentity)
                    or identity.snapshot.block_number != height
                ):
                    raise ValueError("owned historical finalized identity is unavailable")
                else:
                    ref = identity.snapshot
                    block = await self._finality.verified_block_at(height)
                    self._check_finality(ref, block)
                    if (
                        identity.finality_verifier_sha256 != block.finality_verifier_sha256
                        or identity.finality_evidence_sha256 != block.finality_evidence_sha256
                    ):
                        raise ValueError("owned historical finalized evidence binding mismatch")
                    self._fresh(block.timestamp_ms)
            if (
                height is None
                and self._latest is not None
                and self._latest.snapshot.block_hash == ref.block_hash
            ):
                return self._latest
            runtime = await self._runtime_context(ref)
            if (
                not isinstance(runtime, PinnedRuntimeContext)
                or runtime.snapshot != ref
                or runtime.pin != self._runtime_pin
            ):
                raise ValueError("registration runtime binding mismatch")
            batches: list[VerifiedStorageBatch] = []
            base = await self._read(
                runtime,
                (
                    StorageReadSpec("Timestamp", "Now"),
                    StorageReadSpec("SubtensorModule", "NetworksAdded", (78,)),
                    StorageReadSpec("SubtensorModule", "SubnetworkN", (78,)),
                    *model_burn_storage_reads(self.policy),
                ),
            )
            batches.append(base)
            values = {read.spec: read.decoded_value for read in base.reads}
            if values[StorageReadSpec("SubtensorModule", "NetworksAdded", (78,))] is not True:
                raise ValueError("SN78 registration subnet is unavailable")
            timestamp = _uint(values[StorageReadSpec("Timestamp", "Now")], 2**53 - 1)
            if ancestry is not None:
                if not 0 < timestamp <= block.timestamp_ms:
                    raise ValueError("historical timestamp is invalid or newer than its anchor")
                self._fresh(timestamp)
            elif timestamp != block.timestamp_ms:
                raise ValueError("proven timestamp differs from owned finalized header")
            count = _uint(values[StorageReadSpec("SubtensorModule", "SubnetworkN", (78,))], 256)
            if count == 0:
                raise ValueError("SN78 registration is empty")
            keys = await self._read(
                runtime,
                tuple(
                    StorageReadSpec("SubtensorModule", "Keys", (78, uid)) for uid in range(count)
                ),
            )
            batches.append(keys)
            key_values = {read.spec: read.decoded_value for read in keys.reads}
            hotkeys = tuple(
                _hotkey(key_values[StorageReadSpec("SubtensorModule", "Keys", (78, uid))])
                for uid in range(count)
            )
            if len(set(hotkeys)) != count:
                raise ValueError("duplicate registration hotkey")
            inverse = await self._read(
                runtime,
                tuple(
                    StorageReadSpec("SubtensorModule", "Uids", (78, hotkey)) for hotkey in hotkeys
                ),
            )
            batches.append(inverse)
            inverse_values = {read.spec: read.decoded_value for read in inverse.reads}
            for uid, hotkey in enumerate(hotkeys):
                if (
                    _uint(
                        inverse_values[StorageReadSpec("SubtensorModule", "Uids", (78, hotkey))],
                        255,
                    )
                    != uid
                ):
                    raise ValueError("registration inverse mapping mismatch")
            newest = await self._finality.verified_finalized_snapshot()
            if (
                not isinstance(newest, FinalizedSnapshotRef)
                or newest.block_number < head.block_number
                or (newest.block_number == head.block_number and newest != head)
            ):
                raise ValueError("owned finalized head rolled back or changed")
            if newest.block_number - ref.block_number > self.policy.maximum_snapshot_age_blocks:
                raise ValueError("registration snapshot became stale during proof collection")
            self._fresh(timestamp)
            registrations = tuple(
                Registration(uid=uid, hotkey=hotkey) for uid, hotkey in enumerate(hotkeys)
            )
            snapshot = RegistrationSnapshot(
                network="finney",
                netuid=78,
                block=ref.block_number,
                block_hash=ref.block_hash,
                registrations=registrations,
                burn_destination=verified_model_burn_destination(
                    self.policy, values, registrations
                ),
            )
            evidence = canonical_json_bytes(
                {
                    "schema": "umi-competition-registration-evidence/1",
                    "snapshot": snapshot.model_dump(mode="json"),
                    "finality": ancestry
                    if ancestry is not None
                    else json.loads(block.finality_evidence),
                    "runtime_metadata_sha256": runtime.metadata_sha256,
                    "runtime_version": json.loads(runtime.runtime_version_bytes),
                    **(
                        {"storage_codec_mode": runtime.storage_codec_mode}
                        if self._storage_codec is not None
                        else {}
                    ),
                    "storage_batches": [
                        {
                            "state_root": batch.evidence.verified_state_root,
                            "claims": [
                                {
                                    "key": "0x" + claim.storage_key.hex(),
                                    "value": None
                                    if claim.value is None
                                    else "0x" + claim.value.hex(),
                                }
                                for claim in batch.evidence.claims
                            ],
                            "proof": ["0x" + node.hex() for node in batch.evidence.proof],
                        }
                        for batch in batches
                    ],
                }
            )
            if len(evidence) > _MAX_EVIDENCE_BYTES:
                raise ValueError("registration evidence exceeds its byte bound")
            evidence_id = hashlib.sha256(evidence).hexdigest()
            capture = RegistrationCapture(
                snapshot,
                {
                    "schema": "umi-competition-registration-provenance/1",
                    "evidence_class": EVIDENCE_CLASS
                    if ancestry is None
                    else "verified_finalized_ancestry",
                    "offline_finality_proof": False,
                    "genesis_block_hash": "0x" + FINNEY_GENESIS_HASH,
                    "block": ref.block_number,
                    "block_hash": ref.block_hash,
                    "state_root": ref.state_root,
                    "timestamp_ms": timestamp,
                    "snapshot_sha256": digest(snapshot),
                    "evidence_sha256": evidence_id,
                    "metadata_sha256": runtime.metadata_sha256,
                    "finality_evidence_sha256": block.finality_evidence_sha256
                    if ancestry is None
                    else digest(ancestry),
                    "finality_verifier_sha256": block.finality_verifier_sha256,
                    "storage_proof_verifier_sha256": self.config.proof_binary_sha256,
                    "chain_submission_authorized": False,
                },
            )
            cancelled = threading.Event()
            await run_owned_thread(
                partial(
                    self._save,
                    capture,
                    evidence,
                    runtime.metadata_bytes,
                    head=newest,
                    cancelled=cancelled,
                ),
                on_cancel=cancelled.set,
            )
            if ref == head:
                self._latest = capture
            return capture

    def _check_finality(self, ref: FinalizedSnapshotRef, block: Any) -> None:
        if not isinstance(block, VerifiedFinalizedBlock):
            raise ValueError("owned finality evidence is unavailable")
        if (
            block.height != ref.block_number
            or block.block_hash != ref.block_hash
            or block.state_root != ref.state_root
        ):
            raise ValueError("owned finality snapshot binding mismatch")
        self._check_finality_context(block)

    def _check_finality_context(self, block: VerifiedFinalizedBlock) -> None:
        if (
            block.chain_observation != self.config.chain_pin
            or block.scoring_policy_hash != self._finality_policy_hash()
            or block.finality_verifier_sha256
            != self.config.finality_pin.release_sha256_by_target[self.config.target_triple]
        ):
            raise ValueError("owned finality evidence binding mismatch")
        record = json.loads(block.finality_evidence)
        if (
            record.get("evidence_class") != EVIDENCE_CLASS
            or record.get("offline_finality_proof") is not False
            or record.get("genesis_hash") != "0x" + FINNEY_GENESIS_HASH
        ):
            raise ValueError("owned finality evidence class or genesis mismatch")

    def _fresh(self, timestamp: int) -> None:
        now = _uint(self._now_ms(), 2**53 - 1)
        if timestamp < now - self.config.maximum_head_age_ms:
            raise OwnedFinalityStale("owned finalized head is stale")
        if timestamp > now + self.config.maximum_future_skew_ms:
            raise ValueError("owned finalized head is in the future")

    async def _read(
        self, runtime: PinnedRuntimeContext, specs: tuple[StorageReadSpec, ...]
    ) -> VerifiedStorageBatch:
        try:
            if self._prefetch is not None:
                await self._prefetch.prefetch(
                    runtime.snapshot.block_hash,
                    tuple(
                        runtime.storage_key(spec.pallet, spec.item, spec.params) for spec in specs
                    ),
                )
            batch = await self._proofs.storage_reads(runtime, specs)
        finally:
            if self._prefetch is not None:
                self._prefetch.values.clear()
        if not isinstance(batch, VerifiedStorageBatch) or batch.runtime != runtime:
            raise ValueError("registration storage proof uses another runtime or state root")
        if {read.spec for read in batch.reads} != set(specs) or len(batch.reads) != len(specs):
            raise ValueError("registration storage response is incomplete or duplicated")
        if any(
            read.raw_value is None
            and not (
                self.policy.unallocated_model_burn is not None
                and read.spec == StorageReadSpec("SubtensorModule", "RecycleOrBurn", (78,))
                and read.decoded_value == "Burn"
            )
            for read in batch.reads
        ):
            raise ValueError("registration storage membership is incomplete")
        # RecycleOrBurn is ValueQuery storage. Verified non-membership can
        # decode to Burn through the pinned metadata default. The collector
        # verifies that absence against the same state root before decoding;
        # this exception never supplies a local fallback or permits missing
        # owner, UID mapping, timestamp, or registration claims.
        return batch

    def _check_prior(self, ref: FinalizedSnapshotRef) -> None:
        connection = self._connect()
        try:
            self._check_head(connection, ref.block_number, ref.block_hash)
        finally:
            connection.close()

    @staticmethod
    def _check_head(connection, height, block_hash):
        # Include captures for caches written before observed_head existed.
        priors = connection.execute(
            "SELECT block, hash FROM captures UNION ALL SELECT block, hash FROM observed_head "
            "ORDER BY block DESC LIMIT 2"
        ).fetchall()
        if any(
            height < block or (height == block and block_hash != hash_) for block, hash_ in priors
        ):
            raise ValueError("registration finalized head rolled back or changed")

    def _save(
        self,
        capture: RegistrationCapture,
        evidence: bytes,
        metadata: bytes,
        *,
        head: FinalizedSnapshotRef | None = None,
        cancelled: threading.Event | None = None,
    ) -> None:
        if cancelled is not None and cancelled.is_set():
            raise ValueError("registration persistence cancelled")
        snapshot = capture.snapshot
        connection = self._connect()
        capacity = None
        try:
            connection.execute("BEGIN IMMEDIATE")
            metadata_id = hashlib.sha256(metadata).hexdigest()
            artifact = connection.execute(
                "SELECT body FROM artifacts WHERE digest=?", (metadata_id,)
            ).fetchone()
            if artifact and artifact[0] != metadata:
                raise ValueError("retained runtime metadata is corrupt")
            height, block_hash = (
                (snapshot.block, snapshot.block_hash)
                if head is None
                else (head.block_number, head.block_hash)
            )
            self._check_head(connection, height, block_hash)
            if not 0 <= height - snapshot.block <= self.policy.maximum_snapshot_age_blocks:
                raise ValueError("retained registration snapshot is future or stale")
            prior = connection.execute(
                "SELECT snapshot FROM captures WHERE block=?", (snapshot.block,)
            ).fetchone()
            if prior:
                if prior[0] != digest(snapshot):
                    raise ValueError("registration mapping changed at the same finalized block")
            else:
                # Intake may discard old background polls, but never an
                # admission's proof or any still-usable historical snapshot.
                # Other provider consumers retain their existing semantics.
                # Pruning and insertion commit together; a failed save rolls
                # back every deletion. observed_head remains the rollback guard.
                retained = frozenset()
                if self._retained_capture_blocks is not None:
                    retained = self._retained_capture_blocks()
                    if cancelled is not None and cancelled.is_set():
                        raise ValueError("registration persistence cancelled")
                    if not isinstance(retained, frozenset) or any(
                        type(block) is not int or not 0 <= block <= 2**53 - 1 for block in retained
                    ):
                        raise ValueError("invalid retained registration blocks")
                    obsolete = connection.execute(
                        "SELECT block FROM captures WHERE block<?",
                        (height - self.policy.maximum_snapshot_age_blocks,),
                    ).fetchall()
                    connection.executemany(
                        "DELETE FROM captures WHERE block=?",
                        ((block,) for (block,) in obsolete if block not in retained),
                    )
                sizes = connection.execute(
                    "SELECT block, length(evidence) FROM captures"
                ).fetchall()
                archived = sum(size for block, size in sizes if block in retained)
                total = sum(size for block, size in sizes if block not in retained)
                total += connection.execute(
                    "SELECT COALESCE(SUM(length(body)), 0) FROM artifacts"
                ).fetchone()[0]
                added_metadata = 0 if artifact else len(metadata)
                # Receipt-bound evidence is a durable archive, not disposable
                # cache. Its growth is governed by the admission ledger's
                # record/byte limits and disk capacity, not the polling budget.
                added_evidence = 0 if snapshot.block in retained else len(evidence)
                capacity = (
                    total + added_evidence + added_metadata,
                    archived + (len(evidence) if snapshot.block in retained else 0),
                )
                if capacity[0] > self.config.maximum_cache_bytes:
                    self._report_capacity(*capacity)
                    raise RegistrationCacheFull("registration evidence cache is full")
                connection.execute(
                    "INSERT OR IGNORE INTO artifacts VALUES (?, ?)", (metadata_id, metadata)
                )
                connection.execute(
                    "INSERT INTO captures VALUES (?, ?, ?, ?, ?)",
                    (
                        snapshot.block,
                        snapshot.block_hash,
                        digest(snapshot),
                        capture.provenance["evidence_sha256"],
                        evidence,
                    ),
                )
            if cancelled is not None and cancelled.is_set():
                raise ValueError("registration persistence cancelled")
            self._fresh(capture.provenance["timestamp_ms"])
            connection.execute(
                "INSERT INTO observed_head VALUES (1, ?, ?) "
                "ON CONFLICT(singleton) DO UPDATE SET block=excluded.block, hash=excluded.hash",
                (height, block_hash),
            )
            connection.commit()
        finally:
            connection.close()
        if capacity is not None:
            self._report_capacity(*capacity)

    def _report_capacity(self, working_bytes: int, archived_bytes: int) -> None:
        """Warn on pressure transitions without exposing paths or proof contents."""
        try:
            disk = shutil.disk_usage(self._path.parent)
        except OSError:
            _LOGGER.warning("registration_storage_capacity_unavailable")
            return  # A failed capacity probe must not invalidate a saved proof.
        state = (
            working_bytes * 5 >= self.config.maximum_cache_bytes * 4,
            disk.free < max(1024**3, disk.total // 5),
        )
        if state != self._capacity_warning_state and any(state):
            _LOGGER.warning(
                "registration_storage_pressure working_bytes=%d working_limit_bytes=%d "
                "archived_bytes=%d disk_free_bytes=%d cache_pressure=%s disk_pressure=%s",
                working_bytes,
                self.config.maximum_cache_bytes,
                archived_bytes,
                disk.free,
                *state,
            )
        elif self._capacity_warning_state and any(self._capacity_warning_state) and not any(state):
            _LOGGER.info("registration_storage_pressure_recovered")
        self._capacity_warning_state = state


def _uint(value: Any, maximum: int) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError("registration storage integer is invalid")
    return value


def _hotkey(value: Any) -> str:
    import bittensor as bt

    if isinstance(value, str) and value.startswith("0x"):
        value = bytes.fromhex(value[2:])
    account = account_id32(value)
    if account == bytes(32):
        raise ValueError("registration hotkey is empty")
    return bt.sp_core.ss58_encode(account, 42)
