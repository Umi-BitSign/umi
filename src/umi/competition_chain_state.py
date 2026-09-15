"""Owned finality and proof-backed state for successor weight calls.

The returned capability is process-local. Serialized status is evidence, not an
authority token. Epoch-keyed commit-map absence is deliberately not inferred
from a finite set of membership proofs.
"""

from __future__ import annotations

import asyncio
import fcntl
import hashlib
import json
import os
import re
import stat
import time
import weakref
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace

from .chain_evidence import FinalizedSnapshotRef
from .competition_chain import FinalizedRegistrationProvider, _AwaitingFinality, _hotkey, _uint
from .competition_worker import (
    CompetitionReplayWorker,
    _open_directory_without_links,
    _prepare_private_directory,
    _verify_sqlite_family,
)
from .encoding import account_id32
from .grandpa_finality import FINNEY_GENESIS_HASH
from .grandpa_finality_supervisor import (
    GrandpaFinalitySupervisorError,
    GrandpaFinalitySupervisorLimits,
)
from .open_competition import Registration, digest
from .protocol import canonical_json_bytes
from .simple_bootstrap_validator import _manifest_anchor_state
from .substrate_proof import SubprocessStorageProofVerifier
from .validator_chain import (
    BittensorRawJsonRpc,
    FinalizedProofCollector,
    PinnedRuntimeContext,
    ProofCollectionLimits,
    StorageReadSpec,
    ValidatorChainError,
    VerifiedStorageBatch,
)

_ISSUER = object()
_MAX_EVIDENCE_BYTES = 32 * 1024**2
_MAX_CACHE_NAMESPACES = 32
_CACHE_RESERVE_BYTES = 128 * 1024
_CACHE_DATABASE_FILES = frozenset(
    name + suffix
    for name in ("registrations.sqlite3", "finality.sqlite3")
    for suffix in ("", "-wal", "-shm", "-journal")
)
_CACHE_BUDGET_FILE = "namespace-budget.json"
_CACHE_LOCK_FILE = "namespace.lock"
_CACHE_NAMESPACE = re.compile(r"^[0-9a-f]{64}$")


def _cache_file_info(directory: int, name: str, *, budget: bool = False):
    descriptor = os.open(
        name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory
    )
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != (0o400 if budget else 0o600)
        ):
            raise ValueError("weight cache contains an unsafe file")
        return info.st_size
    finally:
        os.close(descriptor)


def _cache_budget(directory: int, namespace: str, maximum_bytes: int) -> int:
    descriptor = os.open(
        _CACHE_BUDGET_FILE,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
        dir_fd=directory,
    )
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o400
            or not 0 < info.st_size <= 512
        ):
            raise ValueError("weight cache namespace budget is malformed")
        payload = os.read(descriptor, 513)
    finally:
        os.close(descriptor)
    record = json.loads(payload)
    if (
        not isinstance(record, dict)
        or canonical_json_bytes(record) != payload
        or set(record) != {"schema", "configuration_sha256", "maximum_namespace_bytes"}
        or record["schema"] != "umi-competition-weight-cache-budget/1"
        or record["configuration_sha256"] != namespace
        or type(record["maximum_namespace_bytes"]) is not int
        or not 2 * _CACHE_RESERVE_BYTES < record["maximum_namespace_bytes"] <= maximum_bytes
    ):
        raise ValueError("weight cache namespace budget binding is invalid")
    return record["maximum_namespace_bytes"]


def _cache_usage(root: Path, maximum_bytes: int) -> dict[str, int]:
    """Bound and account every entry, including retained pre-namespace databases."""
    root_fd = _open_directory_without_links(root)
    usage = {"legacy": 0}
    try:
        with os.scandir(root_fd) as entries:
            for entry in entries:
                name = entry.name
                if name in _CACHE_DATABASE_FILES or name == _CACHE_LOCK_FILE:
                    usage["legacy"] += _cache_file_info(root_fd, name)
                elif _CACHE_NAMESPACE.fullmatch(name):
                    if len(usage) > _MAX_CACHE_NAMESPACES:
                        raise ValueError("weight cache namespace count is exhausted")
                    directory = os.open(
                        name,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=root_fd,
                    )
                    try:
                        info = os.fstat(directory)
                        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                            raise ValueError("weight cache namespace is not private")
                        subtotal, names = 0, set()
                        with os.scandir(directory) as children:
                            for child in children:
                                if child.name not in _CACHE_DATABASE_FILES | {_CACHE_BUDGET_FILE}:
                                    raise ValueError(
                                        "weight cache namespace contains an unknown entry"
                                    )
                                names.add(child.name)
                                subtotal += _cache_file_info(
                                    directory, child.name, budget=child.name == _CACHE_BUDGET_FILE
                                )
                                if subtotal > maximum_bytes:
                                    raise ValueError(
                                        "weight cache aggregate byte budget is exhausted"
                                    )
                        if _CACHE_BUDGET_FILE not in names:
                            raise ValueError("weight cache namespace is incomplete; preserve it")
                        if subtotal > _cache_budget(directory, name, maximum_bytes):
                            raise ValueError("weight cache namespace byte budget is exhausted")
                        usage[name] = subtotal
                    finally:
                        os.close(directory)
                else:
                    raise ValueError("weight cache root contains an unknown entry")
                if sum(usage.values()) > maximum_bytes:
                    raise ValueError("weight cache aggregate byte budget is exhausted")
        return usage
    finally:
        os.close(root_fd)


@dataclass(frozen=True, slots=True)
class OwnedCompetitionChainObservation:
    snapshot: FinalizedSnapshotRef
    timestamp_ms: int
    validator_hotkey: str
    validator_uid: int
    validator_permit: bool
    validator_last_update: int
    validator_nonce: int
    registered_uid_count: int
    validator_row: tuple[tuple[int, int], ...]
    registrations: tuple[Registration, ...]
    mechanism_count: int
    commit_reveal_enabled: bool
    weights_version_key: int
    min_allowed_weights: int
    max_allowed_uids: int
    max_weights_limit: int
    weights_rate_limit: int
    manifest_anchor_sha256: str | None
    manifest_anchor_block: int | None
    chain_config_sha256: str
    captured_monotonic_ns: int
    expires_monotonic_ns: int
    runtime: PinnedRuntimeContext = field(repr=False)
    evidence: bytes = field(repr=False)
    _issuer: object = field(default=None, repr=False, compare=False)
    _binding: str = field(default="", repr=False, compare=False)

    @property
    def block(self) -> int:
        return self.snapshot.block_number

    @property
    def block_hash(self) -> str:
        return self.snapshot.block_hash

    @property
    def genesis_hash(self) -> str:
        return "0x" + FINNEY_GENESIS_HASH

    @property
    def pending_commitments(self) -> None:
        return None  # No exhaustive map-absence proof was collected.

    @property
    def evidence_sha256(self) -> str:
        return hashlib.sha256(self.evidence).hexdigest()


def _binding(observation: OwnedCompetitionChainObservation) -> str:
    values = {
        name: getattr(observation, name)
        for name in observation.__dataclass_fields__
        if name not in {"runtime", "evidence", "_issuer", "_binding", "snapshot"}
    }
    values["registrations"] = [item.model_dump(mode="json") for item in observation.registrations]
    values["captured_monotonic_ns"] = str(observation.captured_monotonic_ns)
    values["expires_monotonic_ns"] = str(observation.expires_monotonic_ns)
    values["snapshot"] = {
        "block": observation.block,
        "hash": observation.block_hash,
        "root": observation.snapshot.state_root,
        "parent": observation.snapshot.parent_hash,
    }
    values["evidence_sha256"] = observation.evidence_sha256
    values["runtime_metadata_sha256"] = observation.runtime.metadata_sha256
    values["runtime_version_sha256"] = hashlib.sha256(
        observation.runtime.runtime_version_bytes
    ).hexdigest()
    return hashlib.sha256(canonical_json_bytes(values)).hexdigest()


def validate_owned_weight_observation(observation: OwnedCompetitionChainObservation) -> None:
    if (
        type(observation) is not OwnedCompetitionChainObservation
        or observation._issuer is not _ISSUER
        or observation._binding != _binding(observation)
        or observation.runtime.snapshot != observation.snapshot
        or not observation.captured_monotonic_ns
        <= time.monotonic_ns()
        <= observation.expires_monotonic_ns
    ):
        raise ValueError("weight observation was not issued by the owned proof adapter")


class FinalizedCompetitionWeightProvider(FinalizedRegistrationProvider):
    """Use the existing pinned GRANDPA owner with bounded weight-state proofs.

    In-process port injections exist only for tests. Production configuration
    never accepts an observation JSON file or an alternative authority adapter.
    """

    def __init__(self, *args, **kwargs):
        self._cache_lease = None
        try:
            super().__init__(*args, **kwargs)
            self._configure_weight_collector()
        except BaseException:
            self._release_cache_lease()
            raise

    def _configure_weight_collector(self):
        # Weight/permit vectors exceed the intake provider's per-value limit.
        # Replace only this successor provider's collector, not historical code.
        if self._owned:
            self._prefetch = None
            self._proofs = FinalizedProofCollector(
                BittensorRawJsonRpc(SimpleNamespace(endpoint=self.config.rpc_url)),
                finality=self._finality,
                verifier=SubprocessStorageProofVerifier(
                    binary_path=self.config.proof_binary,
                    expected_sha256=self.config.proof_binary_sha256,
                ),
                limits=ProofCollectionLimits(
                    maximum_storage_value_bytes=64 * 1024,
                    maximum_storage_values_bytes=1024 * 1024,
                    maximum_proof_node_bytes=2 * 1024**2,
                    maximum_proof_bytes=8 * 1024**2,
                ),
            )

    def _release_cache_lease(self):
        if self._cache_lease is not None:
            self._cache_lease()
            self._cache_lease = None

    def _cache_directory(self, config):
        root = _prepare_private_directory(Path(config.state_directory), "weight finality state")
        root_fd = _open_directory_without_links(root)
        lock = None
        try:
            CompetitionReplayWorker._prepare_state_file(root_fd, _CACHE_LOCK_FILE)
            lock = os.open(
                _CACHE_LOCK_FILE, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root_fd
            )
            _cache_file_info(root_fd, _CACHE_LOCK_FILE)
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._cache_lease = weakref.finalize(self, os.close, lock)
            lock = None
            usage = _cache_usage(root, config.maximum_cache_bytes)
            namespace = digest(config)
            directory = root / namespace
            if namespace not in usage:
                if len(usage) - 1 >= _MAX_CACHE_NAMESPACES:
                    raise ValueError("weight cache namespace count is exhausted")
                available = config.maximum_cache_bytes - sum(usage.values())
                if available <= 2 * _CACHE_RESERVE_BYTES:
                    raise ValueError("weight cache aggregate byte budget is exhausted")
                os.mkdir(namespace, 0o700, dir_fd=root_fd)
                budget = canonical_json_bytes(
                    {
                        "schema": "umi-competition-weight-cache-budget/1",
                        "configuration_sha256": namespace,
                        "maximum_namespace_bytes": available,
                    }
                )
                child = _open_directory_without_links(directory)
                try:
                    descriptor = os.open(
                        _CACHE_BUDGET_FILE,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                        0o400,
                        dir_fd=child,
                    )
                    try:
                        view = memoryview(budget)
                        while view:
                            written = os.write(descriptor, view)
                            if written <= 0:
                                raise OSError("weight cache budget write failed")
                            view = view[written:]
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
                    os.fsync(child)
                finally:
                    os.close(child)
                os.fsync(root_fd)
            child = _open_directory_without_links(directory)
            try:
                self._namespace_budget = _cache_budget(child, namespace, config.maximum_cache_bytes)
                # The persisted ceiling never grows. Under this root-exclusive
                # lease, other namespaces cannot grow; only the remaining
                # aggregate capacity may be used by this open instance.
                other = sum(size for name, size in usage.items() if name != namespace)
                self._namespace_budget = min(
                    self._namespace_budget, config.maximum_cache_bytes - other
                )
                if self._namespace_budget <= 2 * _CACHE_RESERVE_BYTES:
                    raise ValueError("retained weight namespaces exhaust aggregate capacity")
                for name in ("registrations.sqlite3", "finality.sqlite3"):
                    CompetitionReplayWorker._prepare_state_file(child, name)
                    _verify_sqlite_family(directory / name, "weight finality cache")
            finally:
                os.close(child)
            self._cache_root, self._cache_namespace = root, namespace
            return directory
        finally:
            if lock is not None:
                os.close(lock)
            os.close(root_fd)

    def _finality_storage_limits(self):
        maximum = self._namespace_budget - _CACHE_RESERVE_BYTES
        return GrandpaFinalitySupervisorLimits(
            maximum_evidence_bytes=min(4 * 1024**2, maximum // 2),
            maximum_total_evidence_bytes=maximum // 2,
            maximum_database_bytes=maximum,
        )

    async def aclose(self):
        try:
            await super().aclose()
        finally:
            self._release_cache_lease()

    async def collect(self):
        raise ValueError("weight collection needs an explicit validator and recipients")

    async def wait_weights_ready(
        self,
        validator_hotkey: str,
        recipients: tuple[Registration, ...],
    ) -> OwnedCompetitionChainObservation:
        """Retry only initial observer warm-up, not proof or transport failures."""

        async def capture():
            while True:
                if self._owned and self._task is not None and self._task.done():
                    self._task.result()
                try:
                    return await self.collect_weights(validator_hotkey, recipients)
                except _AwaitingFinality:
                    pass
                except ValidatorChainError as error:
                    if not (
                        error.reason_code == "owned_finality_unavailable"
                        and type(error.__cause__) is GrandpaFinalitySupervisorError
                        and error.__cause__.reason_code == "no_verified_finalized_head"
                    ):
                        raise
                await asyncio.sleep(0.25)

        try:
            return await asyncio.wait_for(capture(), self.config.startup_timeout_seconds)
        except asyncio.TimeoutError as error:
            raise ValueError("weight finality startup timed out") from error

    async def collect_weights(
        self,
        validator_hotkey: str,
        recipients: tuple[Registration, ...],
        *,
        manifest_anchor_sha256: str | None = None,
    ) -> OwnedCompetitionChainObservation:
        if self._closed:
            raise ValueError("weight provider is closed")
        _cache_usage(self._cache_root, self.config.maximum_cache_bytes)
        validator_hotkey = _hotkey(validator_hotkey)
        recipients = tuple(
            Registration.model_validate_json(canonical_json_bytes(item)) for item in recipients
        )
        if len(recipients) > 256 or len({item.uid for item in recipients}) != len(recipients):
            raise ValueError("weight recipients are duplicated or unbounded")
        if manifest_anchor_sha256 is not None and (
            len(manifest_anchor_sha256) != 64
            or any(char not in "0123456789abcdef" for char in manifest_anchor_sha256)
        ):
            raise ValueError("invalid expected manifest anchor")
        return await asyncio.wait_for(
            self._collect_weights_locked(validator_hotkey, recipients, manifest_anchor_sha256),
            timeout=self.config.collection_timeout_seconds,
        )

    async def _collect_weights_locked(self, hotkey, recipients, anchor):
        async with self._lock:
            if self._owned and (self._task is None or self._task.done()):
                raise ValueError("owned finality observer is not running")
            ref = await self._proofs.finalized_snapshot()
            if not isinstance(ref, FinalizedSnapshotRef):
                raise ValueError("weight finalized snapshot is invalid")
            if ref.block_number < self.config.minimum_finalized_block or (
                self._owned and ref.block_number <= self._startup_floor
            ):
                raise _AwaitingFinality("awaiting a head verified by this observer process")
            block = await self._finality.verified_block_at(ref.block_number)
            self._check_finality(ref, block)
            self._fresh(block.timestamp_ms)
            runtime = await self._proofs.pinned_runtime(ref, self._runtime_pin)
            if not isinstance(runtime, PinnedRuntimeContext) or (
                runtime.snapshot != ref or runtime.pin != self._runtime_pin
            ):
                raise ValueError("weight runtime binding mismatch")
            specs = (
                StorageReadSpec("Timestamp", "Now"),
                StorageReadSpec("SubtensorModule", "NetworksAdded", (78,)),
                StorageReadSpec("SubtensorModule", "Uids", (78, hotkey)),
                StorageReadSpec("SubtensorModule", "ValidatorPermit", (78,)),
                StorageReadSpec("SubtensorModule", "LastUpdate", (78,)),
                StorageReadSpec("SubtensorModule", "MechanismCountCurrent", (78,)),
                StorageReadSpec("SubtensorModule", "CommitRevealWeightsEnabled", (78,)),
                StorageReadSpec("SubtensorModule", "WeightsVersionKey", (78,)),
                StorageReadSpec("SubtensorModule", "MinAllowedWeights", (78,)),
                StorageReadSpec("SubtensorModule", "MaxAllowedUids", (78,)),
                StorageReadSpec("SubtensorModule", "MaxWeightsLimit", (78,)),
                StorageReadSpec("SubtensorModule", "WeightsSetRateLimit", (78,)),
                StorageReadSpec("System", "Account", (hotkey,)),
                StorageReadSpec("Commitments", "CommitmentOf", (78, hotkey)),
                StorageReadSpec("SubtensorModule", "SubnetworkN", (78,)),
            )
            base = await self._weight_read(runtime, specs)
            values = [read.decoded_value for read in base.reads]
            # Collectors need not preserve requested order.
            by_spec = {read.spec: read.decoded_value for read in base.reads}
            values = [by_spec[spec] for spec in specs]
            if type(values[0]) is not int or values[0] != block.timestamp_ms:
                raise ValueError("weight proven timestamp mismatch")
            if values[1] is not True:
                raise ValueError("SN78 is unavailable")
            uid = _uint(values[2], 255)
            permits, updates = values[3:5]
            if (
                not isinstance(permits, (list, tuple))
                or not isinstance(updates, (list, tuple))
                or not uid < len(permits) <= 256
                or not uid < len(updates) <= 256
                or any(type(item) is not bool for item in permits)
            ):
                raise ValueError("invalid permit or LastUpdate vector")
            last = _uint(updates[uid], ref.block_number)
            if type(values[6]) is not bool:
                raise ValueError("invalid commit reveal flag")
            account = values[12]
            if not isinstance(account, dict) or "nonce" not in account:
                raise ValueError("proof-backed validator nonce is unavailable")
            nonce = _uint(account["nonce"], 2**32 - 1)
            registered_uid_count = _uint(values[14], 256)
            if uid >= registered_uid_count:
                raise ValueError("validator UID exceeds finalized registration count")
            all_registrations = {uid: Registration(uid=uid, hotkey=hotkey)}
            for item in recipients:
                if item.uid in all_registrations and (
                    account_id32(item.hotkey) != account_id32(all_registrations[item.uid].hotkey)
                ):
                    raise ValueError("validator/recipient mapping collision")
                all_registrations[item.uid] = item
            mapping_specs = tuple(
                spec
                for item in sorted(all_registrations.values(), key=lambda entry: entry.uid)
                for spec in (
                    StorageReadSpec("SubtensorModule", "Keys", (78, item.uid)),
                    StorageReadSpec("SubtensorModule", "Uids", (78, item.hotkey)),
                )
            )
            # Maximum 512 mapping keys, plus the row in a separate proof batch.
            mappings = await self._weight_read(runtime, mapping_specs)
            mv = {read.spec: read.decoded_value for read in mappings.reads}
            for item in all_registrations.values():
                if (
                    account_id32(
                        _hotkey(mv[StorageReadSpec("SubtensorModule", "Keys", (78, item.uid))])
                    )
                    != account_id32(item.hotkey)
                    or _uint(mv[StorageReadSpec("SubtensorModule", "Uids", (78, item.hotkey))], 255)
                    != item.uid
                ):
                    raise ValueError("recipient or validator registration changed")
            row_batch = await self._weight_read(
                runtime, (StorageReadSpec("SubtensorModule", "Weights", (78, uid)),)
            )
            raw_row = row_batch.reads[0].decoded_value
            if not isinstance(raw_row, (list, tuple)) or len(raw_row) > 256:
                raise ValueError("invalid proven weight row")
            if any(not isinstance(pair, (tuple, list)) or len(pair) != 2 for pair in raw_row):
                raise ValueError("invalid proven weight row entry")
            row = tuple((_uint(pair[0], 255), _uint(pair[1], 65535)) for pair in raw_row)
            if tuple(sorted(row)) != row or (len({pair[0] for pair in row}) != len(row)):
                raise ValueError("proven weight row is noncanonical")
            newest = await self._finality.verified_finalized_snapshot()
            if (
                newest.block_number < ref.block_number
                or (newest.block_number == ref.block_number and newest != ref)
                or newest.block_number - ref.block_number > self.policy.maximum_snapshot_age_blocks
            ):
                raise ValueError("weight finality rolled back, changed or became stale")
            anchor_block = None
            if anchor is not None:
                anchor_block, _ = _manifest_anchor_state(values[13], anchor)
            evidence = canonical_json_bytes(
                {
                    "schema": "umi-competition-weight-state-evidence/1",
                    "config_sha256": digest(self.config),
                    "block": ref.block_number,
                    "block_hash": ref.block_hash,
                    "state_root": ref.state_root,
                    "finality": json.loads(block.finality_evidence),
                    "runtime_metadata_sha256": runtime.metadata_sha256,
                    "runtime_version": json.loads(runtime.runtime_version_bytes),
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
                        for batch in (base, mappings, row_batch)
                    ],
                    "pending_commitment_absence_proven": False,
                }
            )
            if len(evidence) > _MAX_EVIDENCE_BYTES:
                raise ValueError("weight evidence exceeds its byte bound")
            _cache_usage(self._cache_root, self.config.maximum_cache_bytes)
            self._fresh(block.timestamp_ms)
            observation = OwnedCompetitionChainObservation(
                snapshot=ref,
                timestamp_ms=block.timestamp_ms,
                validator_hotkey=hotkey,
                validator_uid=uid,
                validator_permit=permits[uid],
                validator_last_update=last,
                validator_nonce=nonce,
                registered_uid_count=registered_uid_count,
                validator_row=row,
                registrations=tuple(
                    sorted(all_registrations.values(), key=lambda entry: entry.uid)
                ),
                mechanism_count=_uint(values[5], 255),
                commit_reveal_enabled=values[6],
                weights_version_key=_uint(values[7], 2**64 - 1),
                min_allowed_weights=_uint(values[8], 65535),
                max_allowed_uids=_uint(values[9], 65535),
                max_weights_limit=_uint(values[10], 65535),
                weights_rate_limit=_uint(values[11], 2**64 - 1),
                manifest_anchor_sha256=anchor if anchor_block is not None else None,
                manifest_anchor_block=anchor_block,
                chain_config_sha256=digest(self.config),
                runtime=runtime,
                evidence=evidence,
                captured_monotonic_ns=time.monotonic_ns(),
                expires_monotonic_ns=time.monotonic_ns()
                + max(0, block.timestamp_ms + self.config.maximum_head_age_ms - self._now_ms())
                * 1_000_000,
                _issuer=_ISSUER,
            )
            object.__setattr__(observation, "_binding", _binding(observation))
            return observation

    async def _weight_read(self, runtime, specs) -> VerifiedStorageBatch:
        batch = await self._proofs.storage_reads(runtime, specs)
        if (
            not isinstance(batch, VerifiedStorageBatch)
            or batch.runtime != runtime
            or (len(batch.reads) != len(specs) or {read.spec for read in batch.reads} != set(specs))
        ):
            raise ValueError("weight proof batch binding or coverage mismatch")
        # Default and Optional absent values are decoded by pinned metadata,
        # not replaced by hand-written defaults. Their absence is trie-proven.
        return batch
