"""Bounded spawned native history workers; no network or owner-state access.

Only the parent selects authenticated block identities. Requests carry immutable
proof bytes and compact context, never owner databases, RPC clients or keys.
Cancellation drains started native operations before worker shutdown.
"""

from __future__ import annotations

import asyncio
import hashlib
import multiprocessing
import os
import secrets
import signal
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .chain_evidence import FinalizedSnapshotRef
from .competition_reward_control_evidence import (
    MAX_CONTROL_ARCHIVE_BYTES,
    MAX_CONTROL_METADATA_BYTES,
    _Archive,
)
from .competition_reward_history_effects import MAX_WRITE_EVIDENCE_BYTES, control_block_identity
from .competition_reward_history_verifier import (
    HistoryProofTools,
    verify_slot_archive,
    verify_write_archive,
)
from .competition_reward_write_evidence import _WriteArchive
from .competition_verification_rules import runtime_identity
from .concurrency import run_owned_thread
from .encoding import account_id32
from .native_process_group import owned_native_process_group
from .open_competition import digest
from .protocol import StrictProtocolModel
from .runtime_metadata import RuntimeMetadataExecutor
from .substrate_proof import SubprocessStorageProofVerifier, SubstrateProofLimits
from .validator_chain import FinalizedProofCollector, FinalizedRuntimePin, ProofCollectionLimits

MAX_FRAME_BYTES = MAX_CONTROL_ARCHIVE_BYTES + MAX_CONTROL_METADATA_BYTES + MAX_WRITE_EVIDENCE_BYTES


class HistoryVerificationProfile(StrictProtocolModel):
    """Explicit local capacity selection, independent of signed cohort clocks.

    Older installations omit the profile and retain the serial reader. The byte
    window always admits a maximum supported frame; capacity changes concurrency,
    never the accepted evidence size or the completed prefix.
    """

    schema_: Literal["umi-history-verification-profile/1"] = Field(alias="schema")
    workers: Annotated[int, Field(strict=True, ge=1, le=32)] = 2
    maximum_in_flight: Annotated[int, Field(strict=True, ge=1, le=64)] = 2
    maximum_in_flight_bytes: Annotated[int, Field(strict=True, ge=MAX_FRAME_BYTES)] = (
        2 * MAX_FRAME_BYTES
    )

    @model_validator(mode="after")
    def capacity(self):
        if self.maximum_in_flight < self.workers:
            raise ValueError("history window must admit every selected worker")
        return self

    @property
    def required_memory_bytes(self):
        # Account parent/raw/IPC copies, parsed JSON/SCALE graphs and native
        # subprocess peaks. A selected host policy must qualify this whole
        # reservation, not multiply leases inside an existing stage lease.
        return self.workers * 512 * 1024**2 + 16 * self.maximum_in_flight_bytes


@dataclass(frozen=True, slots=True)
class HistoryWorkerSelection:
    pin: FinalizedRuntimePin
    storage_codec: bool
    proof_binary: str
    proof_sha256: str
    native_proof_limits: SubstrateProofLimits
    proof_timeout_seconds: float
    proof_limits: ProofCollectionLimits
    runtime_proof_limits: ProofCollectionLimits | None
    executor_binary: str | None
    executor_sha256: str | None
    executor_timeout_seconds: float | None
    genesis_hash: str
    finality_sha256: str
    config_sha256: str
    hotkey: str
    semantics: str

    @classmethod
    def from_provider(cls, provider, hotkey):
        verifier = provider._proofs._verifier
        if type(verifier) is not SubprocessStorageProofVerifier:
            raise TypeError("spawned history requires the installed native proof verifier")
        executor = provider._runtime_executor
        return cls(
            provider._runtime_pin,
            provider._storage_codec is not None,
            str(provider.resources.proof_binary),
            provider.config.proof_binary_sha256,
            verifier._limits,
            verifier._timeout_seconds,
            provider._proofs._limits,
            None if executor is None else provider._runtime_proofs._limits,
            None if executor is None else str(provider.resources.runtime_metadata_binary),
            provider.config.runtime_metadata_binary_sha256,
            None if executor is None else executor.timeout_seconds,
            "0x" + provider.config.chain_pin.genesis_block_hash,
            provider.config.finality_pin.release_sha256_by_target[provider.config.target_triple],
            digest(provider.config),
            hotkey,
            runtime_identity(),
        )

    @property
    def identity(self):
        return digest(asdict(self))


@dataclass(frozen=True, slots=True)
class HistoryWork:
    request_id: str
    selection_sha256: str
    snapshot: FinalizedSnapshotRef
    header: str
    timestamp: int | None
    ceiling: int
    slot_evidence: bytes
    slot_metadata: bytes
    evidence: bytes


@dataclass(frozen=True, slots=True)
class HistoryWorkResult:
    request_id: str
    selection_sha256: str
    snapshot: FinalizedSnapshotRef
    header: str
    timestamp: int
    control_sha256: str | None
    committed_at_block: int | None
    slot_evidence_sha256: str
    slot_metadata_sha256: str
    write_evidence_sha256: str
    writes: tuple[tuple[int, str], ...]
    unresolved_extrinsics: tuple[int, ...]
    elapsed_seconds: float


@dataclass(frozen=True, slots=True)
class _Failure:
    request_id: str
    selection_sha256: str
    error_type: str


class HistoryWorkerError(RuntimeError):
    pass


class _Unavailable:
    async def request(self, *_):
        raise RuntimeError("offline history cannot access RPC")

    async def verified_finalized_snapshot(self):
        raise RuntimeError("offline history cannot establish finality")


_selection: HistoryWorkerSelection | None = None
_tools: HistoryProofTools | None = None


def _initialize_worker(selection: HistoryWorkerSelection):
    global _selection, _tools
    if runtime_identity() != selection.semantics:
        raise RuntimeError("spawned history verifier semantics differ from owner")
    unavailable = _Unavailable()
    verifier = SubprocessStorageProofVerifier(
        binary_path=Path(selection.proof_binary),
        expected_sha256=selection.proof_sha256,
        limits=selection.native_proof_limits,
        timeout_seconds=selection.proof_timeout_seconds,
    )
    proofs = FinalizedProofCollector(
        unavailable, finality=unavailable, verifier=verifier, limits=selection.proof_limits
    )
    runtime_proofs = executor = None
    if selection.executor_binary is not None:
        executor = RuntimeMetadataExecutor(
            binary_path=Path(selection.executor_binary),
            expected_sha256=selection.executor_sha256,
            timeout_seconds=selection.executor_timeout_seconds,
        )
        runtime_proofs = FinalizedProofCollector(
            unavailable,
            finality=unavailable,
            verifier=verifier,
            limits=selection.runtime_proof_limits,
        )
    _selection = selection
    _tools = HistoryProofTools(
        proofs,
        runtime_proofs,
        executor,
        selection.pin,
        selection.storage_codec,
        selection.executor_sha256,
    )


async def _verify_work(work: HistoryWork) -> HistoryWorkResult:
    started = time.monotonic()
    selection, tools = _selection, _tools
    if selection is None or tools is None or work.selection_sha256 != selection.identity:
        raise ValueError("history work differs from selected native context")
    slot = _Archive(work.slot_evidence, work.slot_metadata)
    if (
        (slot.snapshot, slot.encoded) != (work.snapshot, work.header)
        or slot.body["finality"].get("genesis_hash") != selection.genesis_hash
        or account_id32(slot.hotkey) != account_id32(selection.hotkey)
    ):
        raise ValueError("history work differs from authenticated owner selection")
    runtime, actual_time, control, committed = await verify_slot_archive(
        slot, tools, timestamp=work.timestamp, ceiling=work.ceiling
    )
    archive = _WriteArchive(work.evidence)
    if slot.evidence_sha256 != archive.body["slot_evidence_sha256"]:
        raise ValueError("control write archive names another slot proof")
    identity = control_block_identity(
        work.snapshot,
        archive.body["header"],
        archive.body["parent_header"],
        slot_header=work.header,
        finality_sha256=selection.finality_sha256,
        evidence_sha256=slot.evidence_sha256,
    )
    writes, unresolved = await verify_write_archive(
        archive, tools, identity, hotkey=slot.hotkey, control=control, committed=committed
    )
    return HistoryWorkResult(
        work.request_id,
        work.selection_sha256,
        work.snapshot,
        work.header,
        actual_time,
        control,
        committed,
        slot.evidence_sha256,
        runtime.metadata_sha256,
        hashlib.sha256(work.evidence).hexdigest(),
        tuple((w.extrinsic_index, w.decision_sha256) for w in writes),
        unresolved,
        time.monotonic() - started,
    )


def _run_worker(work: HistoryWork):
    try:
        return asyncio.run(_verify_work(work))
    except Exception as error:
        # Do not pickle traceback-owned proof graphs or provider diagnostics.
        return _Failure(work.request_id, work.selection_sha256, type(error).__name__)


def _worker_main(connection, selection, initializer, initializer_args):
    os.setsid()
    try:
        with owned_native_process_group():
            initializer(selection, *initializer_args)
            connection.send("ready")
            while True:
                work = connection.recv()
                if work is None:
                    return
                connection.send(_run_worker(work))
    finally:
        connection.close()


class _SpawnWorker:
    """A single owned process; a failed peer cannot terminate this worker."""

    def __init__(self, selection, *, initializer=_initialize_worker, initializer_args=()):
        context = multiprocessing.get_context("spawn")
        self.connection, child = context.Pipe()
        self.process = context.Process(
            target=_worker_main, args=(child, selection, initializer, initializer_args)
        )
        self._child = child
        self._lock = threading.Lock()
        self._started = self._ready = self._closed = False

    def _reap_failed(self):
        # Do this before join()/is_alive()/exitcode: those can reap the child
        # and release its PID for reuse. The retained child identity owns this
        # process group, including Rust tools left behind by abrupt worker exit.
        if self._ready:
            with suppress(ProcessLookupError):
                os.killpg(self.process.pid, signal.SIGKILL)
        elif self._started:
            with suppress(ProcessLookupError):
                self.process.kill()
        if self._started:
            self.process.join()
        self.connection.close()
        self._child.close()
        self._closed = True

    def run(self, work):
        with self._lock:
            if self._closed:
                raise HistoryWorkerError("native history worker is closed")
            try:
                if not self._started:
                    self.process.start()
                    self._started = True
                    self._child.close()
                    if self.connection.recv() != "ready":
                        raise HistoryWorkerError("native history worker did not initialize")
                    self._ready = True
                self.connection.send(work)
                return self.connection.recv()
            except (EOFError, BrokenPipeError, OSError):
                self._reap_failed()
                raise HistoryWorkerError("native history worker process exited") from None

    def close(self):
        with self._lock:
            if self._closed:
                return
            if not self._started:
                self.connection.close()
                self._child.close()
                self._closed = True
                return
            try:
                self.connection.send(None)
            except (EOFError, BrokenPipeError, OSError):
                self._reap_failed()
                return
            self.process.join()
            self.connection.close()
            self._closed = True


class _SpawnPool:
    def __init__(self, workers, selection):
        self.workers = [_SpawnWorker(selection) for _ in range(workers)]
        self._threads = ThreadPoolExecutor(max_workers=workers)
        self._next = 0

    def submit(self, work):
        worker = self.workers[self._next % len(self.workers)]
        self._next += 1
        return self._threads.submit(worker.run, work)

    def close(self):
        # No peer is forcibly terminated after a worker error. Each started
        # invocation finishes or reports its own process death before shutdown.
        self._threads.shutdown(wait=True)
        for worker in self.workers:
            worker.close()


class HistoryWorkers:
    """One bounded window owns all futures through checkpointing and drain."""

    def __init__(self, profile: HistoryVerificationProfile, selection: HistoryWorkerSelection):
        self.profile, self.selection = profile, selection
        self._pool = _SpawnPool(profile.workers, selection)
        self._pending: dict[asyncio.Future, HistoryWork] = {}
        self._bytes = 0
        self._closed = False
        self.session = secrets.token_hex(32)

    def submit(self, *, snapshot, header, timestamp, ceiling, fields):
        size = sum(map(len, fields.values()))
        if (
            self._closed
            or len(self._pending) >= self.profile.maximum_in_flight
            or (self._bytes + size > self.profile.maximum_in_flight_bytes)
        ):
            raise RuntimeError("history worker window has no admitted capacity")
        work = HistoryWork(
            self.session + secrets.token_hex(16),
            self.selection.identity,
            snapshot,
            header,
            timestamp,
            ceiling,
            **fields,
        )
        future = asyncio.wrap_future(self._pool.submit(work))
        self._pending[future] = work
        self._bytes += size
        return future

    def result(self, future):
        work = self._pending[future]
        result = future.result()
        if isinstance(result, _Failure):
            raise HistoryWorkerError("native history worker failed: " + result.error_type)
        if (
            type(result) is not HistoryWorkResult
            or (result.request_id, result.selection_sha256, result.snapshot, result.header)
            != (work.request_id, work.selection_sha256, work.snapshot, work.header)
            or not 0 < result.timestamp <= work.ceiling
            or (work.timestamp is not None and result.timestamp != work.timestamp)
        ):
            raise HistoryWorkerError("native history result differs from private invocation")
        return result

    def release(self, future):
        work = self._pending.pop(future)
        self._bytes -= len(work.slot_evidence) + len(work.slot_metadata) + len(work.evidence)

    async def close(self):
        self._closed = True
        # The parent retains ownership through native drain and group cleanup.
        await run_owned_thread(self._pool.close)
        self._pending.clear()
        self._bytes = 0
