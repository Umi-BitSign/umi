"""Durable successor supervision under the original host process lock.

The installation capability comes from the root-owned activation loader. OS,
artifact and transaction-recovery adapters are in-process implementation ports,
not plugin names or JSON authority. There is no legacy worker start path.
"""

from __future__ import annotations

import asyncio
import errno
import fcntl
import hashlib
import os
import sqlite3
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Any, Literal, Protocol

from pydantic import Field, model_validator
from typing_extensions import Self

from .competition_chain_state import (
    OwnedCompetitionChainObservation,
    validate_owned_weight_observation,
)
from .competition_supervisor import (
    MAX_SUCCESSOR_DOCUMENT_BYTES,
    MAX_SUCCESSOR_HISTORY_BYTES,
    SignedSuccessorSupervisorDirective,
    SuccessorSupervisorDirectiveState,
    advance_successor_supervisor_directive_history_state,
    advance_successor_supervisor_directive_state,
    parse_canonical_signed_successor_supervisor_directive,
    parse_canonical_successor_supervisor_directive_history,
    parse_canonical_successor_supervisor_directive_page,
    parse_canonical_successor_supervisor_state,
    successor_continuation_bytes,
    successor_operator_consent_sha256,
    successor_source_config_sha256,
    verify_signed_successor_supervisor_directive,
    verify_signed_successor_supervisor_directive_history,
)
from .competition_worker import (
    _open_directory_without_links,
    _open_private_regular_file,
    _prepare_private_directory,
    _verify_private_directory,
    _verify_sqlite_family,
)
from .encoding import account_id32
from .protocol import BlockHash, Hex32, StrictProtocolModel, canonical_json_bytes
from .validator_supervisor import ValidatorSupervisorConfig


class SuccessorRuntimeError(ValueError):
    pass


_STARTUP_LEASE_ISSUER = object()
_MAX_STARTUP_LOCK_BYTES = 64 * 1024


@dataclass
class _StartupLeaseState:
    phase: str = "held"
    preserve: bool = False


@dataclass(frozen=True, slots=True)
class SuccessorStartupLease:
    """Scoped ownership of the original process lock, transferable exactly once."""

    config: ValidatorSupervisorConfig
    _anchor: Any = field(repr=False)
    _descriptor: int = field(repr=False)
    _identity: tuple[int, ...] = field(repr=False)
    _bytes: bytes = field(repr=False)
    _state: _StartupLeaseState = field(repr=False, compare=False)
    _issuer: object = field(default=None, repr=False, compare=False)
    _binding: str = field(default="", repr=False, compare=False)

    def recheck(self):
        _validate_startup_lease(self)

    def preserve_on_failure(self):
        # Retaining an already-owned descriptor grants no new authority and
        # must still work if another startup check has just detected corruption.
        _validate_startup_lease_token(self)
        self._state.preserve = True


def _startup_identity(info):
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_gid,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _startup_binding(lease):
    return hashlib.sha256(
        canonical_json_bytes(
            {
                "config": successor_source_config_sha256(lease.config),
                "receipt": lease._anchor.receipt_sha256,
                "descriptor": lease._descriptor,
                "state_identity": id(lease._state),
                "identity": [str(part) for part in lease._identity],
                "bytes": hashlib.sha256(lease._bytes).hexdigest(),
            }
        )
    ).hexdigest()


def _validate_startup_lease_token(lease):
    if (
        type(lease) is not SuccessorStartupLease
        or lease._issuer is not _STARTUP_LEASE_ISSUER
        or lease._state.phase != "held"
        or lease._binding != _startup_binding(lease)
    ):
        raise SuccessorRuntimeError("startup lease is absent, altered or already transferred")


def _validate_startup_lease(lease):
    _validate_startup_lease_token(lease)
    lease._anchor.recheck_for_parent_repair()
    _verify_private_directory(Path(lease.config.state_root), "supervisor state")
    path = Path(lease.config.state_root) / "supervisor-process.lock"
    named = _open_private_regular_file(path, "supervisor process lock")
    try:
        if (
            named == lease._descriptor
            or _startup_identity(os.fstat(named)) != lease._identity
            or _startup_identity(os.fstat(lease._descriptor)) != lease._identity
            or os.pread(lease._descriptor, _MAX_STARTUP_LOCK_BYTES + 1, 0) != lease._bytes
        ):
            raise SuccessorRuntimeError("startup process lock identity or bytes changed")
        try:
            fcntl.flock(named, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            pass
        else:
            fcntl.flock(named, fcntl.LOCK_UN)
            raise SuccessorRuntimeError("startup descriptor no longer holds its original lock")
    finally:
        os.close(named)
    expected = canonical_json_bytes(lease._anchor.v3_state)
    legacy = _open_private_regular_file(
        Path(lease.config.state_root) / "directive-state.json", "legacy high-water"
    )
    try:
        if (
            os.fstat(legacy).st_size != len(expected)
            or os.read(legacy, len(expected) + 1) != expected
        ):
            raise SuccessorRuntimeError("preserved v3 high-water changed during startup")
    finally:
        os.close(legacy)


@contextmanager
def hold_successor_startup_lease(anchor):
    """Hold the same OFD through repair, full loading and runtime adoption.

    This does not stop a container. Before repairing current, the caller must
    confirm exact worker absence. If that stop fails or is cancelled, call
    ``lease.preserve_on_failure()`` so this descriptor remains held until exit.
    """
    from .competition_host_anchor import MaterializedSuccessorAnchor

    if type(anchor) is not MaterializedSuccessorAnchor:
        raise SuccessorRuntimeError("startup requires a genuine root-owned anchor")
    anchor.recheck_for_parent_repair()
    config = _canonical(ValidatorSupervisorConfig, canonical_json_bytes(anchor.config))
    _verify_private_directory(Path(config.state_root), "supervisor state")
    descriptor = _open_private_regular_file(
        Path(config.state_root) / "supervisor-process.lock", "supervisor process lock"
    )
    lease = None
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        info = os.fstat(descriptor)
        payload = os.pread(descriptor, _MAX_STARTUP_LOCK_BYTES + 1, 0)
        if info.st_size > _MAX_STARTUP_LOCK_BYTES or len(payload) != info.st_size:
            raise SuccessorRuntimeError("startup process lock exceeds its byte bound")
        lease = SuccessorStartupLease(
            config,
            anchor,
            descriptor,
            _startup_identity(info),
            payload,
            _StartupLeaseState(),
            _STARTUP_LEASE_ISSUER,
        )
        object.__setattr__(lease, "_binding", _startup_binding(lease))
        lease.recheck()
        yield lease
    finally:
        if lease is None:
            os.close(descriptor)
        elif lease._state.phase == "held":
            if lease._state.preserve:
                lease._state.phase = "retained"
            else:
                lease._state.phase = "closed"
                try:
                    details = os.fstat(descriptor)
                except OSError as error:
                    if error.errno != errno.EBADF:
                        raise
                else:
                    if (details.st_dev, details.st_ino) != lease._identity[:2]:
                        raise SuccessorRuntimeError("startup descriptor was replaced before close")
                    os.close(descriptor)


def _adopt_startup_lease(lease, installation):
    _validate_startup_lease(lease)
    if (
        lease.config != installation.config
        or lease._anchor.receipt_sha256 != installation.receipt_sha256
    ):
        raise SuccessorRuntimeError("startup lease belongs to another installation")
    lease._state.phase = "transferred"
    return lease._descriptor


class SuccessorRuntimeLimits(StrictProtocolModel):
    maximum_history_records: Annotated[int, Field(ge=1, le=65536)]
    maximum_history_bytes: Annotated[int, Field(ge=1024, le=64 * 1024**2)]


@dataclass(frozen=True, slots=True)
class SuccessorWorkerSelection:
    """A signed fixed profile, never a command, mount list or wallet path."""

    signed: SignedSuccessorSupervisorDirective
    continuation_bytes: bytes | None = field(default=None, compare=False, repr=False)

    def __post_init__(self):
        parsed = parse_canonical_signed_successor_supervisor_directive(
            canonical_json_bytes(self.signed)
        )
        if parsed.directive.mode == "hold":
            raise SuccessorRuntimeError("hold has no worker selection")
        if self.continuation_bytes is not None:
            if not isinstance(self.continuation_bytes, bytes) or not (
                0 < len(self.continuation_bytes) <= MAX_SUCCESSOR_HISTORY_BYTES
            ):
                raise SuccessorRuntimeError("selection history exceeds its byte bound")
            history = parse_canonical_successor_supervisor_directive_history(
                self.continuation_bytes
            )
            if history.more or history.head != parsed:
                raise SuccessorRuntimeError("selection history does not end at its signed head")

    @property
    def directive_sha256(self) -> str:
        return self.signed.directive_sha256

    @property
    def mode(self) -> str:
        return self.signed.directive.mode


class SuccessorRuntimeAdapter(Protocol):
    """Fixed production adapter boundary, supplied by host code only.

    Stage verifies signed release bytes, exact package and separate weight
    authorization; it may not start a process or touch a wallet. Preflight
    rechecks those artifacts plus current publication conflicts and chain gates.
    Recovery is chain-read-only and raises if any retained transaction is unresolved.
    It may durably record a proven terminal phase without deleting retained bytes.
    Stop returns only once the exact managed worker/cgroup is empty. Start
    methods enforce the fixed capability/mount table and never launch v3 code.
    """

    async def stage(self, selection: SuccessorWorkerSelection) -> None: ...

    async def preflight(
        self, selection: SuccessorWorkerSelection, observation: OwnedCompetitionChainObservation
    ) -> None: ...

    async def stop_worker(self) -> None: ...

    async def recover_stopped_transactions(
        self, observation: OwnedCompetitionChainObservation
    ) -> None: ...

    async def worker_is_healthy(self, selection: SuccessorWorkerSelection) -> bool: ...

    async def start_replay(self, selection: SuccessorWorkerSelection) -> None: ...

    async def start_weights(self, selection: SuccessorWorkerSelection) -> None: ...


class SuccessorDirectiveFetcher(Protocol):
    async def fetch_directive_page(
        self, *, after_version: int, after_sequence: int, after_directive_sha256: str
    ) -> bytes: ...


class SuccessorObservationReader(Protocol):
    async def observe(self) -> OwnedCompetitionChainObservation: ...


class _WorkerState(StrictProtocolModel):
    phase: Literal["idle", "start_intent", "running", "stop_intent", "effects_hold"]
    sequence: int | None
    directive_sha256: Hex32 | None
    mode: Literal["competition_replay", "competition_weights"] | None

    @model_validator(mode="after")
    def phase_binding(self) -> Self:
        values = (self.sequence, self.directive_sha256, self.mode)
        if self.phase == "idle":
            if any(value is not None for value in values):
                raise ValueError("idle worker state has an execution identity")
        elif any(value is None for value in values) or self.sequence < 2:
            raise ValueError("worker state lacks a complete execution identity")
        return self


class _FinalizedHighWater(StrictProtocolModel):
    block: Annotated[int, Field(ge=1, le=2**53 - 1)]
    block_hash: BlockHash


@dataclass(frozen=True, slots=True)
class SuccessorRuntimeResult:
    status: Literal["holding", "waiting", "started", "healthy"]
    reason: str
    accepted_sequence: int
    accepted_directive_sha256: str
    finalized_block: int | None


def _validate_installation(installation: Any) -> None:
    from .competition_host_activation import validate_authenticated_successor_installation

    validate_authenticated_successor_installation(installation)


def _canonical(model, payload: bytes):
    value = model.model_validate_json(payload)
    if canonical_json_bytes(value) != payload:
        raise SuccessorRuntimeError("runtime state is not canonical")
    return value


def _idle() -> _WorkerState:
    return _WorkerState(phase="idle", sequence=None, directive_sha256=None, mode=None)


class SuccessorSupervisorRuntime:
    """Run inside ``async with`` to keep the original singleton lock held.

    The root receipt authenticates an installation, not a mutable cursor. This
    engine retains its own exact signed history and never reloads an old v3
    worker, including after an interrupted start, policy expiry or feed error.
    """

    def __init__(
        self,
        *,
        installation: Any,
        worker_adapter: SuccessorRuntimeAdapter,
        directive_fetcher: SuccessorDirectiveFetcher,
        observation_reader: SuccessorObservationReader,
        limits: SuccessorRuntimeLimits,
        startup_lease: SuccessorStartupLease | None = None,
    ):
        _validate_installation(installation)
        self.installation = installation
        self.config = _canonical(
            ValidatorSupervisorConfig, canonical_json_bytes(installation.config)
        )
        self.limits = _canonical(SuccessorRuntimeLimits, canonical_json_bytes(limits))
        self.adapter, self.fetcher, self.observer = (
            worker_adapter,
            directive_fetcher,
            observation_reader,
        )
        for port, methods in (
            (
                worker_adapter,
                (
                    "stage",
                    "preflight",
                    "stop_worker",
                    "recover_stopped_transactions",
                    "worker_is_healthy",
                    "start_replay",
                    "start_weights",
                ),
            ),
            (directive_fetcher, ("fetch_directive_page",)),
            (observation_reader, ("observe",)),
        ):
            if any(not callable(getattr(port, method, None)) for method in methods):
                raise TypeError("successor runtime adapter is incomplete")
        self.root = Path(self.config.state_root) / "successor-v4" / "runtime"
        self.path = self.root / "supervisor.sqlite3"
        self._lock_fd = -1
        self._lock_identity: tuple[int, int] | None = None
        self._startup_lease = startup_lease
        self._mutex = asyncio.Lock()
        self._restart_checked = False
        self._observation: OwnedCompetitionChainObservation | None = None
        self._state: SuccessorSupervisorDirectiveState | None = None
        self._binding = canonical_json_bytes(
            {
                "schema": "umi-successor-runtime-binding/1",
                "receipt_sha256": installation.receipt_sha256,
                "source_config_sha256": successor_source_config_sha256(self.config),
                "consent_sha256": successor_operator_consent_sha256(installation.operator_consent),
                "v3_state_sha256": hashlib.sha256(
                    canonical_json_bytes(installation.v3_state)
                ).hexdigest(),
                "v3_signed_sha256": hashlib.sha256(installation.v3_signed_bytes).hexdigest(),
                "limits": self.limits.model_dump(mode="json"),
            }
        )
        self._initialization_marker = canonical_json_bytes(
            {
                "schema": "umi-successor-runtime-initialization/1",
                "binding_sha256": hashlib.sha256(self._binding).hexdigest(),
            }
        )
        self._marker_path = Path(self.config.state_root) / "successor-v4-initialization.json"

    async def __aenter__(self):
        if self._lock_fd >= 0:
            raise SuccessorRuntimeError("successor runtime is already open")
        _validate_installation(self.installation)
        _verify_private_directory(Path(self.config.state_root), "supervisor state")
        if self._startup_lease is None:
            descriptor = _open_private_regular_file(
                Path(self.config.state_root) / "supervisor-process.lock", "supervisor process lock"
            )
        else:
            descriptor = _adopt_startup_lease(self._startup_lease, self.installation)
        try:
            if self._startup_lease is None:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._lock_fd = descriptor
            details = os.fstat(descriptor)
            self._lock_identity = (details.st_dev, details.st_ino)
            self._check_legacy_state()
            self._open_journal()
            self._state, _, _ = self._load_history()
        except BaseException:
            if self._lock_fd >= 0:
                await self.adapter.stop_worker()
            self._lock_fd = -1
            os.close(descriptor)
            raise
        return self

    async def __aexit__(self, *_args):
        # A failed stop intentionally keeps the lock until the host terminates
        # this process; another writer must not start on an unconfirmed cgroup.
        await self.stop()
        descriptor, self._lock_fd = self._lock_fd, -1
        self._lock_identity = None
        os.close(descriptor)

    def _require_lease(self):
        if self._lock_fd < 0 or self._lock_identity is None:
            raise SuccessorRuntimeError("successor runtime process lease is not held")
        descriptor = _open_private_regular_file(
            Path(self.config.state_root) / "supervisor-process.lock", "supervisor process lock"
        )
        try:
            info = os.fstat(descriptor)
            held = os.fstat(self._lock_fd)
            if (info.st_dev, info.st_ino) != self._lock_identity or (
                held.st_dev,
                held.st_ino,
            ) != self._lock_identity:
                raise SuccessorRuntimeError("supervisor process lock inode changed")
            if self._startup_lease is not None and (
                _startup_identity(held) != self._startup_lease._identity
                or os.pread(self._lock_fd, _MAX_STARTUP_LOCK_BYTES + 1, 0)
                != self._startup_lease._bytes
            ):
                raise SuccessorRuntimeError("adopted startup lock bytes or metadata changed")
        finally:
            os.close(descriptor)
        _validate_installation(self.installation)
        self._check_legacy_state()
        self._check_initialization_marker()

    def _check_initialization_marker(self):
        descriptor = _open_private_regular_file(
            self._marker_path, "successor initialization marker"
        )
        try:
            if (
                os.fstat(descriptor).st_size != len(self._initialization_marker)
                or os.read(descriptor, len(self._initialization_marker) + 1)
                != self._initialization_marker
            ):
                raise SuccessorRuntimeError("successor initialization marker changed")
        finally:
            os.close(descriptor)

    def _check_legacy_state(self):
        descriptor = _open_private_regular_file(
            Path(self.config.state_root) / "directive-state.json", "legacy high-water"
        )
        try:
            expected = canonical_json_bytes(self.installation.v3_state)
            if os.fstat(descriptor).st_size != len(expected):
                raise SuccessorRuntimeError("preserved v3 high-water changed")
            if os.read(descriptor, len(expected) + 1) != expected:
                raise SuccessorRuntimeError("preserved v3 high-water changed")
        finally:
            os.close(descriptor)

    @contextmanager
    def _db(self):
        if self._lock_fd < 0:
            raise SuccessorRuntimeError("successor database requires the process lease")
        _verify_sqlite_family(self.path, "successor supervisor journal")
        db = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        try:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("PRAGMA journal_mode=DELETE")
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def _open_journal(self):
        # An existing but incomplete directory is retained and requires repair;
        # it is never mistaken for a fresh installation or reset to v3.
        _prepare_private_directory(self.root.parent, "successor shared state")
        parent = _open_directory_without_links(self.root.parent)
        marker_parent = -1
        try:
            # Early, unshipped layouts used this parent directly. Never move,
            # reinterpret or reset a retained journal from that layout.
            for name in (
                "supervisor.sqlite3",
                "supervisor.sqlite3-journal",
                "supervisor.sqlite3-wal",
                "supervisor.sqlite3-shm",
            ):
                try:
                    os.stat(name, dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                raise SuccessorRuntimeError(
                    "earlier successor journal layout requires explicit migration"
                )
            marker_parent = _open_directory_without_links(self._marker_path.parent)
            try:
                os.stat(self._marker_path.name, dir_fd=marker_parent, follow_symlinks=False)
                initialized = True
            except FileNotFoundError:
                initialized = False
            try:
                os.stat(self.root.name, dir_fd=parent, follow_symlinks=False)
                exists = True
            except FileNotFoundError:
                exists = False
            if initialized != exists:
                raise SuccessorRuntimeError(
                    "successor initialization or retained history is incomplete"
                )
            if not initialized:
                descriptor = os.open(
                    self._marker_path.name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=marker_parent,
                )
                try:
                    payload = memoryview(self._initialization_marker)
                    while payload:
                        size = os.write(descriptor, payload)
                        if size <= 0:
                            raise OSError("short successor initialization marker write")
                        payload = payload[size:]
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                os.fsync(marker_parent)
            self._check_initialization_marker()
            try:
                os.mkdir(self.root.name, 0o700, dir_fd=parent)
                new = True
            except FileExistsError:
                new = False
            os.fsync(parent)
        finally:
            if marker_parent >= 0:
                os.close(marker_parent)
            os.close(parent)
        _prepare_private_directory(self.root, "successor state")
        if not new:
            with self._db() as db:
                row = self._bounded_row(db, "binding", MAX_SUCCESSOR_DOCUMENT_BYTES)
                if row != (self._binding,):
                    raise SuccessorRuntimeError("successor installation or journal binding changed")
            return
        directory = _open_directory_without_links(self.root)
        try:
            descriptor = os.open(
                self.path.name,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=directory,
            )
            os.close(descriptor)
            os.fsync(directory)
        finally:
            os.close(directory)
        page = self.installation.initial_page
        state = self.installation.v3_state
        accepted_block = self.installation.initial_accepted_at_finalized_block
        records = []
        if not page.directives:
            raise SuccessorRuntimeError("installation has no initial successor history")
        for signed in page.directives:
            state = advance_successor_supervisor_directive_history_state(
                signed,
                config=self.config,
                operator_consent=self.installation.operator_consent,
                finalized_block=accepted_block,
                prior_state=state,
                prior_v3_signed_bytes=self.installation.v3_signed_bytes
                if signed.directive.predecessor_version == 3
                else None,
            )
            records.append(
                (signed.directive.sequence, canonical_json_bytes(signed), accepted_block)
            )
        self._check_capacity(records)
        with self._db() as db:
            db.execute(
                "CREATE TABLE binding (id INTEGER PRIMARY KEY CHECK(id=1), body BLOB NOT NULL)"
            )
            db.execute(
                "CREATE TABLE history (sequence INTEGER PRIMARY KEY, signed BLOB NOT NULL, "
                "accepted_block INTEGER NOT NULL)"
            )
            db.execute(
                "CREATE TABLE state (id INTEGER PRIMARY KEY CHECK(id=1), body BLOB NOT NULL)"
            )
            db.execute(
                "CREATE TABLE worker (id INTEGER PRIMARY KEY CHECK(id=1), body BLOB NOT NULL)"
            )
            db.execute(
                "CREATE TABLE finalized (id INTEGER PRIMARY KEY CHECK(id=1), body BLOB NOT NULL)"
            )
            db.execute("INSERT INTO binding VALUES (1, ?)", (self._binding,))
            db.executemany("INSERT INTO history VALUES (?, ?, ?)", records)
            db.execute("INSERT INTO state VALUES (1, ?)", (canonical_json_bytes(state),))
            db.execute("INSERT INTO worker VALUES (1, ?)", (canonical_json_bytes(_idle()),))

    def _check_capacity(self, records):
        if (
            len(records) > self.limits.maximum_history_records
            or sum(len(row[1]) for row in records) > self.limits.maximum_history_bytes
            or any(len(row[1]) > MAX_SUCCESSOR_DOCUMENT_BYTES for row in records)
        ):
            raise SuccessorRuntimeError("successor history capacity exceeded")

    @staticmethod
    def _bounded_row(db, table, maximum_bytes):
        # Table identifiers are fixed by this module, never supplied by a feed.
        if table not in {"binding", "state", "worker", "finalized"}:
            raise SuccessorRuntimeError("invalid runtime singleton table")
        count, size = db.execute(
            f"SELECT COUNT(*), COALESCE(SUM(length(body)),0) FROM {table}"
        ).fetchone()
        if count > 1 or size > maximum_bytes:
            raise SuccessorRuntimeError("successor singleton state exceeds its bounds")
        return db.execute(f"SELECT body FROM {table} WHERE id=1").fetchone()

    def _load_history(self):
        with self._db() as db:
            if self._bounded_row(db, "binding", MAX_SUCCESSOR_DOCUMENT_BYTES) != (self._binding,):
                raise SuccessorRuntimeError("successor journal binding changed")
            count, size = db.execute(
                "SELECT COUNT(*), COALESCE(SUM(length(signed)),0) FROM history"
            ).fetchone()
            if (
                count > self.limits.maximum_history_records
                or size > self.limits.maximum_history_bytes
            ):
                raise SuccessorRuntimeError("successor history exceeds its bounds")
            records = db.execute(
                "SELECT sequence,signed,accepted_block FROM history ORDER BY sequence"
            ).fetchall()
            self._check_capacity(records)
            row = self._bounded_row(db, "state", MAX_SUCCESSOR_DOCUMENT_BYTES)
            worker_row = self._bounded_row(db, "worker", 8192)
        if not records or row is None or worker_row is None:
            raise SuccessorRuntimeError("successor history is incomplete")
        initial = self.installation.initial_page.directives
        if len(records) < len(initial) or any(
            records[index][1] != canonical_json_bytes(signed)
            or records[index][2] != self.installation.initial_accepted_at_finalized_block
            for index, signed in enumerate(initial)
        ):
            raise SuccessorRuntimeError("successor history lost its installation anchor")
        state = self.installation.v3_state
        signed_records = []
        for sequence, payload, block in records:
            signed = parse_canonical_signed_successor_supervisor_directive(payload)
            if sequence != signed.directive.sequence:
                raise SuccessorRuntimeError("successor history sequence differs from signed bytes")
            state = advance_successor_supervisor_directive_history_state(
                signed,
                config=self.config,
                operator_consent=self.installation.operator_consent,
                finalized_block=block,
                prior_state=state,
                prior_v3_signed_bytes=self.installation.v3_signed_bytes
                if signed.directive.predecessor_version == 3
                else None,
            )
            signed_records.append(signed)
        if parse_canonical_successor_supervisor_state(row[0]) != state:
            raise SuccessorRuntimeError("successor high-water does not match signed history")
        worker = _canonical(_WorkerState, worker_row[0])
        if worker.phase != "idle":
            match = next(
                (item for item in signed_records if item.directive.sequence == worker.sequence),
                None,
            )
            if (
                match is None
                or match.directive_sha256 != worker.directive_sha256
                or match.directive.mode != worker.mode
            ):
                raise SuccessorRuntimeError(
                    "successor worker journal is not bound to signed history"
                )
        return state, signed_records, worker

    def _store_worker(self, worker):
        payload = canonical_json_bytes(_canonical(_WorkerState, canonical_json_bytes(worker)))
        with self._db() as db:
            db.execute("UPDATE worker SET body=? WHERE id=1", (payload,))

    def _observe(self, observation):
        validate_owned_weight_observation(observation)
        if account_id32(observation.validator_hotkey) != account_id32(self.config.validator_hotkey):
            raise SuccessorRuntimeError("successor observation belongs to another validator")
        with self._db() as db:
            row = self._bounded_row(db, "finalized", 512)
            if row:
                prior = _canonical(_FinalizedHighWater, row[0])
                if observation.block < prior.block or (
                    observation.block == prior.block and observation.block_hash != prior.block_hash
                ):
                    raise SuccessorRuntimeError("successor finalized head rolled back or forked")
            if self._state and observation.block < self._state.accepted_at_finalized_block:
                raise SuccessorRuntimeError("successor observation predates accepted state")
            db.execute(
                "INSERT INTO finalized VALUES (1,?) "
                "ON CONFLICT(id) DO UPDATE SET body=excluded.body",
                (
                    canonical_json_bytes(
                        _FinalizedHighWater(
                            block=observation.block, block_hash=observation.block_hash
                        )
                    ),
                ),
            )
        self._observation = observation

    def _current_gates(self, signed, observation, *, starting: bool):
        self._require_lease()
        validate_owned_weight_observation(observation)
        verify_signed_successor_supervisor_directive(
            signed,
            config=self.config,
            operator_consent=self.installation.operator_consent,
            finalized_block=observation.block,
        )
        directive = signed.directive
        if observation.block < directive.valid_from_block:
            raise SuccessorRuntimeError("successor directive is not active")
        if not observation.validator_permit:
            raise SuccessorRuntimeError("successor validator permit is absent")
        if (
            observation.genesis_hash.removeprefix("0x")
            != directive.chain.chain_pin.genesis_block_hash
        ):
            raise SuccessorRuntimeError("successor genesis pin changed")
        if (
            starting
            and directive.valid_through_block - observation.block
            < directive.minimum_activation_headroom_blocks
        ):
            raise SuccessorRuntimeError("successor activation headroom is insufficient")

    async def _refresh_observation(self):
        observation = await self.observer.observe()
        self._require_lease()
        self._observe(observation)
        return observation

    async def _stop_and_recover(self, observation):
        _, _, worker = self._load_history()
        if worker.phase != "idle":
            self._store_worker(worker.model_copy(update={"phase": "stop_intent"}))
        await self.adapter.stop_worker()
        try:
            # The tick's pre-stop proof may predate a final durable submission.
            # Re-read after confirmed absence; recovery must still hold if that
            # proof cannot resolve the retained transaction or its mortality.
            observation = await self._refresh_observation()
            await self.adapter.recover_stopped_transactions(observation)
            observation = await self._refresh_observation()
        except Exception:
            if worker.phase != "idle":
                self._store_worker(worker.model_copy(update={"phase": "effects_hold"}))
            raise
        self._store_worker(_idle())
        self._restart_checked = True
        return observation

    async def stop(self):
        async with self._mutex:
            if self._lock_fd < 0:
                raise SuccessorRuntimeError("cannot stop without the runtime process lease")
            try:
                self._require_lease()
                _, _, worker = self._load_history()
                if worker.phase != "idle":
                    self._store_worker(worker.model_copy(update={"phase": "stop_intent"}))
            finally:
                await self.adapter.stop_worker()
            # Do not label an interrupted transaction resolved on shutdown.
            # The next process reconciles retained effects before any restart.
            self._restart_checked = False

    async def _hold(self, reason):
        try:
            _, _, worker = self._load_history()
            if worker.phase != "idle":
                self._store_worker(worker.model_copy(update={"phase": "stop_intent"}))
        finally:
            await self.adapter.stop_worker()
        self._restart_checked = False
        return self._result("holding", reason)

    def _result(self, status, reason):
        state = self._state
        if state is None:
            raise SuccessorRuntimeError("runtime has no accepted successor state")
        return SuccessorRuntimeResult(
            status,
            reason,
            state.accepted_sequence,
            state.accepted_directive_sha256,
            self._observation.block if self._observation else None,
        )

    async def reconcile(self) -> SuccessorRuntimeResult:
        async with self._mutex:
            try:
                self._require_lease()
                return await self._reconcile()
            except Exception:
                return await self._hold("successor_reconcile_failed")

    def _selection(self, signed, history):
        anchor = self.installation.initial_page.head
        if not history or history[-1] != signed:
            raise SuccessorRuntimeError("selection lost its retained history head")
        self._check_capacity(
            [(item.directive.sequence, canonical_json_bytes(item), 0) for item in history]
        )
        continuation = [
            item for item in history if item.directive.sequence > anchor.directive.sequence
        ]
        return SuccessorWorkerSelection(signed, successor_continuation_bytes(anchor, continuation))

    async def _reconcile(self):
        self._state, history, worker = self._load_history()
        observation = await self._refresh_observation()
        if not self._restart_checked:
            observation = await self._stop_and_recover(observation)
            worker = _idle()
        payload = await self.fetcher.fetch_directive_page(
            after_version=4,
            after_sequence=self._state.accepted_sequence,
            after_directive_sha256=self._state.accepted_directive_sha256,
        )
        if not isinstance(payload, bytes):
            raise SuccessorRuntimeError("successor feed is unavailable")
        observation = await self._refresh_observation()
        page = parse_canonical_successor_supervisor_directive_page(payload)
        if (page.after_version, page.after_sequence, page.after_directive_sha256) != (
            4,
            self._state.accepted_sequence,
            self._state.accepted_directive_sha256,
        ):
            raise SuccessorRuntimeError("successor feed cursor mismatch")
        prefix = []
        future = None
        for signed in page.directives or [page.head]:
            verify_signed_successor_supervisor_directive_history(
                signed,
                config=self.config,
                operator_consent=self.installation.operator_consent,
                finalized_block=observation.block,
            )
            if page.directives and future is None:
                if signed.directive.valid_from_block > observation.block:
                    future = signed
                else:
                    prefix.append(signed)
        future_stage_failed = False
        if future is not None and future.directive.mode != "hold":
            try:
                await self.adapter.stage(self._selection(future, [*history, *prefix, future]))
            except Exception:
                # A failed optional pre-stage cannot retire a valid current worker.
                future_stage_failed = True
            observation = await self._refresh_observation()
        if prefix:
            candidate = prefix[-1]
            expired = observation.block > candidate.directive.valid_through_block
            if not expired and candidate.directive.mode != "hold":
                selection = self._selection(candidate, [*history, *prefix])
                self._current_gates(candidate, observation, starting=True)
                await self.adapter.stage(selection)
                observation = await self._refresh_observation()
                await self.adapter.preflight(selection, observation)
                observation = await self._refresh_observation()
                self._current_gates(candidate, observation, starting=True)
            prospective = self._state
            records = []
            for signed in prefix:
                prospective = advance_successor_supervisor_directive_history_state(
                    signed,
                    config=self.config,
                    operator_consent=self.installation.operator_consent,
                    finalized_block=observation.block,
                    prior_state=prospective,
                )
                records.append(
                    (signed.directive.sequence, canonical_json_bytes(signed), observation.block)
                )
            with self._db() as db:
                old = db.execute(
                    "SELECT sequence,signed,accepted_block FROM history ORDER BY sequence"
                ).fetchall()
            self._check_capacity([*old, *records])
            observation = await self._stop_and_recover(observation)
            self._require_lease()
            validate_owned_weight_observation(observation)
            # The stop/recovery boundary can advance finality. Store the actual
            # acceptance block, never the earlier preflight's block.
            prospective = self._state
            records = []
            for signed in prefix:
                prospective = advance_successor_supervisor_directive_history_state(
                    signed,
                    config=self.config,
                    operator_consent=self.installation.operator_consent,
                    finalized_block=observation.block,
                    prior_state=prospective,
                )
                records.append(
                    (signed.directive.sequence, canonical_json_bytes(signed), observation.block)
                )
            with self._db() as db:
                db.executemany("INSERT INTO history VALUES (?,?,?)", records)
                db.execute(
                    "UPDATE state SET body=? WHERE id=1", (canonical_json_bytes(prospective),)
                )
            self._state = prospective
            history.extend(prefix)
            worker = _idle()
        if page.more and future is None:
            return await self._hold("successor_history_catchup_incomplete")
        current = history[-1]
        if observation.block > current.directive.valid_through_block:
            return await self._hold("successor_directive_expired")
        if current.directive.mode == "hold":
            return await self._hold("signed_successor_hold")
        self._current_gates(current, observation, starting=False)
        selection = self._selection(current, history)
        if worker.phase == "running" and worker.directive_sha256 == current.directive_sha256:
            await self.adapter.preflight(selection, observation)
            observation = await self._refresh_observation()
            self._current_gates(current, observation, starting=False)
            if await self.adapter.worker_is_healthy(selection):
                observation = await self._refresh_observation()
                self._current_gates(current, observation, starting=False)
                return self._result(
                    "healthy",
                    "future_stage_failed"
                    if future_stage_failed
                    else "future_directive_staged"
                    if future is not None
                    else "current_worker_healthy",
                )
            observation = await self._stop_and_recover(observation)
        await self.adapter.stage(selection)
        observation = await self._refresh_observation()
        await self.adapter.preflight(selection, observation)
        observation = await self._refresh_observation()
        self._current_gates(current, observation, starting=True)
        advance_successor_supervisor_directive_state(
            current,
            config=self.config,
            operator_consent=self.installation.operator_consent,
            finalized_block=observation.block,
            prior_state=self._state,
        )
        intent = _WorkerState(
            phase="start_intent",
            sequence=current.directive.sequence,
            directive_sha256=current.directive_sha256,
            mode=current.directive.mode,
        )
        self._store_worker(intent)
        if current.directive.mode == "competition_replay":
            await self.adapter.start_replay(selection)
        else:
            await self.adapter.start_weights(selection)
        observation = await self._refresh_observation()
        if not await self.adapter.worker_is_healthy(selection):
            raise SuccessorRuntimeError("successor worker startup was not confirmed")
        observation = await self._refresh_observation()
        self._current_gates(current, observation, starting=False)
        self._store_worker(intent.model_copy(update={"phase": "running"}))
        return self._result("started", "successor_worker_started")

    async def poll(self, stop_event: asyncio.Event):
        while not stop_event.is_set():
            await self.reconcile()
            with suppress(asyncio.TimeoutError):
                await asyncio.wait_for(stop_event.wait(), timeout=float(self.config.poll_seconds))
