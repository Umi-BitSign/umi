"""Successor runtime orchestration with verified artifacts and retained effects.

The host supplies bounded fetching/current-view materialization and its owned
proof observer. Those ports cannot replace artifact or activation verification.
This adapter never loads a wallet or constructs a transaction. A completed
container needs a matching durable receipt; exit status alone proves nothing
about applied weights.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import sqlite3
from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import Protocol

from .competition_adapter_history import (
    MAX_HISTORY_NODE_BYTES,
    encode_history,
    parse_history_node,
    restore_history,
    summarize_history_nodes,
    validate_history_reference,
    validate_reference_head,
)
from .competition_chain_state import (
    OwnedCompetitionChainObservation,
    validate_owned_weight_observation,
)
from .competition_container import PodmanSuccessorContainer
from .competition_evidence_reader import evidence_reader
from .competition_evidence_worker import ContentAddressedWeightWorker
from .competition_host_activation import (
    AuthenticatedSuccessorActivation,
    AuthenticatedSuccessorWorkerInputs,
    _validate_worker_execution_bindings,
    retained_execution_limits,
    selected_weight_state_root,
    validate_authenticated_successor_activation,
    validate_authenticated_successor_installation,
)
from .competition_package import VerifiedCompetitionPackage
from .competition_recovery_packages import RecoveryPackageReplay
from .competition_release import VerifiedSuccessorOCI
from .competition_supervisor import (
    MAX_SUCCESSOR_HISTORY_BYTES,
    MAX_SUCCESSOR_HISTORY_RECORDS,
    load_bound_successor_replay_package,
    parse_canonical_signed_successor_supervisor_directive,
    parse_canonical_successor_supervisor_directive_history,
    verify_bound_successor_chain_authorization,
    verify_signed_successor_supervisor_directive,
    verify_signed_successor_supervisor_directive_history,
)
from .competition_supervisor_runtime import SuccessorWorkerSelection
from .competition_weights import (
    CompetitionWeightWorker,
    SignedCompetitionWeightAuthorization,
    _recovery_journal_snapshot,
    _recovery_package_snapshot,
    _WeightAttempt,
    competition_weight_authorization_digest,
    validate_weight_preflight,
)
from .competition_worker import (
    CompetitionReplayWorker,
    _open_directory_without_links,
    _open_private_regular_file,
    _parse_stored_receipt,
    _prepare_private_directory,
    _verify_sqlite_family,
)
from .competition_worker_cli import SuccessorWorkerExecutionConfig
from .encoding import account_id32
from .open_competition import digest
from .protocol import canonical_json_bytes

_MAX_EXECUTION_BYTES = 128 * 1024
_MAX_AUTHORIZATION_BYTES = 128 * 1024
_MAX_ATTEMPT_BYTES = 256 * 1024
_MAX_RECEIPT_BYTES = 32 * 1024
_TERMINAL = {"applied", "recovered_effect", "expired_unconsumed_nonce"}


class SuccessorAdapterError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class SuccessorArtifactFiles:
    release_bundle_path: Path
    package_path: Path
    worker_execution_bytes: bytes
    current_directive_page_bytes: bytes
    authorization_bytes: bytes | None

    def __post_init__(self):
        for path in (self.release_bundle_path, self.package_path):
            if (
                not isinstance(path, Path)
                or not path.is_absolute()
                or path != Path(os.path.normpath(path))
            ):
                raise ValueError("successor artifact paths must be canonical and absolute")
        for value, limit, optional in (
            (self.worker_execution_bytes, _MAX_EXECUTION_BYTES, False),
            (self.current_directive_page_bytes, MAX_SUCCESSOR_HISTORY_BYTES, False),
            (self.authorization_bytes, _MAX_AUTHORIZATION_BYTES, True),
        ):
            if value is None and optional:
                continue
            if not isinstance(value, bytes) or not 0 < len(value) <= limit:
                raise ValueError("successor artifact control exceeds its explicit byte bound")


class SuccessorArtifactMaterializer(Protocol):
    async def fetch(self, selection: SuccessorWorkerSelection) -> SuccessorArtifactFiles:
        """Fetch into immutable staging; never replace the active current view."""
        ...

    async def retire_redundant(self, retained: Mapping) -> int:
        """Retire cache copies only after their durable recovery sources were audited."""
        ...

    async def activate(
        self,
        selection: SuccessorWorkerSelection,
        artifacts: SuccessorArtifactFiles,
        *,
        owned_observation: OwnedCompetitionChainObservation,
    ) -> AuthenticatedSuccessorActivation:
        """Select the stopped current view and invoke the genuine activation loader."""
        ...


class SuccessorArtifactObserver(Protocol):
    async def observe(self) -> OwnedCompetitionChainObservation:
        """Capture a fresh installed validator head without a target reward policy."""
        ...

    async def observe_for(
        self, selection: SuccessorWorkerSelection, artifacts: SuccessorArtifactFiles
    ) -> OwnedCompetitionChainObservation:
        """Capture a fresh owned proof using the target's authenticated chain config."""
        ...


@dataclass(frozen=True, slots=True)
class SuccessorAdapterLimits:
    maximum_retained_runs: int
    maximum_registry_bytes: int
    maximum_staged_selections: int = 4

    def __post_init__(self):
        for name in self.__dataclass_fields__:
            if type(getattr(self, name)) is not int or getattr(self, name) <= 0:
                raise ValueError("adapter limits must be positive integers")
        if self.maximum_retained_runs > 65536 or not 2 <= self.maximum_staged_selections <= 32:
            raise ValueError("adapter record count exceeds supported bounds")
        if not 1024 <= self.maximum_registry_bytes <= 64 * 1024**2:
            raise ValueError("adapter registry needs a bounded byte budget")


@dataclass(frozen=True, slots=True)
class _Prepared:
    selection: SuccessorWorkerSelection
    files: SuccessorArtifactFiles
    execution: SuccessorWorkerExecutionConfig
    package: VerifiedCompetitionPackage
    authorization: SignedCompetitionWeightAuthorization | None
    release: VerifiedSuccessorOCI | None = None


def _canonical(model, payload):
    result = model.model_validate_json(payload)
    if canonical_json_bytes(result) != payload:
        raise SuccessorAdapterError("successor adapter input is not canonical")
    return result


def _record(selection, files, *, history_reference=None):
    return canonical_json_bytes(
        {
            "schema": "umi-successor-adapter-run/1"
            if history_reference is None
            else "umi-successor-adapter-run/2",
            "signed_directive": json.loads(canonical_json_bytes(selection.signed)),
            "release_bundle_path": str(files.release_bundle_path),
            "package_path": str(files.package_path),
            "worker_execution": json.loads(files.worker_execution_bytes),
            "current_directive_page": json.loads(files.current_directive_page_bytes)
            if history_reference is None
            else history_reference,
            "authorization": None
            if files.authorization_bytes is None
            else json.loads(files.authorization_bytes),
        }
    )


def _decode_record(raw, *, history_nodes=None, history_prefixes=None, metadata_only=False):
    value = json.loads(raw)
    if (
        canonical_json_bytes(value) != raw
        or not isinstance(value, dict)
        or set(value)
        != {
            "schema",
            "signed_directive",
            "release_bundle_path",
            "package_path",
            "worker_execution",
            "current_directive_page",
            "authorization",
        }
        or not isinstance(value["schema"], str)
        or value["schema"] not in {"umi-successor-adapter-run/1", "umi-successor-adapter-run/2"}
    ):
        raise SuccessorAdapterError("retained successor run is corrupt")
    signed = parse_canonical_signed_successor_supervisor_directive(
        canonical_json_bytes(value["signed_directive"])
    )
    if value["schema"] == "umi-successor-adapter-run/2":
        validate_history_reference(value["current_directive_page"])
        if metadata_only:
            validate_reference_head(
                value["current_directive_page"],
                head=signed,
                nodes=history_nodes or {},
                prefixes=history_prefixes or {},
            )
        # Only _records uses metadata_only to validate paths and small fields
        # without allocating every run's full continuation at once.
        page_bytes = (
            b"{}"
            if metadata_only
            else restore_history(
                value["current_directive_page"], head=signed, nodes=history_nodes or {}
            )
        )
    else:
        page_bytes = canonical_json_bytes(value["current_directive_page"])
    return (
        SuccessorWorkerSelection(signed),
        SuccessorArtifactFiles(
            release_bundle_path=Path(value["release_bundle_path"]),
            package_path=Path(value["package_path"]),
            worker_execution_bytes=canonical_json_bytes(value["worker_execution"]),
            current_directive_page_bytes=page_bytes,
            authorization_bytes=None
            if value["authorization"] is None
            else canonical_json_bytes(value["authorization"]),
        ),
    )


class _RetainedRuns(Mapping):
    """One bounded registry snapshot, with histories reconstructed on access."""

    def __init__(self, records, nodes, used_bytes):
        self._records, self.nodes, self.used_bytes = records, nodes, used_bytes

    def __iter__(self):
        return iter(self._records)

    def __len__(self):
        return len(self._records)

    def __getitem__(self, identity):
        return _decode_record(self._records[identity], history_nodes=self.nodes)


@contextmanager
def _read_worker_database(path: Path, lock_path: Path, maximum_bytes: int):
    descriptor = _open_private_regular_file(lock_path, "stopped worker journal lock")
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _verify_sqlite_family(path, "stopped worker journal")
        total = 0
        for suffix in ("", "-wal", "-shm", "-journal"):
            item = path.with_name(path.name + suffix)
            if item.exists():
                opened = _open_private_regular_file(item, "stopped worker journal")
                try:
                    total += os.fstat(opened).st_size
                finally:
                    os.close(opened)
        if total > maximum_bytes:
            raise SuccessorAdapterError("stopped worker journal exceeds its byte budget")
        db = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=1)
        try:
            db.execute("PRAGMA query_only=ON")
            db.execute("BEGIN")
            if db.execute("PRAGMA quick_check").fetchone() != ("ok",):
                raise SuccessorAdapterError("stopped worker journal is corrupt")
            yield db
        finally:
            db.close()
    finally:
        os.close(descriptor)


class ProductionSuccessorRuntimeAdapter:
    """Execute the runtime protocol under its original supervisor process lock.

    Artifact fetching/current-view selection and target-specific owned finality
    are explicit host ports. Production must supply their real implementations;
    neither caller JSON nor an injected Python module can mint activation.
    """

    def __init__(
        self,
        *,
        installation: AuthenticatedSuccessorWorkerInputs,
        materializer: SuccessorArtifactMaterializer,
        observer: SuccessorArtifactObserver,
        container: PodmanSuccessorContainer,
        limits: SuccessorAdapterLimits,
    ):
        validate_authenticated_successor_installation(installation)
        self.installation, self.config = installation, installation.config
        self.materializer, self.observer, self.container = materializer, observer, container
        self.limits = limits
        if canonical_json_bytes(container.config) != canonical_json_bytes(self.config):
            raise ValueError("container config differs from installed supervisor")
        self.root = _prepare_private_directory(
            Path(self.config.state_root) / "successor-adapter", "successor adapter"
        )
        self.path = self.root / "registry.sqlite3"
        root_fd = _open_directory_without_links(self.root)
        try:
            CompetitionReplayWorker._prepare_state_file(root_fd, self.path.name)
        finally:
            os.close(root_fd)
        self._binding = canonical_json_bytes(
            {
                "schema": "umi-successor-adapter-registry/1",
                "receipt": installation.receipt_sha256,
                "config": installation.config_sha256,
                "maximum_retained_runs": limits.maximum_retained_runs,
                "maximum_registry_bytes": limits.maximum_registry_bytes,
            }
        )
        with self._registry() as db:
            db.execute("CREATE TABLE IF NOT EXISTS binding (id INTEGER PRIMARY KEY, body BLOB)")
            db.execute("CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, body BLOB, sha TEXT)")
            db.execute("CREATE TABLE IF NOT EXISTS history_nodes (id TEXT PRIMARY KEY, body BLOB)")
            old = db.execute("SELECT id,body FROM binding").fetchall()
            if not old:
                db.execute("INSERT INTO binding VALUES (1,?)", (self._binding,))
            elif old != [(1, self._binding)]:
                raise SuccessorAdapterError("adapter registry belongs to another installation")
        self._staged: dict[str, _Prepared] = {}
        self._preflight: dict[str, OwnedCompetitionChainObservation] = {}
        self._stopped = False
        self._recovered: OwnedCompetitionChainObservation | None = None
        self._recovered_floor: tuple[int, str] | None = None

    @contextmanager
    def _registry(self):
        _verify_sqlite_family(self.path, "adapter registry")
        db = sqlite3.connect(self.path, timeout=1, isolation_level=None)
        try:
            db.execute("PRAGMA journal_mode=DELETE")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def _records(self):
        with self._registry() as db:
            if db.execute("SELECT id,body FROM binding").fetchall() != [(1, self._binding)]:
                raise SuccessorAdapterError("adapter registry binding changed")
            count, total, maximum = db.execute(
                "SELECT COUNT(*),COALESCE(SUM(length(body)),0),"
                "COALESCE(MAX(length(body)),0) FROM runs"
            ).fetchone()
            node_count, node_total, node_maximum = db.execute(
                "SELECT COUNT(*),COALESCE(SUM(length(body)),0),"
                "COALESCE(MAX(length(body)),0) FROM history_nodes"
            ).fetchone()
            if (
                count > self.limits.maximum_retained_runs
                or node_count > MAX_SUCCESSOR_HISTORY_RECORDS + self.limits.maximum_retained_runs
                or total + node_total > self.limits.maximum_registry_bytes
            ):
                raise SuccessorAdapterError("adapter registry capacity exhausted")
            if count and not 0 < maximum <= self.limits.maximum_registry_bytes:
                raise SuccessorAdapterError("adapter registry record is malformed")
            if node_count and not 0 < node_maximum <= MAX_HISTORY_NODE_BYTES:
                raise SuccessorAdapterError("adapter registry history node is malformed")
            nodes = {
                identity: parse_history_node(identity, body)
                for identity, body in db.execute("SELECT id,body FROM history_nodes")
            }
            prefixes = summarize_history_nodes(nodes)
            result = {}
            for identity, raw, checksum in db.execute("SELECT id,body,sha FROM runs"):
                if not isinstance(raw, bytes) or hashlib.sha256(raw).hexdigest() != checksum:
                    raise SuccessorAdapterError("adapter registry record is corrupt")
                selection, _ = _decode_record(
                    raw, history_nodes=nodes, history_prefixes=prefixes, metadata_only=True
                )
                if selection.directive_sha256 != identity:
                    raise SuccessorAdapterError("adapter registry directive binding changed")
                result[identity] = raw
            return _RetainedRuns(result, nodes, total + node_total)

    def _retain(self, prepared):
        records = self._records()
        identity = prepared.selection.directive_sha256
        if identity in records:
            prior_selection, prior_files = records[identity]
            if (
                prior_selection.signed != prepared.selection.signed
                or prior_files.worker_execution_bytes != prepared.files.worker_execution_bytes
                or prior_files.authorization_bytes != prepared.files.authorization_bytes
            ):
                raise SuccessorAdapterError("retained directive artifacts changed")
            # A refetch may use a new immutable cache path or equivalent signed
            # history page. Preserve the original recovery sources unchanged.
            return
        reference, nodes = encode_history(prepared.files.current_directive_page_bytes)
        raw = _record(prepared.selection, prepared.files, history_reference=reference)
        missing = {
            identity: body for identity, body in nodes.items() if identity not in records.nodes
        }
        if (
            len(records) >= self.limits.maximum_retained_runs
            or len(records.nodes) + len(missing)
            > MAX_SUCCESSOR_HISTORY_RECORDS + self.limits.maximum_retained_runs
            or records.used_bytes + len(raw) + sum(map(len, missing.values()))
            > self.limits.maximum_registry_bytes
        ):
            raise SuccessorAdapterError("adapter registry full; no retained run was removed")
        with self._registry() as db:
            db.executemany("INSERT INTO history_nodes VALUES (?,?)", missing.items())
            db.execute(
                "INSERT INTO runs VALUES (?,?,?)",
                (
                    identity,
                    raw,
                    hashlib.sha256(raw).hexdigest(),
                ),
            )

    def _verify(self, selection, files, *, recovery_packages: RecoveryPackageReplay | None = None):
        validate_authenticated_successor_installation(self.installation)
        if selection.continuation_bytes is not None and (
            selection.continuation_bytes != files.current_directive_page_bytes
        ):
            raise SuccessorAdapterError("delivery differs from the runtime's retained history")
        signed, directive = selection.signed, selection.signed.directive
        verify_signed_successor_supervisor_directive_history(
            signed,
            config=self.config,
            operator_consent=self.installation.operator_consent,
            finalized_block=max(
                directive.issued_at_block, self.installation.checkpoint_finalized_block
            ),
        )
        page = parse_canonical_successor_supervisor_directive_history(
            files.current_directive_page_bytes
        )
        if page.more or page.head != signed:
            raise SuccessorAdapterError("staged history does not end at the selected directive")
        execution = _canonical(SuccessorWorkerExecutionConfig, files.worker_execution_bytes)
        package = (
            load_bound_successor_replay_package(
                files.package_path,
                directive=directive,
                observed_release=directive.release.replay_release_identity,
            )
            if recovery_packages is None
            else recovery_packages.load(files.package_path, directive=directive)
        )
        authorization, body = None, None
        if selection.mode == "competition_weights":
            body = verify_bound_successor_chain_authorization(
                files.authorization_bytes,
                directive=directive,
                config=self.config,
                package=package,
            )
            authorization = _canonical(
                SignedCompetitionWeightAuthorization, files.authorization_bytes
            )
        elif files.authorization_bytes is not None:
            raise SuccessorAdapterError("replay staging contains unexpected weight authority")
        _validate_worker_execution_bindings(
            execution=execution,
            limits=retained_execution_limits(self.installation, directive),
            directive=directive,
            release_identity=directive.release.replay_release_identity,
            authorization_body=body,
        )
        return _Prepared(selection, files, execution, package, authorization)

    def _replay(self, prepared):
        worker = CompetitionReplayWorker(
            self.root / "preflight-replay",
            package_limits=prepared.selection.signed.directive.replay_package.limits,
            capacity=self.installation.worker_execution_limits.replay_capacity_ceiling,
        )
        result = worker.run(
            prepared.files.package_path,
            expected_package_sha256=prepared.package.package_sha256,
            expected_policy_sha256=prepared.package.manifest.policy_sha256,
            observed_release=prepared.selection.signed.directive.release.replay_release_identity,
        )
        if result.current_status.held or result.receipt.status != "replayed_no_weight":
            raise SuccessorAdapterError("successor publication replay is held")
        return result

    async def stage(self, selection):
        files = await self.materializer.fetch(selection)
        if type(files) is not SuccessorArtifactFiles:
            raise TypeError("materializer must return bounded artifact files")
        prepared = self._verify(selection, files)
        self._replay(prepared)
        release = self.container.stage_release(
            files.release_bundle_path, selection.signed.directive.release
        )
        prepared = _Prepared(
            selection, files, prepared.execution, prepared.package, prepared.authorization, release
        )
        if selection.directive_sha256 not in self._staged:
            running = await self.container.status()
            while len(self._staged) >= self.limits.maximum_staged_selections:
                discarded = next(
                    (key for key in self._staged if key != running.directive_sha256), None
                )
                if discarded is None:
                    raise SuccessorAdapterError(
                        "staged selection capacity preserves current worker"
                    )
                del self._staged[discarded]
                self._preflight.pop(discarded, None)
        self._staged[selection.directive_sha256] = prepared

    @staticmethod
    def _observation_floor(observation):
        validate_owned_weight_observation(observation)
        # This lower bound is not observation authority. Slow artifact work may
        # outlive the input proof; all current-state gates use a new owned proof.
        return observation.block, observation.block_hash

    async def _observe_at_floor(self, prepared, floor):
        observation = await self.observer.observe_for(prepared.selection, prepared.files)
        validate_owned_weight_observation(observation)
        if account_id32(observation.validator_hotkey) != account_id32(
            self.config.validator_hotkey
        ) or (
            observation.block < floor[0]
            or (observation.block == floor[0] and observation.block_hash != floor[1])
        ):
            raise SuccessorAdapterError(
                "target proof is behind the supervisor finalized high-water"
            )
        return observation

    async def _observe(self, prepared, floor):
        return await self._observe_at_floor(prepared, self._observation_floor(floor))

    async def preflight(self, selection, observation):
        await self._preflight_at_floor(selection, self._observation_floor(observation))

    async def _preflight_at_floor(self, selection, floor):
        prepared = self._staged.get(selection.directive_sha256)
        if prepared is None:
            # Runtime re-entry may retain a worker while this process's cache is empty.
            await self.stage(selection)
            prepared = self._staged[selection.directive_sha256]
        checked = self._verify(selection, prepared.files)
        self._replay(checked)
        current = await self._observe_at_floor(checked, floor)
        verify_signed_successor_supervisor_directive(
            selection.signed,
            config=self.config,
            operator_consent=self.installation.operator_consent,
            finalized_block=current.block,
        )
        if not current.validator_permit:
            raise SuccessorAdapterError("selected validator has no finalized permit")
        if checked.authorization is not None:
            validate_weight_preflight(
                checked.package,
                checked.authorization.authorization,
                current,
                checked.execution.weights.chain,
                submission=False,
            )
        self._preflight[selection.directive_sha256] = current

    async def stop_worker(self):
        self._recovered = None
        self._recovered_floor = None
        self._stopped = False
        status = await self.container.stop()
        if status.phase == "running":
            raise SuccessorAdapterError("successor worker absence is not confirmed")
        self._stopped = True

    def _attempts(self):
        root = selected_weight_state_root(self.installation)
        path, lock = root / "competition-weights.sqlite3", root / "competition-weights.lock"
        if not os.path.lexists(root):
            if any(
                selection.mode == "competition_weights" for selection, _ in self._records().values()
            ):
                raise SuccessorAdapterError("retained weight launch lost its journal")
            return {}
        if not path.exists() or not lock.exists():
            raise SuccessorAdapterError("successor weight journal is incomplete")
        ceiling = self.installation.worker_execution_limits
        storage = ceiling.weight_evidence_storage
        with _read_worker_database(
            path,
            lock,
            (
                ceiling.maximum_weight_evidence_bytes
                if storage is None
                else storage.maximum_database_bytes
            )
            + ceiling.maximum_weight_attempts * _MAX_ATTEMPT_BYTES
            + 1024**2,
        ) as db:
            count, maximum = db.execute(
                "SELECT COUNT(*),COALESCE(MAX(length(body)),0) FROM attempts"
            ).fetchone()
            if count > ceiling.maximum_weight_attempts or maximum > _MAX_ATTEMPT_BYTES:
                raise SuccessorAdapterError("successor attempt journal exceeds its bounds")
            read_evidence = evidence_reader(
                db,
                storage=storage,
                validator_hotkey=self.config.validator_hotkey,
                maximum_attempts=ceiling.maximum_weight_attempts,
                maximum_evidence_bytes=ceiling.maximum_weight_evidence_bytes,
            )
            result = {}
            for identity, raw, checksum in db.execute("SELECT id,body,sha256 FROM attempts"):
                if not isinstance(raw, bytes) or hashlib.sha256(raw).hexdigest() != checksum:
                    raise SuccessorAdapterError("successor attempt checksum changed")
                attempt = _canonical(_WeightAttempt, raw)
                if attempt.authorization_id != identity or account_id32(
                    attempt.validator_hotkey
                ) != account_id32(self.config.validator_hotkey):
                    raise SuccessorAdapterError("successor attempt identity changed")
                read_evidence(attempt.chain_evidence_sha256)
                result[identity] = attempt
            return result

    async def recover_stopped_transactions(self, observation):
        self._recovered = None
        self._recovered_floor = None
        floor = self._observation_floor(observation)
        genesis_hash = observation.genesis_hash
        if not self._stopped or (await self.container.status()).phase == "running":
            raise SuccessorAdapterError("recovery requires confirmed stopped worker")
        validate_authenticated_successor_installation(self.installation)
        registry_snapshot = _recovery_journal_snapshot(self.path)
        weight_path = selected_weight_state_root(self.installation) / "competition-weights.sqlite3"
        attempts_snapshot = _recovery_journal_snapshot(weight_path, allow_absent_root=True)
        records = self._records()
        attempts = self._attempts()
        if _recovery_journal_snapshot(weight_path, allow_absent_root=True) != attempts_snapshot:
            raise SuccessorAdapterError("stopped weight journal changed during audit")
        targets = {}
        packages = {}
        recovery_packages = RecoveryPackageReplay()
        for selection, files in records.values():
            snapshot = _recovery_package_snapshot(files.package_path)
            prepared = self._verify(selection, files, recovery_packages=recovery_packages)
            if _recovery_package_snapshot(files.package_path) != snapshot:
                raise SuccessorAdapterError("retained recovery package changed during verification")
            packages[files.package_path] = snapshot
            if prepared.authorization is not None:
                identity = prepared.authorization.authorization.authorization_id
                if identity in targets:
                    raise SuccessorAdapterError("retained runs reuse a weight authorization")
                # Keep only bounded identities between audits. Reconstruct the
                # full continuation for the one unsettled attempt being handled.
                targets[identity] = (
                    selection.directive_sha256,
                    competition_weight_authorization_digest(prepared.authorization.authorization),
                    digest(prepared.execution.weights.chain),
                )
            del prepared  # Let the one-package cache release a previous round before the next load.
        for identity, attempt in attempts.items():
            binding = targets.get(identity)
            if (
                binding is None
                or attempt.authorization_sha256 != binding[1]
                or attempt.recovery_checkpoint_sha256 != self.installation.checkpoint_sha256
                or attempt.chain_config_sha256 != binding[2]
            ):
                raise SuccessorAdapterError("weight attempt lacks its retained signed authority")
            if attempt.phase in _TERMINAL:
                continue
            prepared = self._verify(*records[binding[0]], recovery_packages=recovery_packages)
            execution = prepared.execution.weights
            replay = CompetitionReplayWorker(
                self.root / "preflight-replay",
                package_limits=prepared.selection.signed.directive.replay_package.limits,
                capacity=self.installation.worker_execution_limits.replay_capacity_ceiling,
            )
            storage = self.installation.worker_execution_limits.weight_evidence_storage
            worker_type = (
                CompetitionWeightWorker if storage is None else ContentAddressedWeightWorker
            )
            worker = worker_type(
                selected_weight_state_root(self.installation),
                package_limits=prepared.selection.signed.directive.replay_package.limits,
                replay_worker=replay,
                maximum_attempts=execution.maximum_attempts,
                maximum_evidence_bytes=execution.maximum_evidence_bytes,
                submission_timeout_seconds=execution.submission_timeout_seconds,
                **({} if storage is None else storage.worker_options()),
            )
            outcome, current = await worker.reconcile_stopped(
                prepared.files.package_path,
                authorization=prepared.authorization,
                installation=self.installation,
                release=prepared.selection.signed.directive.release.replay_release_identity,
                chain_config=execution.chain,
                observe=partial(self._observe_at_floor, prepared, floor),
                finalized_floor=floor,
            )
            if outcome is None or outcome.status not in _TERMINAL:
                raise SuccessorAdapterError("successor transaction effects remain unknown")
            floor = self._observation_floor(current)
        # Audit all retained effects before the final proof, including the
        # empty and terminal-only cases. Metadata checks below cannot authorize
        # anything; they bind these completed audits across the asynchronous read.
        attempts_snapshot = _recovery_journal_snapshot(weight_path, allow_absent_root=True)
        if any(item.phase not in _TERMINAL for item in self._attempts().values()):
            raise SuccessorAdapterError("successor transaction recovery is incomplete")
        if _recovery_journal_snapshot(weight_path, allow_absent_root=True) != attempts_snapshot:
            raise SuccessorAdapterError("stopped weight journal changed during audit")
        await self.materializer.retire_redundant(records)
        observation = await self.observer.observe()
        validate_authenticated_successor_installation(self.installation)
        if not self._stopped or (await self.container.status()).phase == "running":
            raise SuccessorAdapterError("recovery lost confirmed stopped worker")
        if _recovery_journal_snapshot(self.path) != registry_snapshot:
            raise SuccessorAdapterError("retained recovery registry changed after verification")
        if _recovery_journal_snapshot(weight_path, allow_absent_root=True) != attempts_snapshot:
            raise SuccessorAdapterError("stopped weight journal changed after verification")
        if any(_recovery_package_snapshot(path) != saved for path, saved in packages.items()):
            raise SuccessorAdapterError("retained recovery package changed after verification")
        validate_owned_weight_observation(observation)
        if (
            account_id32(observation.validator_hotkey) != account_id32(self.config.validator_hotkey)
            or observation.genesis_hash != genesis_hash
            or observation.block < max(floor[0], self.installation.checkpoint_finalized_block)
            or (observation.block == floor[0] and observation.block_hash != floor[1])
        ):
            raise SuccessorAdapterError(
                "recovery proof changed validator, chain or finalized floor"
            )
        self._recovered = observation
        self._recovered_floor = self._observation_floor(observation)

    def _completed_replay(self, prepared):
        root = Path(self.config.worker_state_root) / "competition" / "replay"
        maximum = (
            self.installation.worker_execution_limits.replay_capacity_ceiling.maximum_bytes
            + 1024**2
        )
        with _read_worker_database(
            root / "competition-worker.sqlite3", root / "competition-worker.lock", maximum
        ) as db:
            size = db.execute(
                "SELECT length(receipt) FROM runs WHERE package=?",
                (prepared.package.package_sha256,),
            ).fetchone()
            if (
                size is None
                or not isinstance(size[0], int)
                or not 0 < size[0] <= _MAX_RECEIPT_BYTES
            ):
                raise SuccessorAdapterError("completed worker has no bounded replay receipt")
            row = db.execute(
                "SELECT policy,round,manifest_sha256,cutoff_certificate,"
                "settlement_certificate,NULL,status,cutoff_retained,"
                "settlement_retained,receipt_sha256,receipt FROM runs WHERE package=?",
                (prepared.package.package_sha256,),
            ).fetchone()
            manifest = prepared.package.manifest
            if row[:5] != (
                manifest.policy_sha256,
                manifest.round_sha256,
                prepared.package.manifest_sha256,
                manifest.cutoff_certificate_sha256,
                manifest.settlement_certificate_sha256,
            ):
                raise SuccessorAdapterError("completed replay journal metadata changed")
            receipt = _parse_stored_receipt(prepared.package, row)
            if receipt.status != "replayed_no_weight":
                raise SuccessorAdapterError("completed worker replay receipt is held")

    async def worker_is_healthy(self, selection):
        status = await self.container.status()
        if status.directive_sha256 != selection.directive_sha256:
            return False
        if status.phase == "running":
            return True
        if status.phase not in {"completed", "held", "failed"}:
            return False
        prepared = self._staged.get(selection.directive_sha256)
        if prepared is None:
            return False
        prepared = self._verify(selection, prepared.files)
        if prepared.authorization is None and status.phase != "completed":
            return False
        self._completed_replay(prepared)
        self._replay(prepared)
        if prepared.authorization is not None:
            attempt = self._attempts().get(prepared.authorization.authorization.authorization_id)
            if attempt is None or attempt.phase not in {"applied", "recovered_effect"}:
                return False
            if (
                attempt.authorization_sha256
                != competition_weight_authorization_digest(prepared.authorization.authorization)
                or attempt.recovery_checkpoint_sha256 != self.installation.checkpoint_sha256
                or attempt.chain_config_sha256 != digest(prepared.execution.weights.chain)
            ):
                raise SuccessorAdapterError("completed attempt binds different authority")
            floor = self._preflight.get(selection.directive_sha256)
            if floor is None:
                return False
            current = await self._observe(prepared, floor)
            validate_weight_preflight(
                prepared.package,
                prepared.authorization.authorization,
                current,
                prepared.execution.weights.chain,
                submission=False,
            )
            row = prepared.package.retained_settlement.projection
            if current.validator_row != tuple(zip(row.uids, row.weights, strict=True)):
                return False
        return True

    async def _start(self, selection, expected_mode):
        if (
            selection.mode != expected_mode
            or not self._stopped
            or self._recovered is None
            or self._recovered_floor is None
        ):
            raise SuccessorAdapterError(
                "worker start requires the fixed profile and stopped recovery"
            )
        prepared = self._staged.get(selection.directive_sha256)
        if prepared is None or prepared.release is None:
            raise SuccessorAdapterError("worker release has not been staged")
        if (await self.container.status()).phase == "running":
            raise SuccessorAdapterError("managed worker restarted after stopped recovery")
        if any(attempt.phase not in _TERMINAL for attempt in self._attempts().values()):
            raise SuccessorAdapterError("a successor attempt became unresolved before start")
        # Stopped recovery established terminal durable effects. Its timestamp
        # is not today's preflight authority; use its retained high-water only,
        # and collect a new owned proof after the image work below.
        floor = self._recovered_floor
        await self.container.prepare_image(prepared.release)
        await self._preflight_at_floor(selection, floor)
        observation = self._preflight[selection.directive_sha256]
        prepared = self._verify(selection, prepared.files)
        if prepared.authorization is not None:
            if prepared.authorization.authorization.authorization_id in self._attempts():
                # A stopped failed/held process may have had its exact effect
                # recovered after exit. Verify that result without a new run.
                if await self.worker_is_healthy(selection):
                    return
                raise SuccessorAdapterError("single-use successor authority was already attempted")
            validate_weight_preflight(
                prepared.package,
                prepared.authorization.authorization,
                observation,
                prepared.execution.weights.chain,
                submission=True,
            )
            # Initialize the empty private journal before retaining a launch.
            # Its later absence must never be interpreted as "never attempted".
            competition = _prepare_private_directory(
                Path(self.config.worker_state_root) / "competition", "successor worker state"
            )
            execution = prepared.execution.weights
            replay = CompetitionReplayWorker(
                competition / "replay",
                package_limits=selection.signed.directive.replay_package.limits,
                capacity=prepared.execution.replay_capacity,
            )
            storage = execution.evidence_storage
            worker_type = (
                CompetitionWeightWorker if storage is None else ContentAddressedWeightWorker
            )
            worker_type(
                selected_weight_state_root(self.installation),
                package_limits=selection.signed.directive.replay_package.limits,
                replay_worker=replay,
                maximum_attempts=execution.maximum_attempts,
                maximum_evidence_bytes=execution.maximum_evidence_bytes,
                submission_timeout_seconds=execution.submission_timeout_seconds,
                **({} if storage is None else storage.worker_options()),
            )
        self._retain(prepared)  # Durable source/authority identity before any worker start.
        activation = await self.materializer.activate(
            selection, prepared.files, owned_observation=observation
        )
        validate_authenticated_successor_activation(
            activation,
            validator_hotkey=self.config.validator_hotkey,
            directive_sha256=selection.directive_sha256,
            package_sha256=prepared.package.package_sha256,
            authorization_sha256=None
            if prepared.authorization is None
            else hashlib.sha256(prepared.files.authorization_bytes).hexdigest(),
            expected_profile=selection.mode,
        )
        if (
            canonical_json_bytes(activation.worker_execution_config)
            != prepared.files.worker_execution_bytes
        ):
            raise SuccessorAdapterError("activated worker execution differs from staged bytes")
        await self.container.remove_stopped()
        self._stopped, self._recovered = False, None
        self._recovered_floor = None
        await self.container.launch(activation, self._staged[selection.directive_sha256].release)

    async def start_replay(self, selection):
        await self._start(selection, "competition_replay")

    async def start_weights(self, selection):
        await self._start(selection, "competition_weights")
