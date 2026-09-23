"""Root-owned stopped migration lease, with proof capture after the full audit.

No stop/start or unit rewrite occurs here. Both the exact supervisor and its
rootless worker must already be stopped. A systemd namespace-aware entrypoint
must establish the coordinator view before calling this routine.
"""

from __future__ import annotations

import fcntl
import hashlib
import os
import pwd
import sqlite3
import stat
import time
from contextlib import ExitStack, asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path

from .competition_chain_state import validate_owned_weight_observation
from .competition_evidence_copy import verify_copied_legacy_weight_journal
from .competition_evidence_prepare import _hash_file
from .competition_evidence_rollover import EligibleEvidenceRollover
from .competition_evidence_worker import bind_worker_profile
from .competition_host_activation import (
    SuccessorWorkerExecutionLimits,
    validate_evidence_migration_receipt,
)
from .competition_host_artifacts import VerifiedHostTree
from .competition_host_upgrade import (
    _check_service_namespace,
    _require_empty_cgroup,
    _require_root_linux,
    _unit_snapshot,
)
from .competition_upgrade import _open_without_links
from .competition_weights import _recovery_journal_snapshot
from .encoding import account_id32
from .file_identity import file_fingerprint
from .protocol import canonical_json_bytes

_TOKEN = object()


def _stopped_unit(unit, service_uid):
    values = _unit_snapshot(unit)
    _check_service_namespace(unit, values)
    if (
        values["Id"] != unit
        or values["LoadState"] != "loaded"
        or values["ActiveState"] not in {"inactive", "failed"}
        or values["SubState"] not in {"dead", "failed"}
        or values["MainPID"] != "0"
        or values["ControlPID"] != "0"
        or pwd.getpwnam(values["User"]).pw_uid != service_uid
    ):
        raise ValueError("migration requires the exact stopped service identity")
    _require_empty_cgroup(unit, values["ControlGroup"])
    return values


@dataclass(frozen=True)
class StoppedEvidenceMigration:
    _plan: bytes
    _config_sha256: str
    _unit: str
    _uid: int
    _unit_before: dict
    _files: tuple
    _snapshots: tuple
    _observation: object
    _rollover: EligibleEvidenceRollover
    _consent: object
    _config: object
    _issuer: object = field(repr=False)
    _active: list = field(repr=False)

    def runtime_identity(self) -> dict:
        """Retain stable service identity across publication and process restart."""
        self.recheck()
        path, _, identity = self._files[0]
        return {
            "unit_name": self._unit,
            "service_uid": self._uid,
            "service_user": self._unit_before["User"],
            "fragment_path": self._unit_before["FragmentPath"],
            "lock_path": str(path),
            "lock_device": str(identity[0]),
            "lock_inode": str(identity[1]),
        }

    def validate_scope(self, plan, config):
        if (
            type(self) is not StoppedEvidenceMigration
            or self._issuer is not _TOKEN
            or not self._active[0]
            or plan.encoded() != self._plan
            or hashlib.sha256(canonical_json_bytes(config)).hexdigest() != self._config_sha256
        ):
            raise ValueError("stopped evidence lease is absent, closed or for another transition")
        self.recheck()

    def recheck(self):
        if self._issuer is not _TOKEN or not self._active[0]:
            raise ValueError("stopped evidence migration lease is closed")
        if _stopped_unit(self._unit, self._uid) != self._unit_before:
            raise ValueError("stopped supervisor identity changed during migration")
        for path, descriptor, identity in self._files:
            named = _open_without_links(path)
            try:
                if (
                    file_fingerprint(os.fstat(named)) != identity
                    or file_fingerprint(os.fstat(descriptor)) != identity
                ):
                    raise ValueError("migration file or lock identity changed")
            finally:
                os.close(named)
        for path, snapshot in self._snapshots:
            if _recovery_journal_snapshot(path, expected_owner=self._uid) != snapshot:
                raise ValueError("migration database family changed")
        validate_owned_weight_observation(self._observation)
        self._rollover.recheck(
            config=self._config, consent=self._consent, observation=self._observation
        )


def _private_file(path, owner, stack, *, lock=False):
    descriptor = _open_without_links(path)
    stack.callback(os.close, descriptor)
    info = os.fstat(descriptor)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != owner
        or info.st_nlink != 1
        or info.st_mode & 0o777 != 0o600
    ):
        raise ValueError("migration source, candidate or lock is not private")
    if lock:
        if info.st_size > 4096:
            raise ValueError("migration lock is oversized")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    return descriptor


@asynccontextmanager
async def hold_stopped_evidence_migration(
    plan,
    *,
    config,
    unit_name,
    service_uid,
    candidate_receipt,
    consent,
    worker_limits_bytes,
    verified_host_tree,
    observer_config,
    observe_after_audit,
    verify_worker_stopped,
    eligible_replacement,
):
    """Hold both journal locks and the supervisor lock through atomic selection.

    `verify_worker_stopped` must use the installed ownership-checking container
    adapter in its exact service namespace. `observe_after_audit` must return an
    owned proof capability, never a JSON observation. Root CLI integration is
    deliberately separate from these typed storage/authorization boundaries.
    """
    if type(eligible_replacement) is not EligibleEvidenceRollover:
        raise ValueError("migration cannot retire current renewals without an eligible replacement")
    eligible_replacement.recheck(config=config, consent=consent)
    _require_root_linux()
    if type(verified_host_tree) is not VerifiedHostTree:
        raise ValueError("migration requires the authenticated exact Linux host tree")
    validate_evidence_migration_receipt(
        candidate_receipt, config=config, consent=consent, worker_limits_bytes=worker_limits_bytes
    )
    seal = candidate_receipt.evidence_migration
    if seal is None or service_uid != seal.service_uid:
        raise ValueError("migration root seal does not identify this service owner")
    body = consent.history_compatibility.body
    if verified_host_tree.manifest_sha256 != body.target_host_manifest_sha256:
        raise ValueError("migration tree differs from signed target")
    if (
        hashlib.sha256(canonical_json_bytes(observer_config)).hexdigest()
        != candidate_receipt.host_observer_config_sha256
    ):
        raise ValueError(
            "migration observer differs from immutable original observer configuration"
        )
    unit_before = _stopped_unit(unit_name, service_uid)
    with ExitStack() as stack:
        files, snapshots = [], []
        process_path = Path(config.state_root) / "supervisor-process.lock"
        fd = _private_file(process_path, service_uid, stack, lock=True)
        files.append((process_path, fd, file_fingerprint(os.fstat(fd))))
        roots = (Path(seal.source_root), Path(seal.candidate_root))
        expected = (seal.source_database_sha256, seal.candidate_database_sha256)
        databases = []
        for root, sha in zip(roots, expected, strict=True):
            directory = _open_without_links(root)
            stack.callback(os.close, directory)
            info = os.fstat(directory)
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid != service_uid
                or info.st_mode & 0o777 != 0o700
            ):
                raise ValueError("migration database root must be private and owned")
            lock = root / "competition-weights.lock"
            fd = _private_file(lock, service_uid, stack, lock=True)
            files.append((lock, fd, file_fingerprint(os.fstat(fd))))
            path = root / "competition-weights.sqlite3"
            snapshot = _recovery_journal_snapshot(path, expected_owner=service_uid)
            if any(identity is not None for _, identity in snapshot[1][1:]):
                raise ValueError("migration requires native rollback recovery before sealing")
            fd = _private_file(path, service_uid, stack)
            files.append((path, fd, file_fingerprint(os.fstat(fd))))
            if _hash_file(fd, 32 * 1024**3) != sha:
                raise ValueError("migration database image differs from root seal")
            snapshots.append((path, snapshot))
            db = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, isolation_level=None)
            stack.callback(db.close)
            db.execute("PRAGMA query_only=ON")
            db.execute("BEGIN")
            if db.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
                raise ValueError("migration SQLite integrity check failed")
            databases.append(db)
        limits = SuccessorWorkerExecutionLimits.model_validate_json(
            worker_limits_bytes, strict=True
        )
        storage = limits.weight_evidence_storage
        binding = databases[0].execute("SELECT * FROM binding").fetchall()
        if len(binding) != 1 or account_id32(binding[0][0]) != account_id32(
            config.validator_hotkey
        ):
            raise ValueError("migration weight owner differs from signed validator")
        binding_sha = hashlib.sha256(canonical_json_bytes(binding)).hexdigest()
        verify_copied_legacy_weight_journal(
            databases[0],
            databases[1],
            expected_binding_sha256=binding_sha,
            limits=storage.profile().limits,
        )
        bind_worker_profile(databases[1], storage.profile())
        verified_host_tree.recheck()
        await verify_worker_stopped()
        # Capture only after the full evidence/tree audit and OS lifecycle check.
        audited_at = time.monotonic_ns()
        observation = await observe_after_audit()
        validate_owned_weight_observation(observation)
        if (
            observation.captured_monotonic_ns < audited_at
            or account_id32(observation.validator_hotkey) != account_id32(config.validator_hotkey)
            or not body.migration_valid_from_block
            <= observation.block
            <= body.migration_valid_through_block
            or observation.block < seal.migration_finalized_block
            or observation.genesis_hash != candidate_receipt.checkpoint_genesis_hash
            or observation.chain_config_sha256
            != hashlib.sha256(canonical_json_bytes(observer_config.chain)).hexdigest()
        ):
            raise ValueError("migration needs a fresh owned chain proof after its heavy audit")
        eligible_replacement.validate_migration(
            plan=plan,
            config=config,
            consent=consent,
            receipt=candidate_receipt,
            observation=observation,
        )
        active = [True]
        lease = StoppedEvidenceMigration(
            plan.encoded(),
            hashlib.sha256(canonical_json_bytes(config)).hexdigest(),
            unit_name,
            service_uid,
            unit_before,
            tuple(files),
            tuple(snapshots),
            observation,
            eligible_replacement,
            consent,
            config,
            _TOKEN,
            active,
        )
        try:
            lease.validate_scope(plan, config)
            yield lease
            lease.recheck()
        finally:
            active[0] = False
