"""Drain the complete retained C4 inventory while preserving its writer locks.

The installed standing host keeps this context open for its lifetime. It must
select the approved new executable at boot; this library does not install it.
No old attempt, signed history or original process lock is replaced or deleted.
"""

import asyncio
import hashlib
import json
import logging
import os
import sqlite3
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from threading import Event

from .competition_evidence_audit_progress import EvidenceAuditProgress
from .competition_evidence_reader import evidence_reader
from .competition_host_activation import (
    selected_weight_state_root,
    validate_authenticated_successor_installation,
)
from .competition_recovery_packages import RecoveryPackageReplay
from .competition_reward_control_archive import HistoricalRewardControlProvider
from .competition_reward_handoff_models import (
    MAX_HANDOFF_BYTES,
    LegacyRewardHandoffIntent,
    LegacyRewardHandoffPlan,
    VerifiedLegacyRewardHandoff,
    _issue_legacy_handoff,
)
from .competition_reward_handoff_reuse import (
    LegacyHandoffVerification,
    repair_required,
    snapshot_identity,
)
from .competition_reward_legacy_recovery import (
    review_legacy_weight_expiry,
    validate_legacy_weight_expiry,
)
from .competition_reward_preparation import PreparedStandingReward, StandingRewardPreparation
from .competition_supervisor import MAX_SUCCESSOR_DOCUMENT_BYTES
from .competition_supervisor_adapters import (
    _MAX_ATTEMPT_BYTES,
    ProductionSuccessorRuntimeAdapter,
    _read_worker_database,
)
from .competition_supervisor_runtime import (
    SuccessorRuntimeLimits,
    SuccessorSupervisorRuntime,
    retained_runtime_binding,
)
from .competition_weights import (
    _recovery_journal_snapshot,
    _recovery_package_snapshot,
    _WeightAttempt,
    competition_weight_authorization_digest,
)
from .competition_work_progress import (
    WorkProgress,
    cancellable_work,
    check_work_cancelled,
    work_heartbeats,
)
from .competition_worker import _open_private_regular_file
from .concurrency import run_owned_thread
from .encoding import account_id32
from .open_competition import digest, identity
from .protocol import canonical_json_bytes

_LOG = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class RetainedLegacyHandoffIntent:
    """Original private intent metadata, without any process or writer lease."""

    path: Path
    snapshot: tuple
    runtime_binding: bytes
    intent: LegacyRewardHandoffIntent


def read_retained_handoff_intent(installation, limits: SuccessorRuntimeLimits):
    """Read an existing native intent while the original supervisor keeps running.

    Preparation cannot create or replace the intent, replay history, or acquire
    writer ownership. The eventual handoff must match this source identity and
    perform the native selection checks under its original process locks.
    """
    validate_authenticated_successor_installation(installation)
    if type(limits) is not SuccessorRuntimeLimits:
        raise TypeError("native runtime limits required")
    limits = SuccessorRuntimeLimits.model_validate_json(canonical_json_bytes(limits))
    binding = retained_runtime_binding(installation, limits)
    path = Path(installation.config.state_root) / "successor-v4/runtime/supervisor.sqlite3"
    with WorkProgress("legacy_handoff_intent_preparation", 1, unit="intents") as meter:
        snapshot = _recovery_journal_snapshot(path)
        if any(value is not None for suffix, value in snapshot[1] if suffix):
            raise ValueError("read-only intent preparation requires a stable DELETE journal")
        descriptor = _open_private_regular_file(path, "retained handoff intent")
        try:
            header = os.read(descriptor, 20)
        finally:
            os.close(descriptor)
        if header[:16] != b"SQLite format 3\x00" or header[18:20] != b"\x01\x01":
            raise ValueError("read-only intent preparation requires a stable DELETE journal")
        db = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=1)
        try:
            db.execute("PRAGMA query_only=ON")
            db.execute("BEGIN")
            bounded = SuccessorSupervisorRuntime._bounded_row
            if bounded(db, "binding", MAX_SUCCESSOR_DOCUMENT_BYTES) != (binding,):
                raise ValueError("retained handoff runtime binding changed")
            if not db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='standing_handoff'"
            ).fetchone():
                raise ValueError("preparation requires the original retained handoff intent")
            row = bounded(db, "standing_handoff", MAX_HANDOFF_BYTES)
            if row is None:
                raise ValueError("retained handoff intent is incomplete")
            intent = LegacyRewardHandoffIntent.model_validate_json(row[0])
            if canonical_json_bytes(intent) != row[0] or (
                intent.installation_receipt_sha256 != installation.receipt_sha256
                or identity(intent.validator_hotkey)
                != identity(installation.config.validator_hotkey)
            ):
                raise ValueError("retained handoff intent differs from its installation")
            if _recovery_journal_snapshot(path) != snapshot:
                raise ValueError("retained handoff intent changed during preparation")
        finally:
            db.close()
        if _recovery_journal_snapshot(path) != snapshot:
            raise ValueError("retained handoff intent changed during preparation")
        meter.advance()
        return RetainedLegacyHandoffIntent(path, snapshot, binding, intent)


def _attempts(db, installation, *, audit_evidence=True, audit_progress=None):
    ceiling = installation.worker_execution_limits
    count, maximum = db.execute(
        "SELECT COUNT(*),COALESCE(MAX(length(body)),0) FROM attempts"
    ).fetchone()
    if count > ceiling.maximum_weight_attempts or maximum > _MAX_ATTEMPT_BYTES:
        raise ValueError("legacy handoff inventory exceeds its bounds")
    read = evidence_reader(
        db,
        storage=ceiling.weight_evidence_storage,
        validator_hotkey=installation.config.validator_hotkey,
        maximum_attempts=ceiling.maximum_weight_attempts,
        maximum_evidence_bytes=ceiling.maximum_weight_evidence_bytes,
        audit_evidence=audit_evidence,
        audit_progress=audit_progress,
    )
    attempts = []
    for key, raw, sha in db.execute("SELECT id,body,sha256 FROM attempts ORDER BY id"):
        check_work_cancelled()
        if type(raw) is not bytes or hashlib.sha256(raw).hexdigest() != sha:
            raise ValueError("legacy handoff attempt checksum differs")
        item = _WeightAttempt.model_validate_json(raw)
        if (
            canonical_json_bytes(item) != raw
            or item.authorization_id != key
            or account_id32(item.validator_hotkey)
            != account_id32(installation.config.validator_hotkey)
        ):
            raise ValueError("legacy handoff attempt identity differs")
        attempts.append((raw, item))
    return attempts, read


def _check_selection(preparation, prepared, plan, runtime):
    preparation._check_prepared(prepared)
    reader = preparation.reader
    if (
        plan.series_sha256 != preparation.series_sha256
        or plan.cohort_sha256 != digest(reader.series.cohorts[0])
        or plan.cohort_sha256 != prepared.activation.cohort_sha256
        or digest(plan) != prepared.activation.prior_opportunity_sha256
        or identity(runtime.config.validator_hotkey)
        not in {identity(k) for k in reader.series.validators}
    ):
        raise ValueError("legacy handoff differs from approved first activation")
    _, history, _ = runtime._load_history()
    selected = [s.directive for s in history if s.directive.mode == "competition_weights"]
    if not selected:
        raise ValueError("legacy handoff has no accepted C4 weight selection")
    target = selected[-1].replay_package
    if (
        target.policy_sha256 != plan.legacy_policy_sha256
        or target.round_sha256 != plan.legacy_round_sha256
        or target.package_sha256 != plan.legacy_package_sha256
    ):
        raise ValueError("legacy handoff changes the accepted predecessor package")


@asynccontextmanager
async def hold_legacy_reward_handoff(
    runtime: SuccessorSupervisorRuntime,
    *,
    preparation: StandingRewardPreparation,
    prepared: PreparedStandingReward,
    plan: LegacyRewardHandoffPlan,
    providers: Mapping[str, HistoricalRewardControlProvider],
) -> AsyncIterator[VerifiedLegacyRewardHandoff]:
    """Yield only while the old runtime and complete weight inventory stay locked.

    Providers are selected by their exact original chain configuration digest.
    Missing history, live transactions or unavailable proofs leave the migration
    intent pending. A restart resumes the same intent; it cannot restart C4.
    """
    if (
        type(runtime) is not SuccessorSupervisorRuntime
        or type(runtime.adapter) is not ProductionSuccessorRuntimeAdapter
        or type(preparation) is not StandingRewardPreparation
    ):
        raise TypeError("legacy handoff requires the native installed runtime and preparation")
    plan = LegacyRewardHandoffPlan.model_validate_json(canonical_json_bytes(plan))
    adapter = runtime.adapter
    if adapter.installation is not runtime.installation:
        raise ValueError("legacy handoff adapter belongs to another installation")
    async with runtime._mutex:
        runtime._require_lease()
        _check_selection(preparation, prepared, plan, runtime)
        intent = LegacyRewardHandoffIntent(
            schema="umi-legacy-reward-handoff-intent/1",
            plan=plan,
            activation_sha256=digest(prepared.activation),
            installation_receipt_sha256=runtime.installation.receipt_sha256,
            validator_hotkey=runtime.config.validator_hotkey,
        )
        runtime._retain_standing_handoff(intent)
        _LOG.info("legacy_handoff_stop_requested")
        # Keep durable intent even if stop is interrupted or fails. No result is
        # issued until worker absence and the entire retained inventory are checked.
        await runtime.stop_worker_for_handoff()
        if not adapter._stopped or (await adapter.container.status()).phase == "running":
            raise ValueError("legacy handoff requires confirmed worker absence")
        root = selected_weight_state_root(adapter.installation)
        path = root / "competition-weights.sqlite3"
        lock = root / "competition-weights.lock"
        if not path.exists() or not lock.exists():
            raise ValueError("legacy handoff requires its complete retained weight journal")
        limits = adapter.installation.worker_execution_limits
        storage = limits.weight_evidence_storage
        ceiling = (
            (
                limits.maximum_weight_evidence_bytes
                if storage is None
                else storage.maximum_database_bytes
            )
            + limits.maximum_weight_attempts * _MAX_ATTEMPT_BYTES
            + 1024**2
        )
        verification = LegacyHandoffVerification(runtime, intent)
        initial_weight_snapshot = _recovery_journal_snapshot(path)
        context = {
            "weight_journal": snapshot_identity(initial_weight_snapshot),
            "registry": snapshot_identity(_recovery_journal_snapshot(adapter.path)),
            "limits": digest(limits),
            "adapter_binding": hashlib.sha256(adapter._binding).hexdigest(),
        }
        audited = verification.load("evidence_audit", "inventory", context)
        completed = verification.load("completion", "inventory", context)
        database_checked = verification.load("database_check", "inventory", context)
        if completed is not None and audited is None:
            raise repair_required("inventory_audit_completion_missing")
        with _read_worker_database(
            path,
            lock,
            ceiling,
            defer_integrity_check=True,
            verified_snapshot=initial_weight_snapshot
            if audited is not None or database_checked is not None
            else None,
        ) as db:
            # Both locks stay held across slow proof work and the caller's whole
            # execution lifetime. Snapshot guards also reject out-of-protocol edits.
            weight_snapshot = _recovery_journal_snapshot(path)
            registry_snapshot = _recovery_journal_snapshot(adapter.path)
            if (
                snapshot_identity(weight_snapshot) != context["weight_journal"]
                or snapshot_identity(registry_snapshot) != context["registry"]
            ):
                raise repair_required("inputs_changed_during_lock_acquisition")
            lock_identity = (lock.stat().st_dev, lock.stat().st_ino)
            active = True
            packages = {}

            def recheck():
                if not active or not runtime._mutex.locked():
                    raise ValueError("legacy handoff writer lease has ended")
                runtime._require_lease()
                if (
                    runtime._standing_handoff_intent() != intent
                    or _recovery_journal_snapshot(path) != weight_snapshot
                    or _recovery_journal_snapshot(adapter.path) != registry_snapshot
                    or (lock.stat().st_dev, lock.stat().st_ino) != lock_identity
                ):
                    raise ValueError("legacy handoff retained writer state changed")
                for package, snapshot in packages.items():
                    if snapshot_identity(_recovery_package_snapshot(package)) != snapshot:
                        raise repair_required("retained_package_changed")

            try:
                with verification.reuse.exclusive():
                    await _verify_database_integrity(
                        db,
                        verification,
                        context,
                        recheck,
                        already_checked=audited is not None or database_checked is not None,
                    )
                    completed = await _verify_inventory(
                        runtime.installation,
                        providers,
                        verification,
                        context,
                        db,
                        recheck,
                        packages,
                        audited=audited,
                        completed=completed,
                        weight_snapshot=weight_snapshot,
                        registry_snapshot=registry_snapshot,
                        minimum_block=prepared.reviewed_at_block,
                        read_records=adapter._records,
                        verify_package=adapter._verify,
                    )
                if (await adapter.container.status()).phase == "running":
                    raise ValueError("legacy worker restarted during handoff review")
                recheck()
                yield _issue_legacy_handoff(
                    intent,
                    completed["inventory_sha256"],
                    max(prepared.reviewed_at_block, completed["through_block"]),
                    recheck,
                )
            finally:
                active = False


async def _verify_database_integrity(db, verification, context, recheck, *, already_checked):
    """Retain one structural pass; drain cooperative SQLite work on cancellation."""
    if already_checked:
        recheck()
        return
    stopping = Event()

    def check():
        db.set_progress_handler(lambda: int(stopping.is_set()), 1000)
        try:
            if db.execute("PRAGMA quick_check").fetchone() != ("ok",):
                raise ValueError("legacy handoff journal is corrupt")
        except sqlite3.OperationalError as error:
            if stopping.is_set():
                raise asyncio.CancelledError("legacy database check cancelled") from error
            raise
        finally:
            db.set_progress_handler(None, 0)

    with work_heartbeats(), WorkProgress("legacy_database_integrity", 1, unit="journals") as meter:
        await run_owned_thread(check, on_cancel=stopping.set)
        recheck()
        verification.remember("database_check", "inventory", context, {"complete": True})
        meter.advance()


def restore_prepared_inventory(completed, packages, recheck):
    """Restore only source metadata after the caller checks provider bindings."""
    with WorkProgress("legacy_handoff_restoration", 1, unit="inventories") as meter:
        packages.update({Path(item["path"]): item["snapshot"] for item in completed["packages"]})
        recheck()
        meter.advance()
    _LOG.info("legacy_handoff_inventory_restored attempts=%d", completed["attempts"])
    return completed


async def _verify_inventory(
    installation,
    providers,
    verification,
    context,
    db,
    recheck,
    packages,
    *,
    audited,
    completed,
    weight_snapshot,
    registry_snapshot,
    minimum_block,
    read_records,
    verify_package,
):
    """Checkpoint native verification without granting writer ownership."""
    if completed is not None:
        for identity in completed["providers"]:
            provider = providers.get(identity)
            if (
                not isinstance(provider, HistoricalRewardControlProvider)
                or digest(provider.config) != identity
            ):
                raise ValueError("legacy handoff lacks the original chain provider")
        return restore_prepared_inventory(completed, packages, recheck)
    with (
        work_heartbeats(),
        WorkProgress("legacy_handoff_inventory_audit", 1, unit="inventories") as meter,
    ):
        stopping = Event()
        with cancellable_work(stopping):
            attempts, read = await run_owned_thread(
                partial(
                    _attempts,
                    db,
                    installation,
                    audit_evidence=audited is None,
                    audit_progress=EvidenceAuditProgress(verification, context, recheck),
                ),
                on_cancel=stopping.set,
            )
        recheck()
        if audited is None:
            verification.remember("evidence_audit", "inventory", context, {"complete": True})
        meter.advance()
    _LOG.info("legacy_handoff_inventory attempts=%d", len(attempts))
    targets = {}
    replay = RecoveryPackageReplay()
    records = read_records()
    with (
        work_heartbeats(),
        WorkProgress("legacy_handoff_packages", len(records), unit="runs") as progress,
    ):
        for selection, files, restored in records.recovery_values():
            snapshot = _recovery_package_snapshot(files.package_path)
            package_context = {
                "snapshot": snapshot_identity(snapshot),
                "registry": snapshot_identity(registry_snapshot),
                "selection": selection.directive_sha256,
                "installation": installation.receipt_sha256,
            }
            retained = verification.load("package", selection.directive_sha256, package_context)
            if retained is None:
                checked = verify_package(
                    selection,
                    files,
                    recovery_packages=replay,
                    recovery_history=restored,
                )
                if _recovery_package_snapshot(files.package_path) != snapshot:
                    raise ValueError("legacy package changed during handoff replay")
                retained = {"authorization_id": None, "authority": None}
                if checked.authorization is not None:
                    auth = checked.authorization.authorization
                    retained = {
                        "authorization_id": auth.authorization_id,
                        "authority": [
                            competition_weight_authorization_digest(auth),
                            digest(checked.execution.weights.chain),
                            auth.mortality_period,
                        ],
                    }
                recheck()
                verification.remember(
                    "package", selection.directive_sha256, package_context, retained
                )
            packages[files.package_path] = snapshot_identity(snapshot)
            if retained["authorization_id"] is not None:
                authority = tuple(retained["authority"])
                prior = targets.setdefault(retained["authorization_id"], authority)
                if prior != authority:
                    raise ValueError("legacy handoff changes a retained authorization")
            progress.advance()
    expiry_blocks, selected_providers = [], set()
    with (
        work_heartbeats(),
        WorkProgress("legacy_handoff_expiry", len(attempts), unit="attempts") as progress,
    ):
        for index, (raw, item) in enumerate(attempts, 1):
            if (
                targets.get(item.authorization_id)
                != (
                    item.authorization_sha256,
                    item.chain_config_sha256,
                    item.era_death - item.preflight_block,
                )
                or item.recovery_checkpoint_sha256 != installation.checkpoint_sha256
            ):
                raise ValueError("legacy attempt lacks its exact retained authority")
            if item.signed_extrinsic is None:
                # The original worker durably saves exact signed bytes
                # before broadcasting. Preparation binds the unchanged source;
                # final handoff also holds the original lock, so an unsigned
                # intention cannot create a future effect under that lease.
                # Recovery may have changed its local phase to unknown
                # or expired; neither label is used as an expiry proof.
                recheck()
                _LOG.info("legacy_handoff_unsigned index=%d total=%d", index, len(attempts))
                progress.advance()
                continue
            provider = providers.get(item.chain_config_sha256)
            if (
                not isinstance(provider, HistoricalRewardControlProvider)
                or digest(provider.config) != item.chain_config_sha256
            ):
                raise ValueError("legacy handoff lacks the original chain provider")
            selected_providers.add(item.chain_config_sha256)
            expiry_context = {
                "journal": snapshot_identity(weight_snapshot),
                "attempt": hashlib.sha256(raw).hexdigest(),
                "authority": targets[item.authorization_id],
                "provider": digest(provider.config),
            }
            retained = verification.load("expiry", item.authorization_id, expiry_context)
            if retained is None:
                chain = read(item.chain_evidence_sha256)
                metadata = read(json.loads(chain)["runtime_metadata_sha256"])
                result = await review_legacy_weight_expiry(
                    provider,
                    attempt=raw,
                    chain=chain,
                    metadata=metadata,
                    validator_hotkey=installation.config.validator_hotkey,
                )
                if result is None:
                    raise ValueError("legacy transaction remains live; handoff is pending")
                validate_legacy_weight_expiry(
                    result,
                    attempt=raw,
                    chain_config_sha256=item.chain_config_sha256,
                    validator_hotkey=installation.config.validator_hotkey,
                )
                recheck()
                retained = {"finalized_block": result.finalized.block_number}
                verification.remember("expiry", item.authorization_id, expiry_context, retained)
            recheck()
            expiry_blocks.append(retained["finalized_block"])
            _LOG.info("legacy_handoff_expired index=%d total=%d", index, len(attempts))
            progress.advance()
    recheck()
    _LOG.info("legacy_handoff_inventory_verified attempts=%d", len(attempts))
    completed = {
        "inventory_sha256": digest([hashlib.sha256(raw).hexdigest() for raw, _ in attempts]),
        "through_block": max(
            [
                minimum_block,
                *(item.preflight_block for _, item in attempts),
                *expiry_blocks,
            ]
        ),
        "attempts": len(attempts),
        "packages": [
            {"path": str(path), "snapshot": snapshot} for path, snapshot in packages.items()
        ],
        "providers": sorted(selected_providers),
    }
    verification.remember("completion", "inventory", context, completed)
    recheck()
    return completed
