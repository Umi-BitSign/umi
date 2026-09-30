"""Drain the complete retained C4 inventory while preserving its writer locks.

The installed standing host keeps this context open for its lifetime. It must
select the approved new executable at boot; this library does not install it.
No old attempt, signed history or original process lock is replaced or deleted.
"""

import hashlib
import json
import logging
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager

from .competition_evidence_reader import evidence_reader
from .competition_host_activation import selected_weight_state_root
from .competition_recovery_packages import RecoveryPackageReplay
from .competition_reward_control_archive import HistoricalRewardControlProvider
from .competition_reward_handoff_models import (
    LegacyRewardHandoffIntent,
    LegacyRewardHandoffPlan,
    VerifiedLegacyRewardHandoff,
    _issue_legacy_handoff,
)
from .competition_reward_legacy_recovery import (
    review_legacy_weight_expiry,
    validate_legacy_weight_expiry,
)
from .competition_reward_preparation import PreparedStandingReward, StandingRewardPreparation
from .competition_supervisor_adapters import (
    _MAX_ATTEMPT_BYTES,
    ProductionSuccessorRuntimeAdapter,
    _read_worker_database,
)
from .competition_supervisor_runtime import SuccessorSupervisorRuntime
from .competition_weights import (
    _recovery_journal_snapshot,
    _recovery_package_snapshot,
    _WeightAttempt,
    competition_weight_authorization_digest,
)
from .encoding import account_id32
from .open_competition import digest, identity
from .protocol import canonical_json_bytes

_LOG = logging.getLogger(__name__)


def _attempts(db, adapter):
    ceiling = adapter.installation.worker_execution_limits
    count, maximum = db.execute(
        "SELECT COUNT(*),COALESCE(MAX(length(body)),0) FROM attempts"
    ).fetchone()
    if count > ceiling.maximum_weight_attempts or maximum > _MAX_ATTEMPT_BYTES:
        raise ValueError("legacy handoff inventory exceeds its bounds")
    read = evidence_reader(
        db,
        storage=ceiling.weight_evidence_storage,
        validator_hotkey=adapter.config.validator_hotkey,
        maximum_attempts=ceiling.maximum_weight_attempts,
        maximum_evidence_bytes=ceiling.maximum_weight_evidence_bytes,
    )
    attempts = []
    for key, raw, sha in db.execute("SELECT id,body,sha256 FROM attempts ORDER BY id"):
        if type(raw) is not bytes or hashlib.sha256(raw).hexdigest() != sha:
            raise ValueError("legacy handoff attempt checksum differs")
        item = _WeightAttempt.model_validate_json(raw)
        if (
            canonical_json_bytes(item) != raw
            or item.authorization_id != key
            or account_id32(item.validator_hotkey) != account_id32(adapter.config.validator_hotkey)
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
        with _read_worker_database(path, lock, ceiling) as db:
            # Both locks stay held across slow proof work and the caller's whole
            # execution lifetime. Snapshot guards also reject out-of-protocol edits.
            weight_snapshot = _recovery_journal_snapshot(path)
            registry_snapshot = _recovery_journal_snapshot(adapter.path)
            lock_identity = (lock.stat().st_dev, lock.stat().st_ino)
            active = True

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

            try:
                attempts, read = _attempts(db, adapter)
                _LOG.info("legacy_handoff_inventory attempts=%d", len(attempts))
                targets, packages = {}, {}
                replay = RecoveryPackageReplay()
                for selection, files in adapter._records().values():
                    snapshot = _recovery_package_snapshot(files.package_path)
                    checked = adapter._verify(selection, files, recovery_packages=replay)
                    if _recovery_package_snapshot(files.package_path) != snapshot:
                        raise ValueError("legacy package changed during handoff replay")
                    packages[files.package_path] = snapshot
                    if checked.authorization is not None:
                        auth = checked.authorization.authorization
                        authority = (
                            competition_weight_authorization_digest(auth),
                            digest(checked.execution.weights.chain),
                            auth.mortality_period,
                        )
                        prior = targets.setdefault(auth.authorization_id, authority)
                        if prior != authority:
                            raise ValueError("legacy handoff changes a retained authorization")
                receipts = []
                for index, (raw, item) in enumerate(attempts, 1):
                    if (
                        targets.get(item.authorization_id)
                        != (
                            item.authorization_sha256,
                            item.chain_config_sha256,
                            item.era_death - item.preflight_block,
                        )
                        or item.recovery_checkpoint_sha256 != adapter.installation.checkpoint_sha256
                    ):
                        raise ValueError("legacy attempt lacks its exact retained authority")
                    chain = read(item.chain_evidence_sha256)
                    metadata = read(json.loads(chain)["runtime_metadata_sha256"])
                    if item.signed_extrinsic is None:
                        # The original worker durably saves exact signed bytes
                        # before broadcasting. Under its continuously held lock,
                        # an unsigned intention cannot create a future effect.
                        # Recovery may have changed its local phase to unknown
                        # or expired; neither label is used as an expiry proof.
                        recheck()
                        _LOG.info("legacy_handoff_unsigned index=%d total=%d", index, len(attempts))
                        continue
                    provider = providers.get(item.chain_config_sha256)
                    if (
                        not isinstance(provider, HistoricalRewardControlProvider)
                        or digest(provider.config) != item.chain_config_sha256
                    ):
                        raise ValueError("legacy handoff lacks the original chain provider")
                    result = await review_legacy_weight_expiry(
                        provider,
                        attempt=raw,
                        chain=chain,
                        metadata=metadata,
                        validator_hotkey=runtime.config.validator_hotkey,
                    )
                    if result is None:
                        raise ValueError("legacy transaction remains live; handoff is pending")
                    validate_legacy_weight_expiry(
                        result,
                        attempt=raw,
                        chain_config_sha256=item.chain_config_sha256,
                        validator_hotkey=runtime.config.validator_hotkey,
                    )
                    recheck()
                    receipts.append(result)
                    _LOG.info("legacy_handoff_expired index=%d total=%d", index, len(attempts))
                if (await adapter.container.status()).phase == "running":
                    raise ValueError("legacy worker restarted during handoff review")
                for package, snapshot in packages.items():
                    if _recovery_package_snapshot(package) != snapshot:
                        raise ValueError("legacy package changed during handoff review")
                recheck()
                _LOG.info("legacy_handoff_inventory_verified attempts=%d", len(attempts))
                yield _issue_legacy_handoff(
                    intent,
                    digest([hashlib.sha256(raw).hexdigest() for raw, _ in attempts]),
                    max(
                        [
                            prepared.reviewed_at_block,
                            *(item.preflight_block for _, item in attempts),
                            *(r.finalized.block_number for r in receipts),
                        ]
                    ),
                    recheck,
                )
            finally:
                active = False
