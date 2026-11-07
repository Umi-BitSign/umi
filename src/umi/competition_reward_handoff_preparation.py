"""Prepare retained legacy verification while the standing writer remains active.

The caller authenticates the installation through its supported loader and owns
independent native proof providers. This module cannot stop a service, create a
handoff decision, acquire writer ownership or load a signing key.
"""

import hashlib
import os
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from functools import partial
from pathlib import Path

from .competition_chain import CompetitionChainConfig
from .competition_host_activation import (
    selected_weight_state_root,
    validate_authenticated_successor_installation,
)
from .competition_reward_handoff import (
    _verify_database_integrity,
    _verify_inventory,
    read_retained_handoff_intent,
    restore_prepared_inventory,
)
from .competition_reward_handoff_reuse import (
    LegacyHandoffVerification,
    repair_required,
    snapshot_identity,
)
from .competition_supervisor_adapters import (
    _MAX_ATTEMPT_BYTES,
    SuccessorAdapterLimits,
    read_retained_adapter_inventory,
    retained_adapter_binding,
    verify_retained_package,
)
from .competition_weights import _recovery_journal_snapshot, _recovery_package_snapshot
from .competition_worker import _open_private_regular_file
from .open_competition import digest


@dataclass(frozen=True, slots=True)
class LegacyHandoffPreparationResult:
    """Progress summary only; the final handoff reopens native durable receipts."""

    intent_sha256: str
    inventory_sha256: str
    attempts: int
    through_block: int


@contextmanager
def _read_preparation_database(path, maximum_bytes, snapshot):
    if any(value is not None for suffix, value in snapshot[1] if suffix):
        raise repair_required("preparation_requires_stable_delete_journal")
    descriptor = _open_private_regular_file(path, "legacy preparation journal")
    try:
        if os.fstat(descriptor).st_size > maximum_bytes:
            raise ValueError("legacy preparation journal exceeds its byte budget")
        header = os.read(descriptor, 20)
    finally:
        os.close(descriptor)
    if header[:16] != b"SQLite format 3\x00" or header[18:20] != b"\x01\x01":
        raise repair_required("preparation_requires_stable_delete_journal")
    db = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=1, check_same_thread=False)
    try:
        db.execute("PRAGMA query_only=ON")
        db.execute("BEGIN")
        db.execute("SELECT rootpage FROM sqlite_master LIMIT 1").fetchone()
        if _recovery_journal_snapshot(path) != snapshot:
            raise repair_required("preparation_source_changed")
        yield db
    finally:
        db.close()
    if _recovery_journal_snapshot(path) != snapshot:
        raise repair_required("preparation_source_changed")


async def prepare_retained_legacy_handoff(
    installation,
    *,
    runtime_limits,
    adapter_limits: SuccessorAdapterLimits,
    providers,
) -> LegacyHandoffPreparationResult:
    """Verify an existing native intent's inventory, preserving the current writer.

    Source databases are read-only and stable; successful package and expiry work
    checkpoints into the same private owner consumed by final handoff. Repeated
    preparation restores unchanged completion without opening proof payloads.
    Providers must already be independently owned and started by the caller.
    This function does not provide provider construction or service supervision.
    """
    return await _prepare_retained_legacy_handoff(
        installation,
        runtime_limits=runtime_limits,
        adapter_limits=adapter_limits,
        providers=providers,
        completed_configs=None,
    )


async def read_prepared_legacy_handoff(
    installation, *, runtime_limits, adapter_limits, provider_configs
) -> LegacyHandoffPreparationResult | None:
    """Reuse complete native verification before constructing independent readers.

    Configurations come from the authenticated standing boot. This confirms only
    unchanged completed preparation; fresh writer ownership and transaction
    finality remain final-handoff responsibilities. Missing/damaged retained
    receipts require repair. None means no full completion has been recorded.
    The first check may initialize the derived verification-directory binding.
    """
    if type(provider_configs) is not dict or any(
        type(value) is not CompetitionChainConfig or digest(value) != key
        for key, value in provider_configs.items()
    ):
        raise TypeError("original native chain configuration identities required")
    return await _prepare_retained_legacy_handoff(
        installation,
        runtime_limits=runtime_limits,
        adapter_limits=adapter_limits,
        providers=None,
        completed_configs=provider_configs,
    )


async def _prepare_retained_legacy_handoff(
    installation, *, runtime_limits, adapter_limits, providers, completed_configs
):
    validate_authenticated_successor_installation(installation)
    if type(adapter_limits) is not SuccessorAdapterLimits:
        raise TypeError("native adapter limits required")
    retained = read_retained_handoff_intent(installation, runtime_limits)
    verification = LegacyHandoffVerification._for_preparation(
        retained.path.parent, retained.runtime_binding, retained.intent
    )
    # Initial receipt-directory creation changes the runtime directory metadata.
    # Reopen only this small intent after our own initialization, retaining exact
    # file-family identity and original bytes. No history or proof is replayed.
    current = read_retained_handoff_intent(installation, runtime_limits)
    if (
        current.intent != retained.intent
        or current.runtime_binding != retained.runtime_binding
        or current.snapshot[1] != retained.snapshot[1]
    ):
        raise repair_required("preparation_intent_changed")
    retained = current
    path = selected_weight_state_root(installation) / "competition-weights.sqlite3"
    registry = Path(installation.config.state_root) / "successor-adapter/registry.sqlite3"
    weight_snapshot = _recovery_journal_snapshot(path)
    registry_snapshot = _recovery_journal_snapshot(registry)
    limits = installation.worker_execution_limits
    storage = limits.weight_evidence_storage
    maximum_bytes = (
        (
            limits.maximum_weight_evidence_bytes
            if storage is None
            else storage.maximum_database_bytes
        )
        + limits.maximum_weight_attempts * _MAX_ATTEMPT_BYTES
        + 1024**2
    )
    context = {
        "weight_journal": snapshot_identity(weight_snapshot),
        "registry": snapshot_identity(registry_snapshot),
        "limits": digest(limits),
        "adapter_binding": hashlib.sha256(
            retained_adapter_binding(installation, adapter_limits)
        ).hexdigest(),
    }
    packages = {}

    def recheck():
        if (
            _recovery_journal_snapshot(retained.path) != retained.snapshot
            or _recovery_journal_snapshot(path) != weight_snapshot
            or _recovery_journal_snapshot(registry) != registry_snapshot
        ):
            raise repair_required("preparation_source_changed")
        for package, snapshot in packages.items():
            if snapshot_identity(_recovery_package_snapshot(package)) != snapshot:
                raise repair_required("retained_package_changed")

    def records():
        value = read_retained_adapter_inventory(installation, adapter_limits)
        if value.snapshot != registry_snapshot:
            raise repair_required("preparation_registry_changed")
        return value.runs

    with verification.reuse.exclusive():
        audited = verification.load("evidence_audit", "inventory", context)
        completed = verification.load("completion", "inventory", context)
        database_checked = verification.load("database_check", "inventory", context)
        if completed is not None and audited is None:
            raise repair_required("inventory_audit_completion_missing")
        if completed_configs is not None:
            if completed is None:
                recheck()
                return None
            if any(identity not in completed_configs for identity in completed["providers"]):
                raise ValueError("prepared handoff lacks the original chain configuration")
            restore_prepared_inventory(completed, packages, recheck)
        else:
            with _read_preparation_database(path, maximum_bytes, weight_snapshot) as db:
                await _verify_database_integrity(
                    db,
                    verification,
                    context,
                    recheck,
                    already_checked=audited is not None or database_checked is not None,
                )
                completed = await _verify_inventory(
                    installation,
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
                    minimum_block=0,
                    read_records=records,
                    verify_package=partial(verify_retained_package, installation),
                    preparation_retry=True,
                )
        recheck()
    return LegacyHandoffPreparationResult(
        digest(retained.intent),
        completed["inventory_sha256"],
        completed["attempts"],
        completed["through_block"],
    )
